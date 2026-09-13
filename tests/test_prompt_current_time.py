# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The current time the prompt states is in the session timezone, and it says which one.

**Two adjacent lines in one function used the same parameter, and one of them ignored it.** The prompt
announced `Session timezone: UTC+8 — All times from the user are in this timezone. Pass them to tools
as-is, NEVER convert to UTC`, and stated the current time in UTC. The one instruction that consumes
that time, "last 6 hours → start_time = now - 6h in session timezone", therefore had no correct input.

Measured on the deployed agent, 2026-09-13, session timezone UTC+8, `now` 05:52 UTC. The model passed
`start_time=2026-09-12T23:52`, the UTC number. `_parse_start_time` reads an offset-less string as
session-local, so the log query ran over 15:52-21:52 UTC while the question was about the six hours
ending 05:52 UTC. `get_waf_overview` was called in the same turn with an empty `start_time`, computed
its own window correctly, and the reply carried two windows eight hours apart. Both happened to hold
three blocked requests from one IP, so it read as self-consistent. The count could not tell them apart
and the timestamps had to be pulled from CloudWatch Logs to settle it.

**The label is asserted as hard as the value, because a local time labelled `UTC` is worse than a UTC
time labelled `UTC`.** The model copies the label through into its answer, so the wrong one is invisible
to the reader as well as to the model.

Not covered here, and not this defect: the partition timezone that decides which S3 hour directories an
Athena query scans is a third timezone, owned by `waf_athena` and read from Firehose's `CustomTimeZone`.
It has no reason to equal the session timezone, and it is downstream of everything above.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest

import agent

# The rendered minute is truncated, and the two `now()` calls are not simultaneous, so the comparison
# needs slack. Two minutes is loose enough never to flake and far tighter than the one-hour granularity
# any timezone mistake would produce.
SLACK_SECONDS = 120


def _stated(prompt: str) -> tuple[datetime, str]:
    """The time and the timezone label the prompt's first line states.

    Parsed rather than substring-matched, because the defect this file exists for is a correct-looking
    string: `2026-09-13 05:52 UTC` is well-formed, and only comparing it against the offset shows it is
    eight hours out."""
    first = prompt.splitlines()[0]
    match = re.match(r"^Current date/time: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}) (?:\(([^)]+)\)|(UTC))$", first)
    assert match, f"the current-time line changed shape, so this file checks nothing: {first!r}"
    return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M"), (match.group(2) or match.group(3))


@pytest.mark.parametrize("offset", [8.0, -5.0, 5.75, 0.0])
def test_the_stated_time_is_in_the_session_timezone(offset):
    """The assertion that fails on the version this fixes. Half-hour and quarter-hour zones are in the
    list because the frontend offers them: `timedelta(hours=5.75)` is 5h45m, and an implementation that
    rounded to whole hours would pass a test parametrized only on 8 and -5."""
    stated, label = _stated(agent._build_system_prompt(offset))
    assert label == f"UTC{offset:+g}", (
        f"the time is labelled {label!r} while the session timezone is UTC{offset:+g}. A local time "
        f"labelled UTC is the worse failure: the model copies the label into its answer, so nothing "
        f"downstream can tell.")
    expected = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=offset)
    drift = abs((stated - expected).total_seconds())
    assert drift < SLACK_SECONDS, (
        f"the prompt states {stated} for session timezone UTC{offset:+g}, which is {drift / 3600:.2f} "
        f"hours from where that zone actually is. The model computes start_time from this value and "
        f"the tools read an offset-less start_time as session-local, so the query window moves by the "
        f"same amount with nothing in the answer to say so.")


def test_the_two_lines_agree_about_the_timezone():
    """The defect stated directly: the time and the timezone label come from one parameter, and the bug
    was one line using it and the next line not. Asserted across offsets whose labels cannot coincide
    with a UTC rendering."""
    for offset in (8.0, -5.0):
        prompt = agent._build_system_prompt(offset)
        _, label = _stated(prompt)
        assert f"Session timezone: {label} " in prompt, (
            f"the current-time line says {label!r} and the session-timezone line says something else. "
            f"Both are rendered from the same argument, so they cannot disagree honestly.")


def test_an_unset_timezone_says_utc_and_says_it_is_unset():
    """The other branch, and it must stay UTC. A session with no timezone is the agent-creation path,
    where guessing a zone would be worse than naming the one the value is actually in."""
    prompt = agent._build_system_prompt(None)
    stated, label = _stated(prompt)
    assert label == "UTC"
    assert "Session timezone: UTC (not set by user)" in prompt, (
        "an unset timezone no longer says so, so the model cannot tell a real UTC session from a "
        "missing one")
    drift = abs((stated - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds())
    assert drift < SLACK_SECONDS, f"unset timezone should state UTC, off by {drift}s"


def test_the_instruction_that_consumes_the_stated_time_still_exists():
    """The consumer, so the fix above cannot end up guarding nothing. If the "last 6 hours" rule is
    ever reworded to compute the window some other way, the assertions above stop describing anything
    the model does and should be reconsidered rather than left passing."""
    prompt = agent._build_system_prompt(8.0)
    assert "start_time = now - 6h in session timezone" in prompt, (
        "the rule that derives a window from the stated time is gone. That rule is why the stated "
        "time has to be session-local; re-read this file's docstring before deleting these tests.")
    # **On the session-timezone line, not anywhere in the prompt.** `"NEVER convert to UTC" in prompt`
    # was the first version and it is satisfied twice: the line this fix is about carries it, and so
    # does the time-parsing rules section further down. Deleting the one that matters left the
    # assertion green, which the perturbation reported as HOLLOW.
    tz_line = next((l for l in prompt.splitlines() if l.startswith("Session timezone: ")), "")
    assert tz_line, "the session-timezone line is gone"
    assert "NEVER convert to UTC" in tz_line, (
        f"the line that states the session timezone no longer forbids converting to UTC, which is the "
        f"claim the stated time has to be consistent with: {tz_line!r}")
