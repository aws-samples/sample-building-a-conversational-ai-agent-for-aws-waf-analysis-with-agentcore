#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_prompt_current_time.py` claims and require it to notice.

The first case is the defect itself, restored: state the current time in UTC while telling the model the
session is UTC+8. That shipped, and the only thing that found it was a real question whose answer carried
two windows eight hours apart.

**Two cases exist because that test's two halves fail on different things and either alone leaves a
hole.** `the offset flipped` keeps the label honest and moves the time, so only the drift comparison can
catch it. `the label reduced to a bare UTC` keeps the time right and lies about it, which is the worse
direction because the model copies the label into its answer.

The prompt-text cases skip the reachability probe. Their anchors are prose inside a string literal
rather than a statement, so splicing a `raise` in changes the string instead of running, and the probe
would call a good perturbation unreachable.

No case perturbs `SLACK_SECONDS` on purpose. It only loosens, so widening it cannot turn a passing run
red, and tightening it goes red because the rendered minute is truncated, which is a fact about
`strftime` rather than about the property. A constant whose job is to prevent flake has nothing to catch.
"""

import sys

from _harness import sweep

T = "tests/test_prompt_current_time.py"
A = "agent.py"

LOCAL = '        now = datetime.now(timezone(timedelta(hours=tz_offset))).strftime(f"%Y-%m-%d %H:%M ({tz_str})")'

CASES = [
    # The shipped defect. One line ignoring the parameter the next line computes.
    ("the current time stated in UTC again, which is the bug this fixed",
     [(A, LOCAL, '        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")')],
     [f"{T}::test_the_stated_time_is_in_the_session_timezone"], True),

    # Label honest, time wrong. Only the drift half of that test can see this one.
    ("the offset applied with the wrong sign, so the label is right and the time is not",
     [(A, LOCAL,
       '        now = datetime.now(timezone(timedelta(hours=-tz_offset))).strftime(f"%Y-%m-%d %H:%M ({tz_str})")')],
     [f"{T}::test_the_stated_time_is_in_the_session_timezone"], True),

    # Time right, label lying. The worse direction: a local time labelled UTC reads as consistent
    # everywhere downstream, because the model copies the label through.
    ("a session-local time labelled UTC, which nothing downstream could tell",
     [(A, LOCAL,
       '        now = datetime.now(timezone(timedelta(hours=tz_offset))).strftime("%Y-%m-%d %H:%M UTC")')],
     [f"{T}::test_the_stated_time_is_in_the_session_timezone",
      f"{T}::test_the_two_lines_agree_about_the_timezone"], True),

    ("the two lines disagreeing, which is the shape the original bug had",
     [(A, "\\nSession timezone: {tz_str} — All times", "\\nSession timezone: UTC+0 — All times")],
     # Anchor inside the return f-string, so no probe: a spliced `raise` edits the string.
     [f"{T}::test_the_two_lines_agree_about_the_timezone"]),

    # A session with no timezone must say so rather than guess one. Guessing is worse than UTC here:
    # the model would compute a window in a zone nobody chose.
    ("an unset timezone guessing a zone instead of saying it is unset",
     [(A, '    if tz_offset is None:\n', "    if tz_offset is None and False:\n")],
     # No probe: a `raise` at this indent orphans the block below it, so the file stops parsing.
     [f"{T}::test_an_unset_timezone_says_utc_and_says_it_is_unset"]),

    # The consumer. Without the rule that derives a window from the stated time, everything above
    # guards a value nothing reads.
    ("the rule that consumes the stated time deleted",
     [(A, "calculate start_time = now - 6h in session timezone",
       "calculate start_time from the user's stated range")],
     [f"{T}::test_the_instruction_that_consumes_the_stated_time_still_exists"]),

    ("the prompt no longer forbidding a conversion to UTC",
     [(A, "Pass them to tools as-is, NEVER convert to UTC.",
       "Pass them to tools as-is.")],
     [f"{T}::test_the_instruction_that_consumes_the_stated_time_still_exists"]),
]

sys.exit(sweep(CASES))
