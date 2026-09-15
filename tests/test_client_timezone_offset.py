# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A client-supplied timezone offset crashed the request and poisoned the session.

**Measured on the deployed v0.27.1.** A POST carrying `forwardedProps.userTimezoneOffset: -480` returned
HTTP 424 wrapping a runtime 500, whose whole actionable content was "Please check your CloudWatch logs for
more information". The log held an unhandled traceback ending at `agent.py:399`:

    ValueError: offset must be a timedelta strictly between -timedelta(hours=24) and
    timedelta(hours=24), not datetime.timedelta(days=-20).

The field is hours. The frontend sends `-(new Date().getTimezoneOffset() / 60)`, and -480 is what
`getTimezoneOffset()` returns on its own, in minutes with the opposite sign. So the frontend cannot send
this, and that is not the same as unreachable: `docs/deployment.md` documents this POST as how a script or
an agent drives the runtime, and it is how this deployment gets verified.

**Three failures in four lines**, which is why the fix is one validation above them rather than a `try`
around each. `float(raw)` on a non-numeric string fails before the range is ever considered. The offset
reached `set_user_timezone` before the prompt was built, so the bad value was stored and then the build
raised, leaving that runtime instance answering later requests in a timezone 20 days from UTC. And the same
four lines existed twice, on the stream path and the resume path, so fixing one would have left the other.
"""

import pytest

import agent


@pytest.mark.parametrize("raw", [-480, 480, 24, -24, 100.5, float("nan"), float("inf")])
def test_an_offset_no_timezone_has_is_refused(raw):
    """`timezone()` accepts strictly between -24 and 24 hours, so 24 itself is out. NaN and infinity are
    here because they survive `float()` and then fail inside `timedelta`, which is the same crash by a
    different route: the guard is on the value, not on the conversion."""
    offset, reason = agent.parse_tz_offset(raw)
    assert offset is None, f"{raw!r} was accepted"
    assert "hours" in reason and "-24" in reason, reason


@pytest.mark.parametrize("raw", ["abc", "", {}, [8], True])
def test_a_value_that_is_not_a_number_is_refused_with_the_same_shape(raw):
    """The range check is unreachable for these, so a guard written as `abs(offset) >= 24` alone would let
    them through to the same 500. Measured on the real crash: the traceback started at `float(tz_offset)`
    for a string and at `timedelta` for a number, and the caller could not tell those apart.

    Every one of these is what `json.loads` produces for a real body. `null` is not in the list because the
    handler treats a missing field and a null one alike and never calls this, so asserting on it would hide
    why it cannot happen. `True` is here because JSON `true` does reach `float()`, which accepts it."""
    offset, reason = agent.parse_tz_offset(raw)
    assert offset is None, f"{raw!r} was accepted"
    assert "number of hours" in reason, reason


@pytest.mark.parametrize("raw,expected", [
    (8, 8.0), (-8, -8.0), (5.5, 5.5), (-9.5, -9.5), (0, 0.0), ("8", 8.0), (13.75, 13.75),
])
def test_every_real_offset_is_accepted_including_the_fractional_ones(raw, expected):
    """**The positive control, and it is not a formality.** A refusal that also refuses India (+5:30),
    the Marquesas (-9:30) and Chatham (+13:45) would replace a crash with a wrong answer, and the
    half-hour case is one `set_user_timezone`'s own docstring calls out. A string is accepted because JSON
    from a hand-written client may quote it and the value is unambiguous."""
    offset, reason = agent.parse_tz_offset(raw)
    assert reason is None, reason
    assert offset == expected


def test_the_refusal_names_the_mistake_the_caller_actually_made():
    """The measured value was -480, and the reason it is wrong is a unit. A message saying only "out of
    range" leaves the caller to guess, and the guess a browser API invites is exactly this one."""
    _, reason = agent.parse_tz_offset(-480)
    assert "getTimezoneOffset" in reason and "/ 60" in reason, reason


def test_a_rejected_offset_never_reaches_session_state():
    """**The poisoning half, and it outlives the request.** `set_user_timezone(-480)` succeeded and only
    the prompt build raised, so the runtime instance carried -480 into every later request in that session
    that sent no offset of its own. Asserted through the parser because it is what decides: the handler
    returns before either write."""
    from tools import session_state

    session_state.set_user_timezone(8.0)
    offset, reason = agent.parse_tz_offset(-480)
    assert reason and offset is None
    assert session_state.get_user_timezone() == 8.0, (
        "validating the offset changed the session timezone, so a refused request still moved the clock")


def test_the_handler_validates_once_above_both_paths():
    """Two copies of the same four lines is how one of them keeps the defect. Asserted on the source
    because reaching the resume path needs a live interrupt: what has to hold is that neither branch
    converts the raw value itself."""
    import ast
    import pathlib

    src = pathlib.Path(agent.__file__).read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "_invocations")
    body = ast.get_source_segment(src, fn) or ""
    assert body.count("parse_tz_offset(") == 1, (
        "the offset is parsed more than once in this handler, so the two paths can disagree")
    assert "float(tz_offset)" not in body, (
        "a branch still converts the raw value itself, which is the call that raised")
    assert body.count("set_user_timezone(tz_offset)") == 2, (
        "both the stream path and the resume path have to use the validated value")
    # The refusal has to precede the parse in reading order, or the crash happens before the check.
    assert body.index("parse_tz_offset(") < body.index("get_agent("), (
        "the offset is validated after the agent is built, so a bad value can still reach it")


def test_no_offset_at_all_is_not_an_error():
    """The CLI path and the AG-UI short form both omit it, and the prompt has a `None` branch for exactly
    that. Refusing a missing field would turn a working call into a 400."""
    import ast
    import pathlib

    src = pathlib.Path(agent.__file__).read_text()
    fn_src = src[src.index("async def _invocations"):]
    fn_src = fn_src[:fn_src.index("\n    app.")] if "\n    app." in fn_src else fn_src
    assert "if raw_tz is not None:" in fn_src, (
        "a request with no offset must skip the parse rather than be refused")
    assert agent._build_system_prompt(None), "the prompt has to build with no offset at all"
