# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A long answer stopped mid-row and had an SDK exception glued to its last table cell.

**Measured on the deployed endpoint 2026-09-15**, on an ordinary question: country and referer breakdowns
for one day, which `aggregate_logs`' 360-minute cap splits into four windows. The answer ended:

    | 12:00–18:00 | 1,222,880 |
    | **全天Error: Agent has reached an unrecoverable state due to max_tokens limit. For more
    information see: https://strandsagents.com/latest/user-guide/concepts/agents/agent-loop/...

Two defects in one line. The model was constructed with `max_tokens=4096`, three per cent of what it
allows: measured against `global.anthropic.claude-sonnet-5` in ap-northeast-1, 4,096 through 65,536 are all
accepted and 131,072 is refused with "exceeds the model limit of 128000". And the error was emitted on the
same `messageId` as the streamed answer with no separator, so it read as the next table cell, while the only
actionable content in it was a link to another project's documentation.

**The fix is to send no bound at all, not a larger one.** The first attempt raised the number, and a number
picked in this repository is a ceiling the model did not choose; the maintainer's standing instruction is not
to set one. Measured that omitting works: a Converse call with no `inferenceConfig` answers and reports
`stopReason: end_turn`. The second half stays necessary either way, because the service has its own ceiling
and a request can still be cut short by it.
"""

import agent


def test_no_output_bound_reaches_the_request():
    """**Nothing is sent, rather than a larger number.** The first fix raised 4,096 to 32,768, which is the
    wrong shape: a number picked in this file is a ceiling the model did not choose, and the maintainer's
    standing instruction is not to set one.

    Measured that omitting works end to end: a Converse call with no `inferenceConfig` at all answers and
    reports `stopReason: end_turn`, and `BedrockModel` with neither keyword sends `inferenceConfig: {}`. The
    service still has its own ceiling, 131,072 is refused with "exceeds the model limit of 128000", and
    enforcing it is the service's job.

    Read from the request the SDK would send rather than from the constructor's keywords, because a keyword
    dropped between the two would satisfy an assertion on the constructor while the request still carried
    a bound."""
    cfg = agent._get_model()._format_request([{"role": "user", "content": [{"text": "hi"}]}])
    assert "maxTokens" not in cfg["inferenceConfig"], cfg["inferenceConfig"]
    assert cfg["inferenceConfig"] == {}, (
        f"the request carries inference parameters this file chose: {cfg['inferenceConfig']}")


def test_a_truncated_answer_says_so_in_the_reader_s_terms():
    """**Not the SDK's sentence.** It names a Python exception and a URL to another project's docs, neither
    of which is about this WebACL. What a person reading a WAF report needs is that the answer is
    incomplete, that what they can see is still real, and what to do next."""
    msg = agent._error_text("Agent has reached an unrecoverable state due to max_tokens limit. For more "
                            "information see: https://strandsagents.com/latest/...", True)
    assert "This answer is incomplete" in msg
    assert "Everything above this line is real" in msg
    assert "narrower window" in msg
    assert "strandsagents.com" not in msg and "unrecoverable" not in msg


def test_the_message_is_separated_from_the_answer_it_follows():
    """The half of the defect that made the error read as a table cell. Same `messageId`, so the delta is
    appended to whatever was already streamed, and the streamed text ended inside a row."""
    mid = agent._error_text("... max_tokens limit ...", True)
    assert mid.startswith("\n\n"), repr(mid[:10])
    fresh = agent._error_text("... max_tokens limit ...", False)
    assert not fresh.startswith("\n"), "nothing to separate from when no text was streamed"


def test_any_other_failure_keeps_its_own_message():
    """The narrowing owes this: rewriting every error into the truncation sentence would hide a throttle, a
    missing permission or a bad table name behind a sentence about output length. Only the truncation is
    rewritten, and it is recognised by the string the SDK actually raises."""
    for other in ("AccessDeniedException: not authorized to perform wafv2:GetWebACL",
                  "ThrottlingException: Rate exceeded",
                  "TABLE_NOT_FOUND: line 1:15: Table awsdatacatalog.default.waf_logs does not exist"):
        msg = agent._error_text(other, True)
        assert other in msg, msg
        assert "This answer is incomplete" not in msg


def test_the_streaming_loop_asks_for_the_formatted_text():
    """Structural, because reaching it needs a live agent thread that raises. The `ERROR` branch is the only
    consumer, and the two properties above are worth nothing if it goes on emitting `f"Error: {payload}"`
    with the raw message."""
    import pathlib

    src = pathlib.Path(agent.__file__).read_text()
    block = src[src.index('elif event_type == "ERROR":'):]
    block = block[:block.index("TEXT_MESSAGE_END", 10)]
    assert "_error_text(payload, has_streamed_text)" in block, block
