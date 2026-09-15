# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A query window narrowed from two days to six hours, and the answer said nothing about it.

**Measured on the deployed v0.27.0.** `run_logs_query(query_type="top_blocked_ips",
start_time="2026-09-08T00:00", duration_minutes=2880)`. The clamp used 360 and the answer was
`Query returned 0 results` with three generic reasons: wrong action filter, wrong window, no matching
traffic. The window it actually covered was the quiet six hours before an attack that produced 566,070
blocks later the same day, so the one true reason, that the request had been narrowed, was the one absent.

The model noticed the contradiction and could not confirm it. Its own words: "工具没有任何一句话告诉我它把窗口
改小了", followed by a guess reconstructed from the tool's documentation.

**`aggregate_logs` already solved this**, in the header `_describe` builds, and its docstring says why: the
model chose the parameters and the window was silently clamped, so a header naming the request is how a
caller notices it got the aggregation it asked for over the window it did not. Three other sites had the
same clamp and no header, and the third of them, `analyze_ip`, is the one users reach most.

**0.27.1 shipped that fix at three of five return paths, and the two it missed were the ones that answer
with content.** `run_logs_query` appended the sentence on its empty-result return and not on its table, so
a reader who got 25 rows read them as two days while a reader who got none at least doubted them; its
query-failure and poll-timeout returns were silent too, so "my two-day query timed out" described a
six-hour attempt. `analyze_ip` covered its no-records branch and its main output and missed the NAT
verdict, which prints `Confidence: HIGH` and "blocking this IP would affect multiple legitimate users"
from diversity counts taken over the narrowed window, with a Log Filter caveat right beside it.

**Four more tools clamp and never said anything at all**: `detect_bypass`,
`check_challenge_compatibility`, `investigate_injection` and `aggregate_logs`. The first version of this
file asserted the disclosing set equalled the two modules being edited, so the four were never asked
about. Both mistakes have one shape, counting return paths and counting tools by looking at the diff, and
one fix: the clamp records and `SourceDisclosure` appends once where the result leaves the tool call.
"""

import pytest

import agent
from tools import session_state
from tools.query_limits import MAX_MINUTES, window_capped_note

CAPPED = window_capped_note(2880, MAX_MINUTES)


def test_a_narrowed_window_says_both_numbers():
    """Both, because either alone leaves the reader doing arithmetic to find out what happened."""
    assert "2,880" in CAPPED and "360" in CAPPED, CAPPED


def test_it_says_what_the_result_does_not_mean():
    """The sentence exists for the answer that follows it. "0 results" over a sixth of the requested window
    is not a statement about the rest, and the reader has to be told that before reading the rows."""
    assert "says nothing about the rest" in CAPPED, CAPPED
    assert "Split the range" in CAPPED, "and what to do instead"


def test_a_window_inside_the_cap_says_nothing():
    """**The check that is always on is not a check.** Most questions ask for less than the cap, and a note
    on every one of them is noise that trains a reader to skip it."""
    assert window_capped_note(60, 60) == ""
    assert window_capped_note(MAX_MINUTES, MAX_MINUTES) == ""


def _clamp_sites():
    """Every function in `tools/` that clamps `duration_minutes` to `MAX_MINUTES`, and whether it records.

    Read as `Call` nodes rather than as text, so a docstring quoting the clamp is not a clamp. The first
    version of this sweep matched the string and counted `note_window_capped`'s own docstring as a silent
    site, then looked for the recorder within four lines and missed one sitting under a comment: both are
    the same mistake as the defect, a check on the shape of the source instead of on the code.
    """
    import ast
    import pathlib

    def _calls(node, name):
        return [c for c in ast.walk(node)
                if isinstance(c, ast.Call) and getattr(c.func, "id", "") == name]

    root = pathlib.Path(__file__).resolve().parents[1]
    sites = []
    for path in sorted(root.glob("tools/*.py")):
        tree = ast.parse(path.read_text())
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            clamps = [c for c in _calls(fn, "min")
                      if {getattr(a, "id", "") for a in c.args} == {"duration_minutes", "MAX_MINUTES"}]
            if clamps:
                sites.append((f"{path.name}::{fn.name}", bool(_calls(fn, "note_window_capped"))))
    return sites


def test_every_clamp_in_the_package_records_it():
    """**Swept rather than enumerated, because enumerating is what shipped the gap.**

    0.27.1's version of this test asserted the set of disclosing modules equalled
    `{"waf_logs.py", "waf_block_fp.py"}` and parametrised over those two. Both passed. There are seven
    clamp sites: the four it never asked about are `aggregate_logs`, `detect_bypass`,
    `check_challenge_compatibility` and `investigate_injection`, and none of them said anything. Pinning
    the set I had already edited turned the gap into a passing assertion.

    So the question this asks is what the package can ask for, not what I remember editing. A clamp with no
    recorder fails here whichever file it lands in."""
    sites = _clamp_sites()
    assert len(sites) == 7, f"seven functions clamp the window; found {[n for n, _ in sites]}"
    silent = [name for name, records in sites if not records]
    assert not silent, (
        f"these clamps narrow the window and record nothing, so the answer will not mention it: {silent}")


def test_the_note_is_never_appended_at_a_return():
    """**The counting error had a shape, and this is it.** Appending the sentence at each return means
    knowing every return, and `run_logs_query` has five: 0.27.1 covered the empty-result one and left the
    table, the query-failure and the poll-timeout returns silent. `analyze_ip` has three and its NAT
    verdict, which prints `Confidence: HIGH` from diversity counts, was one of the missed ones.

    One append in the hook cannot miss a return, so no tool should be building this string itself."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    builders = [p.name for p in sorted(root.glob("tools/*.py"))
                if p.name != "query_limits.py" and "window_capped_note(" in p.read_text()]
    assert builders == [], (
        f"{builders} calls the wording function directly. Record with `note_window_capped` and let "
        f"`SourceDisclosure` append it, or the next return added to that tool is silent again.")


class _FakeEvent:
    """`AfterToolCallEvent`'s own `_can_write` permits exactly `result` and `retry`, so a stand-in carrying
    `result` matches the contract the hook is allowed to use."""

    def __init__(self, content, tool_use_id="t1", name="run_logs_query"):
        self.tool_use = {"name": name, "toolUseId": tool_use_id}
        self.result = {"toolUseId": tool_use_id, "status": "success",
                       "content": [{"text": t} for t in content]}


@pytest.fixture(autouse=True)
def clean():
    for key in ("window_cap", "provenance", "provenance_subject", "provenance_stash"):
        session_state._state.pop(key, None)
    session_state.begin_tool_call("")
    yield
    session_state.begin_tool_call("")
    session_state._state.pop("window_cap", None)


@pytest.mark.parametrize("content", [
    ["| httpRequest.clientIp | cnt |\n| 1.2.3.4 | 57691 |"],       # the table return
    ["## 1.2.3.4 — NAT/Shared IP (skipped)\n**Confidence: HIGH**"],  # the NAT verdict return
    ["Query 'top_blocked_ips' failed: ThrottlingException"],          # the query-failure return
    ["Query returned 0 results. (query: top_blocked_ips)"],           # the one 0.27.1 covered
])
def test_the_hook_appends_it_whatever_the_tool_returned(content):
    """**The property is the absence of a per-return decision.** Each of these strings is a different
    return of `run_logs_query` or `analyze_ip`, and three of the four were silent in 0.27.1. The hook does
    not read them, which is why it cannot get the fourth one wrong either."""
    session_state.begin_tool_call("t1")
    session_state.note_window_capped(2880, 360)
    event = _FakeEvent(content)
    agent.SourceDisclosure().append_source(event)
    blocks = [c["text"] for c in event.result["content"]]
    assert len(blocks) == 2, f"the note has to be its own block, not spliced into the output: {blocks}"
    assert "Window narrowed" in blocks[1] and "2,880" in blocks[1], blocks[1]


def test_a_window_that_fitted_adds_nothing_to_the_result():
    """**The check that is always on is not a check**, one layer out from the wording test above. Most
    tool calls ask for less than the cap, and a note on all of them is noise."""
    session_state.begin_tool_call("t1")
    session_state.note_window_capped(180, 180)
    event = _FakeEvent(["rows"])
    agent.SourceDisclosure().append_source(event)
    assert event.result["content"] == [{"text": "rows"}], "a tool that got the window it asked for was told otherwise"


def test_the_cap_and_the_source_line_arrive_in_one_block_with_the_cap_first():
    """Both disclosures come from this hook now, so their order is a decision. The cap changes how the rows
    above it should be read; the `SOURCE:` line is the signature under both."""
    session_state.set_webacl_context("shield-sample-webacl", "arn:x", "CLOUDFRONT", "us-east-1",
                                     log_destination="arn:aws:logs:us-east-1:1:log-group:lg")
    session_state.begin_tool_call("t1")
    session_state.note_window_capped(2880, 360)
    session_state.note_query_provenance("CloudWatch Logs Insights", 1000, 2000)
    event = _FakeEvent(["rows"])
    agent.SourceDisclosure().append_source(event)
    appended = event.result["content"][1]["text"]
    assert appended.index("Window narrowed") < appended.index("SOURCE:"), appended


def test_a_tool_call_that_clamped_nothing_but_queried_still_gets_its_source_line():
    """The two are independent, and reading the cap must not have made the line conditional on it. The
    reverse pairing is the one above."""
    session_state.set_webacl_context("shield-sample-webacl", "arn:x", "CLOUDFRONT", "us-east-1",
                                     log_destination="arn:aws:logs:us-east-1:1:log-group:lg")
    session_state.begin_tool_call("t1")
    session_state.note_query_provenance("CloudWatch Logs Insights", 1000, 2000)
    event = _FakeEvent(["rows"])
    agent.SourceDisclosure().append_source(event)
    assert "SOURCE:" in event_text(event), event_text(event)
    assert "Window narrowed" not in event_text(event)


def event_text(event):
    return "\n".join(c["text"] for c in event.result["content"])


def test_a_tool_call_that_clamped_but_never_queried_still_says_so():
    """`run_logs_query` can clamp and then refuse, and `investigate_block_fp` clamps before it validates
    its IP. There is no provenance record on those paths, so a note gated on one would vanish exactly
    where the user was told the least."""
    session_state.begin_tool_call("t1")
    session_state.note_window_capped(2880, 360)
    event = _FakeEvent(["Error: invalid IP address 'x'"])
    agent.SourceDisclosure().append_source(event)
    assert "Window narrowed" in event_text(event), event_text(event)
    assert "SOURCE:" not in event_text(event), "a tool that ran no query claimed a source"


def test_the_next_tool_call_does_not_inherit_the_cap():
    """A note that outlives its tool call is a claim about the next one's window, which is the
    misattribution class this whole channel exists to remove."""
    session_state.begin_tool_call("t1")
    session_state.note_window_capped(2880, 360)
    agent.SourceDisclosure().append_source(_FakeEvent(["rows"]))
    second = _FakeEvent(["rows"], tool_use_id="t2")
    agent.SourceDisclosure().append_source(second)
    assert second.result["content"] == [{"text": "rows"}], event_text(second)
    assert not session_state._state.get("window_cap"), "the slot outlived the tool call"


def test_two_concurrent_tool_calls_keep_their_own_cap():
    """Same slot keying as the provenance record, and for the same measured reason: two tool calls run as
    interleaved asyncio tasks on one thread, so one shared slot would tell one of them about the other's
    window."""
    import asyncio

    async def run():
        async def one(tool_call, asked):
            session_state.begin_tool_call(tool_call)
            session_state.note_window_capped(asked, 360)
            await asyncio.sleep(0)
        await asyncio.gather(one("call-A", 2880), one("call-B", 720))

    asyncio.run(run())
    assert session_state.take_window_cap("call-A") == {"asked": 2880, "used": 360}
    assert session_state.take_window_cap("call-B") == {"asked": 720, "used": 360}
