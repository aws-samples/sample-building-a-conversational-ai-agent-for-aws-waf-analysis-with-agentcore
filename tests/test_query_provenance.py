# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A log query answers from the session's WebACL, never from the one the question named.

`run_logs_query` reads the logging destination out of session state, set by the last
`get_waf_config` call. Nothing connects it to the WebACL the user asked about. So a question about
WebACL A is answered from WebACL B's logs whenever the context holds B, with no error.

**Measured on a real investigation, 2026-09-12.** The maintainer asked about a WebACL logging to
CloudWatch Logs (`aws-waf-logs-group`) while the session context held one logging to Firehose. The
runtime log records `dest=arn:aws:firehose:...:deliverystream/aws-waf-logs-kinesis-s3`. The answer was
"Query returned 0 results" followed by three candidate causes: wrong action filter, wrong time window,
no matching traffic. None of them was it.

**Zero rows was luck, and that is why the provenance line goes on the success path too.** Had the
other WebACL held matching traffic in that window, rows would have come back, been read as the answer,
and the zero-result branch that carries these hints would never have executed. The dangerous outcome
is rows, so a check that only covers the empty answer covers the safe half.

**The emitter moved on 2026-09-14, and the tests moved with it.** The line was built inside `waf_logs`
and appended at that module's two output paths, which covered two of the ten tools that query. It is now
`session_state.provenance_source_line`, appended by `agent.SourceDisclosure` at `AfterToolCallEvent`,
the one point every tool string passes. So the structural assertions that pinned two call sites are gone:
there is one, it is keyed on whether the tool queried anything, and a tool written next year is covered
without being listed. Two properties become testable that were not before, and both are below: the engine
named is the one the query used rather than one re-derived from state at render time, and the record the
chip needs survives being read here.
"""

import pathlib

from tools import session_state
from tools.session_state import provenance_source_line

import agent

FIREHOSE = "arn:aws:firehose:us-east-1:111122223333:deliverystream/aws-waf-logs-kinesis-s3"
LOG_GROUP_DEST = "arn:aws:logs:us-east-1:111122223333:log-group:aws-waf-logs-group"
CWL, ATHENA = "CloudWatch Logs Insights", "Athena over S3"


def _context(name, dest):
    session_state.set_webacl_context(name, f"arn:aws:wafv2:::webacl/{name}/x", "CLOUDFRONT",
                                     "us-east-1", log_destination=dest)


def _record(engine, subject=None, start=1000, end=2000):
    """A fresh record, read straight out of state. Nothing peeks in production: the hook drains."""
    session_state._state.pop("provenance", None)
    session_state._state.pop("provenance_stash", None)
    session_state.note_query_provenance(engine, start, end, subject=subject)
    return dict(session_state._state["provenance"])


class _FakeEvent:
    """`AfterToolCallEvent`'s own `_can_write` permits exactly `result` and `retry`, so a stand-in
    carrying `result` matches the contract the hook is allowed to use. Same shape as the one in
    `test_log_value_disclosure.py`, kept local rather than imported so neither file's fixture can be
    changed for the other's reasons."""

    def __init__(self, content):
        self.tool_use = {"name": "run_logs_query", "toolUseId": "t1"}
        self.result = {"toolUseId": "t1", "status": "success", "content": content}


def test_the_line_names_the_webacl_and_the_engine_that_answered():
    """Both halves of what went wrong: which WebACL, and which engine that implies."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    cwl = provenance_source_line(_record(CWL))
    assert "shield-sample-webacl" in cwl and "CloudWatch" in cwl, cwl

    _context("some-other-webacl", FIREHOSE)
    athena = provenance_source_line(_record(ATHENA))
    assert "some-other-webacl" in athena and "Athena" in athena, athena
    assert cwl != athena, "the line does not change with the context, so it carries no information"


def test_the_engine_named_is_the_one_the_query_used():
    """**Not re-derived from session state when the line is rendered**, which the old emitter did by
    calling `get_log_type()` at that moment. A state read at render time answers "what would a query use
    now", and the question is "what did this one use". The two differ for exactly the case this file
    exists for: a destination that changed, or a tool that took a different path.

    Asserted by making them disagree: the context says CloudWatch and the record says Athena. The record
    wins, because the record is the only one of the two that observed the query."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    line = provenance_source_line(_record(ATHENA))
    assert "Athena" in line and "CloudWatch" not in line, line


def test_an_explicit_log_group_is_named_instead_of_the_session_webacl():
    """An explicit `log_group` forces the CloudWatch path, builds its own client and never reaches
    `query_logs`, so claiming the session's WebACL would be a lie in the other direction.

    **That path records for itself, and the structural half of this test is why it has to.** It is the
    one query in the repository outside the funnel, so nothing else would notice if the recording were
    dropped: the tool would answer, the chip would show nothing and the line would name a WebACL that was
    not consulted."""
    _context("some-other-webacl", FIREHOSE)
    explicit = provenance_source_line(_record(CWL, subject="log group aws-waf-logs-group"))
    assert "aws-waf-logs-group" in explicit
    assert "some-other-webacl" not in explicit, "named a WebACL that had nothing to do with the query"

    src = pathlib.Path(session_state.__file__).with_name("waf_logs.py").read_text()
    forced = src.index("# If explicit log_group provided, force CWL path")
    window = src[forced:forced + 700]
    assert "note_query_provenance(" in window and "subject=" in window, (
        "the explicit-log-group path no longer records what it queried, so its answer discloses nothing")


def test_the_line_does_not_tell_the_model_to_undo_an_explicit_log_group():
    """**The assertion above passed while the rest of the sentence was false.** Merging the two emitters
    into one kept only the session-derived wording, so with an explicit log group the line read
    `SOURCE: log group X via CloudWatch Logs Insights. That is the WebACL from the last get_waf_config
    call ... call get_waf_config(webacl_name='...') and run this again.` The subject was right and every
    clause after it was wrong, including an instruction to undo the thing the caller had just asked for.

    Same class as the ALLOW probe that told a user to change their logging filter because a query had
    timed out: a tool acting on a false premise and directing a change to the user's own configuration.

    **The criterion is the whole string the model reads, not the identifier inside it.** The test above
    checks which names appear and would have passed on that line forever; the lie sat thirty characters
    later in prose."""
    _context("some-other-webacl", FIREHOSE)
    explicit = provenance_source_line(_record(CWL, subject="log group aws-waf-logs-group"))
    assert "get_waf_config" not in explicit, explicit
    assert "not consulted" in explicit, "it has to say the session context was bypassed, not imply it"

    session_derived = provenance_source_line(_record(CWL))
    assert "get_waf_config" in session_derived, (
        "the session-derived path still needs the instruction; that is the whole point of the line")


def test_an_unset_context_says_so_rather_than_looking_confident():
    """The empty case has to read as empty. `None` or a blank name would render as a sentence that
    looks like it names something."""
    session_state.set_webacl_context("", "", "CLOUDFRONT", "us-east-1", log_destination=None)
    session_state._state.pop("provenance", None)
    text = provenance_source_line({})
    assert "(none set)" in text and "no engine" in text, text


def test_every_tool_result_that_queried_carries_the_line():
    """**The assertion the old file could only make structurally, and only for one module.** It anchored
    two output paths in `waf_logs` and asserted the emitter was called near each. That covered two of ten
    tools and said nothing about the other eight.

    The hook is keyed on the record, so this drives it directly: a tool call that queried gets the line
    appended as its own text block, and one that queried nothing gets nothing. The second half is not a
    detail. A config-only tool carrying `SOURCE: ... via no engine` would be a claim about a query that
    never happened, and there are more tools like that than like the first kind."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    _record(CWL)
    event = _FakeEvent([{"text": "Query 'top_blocked_ips' returned 25 results"}])
    agent.SourceDisclosure().append_source(event)
    blocks = [c["text"] for c in event.result["content"]]
    assert len(blocks) == 2, f"the line has to be its own block, not spliced into a table: {blocks}"
    assert "SOURCE:" in blocks[1] and "shield-sample-webacl" in blocks[1]

    session_state._state.pop("provenance", None)
    quiet = _FakeEvent([{"text": "WebACL config loaded"}])
    agent.SourceDisclosure().append_source(quiet)
    assert quiet.result["content"] == [{"text": "WebACL config loaded"}], (
        "a tool that ran no query claimed a source anyway")


def test_the_hook_hands_the_record_to_the_chip_by_tool_call_id():
    """Two readers, one record. The hook drains and stashes under this tool call's id; the streaming loop
    collects it with that id, which it already has as the `TOOL_END` payload."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    _record(CWL)
    agent.SourceDisclosure().append_source(_FakeEvent([{"text": "rows"}]))
    assert session_state.take_query_provenance("other-tool") == {}, (
        "another tool call collected this one's record")
    assert session_state.take_query_provenance("t1").get("webacl") == "shield-sample-webacl", (
        "the record never reached the chip, so the model got the line and the user got nothing")
    assert session_state.take_query_provenance("t1") == {}, "collected twice"


def test_the_stash_lives_where_the_isolation_fixture_can_clear_it():
    """**The property the stash's location is for, asserted instead of implied.**

    `tests/conftest.py`'s autouse `_isolate_module_state` clears `session_state._state` and the Athena
    table cache, and nothing else. A module-level stash sits outside it, which leaks records between test
    files the day a second file touches the hook.

    Moving it into `_state` fixed that, and for one commit the only thing holding it there was a string:
    `perturb-source-line.py` quotes the new expression in an anchor, so reverting the move goes red on the
    drift test with the message "the case has drifted". That sends the next reader to update the anchor,
    which turns the suite green and brings the leak back. **A guard has to say the property when it fires**,
    not name a neighbour of the symptom, which is the same lesson as the sweep reporting an unreachable line
    for what was really a stale anchor."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    session_state.note_query_provenance(CWL, 1000, 2000)
    session_state.stash_query_provenance("t1")
    assert "provenance_stash" in session_state._state, (
        "the stash has to live inside _state, which is the only thing conftest's "
        "_isolate_module_state clears")


def test_a_cleared_state_drops_the_stash():
    """The same property from the reader's side, **and it is a separate function because that is what makes
    it run.**

    It began as a second assertion inside the test above, where it was unreachable: pytest stops at the
    first failure, so the perturbation that moves the container out of `_state` never got here. I wrote that
    up as a weak assertion that only a reader keeping its own copy could break. Measured: under that same
    perturbation `take_query_provenance("t1")` returns the whole record after `_state.clear()`, so it is
    red, and the only thing hiding it was sharing a function. One `def` turns a gap I had recorded into a
    property that is guarded, with no new case."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    session_state.note_query_provenance(CWL, 1000, 2000)
    session_state.stash_query_provenance("t1")
    session_state._state.clear()
    assert session_state.take_query_provenance("t1") == {}, "a cleared _state must drop the stash"


def test_the_chip_still_gets_a_record_if_the_hook_never_ran():
    """**The fallback, and it keeps the two failures independent.** Whether the hook fires is on the
    post-deploy checklist, because nothing in this suite can answer it: a unit test calls it directly. If
    it does not fire, the model loses its line, and without this the chip would lose its window in the
    same breath. One degradation at a time."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    _record(CWL)
    assert session_state.take_query_provenance("t1").get("webacl") == "shield-sample-webacl", (
        "the live record is unreachable once the stash is empty, so a hook that did not fire loses both")


def test_a_second_tool_call_does_not_inherit_the_first_ones_window():
    """**The CLI path never drained, so the line accumulated.** `take_query_provenance` was called in one
    place, inside the SSE generator, and `invoke` does not go through it. Measured 2026-09-14: a second
    tool call in one CLI run rendered `SOURCE: webacl-B` over a 167-hour window that spanned the first
    tool's query of webacl-A, and a count of 2. A subject and a window contradicting each other is the
    misattribution this record exists to remove.

    It was a regression rather than an old gap: before the record existed, the CLI line was rendered fresh
    from state with no window at all, so it had nothing to accumulate.

    **Clearing at the end of a turn would not have fixed it**, which is why the drain sits in the hook: the
    second tool call in one turn inherits the first one's window either way. Driven here as two tool calls
    with no streaming loop at all, which is exactly the CLI shape."""
    _context("webacl-A", LOG_GROUP_DEST)
    _record(CWL, start=1000, end=4600)
    first = _FakeEvent([{"text": "rows from A"}])
    agent.SourceDisclosure().append_source(first)

    _context("webacl-B", LOG_GROUP_DEST)
    session_state.note_query_provenance(CWL, 600_000, 604_600)
    second = _FakeEvent([{"text": "rows from B"}])
    second.tool_use = {"name": "run_logs_query", "toolUseId": "t2"}
    second.result = {"toolUseId": "t2", "status": "success", "content": second.result["content"]}
    agent.SourceDisclosure().append_source(second)

    record = session_state.take_query_provenance("t2")
    assert record["webacl"] == "webacl-B"
    assert (record["start"], record["end"]) == (600_000, 604_600), (
        f"the second tool call inherited the first's window: {record}")
    assert record["queries"] == 1, "and its query count"
    assert "webacl-B" in second.result["content"][1]["text"]


def test_the_streaming_loop_collects_by_the_id_it_already_has():
    """The other end of the handoff, asserted on the source because reaching it needs a live agent. The
    `TOOL_END` branch has the tool call id as its payload, so passing it costs nothing; passing nothing
    would fall through to the live record, which the hook has already drained, and every chip would go
    blank while every test here stayed green."""
    src = pathlib.Path(agent.__file__).read_text()
    block = src[src.index('"type": "TOOL_CALL_END"'):]
    block = block[:block.index("elif event_type ==", 10)]
    assert "take_query_provenance(payload)" in block, (
        "the loop takes the live record instead of this tool call's stashed one")


def test_the_prompt_tells_the_model_to_read_the_source_line():
    """**The two halves are bound here on purpose.** The tool discloses which WebACL it used; only the
    model can tell whether that is the one the user asked about, because the tool never receives the
    question. So the disclosure is worthless without an instruction that consumes it, and an
    instruction is worthless if the disclosure gets renamed. Asserted from both sides so neither can
    drift alone.

    The prompt bullet this replaces read "After WebACL is selected: ALWAYS call get_waf_config",
    which is satisfied once and stays satisfied. Nothing covered a user naming a different WebACL
    halfway through a conversation, which is exactly what happened."""
    prompt = pathlib.Path(agent.__file__).read_text()
    # Cut the prompt out of the file so a mention of SOURCE in unrelated Python cannot satisfy this.
    start = prompt.index("## Behavior")
    behaviour = prompt[start:prompt.index("\n## ", start + 10)]
    assert "SOURCE:" in behaviour, (
        "the prompt does not mention the SOURCE line, so nothing instructs the model to compare the "
        "WebACL a result came from against the one the user asked about")
    assert "not a one-time setup step" in behaviour, (
        "the instruction to re-call get_waf_config mid-conversation is gone; the original wording was "
        "satisfiable once and that is how a question about one WebACL got answered from another")
    assert "SOURCE:" in provenance_source_line(_record(CWL)), "the emitter no longer produces the marker"
