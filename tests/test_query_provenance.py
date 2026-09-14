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


def _record(engine, subject=None):
    session_state._state.pop("provenance", None)
    session_state.note_query_provenance(engine, 1000, 2000, subject=subject)
    return session_state.peek_query_provenance()


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


def test_the_hook_leaves_the_record_for_the_chip_to_read():
    """Two readers, one record, and only the streaming loop may clear it. Reading destructively here
    would append the line for the model and leave the user's chip empty, which is the exact split the
    channel was built to close."""
    _context("shield-sample-webacl", LOG_GROUP_DEST)
    _record(CWL)
    agent.SourceDisclosure().append_source(_FakeEvent([{"text": "rows"}]))
    assert session_state.take_query_provenance().get("webacl") == "shield-sample-webacl", (
        "the hook drained the record, so the frontend has nothing to render")


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
