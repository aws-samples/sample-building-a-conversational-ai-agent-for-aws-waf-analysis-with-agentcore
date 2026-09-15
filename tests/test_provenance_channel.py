# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Which WebACL, which window and which engine answered, sent as its own event.

ROADMAP 7.2. `SOURCE:` existed in one module and covered two of ten tools, and the plan was to add it to
the other eight. **Measured 2026-09-13, and that plan would have shown a user nothing**: `SOURCE:`
appeared nowhere in a verification answer while the same answer proved the line had been read, because it
noticed the loaded WebACL was the wrong one and reloaded before querying. The model consumes the line and
summarises it away.

So instruction-following is the link that is already failing, and a prompt rule telling the model to relay
the line would be a second layer on the same mechanism. These facts are recorded by the query layer and
emitted as a `CUSTOM` event the frontend renders, which is the one path whose visibility does not depend
on the model's cooperation.
"""

import pytest

import agent as A
from tools import session_state as S
from tools import waf_query as Q


@pytest.fixture(autouse=True)
def clean():
    S._state.pop("provenance", None)
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1",
                         log_destination="arn:aws:logs:r:1:log-group:lg")
    S.set_user_timezone(8.0)
    yield
    S._state.pop("provenance", None)


def test_a_log_query_records_the_engine_and_the_window(monkeypatch):
    monkeypatch.setattr(Q, "_run_cwl", lambda *a, **k: [])
    Q.query_logs("filter x", "SELECT 1", 1000, 4600, 5)
    p = S.take_query_provenance()
    assert p["engines"] == ["CloudWatch Logs Insights"]
    assert (p["start"], p["end"]) == (1000, 4600)
    assert p["webacl"] == "acl"
    assert p["tz_offset"] == 8.0
    assert p["queries"] == 1


def test_many_queries_in_one_tool_call_widen_the_window_and_count(monkeypatch):
    """**One tool call issues up to fifteen queries, so the record has to be a union rather than the last
    one.** A user told "CloudWatch, 12:37 to 18:37" deserves to know whether that describes one query or
    fifteen, and keeping only the final query's window would hide the widest thing that was read."""
    monkeypatch.setattr(Q, "_run_cwl", lambda *a, **k: [])
    # **The wide query goes first and the narrow one second, which is the whole discriminating power of
    # this test.** With the widest last, overwriting per query and taking the union give the same answer,
    # and the perturbation that replaces min/max with assignment passes. Found by the sweep reporting
    # HOLLOW on exactly that case.
    Q.query_logs("filter a", "SELECT 1", 1000, 5000, 5)
    Q.query_logs("filter b", "SELECT 1", 2000, 3000, 5)
    p = S.take_query_provenance()
    assert (p["start"], p["end"], p["queries"]) == (1000, 5000, 2)


def test_one_tool_call_reading_two_engines_names_both(monkeypatch):
    """**Not a hypothetical, and not deferred until the metric funnel lands.** Three tools pair a log
    query with a CloudWatch metric read in the same call, through `missed_data_warning` and
    `missed_action_warning`: `waf_injection`, `waf_challenge_check` and `waf_count_eval`. In
    `waf_count_eval` the log query is at line 55 and the metric read at line 490, so a single field
    holding the last writer would label a conclusion drawn from logs `CloudWatch metrics`, which is a
    misattribution of exactly the kind this record exists to prevent.

    In reading order, because a set's iteration order is randomised per process and this string is
    displayed."""
    monkeypatch.setattr(Q, "_run_cwl", lambda *a, **k: [])
    Q.query_logs("filter x", "SELECT 1", 1000, 2000, 5)
    S.note_query_provenance("CloudWatch metrics", 1000, 2000)
    S.note_query_provenance("CloudWatch metrics", 1500, 2500)
    p = S.take_query_provenance()
    assert p["engines"] == ["CloudWatch Logs Insights", "CloudWatch metrics"], p["engines"]
    assert p["queries"] == 3, "the count is per attempt, whichever engine was asked"


def test_the_record_is_cleared_on_read_so_the_next_tool_cannot_inherit_it(monkeypatch):
    """The defect this prevents is 0.24.0's in another form: a window from one question presented as the
    answer to another."""
    monkeypatch.setattr(Q, "_run_cwl", lambda *a, **k: [])
    Q.query_logs("filter x", "SELECT 1", 1000, 2000, 5)
    assert S.take_query_provenance()["queries"] == 1
    assert S.take_query_provenance() == {}


def test_a_tool_that_ran_no_log_query_records_nothing():
    """**And therefore emits nothing**, which is the point rather than an omission. A config-only tool has
    no window to disclose, and inventing one would be the defect this exists to fix."""
    assert S.take_query_provenance() == {}


def test_the_event_carries_the_record_and_names_the_tool_call():
    """Read off the source, because the emit sits inside an async generator whose other branches need a
    live Strands agent. What is asserted is the pairing: the event is emitted where `TOOL_CALL_END` is, it
    carries the tool call id so the frontend can attach it to the right chip, and an empty record emits
    nothing."""
    import inspect
    import re

    src = inspect.getsource(A)
    block = src[src.index('"type": "TOOL_CALL_END"'):]
    block = block[:block.index("elif event_type ==", 10)]
    assert "take_query_provenance" in block, "provenance is not read where the tool call ends"
    assert '"name": "provenance"' in block
    assert re.search(r"if _prov:", block), "an empty record must emit no event"
    # Asserted with `**_prov` attached, because `"toolCallId": payload` also appears on the
    # `TOOL_CALL_END` line three lines above and satisfied this on its own. The sweep reported HOLLOW.
    assert '"toolCallId": payload, **_prov' in block, (
        "the provenance event has to say which tool call it describes")


def test_the_frontend_attaches_it_to_the_chip_and_renders_both_window_renderings():
    """The other end of the channel, asserted on the source for the same reason.

    **The two renderings are the property, not decoration.** The local pair answers "is this the window I
    asked about" and the UTC pair answers "is this what the log store saw", and 0.24.0's timezone defect
    was invisible for exactly as long as only one of them was shown."""
    import pathlib

    app = pathlib.Path("frontend/src/App.jsx").read_text()
    assert "event.name === 'provenance'" in app, "the frontend ignores the event"
    assert "t.id === p.toolCallId" in app, "it has to land on the chip for that tool call"
    assert "function provenanceText" in app
    text = app[app.index("function provenanceText"):]
    text = text[:text.index("\n}\n")]
    assert "UTC" in text and "tz_offset" in text, "both renderings, from the offset the query used"
    assert "p.queries" in text, "how many queries the window describes"
    assert "p.engines" in text and ".join(" in text, (
        "a tool call can read two engines, so the chip names all of them rather than one")
    css = pathlib.Path("frontend/src/style.css").read_text()
    assert ".tool-src" in css, "rendered in the chip, not only in a title attribute"


_PAUSE = 0.4


class _PausingRecord(dict):
    """The record dict, holding the first writer between one merge's read and its write.

    The pause is what makes the interleaving a fact rather than a hope. It fires once, on the first read
    of the key under test, after that read has returned its value, so the paused writer resumes holding
    a value the other writer has since replaced.
    """

    def __init__(self, trigger, read, resume):
        super().__init__()
        self._trigger, self._read, self._resume = trigger, read, resume
        self._fired = False

    def _pause(self, key):
        if key == self._trigger and not self._fired:
            self._fired = True
            self._read.set()
            # The locked build waits this out, because the other writer cannot get in. 0.4 s against a
            # call that takes microseconds, so a slow machine changes the wait and not the verdict.
            self._resume.wait(_PAUSE)

    def get(self, key, *default):
        value = super().get(key, *default)
        self._pause(key)
        return value

    def __contains__(self, key):
        present = super().__contains__(key)
        self._pause(key)
        return present


@pytest.mark.parametrize("trigger,field,expected,broken", [
    ("queries", "queries", 2, 1),
    ("start", "start", 5_000, 10_000),
])
def test_the_lock_is_what_keeps_one_merge_from_overwriting_the_other(trigger, field, expected, broken):
    """**All three merges are read-modify-write and concurrency reaches them by default.**
    `run_concurrently` submits every independent query of a tool call to a `ThreadPoolExecutor` and
    `_cwl_semaphore` allows eight at once, so two threads read `queries` as 3 and both write 4.

    Both losses point the wrong way, and both are driven here. An undercount reports fifteen queries as
    fewer, which is the one thing the counter exists to say. A lost `min` reports a window narrower than
    what was read, so a finding from the earliest query is attributed to a window that starts later, and
    misattribution is what this record was built to prevent.

    **The interleaving is forced, not raced for.** This test used to be sixteen threads writing five
    hundred times each under `sys.setswitchinterval(1e-6)`, and it caught a lock-free build fifteen times
    out of fifteen locally. It then passed on one CI runner and failed on another against identical code,
    #111 against #112, so its verdict was a fact about the machine. A `dict` subclass stops the first
    writer between its read and its write instead, which puts the two orderings under this test's control
    and makes the same defect fail the same way on any machine.

    Two orderings rather than one, because the read the pause interposes on decides which merge loses.
    Paused at `queries`, the resuming writer holds a stale count and its increment lands on the same
    number the other writer already wrote. Paused at `"start" in p`, it holds "absent" and writes its own
    epoch over a lower one, which is the lost `min`."""
    import threading

    S.begin_tool_call("")
    read, resume = threading.Event(), threading.Event()
    S._state["provenance"] = {"": _PausingRecord(trigger, read, resume)}

    # The paused writer asks about the later window, so clobbering the other one narrows it.
    paused = threading.Thread(target=S.note_query_provenance, args=("E", 10_000, 20_000))
    paused.start()
    try:
        assert read.wait(5), "the pause was never reached, so this test proves nothing"
        S.note_query_provenance("E", 5_000, 15_000)
    finally:
        resume.set()
        paused.join(5)

    p = S.take_query_provenance()
    assert p[field] == expected, (
        f"{field} is {p[field]}, which is what a lost update leaves behind ({broken} when the two merges "
        f"overlap unprotected). Both writers ran, so {field} has to be {expected}.")


def test_the_athena_record_lands_before_table_resolution_can_block(monkeypatch):
    """**The record has to exist before anything that can block, or it lands in the next tool call.**

    What decides that is the distance from entering `query_logs` to the record, not the distance from the
    record to the engine call. Recorded after `_ensure_athena_table`, that distance was 48 lines, and on a
    cold session that call walks S3, enumerates Glue and runs a CREATE through `_wait_query`, whose
    deadline is `MAX_POLL` 120 s, the same number as `MAX_FANOUT_WAIT`. One slow CREATE can consume the
    whole batch budget, so a fan-out job can still be inside table resolution when the batch gives up. The
    tool returns, the record is drained, and the job then writes into the next tool call's record, where
    `setdefault` merges it and `engine` goes to the last writer.

    Reproduced before the fix: a tool that ran only CloudWatch queries over one hour showed
    `Athena over S3`, a 195-hour window and an inflated count.

    This holds the resolver open on an `Event` and asserts the record is already there, which is the only
    shape that distinguishes "written on entry" from "written eventually"."""
    import threading

    S._state.pop("provenance", None)
    held = threading.Event()
    entered = threading.Event()

    def blocking_resolve(dest):
        entered.set()
        held.wait(5)
        return "db.t"

    monkeypatch.setattr(Q, "_ensure_athena_table", blocking_resolve)
    monkeypatch.setattr(Q, "get_log_destination", lambda: "arn:aws:s3:::bucket")
    monkeypatch.setattr(Q, "_run_athena", lambda sql: [])
    monkeypatch.setattr(Q, "_scan_log_values", lambda rows: rows)
    from tools import waf_athena
    monkeypatch.setattr(waf_athena, "_athena_state", {}, raising=False)
    monkeypatch.setattr(waf_athena, "partition_predicate", lambda a, b: ("", None))

    worker = threading.Thread(
        target=lambda: Q.query_logs("filter x", "SELECT a FROM {TABLE} LIMIT {LIMIT}", 1000, 5000, 5))
    worker.start()
    try:
        assert entered.wait(5), "the resolver was never reached, so this test proves nothing"
        # The record is keyed by tool call since 2026-09-15; this fixture records outside one, so its
        # slot is the empty string.
        p = (S._state.get("provenance") or {}).get(S.current_tool_call(), {})
        assert p.get("engines") == ["Athena over S3"], (
            f"the record is not there while table resolution blocks: {p}. A fan-out job stuck here when "
            f"the batch times out would write into the next tool call's record.")
        assert (p.get("start"), p.get("end")) == (1000, 5000)
    finally:
        held.set()
        worker.join(5)
