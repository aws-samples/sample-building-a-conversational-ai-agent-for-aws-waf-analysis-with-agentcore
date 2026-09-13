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
    assert p["engine"] == "CloudWatch Logs Insights"
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
    css = pathlib.Path("frontend/src/style.css").read_text()
    assert ".tool-src" in css, "rendered in the chip, not only in a title attribute"


def test_concurrent_queries_do_not_lose_a_count_or_narrow_the_window():
    """**All three merges are read-modify-write and concurrency reaches them by default.**
    `run_concurrently` submits every independent query of a tool call to a `ThreadPoolExecutor` and
    `_cwl_semaphore` allows eight at once, so two threads read `queries` as 3 and both write 4.

    Both losses point the wrong way. An undercount reports fifteen queries as fewer, which is the one
    thing the counter exists to say. A lost `min` reports a window narrower than what was read, which
    attributes a finding from the earliest query to a window that starts later — a misattribution, which
    is what this record was built to prevent.

    Sixteen threads and five hundred writes each, because a lost update has to be near-certain rather
    than likely for the perturbation that removes the lock to fail reliably. Measured without the lock:
    the count came back short every run."""
    import sys
    import threading

    S._state.pop("provenance", None)
    THREADS, PER = 16, 500
    # **Without this the test is hollow, measured.** CPython's default switch interval is 5 ms, long
    # enough that a thread runs all five hundred cheap iterations before it is ever preempted, so the
    # threads do not interleave and the unlocked version passes. The sweep reported HOLLOW on exactly
    # that. Forcing a switch every microsecond makes the interleaving certain rather than likely.
    _interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)

    def work(offset):
        for i in range(PER):
            # Every thread walks its own window outward, so the true union is the widest pair and a
            # lost min or max is visible in the result rather than only in the count.
            S.note_query_provenance("E", 10_000 - offset - i, 10_000 + offset + i)

    threads = [threading.Thread(target=work, args=(t,)) for t in range(THREADS)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(_interval)

    p = S.take_query_provenance()
    assert p["queries"] == THREADS * PER, f"lost {THREADS * PER - p['queries']} increments"
    widest = 10_000 - (THREADS - 1) - (PER - 1)
    assert p["start"] == widest, f"window narrowed to {p['start']} from {widest}"
    assert p["end"] == 20_000 - widest
