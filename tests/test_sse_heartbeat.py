# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The SSE stream must not go silent while a query runs.

`agent.py`'s consume loop was a bare `await q.get()`, and the streaming callback emits on
text tokens, TOOL_START and TOOL_END only. So a four-minute Athena query was four minutes
of zero bytes on the wire, with the input box disabled and no stop control, which is
indistinguishable from a crash.

The behaviour worth testing is what happens when *nothing* happens, so the waiting had to
come out of the `create_app` closure to be reachable at all.
"""

import asyncio

import pytest

import agent
from tools import waf_athena as A


@pytest.fixture(autouse=True)
def no_progress():
    """Default to no query in flight, so each test states its own."""
    A._query_progress = None
    yield
    A._query_progress = None


async def _collect(q, n, timeout):
    """Take `n` items from the heartbeat-wrapped queue."""
    it = agent._queue_with_heartbeat(q, timeout=timeout).__aiter__()
    return [await it.__anext__() for _ in range(n)]


def test_a_quiet_queue_produces_beats_rather_than_silence():
    """The defect, stated directly: nothing on the queue used to mean nothing on the wire."""
    async def run():
        q = asyncio.Queue()
        return await _collect(q, 3, timeout=0.02)

    items = asyncio.run(asyncio.wait_for(run(), timeout=5))
    assert items == [agent._BEAT, agent._BEAT, agent._BEAT]


def test_beats_do_not_swallow_or_delay_real_items():
    """A heartbeat must be something the loop does *while* waiting, not instead of
    receiving. If it consumed the item it was racing, the stream would lose events."""
    async def run():
        q = asyncio.Queue()
        q.put_nowait(("TEXT", "hello"))
        first = await _collect(q, 1, timeout=5)
        return first

    assert asyncio.run(asyncio.wait_for(run(), timeout=5)) == [("TEXT", "hello")]


def test_the_beat_sentinel_is_not_the_end_of_stream_marker():
    """`None` already means end-of-stream on this queue: the agent thread puts it there in
    a `finally`. A heartbeat sharing that value would end the response instead of keeping
    it open, which is the exact opposite of the fix."""
    assert agent._BEAT is not None
    async def run():
        q = asyncio.Queue()
        q.put_nowait(None)
        return await _collect(q, 1, timeout=5)

    got = asyncio.run(asyncio.wait_for(run(), timeout=5))
    assert got == [None] and got[0] is not agent._BEAT


# --- what a beat carries ----------------------------------------------------


def test_an_idle_beat_is_a_bare_sse_comment():
    """Comment lines are ignored by clients while holding the connection open, which is all
    that is needed when there is nothing to report."""
    assert agent._heartbeat() == ":\n\n"


def test_a_beat_during_a_query_reports_what_it_has_scanned():
    """`get_query_execution` returns DataScannedInBytes while the query is still running, so
    the poll loop was already fetching this and discarding it."""
    A._query_progress = {"engine": "Athena", "state": "RUNNING",
                         "scanned_bytes": 2_100_000_000, "elapsed": 45.4, "budget": 120}
    beat = agent._heartbeat()
    assert beat.startswith("data: ")
    assert '"query_progress"' in beat
    assert "2.10 GB" in beat
    assert "45s of 120s" in beat


def test_small_scans_are_reported_in_megabytes():
    """0.00 GB is not a progress report."""
    A._query_progress = {"engine": "Athena", "state": "RUNNING",
                         "scanned_bytes": 4_300_000, "elapsed": 3.2, "budget": 120}
    assert "4 MB" in agent._heartbeat()


def test_a_broken_progress_snapshot_degrades_to_a_comment(monkeypatch):
    """A heartbeat must never be the thing that breaks the stream. Its whole job is to keep
    the connection open, so any failure reading progress has to fall back rather than raise
    through the generator."""
    monkeypatch.setattr(A, "_query_progress", {"engine": "Athena"})  # missing keys
    assert agent._heartbeat() == ":\n\n"


# --- the publisher side -----------------------------------------------------


def test_progress_is_cleared_on_every_exit_path(monkeypatch):
    """A stale snapshot would have the heartbeat reporting a query that finished, and on the
    timeout path it would claim a query is running after the caller was told it stopped."""
    import time as _t
    monkeypatch.setattr(_t, "sleep", lambda s: None)
    monkeypatch.setattr(A.time, "monotonic", lambda: 0.0)  # never reach the deadline

    class Ok:
        def get_query_execution(self, QueryExecutionId):
            return {"QueryExecution": {"Status": {"State": "SUCCEEDED"},
                                       "Statistics": {"DataScannedInBytes": 5}}}

    A._query_progress = {"stale": True}
    A._wait_query(Ok(), "q-1")
    assert A.query_progress() is None, "success must clear it"

    class Fails:
        def get_query_execution(self, QueryExecutionId):
            return {"QueryExecution": {"Status": {"State": "FAILED",
                                                  "StateChangeReason": "boom"}}}

    A._query_progress = {"stale": True}
    with pytest.raises(RuntimeError):
        A._wait_query(Fails(), "q-1")
    assert A.query_progress() is None, "failure must clear it"


def test_progress_is_published_while_the_query_runs(monkeypatch):
    """Otherwise the heartbeat has nothing to say and the whole progress half is dead."""
    clock = {"t": 0.0}
    monkeypatch.setattr(A.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    monkeypatch.setattr(A.time, "monotonic", lambda: clock["t"])
    seen = []

    class Running:
        def get_query_execution(self, QueryExecutionId):
            seen.append(A.query_progress())
            return {"QueryExecution": {"Status": {"State": "RUNNING"},
                                       "Statistics": {"DataScannedInBytes": 7_000_000}}}

    with pytest.raises(RuntimeError):
        A._wait_query(Running(), "q-1")
    # The first poll sees nothing yet; every later one sees the previous snapshot.
    published = [s for s in seen if s]
    assert published, "no progress was ever published"
    assert published[-1]["scanned_bytes"] == 7_000_000
    assert published[-1]["state"] == "RUNNING"
    assert published[-1]["budget"] == A.MAX_POLL
