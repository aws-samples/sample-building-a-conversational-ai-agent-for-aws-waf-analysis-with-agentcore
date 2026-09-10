# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Independent queries run at once, and a batch that runs out of budget says so.

ROADMAP 4.6. The bypass scan's six anomaly filters never read each other's output, so the
serial chain's wall time was the sum for no reason. Making them concurrent is the
non-destructive half of the chain-length work: unlike 3.4's drill-down-to-candidates it
drops no analysis dimension.

**The risk in this change is not slowness, it is a new way to have no rows.** Before, a
section was empty because the query failed or because nothing matched, and 0.17.0 made those
two distinguishable. A fan-out adds a third: the batch budget expired with this query still
outstanding. If that arrives as `[]` it renders as "(none found)", which is the same wrong
answer in a new disguise. So most of this file is about the partition of outcomes rather
than about speed.

Concurrency is asserted with a `Barrier` rather than by timing. A barrier of N releases only
if N jobs are genuinely in flight at once, so it proves the property instead of inferring it
from a duration that a loaded machine can invalidate. The one timing assertion left is the
one whose subject IS a duration, and it has a wide margin.
"""

import concurrent.futures
import itertools
import re
import threading
import time

import pytest

from tools import waf_bypass as B
from tools import waf_query as Q
from tools.query_limits import MAX_FANOUT_WAIT

ROW = {"httpRequest.clientIp": "203.0.113.9", "total": "9", "unique_uris": "9",
       "cnt": "9", "ja4Fingerprint": "t13d1516h2", "ua": "curl/8.0",
       "unique_uas": "9", "unique_ips": "9"}


# --- the primitive ----------------------------------------------------------


def test_every_job_lands_in_exactly_one_of_results_and_reasons():
    """The contract the callers rely on. A key in neither would render as an empty result,
    and a key in both would let a caller pick whichever it read first."""
    def boom():
        raise RuntimeError("nope")
    jobs = {"ok": lambda: ["row"], "empty": lambda: [], "raised": boom}
    results, reasons = Q.run_concurrently(jobs)
    assert set(results) | set(reasons) == set(jobs)
    assert not (set(results) & set(reasons))
    # An empty return is a RESULT, not a reason. Collapsing the two is the defect.
    assert results["empty"] == []
    assert "nope" in reasons["raised"]


def test_one_job_raising_does_not_lose_the_others():
    """`future.result()` re-raises at collection, so an unguarded loop body would abandon
    every job not yet collected. Five of six sections should not vanish because one query
    hit an unexpected error."""
    def boom():
        raise ValueError("one bad job")
    jobs = {f"ok{i}": (lambda: ["row"]) for i in range(5)}
    jobs["bad"] = boom
    results, reasons = Q.run_concurrently(jobs)
    assert len(results) == 5 and list(reasons) == ["bad"]


def test_jobs_really_run_at_the_same_time():
    """Five jobs must be in flight together, or nothing about this change is true.

    A `Barrier(5)` releases only when the fifth job arrives. Run serially the first job
    blocks until the barrier's own timeout and the assertion fails, so this cannot pass on a
    sequential implementation."""
    barrier = threading.Barrier(5, timeout=10)
    def job():
        barrier.wait()
        return ["row"]
    results, reasons = Q.run_concurrently({f"j{i}": job for i in range(5)})
    assert reasons == {}, reasons
    assert len(results) == 5


def test_concurrency_is_capped_at_the_worker_count():
    """The other side of the same property, and the one that protects Athena's account-level
    active-DML quota. Six jobs with five workers must NOT all be in flight, so a barrier of
    six has to time out. Without the cap a scenario tool would submit its whole chain at
    once and compete with patrol's five for the same quota."""
    barrier = threading.Barrier(6, timeout=1)
    hit = []
    def job():
        try:
            barrier.wait()
            hit.append("all six at once")
        except threading.BrokenBarrierError:
            pass
        return ["row"]
    Q.run_concurrently({f"j{i}": job for i in range(6)}, budget=20)
    assert hit == [], "six jobs ran concurrently, so the worker cap is not applied"


def test_a_job_past_the_budget_is_reported_rather_than_waited_for():
    """Two claims, and the second is the 2.3 defect.

    A job still running at the budget must land in `reasons`. And this must RETURN at the
    budget: `Executor.__exit__` calls `shutdown(wait=True)`, so a `with` block would block
    here until the slow job finished, making the budget bound when collecting stops rather
    than when the caller is freed. The margin is wide because the subject is a duration."""
    # The slow job waits on an event this test releases rather than on a `sleep`. Abandoned
    # pool threads are non-daemon, so the interpreter joins them at exit: a `sleep(10)` here
    # cost the whole suite ten seconds AFTER the assertions had already passed.
    started, release = threading.Event(), threading.Event()
    def slow():
        started.set()
        release.wait(timeout=30)
        return ["row"]
    began = time.monotonic()
    try:
        results, reasons = Q.run_concurrently({"fast": lambda: ["row"], "slow": slow},
                                              budget=1)
        elapsed = time.monotonic() - began
    finally:
        release.set()
    assert started.is_set(), "the slow job never started, so the budget was not what ended this"
    assert list(results) == ["fast"]
    assert list(reasons) == ["slow"]
    assert str(MAX_FANOUT_WAIT) in reasons["slow"] or "budget" in reasons["slow"]
    assert elapsed < 5, f"returned in {elapsed:.1f}s, so it waited for the abandoned job"


# --- the scan ---------------------------------------------------------------


@pytest.fixture
def offline(monkeypatch):
    """Everything `_step_scan` reaches outside the query layer."""
    monkeypatch.setattr(B, "_check_coverage_gaps", lambda: [])
    monkeypatch.setattr(B, "get_client", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("no AWS in tests")))
    monkeypatch.setattr(B, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(B, "get_scope", lambda: "CLOUDFRONT")
    monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)


def test_the_scan_issues_its_six_queries_concurrently(monkeypatch, offline):
    """End to end through the real `_step_scan`, so a query that never got deferred fails
    here rather than just making the suite slower.

    **The barrier is gated to the first five arrivals, and leaving that out is what made the
    first version of this test hollow.** A `Barrier` is REUSABLE: once five parties release
    it, it rearms. The scan has six queries, so the sixth arrived at a rearmed barrier,
    waited alone for the full timeout and raised `BrokenBarrierError` inside the fake, which
    `_safe_query` dutifully recorded as a query failure. The test passed on a report where
    every section had failed, took ten seconds, and asserted nothing about concurrency. The
    assertions below now require the queries to have SUCCEEDED, which is what closes that."""
    gate = threading.Barrier(5, timeout=10)
    arrivals = itertools.count()

    def fake_query_logs(cwl, athena, start, end, limit=25):
        # `next` on a count is atomic in CPython, so exactly five threads take the barrier.
        if next(arrivals) < 5:
            gate.wait()
        return [dict(ROW)]

    monkeypatch.setattr(B, "query_logs", fake_query_logs)
    began = time.monotonic()
    out = B._step_scan(0, 3600)
    assert "## Bypass Scan Results" in out
    assert "batch of concurrent log queries" not in out
    # Every section answered. Without this the barrier could break and the test still pass.
    assert "the query for this section failed" not in out
    assert "(none found)" not in out
    assert time.monotonic() - began < 5, "the barrier released late, so five never overlapped"


def test_a_batch_timeout_never_reads_as_no_findings(monkeypatch, offline):
    """The wrong answer this change could have introduced. Every query is still outstanding
    when the budget expires, so every section is empty, and the old serial code's rendering
    would call that a clean scan."""
    release = threading.Event()
    monkeypatch.setattr(B, "query_logs",
                        lambda *a, **k: (release.wait(timeout=30), [dict(ROW)])[1])
    monkeypatch.setattr(B, "run_concurrently",
                        lambda jobs, **k: Q.run_concurrently(jobs, budget=1))
    try:
        out = B._step_scan(0, 3600)
    finally:
        release.set()
    assert "No Obvious Bypass Candidates Found" not in out
    assert "Cannot Say Whether Bypass Candidates Exist" in out
    assert "(none found)" not in out
    assert "batch of concurrent log queries" in out


def test_the_scan_registers_a_job_for_every_section_that_reports_one(monkeypatch, offline):
    """The pairing invariant between the two halves of this change.

    A label registered as a job but never rendered is a query paid for and thrown away; a
    label rendered but never registered gets `_empty_reason`'s "(none found)" forever,
    because no job can ever record a reason for it. Both directions matter, so the job keys
    and the rendered labels are compared as sets."""
    seen: dict = {}
    monkeypatch.setattr(B, "query_logs", lambda *a, **k: [dict(ROW)])
    real = Q.run_concurrently
    monkeypatch.setattr(B, "run_concurrently",
                        lambda jobs, **k: (seen.update({"keys": set(jobs)}), real(jobs, **k))[1])
    B._step_scan(0, 3600)
    assert seen["keys"], "no jobs registered, so this proves nothing"

    # `_step_scan`'s own source, so this reads what the renderer asks for rather than what a
    # fixture happened to exercise. Sliced to the function to keep the other steps' labels out.
    import inspect
    body = inspect.getsource(B._step_scan)
    rendered = set(re.findall(r'_empty_reason\(failures,\s*"([a-z0-9_]+)"', body))
    assert rendered, "no rendered labels parsed, so this proves nothing"
    assert seen["keys"] == rendered, {"registered only": seen["keys"] - rendered,
                                      "rendered only": rendered - seen["keys"]}
