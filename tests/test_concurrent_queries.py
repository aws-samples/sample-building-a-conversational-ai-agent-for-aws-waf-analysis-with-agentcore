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

    def fake_query_logs(cwl, athena, start, end, limit=25, **kw):
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


# --- investigate_block, the second 4.6 target ------------------------------


BLOCK_ROW = {"terminatingRuleId": "SomeRule", "terminatingRuleType": "RATE_BASED",
             "action": "BLOCK", "hits": "9", "peak_rpm": "9", "avg_rpm": "9",
             "sub_rule": "SubRule", "httpRequest.uri": "/x",
             "httpRequest.httpMethod": "GET"}

# label -> a string that appears only in that query's pair, so one query can be failed
# without touching the other four. Verified by the completeness test below.
ONLY_IN = {
    "block": "by terminatingRuleId, terminatingRuleType",
    "ratio": "as hits by action",
    "freq": "as peak_rpm",
    "multi": "action != 'ALLOW'",
    "uri": "httpRequest.httpMethod",
}


def _fake_block_query(fail_marker=None):
    def run(cwl, athena, start, end, limit=25, **kw):
        if fail_marker and fail_marker in f"{cwl}\n{athena}":
            return [{"_error": "CloudWatch Logs Insights did not finish within 120 seconds."}]
        return [dict(BLOCK_ROW)]
    return run


def test_the_investigation_registers_exactly_the_independent_queries(monkeypatch):
    """Five of six. The sub-rule lookup is excluded because whether it runs depends on the
    primary rule's TYPE, which only the block query can tell us, so it cannot join the wave.
    Asserted as a set: adding a sixth job without checking its dependencies is the way this
    change turns into a wrong answer rather than a slow one."""
    from tools import waf_block_fp as F

    seen = {}
    monkeypatch.setattr(F, "query_logs", _fake_block_query())
    real = Q.run_concurrently
    monkeypatch.setattr(F, "run_concurrently",
                        lambda jobs, **k: (seen.update({"k": set(jobs)}), real(jobs, **k))[1])
    F._investigate_gather("203.0.113.9", 0, 3600)
    assert seen["k"] == {"block", "ratio", "freq", "multi", "uri"}, seen["k"]


def test_each_markers_string_identifies_exactly_one_query(monkeypatch):
    """The precondition for the sweep below, and it is the part that could silently rot. If a
    marker matched two queries, "failing only the ratio query" would fail two and the
    refusal test would pass for the wrong reason."""
    from tools import waf_block_fp as F

    captured = []
    monkeypatch.setattr(F, "query_logs", _fake_block_query())
    real = Q.run_concurrently
    monkeypatch.setattr(F, "run_concurrently",
                        lambda jobs, **k: (captured.append(jobs), real(jobs, **k))[1])
    F._investigate_gather("203.0.113.9", 0, 3600)
    jobs = captured[0]
    assert set(jobs) == set(ONLY_IN), (set(jobs), set(ONLY_IN))
    # Re-run each job with a recording query layer to get its text back.
    texts = {}
    def capture(cwl, athena, start, end, limit=25, **kw):
        texts[len(texts)] = f"{cwl}\n{athena}"
        return [dict(BLOCK_ROW)]
    monkeypatch.setattr(F, "query_logs", capture)
    for label, job in jobs.items():
        before = len(texts)
        job()
        texts[label] = texts.pop(before)
    for label, marker in ONLY_IN.items():
        hits = [l for l, t in texts.items() if marker in t]
        assert hits == [label], f"{marker!r} matches {hits}, not just {label}"


@pytest.mark.parametrize("label", sorted(ONLY_IN))
def test_one_failed_query_refuses_the_investigation_rather_than_degrading(monkeypatch, label):
    """The invariant that makes this a latency change and not a behaviour change.

    The false-positive verdict branches on `allow_count == 0`, which it reads as "this IP was
    only ever blocked" and leans toward a real attack. `allow_count` comes from the ratio
    query, so a failed ratio query produces exactly that value: a query that did not run,
    turned into evidence against the user's IP. Same for `peak_rpm` (freq) and
    `rules_triggered` (multi). 0.18.0 removed that shape from the bypass verdict and a
    fan-out that absorbed failures into `reasons` would put it back here.

    Swept over all five rather than tested on ratio alone, because the next person to add a
    job is who this protects, and a per-query test only covers the ones someone remembered."""
    from tools import waf_block_fp as F

    monkeypatch.setattr(F, "query_logs", _fake_block_query(ONLY_IN[label]))
    with pytest.raises(RuntimeError) as exc:
        F._investigate_gather("203.0.113.9", 0, 3600)
    assert label in str(exc.value), str(exc.value)
    assert "did not finish" in str(exc.value)


def test_the_investigation_runs_its_five_queries_concurrently(monkeypatch):
    """Gated to five arrivals, since there are exactly five jobs and a `Barrier` rearms."""
    from tools import waf_block_fp as F

    gate = threading.Barrier(5, timeout=10)
    arrivals = itertools.count()

    def run(cwl, athena, start, end, limit=25, **kw):
        if next(arrivals) < 5:
            gate.wait()
        return [dict(BLOCK_ROW)]

    monkeypatch.setattr(F, "query_logs", run)
    began = time.monotonic()
    data = F._investigate_gather("203.0.113.9", 0, 3600)
    assert data is not None
    assert time.monotonic() - began < 5, "the barrier released late, so five never overlapped"


def test_the_sub_rule_query_is_not_in_the_wave(monkeypatch):
    """It is data-dependent: it runs only when the primary rule is a MANAGED_RULE_GROUP,
    which only the block query's result reveals. If it ever joined the wave it would run
    against a rule type nobody had read yet, so this pins it outside.

    The barrier is sized to the wave, so a sixth arrival inside it would block and this test
    would time out rather than quietly pass."""
    from tools import waf_block_fp as F

    order, lock = [], threading.Lock()
    gate = threading.Barrier(5, timeout=10)
    arrivals = itertools.count()

    def classify(cwl, athena):
        text = f"{cwl}\n{athena}"
        if "ruleGroupList" in cwl or "UNNEST(rulegrouplist)" in athena:
            return "sub"
        for label, marker in ONLY_IN.items():
            if marker in text:
                return label
        # `_gather_match_detail` runs a further query after the sub-rule lookup. Classified
        # rather than lumped in with the wave: the first version of this test asserted the
        # sub-rule query ran LAST, and it does not, so the assertion failed on correct code.
        # What the ordering claim is actually about is the wave, not the tail.
        return "other"

    def run(cwl, athena, start, end, limit=25, **kw):
        kind = classify(cwl, athena)
        if kind in ONLY_IN and next(arrivals) < 5:
            gate.wait()
        with lock:
            order.append(kind)
        return [dict(BLOCK_ROW, terminatingRuleType="MANAGED_RULE_GROUP")]

    monkeypatch.setattr(F, "query_logs", run)
    data = F._investigate_gather("203.0.113.9", 0, 3600)
    assert order.count("sub") == 1, order
    assert set(order[:5]) == set(ONLY_IN), f"the wave is not the first five: {order}"
    assert order.index("sub") > 4, f"the sub-rule query ran inside the wave: {order}"
    assert data["sub_rule"] == "SubRule"


# --- analyze_ip, the third 4.6 target --------------------------------------
#
# `analyze_ip` runs a diversity check first (phase 1), which decides whether the IP is a shared
# NAT and whether phase 2 runs at all, so it stays sequential. Phase 2's five queries are
# independent and run in one wave. The mock keeps diversity low (ua_count/ja4_count <= 3) so the
# NAT branch is skipped and phase 2 is reached; the diversity query is the only one carrying
# `ua_count`, so it is easy to tell apart from the wave.

# Fields the five phase-2 queries' rows are read by, in one dict so any of them can return it.
AIP_ROW = {"action": "ALLOW", "terminatingRuleId": "r", "cnt": "9", "avg_rpm": "1",
           "peak_rpm": "1", "active_minutes": "1", "ja4Fingerprint": "t13d1516h2",
           "unique_uris": "1", "total_non_static": "1", "args": "?a=1", "hits": "1"}
AIP_PHASE2 = {"actions", "request_rate", "ja4", "uri_diversity", "query_strings"}


def _analyze_offline(monkeypatch):
    """Patch the query layer analyze_ip reaches. Both names are imported inside the function from
    `waf_query`, so the module attribute there is the patch point (patching `waf_logs` misses it)."""
    from tools import waf_query as WQ
    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: None)


def _is_diversity(cwl, athena):
    return "ua_count" in cwl or "ua_count" in athena


def test_analyze_ip_registers_its_five_phase_two_queries(monkeypatch):
    """The wave is exactly phase 2's five independent queries. A query dropped from it is one paid
    for serially or not at all; the diversity check and the NAT ua_list are phase 1 and must not be
    in the wave. Asserted as a set, so either direction of drift is caught."""
    from tools import waf_logs as L
    from tools import waf_query as WQ
    _analyze_offline(monkeypatch)

    def q(cwl, athena, start, end, limit=25, **kw):
        if _is_diversity(cwl, athena):
            return [{"ua_count": "1", "ja4_count": "1", "total": "9"}]
        return [dict(AIP_ROW)]
    monkeypatch.setattr(WQ, "query_logs", q)
    seen = {}
    real = WQ.run_concurrently
    monkeypatch.setattr(WQ, "run_concurrently",
                        lambda jobs, **k: (seen.update({"k": set(jobs)}), real(jobs, **k))[1])
    L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    assert seen.get("k") == AIP_PHASE2, seen.get("k")


def test_analyze_ip_runs_its_phase_two_queries_concurrently(monkeypatch):
    """Five phase-2 queries in flight at once. Gated to five arrivals, and the diversity query is
    excluded from the barrier, so run serially the first phase-2 query would wait alone until the
    barrier's timeout and this would exceed the margin."""
    from tools import waf_logs as L
    from tools import waf_query as WQ
    _analyze_offline(monkeypatch)

    gate = threading.Barrier(5, timeout=10)

    def q(cwl, athena, start, end, limit=25, **kw):
        if _is_diversity(cwl, athena):
            return [{"ua_count": "1", "ja4_count": "1", "total": "9"}]
        gate.wait()
        return [dict(AIP_ROW)]
    monkeypatch.setattr(WQ, "query_logs", q)
    began = time.monotonic()
    out = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    assert "## IP Analysis" in out
    assert time.monotonic() - began < 5, "the barrier released late, so five never overlapped"


def test_an_analyze_ip_batch_timeout_says_so_not_no_rows(monkeypatch):
    """The new way to have no rows a fan-out introduces. When the batch budget expires with the
    phase-2 queries still outstanding, the labels land in `reasons`; folding them into `failures`
    is what makes a section render the timeout rather than `_empty_reason`'s "(no requests)". Drop
    the fold and a timed-out query reads as a quiet window, the 0.17.0 defect under a speed heading."""
    from tools import waf_logs as L
    from tools import waf_query as WQ
    _analyze_offline(monkeypatch)

    release = threading.Event()

    def q(cwl, athena, start, end, limit=25, **kw):
        if _is_diversity(cwl, athena):
            return [{"ua_count": "1", "ja4_count": "1", "total": "9"}]
        release.wait(timeout=30)
        return [dict(AIP_ROW)]
    monkeypatch.setattr(WQ, "query_logs", q)
    # Capture the real one before patching, so the lambda does not call itself: analyze_ip imports
    # run_concurrently from `waf_query`, which is the same module object as Q, so patching it and
    # then calling Q.run_concurrently inside the patch would recurse. Capture the wave's job keys
    # too, so the count below is checked against the size of the wave rather than a literal 5.
    seen: dict = {}
    real = Q.run_concurrently
    monkeypatch.setattr(WQ, "run_concurrently",
                        lambda jobs, **k: (seen.update({"k": set(jobs)}), real(jobs, budget=1))[1])
    try:
        out = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    finally:
        release.set()
    # Every phase-2 section must say it timed out: query_strings was the one label with no
    # disclosure site, so its section vanished on a timeout instead of saying so. `in` passed on
    # the first of the other four; the count pins every section. Checked against the wave's own
    # size, not the literal 5, so a sixth query added later without a disclosure site fails here
    # rather than passing because 5 still happens to match its five disclosures.
    assert seen.get("k"), "phase 2 never ran, so this proves nothing"
    assert out.count("the query for this section failed") == len(seen["k"]), out
    assert "(no requests in this window)" not in out
    assert "(no query strings sent)" not in out, "the timeout must not read as an IP that sent none"
