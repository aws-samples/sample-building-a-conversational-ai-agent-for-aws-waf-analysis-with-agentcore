#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.6: restore each defect the fan-out removed or could introduce, require red.

Two classes here. Reverting to serial should fail the concurrency claims. Getting the
fan-out subtly wrong should fail the outcome-partition claims, and those are the ones worth
the most: a batch timeout that renders as "(none found)" is the 0.17.0 defect reintroduced
by a change whose stated purpose was speed.
"""

import sys
import ast

from _harness import sweep

T = "tests/test_concurrent_queries.py"
PROBE_BLIND = "probe blind"
TEXTUAL = "textual"
SERIAL = """    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    results: dict = {}
    reasons: dict = {}
    futures = {executor.submit(job): key for key, job in jobs.items()}"""
CASES = [
    (
        "serial again, i.e. the chain whose wall time is the sum",
        "tools/waf_query.py",
        SERIAL,
        """    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    results: dict = {}
    reasons: dict = {}
    futures = {executor.submit(job): key for key, job in jobs.items()}""",
        [f"{T}::test_jobs_really_run_at_the_same_time",
         f"{T}::test_the_scan_issues_its_six_queries_concurrently"],
    ),
    (
        "the worker cap removed, i.e. a whole chain submitted against Athena's DML quota",
        "tools/waf_query.py",
        "                     workers: int = 5) -> tuple[dict, dict]:",
        "                     workers: int = 32) -> tuple[dict, dict]:",
        [f"{T}::test_concurrency_is_capped_at_the_worker_count"],
    ),
    (
        "shutdown waits, i.e. the 2.3 defect where the budget bounds collecting only",
        "tools/waf_query.py",
        "        executor.shutdown(wait=False, cancel_futures=True)",
        "        executor.shutdown(wait=True)",
        [f"{T}::test_a_job_past_the_budget_is_reported_rather_than_waited_for"],
    ),
    (
        "an unfinished job left out of both dicts, i.e. it renders as no rows",
        "tools/waf_query.py",
        "        for future, key in futures.items():\n"
        "            if key not in results and key not in reasons:\n"
        "                reasons[key] = fanout_timeout_message()",
        "        pass",
        [f"{T}::test_a_job_past_the_budget_is_reported_rather_than_waited_for",
         f"{T}::test_a_batch_timeout_never_reads_as_no_findings"],
    ),
    (
        "a raising job killing the rest of the collection",
        "tools/waf_query.py",
        "            try:\n"
        "                results[key] = future.result()\n"
        "            except Exception as exc:\n"
        "                reasons[key] = f\"{type(exc).__name__}: {exc}\"",
        "            results[key] = future.result()",
        [f"{T}::test_one_job_raising_does_not_lose_the_others",
         f"{T}::test_every_job_lands_in_exactly_one_of_results_and_reasons"],
    ),
    (
        "the scan discarding the batch reasons, i.e. a timeout reads as a clean scan",
        "tools/waf_bypass.py",
        "    results, reasons = run_concurrently(jobs)\n    failures.update(reasons)",
        "    results, reasons = run_concurrently(jobs)",
        [f"{T}::test_a_batch_timeout_never_reads_as_no_findings"],
    ),
    (
        "one section rendered but never queried, i.e. permanently (none found)",
        "tools/waf_bypass.py",
        '    later("datacenter", datacenter_cwl, datacenter_athena)\n',
        "",
        [f"{T}::test_the_scan_registers_a_job_for_every_section_that_reports_one"],
    ),
    (
        "analyze_ip back to reading the CloudWatch error row as data",
        "tools/waf_logs.py",
        "    reason = log_query_error(rows)\n"
        "    if reason:\n"
        "        return _record(reason)\n"
        "    return rows or []",
        "    return rows or []",
        ["tests/test_query_failure_visible.py::test_analyze_ip_sections_say_the_query_failed_instead_of_going_missing",
         "tests/test_window_cap.py::test_every_query_logs_caller_checks_for_an_error_row"],
    ),
    (
        "the quiet-IP claim made before the failure is checked",
        "tools/waf_logs.py",
        '    if failures.get("diversity"):',
        "    if False:",
        ["tests/test_query_failure_visible.py::test_analyze_ip_sections_say_the_query_failed_instead_of_going_missing",
         "tests/test_query_failure_visible.py::test_analyze_ip_survives_an_athena_raise"],
    ),
    (
        "one analyze_ip section back to vanishing instead of reporting",
        "tools/waf_logs.py",
        '        lines.append(_empty_reason(failures, "request_rate", "  (no requests in this window)"))',
        '        lines.append("")',
        ["tests/test_query_failure_visible.py::test_one_failed_section_does_not_erase_the_others"],
    ),
    (
        "the content sampler back to reading an error row as no matching content",
        "tools/waf_query.py",
        "        rows = query_logs(cwl, athena, start_epoch, end_epoch, limit=limit)\n"
        "        reason = log_query_error(rows)\n"
        "        if reason:\n"
        "            raise RuntimeError(reason)\n"
        "        return rows or []",
        "        return query_logs(cwl, athena, start_epoch, end_epoch, limit=limit) or []",
        ["tests/test_query_failure_visible.py::test_a_failed_content_sample_is_unavailable_not_absent"],
        PROBE_BLIND,
    ),
    (
        # Perturb the CODE the sweep guards, never the sweep's own variables. Setting
        # `spread = {}` makes the assertion pass, which is what the first version of this
        # entry did and then called the sweep hollow for not failing.
        "a second, unguarded query_logs call site in a funneled module",
        "tools/waf_logs.py",
        '        _failures: dict[str, str] = {}\n'
        '        results = _safe_query(query, athena_query, start_epoch, end_epoch,\n'
        '                              limit=params["limit"], failures=_failures, label="query")',
        '        from tools.waf_query import query_logs\n'
        '        _failures: dict[str, str] = {}\n'
        '        results = query_logs(query, athena_query, start_epoch, end_epoch,\n'
        '                             limit=params["limit"])',
        ["tests/test_window_cap.py::test_every_query_logs_caller_calls_it_from_exactly_one_place",
         "tests/test_window_cap.py::test_every_query_logs_caller_checks_for_an_error_row"],
        TEXTUAL,
    ),
    (
        "the investigation absorbing a failure instead of refusing, i.e. a query that did "
        "not run becomes evidence against the IP",
        "tools/waf_block_fp.py",
        '    results, reasons = run_concurrently(jobs)\n'
        '    if reasons:\n'
        '        raise RuntimeError("; ".join(f"{k}: {v}" for k, v in sorted(reasons.items())))',
        "    results, reasons = run_concurrently(jobs)\n"
        "    results = {k: results.get(k) or [] for k in jobs}",
        [f"{T}::test_one_failed_query_refuses_the_investigation_rather_than_degrading"],
    ),
    (
        "the data-dependent sub-rule query pulled into the wave",
        "tools/waf_block_fp.py",
        '    later("uri", uri_cwl, uri_athena)',
        '    later("uri", uri_cwl, uri_athena)\n'
        '    later("sub", block_cwl, block_athena)',
        [f"{T}::test_the_investigation_registers_exactly_the_independent_queries"],
    ),
    (
        "one investigation query dropped from the wave and left serial",
        "tools/waf_block_fp.py",
        '    later("multi", multi_cwl, multi_athena)',
        "    multi_results_unused = None",
        [f"{T}::test_the_investigation_registers_exactly_the_independent_queries",
         f"{T}::test_the_investigation_runs_its_five_queries_concurrently"],
    ),
]

# A case with no marker gets the reachability probe: the anchor is replaced with a bare raise
# and the targets must go red, or the line never executes and a green result from the real
# perturbation below would say nothing. A marker means the target reads source rather than
# running it, or that reachability is established elsewhere; each one says which in a comment.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
