#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Restore each swallow and require the tests that cover it to fail.

`ast.parse` runs before pytest on every perturbation: one that breaks the build fails at
collection rather than at the assertion, and the red output looks like proof.
"""

import sys

from _harness import sweep

T = "tests/test_query_failure_visible.py"
TEXTUAL = "textual"
CASES = [
    (
        "_safe_query swallows to [] again, i.e. the shipped behaviour",
        "tools/waf_bypass.py",
        "    try:\n"
        "        rows = query_logs(cwl, athena, start, end, limit)\n"
        "    except Exception as e:\n"
        "        return _record(f\"{type(e).__name__}: {e}\")\n"
        "    reason = log_query_error(rows)\n"
        "    if reason:\n"
        "        return _record(reason)\n"
        "    return rows or []",
        "    try:\n"
        "        return query_logs(cwl, athena, start, end, limit) or []\n"
        "    except Exception as e:\n"
        "        print(f\"[waf_bypass] query_logs error: {e}\", file=sys.stderr, flush=True)\n"
        "        return []",
        [T],
    ),
    (
        "the _error row passed through as data, i.e. the fabricated `| ? |` row",
        "tools/waf_bypass.py",
        "    reason = log_query_error(rows)\n"
        "    if reason:\n"
        "        return _record(reason)",
        "    reason = None\n"
        "    if reason:\n"
        "        return _record(reason)",
        [f"{T}::test_a_fabricated_row_is_never_rendered",
         f"{T}::test_safe_query_records_the_reason_and_returns_no_rows"],
    ),
    (
        "the clean-scan claim ungated, i.e. every query failed and it reads as clean",
        "tools/waf_bypass.py",
        "        if failures:\n"
        "            # The emptiness guard",
        "        if False:\n"
        "            # The emptiness guard",
        [f"{T}::test_a_scan_whose_queries_all_failed_does_not_report_a_clean_scan"],
    ),
    (
        "the verdict built on an unread label set, i.e. the false bypass call",
        "tools/waf_bypass.py",
        '    labels_unknown = "labels" in failures',
        "    labels_unknown = False",
        [f"{T}::test_a_failed_label_query_refuses_the_verdict"],
    ),
    (
        "one flag instead of a per-section reason, i.e. a failure erases what did answer",
        "tools/waf_bypass.py",
        "    reason = failures.get(label)",
        "    reason = next(iter(failures.values()), None)",
        [f"{T}::test_one_failed_query_marks_only_its_own_section"],
    ),
    (
        "_run_log_query swallows the Athena raise, i.e. the engine asymmetry",
        "tools/waf_count_eval.py",
        "    except Exception as exc:\n"
        "        raise LogQueryFailed(f\"{type(exc).__name__}: {exc}\") from exc",
        "    except Exception:\n"
        "        return []",
        [f"{T}::test_an_athena_failure_reaches_the_caller_like_a_cloudwatch_one",
         f"{T}::test_the_count_step_says_the_query_failed_instead_of_showing_no_clients"],
    ),
    (
        "waf_block_fp back to passing the _error row through as data",
        "tools/waf_block_fp.py",
        "    reason = log_query_error(results)\n"
        "    if reason:\n"
        "        raise RuntimeError(reason)\n"
        "    return results if results is not None else []",
        "    return results if results is not None else []",
        [f"{T}::test_the_remaining_wrappers_raise_on_a_cloudwatch_error_row",
         "tests/test_window_cap.py::test_every_query_logs_caller_checks_for_an_error_row"],
    ),
    (
        "the wrappers raising on everything, i.e. the constant a one-sided test allows",
        "tools/waf_challenge_check.py",
        "    reason = log_query_error(results)\n    if reason:",
        "    reason = log_query_error(results)\n    if True:",
        [f"{T}::test_the_remaining_wrappers_still_return_rows"],
    ),
    (
        "the sentinel check re-derived inline instead of shared",
        "tools/waf_bypass.py",
        "    reason = log_query_error(rows)",
        '    reason = str(rows[0]["_error"]) if rows and "_error" in rows[0] else None',
        ["tests/test_window_cap.py::test_the_error_row_check_is_written_once"],
        TEXTUAL,
    ),
    (
        "the verdict taken without the name it was made about, in count_eval",
        "tools/waf_count_eval.py",
        "        rule_name, bad = checked_rule_name(rule_name)\n"
        "        if bad:\n"
        "            return bad\n"
        "        return _step_check_clients(rule_name, start_time, duration_minutes)",
        "        bad = checked_rule_name(rule_name)[1]\n"
        "        if bad:\n"
        "            return bad\n"
        "        return _step_check_clients(rule_name, start_time, duration_minutes)",
        [f"{T}::test_a_padded_rule_name_reaches_the_query_without_its_padding"],
    ),
    (
        "the same in block_fp, where nothing downstream strips either",
        "tools/waf_block_fp.py",
        "        rule_name, bad = checked_rule_name(rule_name)",
        "        bad = checked_rule_name(rule_name)[1]",
        [f"{T}::test_a_padded_rule_name_reaches_the_query_without_its_padding"],
    ),
    (
        "the validator hands back the input, i.e. it decides on a copy it discards",
        "tools/waf_query.py",
        "    return name, None",
        "    return rule_name, None",
        [f"{T}::test_a_padded_rule_name_reaches_the_query_without_its_padding",
         f"{T}::test_a_legitimate_rule_name_still_gets_through"],
    ),
    (
        "a refused name echoed back for use rather than emptied",
        "tools/waf_query.py",
        '        return "", (f"Error: \'{rule_name}\' is not a rule name.',
        '        return rule_name, (f"Error: \'{rule_name}\' is not a rule name.',
        [f"{T}::test_a_legitimate_rule_name_still_gets_through"],
    ),
]

# A case with no marker gets the reachability probe: the anchor is replaced with a bare raise
# and the targets must go red, or the line never executes and a green result from the real
# perturbation below would say nothing. A marker means the target reads source rather than
# running it, or that reachability is established elsewhere; each one says which in a comment.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
