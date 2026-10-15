#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_overview_old_window.py` fail?

One case per mechanism the live window 2026-09-08 04:00 needed, each restoring the shipped
behaviour of that mechanism alone: the period chosen by window length, SEARCH as the only source,
the week-long solved period, the window length as a period, a failure read as zero or as none.
"""

import sys

from _harness import sweep

T = "tests/test_overview_old_window.py"
O = "tools/waf_overview.py"
P = "tools/waf_patrol.py"
B = "tools/waf_bypass.py"

CASES = [
    ("the period chosen by window length alone",
     [(O, "    return max(period, _period_for_window(int(start.timestamp())) or 3600)", "    return period")],
     [f"{T}::test_the_period_is_never_finer_than_cloudwatch_keeps",
      f"{T}::test_no_query_type_asks_for_points_cloudwatch_no_longer_holds",
      f"{T}::test_top_rules_on_an_old_window_finds_the_rule_search_missed"], True),

    ("top_rules reading SEARCH alone",
     [(O, "    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope,\n"
          "                                              region=region, rules=rules)",
       "    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope,\n"
       "                                              region=region)")],
     [f"{T}::test_top_rules_on_an_old_window_finds_the_rule_search_missed"], True),

    ("the overview never reading the configuration",
     [(O, '            rules = waf.get_web_acl(Name=webacl_name, Scope=waf_scope, Id=acl["Id"])["WebACL"].get("Rules", [])',
       "            rules = None")],
     [f"{T}::test_top_rules_on_an_old_window_finds_the_rule_search_missed",
      f"{T}::test_rate_limits_reads_each_rate_rule_by_its_metric_name"], True),

    ("a failed configuration read left unsaid in top_rules",
     [(O, "    if rules is None:\n        lines.append(f\"⚠️ The WebACL configuration could not be read",
       "    if False:\n        lines.append(f\"⚠️ The WebACL configuration could not be read")],
     [f"{T}::test_a_failed_config_read_is_disclosed_in_top_rules"], True),

    ("a window past 455 days sent to CloudWatch anyway",
     [(O, "    if _period_for_window(int(start.timestamp())) is None:", "    if False:")],
     [f"{T}::test_a_window_past_every_retention_says_so"], True),

    ("rate rules looked up by rule name instead of metric name",
     [(O, '    lit = {(r.get("VisibilityConfig") or {}).get("MetricName") or r["Name"]: r["Name"] for r in rate',
       '    lit = {r["Name"]: r["Name"] for r in rate')],
     [f"{T}::test_rate_limits_reads_each_rate_rule_by_its_metric_name"], True),

    ("rate rules counting only block and challenge again",
     [(O, '    keys = ("blocked", "challenge", "captcha", "counted")', '    keys = ("blocked", "challenge")')],
     [f"{T}::test_rate_limits_reads_each_rate_rule_by_its_metric_name"], True),

    ("a rate rule with metrics off left unnamed",
     [(O, "    if dark:\n", "    if False:\n")],
     [f"{T}::test_rate_limits_names_a_rate_rule_with_metrics_off"], True),

    ("a failed configuration read reported as no rate rules",
     [(O, "    if rules is None:\n        lines.append(f\"  ⚠️ The WebACL configuration could not be read ({rules_error}), so which rules \"",
       "    if rules is None:\n        rules = []\n    if False:\n        lines.append(f\"  ⚠️ The WebACL configuration could not be read ({rules_error}), so which rules \"")],
     [f"{T}::test_rate_limits_does_not_report_no_rate_rules_when_the_config_read_failed"], True),

    ("the challenge counts read through SEARCH alone",
     [(O, "    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope, region=region, rules=[])",
       "    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope, region=region)")],
     [f"{T}::test_challenge_counts_search_missed_are_read_directly"], True),

    ("solved counts read at a week again",
     [(P, '    period = _period_for_window(int(start.timestamp())) or 3600\n    resp = cw.get_metric_data(\n        MetricDataQueries=[\n            {"Id": "cs"',
       '    period = 604800\n    resp = cw.get_metric_data(\n        MetricDataQueries=[\n            {"Id": "cs"')],
     [f"{T}::test_solved_counts_are_read_for_the_window_not_a_week"], True),

    ("a failed solved read printed as zero",
     [(O, '        cs = cas = None\n        solved_error = f"{type(e).__name__}: {e}"',
       '        cs = cas = 0\n        solved_error = ""')],
     [f"{T}::test_a_failed_solved_read_is_not_zero"], True),

    ("the mitigated check using the window length as its period",
     [(O, '    period = _period_for_window(int(start.timestamp())) or 3600\n    resp = cw.get_metric_data(\n        MetricDataQueries=[\n            {"Id": f"m{i}"',
       '    period = int((end - start).total_seconds())\n    resp = cw.get_metric_data(\n        MetricDataQueries=[\n            {"Id": f"m{i}"')],
     [f"{T}::test_a_window_clipped_at_now_is_still_checked"], True),

    ("a failed mitigated check read as no activity",
     [(O, '        return [f"  ⚠️ The breakdown is empty',
       '        return [none]\n        return [f"  ⚠️ The breakdown is empty')],
     [f"{T}::test_a_failed_check_is_not_read_as_no_activity"], True),

    ("every query sent in one call whatever its size",
     [(P, '    for i in range(0, len(queries), 500):\n        kw = {"MetricDataQueries": queries[i:i + 500]',
       '    for i in range(0, len(queries), 100000):\n        kw = {"MetricDataQueries": queries[i:i + 100000]')],
     [f"{T}::test_a_webacl_with_many_rules_is_read_in_calls_cloudwatch_accepts"], True),

    ("the first page taken as the whole answer",
     [(P, '            if not resp.get("NextToken"):\n                break', '            if True:\n                break')],
     [f"{T}::test_a_paged_answer_is_joined"], True),

    ("bypass reading ALL through SEARCH",
     [(B, "    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=7 * 86400, scope=scope, region=region, rules=[])",
       "    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=7 * 86400, scope=scope, region=region)")],
     [f"{T}::test_bypass_volume_reads_all_without_search"], True),

    ("the gap line no longer naming the 14-day cause",
     [(O, "or a managed sub-rule whose metric CloudWatch's SEARCH-based discovery has not indexed in the last 14 days (rules in the WebACL's configuration are read directly).",
       "or a managed sub-rule that does not publish a metric.")],
     [f"{T}::test_top_rules_gap_detection_names_both_possible_causes"], False),
]

sys.exit(sweep(CASES))
