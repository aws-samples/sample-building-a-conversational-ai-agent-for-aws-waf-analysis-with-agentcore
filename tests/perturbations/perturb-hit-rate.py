#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.2: break each property `test_hit_rate.py` claims and require it to notice.

Same contract as the other perturbation runners: `ast.parse`, then a reachability probe, then the
real edit, with pytest's tail read as well as its exit code so a collection failure is not scored
as a caught defect. `TEXTUAL` marks a target read from source rather than executed.
"""

import sys

from _harness import sweep

T = "tests/test_hit_rate.py"
TEXTUAL = "textual"
CASES = [
    (
        "plain rounding, so a real match prints as 0.00%",
        "tools/waf_overview.py",
        '        if 0 < pct < 0.01:\n            return "<0.01%"\n',
        "",
        [f"{T}::test_a_small_nonzero_rate_is_not_printed_as_zero"],
    ),
    (
        "CountedRequests requested for the denominator, which double-counts",
        "tools/waf_overview.py",
        '{"Id": "raw_p", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchaRequests"',
        '{"Id": "raw_p", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CountedRequests"',
        [f"{T}::test_the_denominator_never_requests_counted_requests"],
        TEXTUAL,
    ),
    (
        "counted dropped from the numerator, so a Count rule reads 0%",
        "tools/waf_overview.py",
        "                     _rate(mitigated + counted)))",
        "                     _rate(mitigated)))",
        [f"{T}::test_a_counted_only_rule_still_gets_a_rate"],
    ),
    (
        "the rate computed on the SEARCH fallback denominator, silently",
        "tools/waf_overview.py",
        '    lines.append(_hdr + (f" {\'Hit rate\':>9}" if denom_exact else ""))',
        '    lines.append(_hdr + f" {\'Hit rate\':>9}")',
        [f"{T}::test_no_rate_column_when_the_denominator_came_from_the_fallback"],
    ),
    (
        "denom_exact never set, so the column disappears even when the denominator is good",
        "tools/waf_overview.py",
        "        denom_exact = True",
        "        denom_exact = False",
        [f"{T}::test_the_rate_uses_the_verified_denominator_and_says_what_it_is",
         f"{T}::test_a_small_nonzero_rate_is_not_printed_as_zero"],
    ),
    (
        "a zero denominator divided anyway",
        "tools/waf_overview.py",
        '        if not denom:\n            return "-"\n',
        "",
        [f"{T}::test_a_zero_denominator_yields_no_rate_rather_than_a_crash"],
    ),
    (
        "the omission stops saying why, so a missing column reads as a rule with no rate",
        "tools/waf_overview.py",
        '        lines.append("Hit rate omitted: the Rule=ALL totals came from the metric SEARCH fallback "\n'
        '                     "rather than a direct query, and that source is subject to a 14-day index "\n'
        '                     "expiry, so the denominator may be understated. The per-rule counts above "\n'
        '                     "are unaffected.")',
        '        lines.append("Hit rate omitted.")',
        [f"{T}::test_no_rate_column_when_the_denominator_came_from_the_fallback"],
    ),
    (
        "the prompt routing a per-rule question at the log path",
        "agent.py",
        "- \"hit rate of rule X\" / \"what % of traffic does this rule match\" → get_waf_overview(query_type='top_rules')",
        "- \"hit rate of rule X\" / \"what % of traffic does this rule match\" → aggregate_logs(query_type='top_rules')",
        [f"{T}::test_the_prompt_sends_each_hit_rate_question_to_the_right_level"],
        TEXTUAL,
    ),
    (
        "the Log Filter caveat moved onto the metrics level, where it does not apply",
        "agent.py",
        "a Log Filter cannot affect it",
        "a Log Filter may affect it",
        [f"{T}::test_the_prompt_sends_each_hit_rate_question_to_the_right_level"],
        TEXTUAL,
    ),
    (
        "the prompt no longer saying a missing rule is not a zero",
        "agent.py",
        'So absence from that table means "no data", never "never fires"',
        'So a missing rule had no matches',
        [f"{T}::test_the_prompt_says_a_missing_rule_is_not_a_zero"],
        TEXTUAL,
    ),
    (
        "a hand-written ratio template beside the primitive",
        "tools/waf_logs.py",
        '    "host_method_distribution": {',
        '    "uri_hit_rate": {\n'
        '        "query": "stats count(*) as total by httpRequest.uri",\n'
        '        "athena": "SELECT httprequest.uri, count(*) AS total, count_if(action = \'BLOCK\')'
        ' AS matched FROM {TABLE} WHERE \\"timestamp\\" BETWEEN {START_MS} AND {END_MS}'
        ' {PARTITION_FILTER} GROUP BY 1 LIMIT {LIMIT}",\n'
        '        "params": [],\n'
        '        "description": "hand-written ratio",\n'
        "    },\n"
        '    "host_method_distribution": {',
        [f"{T}::test_no_new_log_query_path_was_added_beside_the_primitive"],
        TEXTUAL,
    ),
    (
        "waf_overview reaching the log layer",
        "tools/waf_overview.py",
        "def _top_rules(cw, webacl_name, start, end, prev_start, minutes, scope=\"CLOUDFRONT\", region=\"\"):",
        "def _top_rules(cw, webacl_name, start, end, prev_start, minutes, scope=\"CLOUDFRONT\", region=\"\"):\n"
        "    from tools.waf_query import query_logs\n"
        "    query_logs('a', 'b', 0, 1)",
        [f"{T}::test_no_new_log_query_path_was_added_beside_the_primitive"],
        TEXTUAL,
    ),
    (
        "the measured denominator drifting away from the number the tests pin",
        "tools/waf_overview.py",
        "        10/45513, which is 0.022%",
        "        10/45515, which is 0.022%",
        [f"{T}::test_the_quoted_measurement_matches_the_one_the_tests_pin"],
        TEXTUAL,
    ),
]

# A case with no marker gets the reachability probe: the anchor is replaced with a bare raise
# and the targets must go red, or the line never executes and a green result from the real
# perturbation below would say nothing. A marker means the target reads source rather than
# running it, or that reachability is established elsewhere; each one says which in a comment.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
