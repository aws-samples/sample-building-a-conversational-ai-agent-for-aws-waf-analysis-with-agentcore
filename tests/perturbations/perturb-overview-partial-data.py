#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_overview_partial_data.py` fail?

Three cases, one per new disclosure. Each inverts or drops the exact clause the matching test
exists to pin, not the surrounding scaffolding.

Run from the repo root. Restores every touched file on any exit path.
"""

import sys

from _harness import sweep

T = "tests/test_overview_partial_data.py"
CASES = [
    (
        "rate_limits checks the whole WebACL again instead of the specific rate-limit rule, reintroducing the false positive a reviewer caught",
        "tools/waf_overview.py",
        "            if any(_has_mitigated_traffic(cw, webacl_name, start, end, scope, region, rule=name)\n"
        "                   for name in rate_rule_names):",
        "            if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):",
        [f"{T}::test_the_specific_rate_rule_being_genuinely_idle_is_a_clean_zero_even_with_other_traffic",
         f"{T}::test_a_direct_query_on_the_specific_rule_finding_real_traffic_discloses_partial_data"],
    ),
    (
        "challenge_solve_rate sums Blocked back in, reintroducing the same false positive",
        "tools/waf_overview.py",
        "        if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region,\n"
        "                                   metric_names=(\"ChallengeRequests\", \"CaptchaRequests\")):",
        "        if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):",
        [f"{T}::test_blocked_only_traffic_is_a_clean_zero_not_partial_data",
         f"{T}::test_a_direct_query_finding_real_challenge_traffic_discloses_partial_data"],
    ),
    (
        "top_rules' gap-detection line drops the 14-day SEARCH-discovery cause, back to naming only sub-rules",
        "tools/waf_overview.py",
        "not attributed to visible rules. Likely causes: managed rule group sub-rules that don't "
        "publish their own per-rule metric (e.g., AMR ChallengeAllDuringEvent), or a rule whose "
        "per-rule metric CloudWatch's SEARCH-based discovery has not indexed in the last 14 days. "
        "Use ip_cross_query",
        "not attributed to visible rules. Likely cause: managed rule group sub-rules that don't "
        "publish their own per-rule metric (e.g., AMR ChallengeAllDuringEvent). "
        "Use ip_cross_query",
        [f"{T}::test_top_rules_gap_detection_names_both_possible_causes"],
        False,  # its target reads the source text rather than running `_top_rules`
    ),
]

# The first two cases' anchors are lines the matching fixtures actually execute, so they get the
# reachability probe. The third's target never calls `_top_rules`, so probe=False, per case above.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], c[5] if len(c) > 5 else True) for c in CASES]))
