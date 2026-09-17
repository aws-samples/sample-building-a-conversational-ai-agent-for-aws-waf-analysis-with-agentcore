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
        "rate_limits' mitigated-traffic check is inverted, so a real gap reads as a clean zero and a genuine zero reads as unexplained",
        "tools/waf_overview.py",
        "            if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):\n"
        "                lines.append(\"  ⚠️ PARTIAL DATA: Rate-limit rule trigger counts unavailable (CloudWatch only retains per-rule index for 14 days).\")",
        "            if not _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):\n"
        "                lines.append(\"  ⚠️ PARTIAL DATA: Rate-limit rule trigger counts unavailable (CloudWatch only retains per-rule index for 14 days).\")",
        [f"{T}::test_a_configured_rate_rule_with_no_search_rows_but_real_mitigation_discloses_partial_data",
         f"{T}::test_a_configured_rate_rule_with_no_search_rows_and_no_mitigation_is_a_clean_zero"],
    ),
    (
        "challenge_solve_rate's mitigated-traffic check is inverted the same way",
        "tools/waf_overview.py",
        "        if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):\n"
        "            lines.append(\"  ⚠️ PARTIAL DATA: Challenge/CAPTCHA issued counts unavailable",
        "        if not _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):\n"
        "            lines.append(\"  ⚠️ PARTIAL DATA: Challenge/CAPTCHA issued counts unavailable",
        [f"{T}::test_zero_issued_with_real_mitigation_discloses_partial_data",
         f"{T}::test_zero_issued_with_no_mitigation_is_a_clean_zero"],
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
