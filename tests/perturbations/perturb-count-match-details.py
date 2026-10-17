#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_count_match_details.py` fail?

Each property of the match-details section broken once: once per request, this rule's entries only,
both levels, a failure said as a failure, and the null-data wording.
"""

import sys

from _harness import sweep

T = "tests/test_count_match_details.py"
C = "tools/waf_count_eval.py"
CWL = f"{T}::test_cloudwatch_shows_each_matched_payload_once_per_request"

CASES = [
    ("a request counted once per entry, so a group deployed twice counts it twice",
     [(C, "            for text in {_detail_text(d) for e in entries\n"
          "                         if e.get(\"ruleId\") == rule_name and e.get(\"action\") == \"COUNT\"\n"
          "                         for d in e.get(\"ruleMatchDetails\") or []}:",
       "            for text in [_detail_text(d) for e in entries\n"
          "                         if e.get(\"ruleId\") == rule_name and e.get(\"action\") == \"COUNT\"\n"
          "                         for d in e.get(\"ruleMatchDetails\") or []]:")],
     [CWL]),

    ("another rule's details attributed to this one",
     [(C, "                         if e.get(\"ruleId\") == rule_name and e.get(\"action\") == \"COUNT\"",
       "                         if e.get(\"action\") == \"COUNT\"")],
     [CWL]),

    ("the entries inside a rule group skipped",
     [(C, "                entries += g.get(\"nonTerminatingMatchingRules\") or []", "                entries += []")],
     [CWL], True),

    ("a failed read shown as none logged",
     [(C, "        lines.append(f\"  UNKNOWN, the query for this section failed: {exc}\")", "        lines.append(\"  (none logged)\")")],
     [f"{T}::test_a_failed_read_says_so_rather_than_none"], True),

    ("Athena counting entries rather than requests",
     [(C, "              f\" count(DISTINCT httprequest.requestid) as hits\"", "              f\" count(*) as hits\"")],
     [f"{T}::test_athena_shows_the_rows_its_query_returns"]),

    ("null matched data rendered as nothing",
     [(C, "f\"{' '.join(data) if data else 'matched data not recorded'}\")", "f\"{' '.join(data) if data else ''}\")")],
     [f"{T}::test_a_regex_entry_says_its_matched_data_is_not_recorded"]),
]

sys.exit(sweep(CASES))
