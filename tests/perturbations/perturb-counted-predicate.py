#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_counted_predicate.py` claims and require it to notice.

Every target reads source or assembled query text, so the reachability probe does not apply.

**The anchoring case is the one that justifies extending the old sweep.** `action=COUNT` got its own
predicate through `by_value`, and the anchoring test in `test_aggregate_logs.py` used to read only
each filter's template. An unanchored COUNT predicate would then have passed it untouched.
"""

import sys

from _harness import sweep

T = "tests/test_counted_predicate.py"
A = "tests/test_aggregate_logs.py"
C = "tools/counted.py"
L = "tools/waf_logs.py"
G = "tools/waf_aggregate.py"

CASES = [
    ("top_counted_ips back on the first-element-only CloudWatch filter",
     [(L, '"query": "filter " + COUNTED_CWL + " | stats count(*) as cnt by httpRequest.clientIp |',
       '"query": "filter nonTerminatingMatchingRules.0.action = \'COUNT\' | stats count(*) as cnt by httpRequest.clientIp |')],
     [f"{T}::test_no_query_in_the_package_reads_a_count_from_the_top_level",
      f"{T}::test_the_counted_templates_use_the_shared_predicate"]),

    ("top_counted_countries back on the top-level-only Athena predicate",
     [(L, '{PARTITION_FILTER} AND " + COUNTED_ATHENA + " GROUP BY httprequest.country ',
       "{PARTITION_FILTER} AND any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT') GROUP BY httprequest.country ")],
     [f"{T}::test_no_query_in_the_package_reads_a_count_from_the_top_level"]),

    ("the shared predicate losing its nested branch, which is where the measured Counts were",
     [(C, "    \" OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules,\"\n"
          "    \" r -> r.action = 'COUNT'))\"\n", "")],
     [f"{T}::test_the_shared_predicate_names_the_nested_location_it_was_measured_at"]),

    ("aggregate's COUNT back on the top-level action",
     [(G, '        by_value={"COUNT": (COUNTED_ATHENA, COUNTED_CWL),\n', '        by_value={\n')],
     [f"{T}::test_aggregate_count_filter_finds_nested_counts"]),

    ("_build ignoring by_value, so every value takes the template",
     [(G, "        pairs = [spec.by_value.get(v, (spec.athena, spec.cwl)) for v in values]",
       "        pairs = [(spec.athena, spec.cwl) for v in values]")],
     [f"{T}::test_aggregate_count_filter_finds_nested_counts"]),

    ("BLOCK routed through the counted predicate too, which the control exists for",
     [(G, "        pairs = [spec.by_value.get(v, (spec.athena, spec.cwl)) for v in values]",
       "        pairs = [spec.by_value.get('COUNT', (spec.athena, spec.cwl)) if key == 'action' else (spec.athena, spec.cwl) for v in values]")],
     [f"{T}::test_aggregate_terminating_actions_still_filter_on_the_top_level"]),

    ("an unanchored COUNT predicate, reachable only through by_value",
     [(C, 'COUNTED_CWL = f"(@message like \'\\"action\\":\\"COUNT\\"\' or {EXCLUDED_CWL})"',
       'COUNTED_CWL = f"(@message like \'COUNT\' or {EXCLUDED_CWL})"')],
     [f"{A}::test_no_filter_matches_the_raw_record_instead_of_a_field"]),
]

sys.exit(sweep(CASES))
