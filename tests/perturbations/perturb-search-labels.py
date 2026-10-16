#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_search_labels.py` fail?

A template dropped from a query, a parser that stops splitting on `|`, a rule-match series counted
as requests, and the sweep's own matcher drifting until it finds nothing.
"""

import sys

from _harness import sweep

T = "tests/test_search_labels.py"
O = "tools/waf_overview.py"
R = "tools/report.py"
P = "tools/waf_patrol.py"

CASES = [
    ("the bot-name query losing its template",
     [(O, '\n         "Label": search_label("LabelName")},', "},")],
     [f"{T}::test_a_lone_bot_is_named_not_called_by_its_metric",
      f"{T}::test_every_search_query_in_the_tools_names_its_label"], False),

    ("a patrol query losing its template",
     [(P, '\n                 "Label": search_label("Attack")},', "},")],
     [f"{T}::test_every_search_query_in_the_tools_names_its_label"], False),

    ("top_labels counting rule matches as requests",
     [(O, '''WebACL=\\"{webacl_name}\\" {REQUEST_METRIC_FILTER}', 'Sum', {period})",''',
       '''WebACL=\\"{webacl_name}\\"', 'Sum', {period})",''')],
     [f"{T}::test_a_label_with_two_metrics_is_one_row_counted_once"]),

    ("targeted signals adding rule matches to requests again",
     [(O, '        if len(parts) != 3 or parts[2] not in REQUEST_METRICS:\n            continue\n        namespace, name, metric = parts',
       '        if len(parts) != 3:\n            continue\n        namespace, name, metric = parts'),
      (O, '        b = metrics.get("BlockedRequests", 0)\n', '        b = metrics.get("BlockedRequests", 0) + metrics.get("BlockRuleMatch", 0)\n')],
     [f"{T}::test_a_signal_is_not_counted_once_per_metric_family"],
     False),  # two edits, the filter and the sum, and the probe takes one; the sum's line is plain

    ("an attack type keyed on the whole label",
     [(O, '        atype = r.get("Label", "").split("|")[0]', '        atype = r.get("Label", "")')],
     [f"{T}::test_an_attack_type_with_two_actions_is_one_row"], True),

    ("the report keying a country on the whole label",
     [(R, '        country = r.get("Label", "").split("|")[0]', '        country = r.get("Label", "")')],
     [f"{T}::test_the_report_names_a_lone_country_and_attack_type"], True),

    ("the report's rule query losing its template",
     [(R, '"Expression": expression, "Label": search_label("Rule")}],', '"Expression": expression}],')],
     [f"{T}::test_report_top_rules_names_its_label"], False),

    ("the targeted card counting rule matches as requests",
     [(R, '                if total <= 0 or len(parts) != 2 or not parts[0].startswith("TGT_") or parts[1] not in REQUEST_METRICS:',
       '                if total <= 0 or len(parts) != 2 or not parts[0].startswith("TGT_"):')],
     [f"{T}::test_the_targeted_card_counts_requests_not_rule_matches"], True),

    ("a verified bot merged with a client claiming its name",
     [(R, '                b = bots.setdefault((bot_name, parts[4] == "bot:verified"), {',
       '                b = bots.setdefault((bot_name, True), {')],
     [f"{T}::test_a_name_claimed_by_an_unverified_client_is_not_a_good_bot"], True),

    ("the sweep's matcher finding no SEARCH",
     [(T, '        if isinstance(head, ast.Constant) and str(head.value).startswith("SEARCH("):',
       '        if isinstance(head, ast.Constant) and str(head.value).startswith("SEARCH ("):')],
     [f"{T}::test_every_search_query_in_the_tools_names_its_label"], True),

    ("the report read at a week whatever its length again",
     [(R, "    period = max(days, 1) * 86400", "    period = 604800")],
     [f"{T}::test_a_short_report_reads_no_further_than_its_window"], True),
]

sys.exit(sweep(CASES))
