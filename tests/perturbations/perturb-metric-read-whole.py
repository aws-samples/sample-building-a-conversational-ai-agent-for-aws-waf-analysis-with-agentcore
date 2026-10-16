#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_metric_read_whole.py` fail?

Each case puts back one way a metric read came back short: a SEARCH sharing a call, a call over 500
queries, the first page taken as the answer, a SEARCH at the cap accepted, and the fake's own cut.
"""

import sys

from _harness import sweep

T = "tests/test_metric_read_whole.py"
A = "tools/aws_session.py"

CASES = [
    ("every query sent in one call, so SEARCH shares it and is cut",
     [(A, "    calls = [([q], q[\"Id\"]) for q in searches] + [(rest[i:i + 500], None) for i in range(0, len(rest), 500)]",
       "    calls = [(queries, None)]")],
     [f"{T}::test_a_search_beside_many_reads_is_not_cut",
      f"{T}::test_patrol_on_a_webacl_of_many_rules_keeps_every_search_series"], True),

    ("the other queries sent in one call whatever their number",
     [(A, "    calls = [([q], q[\"Id\"]) for q in searches] + [(rest[i:i + 500], None) for i in range(0, len(rest), 500)]",
       "    calls = [([q], q[\"Id\"]) for q in searches] + [(rest, None)]")],
     [f"{T}::test_more_than_500_reads_go_in_calls_cloudwatch_accepts"], True),

    ("the first page taken as the whole answer",
     [(A, '            if not resp.get("NextToken"):\n                break', '            if True:\n                break')],
     [f"{T}::test_a_paged_answer_is_joined"], True),

    ("a SEARCH at the cap accepted as whole",
     [(A, "        if search_id and sum(1 for k in joined if k[0] == search_id) >= SERIES_CAP:",
       "        if False:")],
     [f"{T}::test_a_search_at_the_cap_on_its_own_raises"], True),

    ("the fake no longer cutting a shared call",
     [(T, "                n = min(self.search_series, room)", "                n = self.search_series")],
     [f"{T}::test_the_control_the_fake_does_cut_a_shared_call"], True),

    ("a SEARCH recognised only by its first word again",
     [(A, '''    searches = [q for q in queries if "SEARCH(" in q.get("Expression", "")]
    rest = [q for q in queries if "SEARCH(" not in q.get("Expression", "")]''',
       '''    searches = [q for q in queries if q.get("Expression", "").startswith("SEARCH(")]
    rest = [q for q in queries if not q.get("Expression", "").startswith("SEARCH(")]''')],
     [f"{T}::test_a_wrapped_search_is_sent_alone_too"], True),

    ("top_labels asking for every metric name again",
     [("tools/waf_overview.py", '''WebACL=\\"{webacl_name}\\" {REQUEST_METRIC_FILTER}', 'Sum', {period})",''',
       '''WebACL=\\"{webacl_name}\\"', 'Sum', {period})",''')],
     [f"{T}::test_the_label_searches_ask_only_for_the_metrics_they_add"]),

    ("bot_names asking for every metric name again",
     [("tools/waf_overview.py", '''bot-control:bot:name\\" {REQUEST_METRIC_FILTER}', 'Sum',''',
       '''bot-control:bot:name\\"', 'Sum',''')],
     [f"{T}::test_the_label_searches_ask_only_for_the_metrics_they_add"]),
]

sys.exit(sweep(CASES))
