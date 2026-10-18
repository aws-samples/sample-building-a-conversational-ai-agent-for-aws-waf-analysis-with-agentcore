#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_bypass_endpoints.py` fail? Each threshold dropped, an empty week-earlier window read
as zero everywhere, an absent endpoint read as unknown, the disclosures printed unconditionally or not
at all, an unchecked path queried, a marked endpoint not counted as a candidate, the list ordered by IPs
so popular pages fill it, and a cut-off list not disclosed."""

import sys

from _harness import sweep

B = "tools/waf_bypass.py"
T = "tests/test_bypass_endpoints.py"

CASES = [
    ("the request floor dropped",
     [(B, "ips >= ENDPOINT_MIN_IPS and total >= ENDPOINT_MIN_REQUESTS and (", "ips >= ENDPOINT_MIN_IPS and (")],
     [f"{T}::test_below_either_floor_nothing_is_marked"], False),

    ("the growth test dropped",
     [(B, "            prior == 0 or ips >= ENDPOINT_IP_GROWTH * prior)", "            True)")],
     [f"{T}::test_growth_marks_and_less_growth_does_not", f"{T}::test_a_busy_endpoint_says_a_few_more_sources_do_not_mark_it"], False),

    ("an empty week earlier read as zero on every endpoint",
     [(B, "    elif not logged_n:\n", "    elif False:\n")],
     [f"{T}::test_a_week_earlier_holding_no_log_marks_nothing_and_says_why"], False),

    ("an endpoint absent a week earlier read as unknown",
     [(B, "        prior = before.get((uri, method), 0) if (uri, method) in safe and baseline is None else None\n",
       "        prior = before.get((uri, method)) if (uri, method) in safe and baseline is None else None\n")],
     [f"{T}::test_the_credential_stuffing_run_is_marked"], True),

    ("the new-endpoint line printed whatever was marked",
     [(B, "    if new_marked:\n        lines.append(\"  A marked endpoint with no IPs", "    if True:\n        lines.append(\"  A marked endpoint with no IPs")],
     [f"{T}::test_growth_marks_and_less_growth_does_not"], True),

    ("the busy-endpoint line printed whatever the endpoints were",
     [(B, "    if busy:\n        lines.append(\"  An endpoint that already draws", "    if True:\n        lines.append(\"  An endpoint that already draws")],
     [f"{T}::test_the_credential_stuffing_run_is_marked"], True),

    ("a busy endpoint left unsaid",
     [(B, "        busy = busy or (prior is not None and prior >= ENDPOINT_MIN_IPS and not hit)\n", "")],
     [f"{T}::test_a_busy_endpoint_says_a_few_more_sources_do_not_mark_it"], True),

    ("an unchecked path queried",
     [(B, "    safe = [(u, m) for u, m, _ in keyed if _SAFE_URI.fullmatch(u) and re.fullmatch(r\"[A-Z]+\", m)]\n",
       "    safe = [(u, m) for u, m, _ in keyed]\n")],
     [f"{T}::test_a_path_a_quote_could_break_out_of_is_not_compared"], True),

    ("the condition stated only when something is marked",
     [(B, "        return head + [f\"  (no endpoint drew {ENDPOINT_MIN_IPS} or more IPs and {ENDPOINT_MIN_REQUESTS} or more \"\n"
          "                       f\"allowed requests in this window)\", rule], False\n",
       "        return head + [f\"  (no endpoint drew {ENDPOINT_MIN_IPS} or more IPs and {ENDPOINT_MIN_REQUESTS} or more \"\n"
          "                       f\"allowed requests in this window)\"], False\n")],
     [f"{T}::test_the_condition_is_stated_with_its_numbers_every_time"], True),

    ("a marked endpoint not counted as a candidate",
     [(B, " or ua_rotation or endpoints_marked)", " or ua_rotation)")],
     [f"{T}::test_the_scan_counts_a_marked_endpoint_as_a_candidate"], True),

    ("verified bots counted on the endpoint",
     [(B, "        \" and (not ispresent(lbls) or not (lbls like 'bot:verified'))\"\n"
          "        \" | stats count(*) as total, count_distinct(httpRequest.clientIp) as unique_ips\"",
       "        \" | stats count(*) as total, count_distinct(httpRequest.clientIp) as unique_ips\"")],
     [f"{T}::test_the_scan_counts_a_marked_endpoint_as_a_candidate"], False),

    ("the CloudWatch list ordered by IPs again",
     [(B, '        " | fields total / unique_ips as per_ip"\n        f" | sort per_ip desc | limit {_ENDPOINTS}"\n',
       '        f" | sort unique_ips desc | limit {_ENDPOINTS}"\n')],
     [f"{T}::test_both_floors_are_in_the_query_and_the_list_is_by_requests_per_ip"], False),

    ("the Athena list ordered by IPs again",
     [(B, '" ORDER BY count(*) * 1.0 / count(DISTINCT httprequest.clientip) DESC LIMIT {LIMIT}"',
       '" ORDER BY unique_ips DESC LIMIT {LIMIT}"')],
     [f"{T}::test_both_floors_are_in_the_query_and_the_list_is_by_requests_per_ip"], False),

    ("the request floor left out of the query",
     [(B, 'f" | filter unique_ips >= {ENDPOINT_MIN_IPS} and total >= {ENDPOINT_MIN_REQUESTS}"',
       'f" | filter unique_ips >= {ENDPOINT_MIN_IPS}"')],
     [f"{T}::test_both_floors_are_in_the_query_and_the_list_is_by_requests_per_ip"], False),

    ("a cut-off list not disclosed",
     [(B, '    if notes.get("endpoints"):\n        lines.append(f"  The list stopped at',
       '    if False:\n        lines.append(f"  The list stopped at')],
     [f"{T}::test_a_cut_off_list_says_a_quieter_endpoint_may_be_outside_it"], True),
]

sys.exit(sweep(CASES))
