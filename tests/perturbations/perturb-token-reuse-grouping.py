#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Put `token_reuse_ips` back to grouping by the whole Cookie header, require the test to notice.

The live 7-region replay showed one token, replayed from seven IPs, counted as `ip_count=1` because the
query grouped by the entire Cookie header and a real header carries the load balancer's per-backend
stickiness cookies after the token. Each case here restores one half of that defect. No reachability
probe: the targets read the template strings and the extraction patterns lifted from them, they do not run
a query, and each says so.
"""

import sys

from _harness import sweep

W = "tools/waf_logs.py"
T = "tests/test_token_reuse_grouping.py"
CASES = [
    ("the CWL parse back to the whole cookie header, so ALB cookies fragment one token",
     [(W, "parse @message /aws-waf-token=(?<waf_token>[^;\\\"]+)/ | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by waf_token",
       "parse @message '\\\"name\\\":\\\"cookie\\\",\\\"value\\\":\\\"*\\\"' as cookie | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by cookie")],
     [f"{T}::test_the_group_key_is_the_token_not_the_whole_cookie_header",
      f"{T}::test_neither_engine_groups_by_the_raw_cookie_header_anymore",
      f"{T}::test_the_extracted_token_stops_at_the_first_other_cookie"],
     False),   # textual: targets read the template strings, nothing runs a query

    ("the Athena extract back to the whole cookie header value",
     [(W, "regexp_extract(element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value, 'aws-waf-token=([^;]+)', 1) as waf_token",
       "element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value as cookie"),
      (W, "GROUP BY regexp_extract(element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value, 'aws-waf-token=([^;]+)', 1)",
       "GROUP BY element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value")],
     [f"{T}::test_the_group_key_is_the_token_not_the_whole_cookie_header",
      f"{T}::test_neither_engine_groups_by_the_raw_cookie_header_anymore"],
     False),   # textual: targets read the template strings, nothing runs a query

    # A name that reads fine and drops the masking: `waftoken` has no separator, so it does not carry the
    # `token` name token and `_name_is_sensitive` returns False, and the encrypted token renders in clear.
    ("the token column renamed to one the masker does not recognise",
     [(W, "parse @message /aws-waf-token=(?<waf_token>[^;\\\"]+)/", "parse @message /aws-waf-token=(?<waftoken>[^;\\\"]+)/"),
      (W, "count(*) as total by waf_token", "count(*) as total by waftoken")],
     [f"{T}::test_the_token_column_is_named_so_it_is_masked_on_display"],
     False),   # textual: targets read the template strings, nothing runs a query
]

sys.exit(sweep(CASES))
