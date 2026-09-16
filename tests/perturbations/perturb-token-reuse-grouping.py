#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Put `token_reuse_ips` back to a key that fragments one session, require the test to notice.

Measured on a live replay: one session (`token:id`) spanned 18 IPs but carried five distinct full
`aws-waf-token` values, so keying on the token value, or on the whole Cookie header, splits one session
into many rows and undercounts the reuse. The fix keys on the `awswaf:managed:token:id` label. Each case
here restores a fragmenting key or reopens the empty-group hole. No reachability probe: the targets read
the template strings and the CWL parse pattern lifted from them, they do not run a query.
"""

import sys

from _harness import sweep

W = "tools/waf_logs.py"
T = "tests/test_token_reuse_grouping.py"
CASES = [
    ("the CWL key back to the extracted token value, which fragments one session",
     [(W, "parse @message /awswaf:managed:token:id:(?<token_id>[0-9a-f-]+)/ | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by token_id",
       "parse @message /aws-waf-token=(?<token_id>[^;\\\"]+)/ | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by token_id")],
     [f"{T}::test_one_session_across_many_ips_is_one_group_with_the_full_ip_count",
      f"{T}::test_two_token_values_sharing_one_session_do_not_fragment",
      f"{T}::test_the_sdk_header_request_joins_its_session_not_an_empty_group",
      f"{T}::test_neither_engine_parses_the_cookie_anymore"],
     False),   # textual: targets read the template string and the parse pattern, nothing runs a query

    ("the Athena key back to the cookie token value",
     [(W, "regexp_extract(array_join(transform(labels, l -> l.name), ','), 'awswaf:managed:token:id:([0-9a-f-]+)', 1) as token_id",
       "regexp_extract(element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value, 'aws-waf-token=([^;]+)', 1) as token_id"),
      (W, "GROUP BY regexp_extract(array_join(transform(labels, l -> l.name), ','), 'awswaf:managed:token:id:([0-9a-f-]+)', 1)",
       "GROUP BY regexp_extract(element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value, 'aws-waf-token=([^;]+)', 1)")],
     [f"{T}::test_neither_engine_parses_the_cookie_anymore"],
     False),   # textual

    # Drop the label filter: a token:accepted record with no token:id parses to an empty key and sorts
    # first by ip_count. The test that requires the filter goes red.
    ("the CWL label filter removed, reopening the empty catch-all group",
     [(W, "filter @message like 'token:accepted' and @message like 'awswaf:managed:token:id:' | parse",
       "filter @message like 'token:accepted' | parse")],
     [f"{T}::test_the_query_requires_the_label_so_there_is_no_empty_catch_all"],
     False),   # textual

    ("the Athena label filter removed",
     [(W, "AND any_match(labels, l -> l.name LIKE '%token:accepted%') AND any_match(labels, l -> l.name LIKE 'awswaf:managed:token:id:%')",
       "AND any_match(labels, l -> l.name LIKE '%token:accepted%')")],
     [f"{T}::test_the_query_requires_the_label_so_there_is_no_empty_catch_all"],
     False),   # textual

    # A name that reads fine and drops the masking: `tokenid` has no separator, so it does not carry the
    # `token` name token and `_name_is_sensitive` returns False, and the session id renders in clear.
    ("the session column renamed to one the masker does not recognise",
     [(W, "(?<token_id>[0-9a-f-]+)/ | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by token_id",
       "(?<tokenid>[0-9a-f-]+)/ | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by tokenid")],
     [f"{T}::test_the_session_column_is_named_so_it_is_masked_on_display"],
     False),   # textual
]

sys.exit(sweep(CASES))
