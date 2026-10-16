#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_template_anchoring.py` claims and require it to notice.

One case per site the sweep found, so the sweep is shown to reach each module rather than only the
templates it started from.
"""

import sys

from _harness import sweep

T = "tests/test_template_anchoring.py"
SWEEP = f"{T}::test_no_query_in_the_package_matches_the_raw_record_unanchored"

CASES = [
    ("host_top_ips back on a bare host substring",
     [("tools/waf_logs.py", '''"query": "parse @message /(?i)\\\\{\\"name\\":\\"host\\",\\"value\\":\\"(?<host>.*?)\\"\\\\}/ | filter host = '{host}' | stats count(*) as hits by httpRequest.clientIp, action''',
       '''"query": "filter @message like '{host}' | stats count(*) as hits by httpRequest.clientIp, action''')],
     [f"{T}::test_every_raw_record_match_on_a_parameter_is_anchored", SWEEP]),

    ("the bypass scan's verified exclusion back on the raw record",
     [("tools/waf_bypass.py", '''        _LABELS_ARRAY + " | " "filter action = 'ALLOW'"\n        f"{CWL_EXCLUDE_STATIC}"\n        " and (not ispresent(lbls) or not (lbls like 'bot:verified'))"\n        " | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp"\n        " | filter unique_uris''',
       '''        "filter action = 'ALLOW'"\n        f"{CWL_EXCLUDE_STATIC}"\n        " and @message not like 'bot:verified'"\n        " | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp"\n        " | filter unique_uris''')],
     [SWEEP]),

    ("the report's event query on a leading quote again, which a header value matches",
     [("tools/report.py", '''"filter @message like '\\"name\\":\\"awswaf:managed:aws:anti-ddos:ddos-request\\"' |''', '''"filter @message like '\\"awswaf:managed:aws:anti-ddos:ddos-request' |''')],
     [SWEEP]),

    ("token_reuse_ips filtering on unanchored label text again",
     [("tools/waf_logs.py", '''"query": "filter @message like '\\"name\\":\\"awswaf:managed:token:accepted\\"' and''', '''"query": "filter @message like 'token:accepted' and''')],
     [SWEEP]),

    ("the report's event query on a key a client writes, `value`",
     [("tools/report.py", '''"filter @message like '\\"name\\":\\"awswaf:managed:aws:anti-ddos:ddos-request\\"' |''', '''"filter @message like '\\"value\\":\\"awswaf:managed:aws:anti-ddos:ddos-request' |''')],
     [SWEEP]),

    ("an f-string's Count filter on a leading quote, which only an f-string-reading sweep sees",
     [("tools/waf_count_eval.py", '''    cwl = (f"filter @message like '\\"ruleId\\":\\"{rule_name}\\",\\"action\\":\\"COUNT\\"'"''',
       '''    cwl = (f"filter @message like '\\"{rule_name}'"''')],
     [SWEEP]),

    ("a quoted operand pinning an escaped quote, which only client text holds",
     [("tools/waf_bypass.py", """and @message like '\\"action\\":\\"COUNT\\"'\"""",
       """and @message like '\\"action\\\\\\":\\"COUNT\\"'\"""")],
     [SWEEP]),
]

sys.exit(sweep(CASES))
