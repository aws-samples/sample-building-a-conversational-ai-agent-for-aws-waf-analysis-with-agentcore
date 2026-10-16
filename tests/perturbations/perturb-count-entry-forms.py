#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_count_entry_forms.py` fail?

The Count form split back into two substrings, once per template, and the Host parse back on two
spellings.
"""

import sys

from _harness import sweep

T = "tests/test_count_entry_forms.py"
L = "tools/waf_logs.py"
ONE = """@message like '\\"ruleId\\":\\"{rule_name}\\",\\"action\\":\\"COUNT\\"'"""
TWO = """@message like '\\"ruleId\\":\\"{rule_name}\\"' and @message like '\\"action\\":\\"COUNT\\"'"""

CASES = [
    (f"{key} matching a rule and a Count as two substrings again",
     [(L, f'''"{key}": {{\n        "query": "{prefix}filter {ONE}''', f'''"{key}": {{\n        "query": "{prefix}filter {TWO}''')],
     [f"{T}::test_the_count_rule_templates_match_one_entry",
      f"{T}::test_no_query_matches_a_rule_and_a_count_as_two_substrings"])
    for key, prefix in (("count_rule_top_ips", ""), ("count_rule_top_uris", ""),
                        ("count_rule_top_uas", 'parse @message /(?i)\\\\{\\"name\\":\\"user-agent\\",\\"value\\":\\"(?<ua>.*?)\\"\\\\}/ | '))
] + [
    ("host_top_ips reading two spellings of Host again",
     [(L, '''"query": "parse @message /(?i)\\\\{\\"name\\":\\"host\\",\\"value\\":\\"(?<host>.*?)\\"\\\\}/ | filter host = '{host}' | stats count(*) as hits by httpRequest.clientIp''',
       '''"query": "parse @message /\\\\{\\"name\\":\\"(H|h)ost\\",\\"value\\":\\"(?<host>.*?)\\"\\\\}/ | filter host = '{host}' | stats count(*) as hits by httpRequest.clientIp''')],
     [f"{T}::test_every_host_parse_reads_any_casing"]),
]

sys.exit(sweep(CASES))
