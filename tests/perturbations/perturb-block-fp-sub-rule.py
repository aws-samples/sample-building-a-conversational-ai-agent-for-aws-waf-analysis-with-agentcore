#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_block_fp_sub_rule.py` fail?

The sub-rule lookup back on the first group entry, back on every BLOCK from the IP, and the Athena
side back on every group's entry.
"""

import sys

from _harness import sweep

T = "tests/test_block_fp_sub_rule.py"
F = "tools/waf_block_fp.py"

CASES = [
    ("the first group entry with a terminatingRule taken again",
     [(F, """_LAST_SUB_RULE_CWL = ('parse @message /.*\\\\{"ruleGroupId":""", """_LAST_SUB_RULE_CWL = ('parse @message /\\\\{"ruleGroupId":""")],
     [f"{T}::test_the_sub_rule_is_the_blocking_groups_not_a_count_groups"]),

    ("every BLOCK from the IP read again, whichever rule blocked it",
     [(F, """            f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK' and terminatingRuleId = '{safe_rule}'\"""",
       """            f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'\"""")],
     [f"{T}::test_the_sub_rule_is_the_blocking_groups_not_a_count_groups"]),

    ("Athena taking the first group with a terminatingRule",
     [(F, "rg -> rg.terminatingrule IS NOT NULL), -1).terminatingrule.ruleid\"",
       "rg -> rg.terminatingrule IS NOT NULL), 1).terminatingrule.ruleid\"")],
     [f"{T}::test_the_athena_lookup_reads_the_last_matching_group_of_the_blocking_rule"]),

    ("Athena reading every BLOCK from the IP again",
     [(F, " AND action = 'BLOCK' AND terminatingruleid = '{safe_rule}')\"", " AND action = 'BLOCK')\"")],
     [f"{T}::test_the_athena_lookup_reads_the_last_matching_group_of_the_blocking_rule"]),
]

sys.exit(sweep(CASES))
