#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_whole_group_count.py` fail?

Each case keeps only the branch a whole-group Count does NOT use, which is the defect the file's
note used to predict: the group's own entry carries the sub-rule's native BLOCK, so a predicate
keyed on anything nested misses the record.
"""

import sys

from _harness import sweep

T = "tests/test_whole_group_count.py"
C = "tools/counted.py"
A = "tools/waf_aggregate.py"
I = "tools/waf_injection.py"
TEXTUAL = False  # the targets read predicate strings, so no line of these executes under them

CASES = [
    ("the CloudWatch predicate matching only a sub-rule override",
     [(C, """COUNTED_CWL = f"(@message like '\\"action\\":\\"COUNT\\"' or {EXCLUDED_CWL})\"""",
       """COUNTED_CWL = f"(@message like '\\"overriddenAction\\":\\"COUNT\\"' or {EXCLUDED_CWL})\"""")],
     [f"{T}::test_the_counted_predicate_matches_a_whole_group_count"], TEXTUAL),

    ("the Athena predicate losing its top-level branch",
     [(C, """    "(any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT')"
    " OR any_match(rulegrouplist""", """    "(any_match(rulegrouplist""")],
     [f"{T}::test_the_counted_predicate_matches_a_whole_group_count"], TEXTUAL),

    ("the CloudWatch rule filter keyed on the terminating rule alone",
     [(A, """_RULE_CWL = ("(terminatingRuleId = '{v}' or @message like '\\"ruleId\\":\\"{v}\\"'\"""",
       """_RULE_CWL = ("(terminatingRuleId = '{v}' or @message like '\\"terminatingRuleId\\":\\"{v}\\"'\"""")],
     [f"{T}::test_the_rule_filter_finds_the_group_by_its_webacl_rule_name"], TEXTUAL),

    ("the Athena rule filter losing the top-level non-terminating branch",
     [(A, """    " OR any_match(nonterminatingmatchingrules, r -> r.ruleid = '{v}')"
    " OR any_match(rulegrouplist, rg -> rg.terminatingrule.ruleid = '{v}')\"""",
       """    " OR any_match(rulegrouplist, rg -> rg.terminatingrule.ruleid = '{v}')\"""")],
     [f"{T}::test_the_rule_filter_finds_the_group_by_its_webacl_rule_name"], TEXTUAL),

    ("a group overridden to Count not read as Count mode",
     [(I, """        whole = "Count" in (rule.get("OverrideAction") or {})""", """        whole = False""")],
     [f"{T}::test_an_injection_group_overridden_to_count_is_a_count_mode_detector"], True),

    ("the fixture losing the measured shape",
     [(T, '''"action":"BLOCK","ruleMatchDetails":null},"nonTerminatingMatchingRules":[]''',
       '''"action":"COUNT","ruleMatchDetails":null},"nonTerminatingMatchingRules":[]''')],
     [f"{T}::test_the_record_has_the_measured_shape"], TEXTUAL),
]

sys.exit(sweep(CASES))
