#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_count_eval_label_readers.py` fail? Key matching loosened or narrowed, label matches
missed under Not or a scope-down, a rule's position ignored, the inventory calling a possibly-read rule
safe, and the clients judged on every match again."""

import sys

from _harness import sweep

C = "tools/waf_count_eval.py"
T = "tests/test_count_eval_label_readers.py"

CASES = [
    ("a short key reaching a managed label",
     [(C, '    head = key if key.startswith("awswaf:") else prefix + "([0-9A-Za-z_-]+:)*" + key\n',
       '    head = key if key.startswith("awswaf:") else "([0-9A-Za-z_-]+:)*" + key\n')],
     [f"{T}::test_label_key_matches"], True),

    ("a LABEL key matched as a prefix",
     [(C, '    return "^" + head + ("$" if scope == "LABEL" else "")', '    return "^" + head')],
     [f"{T}::test_label_key_matches"], True),

    ("no namespaces between the prefix and a short key",
     [(C, 'prefix + "([0-9A-Za-z_-]+:)*" + key', 'prefix + key')],
     [f"{T}::test_label_key_matches"], True),

    ("a label match under Not missed",
     [(C, '    if "NotStatement" in stmt:\n        found += _label_matches(stmt["NotStatement"].get("Statement", {}))\n', "")],
     [f"{T}::test_a_label_match_is_found_wherever_it_sits"], True),

    ("a label match in a scope-down missed",
     [(C, '    for key in ("RateBasedStatement", "ManagedRuleGroupStatement"):\n        if key in stmt:\n'
          '            found += _label_matches(stmt[key].get("ScopeDownStatement", {}))\n', "")],
     [f"{T}::test_a_label_match_is_found_wherever_it_sits"], True),

    ("a rule before the Count rule counted as reading it",
     [(C, '            if own is None or r.get("Priority", 0) > own.get("Priority", 0)\n', '            if True\n')],
     [f"{T}::test_a_rule_before_it_cannot_read_its_label", f"{T}::test_a_managed_sub_rule_is_positioned_at_its_group"], False),

    ("a custom rule a later rule reads called safe again",
     [(C, "        if rule_id in no_metric or rule_id in designed:\n", "        if rule_id in no_metric:\n")],
     [f"{T}::test_the_inventory_keeps_a_rule_a_later_rule_reads"], True),

    ("a zero-hit sub-rule a later rule may read called safe again",
     [(C, "        elif rule_id in managed_readers and (hits == 0 or rule_id in LOW_FP_RULES\n",
       "        elif False and (hits == 0 or rule_id in LOW_FP_RULES\n")],
     [f"{T}::test_a_zero_hit_sub_rule_a_later_rule_may_read_is_not_called_safe"], False),

    ("a failed rules read reported as no readers",
     [(C, '    if rules is None:\n        return head + [f"  UNKNOWN: the WebACL\'s rules could not be read',
       '    if rules is None:\n        rules = []\n    if False:\n        return head + [f"  UNKNOWN: the WebACL\'s rules could not be read')],
     [f"{T}::test_a_failed_rules_read_is_not_a_clean_answer"], True),

    ("the clients judged on every match again",
     [(C, "\\\"action\\\":\\\"COUNT\\\"' and action = 'ALLOW'\"\n        \" | stats count(*) as hits by httpRequest.clientIp\"\n        \" | sort hits asc",
       "\\\"action\\\":\\\"COUNT\\\"'\"\n        \" | stats count(*) as hits by httpRequest.clientIp\"\n        \" | sort hits asc")],
     [f"{T}::test_only_matches_that_ended_allowed_change_outcome"], False),

    ("every match stopped elsewhere read as missing logs",
     [(C, '    if bottom:\n        for r in bottom:\n            lines.append(f"  {r.get(\'httpRequest.clientIp\', \'?\'):>15}  {r.get(\'hits\', \'?\'):>6} hits")\n    elif outcomes and not allowed:\n        lines.append("  (none: every request it counted was already stopped by another rule)")\n    else:\n        lines.append("  (no results — check if Log Filter drops COUNT logs)")',
       '    if bottom:\n        for r in bottom:\n            lines.append(f"  {r.get(\'httpRequest.clientIp\', \'?\'):>15}  {r.get(\'hits\', \'?\'):>6} hits")\n    else:\n        lines.append("  (no results — check if Log Filter drops COUNT logs)")')],
     [f"{T}::test_every_match_stopped_elsewhere_is_named_not_read_as_missing_logs"], True),
    ("an unplaced rule read as having no readers",
     [(C, "            if own is None or r.get(\"Priority\", 0) > own.get(\"Priority\", 0)",
       "            if own is not None and r.get(\"Priority\", 0) > own.get(\"Priority\", 0)")],
     [f"{T}::test_a_rule_the_configuration_does_not_name_is_read_by_every_label_match",
      f"{T}::test_an_unplaced_rule_is_checked_against_every_reader_and_says_why"], False),

    ("an unplaced rule's unknown position not said",
     [(C, "    if unplaced:\n        head.append(", "    if False:\n        head.append(")],
     [f"{T}::test_an_unplaced_rule_is_checked_against_every_reader_and_says_why"], True),

    ("every rule said to be unplaced",
     [(C, "    unplaced = _rule_of(rules, rule_name) is None\n", "    unplaced = True\n")],
     [f"{T}::test_a_placed_rule_does_not_say_its_position_is_unknown"], True),
]

sys.exit(sweep(CASES))
