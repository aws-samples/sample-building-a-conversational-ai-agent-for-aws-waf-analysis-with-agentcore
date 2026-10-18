#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_analyze_ip_attack_source.py` fail? The attack-source rung removed, counted by rule
instead of by category, fooled by a whole-group Count entry or a third-party group's names, and the
bot rungs reading the attack's blocks again."""

import sys

from _harness import sweep

L = "tools/waf_logs.py"
I = "tools/waf_injection.py"
T = "tests/test_analyze_ip_attack_source.py"
RET = '        return n >= ATTACK_CATEGORIES_ALONE or (n >= ATTACK_CATEGORIES_WITH_MAJORITY and content + unknown_blocks > allowed\n                                                and spread >= ATTACK_PATHS_WITH_MAJORITY)\n'

CASES = [
    ("no attack-source rung",
     [(L, "        ((\"attack_categories\", \"allowed\"), lambda: _is_attack_source(*_attack_counts()), _attack_source),\n",
       "")],
     [f"{T}::test_the_scanner_is_an_attack_source_before_it_is_a_scraper"], False),

    ("counted per WebACL rule, so reputation lists and Bot Control count",
     [(L, "        if why:\n            blocks, reasons = unknown.get(rule, (0, why))\n            unknown[rule] = (blocks + n, reasons)\n"
           "            excluded.add((rule, \"\"))\n            paths[rule] = max(paths.get(rule, 0), uris)\n        elif cat:\n            cats[cat] = cats.get(cat, 0) + n\n",
       "        if why:\n            blocks, reasons = unknown.get(rule, (0, why))\n            unknown[rule] = (blocks + n, reasons)\n"
           "            excluded.add((rule, \"\"))\n            paths[rule] = max(paths.get(rule, 0), uris)\n        else:\n"
           "            cat = cat or rule\n            cats[cat] = cats.get(cat, 0) + n\n")],
     [f"{T}::test_rate_limits_reputation_lists_and_bot_control_are_not_categories"], True),

    ("two categories without a majority of blocks",
     [(L, RET, RET.replace(" and content + unknown_blocks > allowed\n", "\n"))],
     [f"{T}::test_two_categories_need_more_blocks_than_allowed_requests"], True),

    ("two categories on one path",
     [(L, RET, RET.replace("\n                                                and spread >= ATTACK_PATHS_WITH_MAJORITY)", ")"))],
     [f"{T}::test_two_categories_on_one_path_are_not_an_attack_source"], True),

    ("the categories' paths summed, not the widest",
     [(L, "        spread = max([attack", "        spread = sum([attack")],
     [f"{T}::test_two_categories_on_one_path_are_not_an_attack_source"], True),

    ("a whole-group Count entry read as the block",
     [(L, "        if kind == \"MANAGED_RULE_GROUP\":\n            if not sub:", "        if sub or kind == \"MANAGED_RULE_GROUP\":\n            if not sub:")],
     [f"{T}::test_a_whole_group_count_entry_is_not_read_as_the_block"], True),

    ("a third-party group classified by its rule names",
     [(L, "        if kind == \"MANAGED_RULE_GROUP\":\n            if not sub:\n                why = \"its sub-rule is not in the record\"\n"
           "            elif not group.startswith(\"AWS#\"):",
       "        if kind == \"MANAGED_RULE_GROUP\":\n            if not sub:\n                why = \"its sub-rule is not in the record\"\n"
           "            elif False:")],
     [f"{T}::test_a_third_party_group_is_not_classified_by_its_rule_names"], True),

    ("unreadable blocks skipped instead of stopping the rung",
     [(L, "        ((\"attack_categories\", \"allowed\"), _attack_source_unread, _unread_text),\n", "")],
     [f"{T}::test_a_failed_config_read_stops_the_rung_when_it_could_decide_it"], False),

    ("the configuration read on every IP",
     [(L, "        if any(r.get(\"terminatingRuleType\") == \"REGULAR\"", "        if True or any(r.get(\"terminatingRuleType\") == \"REGULAR\"")],
     [f"{T}::test_the_config_is_read_only_when_a_custom_rule_blocked"], True),

    ("a block list cut off at its limit read as complete",
     [(L, "    if not (failures.get(\"attack_categories\") or notes.get(\"attack_categories\")):",
       "    if not failures.get(\"attack_categories\"):")],
     [f"{T}::test_a_block_list_cut_off_at_its_limit_is_not_complete"], True),

    ("the bot rungs reading the attack's blocks again",
     [(L, "        bot_parse, bot_filter, bot_athena = _without_attack_blocks(attack[\"excluded\"] if attack else set())",
       "        bot_parse, bot_filter, bot_athena = _without_attack_blocks(set())")],
     [f"{T}::test_the_bot_rung_queries_leave_out_the_attack_blocks"], True),

    ("the static share over every request again",
     [(L, "lambda: static_peak > 200 and non_static < 0.1 * kept, None", "lambda: static_peak > 200 and non_static < 0.1 * total, None")],
     [f"{T}::test_the_static_share_is_of_the_requests_the_bot_rungs_read"], False),

    ("restricted extensions not path probing",
     [(I, '_PATH_PROBE_RULES = frozenset({"ExploitablePaths_URIPATH", "RestrictedExtensions_URIPATH"})',
       '_PATH_PROBE_RULES = frozenset({"ExploitablePaths_URIPATH"})')],
     [f"{T}::test_attack_category"], False),

    ("not blocked and blocked by other rules worded alike",
     [(L, "        lines.append(\"  \" + (\", \".join(f\"{c} {b:,}{paths(c)}\" for c, b in sorted(cats.items(), key=lambda kv: -kv[1]))\n"
           "                             or (\"none: it was not blocked\" if not attack[\"blocked\"] else",
       "        lines.append(\"  \" + (\", \".join(f\"{c} {b:,}{paths(c)}\" for c, b in sorted(cats.items(), key=lambda kv: -kv[1]))\n"
           "                             or (\"none: its blocks came from rules that do not inspect what a request asks for or carries\" if not attack[\"blocked\"] else")],
     [f"{T}::test_not_blocked_and_blocked_by_other_rules_read_differently"], True),
]

sys.exit(sweep(CASES))
