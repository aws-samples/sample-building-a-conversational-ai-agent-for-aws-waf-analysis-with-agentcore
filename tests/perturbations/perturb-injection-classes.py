#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_injection_classes.py` fail?

The classification line moved each way it was drawn, a mixed group taken whole again, and the two
supports the per-sub-rule ranking needs: the batched count and the group-dimension cross-check.
"""

import sys

from _harness import sweep

T = "tests/test_injection_classes.py"
I = "tools/waf_injection.py"
A = "tools/waf_aggregate.py"
M = "tools/waf_metrics.py"
CLASS = f"{T}::test_a_sub_rule_is_injection_by_its_family_and_component"

CASES = [
    ("file inclusion on the URI path called injection",
     [(I, '    return not (name.startswith(("GenericLFI_", "LFI_")) and name.endswith("_URIPATH"))', "    return True")],
     [CLASS]),

    ("the _RC_COUNT helpers called detectors",
     [(I, ' or name.endswith("_RC_COUNT"):', ":")],
     [CLASS]),

    ("SSRF left out",
     [(I, '"PowerShellCommands_", "PHPHighRiskMethodsVariables_", "EC2MetaDataSSRF_",', '"PowerShellCommands_", "PHPHighRiskMethodsVariables_",')],
     [CLASS]),

    ("a mixed group taken whole again",
     [(I, "                found += [n for n in _group_sub_rules(group) if n not in found]", "                found.append(name)")],
     [f"{T}::test_a_mixed_group_contributes_its_injection_sub_rules_not_itself",
      f"{T}::test_blocks_by_a_mixed_groups_other_rules_are_not_injection_activity"], True),

    ("a whole-group Count leaving its sub-rules in Block mode",
     [(I, "            (counted if whole or \"Count\" in action else blocking).add(sub)",
       "            (counted if \"Count\" in action else blocking).add(sub)")],
     [f"{T}::test_a_group_in_whole_group_count_puts_its_sub_rules_in_count_mode"]),

    ("a sub-rule one instance blocks put in Count mode by the other",
     [(I, "    return counted - blocking\n", "    return counted\n")],
     [f"{T}::test_a_sub_rule_one_instance_blocks_is_not_in_count_mode",
      f"{T}::test_the_control_a_sub_rule_one_instance_blocks_is_not_said_to_block_nothing"]),

    ("a sub-rule whose own action is Count read as blocking",
     [(I, '_NATIVE_COUNT = frozenset({"SQLi_QUERYSTRING_COUNT"})', "_NATIVE_COUNT = frozenset()")],
     [f"{T}::test_a_sub_rule_whose_own_action_is_count_is_in_count_mode"]),

    ("a pinned version's detectors missing from the list again",
     [(I, '        "SQLiExtendedPatterns_BODY", "SQLiExtendedPatterns_HEADER", "SQLiExtendedPatterns_QUERYARGUMENTS",',
       '        "SQLiExtendedPatterns_QUERYARGUMENTS",')],
     [f"{T}::test_every_injection_name_any_version_has_used_is_listed",
      f"{T}::test_a_pinned_versions_detectors_are_found_with_no_override"]),

    ("a Count rule's blocks called its own",
     [(I, '                 + (" by other rules" if ranked[0][0] in count_mode else ""))', '                 )')],
     [f"{T}::test_a_count_mode_focus_says_its_blocks_were_another_rules"]),

    ("a Count rule's matches all called allowed again",
     [(I, 'so it blocked none of the requests below; any that "', 'so the requests below matched it and were allowed through; any that "')],
     [f"{T}::test_a_count_mode_focus_says_its_blocks_were_another_rules"]),

    ("managed sub-rules cross-checked under Rule= again",
     [(I, "                    if target in managed:\n                        continue\n", "")],
     [f"{T}::test_a_quiet_window_cross_checks_a_sub_rule_on_its_group_whatever_its_mode"]),

    ("the group metric reading BlockedRequests only, which a Count override leaves empty",
     [(M, '              for n in names for metric in ("BlockedRequests", "CountedRequests")]',
       '              for n in names for metric in ("BlockedRequests",)]'),
      (M, "        count = None if sums is None else sums[2 * i] + sums[2 * i + 1]",
       "        count = None if sums is None else sums[i]")],
     [f"{T}::test_the_group_metric_adds_blocked_and_counted_in_one_call"]),

    ("the group metric read one call per series",
     [(M, "    sums, reason = _metric_sums(webacl_name, series, start_epoch, end_epoch)\n    out = []",
       "    sums = []\n    for one in series:\n        got, reason = _metric_sums(webacl_name, [one], start_epoch, end_epoch)\n"
       "        sums = None if got is None or sums is None else sums + got\n    out = []")],
     [f"{T}::test_the_group_metric_adds_blocked_and_counted_in_one_call"]),

    ("the batched count's blocks counting every match",
     [(A, "sum(if(action = 'BLOCK' and {pred}, 1, 0)) as b{i}", "sum(if({pred}, 1, 0)) as b{i}")],
     [f"{T}::test_cloudwatch_counts_matches_and_blocks_for_every_name"]),

    ("every name in one CloudWatch query",
     [(A, '                if chunks[-1] and len("stats " + ', '                if False and len("stats " + ')],
     [f"{T}::test_cloudwatch_counts_matches_and_blocks_for_every_name"]),

    ("a failed count read as all zeros",
     [(A, '    except Exception as exc:                              # noqa: BLE001\n        return None, f"{type(exc).__name__}: {exc}"\n    row = {}',
       '    except Exception as exc:                              # noqa: BLE001\n        return {n: (0, 0) for n in names}, ""\n    row = {}')],
     [f"{T}::test_a_failed_count_is_none_with_its_reason"]),
]

sys.exit(sweep(CASES))
