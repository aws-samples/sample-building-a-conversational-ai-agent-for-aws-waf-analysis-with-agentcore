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
     [(I, "                out |= set(_group_sub_rules(group))", "                pass")],
     [f"{T}::test_a_group_in_whole_group_count_puts_its_sub_rules_in_count_mode"], True),

    ("the quiet-window cross-check asking Rule=<sub-rule> again",
     [(I, '                        group="" if target in count_mode else groups.get(target, ""))', '                        group="")')],
     [f"{T}::test_a_quiet_window_cross_checks_each_sub_rule_against_its_group_metric"]),

    ("the metric ignoring the group it was given",
     [(M, "    if group:\n        return _metric_sum(", "    if False:\n        return _metric_sum(")],
     [f"{T}::test_the_group_metric_reads_the_sub_rule_dimensions"], True),

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
