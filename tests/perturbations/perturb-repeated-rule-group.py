#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_repeated_rule_group.py` fail?

Each case drops one part of the disclosure for a managed group deployed twice: finding the repeat,
attributing a sub-rule to its group, saying when that lookup failed, printing the note, and listing
an override once.
"""

import sys

from _harness import sweep

T = "tests/test_repeated_rule_group.py"
M = "tools/waf_metrics.py"
O = "tools/waf_overview.py"
C = "tools/waf_count_eval.py"

CASES = [
    ("a repeated group never found",
     [(M, "    repeated = {g: n for g, n in counts.items() if n > 1}", "    repeated = {}")],
     [f"{T}::test_a_sub_rule_of_a_repeated_group_is_marked_summed",
      f"{T}::test_count_eval_marks_a_repeated_groups_sub_rule"], True),

    ("every override marked, whichever group it belongs to",
     [(M, '        if group.get("Name") in repeated:', "        if True:")],
     [f"{T}::test_count_eval_marks_a_repeated_groups_sub_rule"], True),

    ("the group lookup sent for every group",
     [(M, "        for group in repeated:", "        for group in counts:")],
     [f"{T}::test_the_group_lookup_is_sent_only_for_a_repeated_group",
      f"{T}::test_a_sub_rule_of_a_group_run_once_is_not_marked"], True),

    ("the group lookup's answer dropped, so a sub-rule nothing overrides goes unmarked",
     [(M, '            names |= {r.get("Label", "").split("|")[0] for r in resp.get("MetricDataResults", [])}',
       "            pass")],
     [f"{T}::test_a_sub_rule_of_a_repeated_group_is_marked_summed"], True),

    ("a failed group lookup left unsaid",
     [(M, '        note += (f" Only the sub-rules the configuration overrides are marked',
       '        note = note or (f" Only the sub-rules the configuration overrides are marked')],
     [f"{T}::test_a_failed_group_lookup_still_marks_the_overrides_and_says_so"], True),

    ("top_rules marking rows without saying why",
     [(O, "    if any(r[1] in summed for r in rows[:15]):\n        lines.append(repeated)",
       "    if False:\n        lines.append(repeated)")],
     [f"{T}::test_a_sub_rule_of_a_repeated_group_is_marked_summed"], True),

    ("an override listed once per instance",
     [(C, "    return list(dict.fromkeys(count_rules))  # a group deployed twice names its overrides twice",
       "    return count_rules")],
     [f"{T}::test_an_override_on_a_repeated_group_is_listed_once",
      f"{T}::test_count_eval_marks_a_repeated_groups_sub_rule"], True),

    ("count_eval not marking the summed row",
     [(C, '    mark = lambda r: f"{r}*" if r in summed else r', "    mark = lambda r: r")],
     [f"{T}::test_count_eval_marks_a_repeated_groups_sub_rule"], True),

    ("count_eval marking rows without saying why",
     [(C, "    if any(r in summed for r, _ in permanent_count + low_fp_nonzero + needs_analysis):",
       "    if False:")],
     [f"{T}::test_count_eval_marks_a_repeated_groups_sub_rule"], True),
]

sys.exit(sweep(CASES))
