#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_count_eval_inventory.py` claims and require it to notice.

The metrics-off case perturbs `waf_metrics`, not `waf_count_eval`: the refusal under test is the
real one in `rule_blocked_per_metrics`, so breaking it there is what the inventory has to see.
"""

import sys

from _harness import sweep

T = "tests/test_count_eval_inventory.py"
C = "tools/waf_count_eval.py"
M = "tools/waf_metrics.py"

CASES = [
    ("an unconfirmed absence read as zero again",
     [(C, "        if not counted:\n            counted, reason = rule_blocked_per_metrics(",
       "        if False:\n            counted, reason = rule_blocked_per_metrics(")],
     [f"{T}::test_only_a_confirmed_zero_is_called_safe"], True),

    ("a failed confirmation filed as zero instead of no-metric",
     [(C, "            if counted is None:\n                no_metric[rule_id] = reason\n                continue",
       "            if counted is None:\n                counted = 0")],
     [f"{T}::test_only_a_confirmed_zero_is_called_safe", f"{T}::test_a_rule_with_no_metric_says_why"], True),

    ("the metrics-off refusal removed at its source",
     [(M, '    if in_config == "metrics-off":\n        return None, (',
       '    if False:\n        return None, (')],
     [f"{T}::test_only_a_confirmed_zero_is_called_safe"], True),

    ("every rule confirmed, including the ones SEARCH already counted",
     [(C, "        if not counted:\n            counted, reason", "        if True:\n            counted, reason")],
     [f"{T}::test_a_rule_search_already_counted_is_not_asked_again"], True),

    ("Step 3 back in WebACL order",
     [(C, "    needs_analysis.sort(key=lambda rh: rh[1], reverse=True)\n", "")],
     [f"{T}::test_step_three_is_ranked_by_hit_volume"]),

    ("the no-metric section dropped from the output",
     [(C, "    if no_metric:\n        lines.append(\"\")", "    if False:\n        lines.append(\"\")")],
     [f"{T}::test_a_rule_with_no_metric_says_why"], True),
]

sys.exit(sweep(CASES))
