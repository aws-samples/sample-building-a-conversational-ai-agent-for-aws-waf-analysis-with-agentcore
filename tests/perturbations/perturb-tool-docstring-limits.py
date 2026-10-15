#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the property `test_tool_docstring_limits.py` claims and require it to notice.

Both shapes the stale text could take: the per-engine wording restored, and a single wrong number.
Every target reads docstrings, so the reachability probe does not apply.
"""

import sys

from _harness import sweep

T = "tests/test_tool_docstring_limits.py::test_every_duration_cap_a_tool_states_is_the_one_the_code_applies"

CASES = [
    ("the per-engine cap back in one tool's schema",
     [("tools/waf_challenge_check.py", "(default 180, max 360, both engines)", "(default 180, max 360 for CWL, 60 for Athena)")],
     [T]),

    ("a tool stating the wrong cap",
     [("tools/waf_count_eval.py", "(default 60, max 360, both engines)", "(default 60, max 60, both engines)")],
     [T]),
]

sys.exit(sweep(CASES))
