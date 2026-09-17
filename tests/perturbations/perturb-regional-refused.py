#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""REGIONAL is refused at every scope-taking tool. Break the guard, require red.

Two shapes. Breaking the shared predicate must fail both the helper test and an end-to-end tool
refusal, because every tool routes through it. Removing one tool's guard must fail that tool's
parametrised case alone, which is what proves the walk-and-parametrise catches a single tool losing
its guard rather than only the helper.
"""

import sys

from _harness import sweep

T = "tests/test_regional_refused.py"
CASES = [
    (
        "the shared predicate never matches, so nothing is refused",
        "tools/session_state.py",
        'return REGIONAL_UNSUPPORTED_MESSAGE if (scope or "").strip().upper() == "REGIONAL" else None',
        'return REGIONAL_UNSUPPORTED_MESSAGE if (scope or "").strip().upper() == "__NOMATCH__" else None',
        [f"{T}::test_the_helper_keys_on_regional_only",
         f"{T}::test_every_scope_tool_refuses_regional"],
    ),
    (
        "one tool loses its guard and falls through to the AWS path",
        "tools/waf_overview.py",
        "    from tools.session_state import resolve_region, refuse_if_regional\n"
        "    if (msg := refuse_if_regional(scope)):\n"
        "        return msg\n"
        "    region = resolve_region(scope)",
        "    from tools.session_state import resolve_region\n"
        "    region = resolve_region(scope)",
        [f"{T}::test_every_scope_tool_refuses_regional"],
    ),
]

# Every case gets the reachability probe: a bare raise goes in above the anchor's line and the
# targets must go red, or the line never runs under those tests and the real perturbation proves
# nothing. Both anchors begin on a runnable statement (a return, an import), so both are probeable.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
