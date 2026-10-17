#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can the conservative UA-rotation tests fail?

Each part of the conservative rung undone: the old one-JA4 condition, the machine pace, the shape
test, the query that feeds it, the failure path, and the wording in both tools.
"""

import sys

from _harness import sweep

T = "tests/test_analyze_ip_verdicts.py"
L = "tools/waf_logs.py"
NOT_ALONE = f"{T}::test_one_fingerprint_behind_several_uas_is_not_called_rotation_on_its_own"

CASES = [
    ("one JA4 behind more than one UA called rotation again",
     [(L, "lambda: rotation and ja4_count == 1 and peak_val > 200,", "lambda: ua_count > 1 and ja4_count == 1 and peak_val > 50,")],
     [NOT_ALONE]),

    ("the machine-pace bar back at 50",
     [(L, "lambda: rotation and ja4_count == 1 and peak_val > 200,", "lambda: rotation and ja4_count == 1 and peak_val > 50,")],
     [NOT_ALONE]),

    ("one browser family with several templates called rotation again",
     [(L, "    return None  # One OS and browser with several templates, or too few UAs: cannot tell",
       "    return False")],
     [f"{T}::test_one_browser_family_without_the_rotation_shape_is_undecided"]),

    ("the UA list not read for one JA4",
     [(L, "    elif ua_count >= 5 and ja4_count == 1:", "    elif False:")],
     [f"{T}::test_one_client_rotating_its_ua_is_named"]),

    ("a failed UA list read as no rotation",
     [(L, '        rotation = None if failures.get("user_agents") else', '        rotation = False if failures.get("user_agents") else')],
     [f"{T}::test_a_failed_ua_list_stops_the_rotation_rung"], True),

    ("one JA4 called likely spoofing again",
     [(L, 'lines.append("⚠️ Multiple UAs but a single JA4: one TLS stack. That fits one client rotating its "',
       'lines.append("⚠️ Multiple UAs but single JA4 = likely UA spoofing (same TLS stack) "')],
     [f"{T}::test_the_diversity_line_does_not_call_one_fingerprint_spoofing"]),

    ("the scan calling one JA4 behind many UAs a strong spoofing indicator again",
     [("tools/waf_bypass.py", 'lines.append("  ⚠️  Candidate signal: one TLS fingerprint behind many User-Agents from few IPs. That fits one "',
       'lines.append("  ⚠️  Candidate signal: a strong UA-spoofing indicator. "')],
     ["tests/test_bypass_verdict.py::test_the_scan_does_not_call_one_fingerprint_behind_many_uas_spoofing"]),

    ("lookup_ja4 calling one JA4 behind many UAs spoofing again",
     [("tools/ja4.py", 'lines.append("Multiple UAs but single JA4 = one TLS stack: one client rotating UAs, or several users of "',
       'lines.append("Multiple UAs but single JA4 = UA spoofing (same client rotating UAs), or several users of "')],
     [f"{T}::test_lookup_ja4_does_not_call_one_fingerprint_spoofing_either"]),
]

sys.exit(sweep(CASES))
