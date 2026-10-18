#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_block_fp_shared_egress.py` fail? The verdict back on the IP's own numbers behind a
shared address, blocks from several clients judged anyway, a rotating client split up, and the scan
held to the targeted check's ratio, and the blocked User-Agent
under another JA4 judged anyway."""

import sys

from _harness import sweep

F = "tools/waf_block_fp.py"
T = "tests/test_block_fp_shared_egress.py"

CASES = [
    ("the IP's ratio judged behind a shared address",
     [(F, '        allow_count, block_count = clients["allow"], clients["block"]\n', "")],
     [f"{T}::test_an_attacker_behind_an_office_nat_is_not_a_false_positive_candidate"], True),

    ("the IP's pace judged behind a shared address",
     [(F, '        peak_rpm, rules_triggered = clients["peak"] if clients["peak"] is not None else "?", clients["rules"]\n',
       '        rules_triggered = clients["rules"]\n')],
     [f"{T}::test_a_real_user_behind_a_busy_nat_is_read_at_their_own_pace"], True),

    ("blocks from several clients judged anyway",
     [(F, '    if clients["basis"] == "several":\n        lines.append(f"**CANNOT DETERMINE**',
       '    if False:\n        lines.append(f"**CANNOT DETERMINE**')],
     [f"{T}::test_blocks_from_several_clients_refuse_a_direction"], True),

    ("several blocked clients reduced to the first",
     [(F, "    if len(blocked) != 1:\n", "    if not blocked:\n")],
     [f"{T}::test_blocks_from_several_clients_judge_none_of_them"], True),

    ("a rotating client split into clients",
     [(F, '    if _is_nat_traffic([{"ua": ua} for ua in dict.fromkeys(ua for ua, _ in table)]) is False:\n',
       '    if False:\n')],
     [f"{T}::test_user_agents_differing_only_by_version_are_one_client"], True),

    ("a client list cut off at its limit read as complete",
     [(F, "    if len(table) >= _CLIENTS:\n", "    if False:\n")],
     [f"{T}::test_a_client_list_cut_off_at_its_limit_judges_none"], True),

    ("the average mixed with one client's peak",
     [(F, '        avg_rpm = "not split per client"\n', "")],
     [f"{T}::test_the_average_is_not_mixed_with_one_clients_peak"], True),

    ("the scan held to the targeted check's ratio",
     [(F, "        if ratio > SCAN_ALLOW_RATIO:", "        if ratio > FP_ALLOW_RATIO:")],
     [f"{T}::test_the_scan_picks_candidates_at_the_looser_ratio"], True),
    ("the blocked User-Agent under another JA4 judged anyway",
     [(F, "    if others:\n        return {\"n\": len(table), \"basis\": \"several\", \"blocked\": 1,",
       "    if False:\n        return {\"n\": len(table), \"basis\": \"several\", \"blocked\": 1,")],
     [f"{T}::test_the_blocked_user_agent_under_another_ja4_judges_none"], True),

    ("any other client under the same JA4 counted as the same browser",
     [(F, "    others = sum(1 for u, j in table if u == ua and j != ja4)\n",
       "    others = sum(1 for u, j in table if (u == ua) != (j == ja4))\n")],
     [f"{T}::test_another_user_agent_under_the_same_ja4_is_still_another_client"], True),
]

sys.exit(sweep(CASES))
