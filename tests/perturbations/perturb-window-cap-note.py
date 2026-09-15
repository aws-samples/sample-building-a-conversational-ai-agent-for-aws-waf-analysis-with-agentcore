#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Silence a narrowed window again and require `test_window_cap_disclosed.py` to notice.

Three tools clamp `duration_minutes` and all three were silent. The cases below remove the note per site,
because the first fix caught `run_logs_query` and missed `analyze_ip`, which is the one users reach most.
"""

import sys

from _harness import sweep

T = "tests/test_window_cap_disclosed.py"
L = "tools/query_limits.py"
W = "tools/waf_logs.py"
B = "tools/waf_block_fp.py"

CASES = [
    ("the note emptied, so every clamp is silent again",
     [(L, "    if used_minutes >= asked_minutes:\n        return \"\"", "    if True:\n        return \"\"")],
     [f"{T}::test_a_narrowed_window_says_both_numbers",
      f"{T}::test_it_says_what_the_result_does_not_mean"], True),

    ("the note on every query, including the ones inside the cap",
     [(L, "    if used_minutes >= asked_minutes:", "    if False:")],
     [f"{T}::test_a_window_inside_the_cap_says_nothing"], True),

    ("only the used number reported, so the reader cannot see what was asked",
     [(L, 'f"\\n⚠️  **Window narrowed.** You asked for {asked_minutes:,} minutes and this engine caps a "',
       'f"\\n⚠️  **Window narrowed.** This engine caps a "')],
     [f"{T}::test_a_narrowed_window_says_both_numbers"], True),

    # Anchored on the whole `return`, not the clause inside it: a line in the middle of a multi-line
    # expression is a continuation line and no statement can be inserted ahead of one, so the probe had
    # nothing to sit on and the case would have joined `unprobeable.txt` for no reason.
    ("the consequence dropped, leaving two numbers and no reading of them",
     [(L, '    return (f"\\n⚠️  **Window narrowed.** You asked for {asked_minutes:,} minutes and this '
          'engine caps a "\n'
          '            f"single query at {MAX_MINUTES}, so only the first {used_minutes:,} minutes were '
          'queried. An "\n'
          '            f"empty or small result says nothing about the rest of the window. Split the range '
          'into "\n'
          '            f"{MAX_MINUTES}-minute queries to cover it.")',
       '    return (f"\\n⚠️  **Window narrowed.** You asked for {asked_minutes:,} minutes and this '
       'engine caps a "\n'
       '            f"single query at {MAX_MINUTES}, so only the first {used_minutes:,} minutes were '
       'queried.")')],
     [f"{T}::test_it_says_what_the_result_does_not_mean"], True),

    # Per site, because a module-level count hid the one that was missed.
    ("analyze_ip silent again, which is the site the first fix missed",
     [(W, "    _duration = min(duration_minutes, MAX_MINUTES)\n"
          "    # The same clamp and the same silence, and this is the one users reach most. Its header "
          "already prints\n"
          "    # `_duration`, which a reader could compare against what they asked for; the note says it "
          "outright.\n"
          "    _cap = window_capped_note(duration_minutes, _duration)",
       "    _duration = min(duration_minutes, MAX_MINUTES)\n    _cap = \"\"")],
     [f"{T}::test_every_clamp_computes_the_note_beside_it"], False),

    ("investigate_block_fp silent again",
     [(B, "    _cap = window_capped_note(duration_minutes, _duration)", '    _cap = ""')],
     [f"{T}::test_every_clamp_computes_the_note_beside_it",
      f"{T}::test_the_note_is_one_sentence_shared_by_every_site"], False),
]

sys.exit(sweep(CASES))
