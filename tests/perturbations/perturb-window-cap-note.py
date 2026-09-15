#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Silence a narrowed window again and require `test_window_cap_disclosed.py` to notice.

Seven tools clamp `duration_minutes` and all seven were silent. The first fix appended the note at the
returns it could see, reaching three of five in two tools, so the cases here break the two halves that
replaced it: the record at the clamp, and the one append in the hook. A case per clamp site would be back
to enumerating, which is the mistake the funnel removes.
"""

import sys

from _harness import sweep

T = "tests/test_window_cap_disclosed.py"
L = "tools/query_limits.py"
S = "tools/session_state.py"
A = "agent.py"
W = "tools/waf_logs.py"

CASES = [
    ("the note emptied, so every clamp is silent again",
     [(L, "    if used_minutes >= asked_minutes:\n        return \"\"", "    if True:\n        return \"\"")],
     [f"{T}::test_a_narrowed_window_says_both_numbers",
      f"{T}::test_it_says_what_the_result_does_not_mean"], True),

    ("the note on every query, including the ones inside the cap",
     [(L, "    if used_minutes >= asked_minutes:", "    if False:")],
     [f"{T}::test_a_window_inside_the_cap_says_nothing",
      f"{T}::test_a_window_that_fitted_adds_nothing_to_the_result"], True),

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

    # The record. Nothing stored means nothing to append, whichever return the tool took.
    ("the clamp recording nothing, so the hook has nothing to say",
     [(S, '            _state.setdefault("window_cap", {})[current_tool_call()] = {\n'
          '                "asked": asked_minutes, "used": used_minutes}',
       "            pass")],
     [f"{T}::test_the_hook_appends_it_whatever_the_tool_returned",
      f"{T}::test_a_tool_call_that_clamped_but_never_queried_still_says_so"], True),

    ("the record kept on read, so the next tool call inherits this one's window",
     [(S, '        return (_state.get("window_cap") or {}).pop(tool_use_id or "", {})',
       '        return (_state.get("window_cap") or {}).get(tool_use_id or "", {})')],
     [f"{T}::test_the_next_tool_call_does_not_inherit_the_cap"], True),

    ("one slot for the session again, so two concurrent tool calls share a window",
     [(S, '            _state.setdefault("window_cap", {})[current_tool_call()] = {',
       '            _state.setdefault("window_cap", {})["shared"] = {')],
     [f"{T}::test_two_concurrent_tool_calls_keep_their_own_cap"], True),

    # The append. Gated on the provenance record is exactly how a refusal loses it, and that was the
    # shape of the hook before the cap moved into it.
    ("the append gated on a query having run, so a clamp that refused says nothing",
     [(A, "        if not disclosures:\n            return", "        if not record:\n            return")],
     [f"{T}::test_a_tool_call_that_clamped_but_never_queried_still_says_so"], True),

    ("the cap dropped from the hook, so the record is written and never read",
     [(A, "        if cap:\n            disclosures.append(window_capped_note(cap[\"asked\"], cap[\"used\"]).lstrip(\"\\n\"))",
       "        if False:\n            disclosures.append(\"\")")],
     [f"{T}::test_the_hook_appends_it_whatever_the_tool_returned",
      f"{T}::test_the_cap_and_the_source_line_arrive_in_one_block_with_the_cap_first"], True),

    ("the source line dropped instead, which is the other half of the same append",
     [(A, "        if record:\n            disclosures.append(provenance_source_line(record))",
       "        if False:\n            disclosures.append(\"\")")],
     [f"{T}::test_a_tool_call_that_clamped_nothing_but_queried_still_gets_its_source_line",
      f"{T}::test_the_cap_and_the_source_line_arrive_in_one_block_with_the_cap_first"], True),

    ("the two disclosures swapped, so the signature precedes the caveat it applies to",
     [(A, "        if cap:\n            disclosures.append(window_capped_note(cap[\"asked\"], cap[\"used\"]).lstrip(\"\\n\"))\n"
          "        if record:\n            disclosures.append(provenance_source_line(record))",
       "        if record:\n            disclosures.append(provenance_source_line(record))\n"
       "        if cap:\n            disclosures.append(window_capped_note(cap[\"asked\"], cap[\"used\"]).lstrip(\"\\n\"))")],
     [f"{T}::test_the_cap_and_the_source_line_arrive_in_one_block_with_the_cap_first"], True),

    # A tool going back to building the string itself. `run_logs_query` is the one that did, on the one
    # return it covered, so this is the regression in its original form. No probe: the target reads the
    # package's source rather than running it.
    ("a tool appending the note at one of its returns again",
     [(W, "        msg += _table_block()\n        return msg",
       "        msg += _table_block()\n"
       "        from tools.query_limits import window_capped_note\n"
       "        return msg + window_capped_note(duration_minutes, _duration)")],
     [f"{T}::test_the_note_is_never_appended_at_a_return"], False),

    # A clamp with no recorder, which is what four tools looked like before this landed.
    ("one clamp site silent again, the shape all seven had",
     [("tools/waf_bypass.py", "    note_window_capped(duration_minutes, _duration)\n", "")],
     [f"{T}::test_every_clamp_in_the_package_records_it"], False),
]

sys.exit(sweep(CASES))
