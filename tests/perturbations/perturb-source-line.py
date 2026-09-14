#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the `SOURCE:` line and require `test_query_provenance.py` to notice.

The line existed for two releases with six tests and no perturbation script, so nothing had shown those
tests can fail. It moved on 2026-09-14 from two call sites inside `waf_logs` to one hook at
`AfterToolCallEvent`, which is what made most of these cases expressible: a property spread across two
renderers is broken two ways, and one held in a hook is broken once.

Two of the cases below are for defects the move itself introduced and review caught: the merged wording
told the model to undo an explicit log group, and the hook's drain point is what makes the CLI path stop
accumulating. Both were reproduced before being fixed, and both have their own case here because a
regression is exactly what a case is for.
"""

import sys

from _harness import sweep

A = "agent.py"
S = "tools/session_state.py"
L = "tools/waf_logs.py"
T = "tests/test_query_provenance.py"

CASES = [
    ("the line never appended, so a wrong-WebACL answer reads like a right one",
     [(A, '        content.append({"text": f"\\n{provenance_source_line(record)}"})\n', "")],
     [f"{T}::test_every_tool_result_that_queried_carries_the_line"], True),

    ("appended on every tool call, so a config read claims a query it never ran",
     [(A, "        if not record:\n            return", "        if False:\n            return")],
     [f"{T}::test_every_tool_result_that_queried_carries_the_line"], True),

    ("the line merged into the tool's last block, where it can land inside a table",
     [(A, '        content.append({"text": f"\\n{provenance_source_line(record)}"})',
       '        content[-1] = {"text": content[-1].get("text", "") + f"\\n{provenance_source_line(record)}"}')],
     [f"{T}::test_every_tool_result_that_queried_carries_the_line"], True),

    # The handoff. The hook drains, so the record has to arrive somewhere the loop can find it.
    ("the record drained and not stashed, so the chip goes blank",
     [(A, '        record = stash_query_provenance((event.tool_use or {}).get("toolUseId") or "")',
       '        record = stash_query_provenance("")')],
     [f"{T}::test_the_hook_hands_the_record_to_the_chip_by_tool_call_id"], True),

    ("the loop asking for the live record instead of this tool call's",
     [(A, "                _prov = take_query_provenance(payload)",
       "                _prov = take_query_provenance()")],
     [f"{T}::test_the_streaming_loop_collects_by_the_id_it_already_has"], False),

    ("the fallback removed, so a hook that did not fire loses the chip as well as the line",
     [(S, '            record = (_state.get("provenance_stash") or {}).pop(tool_use_id, None)\n'
          "            if record:\n                return record",
       '            return (_state.get("provenance_stash") or {}).pop(tool_use_id, None) or {}')],
     [f"{T}::test_the_chip_still_gets_a_record_if_the_hook_never_ran"], True),

    # Two edits, so no probe: this moves a container rather than changing a line, and the target runs
    # both halves anyway. It is the shape of the regression itself, someone putting the stash back where
    # `conftest` cannot reach it.
    ("the stash moved back out of _state, where the isolation fixture cannot clear it",
     [(S, '            stash = _state.setdefault("provenance_stash", {})',
       '            stash = globals().setdefault("_leaked_stash", {})'),
      (S, '            record = (_state.get("provenance_stash") or {}).pop(tool_use_id, None)',
       '            record = globals().setdefault("_leaked_stash", {}).pop(tool_use_id, None)')],
     [f"{T}::test_the_stash_lives_where_the_isolation_fixture_can_clear_it",
      f"{T}::test_a_cleared_state_drops_the_stash"], False),

    # The regression review caught: one wording for both paths.
    ("both paths given the session-derived wording again, which orders the model to undo the bypass",
     [(S, '    if p.get("subject_explicit"):', "    if False:")],
     [f"{T}::test_the_line_does_not_tell_the_model_to_undo_an_explicit_log_group"], True),

    ("the explicit-subject bit never set, so the wording cannot tell the two paths apart",
     [(S, '        p["subject_explicit"] = bool(subject or declared)',
       '        p["subject_explicit"] = False')],
     [f"{T}::test_the_line_does_not_tell_the_model_to_undo_an_explicit_log_group"], True),

    # The other regression: the CLI path never drained.
    ("the drain moved back off the per-tool-call path, so a second tool call inherits the first's window",
     [(S, '        record = _state.pop("provenance", {})',
       '        record = dict(_state.get("provenance") or {})')],
     [f"{T}::test_a_second_tool_call_does_not_inherit_the_first_ones_window"], True),

    # The old emitter's shape: derive the engine from session state when the line is rendered, which
    # answers "what would a query use now" rather than "what did this one use".
    ("the engine re-derived from state at render time instead of read from the record",
     [(S, '    engines = " + ".join(p.get("engines") or []) or "no engine"',
       '    from tools.waf_query import get_log_type\n'
       '    engines = {"cwl": "CloudWatch Logs", "s3": "Athena over S3"}.get(get_log_type(), "no engine")')],
     [f"{T}::test_the_engine_named_is_the_one_the_query_used"], True),

    ("the subject ignored, so an explicit log group is reported as the session's WebACL",
     [(S, '        p["webacl"] = subject or declared or get_webacl_name()',
       '        p["webacl"] = get_webacl_name()')],
     [f"{T}::test_an_explicit_log_group_is_named_instead_of_the_session_webacl"], True),

    # The one query in the repository outside the funnel. Nothing else would notice.
    ("the explicit-log-group path no longer recording what it queried",
     [(L, '        note_query_provenance("CloudWatch Logs Insights", start_epoch, end_epoch,\n'
          '                              subject=f"log group {log_group}")\n', "")],
     [f"{T}::test_an_explicit_log_group_is_named_instead_of_the_session_webacl"], False),

    ("an unset context rendered as a sentence that looks like it names something",
     [(S, '    subject = p.get("webacl") or "(none set)"', '    subject = p.get("webacl")')],
     [f"{T}::test_an_unset_context_says_so_rather_than_looking_confident"], True),

    # The pairing. Either half alone is worthless, so the marker is perturbed on the emitter's side and
    # the prompt's side is what goes red. Twice, because there are two wordings now.
    ("the marker renamed on the emitter while the prompt still names SOURCE",
     [(S, '    return (f"SOURCE: ', '    return (f"ORIGIN: ', 2)],
     [f"{T}::test_the_prompt_tells_the_model_to_read_the_source_line"], True),
]

sys.exit(sweep(CASES))
