#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the log-path cross-check and require `test_log_path_cross_check.py` to notice.

Two directions, and both matter. Removing a witness makes the check silent where it should speak; removing
a guard makes it speak where it cannot know, and this check's only output is a statement about the log
path, so a false one is worse than none.

The mismatch guard has its own case because its failure is measured rather than argued:
`response-id-on-page`'s metric was 132 on 2026-09-08 while a control query for that WebACL inside
`shield-sample-webacl`'s log group returned 0, so the pair fires falsely without it.
"""

import sys

from _harness import sweep

T = "tests/test_log_path_cross_check.py"
M = "tools/waf_metrics.py"

CASES = [
    # The second witness. Without it the check is a control-only check, which flags every quiet window.
    ("the control witness ignored, so a genuinely quiet window reads as a broken log path",
     [(M, "    control, why = control_rows(webacl_name, action, start_epoch, end_epoch)",
       "    control, why = 0, \"\"")],
     [f"{T}::test_a_window_that_held_nothing_for_anyone_says_nothing",
      f"{T}::test_a_working_path_says_nothing"], True),

    # The first witness, the other way round.
    ("the metric witness ignored, so the check speaks with one witness",
     [(M, "    if total is None:\n        print(f\"[waf_metrics] no log-path cross-check: {reason}\"",
       "    if False:\n        print(f\"[waf_metrics] no log-path cross-check: {reason}\"")],
     [f"{T}::test_a_witness_that_could_not_answer_produces_silence"], True),

    ("a control that could not answer treated as a control that found nothing",
     [(M, "    if control is None:\n        print(f\"[waf_metrics] no log-path cross-check: {why}\"",
       "    if False:\n        print(f\"[waf_metrics] no log-path cross-check: {why}\"")],
     [f"{T}::test_a_control_that_failed_is_not_a_control_that_found_nothing",
      f"{T}::test_a_witness_that_could_not_answer_produces_silence"], True),

    # The mismatch guard, whose failure is measured.
    ("the two witnesses allowed to be about different WebACLs",
     [(M, "    if webacl_name != session_acl:", "    if False:")],
     [f"{T}::test_the_two_witnesses_must_be_about_the_same_webacl"], True),

    ("the guard widened until it refuses the matching case too",
     [(M, "    if webacl_name != session_acl:", "    if True:")],
     [f"{T}::test_a_matching_webacl_is_not_refused"], True),

    # The unreachable row shape that would read as the firing value.
    ("a missing count read as zero, which is the one value that fires",
     [(M, '    if "cnt" not in rows[0]:\n        return None, f"the control query returned a row with '
          'no count in it: {sorted(rows[0])}"\n    return int(rows[0]["cnt"]), ""',
       '    return int(rows[0].get("cnt", 0)), ""')],
     [f"{T}::test_a_row_with_no_count_refuses_rather_than_reading_as_zero"], True),

    # The actionable cell, and what it must not become.
    ("the actionable cell silenced, so a broken log path reads as absence",
     [(M, "    if total > 0 and control == 0:", "    if False:")],
     [f"{T}::test_a_metric_above_zero_with_an_empty_control_is_the_one_actionable_cell"], True),

    ("the cell widened to any non-zero metric, so a working path is called broken",
     [(M, "    if total > 0 and control == 0:", "    if total > 0:")],
     [f"{T}::test_a_working_path_says_nothing"], True),

    ("the reverse disagreement written as a verdict rather than a note",
     [(M, '        return (f"\\nNote: the log path returned rows in this window while CloudWatch reports no "',
       '        return (f"\\n⚠️  **The log query missed data.** Do NOT trust this. "\n'
       '                f"The log path returned rows while CloudWatch reports no "')],
     [f"{T}::test_the_reverse_disagreement_is_one_line_and_not_a_verdict"], True),

    # The subject rules.
    ("a non-empty answer cross-checked anyway, which the partial-gap limit forbids",
     [(M, "    if narrow_rows != 0:\n        return \"\"", "    if False:\n        return \"\"")],
     [f"{T}::test_a_narrow_answer_that_found_rows_is_never_cross_checked"], True),

    ("COUNT compared against CountedRequests, which is not disjoint from the other four",
     [(M, '_ACTION_METRIC = {"BLOCK": "BlockedRequests", "ALLOW": "AllowedRequests",',
       '_ACTION_METRIC = {"COUNT": "CountedRequests", "BLOCK": "BlockedRequests", '
       '"ALLOW": "AllowedRequests",')],
     # No probe: the anchor is a module-level constant, so a `raise` above it fires at import and the
     # probe run errors at collection rather than at an assertion.
     [f"{T}::test_an_action_with_no_metric_is_refused_rather_than_guessed",
      f"{T}::test_no_action_sums_the_four_terminating_ones"], False),

    # The four wiring sites. Without these every case above stays green while no tool asks the check.
    # No probe on any of them: both targets read source rather than running it.
    ("analyze_ip back to reporting absence with no witness",
     [("tools/waf_logs.py",
       "        warning = log_path_warning(get_webacl_name(), None, start_epoch, end_epoch, narrow_rows=0)\n"
       '        return f"No log records found for {ip} in this time window.{warning}"',
       '        return f"No log records found for {ip} in this time window."')],
     [f"{T}::test_every_absence_branch_group_b_names_asks_the_check"], False),

    ("investigate_block_fp's absence branch unwitnessed",
     [("tools/waf_block_fp.py",
       '        warning = log_path_warning(get_webacl_name(), "BLOCK", start_epoch, end_epoch, narrow_rows=0)',
       '        warning = ""')],
     [f"{T}::test_each_site_passes_the_action_its_own_answer_is_about"], False),

    ("detect_bypass's clean verdict unwitnessed",
     [("tools/waf_bypass.py",
       '            _warning = log_path_warning(get_webacl_name(), "ALLOW", start_epoch, end_epoch, narrow_rows=0)',
       '            _warning = ""')],
     [f"{T}::test_each_site_passes_the_action_its_own_answer_is_about"], False),

    ("aggregate_logs' zero-result branch unwitnessed",
     [("tools/waf_aggregate.py",
       "        msg += log_path_warning(get_webacl_name(), _action, start_epoch, end_epoch, narrow_rows=0)",
       '        msg += ""')],
     [f"{T}::test_every_absence_branch_group_b_names_asks_the_check"], False),

    ("a site passing the wrong action, so the witness is a series about something else",
     [("tools/waf_block_fp.py",
       '        warning = log_path_warning(get_webacl_name(), "BLOCK", start_epoch, end_epoch, narrow_rows=0)',
       '        warning = log_path_warning(get_webacl_name(), "ALLOW", start_epoch, end_epoch, narrow_rows=0)')],
     [f"{T}::test_each_site_passes_the_action_its_own_answer_is_about"], False),

    ("the no-action control given an action filter, so it asks a narrower question than it answers",
     [(M, '    cwl = f"filter action = \'{action}\' | " if action else ""',
       '    cwl = f"filter action = \'{action}\' | " if action else "filter action = \'BLOCK\' | "')],
     [f"{T}::test_the_control_query_asks_the_same_action_on_both_engines"], True),
]

sys.exit(sweep(CASES))
