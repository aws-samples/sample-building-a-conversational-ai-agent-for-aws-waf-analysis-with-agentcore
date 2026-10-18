#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_volume_window.py` and `tests/test_local_import_shadowing.py` fail? The volume step
and the scan's spike note put back on seven-day totals, and the local import that silenced the note."""

import sys

from _harness import sweep

B = "tools/waf_bypass.py"
T = "tests/test_volume_window.py"
# The whole if/elif chain, so the reachability probe goes ahead of its `if`, not an `elif` header.
CHAIN = '    if peak_x is not None:\n        allowed_x, base, basis = peak_x, peak_prev, peak_label\n    elif week_allowed is not None:\n'

CASES = [
    ("the volume step compares seven-day totals again",
     [(B, "end, chosen = min(start + timedelta(hours=1), now),", "start, end, chosen = now - timedelta(days=7), now,")],
     [f"{T}::test_an_hour_long_burst_is_found_and_called_significant"], True),

    ("the week-earlier read not moved back with the window",
     [(B, "start - week, end - week, period, scope, region) if has_week",
       "start - week, end, period, scope, region) if has_week")],
     [f"{T}::test_the_week_earlier_window_is_the_same_window_seven_days_back"], True),

    ("an empty week earlier decides anyway",
     [(B, CHAIN, CHAIN.replace("    elif week_allowed is not None:\n", "    elif True:\n"))],
     [f"{T}::test_no_traffic_a_week_earlier_falls_back_to_the_hours_around_it"], True),

    ("the event read over another window",
     [(B, "    if this[\"event\"]:\n        lines += [", "    if before[\"event\"]:\n        lines += [")],
     [f"{T}::test_an_event_in_the_window_is_reported"], True),

    ("a rise in mitigated traffic from none read as no rise",
     [(B, "(mitigated_x is None or mitigated_x > WOW_ANOMALY_SIGNIFICANT)",
       "(mitigated_x is not None and mitigated_x > WOW_ANOMALY_SIGNIFICANT)")],
     [f"{T}::test_mitigated_traffic_rising_from_none_is_a_rise"], True),

    ("the scan's note back on seven-day totals",
     [(B, "        window = _comparison_window(datetime.fromtimestamp(start_epoch, timezone.utc),\n"
          "                                    datetime.fromtimestamp(end_epoch, timezone.utc), datetime.now(timezone.utc))\n",
       "        window = _comparison_window(datetime.now(timezone.utc) - timedelta(days=7),\n"
          "                                    datetime.now(timezone.utc), datetime.now(timezone.utc))\n")],
     [f"{T}::test_the_scan_compares_its_own_window_a_week_earlier"], True),

    # probe=False: the shadowing test reads source rather than running it, so any inserted line turns
    # it red whether or not the line executes.
    ("the import that silenced the scan's note, back",
     [(B, "            from tools.waf_metrics import log_path_warning\n            _warning",
       "            from tools.waf_metrics import log_path_warning\n"
       "            from tools.session_state import get_webacl_name\n            _warning")],
     [f"{T}::test_the_scan_compares_its_own_window_a_week_earlier",
      "tests/test_local_import_shadowing.py::test_no_function_in_tools_shadows_a_name_it_already_used"], False),
    ("a picked hour set against its own hour a week earlier",
     [(B, "    if peak_x is not None:\n        allowed_x, base, basis = peak_x, peak_prev, peak_label\n",
       "    if False:\n        allowed_x, base, basis = peak_x, peak_prev, peak_label\n")],
     [f"{T}::test_a_picked_hour_is_set_against_the_busiest_hour_of_the_week_before"], True),

    ("the week before's peak read from this week",
     [(B, "            prev_peak = _peak_hour(cw, webacl_name, scope, region, now - week)\n",
       "            prev_peak = _peak_hour(cw, webacl_name, scope, region, now)\n")],
     [f"{T}::test_a_picked_hour_is_set_against_the_busiest_hour_of_the_week_before"], True),

    ("a named window set against a peak",
     [(B, "        prev_peak = None\n        if start_epoch is None:\n",
       "        prev_peak = _peak_hour(cw, webacl_name, scope, region, now - week)\n        if start_epoch is None:\n")],
     [f"{T}::test_a_window_the_user_names_is_not_set_against_a_peak"], True),

    ("a window read past its last whole point",
     [(B, "    return start, max(min(end, last), start + timedelta(seconds=period)), period, has_week\n",
       "    return start, end, period, has_week\n")],
     [f"{T}::test_the_scan_reads_whole_points_and_stops_at_the_last_one"], True),
    ("mitigated traffic set against the same window while ALLOW is set against the peak",
     [(B, "        allowed_x, base, basis = peak_x, peak_prev, peak_label\n",
       "        allowed_x, base, basis = peak_x, prev, peak_label\n")],
     [f"{T}::test_the_table_and_the_mitigated_comparison_use_the_same_peak"], True),

    ("the week before's busiest hour left out of the table",
     [(B, '        + (f" {peak_prev[\'allowed\']:,.0f} |" if peak_prev else ""),\n', '        + "",\n')],
     [f"{T}::test_the_table_and_the_mitigated_comparison_use_the_same_peak"], False),
]

sys.exit(sweep(CASES))
