#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_volume_window.py` and `tests/test_local_import_shadowing.py` fail? The volume step
and the scan's spike note put back on seven-day totals, and the local import that silenced the note."""

import sys

from _harness import sweep

B = "tools/waf_bypass.py"
T = "tests/test_volume_window.py"

CASES = [
    ("the volume step compares seven-day totals again",
     [(B, "end, chosen = min(start + timedelta(hours=1), now),", "start, end, chosen = now - timedelta(days=7), now,")],
     [f"{T}::test_an_hour_long_burst_is_found_and_called_significant"], True),

    ("the week-earlier read not moved back with the window",
     [(B, "start - week, end - week, period, scope, region) if has_week",
       "start - week, end, period, scope, region) if has_week")],
     [f"{T}::test_the_week_earlier_window_is_the_same_window_seven_days_back"], True),

    ("an empty week earlier decides anyway",
     [(B, "    if week_allowed is not None:\n", "    if True:\n")],
     [f"{T}::test_no_traffic_a_week_earlier_falls_back_to_the_hours_around_it"], True),

    ("the event read over another window",
     [(B, "    if this[\"event\"]:\n        lines += [", "    if before[\"event\"]:\n        lines += [")],
     [f"{T}::test_an_event_in_the_window_is_reported"], True),

    ("a rise in mitigated traffic from none read as no rise",
     [(B, "(mitigated_x is None or mitigated_x > WOW_ANOMALY_SIGNIFICANT)",
       "(mitigated_x is not None and mitigated_x > WOW_ANOMALY_SIGNIFICANT)")],
     [f"{T}::test_mitigated_traffic_rising_from_none_is_a_rise"], True),

    ("the scan's note back on seven-day totals",
     [(B, "start_dt = datetime.fromtimestamp(start_epoch, timezone.utc)\n        end_dt = datetime.fromtimestamp(end_epoch, timezone.utc)",
       "start_dt = datetime.now(timezone.utc) - timedelta(days=7)\n        end_dt = datetime.now(timezone.utc)")],
     [f"{T}::test_the_scan_compares_its_own_window_a_week_earlier"], True),

    # probe=False: the shadowing test reads source rather than running it, so any inserted line turns
    # it red whether or not the line executes.
    ("the import that silenced the scan's note, back",
     [(B, "            from tools.waf_metrics import log_path_warning\n            _warning",
       "            from tools.waf_metrics import log_path_warning\n"
       "            from tools.session_state import get_webacl_name\n            _warning")],
     [f"{T}::test_the_scan_compares_its_own_window_a_week_earlier",
      "tests/test_local_import_shadowing.py::test_no_function_in_tools_shadows_a_name_it_already_used"], False),
]

sys.exit(sweep(CASES))
