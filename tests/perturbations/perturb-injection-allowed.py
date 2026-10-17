#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_injection_allowed.py` fail, and the Log Filter test beside it? The sections unwired,
the lookback dropped or past the cap, unchecked values passed on, blocked traffic read as allowed, and a
section answering for itself instead of through aggregate_logs, which is the shape that lost the Log
Filter warning."""

import sys

from _harness import sweep

I = "tools/waf_injection.py"
T = "tests/test_injection_allowed.py"

CASES = [
    # probe=False: the target reads the tool's source.
    ("the two sections not run",
     [(I, "    lines += _allowed_sections(aggregate_logs._tool_func, ips, _extract_column(paths, \"httpRequest.uri\"),\n"
          "                               start_time, duration)\n", "")],
     [f"{T}::test_the_investigation_runs_both_sections"], False),

    ("no lookback before the window",
     [(I, "        lookback = max(MAX_MINUTES - duration, 0)\n", "        lookback = 0\n")],
     [f"{T}::test_the_sources_are_read_from_before_the_window_up_to_the_cap"], True),

    ("a lookback past the query cap",
     [(I, "        lookback = max(MAX_MINUTES - duration, 0)\n", "        lookback = MAX_MINUTES\n")],
     [f"{T}::test_the_sources_are_read_from_before_the_window_up_to_the_cap"], True),

    ("any value passed on as an address",
     [(I, '    sources = [ip for ip in ips if not _FILTERS["ip"].check(ip)[1]][:_SOURCES_ALLOWED]\n',
       '    sources = ips[:_SOURCES_ALLOWED]\n')],
     [f"{T}::test_at_most_five_sources_and_only_addresses_reach_the_query"], True),

    ("a path the filter refuses passed on, so the whole section is refused",
     [(I, '    paths = [p for p in target_paths[:_TARGETS] if not _FILTERS["uri"].check(p)[1]]\n',
       '    paths = list(target_paths[:_TARGETS])\n')],
     [f"{T}::test_a_path_the_filter_refuses_is_left_out_and_named"], True),

    ("blocked traffic read as what the sources got through",
     [(I, 'filter_by=json.dumps({"ip": sources, "action": "ALLOW"})', 'filter_by=json.dumps({"ip": sources})')],
     [f"{T}::test_the_sources_are_read_from_before_the_window_up_to_the_cap"], False),

    ("the sources section answering for itself rather than through aggregate_logs",
     [(I, '                agg(start_time=earlier.strftime("%Y-%m-%dT%H:%M"), duration_minutes=lookback + duration,\n'
          '                    group_by="clientIp,uri", filter_by=json.dumps({"ip": sources, "action": "ALLOW"})), ""]',
       '                "  (none: nothing they sent was allowed)", ""]')],
     ["tests/test_aggregate_lists_and_groups.py::test_the_injection_sources_section_under_a_log_filter_does_not_say_nothing_was_allowed",
      f"{T}::test_the_tables_are_the_aggregates_own"], False),
]

sys.exit(sweep(CASES))
