#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_no_log_data_reaches_html.py` claims and require it to notice."""

import sys

from _harness import sweep

T = "tests/test_no_log_data_reaches_html.py"
CASES = [
    ("a log query moved into the scope that renders the patrol HTML",
     "tools/waf_patrol.py",
     "    _latest_patrol_html = _render_patrol_html_v2([wr], all_action_items, start, end, hours, lang)",
     "    from tools.waf_query import query_logs\n"
     "    query_logs('c', 'a', 0, 1)\n"
     "    _latest_patrol_html = _render_patrol_html_v2([wr], all_action_items, start, end, hours, lang)",
     [f"{T}::test_no_html_renderer_sits_beside_a_log_query"]),
    ("a renderer fetching its own log data",
     "tools/waf_patrol.py",
     'def _render_patrol_html_v2(webacl_results: list, all_action_items: list, start, end, hours: int, lang: str = "en") -> str:',
     'def _render_patrol_html_v2(webacl_results: list, all_action_items: list, start, end, hours: int, lang: str = "en") -> str:\n'
     "    from tools.waf_query import query_logs\n"
     "    query_logs('c', 'a', 0, 1)",
     [f"{T}::test_a_renderer_does_not_query_logs_itself",
      f"{T}::test_the_declared_exception_still_exists_and_is_still_the_only_one"]),
    ("the declared exception left behind after it stops holding both",
     T, 'DECLARED = {"report.py:generate_weekly_report"}',
     'DECLARED = {"report.py:gone_function"}',
     [f"{T}::test_the_declared_exception_still_exists_and_is_still_the_only_one"]),
    ("HTML detected by renderer NAME again, so the inline report is invisible",
     T, "    return _builds_html(fn) or bool(_calls_in_own_scope(fn, RENDERERS))",
     "    return bool(_calls_in_own_scope(fn, RENDERERS))",
     [f"{T}::test_the_sweep_found_the_renderers_it_names",
      f"{T}::test_the_declared_exception_still_exists_and_is_still_the_only_one"]),
    ("review_deep stops escaping the markdown it renders",
     "tools/waf_review_deep.py",
     "            html_lines.append(html_mod.escape(line))",
     "            html_lines.append(line)",
     [f"{T}::test_review_deep_escapes_what_it_renders"]),
    ("the raw Insights path dropped from LOG_CALLS, hiding report.py's fourth query path",
     T, '             "aggregate_logs", "_poll_log_query"}', '             "aggregate_logs"}',
     [f"{T}::test_the_declared_exception_still_exists_and_is_still_the_only_one"]),
    ("a fourth raw-Insights call site absorbed by the exemption",
     "tools/report.py",
     "    logs_client = get_client(\"logs\", region_name=region) if log_group else None",
     "    logs_client = get_client(\"logs\", region_name=region) if log_group else None\n"
     "    _extra = _poll_log_query(logs_client, log_group, 0, 1, 'q')",
     [f"{T}::test_the_hand_traced_call_sites_are_pinned_by_count"]),
    ("a raw-Insights value interpolated into HTML as free text",
     "tools/report.py", "    ddos_total = 0", "    ddos_total = str(ddos_total_raw)",
     [f"{T}::test_no_raw_insights_value_reaches_an_html_interpolation"]),
    ("the numeric classifier passing everything, so the exemption excuses free text",
     T, "    return False\n\n\ndef _tainted_names", "    return True\n\n\ndef _tainted_names",
     [f"{T}::test_no_raw_insights_value_reaches_an_html_interpolation"]),
    ("a dynamic-name escape, so a value reaches a template unnamed",
     "tools/report.py", "_latest_report_html: str | None = None",
     "_latest_report_html: str | None = None\n_ = locals()",
     [f"{T}::test_no_dynamic_name_can_reach_a_template"]),
]

sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4]) for c in CASES]))
