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

    # --- 5.3's trigger. Each case is a way the URI column arrives, and the point of the group is that
    # the four tests fail on different ones: naming the key, not naming it, reading the row wholesale,
    # and the path going away so the pin should be deleted rather than kept.
    ("the URI column added under the name the test predicted",
     "tools/waf_patrol.py",
     '            bar_counted = json.dumps([r["counted"] for r in rules_sorted])',
     '            bar_counted = json.dumps([r["counted"] for r in rules_sorted])\n'
     '            bar_uris = json.dumps([r["log_detail"] for r in rules_sorted])',
     [f"{T}::test_the_patrol_renderer_reads_no_log_derived_key"]),

    # The case the absence claim above cannot catch, which is why the pin exists beside it: a column
    # under a name nobody thought to add to LOG_DERIVED_KEYS.
    ("the URI column added under a name nobody predicted",
     "tools/waf_patrol.py",
     '            bar_counted = json.dumps([r["counted"] for r in rules_sorted])',
     '            bar_counted = json.dumps([r["counted"] for r in rules_sorted])\n'
     '            bar_worst = json.dumps([r["worst_path"] for r in rules_sorted])',
     [f"{T}::test_the_patrol_renderers_key_set_is_pinned_so_a_new_column_fires"]),

    ("a rule row read wholesale, so the column arrives with the pinned set unchanged",
     "tools/waf_patrol.py",
     '            bar_counted = json.dumps([r["counted"] for r in rules_sorted])',
     '            bar_counted = json.dumps([r["counted"] for r in rules_sorted])\n'
     '            bar_all = json.dumps([list(r.values()) for r in rules_sorted])',
     [f"{T}::test_the_patrol_renderer_reads_no_dict_wholesale"]),

    ("the detail rows no longer inside the renderer's argument, so the pin guards nothing",
     "tools/waf_patrol.py", '"log_detail": log_details.get(rule_name, {})',
     '"log_details_out_of_band": log_details.get(rule_name, {})',
     [f"{T}::test_the_attacker_controlled_rows_are_already_inside_the_renderers_argument"]),

    ("a second rules_table row shape, so which row the renderer iterates is no longer decided",
     "tools/waf_patrol.py", "    rules_table.sort(key=lambda x: x[\"total\"], reverse=True)",
     "    rules_table.append({\"name\": \"synthetic\", \"total\": 0})\n"
     "    rules_table.sort(key=lambda x: x[\"total\"], reverse=True)",
     [f"{T}::test_the_attacker_controlled_rows_are_already_inside_the_renderers_argument"]),

    ("a log-derived name that is also a translated label, so the subtraction hides it",
     "tools/waf_patrol.py", '        "title": "Security Patrol Report",',
     '        "title": "Security Patrol Report",\n        "uris": "URIs",',
     [f"{T}::test_the_patrol_renderers_key_set_is_pinned_so_a_new_column_fires"]),

    # The two halves of the extractor. Blinding either one satisfies the pin by having nothing to
    # compare, which is what a detector whose corpus cannot hold the bug looks like from the inside.
    ("the key extractor blinded, so the pin compares two empty sets",
     T, "    keys = set()\n    for node in ast.walk(fn):", "    keys = set()\n    for node in []:",
     [f"{T}::test_the_patrol_renderers_key_set_is_pinned_so_a_new_column_fires"]),

    ("the label extractor returning nothing, so every label lands in the pinned set",
     T, '                if isinstance(key, ast.Constant) and key.value == "en":',
     '                if isinstance(key, ast.Constant) and key.value == "xx":',
     [f"{T}::test_the_patrol_renderers_key_set_is_pinned_so_a_new_column_fires"]),
]

sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4]) for c in CASES]))
