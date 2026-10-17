#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_report_escaping.py` fail? Each escape taken out on its own."""

import sys

from _harness import sweep

T = "tests/test_report_escaping.py"
P = "tools/waf_patrol.py"
R = "tools/report.py"
H = "tools/html_safe.py"
PATROL = f"{T}::test_the_patrol_report_renders_every_string_as_text"
WEEKLY = f"{T}::test_the_weekly_report_renders_every_string_as_text"

CASES = [
    ("the patrol renderer's input not escaped",
     [(P, "    webacl_results, all_action_items = escaped(webacl_results), escaped(all_action_items)\n", "")],
     [PATROL]),

    ("the patrol report JSON dumped as it was",
     [(P, "    report_json = script_json({", "    report_json = json.dumps({")],
     [f"{T}::test_the_patrol_report_json_keeps_the_raw_values"]),

    ("the summary's HTML passed through again",
     [(R, 'summary_html = markdown.markdown(escape(summary, quote=False), extensions=["smarty"])',
       'summary_html = markdown.markdown(summary, extensions=["smarty"])')],
     [WEEKLY]),

    ("the attack data dumped into its script as it was",
     [(R, "        attack_data_json=script_json(attack_ts),", "        attack_data_json=json.dumps(attack_ts),")],
     [WEEKLY]),

    ("dict keys not escaped",
     [(H, "        return {escaped(k): escaped(v) for k, v in value.items()}", "        return {k: escaped(v) for k, v in value.items()}")],
     [f"{T}::test_escaped_reaches_every_string_keys_included", PATROL]),

    ("a backslash left as it is",
     [(H, '        return html.escape(value).replace("\\\\", "&#92;")', "        return html.escape(value)")],
     [f"{T}::test_escaped_reaches_every_string_keys_included"]),

    ("script JSON leaving < alone",
     [(H, '            .replace("<", "\\\\u003c").replace(">", "\\\\u003e").replace("&", "\\\\u0026"))', "            )")],
     [f"{T}::test_script_json_cannot_close_its_element_and_reads_back_the_same", WEEKLY]),
]

sys.exit(sweep(CASES))
