#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_mask_coverage.py` claims and require it to notice."""

import sys

from _harness import sweep

T = "tests/test_mask_coverage.py"
Q = "tools/waf_query.py"
CASES = [
    ("the namespace lookbehind removed, so a WAF label masks again", Q,
     r'r"(?i)((?<!:)(session|sess|auth|token|secret|csrf|xsrf|password|passwd|sid|apikey|"',
     r'r"(?i)((session|sess|auth|token|secret|csrf|xsrf|password|passwd|sid|apikey|"',
     [f"{T}::test_a_waf_label_is_not_read_as_a_credential_assignment"]),
    ("the lookbehind widened to a word char, which kills PHPSESSID", Q,
     r'r"(?i)((?<!:)(session|sess|auth|token|secret|csrf|xsrf|password|passwd|sid|apikey|"',
     r'r"(?i)((?<![:\w])(session|sess|auth|token|secret|csrf|xsrf|password|passwd|sid|apikey|"',
     [f"{T}::test_a_credential_name_inside_a_longer_cookie_name_still_masks"]),
    ("the colon dropped from the assignment class, closing the boundary silently", Q,
     'api[-_]?key|access[-_]?token|bearer)\\w*\\s*[=:]\\s*\\S)',
     'api[-_]?key|access[-_]?token|bearer)\\w*\\s*[=]\\s*\\S)',
     [f"{T}::test_a_bare_short_form_label_is_still_masked_which_is_the_known_boundary"]),
    ("waf_overview reaching the masker, which gives the boundary a live path",
     "tools/waf_overview.py", "from tools.session_state import get_scope, get_user_timezone",
     "from tools.session_state import get_scope, get_user_timezone\n"
     "from tools.waf_query import query_logs  # noqa: F401",
     [f"{T}::test_the_metrics_label_path_does_not_reach_the_masker"]),
    ("the raw-record exclusion dropped", Q,
     '_NEVER_MASK_COLUMNS = frozenset({"@message"})',
     "_NEVER_MASK_COLUMNS = frozenset()",
     [f"{T}::test_the_raw_record_column_is_never_masked"]),
    ("the exclusion widened to every column", Q,
     "            if key in _NEVER_MASK_COLUMNS:", "            if True:",
     [f"{T}::test_the_raw_record_column_is_never_masked",
      f"{T}::test_a_credential_name_inside_a_longer_cookie_name_still_masks"]),
    ("masking moved back out of the funnel", Q,
     "    if redact_row_fields(rows):", "    if False:",
     [f"{T}::test_masking_happens_inside_the_funnel_so_no_consumer_can_forget",
      f"{T}::test_a_masked_row_still_tells_the_user_why"]),
    ("a consumer masking its own rows again", "tools/waf_logs.py",
     "    # Use row with most keys for column headers",
     "    from tools.waf_query import redact_row_fields\n"
     "    redact_row_fields(results)\n"
     "    # Use row with most keys for column headers",
     [f"{T}::test_masking_happens_inside_the_funnel_so_no_consumer_can_forget"]),
    ("the mask/scan order inverted, which no value survives to reveal", Q,
     "    if redact_row_fields(rows):\n        with _value_findings_lock:\n"
     '            _value_findings["masked"].add("row")\n    return rows',
     "    return rows",
     [f"{T}::test_the_scan_runs_before_the_mask"]),
    ("a template selecting the excluded column for display", "tools/waf_logs.py",
     '"query": "filter httpRequest.clientIp = \'{ip}\' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}"',
     '"query": "filter httpRequest.clientIp = \'{ip}\' | fields @message | limit {limit}"',
     [f"{T}::test_no_display_template_selects_the_excluded_column"]),
]

sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4]) for c in CASES]))
