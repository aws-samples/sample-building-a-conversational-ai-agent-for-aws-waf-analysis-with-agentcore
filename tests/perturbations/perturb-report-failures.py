#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_report_failures_named.py` claims and require it to notice.

Each handler is reverted to its `pass` by removing what it records, one at a time, plus the
over-correction of an always-unknown DDoS card, which only the quiet-week control catches.
"""

import sys

from _harness import sweep

T = "tests/test_report_failures_named.py"
R = "tools/report.py"

CASES = [
    ("the total without CAPTCHA again",
     [(R, '    total_this = this_week["allowed"] + this_week["blocked"] + this_week["challenge"] + this_week["captcha"]',
       '    total_this = this_week["allowed"] + this_week["blocked"] + this_week["challenge"]')],
     [f"{T}::test_the_total_includes_captcha"], True),

    ("a failed solved count left at zero",
     [(R, '            solved_error = f"{type(exc).__name__}: {exc}"', "            solved_error = None")],
     [f"{T}::test_a_failed_solved_count_is_not_zero"], True),

    ("a failed logging read explained by the destination again",
     [(R, '            log_dest_error = f"{type(exc).__name__}: {exc}"', "            log_dest_error = None")],
     [f"{T}::test_a_failed_logging_read_is_not_explained_as_an_s3_destination"], True),

    ("a failed bot section left to the discovery explanation",
     [(R, '            section_skips["bot_control"] = (f"the Bot Control queries failed',
       '            _unused = (f"the Bot Control queries failed')],
     [f"{T}::test_a_failed_bot_section_names_its_failure_not_metric_discovery"], True),

    ("a failed DDoS count shown as no events again",
     [(R, "    if ddos_count_error:\n        ddos_status =", "    if False:\n        ddos_status =")],
     [f"{T}::test_a_failed_ddos_event_count_is_not_no_events"], True),

    ("the over-correction: the DDoS card always unknown",
     [(R, "    if ddos_count_error:\n        ddos_status =", "    if True:\n        ddos_status =")],
     [f"{T}::test_a_quiet_ddos_count_still_says_no_events"], True),

    ("the summary tool asking for ROI language again",
     [(R, "    that answers: What happened this week? What did AWS WAF protect? Follow the tone rule\n",
       "    that answers: What happened this week? What did AWS WAF protect? Is the investment worth it? Follow the tone rule\n")],
     [f"{T}::test_the_summary_tool_does_not_ask_for_the_roi_language_the_report_bans"]),
]

sys.exit(sweep(CASES))
