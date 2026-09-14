#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the weekly report's window label and require `test_report_window_label.py` to notice.

Both halves of the defect are restored here, because they push opposite ways and each one alone looks
like a rounding argument. The zone half moves the start date, and only for offsets on one side of UTC;
the exclusive-end half moves the end date for every offset including UTC.

Every case runs the real function, so all of them ask for the reachability probe.
"""

import sys

from _harness import sweep

R = "tools/report.py"
T = "tests/test_report_window_label.py"

CASES = [
    # The shipped behaviour: format the UTC value the caller never asked in.
    ("the start formatted in UTC again, so the title names the previous day at UTC+8",
     [(R, "{start.astimezone(user_tz).strftime('%Y-%m-%d')}", "{start.strftime('%Y-%m-%d')}")],
     [f"{T}::test_the_start_date_is_the_day_the_caller_asked_for"], True),

    # The plausible wrong fix, and the reason the UTC-5 test exists. It passes the case above.
    ("a fixed eight-hour shift instead of the session zone, which is right for one timezone",
     [(R, "{start.astimezone(user_tz).strftime('%Y-%m-%d')}",
       "{(start + timedelta(hours=8)).strftime('%Y-%m-%d')}")],
     [f"{T}::test_a_negative_offset_moves_the_day_the_other_way"], True),

    ("the exclusive end printed, so a seven-day report names an eighth day",
     [(R, "    last = end - timedelta(seconds=1)", "    last = end")],
     [f"{T}::test_the_end_date_is_the_last_day_covered_not_the_first_day_after"], True),

    # A whole day back is right for an uncapped window and wrong for a capped one, which is the only
    # thing the capped case discriminates.
    ("a whole day stepped back instead of a second, which breaks a window capped at now",
     [(R, "    last = end - timedelta(seconds=1)", "    last = end - timedelta(days=1)")],
     [f"{T}::test_an_end_capped_at_now_names_the_day_it_was_capped_on"], True),

    # Anchored on the whole two-line return rather than on the second line, which is a continuation and
    # cannot take a probe above it.
    ("the zone dropped from the label, leaving two dates nobody can check",
     [(R, """    return (f"{start.astimezone(user_tz).strftime('%Y-%m-%d')} to "
            f"{last.astimezone(user_tz).strftime('%Y-%m-%d')} {tz_label}")""",
       """    return (f"{start.astimezone(user_tz).strftime('%Y-%m-%d')} to "
            f"{last.astimezone(user_tz).strftime('%Y-%m-%d')}")""")],
     [f"{T}::test_the_zone_is_named_in_the_label"], True),
]

sys.exit(sweep(CASES))
