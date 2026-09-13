#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Restore the daily bucket and require `test_metric_period.py` to name the wrong day.

The first case is the shipped defect: `Period=86400` over a `StartTime` of `now - period_hours`, so the
buckets began at the hour the question was asked and the table labelled each with its own start. On the
live account that put a 566,070-request attack under the day before the one it happened on.

The remaining cases cover what a careless fix breaks: collapsing every range onto one period, dropping
the local-time conversion the date labels depend on, and answering a window whose data no longer exists.
"""

import sys

from _harness import sweep

T = "tests/test_metric_period.py"
M = "tools/waf_metrics.py"

PERIOD = "    period = 300 if period_hours <= 24 else 3600"
GUARD = ("    if period_hours > 24 * 455:\n"
         "        return (f\"Error: CloudWatch keeps 1-hour metric data for 455 days, so a "
         "{period_hours}h \"\n")

CASES = [
    # The shipped defect, restored exactly.
    ("the daily bucket restored, i.e. an attack reported under the wrong date",
     [(M, PERIOD,
       "    if period_hours <= 24:\n"
       "        period = 300\n"
       "    elif period_hours <= 168:\n"
       "        period = 3600\n"
       "    else:\n"
       "        period = 86400")],
     [f"{T}::test_a_range_longer_than_a_day_is_never_asked_for_in_daily_buckets"], True),

    # The careless fix: one period everywhere. Passes the case above and throws away the resolution
    # a same-day question needs.
    ("every range collapsed onto hour buckets, losing same-day resolution",
     [(M, PERIOD, "    period = 3600")],
     [f"{T}::test_a_day_or_less_still_asks_for_five_minute_buckets"], True),

    # The other direction, which is the one the parametrized case exists to catch.
    ("five-minute buckets for every range, beyond where they are retained",
     [(M, PERIOD, "    period = 300")],
     [f"{T}::test_a_range_longer_than_a_day_is_never_asked_for_in_daily_buckets"], True),

    # The date labels depend on this conversion, and the tool renders them for a session that chose
    # a timezone. Grouping by UTC merges a local day boundary into the wrong row.
    ("the local-time conversion dropped, so the date rows are UTC days",
     [(M, "    if tz_off is not None:\n", "    if False:\n")],
     [f"{T}::test_each_date_row_sums_the_local_day_it_names"], True),

    ("the retention refusal removed, so the surviving part is reported as the whole",
     [(M, GUARD, "    if False:\n" + GUARD.split("\n", 1)[1])],
     [f"{T}::test_a_window_older_than_the_hourly_retention_is_refused_rather_than_shortened"], True),
]

sys.exit(sweep(CASES))
