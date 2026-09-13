# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A metric row labelled with a date has to be the sum of that date.

`get_waf_metrics` asked CloudWatch for `Period=86400` whenever the range exceeded 168 hours. A daily
period buckets from `StartTime`, and `StartTime` is `now - period_hours`, so each bucket began at
whatever time of day the question was asked while the table labelled it with its own start.

**Measured against the live account 2026-09-13 at 10:50 UTC**, session timezone UTC+8:
`period_hours=720` reported `2026-09-07 | 566,070` for a rate-limit attack that happened
2026-09-08 04:15 UTC. Midnight-aligned truth: 2026-09-07 00:00-24:00 UTC holds zero and
2026-09-08 holds 566,077. The same tool asked for 168 hours took the hourly branch and answered
`2026-09-08 | 566,073`, so the two ranges contradicted each other and neither output said which to
believe.

**Two assertions, because one of them is about the cause and the other about the effect.** The
requested period is what went wrong; the date grouping is what a reader sees. A test on the grouping
alone passes on the old code as soon as the fake client returns hour-aligned rows, since the fake
decides the bucket shape rather than the code under test.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest

from tools import session_state as S
from tools import waf_metrics as M


class FakeCw:
    """A CloudWatch client that records the request and replays given datapoints."""

    def __init__(self, points=()):
        self.requests = []
        self.points = list(points)

    def get_metric_data(self, **kw):
        self.requests.append(kw)
        return {"MetricDataResults": [{
            "Timestamps": [ts for ts, _ in self.points],
            "Values": [float(v) for _, v in self.points],
        }]}


@pytest.fixture
def cw(monkeypatch):
    fake = FakeCw()
    monkeypatch.setattr(M, "get_client", lambda *a, **k: fake)
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1")
    S.set_user_timezone(8.0)
    return fake


@pytest.mark.parametrize("period_hours", [25, 168, 169, 720, 8760])
def test_a_range_longer_than_a_day_is_never_asked_for_in_daily_buckets(cw, period_hours):
    """The cause. 86400 is the only period whose buckets are not aligned to something a reader can
    name, because the alignment comes from `StartTime` rather than from a clock boundary."""
    M.get_waf_metrics._tool_func(webacl_name="acl", period_hours=period_hours)
    assert cw.requests, "no request was made, so this test proves nothing"
    period = cw.requests[0]["MetricDataQueries"][0]["MetricStat"]["Period"]
    assert period == 3600, f"period_hours={period_hours} asked for Period={period}"


def test_a_day_or_less_still_asks_for_five_minute_buckets(cw):
    """The control for the branch above. Collapsing every range onto one period would satisfy that
    parametrized test and throw away the resolution a same-day question needs."""
    M.get_waf_metrics._tool_func(webacl_name="acl", period_hours=6)
    assert cw.requests[0]["MetricDataQueries"][0]["MetricStat"]["Period"] == 300


def test_each_date_row_sums_the_local_day_it_names(monkeypatch):
    """The effect, asserted on hour buckets that straddle a local midnight.

    The three points are 15:30, 16:30 and 17:30 UTC, which in UTC+8 are 23:30 on one day and 00:30
    and 01:30 on the next. A correct table shows 1 on the first date and 2 on the second. Summing by
    UTC date instead would show 3 on one row, and labelling a `StartTime`-anchored daily bucket would
    show one row with a date that matches neither."""
    day = datetime(2026, 9, 8, tzinfo=timezone.utc)
    points = [(day + timedelta(hours=15, minutes=30), 1),
              (day + timedelta(hours=16, minutes=30), 1),
              (day + timedelta(hours=17, minutes=30), 1)]
    fake = FakeCw(points)
    monkeypatch.setattr(M, "get_client", lambda *a, **k: fake)
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1")
    S.set_user_timezone(8.0)

    out = M.get_waf_metrics._tool_func(webacl_name="acl", period_hours=720)
    rows = dict(re.findall(r"^\| (\d{4}-\d\d-\d\d) \| ([\d,]+) \|$", out, re.M))
    assert rows == {"2026-09-08": "1", "2026-09-09": "2"}, out


def test_a_window_older_than_the_hourly_retention_is_refused_rather_than_shortened(cw):
    """455 days is where 1-hour data stops existing. Answering anyway would report the part that
    survives as the whole, which is the shape of every other defect in this file."""
    out = M.get_waf_metrics._tool_func(webacl_name="acl", period_hours=24 * 456)
    assert "455 days" in out and "Error" in out
    assert not cw.requests, "the refusal has to come before the query, not after it"
