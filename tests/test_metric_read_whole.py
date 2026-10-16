# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every CloudWatch metric read is answered whole, by the client every tool gets.

Measured 2026-10-15 on `shield-sample-webacl`: one `GetMetricData` call answers at most 500 series and
cuts SEARCH results to fit, with `StatusCode: Complete` and no message. A label SEARCH answering 45
series alone answered 20 beside 480 MetricStats and 5 beside 495. 501 queries is a `ValidationError`.
Patrol reads five metrics per configured rule beside five SEARCH queries, so a WebACL of about 50
rules lost the sub-rules only SEARCH finds. `_RecordingCloudWatch` is the client `get_client`
returns for CloudWatch, so the fix covers every call site without touching one.
"""

from datetime import datetime, timedelta, timezone

import pytest

from tools.aws_session import _RecordingCloudWatch
from tools import waf_patrol as P

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


class CuttingCW:
    """CloudWatch as measured: 501 queries is refused, and a call answers at most 500 series, with
    SEARCH answers cut to fit and nothing said. `search_series` is how many series each SEARCH has."""

    def __init__(self, search_series=45, stat_value=None):
        self.search_series, self.stat_value = search_series, stat_value or {}
        self.calls = []

    def get_metric_data(self, MetricDataQueries, NextToken=None, **kw):
        self.calls.append([q["Id"] for q in MetricDataQueries])
        if len(MetricDataQueries) > 500:
            raise RuntimeError("ValidationError: MetricDataQueries must not have a size greater than 500")
        out = [{"Id": q["Id"], "Label": "", "Values": [self.stat_value.get(q["Id"], 0)], "Timestamps": [T0]}
               for q in MetricDataQueries if "MetricStat" in q]
        room = 500 - len(out)
        for q in MetricDataQueries:
            if q.get("Expression", "").startswith("SEARCH("):
                n = min(self.search_series, room)
                room -= n
                out += [{"Id": q["Id"], "Label": f"rule{i}|BlockedRequests", "Values": [1], "Timestamps": [T0]}
                        for i in range(n)]
        return {"MetricDataResults": out, "Messages": []}


def test_a_search_beside_many_reads_is_not_cut():
    cw = _RecordingCloudWatch(CuttingCW(search_series=45))
    stats = [{"Id": f"x{i}", "MetricStat": {"Metric": {}, "Period": 60, "Stat": "Sum"}} for i in range(495)]
    resp = cw.get_metric_data(MetricDataQueries=[*stats, {"Id": "s", "Expression": "SEARCH('x', 'Sum', 60)"}],
                              StartTime=T0, EndTime=T0 + timedelta(hours=1))
    assert sum(1 for r in resp["MetricDataResults"] if r["Id"] == "s") == 45
    assert sum(1 for r in resp["MetricDataResults"] if r["Id"].startswith("x")) == 495


def test_the_control_the_fake_does_cut_a_shared_call():
    """Without this, a fake that never cut would pass the test above."""
    raw = CuttingCW(search_series=45)
    stats = [{"Id": f"x{i}", "MetricStat": {"Metric": {}}} for i in range(495)]
    resp = raw.get_metric_data(MetricDataQueries=[*stats, {"Id": "s", "Expression": "SEARCH('x', 'Sum', 60)"}])
    assert sum(1 for r in resp["MetricDataResults"] if r["Id"] == "s") == 5


def test_more_than_500_reads_go_in_calls_cloudwatch_accepts():
    inner = CuttingCW()
    stats = [{"Id": f"x{i}", "MetricStat": {"Metric": {}}} for i in range(605)]
    resp = _RecordingCloudWatch(inner).get_metric_data(MetricDataQueries=stats, StartTime=T0,
                                                       EndTime=T0 + timedelta(hours=1))
    assert [len(c) for c in inner.calls] == [500, 105] and len(resp["MetricDataResults"]) == 605


def test_a_search_at_the_cap_on_its_own_raises():
    cw = _RecordingCloudWatch(CuttingCW(search_series=900))
    with pytest.raises(RuntimeError, match="500-series maximum"):
        cw.get_metric_data(MetricDataQueries=[{"Id": "s", "Expression": "SEARCH('x', 'Sum', 60)"}],
                           StartTime=T0, EndTime=T0 + timedelta(hours=1))


def test_patrol_on_a_webacl_of_many_rules_keeps_every_search_series():
    """90 rules is 455 explicit reads plus five SEARCH queries: one call, under the query limit, and
    the SEARCH answers cut to the 45 series of room left."""
    rules = [{"Name": f"r{i}", "VisibilityConfig": {"MetricName": f"r{i}"}} for i in range(90)]
    inner = CuttingCW(search_series=60)
    m = P._get_all_rules_metrics_search(_RecordingCloudWatch(inner), "acl", T0, T0 + timedelta(hours=1),
                                        period=3600, rules=rules)
    assert max(len(c) for c in inner.calls) <= 500, [len(c) for c in inner.calls]
    assert all(f"rule{i}" in m for i in range(60)), sorted(k for k in m if k.startswith("rule"))[:5]


def test_a_paged_answer_is_joined():
    class Paged:
        def __init__(self):
            self.tokens = []

        def get_metric_data(self, MetricDataQueries, NextToken=None, **kw):
            self.tokens.append(NextToken)
            t = T0 if NextToken is None else T0 + timedelta(hours=1)
            return {"MetricDataResults": [{"Id": "m", "Label": "", "Values": [5], "Timestamps": [t]}],
                    **({"NextToken": "p2"} if NextToken is None else {})}
    inner = Paged()
    resp = _RecordingCloudWatch(inner).get_metric_data(
        MetricDataQueries=[{"Id": "m", "MetricStat": {}}], StartTime=T0, EndTime=T0 + timedelta(hours=2))
    assert inner.tokens == [None, "p2"] and resp["MetricDataResults"][0]["Values"] == [5, 5], resp
