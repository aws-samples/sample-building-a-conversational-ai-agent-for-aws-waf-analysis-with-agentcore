# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The overview reads a window weeks old as CloudWatch still holds it.

Measured 2026-10-15 on `response-id-on-page`, window 2026-09-08 04:00-05:00, where the SQLi rule
blocked 120 and 1,923 requests were allowed. `get_waf_overview(top_rules)` said "No metrics data
... Verify the WebACL name and time range", for two independent reasons:

- **SEARCH discovers only metrics with data in the last 14 days, counted from now.** It returned
  no SQLi series at all. This is the defect patrol had, and the fix is the same: every rule in the
  WebACL's configuration is also read with an explicit MetricStat.
- **One-minute data is kept for 15 days.** A 60-minute window asked for `Period=60`, and the
  explicit Rule=ALL read that exists to be immune to SEARCH answered `StatusCode: Complete` with
  60 zeros. `Period=300` and `Period=3600` both answered 1,923. Every overview query type chose
  its period from the window's length alone, so this hit all eight of them.

`_has_mitigated_traffic`, which tells "not indexed" from "none" for the four breakdowns that stay
SEARCH-only, used the window's length in seconds as its period. A window clipped at now is not a
whole number of minutes, which is a `ValidationError` (measured), and the bare `except` turned that
into "no activity".
"""

import re
from datetime import datetime, timedelta, timezone

import pytest

from tools import session_state as S
from tools import waf_overview as O
from tools import waf_patrol as P

NOW = datetime.now(timezone.utc)
OLD = (NOW - timedelta(days=37)).replace(minute=0, second=0, microsecond=0)
HOUR = timedelta(hours=1)

ACL = [
    {"Name": "AWS-AWSManagedRulesSQLiRuleSet", "Statement": {"ManagedRuleGroupStatement": {}},
     "VisibilityConfig": {"CloudWatchMetricsEnabled": True, "MetricName": "SQLiMetric"}},
    {"Name": "RateLimit200", "Statement": {"RateBasedStatement": {"Limit": 200}},
     "VisibilityConfig": {"CloudWatchMetricsEnabled": True, "MetricName": "rate200-metric"}},
    {"Name": "RateDark", "Statement": {"RateBasedStatement": {"Limit": 100}},
     "VisibilityConfig": {"CloudWatchMetricsEnabled": False, "MetricName": "RateDark"}},
]
OLD_TRAFFIC = {("SQLiMetric", "BlockedRequests"): 120, ("ALL", "BlockedRequests"): 130,
               ("ALL", "AllowedRequests"): 1923}


def _dim(metric, name):
    return next((d["Value"] for d in metric["Dimensions"] if d["Name"] == name), None)


def render_label(query, dims: dict, metric: str, n_series: int) -> str:
    """The label CloudWatch gives a SEARCH series. With a template, the template filled in.
    Without one, the measured default: the metric name for a lone series, otherwise only the
    dimension that varies."""
    template = query.get("Label")
    if not template:
        return metric if n_series == 1 else next(iter(dims.values()))
    template = template.replace("${PROP('MetricName')}", metric)
    for k, v in dims.items():
        template = template.replace(f"${{PROP('Dim.{k}')}}", v)
    return template


class RetainingCW:
    """CloudWatch as measured: SEARCH finds only `discoverable` series, a read finer than
    `retained` answers no values, and a Period that is not a multiple of 60 or more than 500
    queries in a call is a ValidationError. `FILL(x,0)` answers zeros where `x` had nothing."""

    def __init__(self, data, discoverable=frozenset({("ALL", "AllowedRequests")}), retained=300):
        self.data, self.discoverable, self.retained = data, discoverable, retained
        self.periods, self.calls = [], 0

    def _value(self, rule, name, period):
        self.periods.append(period)
        if period % 60:
            raise RuntimeError("ValidationError: Period must be a multiple of 60")
        v = self.data.get((rule, name), 0)
        return [v] if v and period >= self.retained else []

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
        self.calls += 1
        if len(MetricDataQueries) > 500:
            raise RuntimeError("ValidationError: MetricDataQueries must not have a size greater than 500")
        raw, out = {}, []
        for q in MetricDataQueries:
            expr = q.get("Expression", "")
            if "MetricStat" in q:
                st = q["MetricStat"]
                vals = self._value(_dim(st["Metric"], "Rule"), st["Metric"]["MetricName"], st["Period"])
                raw[q["Id"]] = vals
                if q.get("ReturnData", True):
                    out.append({"Id": q["Id"], "Label": "", "Values": vals, "Timestamps": [StartTime] * len(vals)})
            elif expr.startswith("FILL("):
                vals = raw.get(expr[5:].split(",")[0]) or [0]
                out.append({"Id": q["Id"], "Label": "", "Values": vals, "Timestamps": [StartTime] * len(vals)})
            elif expr.startswith("SEARCH("):
                period = int(expr.rsplit(",", 1)[1].strip(" )"))
                if "{AWS/WAFV2,Rule,WebACL}" not in expr:
                    self.periods.append(period)  # label and attack-type dimensions: none discoverable
                    continue
                metric = re.search(r'MetricName="(\w+)"', expr).group(1)
                hits = [(rule, vals) for rule, name in self.discoverable if name == metric
                        for vals in [self._value(rule, name, period)] if vals]
                for rule, vals in hits:
                    out.append({"Id": q["Id"], "Label": render_label(q, {"Rule": rule}, metric, len(hits)),
                                "Values": vals, "Timestamps": [StartTime]})
        return {"MetricDataResults": out}


class FakeWaf:
    def __init__(self, fails=False):
        self.fails = fails

    def list_web_acls(self, Scope):
        return {"WebACLs": [{"Name": "acl", "Id": "id1", "ARN": "arn:aws:wafv2:us-east-1:1:global/webacl/acl/id1"}]}

    def get_web_acl(self, Name, Scope, Id):
        if self.fails:
            raise RuntimeError("AccessDeniedException: not authorized to perform wafv2:GetWebACL")
        return {"WebACL": {"Rules": ACL}}


@pytest.fixture
def overview(monkeypatch):
    def run(query_type, cw, start=OLD, minutes=60, waf=None):
        waf = waf or FakeWaf()
        monkeypatch.setattr(O, "get_client", lambda svc, **k: {"cloudwatch": cw, "wafv2": waf}[svc])
        monkeypatch.setattr(O, "declare_query_subject", lambda name: None)
        monkeypatch.setattr(O, "get_user_timezone", lambda: 0)
        monkeypatch.setattr(S, "get_user_timezone", lambda: 0)
        monkeypatch.setattr(S, "refuse_if_regional", lambda scope: "")
        monkeypatch.setattr(S, "resolve_region", lambda scope: "us-east-1")
        return O.get_waf_overview._tool_func(query_type=query_type, webacl_name="acl", minutes=minutes,
                                             start_time=start.strftime("%Y-%m-%dT%H:%M") if start else "",
                                             scope="CLOUDFRONT")
    return run


def test_top_rules_on_an_old_window_finds_the_rule_search_missed(overview):
    cw = RetainingCW(OLD_TRAFFIC)
    out = overview("top_rules", cw)
    row = next((l for l in out.splitlines() if l.startswith("SQLiMetric")), None)
    assert row and row.split()[1] == "120", out
    assert "blocked 130" in out and "allowed 1,923" in out, out
    assert "No metrics data" not in out


def test_the_control_a_recent_window_still_reads_one_minute_points(overview):
    """Without this, a period fixed at 3600 everywhere would pass the test above."""
    cw = RetainingCW(OLD_TRAFFIC, retained=60)
    overview("top_rules", cw, start=NOW - 2 * HOUR)
    assert set(cw.periods) == {60}, sorted(set(cw.periods))


@pytest.mark.parametrize("age_days,expected", [(1, 60), (37, 300), (100, 3600)])
def test_the_period_is_never_finer_than_cloudwatch_keeps(age_days, expected):
    assert O._calc_period(60, NOW - timedelta(days=age_days)) == expected
    assert O._calc_period(10080, NOW - timedelta(days=age_days)) == 3600, "a coarse period got finer"


@pytest.mark.parametrize("query_type", ["top_rules", "attack_types", "bot_summary", "bot_names",
                                        "targeted_signals", "rate_limits", "challenge_solve_rate",
                                        "top_labels"])
def test_no_query_type_asks_for_points_cloudwatch_no_longer_holds(overview, query_type):
    cw = RetainingCW(OLD_TRAFFIC)
    overview(query_type, cw)
    assert cw.periods and min(cw.periods) >= 300, (query_type, sorted(set(cw.periods)))


def test_a_window_past_every_retention_says_so(overview):
    out = overview("top_rules", RetainingCW({}), start=NOW - timedelta(days=500))
    assert "455 days" in out and "Verify the WebACL name" not in out, out


def test_a_failed_config_read_is_disclosed_in_top_rules(overview):
    out = overview("top_rules", RetainingCW(OLD_TRAFFIC), waf=FakeWaf(fails=True))
    assert "AccessDeniedException" in out and "14 days" in out, out


def test_rate_limits_reads_each_rate_rule_by_its_metric_name(overview):
    """`rate200-metric` is the dimension, `RateLimit200` the rule. The old lookup compared SEARCH's
    metric names against rule names, so a rate rule whose two names differ was never listed."""
    cw = RetainingCW({("rate200-metric", "BlockedRequests"): 12, ("rate200-metric", "CaptchaRequests"): 3,
                      ("rate200-metric", "CountedRequests"): 40})
    out = overview("rate_limits", cw)
    line = next((l for l in out.splitlines() if "RateLimit200" in l), "")
    assert "55" in line and "captcha 3" in line and "counted 40" in line, out


def test_rate_limits_names_a_rate_rule_with_metrics_off(overview):
    out = overview("rate_limits", RetainingCW({}))
    assert "RateDark" in out and "metrics" in out.split("RateDark", 1)[1][:200].lower(), out
    assert "no triggers in this period" in out, "the quiet rule with metrics on lost its zero"


def test_rate_limits_does_not_report_no_rate_rules_when_the_config_read_failed(overview):
    out = overview("rate_limits", RetainingCW({}), waf=FakeWaf(fails=True))
    assert "No rate-limit rules detected" not in out and "AccessDeniedException" in out, out


def test_rate_limits_idle_rule_is_a_zero_while_other_rules_block(overview):
    out = overview("rate_limits", RetainingCW({("SQLiMetric", "BlockedRequests"): 500}))
    assert "no triggers in this period" in out, out


def test_challenge_counts_search_missed_are_read_directly(overview):
    out = overview("challenge_solve_rate", RetainingCW({("ALL", "ChallengeRequests"): 30}))
    assert re.search(r"Challenges issued:\s+30\b", out), out


def test_solved_counts_are_read_for_the_window_not_a_week(overview):
    """`Period=604800` on a one-hour window read past its end: measured 2026-10-15, 130,678
    allowed against 1,896 for the hour itself."""
    cw = RetainingCW({("ALL", "ChallengeRequests"): 30, ("ALL", "ChallengesSolved"): 6})
    out = overview("challenge_solve_rate", cw)
    assert re.search(r"Challenges solved:\s+6\s+\(20% solve rate\)", out), out
    assert max(cw.periods) <= 3600, sorted(set(cw.periods))


def test_a_failed_solved_read_is_not_zero(overview):
    class _SolvedFails(RetainingCW):
        def _value(self, rule, name, period):
            if name.endswith("Solved"):
                raise RuntimeError("ThrottlingException: rate exceeded")
            return super()._value(rule, name, period)
    out = overview("challenge_solve_rate", _SolvedFails({("ALL", "ChallengeRequests"): 30}))
    assert "Challenges solved:           0" not in out and "ThrottlingException" in out, out
    assert "solve rate" not in out.split("ThrottlingException", 1)[0].split("Challenges solved", 1)[1], out


def test_challenges_none_solved_is_a_low_solve_rate(overview):
    """The verdict needed a nonzero solved count, so every challenge failing gave no verdict."""
    out = overview("challenge_solve_rate", RetainingCW({("ALL", "ChallengeRequests"): 30}))
    assert "Low solve rate (0%)" in out, out


def test_blocked_only_traffic_is_still_no_challenges(overview):
    out = overview("challenge_solve_rate", RetainingCW({("ALL", "BlockedRequests"): 500}))
    assert "No challenges or CAPTCHAs issued" in out, out


# --- the "not indexed or none" check behind the four SEARCH-only breakdowns ----------------------

def test_a_window_clipped_at_now_is_still_checked():
    """A window clipped at now is a whole number of minutes only when now falls on second 0, so
    this passes the clipped shape directly: going through `get_waf_overview` made it pass under
    the old period one run in 60. Its length in seconds was the period."""
    cw = RetainingCW({("ALL", "BlockedRequests"): 9}, retained=60)
    start = NOW - timedelta(hours=1)
    out = O._attack_types(cw, "acl", start, start + timedelta(minutes=47, seconds=13), 60)
    assert "PARTIAL DATA" in out, out


def test_an_old_window_is_checked_at_a_retained_period(overview):
    out = overview("attack_types", RetainingCW({("ALL", "BlockedRequests"): 9}))
    assert "PARTIAL DATA" in out, out


def test_the_control_no_mitigation_is_no_attack_data(overview):
    out = overview("attack_types", RetainingCW({}))
    assert "No attack data in this period" in out, out


class _FailingStatCW(RetainingCW):
    def _value(self, rule, name, period):
        raise RuntimeError("ThrottlingException: rate exceeded")


@pytest.mark.parametrize("query_type,none_text", [
    ("attack_types", "No attack data"), ("bot_names", "No bot name data"),
    ("targeted_signals", "No targeted bot signals"), ("top_labels", "No label metrics found")])
def test_a_failed_check_is_not_read_as_no_activity(overview, query_type, none_text):
    out = overview(query_type, _FailingStatCW({}))
    assert none_text not in out and "ThrottlingException" in out, out


def test_top_rules_gap_detection_names_both_possible_causes():
    """Moved from `test_overview_partial_data.py`. Configured rules are read directly now, so the
    14-day cause narrows to the sub-rules only SEARCH finds, and it must still be named."""
    import pathlib
    src = pathlib.Path(O.__file__).read_text()
    block = src[src.index("Gap detection"):src.index("Gap detection") + 900]
    assert "sub-rule" in block and ("14-day" in block or "14 days" in block), block


def test_bypass_volume_reads_all_without_search(monkeypatch):
    """Bypass uses only the `ALL` series. Its windows end now, so SEARCH would usually find it, but
    nothing it consumes should depend on discovery."""
    from tools import waf_bypass as B
    cw = RetainingCW({("ALL", "AllowedRequests"): 1000, ("ALL", "BlockedRequests"): 40},
                     discoverable=frozenset(), retained=60)
    monkeypatch.setattr(B, "get_client", lambda svc, **k: cw)
    monkeypatch.setattr(B, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(B, "get_scope", lambda: "CLOUDFRONT")
    monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")
    out = B._step_volume_anomaly()
    assert "| ALLOW | 1,000 | 1,000 |" in out and "| 40 | 40 |" in out, out


# --- the window CloudWatch answers ---------------------------------------------------------------

class ClockCW:
    """Points placed as measured 2026-10-16: the first at StartTime rounded down to the resolution
    still kept for data that old (a minute to 15 days, five minutes to 63, an hour after), then one
    every period while it starts before EndTime. Each point holds `per_minute` times its length, so a
    reading says how much time it really covered. `reads` records each read's window and period."""

    def __init__(self, per_minute, now=None):
        self.per_minute, self.now, self.reads = per_minute, now or NOW, []

    def points(self, start, end, period):
        age = self.now - start
        step = 60 if age <= timedelta(days=15) else 300 if age <= timedelta(days=63) else 3600
        t = start - timedelta(seconds=int(start.timestamp()) % step, microseconds=start.microsecond)
        out = []
        while t < end:
            out.append(t)
            t += timedelta(seconds=period)
        return out

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
        raw, out = {}, []
        for q in MetricDataQueries:
            if "MetricStat" in q:
                st, m = q["MetricStat"], q["MetricStat"]["Metric"]
                self.reads.append((StartTime, EndTime, st["Period"]))
                rate = self.per_minute.get((_dim(m, "Rule"), m["MetricName"]), 0)
                ts = self.points(StartTime, EndTime, st["Period"]) if rate else []
                raw[q["Id"]] = (ts, [rate * st["Period"] // 60] * len(ts), st["Period"])
                if q.get("ReturnData", True):
                    out.append({"Id": q["Id"], "Label": "", "Values": raw[q["Id"]][1], "Timestamps": ts})
            elif q.get("Expression", "").startswith("FILL("):
                ts, vals, period = raw[q["Expression"][5:].split(",")[0]]
                if not vals:
                    ts = self.points(StartTime, EndTime, period)
                    vals = [0] * len(ts)
                out.append({"Id": q["Id"], "Label": "", "Values": vals, "Timestamps": ts})
            elif q.get("Expression", "").startswith("SEARCH("):
                self.reads.append((StartTime, EndTime, int(q["Expression"].rsplit(",", 1)[1].strip(" )"))))
        return {"MetricDataResults": out}

    def misread(self):
        """The reads whose points do not cover exactly the window sent."""
        return [(s, e, p) for s, e, p in self.reads
                if (pts := self.points(s, e, p)) and (pts[0] != s or pts[-1] + timedelta(seconds=p) != e)]


OLD97 = (NOW - timedelta(days=97)).replace(minute=0, second=0, microsecond=0)


def test_a_half_hour_97_days_old_is_widened_and_says_so(overview):
    """The reviewer's case: 04:30-05:00 at 3600 answered the whole hour. The figure must either be
    the half hour, or say it is the hour."""
    out = overview("top_rules", ClockCW({("ALL", "AllowedRequests"): 1}), start=OLD97 + timedelta(minutes=30), minutes=30)
    assert "allowed 60" in out, out
    hour = lambda t: t.strftime("%Y-%m-%d %H:%M")
    assert f"covers {hour(OLD97)} to {hour(OLD97 + HOUR)}" in out, out


def test_an_old_window_off_the_clock_reads_whole_points(overview):
    """37 days old, 04:02 for 30 minutes, points of five minutes on the clock."""
    start = OLD + timedelta(minutes=2)
    out = overview("top_rules", ClockCW({("ALL", "AllowedRequests"): 1}), start=start, minutes=30)
    total = int(re.search(r"allowed ([\d,]+)", out).group(1).replace(",", ""))
    covered = re.search(r"covers (\d{4}-\d\d-\d\d \d\d:\d\d) to (\d{4}-\d\d-\d\d \d\d:\d\d)", out)
    assert covered, out
    span = datetime.fromisoformat(covered.group(2)) - datetime.fromisoformat(covered.group(1))
    assert total == span.total_seconds() // 60, (total, covered.groups())


@pytest.fixture
def mid_minute_clock(monkeypatch):
    """`now` thirty seconds into a minute, an hour before the real one.

    **The control below read the real clock, and once a minute it could not fail.** Its window starts
    at now less 24 hours and is rounded down to the minute; at a whole second there is nothing to round,
    the window is exactly 96 points of 15 minutes, and its end is now, so `read_end = end` gave no note
    either and the perturbation that drops the clamp survived. Measured: the CI sweep of 78cb98b on
    2026-10-17 reported it caught 23 of 24, and the rerun passed."""
    from tools import waf_metrics as M
    import types
    now = datetime.fromtimestamp(int(NOW.timestamp()) // 60 * 60 - 3600 + 30, timezone.utc)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return now if tz else now.replace(tzinfo=None)
    monkeypatch.setattr(O, "datetime", Clock)
    monkeypatch.setattr(M, "time", types.SimpleNamespace(time=lambda: now.timestamp()))
    return now


def test_the_control_a_window_ending_now_carries_no_note(overview, mid_minute_clock):
    """A default "past 24 hours" ends at now, mid-minute, so whole points run past it, and reading
    past now reads nothing. No start_time, or the window would end on a whole minute instead."""
    cw = ClockCW({("ALL", "AllowedRequests"): 1}, now=mid_minute_clock)
    out = overview("top_rules", cw, start=None, minutes=1440)
    assert "Note: CloudWatch answers" not in out, out


@pytest.fixture
def fixed_clock(monkeypatch):
    """`now` two minutes past a five-minute line that is not on the hour, so a retention line falls
    between two five-minute points and rounding to five minutes and to the hour differ."""
    from tools import waf_metrics as M
    import types
    now = datetime.fromtimestamp(int(NOW.timestamp()) // 3600 * 3600 + 25 * 60 + 120, timezone.utc)
    monkeypatch.setattr(M, "time", types.SimpleNamespace(time=lambda: now.timestamp()))
    return now


def test_the_previous_window_is_read_in_whole_points_across_the_63_day_line(overview, fixed_clock):
    """The reviewer's case. The step was chosen from the previous window's start before the window
    moved, moving it took that start past 63 days, and the previous window was then read at 3600 over
    a window that was not whole hours: 25 hours for 24 h 15 min, overlapping the current one. Here
    the current window starts 180 s past a five-minute line, so rounding it moves the previous
    window's start 180 s back, across the line, which sits 120 s past one."""
    line = fixed_clock - timedelta(days=63)
    start = line + timedelta(days=1, seconds=60)
    cw = ClockCW({("ALL", "AllowedRequests"): 1}, now=fixed_clock)
    overview("top_rules", cw, start=start, minutes=1440)
    assert {p for _, _, p in cw.reads} == {3600}, sorted({p for _, _, p in cw.reads})
    assert not cw.misread(), cw.misread()


def test_a_window_moved_past_the_63_day_line_is_read_and_described_whole(overview, fixed_clock):
    """attack_types, six hours starting just inside 63 days: the window moved past the line, the
    reader chose 3600 from the moved start, and the note still said five-minute points."""
    start = fixed_clock - timedelta(days=63) + timedelta(seconds=60)
    cw = ClockCW({("ALL", "BlockedRequests"): 1}, now=fixed_clock)
    out = overview("attack_types", cw, start=start, minutes=360)
    assert not cw.misread(), cw.misread()
    assert {p for _, _, p in cw.reads} == {3600}, sorted({p for _, _, p in cw.reads})
    assert "whole 60-minute points" in out, out


def test_the_control_a_window_well_inside_63_days_keeps_five_minute_points(overview, fixed_clock):
    start = fixed_clock - timedelta(days=40)
    cw = ClockCW({("ALL", "BlockedRequests"): 1}, now=fixed_clock)
    overview("attack_types", cw, start=start, minutes=360)
    assert {p for _, _, p in cw.reads} == {300} and not cw.misread(), cw.reads


def test_an_old_window_moves_only_to_the_resolution_kept(overview):
    """37 days old, a day from 04:07 at 900: points start at 04:05. Rounding to the period instead
    took the window to 04:00."""
    start = OLD + timedelta(minutes=7)
    out = overview("top_rules", ClockCW({("ALL", "AllowedRequests"): 1}), start=start, minutes=1440)
    hm = lambda t: t.strftime("%Y-%m-%d %H:%M")
    assert f"covers {hm(OLD + timedelta(minutes=5))} to" in out, out


def test_a_start_moved_past_63_days_is_rounded_to_the_hour_when_the_period_is_already_an_hour(overview, fixed_clock):
    """The loop checked only the period. Over 4,320 minutes the period is 3600 from the start, so it
    never changed, and a start moved past 63 days stayed rounded to five minutes: the reviewer's
    case sent 03:35 at 3600 where CloudWatch reads from 03:00."""
    start = fixed_clock - timedelta(days=63) + timedelta(seconds=60)
    cw = ClockCW({("ALL", "BlockedRequests"): 1}, now=fixed_clock)
    overview("attack_types", cw, start=start, minutes=5000)
    assert cw.reads and not cw.misread(), cw.misread()
