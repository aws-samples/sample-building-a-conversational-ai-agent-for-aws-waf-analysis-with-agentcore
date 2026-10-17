"""`detect_bypass(step="volume_anomaly")` compares a window, not a week. ROADMAP 7.14.

It set this week's `AllowedRequests` against last week's, so an hour-long scraper or flood barely moved
the ratio and the likely reading of a real anomaly was "within normal range". The fake below answers by
time, so a test can tell which window was read: points start at StartTime rounded down to the resolution
CloudWatch keeps for data that old (a minute to 15 days, five minutes to 63, an hour after), then one
every period while it starts before EndTime, and each holds what was sent in its interval. Measured
2026-10-16, see `tests/test_overview_old_window.py::ClockCW`.
"""

from datetime import datetime, timedelta, timezone

import pytest

from tools import waf_bypass as B

NOW = datetime.now(timezone.utc).replace(second=0, microsecond=0)
# Three days ago, on the hour, so the busiest hour is unambiguous.
BURST = (NOW - timedelta(days=3)).replace(minute=0)


class TimelineCW:
    """`allowed(t)` and `blocked(t)` are per-minute counts at minute `t`. Every read is recorded."""

    def __init__(self, allowed, blocked=lambda t: 0, event=lambda t: 0, fails=False):
        self.rate = {"AllowedRequests": allowed, "BlockedRequests": blocked}
        self.event, self.fails, self.reads = event, fails, []

    def _points(self, start, end, period):
        age = NOW - start
        step = 60 if age <= timedelta(days=15) else 300 if age <= timedelta(days=63) else 3600
        t = start - timedelta(seconds=int(start.timestamp()) % step, microseconds=start.microsecond)
        while t < end:
            yield t
            t += timedelta(seconds=period)

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
        if self.fails:
            raise RuntimeError("ThrottlingException: Rate exceeded")
        out = []
        for q in MetricDataQueries:
            st = q["MetricStat"]
            name, period = st["Metric"]["MetricName"], st["Period"]
            dims = {d["Name"]: d["Value"] for d in st["Metric"]["Dimensions"]}
            self.reads.append((name, StartTime, EndTime, period))
            if "LabelName" in dims:
                rate = self.event
            else:
                rate = self.rate.get(name, lambda t: 0)
            ts, vals = [], []
            for t in self._points(StartTime, EndTime, period):
                v = sum(rate(t + timedelta(minutes=m)) for m in range(period // 60)
                        if t + timedelta(minutes=m) < NOW)
                if v:
                    ts.append(t)
                    vals.append(v)
            out.append({"Id": q["Id"], "Values": vals, "Timestamps": ts})
        return {"MetricDataResults": out}


@pytest.fixture
def volume(monkeypatch):
    def run(cw, start=None, minutes=60):
        monkeypatch.setattr(B, "get_client", lambda svc, **k: cw)
        monkeypatch.setattr(B, "get_webacl_name", lambda: "acl")
        monkeypatch.setattr(B, "get_scope", lambda: "CLOUDFRONT")
        monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")
        if start is None:
            return B._step_volume_anomaly()
        epoch = int(start.timestamp())
        return B._step_volume_anomaly(epoch, epoch + minutes * 60)
    return run


def _in(t, start, minutes=60):
    return start <= t < start + timedelta(minutes=minutes)


def steady_with_burst(t):
    return 1000 if _in(t, BURST) else 30


def test_an_hour_long_burst_is_found_and_called_significant(volume):
    """The case the weekly totals hid: 1,000 a minute for an hour over a steady 30. Over the week that is
    1.1x, "within normal range"; over the hour it is 33x."""
    week_total = 30 * 60 * 24 * 7 + (1000 - 30) * 60
    assert week_total / (30 * 60 * 24 * 7) < B.WOW_ANOMALY_MODERATE, "the precondition: a week hides it"
    out = volume(TimelineCW(steady_with_burst))
    assert "Significant Anomaly" in out and "33.3x" in out, out
    assert BURST.strftime("%Y-%m-%d %H:%M") in out, out
    assert "the busiest hour of ALLOW traffic in the last 7 days" in out, out


def test_the_week_earlier_window_is_the_same_window_seven_days_back(volume):
    cw = TimelineCW(steady_with_burst)
    volume(cw)
    allowed = [(s, e) for name, s, e, p in cw.reads if name == "AllowedRequests" and p != 3600]
    assert (BURST, BURST + timedelta(hours=1)) in allowed, allowed
    assert (BURST - timedelta(days=7), BURST - timedelta(days=6, hours=23)) in allowed, allowed


def test_a_window_the_user_names_is_the_one_read(volume):
    start = BURST + timedelta(hours=5)
    out = volume(TimelineCW(steady_with_burst), start=start, minutes=30)
    assert "the window asked for" in out and start.strftime("%Y-%m-%d %H:%M") in out, out
    assert "No Significant Volume Anomaly" in out and "1.0x the same window a week earlier" in out, out


def test_the_scan_it_points_to_covers_the_window(volume):
    out = volume(TimelineCW(steady_with_burst))
    assert f"start_time='{BURST.strftime('%Y-%m-%dT%H:%M')}'" in out, out


def test_no_traffic_a_week_earlier_falls_back_to_the_hours_around_it(volume):
    """A site launched four days ago: the week-earlier ratio has nothing under it, so it must not decide."""
    launched = NOW - timedelta(days=4)
    out = volume(TimelineCW(lambda t: 0 if t < launched else steady_with_burst(t)))
    assert "the 6 hours either side" in out and "Significant Anomaly" in out, out
    assert "| ALLOW ratio | | n/a |" in out, out


def test_with_no_baseline_at_all_no_ratio_is_given(volume):
    out = volume(TimelineCW(lambda t: 1000 if _in(t, BURST) else 0))
    assert "No Baseline" in out and "Significant" not in out and "within" not in out, out


def test_mitigated_traffic_rising_too_is_named(volume):
    out = volume(TimelineCW(steady_with_burst, blocked=lambda t: 500 if _in(t, BURST) else 5))
    assert "WAF IS catching some of it" in out, out


def test_a_failed_read_is_not_a_quiet_window(volume):
    out = volume(TimelineCW(steady_with_burst, fails=True))
    assert "ThrottlingException" in out and "nothing here says whether traffic was normal" in out, out
    assert "No Significant" not in out, out


def test_an_event_in_the_window_is_reported(volume):
    out = volume(TimelineCW(steady_with_burst, event=lambda t: 3 if _in(t, BURST) else 0))
    assert "event-detected label appeared in this window" in out, out


def test_the_scan_compares_its_own_window_a_week_earlier(monkeypatch):
    """The scan's spike note made the same seven-day comparison."""
    cw = TimelineCW(steady_with_burst)
    monkeypatch.setattr(B, "get_client", lambda svc, **k: cw)
    monkeypatch.setattr(B, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(B, "get_scope", lambda: "CLOUDFRONT")
    monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    monkeypatch.setattr(B, "_check_coverage_gaps", lambda: [])
    monkeypatch.setattr(B, "query_logs", lambda *a, **k: [])
    monkeypatch.setattr("tools.waf_metrics.log_path_warning", lambda *a, **k: "")
    start = int(BURST.timestamp())
    out = B._step_scan(start, start + 3600)
    assert "33.3x the same window a week earlier" in out, out
    quiet = int((BURST + timedelta(hours=5)).timestamp())
    assert "week earlier" not in B._step_scan(quiet, quiet + 3600)


def test_mitigated_traffic_rising_from_none_is_a_rise(volume):
    """The first live run: a flood the rate limit blocked, 562,445 mitigated against 0 a week earlier,
    read as "did NOT rise ... the extra traffic is being allowed"."""
    out = volume(TimelineCW(steady_with_burst, blocked=lambda t: 9000 if _in(t, BURST) else 0))
    assert "WAF IS catching some of it" in out and "540,000 against none" in out, out
    assert "did NOT rise" not in out, out


def test_mitigated_traffic_that_stayed_flat_is_not_a_rise(volume):
    out = volume(TimelineCW(steady_with_burst, blocked=lambda t: 5))
    assert "did NOT rise as much (1.0x)" in out, out
