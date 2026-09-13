# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A log query returning zero must be checked against the one witness it cannot corrupt.

ROADMAP 7.1. On 2026-09-08 the injection investigation reported zero SQLi hits on the strength of one
log query, and **a log query returning zero is byte-identical to the attack not having happened**, so
the reassuring answer is the one a broken query produces. CloudWatch metrics are recorded upstream of
every log-side failure mode: no partition layout, engine difference, logging filter or query timeout
reaches them.

Verified against the live account for the 2026-09-08 window, which is a ready-made pair of controls:
`response-id-on-page` SQLi 122 with an empty log answer, and `shield-sample-webacl` SQLi genuinely
empty while that same WebACL's rate-limit rule blocked 566,070. The second is why the comparison is per
rule: at the WebACL level the check would fire there and be wrong, and **a check that is always on is
not a check**.

Three of the guards below exist because a wrong answer here is indistinguishable from a right one:

- A `MetricStat` for a rule name that does not exist returns series present, `Complete`, `Values: []`,
  `Messages: []`. Measured. Nothing in the response separates a typo from a quiet rule.
- A resolution no longer retained returns the same empty-and-Complete shape. Measured at 20 days with
  `Period=60`.
- `VisibilityConfig.MetricName` is the dimension value, and it equals `Name` for all 20 rules on the
  measurement account, so an implementation that used `Name` would pass every test written there.
"""

import re
from datetime import datetime, timedelta, timezone

import pytest

from tools import session_state as S
from tools import waf_metrics as M


def rule(name, metric_name=None, enabled=True):
    return {"Name": name, "VisibilityConfig": {"MetricName": metric_name or name,
                                               "CloudWatchMetricsEnabled": enabled}}


RULES = [rule("AWS-AWSManagedRulesSQLiRuleSet"), rule("rate-limit"),
         rule("odd-name", metric_name="oddMetric"), rule("no-metrics", enabled=False)]


class FakeCw:
    def __init__(self, values=()):
        self.requests = []
        self.values = list(values)

    def get_metric_data(self, **kw):
        self.requests.append(kw)
        return {"MetricDataResults": [{"Timestamps": [], "Values": [float(v) for v in self.values]}]}


@pytest.fixture
def cw(monkeypatch):
    fake = FakeCw([122])
    monkeypatch.setattr(M, "get_client", lambda *a, **k: fake)
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1")
    return fake


def _window(days_ago=1, hours=6):
    end = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return int((end - timedelta(hours=hours)).timestamp()), int(end.timestamp())


# --- the period, keyed on the oldest point in the window --------------------


@pytest.mark.parametrize("age_days,expected", [(1, 60), (14, 60), (20, 300), (62, 300),
                                               (100, 3600), (454, 3600), (500, None)])
def test_the_period_follows_the_age_of_the_oldest_point(age_days, expected):
    """**The oldest point, not the newest, and that is the whole content of the function.** A 30-day
    window ending today straddles the 15-day boundary where 1-minute data stops existing: choosing by
    its recent end asks for `Period=60` and the older half comes back silently empty, `Complete`, with
    no `Messages`. Choosing by the oldest point asks for 300 and covers the span.

    Beyond 455 days nothing is retained at any resolution, so the answer is None rather than a period
    that would return an empty series indistinguishable from a quiet rule."""
    start = int((datetime.now(timezone.utc) - timedelta(days=age_days)).timestamp())
    assert M._period_for_window(start) == expected


def test_the_query_uses_the_period_the_window_earns(cw):
    """The pairing. The function above can be right while the caller ignores it."""
    start, end = _window(days_ago=30)
    M.rule_blocked_per_metrics("acl", "rate-limit", RULES, start, end)
    assert cw.requests[0]["MetricDataQueries"][0]["MetricStat"]["Period"] == 300


def test_a_window_beyond_every_retention_is_refused_without_querying(cw):
    start, end = _window(days_ago=500)
    count, reason = M.rule_blocked_per_metrics("acl", "rate-limit", RULES, start, end)
    assert count is None and "455 days" in reason
    assert not cw.requests, "the refusal has to come before the query"


# --- the membership check, at the line that issues the query ----------------


def test_a_rule_name_that_is_not_configured_is_refused_rather_than_answered_zero(cw):
    """The guard the measurement demands. A `MetricStat` for `AWS-AWSManagedRulesSQLiRuleSetX` returns
    exactly what a real rule with no traffic returns, so the response can never tell them apart and
    the name's provenance is the only defence. Measured 2026-09-13 on the live account.

    The reason lists the configured rules, because the likely cause is not a typo but one WebACL's
    rule name used against another: `rate-limit` exists on `shield-sample-webacl` and the equivalent
    on `response-id-on-page` is `rate-limit-blanket`."""
    start, end = _window()
    count, reason = M.rule_blocked_per_metrics("acl", "SQLiRuleSetX", RULES, start, end)
    assert count is None
    assert "not a rule on acl" in reason
    assert "rate-limit" in reason, "the reason has to say what the configured names are"
    assert not cw.requests, "a name that failed the check must not reach CloudWatch"


def test_a_rule_with_metrics_switched_off_is_refused_rather_than_answered_zero(cw):
    """`CloudWatchMetricsEnabled: false` publishes nothing, so its zero means nothing. All 20 rules on
    the measurement account have it true, which is why this needs a fixture rather than a run."""
    start, end = _window()
    count, reason = M.rule_blocked_per_metrics("acl", "no-metrics", RULES, start, end)
    assert count is None and "CloudWatchMetricsEnabled" in reason
    assert not cw.requests


def test_the_dimension_is_the_metric_name_and_not_the_rule_name(cw):
    """They are equal for every rule on the measurement account, so an implementation reading `Name`
    would pass every test written against real data. `odd-name` publishes as `oddMetric`."""
    start, end = _window()
    M.rule_blocked_per_metrics("acl", "odd-name", RULES, start, end)
    dims = {d["Name"]: d["Value"]
            for d in cw.requests[0]["MetricDataQueries"][0]["MetricStat"]["Metric"]["Dimensions"]}
    assert dims["Rule"] == "oddMetric", dims
    assert dims["WebACL"] == "acl"
    assert "Region" not in dims, "CLOUDFRONT metrics carry no Region dimension"


def test_a_configured_rule_is_answered_with_the_sum(cw):
    """The control for all four refusals above. Every one of them returns None, and an implementation
    that returned None unconditionally would satisfy them and never report a missed query."""
    start, end = _window()
    count, reason = M.rule_blocked_per_metrics("acl", "rate-limit", RULES, start, end)
    assert (count, reason) == (122, "")


def test_a_failed_metric_query_says_so_instead_of_reporting_zero(monkeypatch):
    class Broken:
        def get_metric_data(self, **kw):
            raise ConnectionError("socket dropped")

    monkeypatch.setattr(M, "get_client", lambda *a, **k: Broken())
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1")
    start, end = _window()
    count, reason = M.rule_blocked_per_metrics("acl", "rate-limit", RULES, start, end)
    assert count is None and "ConnectionError" in reason


# --- the warning, which only speaks for the unambiguous cell ----------------


def test_a_non_zero_metric_beside_zero_log_rows_reports_a_missed_query(cw):
    """The one observation on 7.1's three-state table that supports a confident, serious claim."""
    start, end = _window()
    out = M.missed_data_warning("acl", "rate-limit", RULES, start, end, log_rows=0)
    assert "missed data" in out and "122" in out
    assert "Do NOT report this window as quiet" in out


def test_a_partial_gap_is_not_reported_yet_and_the_reason_is_a_dependency(cw):
    """**The deliberate limit, asserted so that widening it is a decision rather than a discovery.**
    Metric 122 beside 40 log rows may be a `limit` on the query rather than data it missed, and nothing
    available today separates those. ROADMAP 7.7's truncation disclosure is what makes a partial gap
    decidable; until then this stays silent, and a partial gap is the more common shape."""
    start, end = _window()
    assert M.missed_data_warning("acl", "rate-limit", RULES, start, end, log_rows=40) == ""
    assert not cw.requests, "no metric query at all when the log side returned rows"


def test_a_metric_that_could_not_answer_never_becomes_a_claim_about_the_logs(cw):
    """Every refusal path must reach the report as silence. Turning "I could not check" into "your
    query missed data" is the same defect class in the opposite direction."""
    start, end = _window()
    assert M.missed_data_warning("acl", "SQLiRuleSetX", RULES, start, end, log_rows=0) == ""


def test_a_zero_metric_beside_zero_log_rows_says_nothing(monkeypatch):
    """7.1's third row. Metrics and logs are two recordings of one upstream event, so zero beside zero
    cannot confirm absence, and a real bypass is metric-silent by construction. The tool's existing
    sentence already covers that case; this must not add to it."""
    fake = FakeCw([])
    monkeypatch.setattr(M, "get_client", lambda *a, **k: fake)
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1")
    start, end = _window()
    assert M.missed_data_warning("acl", "rate-limit", RULES, start, end, log_rows=0) == ""


def test_the_injection_tool_reaches_the_cross_check_from_its_no_activity_branch():
    """The wiring, read structurally because the behavioural path needs three AWS calls to set up.

    The branch is the one that produced the wrong answer: `investigate_injection` concluding that no
    injection rule blocked anything. It must pass the rule list it read from `get_web_acl` in that same
    function, since the membership check is only as good as its input."""
    import inspect

    from tools import waf_injection as I

    src = inspect.getsource(I.investigate_injection._tool_func)
    assert "missed_data_warning" in src, "the no-activity branch does not cross-check metrics"
    assert "acl_rules" in src, "the cross-check must be handed the rules read in this function"
    assert re.search(r"missed_data_warning\(\s*get_webacl_name\(\),\s*target,\s*acl_rules", src), (
        "the rule list passed to the cross-check is not the one read from get_web_acl here")
