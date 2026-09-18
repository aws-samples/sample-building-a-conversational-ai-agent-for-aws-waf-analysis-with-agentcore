# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`_rate_limits` and `_challenge_solve_rate` read their per-rule/per-outcome breakdown from
`_get_all_rules_metrics_search`, the same SEARCH expression `attack_types`, `bot_names`,
`targeted_signals` and `top_labels` already flag as subject to CloudWatch's 14-day metric-discovery
window. Those four say so when the breakdown comes back empty; these two did not, so "no triggers"
and "no challenges issued" read identically whether that is true or whether SEARCH simply has not
indexed the metric recently. `_bot_summary` is deliberately not touched here: it queries
`AllowedRequests`/`BlockedRequests` with explicit `Dimensions`, never a SEARCH expression, so it has
no 14-day exposure to disclose.

The discriminant is `_has_mitigated_traffic`, a direct `MetricStat` immune to the same expiry. **The
first version of this fix called it with its default (Rule="ALL", Blocked+Challenge+Captcha summed
together), which is a real regression a reviewer caught before merge:** a WebACL that only ever
blocks (no Challenge or CAPTCHA action configured anywhere) has Blocked > 0 on every call, so
`_challenge_solve_rate` reported "unavailable" for Challenge/CAPTCHA on every single invocation, even
though the true state is a clean, permanent zero -- the exact false-positive shape this fix exists to
remove. Same shape, weaker, in `_rate_limits`: checking WebACL-wide mitigation flags a rate-limit rule
that is simply quiet while some OTHER rule mitigates heavily.

The fix generalises `_has_mitigated_traffic` to take which rule and which metric names to check
(defaulting to the old WebACL-wide, all-three-metrics behaviour the other four callers still want),
and narrows each new call site to what its own claim is actually about: `_challenge_solve_rate` checks
only Challenge+Captcha at Rule="ALL", and `_rate_limits` checks each configured rate-limit rule by its
own name, not the WebACL as a whole.
"""

import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from tools import waf_overview as O

START = datetime(2026, 9, 1, tzinfo=timezone.utc)
END = START + timedelta(hours=1)


class FakeMetricCW:
    """Answers `_has_mitigated_traffic`'s MetricStat queries from a `{(rule, metric_name): total}`
    map, keyed on what the query actually asks for rather than a fixed shape, so a case can tell
    "this rule/metric is genuinely zero" apart from "something else in the WebACL is not".

    **A query with no `Rule` dimension is recorded on `self.misused`, not raised.**
    `_has_mitigated_traffic` wraps its whole `get_metric_data` call in a bare `except Exception:
    return False`, so raising here, an `assert` included, would be caught there and read as "no
    traffic" instead of surfaced -- confirmed, not assumed: an `AssertionError` inside that try
    disappears the same way a bare `next()`'s `StopIteration` would. A flag set here and asserted by
    the caller after the call never goes through that exception path at all, so nothing catches it.
    The fixtures below assert `not fake.misused` right after every call. The asymmetry this closes was
    real but partial even before the flag: the two disclosure-direction tests need a `True` a broken
    query can no longer produce, so they would still go red; only the clean-zero-direction tests would
    have kept passing for the wrong reason. See `test_the_fake_itself_flags_a_malformed_query` for
    proof the flag actually fires."""

    def __init__(self, values: dict):
        self.values = values
        self.misused = False

    def get_metric_data(self, **kw):
        out = []
        for q in kw["MetricDataQueries"]:
            metric = q["MetricStat"]["Metric"]
            name = metric["MetricName"]
            rule = next((d["Value"] for d in metric["Dimensions"] if d["Name"] == "Rule"), None)
            if rule is None:
                self.misused = True
            out.append({"Id": q["Id"], "Values": [self.values.get((rule, name), 0)]})
        return {"MetricDataResults": out}


class FakeWaf:
    """A WebACL config with one RateBasedStatement rule named `_rate_limits` looks for."""

    def list_web_acls(self, Scope):
        return {"WebACLs": [{"Name": "acl", "ARN": "arn:aws:wafv2:us-east-1:1:webacl/acl/id"}]}

    def get_web_acl(self, Name, Scope, Id):
        return {"WebACL": {"Rules": [
            {"Name": "RateLimit200", "Statement": {"RateBasedStatement": {"Limit": 200}}},
        ]}}


@pytest.fixture
def rate_limits(monkeypatch):
    def run(values: dict):
        monkeypatch.setattr(O, "get_client", lambda service, region_name="": FakeWaf())
        import tools.waf_patrol as P
        # No SEARCH rows at all for the configured rule: the exact "index has not caught up, or it
        # genuinely never fired" shape `_has_mitigated_traffic` exists to disambiguate.
        monkeypatch.setattr(P, "_get_all_rules_metrics_search",
                            lambda cw, name, s, e, period=86400, scope="CLOUDFRONT", region="": {})
        fake = FakeMetricCW(values)
        out = O._rate_limits(fake, "acl", START, END, 1440)
        assert not fake.misused, "a query to the fake had no Rule dimension"
        return out
    return run


def test_the_specific_rate_rule_being_genuinely_idle_is_a_clean_zero_even_with_other_traffic(rate_limits):
    """The regression this fix removes: `RateLimit200` itself never fired, `OtherRule` fired a lot,
    and a WebACL-wide check would have flagged this as unavailable on every quiet day for the
    rate-limit rule specifically. The per-rule query must see `RateLimit200` as zero regardless."""
    out = rate_limits({("OtherRule", "BlockedRequests"): 500})
    assert "no triggers in this period" in out, out
    assert "PARTIAL DATA" not in out, "flagged uncertainty for a rule that is genuinely idle"


def test_a_direct_query_on_the_specific_rule_finding_real_traffic_discloses_partial_data(rate_limits):
    """The genuine gap: a direct, index-immune MetricStat on `RateLimit200` itself finds real
    traffic that the SEARCH-based breakdown missed."""
    out = rate_limits({("RateLimit200", "BlockedRequests"): 12})
    assert "PARTIAL DATA" in out and "14 days" in out, out
    assert "no triggers in this period" not in out


def test_a_configured_rate_rule_with_nothing_anywhere_is_a_clean_zero(rate_limits):
    out = rate_limits({})
    assert "no triggers in this period" in out, out
    assert "PARTIAL DATA" not in out


def test_a_count_mode_rate_rule_that_fired_is_not_missed(rate_limits):
    """A rate-limit rule configured with a COUNT action never blocks, challenges or CAPTCHAs, so it
    only ever shows up in `CountedRequests`. Checking just the other three would make a COUNT rule
    that genuinely fired, but whose SEARCH breakdown missed it, indistinguishable from one that never
    fired at all -- the same shape this whole fix removes, just for the fourth metric."""
    out = rate_limits({("RateLimit200", "CountedRequests"): 40})
    assert "PARTIAL DATA" in out and "14 days" in out, out
    assert "no triggers in this period" not in out


@pytest.fixture
def challenge_solve_rate(monkeypatch):
    def run(values: dict):
        import tools.waf_patrol as P
        # ALL bucket absent entirely: the SEARCH result the 14-day expiry actually produces.
        monkeypatch.setattr(P, "_get_all_rules_metrics_search",
                            lambda cw, name, s, e, period=86400, scope="CLOUDFRONT", region="": {})
        monkeypatch.setattr(P, "_get_challenge_solved", lambda cw, name, scope, region, s, e: (0, 0))
        fake = FakeMetricCW(values)
        out = O._challenge_solve_rate(fake, "acl", "CLOUDFRONT", "", START, END, 1440)
        assert not fake.misused, "a query to the fake had no Rule dimension"
        return out
    return run


def test_blocked_only_traffic_is_a_clean_zero_not_partial_data(challenge_solve_rate):
    """The regression this fix removes: a WebACL with real Blocked traffic and no Challenge/CAPTCHA
    action configured anywhere used to read as "unavailable" for Challenge/CAPTCHA, on every call,
    because the old check summed Blocked in with Challenge and Captcha."""
    out = challenge_solve_rate({("ALL", "BlockedRequests"): 500})
    assert "No challenges or CAPTCHAs issued" in out, out
    assert "PARTIAL DATA" not in out, "a permanent, genuine zero was flagged as merely unavailable"


def test_a_direct_query_finding_real_challenge_traffic_discloses_partial_data(challenge_solve_rate):
    """The genuine gap: Rule=ALL's direct MetricStat shows real Challenge traffic that the
    SEARCH-based breakdown (tot_ch/tot_cap) missed."""
    out = challenge_solve_rate({("ALL", "ChallengeRequests"): 30})
    assert "PARTIAL DATA" in out and "14 days" in out, out
    assert "No challenges or CAPTCHAs issued" not in out


def test_nothing_anywhere_is_a_clean_zero(challenge_solve_rate):
    out = challenge_solve_rate({})
    assert "No challenges or CAPTCHAs issued" in out, out
    assert "PARTIAL DATA" not in out


def test_the_fake_itself_flags_a_malformed_query():
    """The two fixtures assert `not fake.misused` after every call, which only means something if
    the flag actually fires on a query with no `Rule` dimension. Exercised directly against
    `FakeMetricCW`, the one place this can be proven without going through `_has_mitigated_traffic`'s
    exception-swallowing try block, which is exactly what the flag exists to not need."""
    fake = FakeMetricCW({})
    fake.get_metric_data(MetricDataQueries=[
        {"Id": "m0", "MetricStat": {"Metric": {
            "MetricName": "BlockedRequests",
            "Dimensions": [{"Name": "WebACL", "Value": "acl"}]}}},
    ])
    assert fake.misused, "a query with no Rule dimension went unflagged"


def test_top_rules_gap_detection_names_both_possible_causes():
    """`_top_rules`'s existing gap-detection line named only managed-rule-group sub-rules. That is a
    real cause, but so is the same 14-day SEARCH-discovery gap the other functions disclose, and the
    line did not say so. Both must be named now, or a reader rules out the actual cause on the
    strength of the one this line happens to mention."""
    src = pathlib.Path(O.__file__).read_text()
    block = src[src.index("Gap detection"):src.index("Gap detection") + 800]
    assert "sub-rule" in block, block
    assert "14-day" in block or "14 days" in block, (
        "the gap-detection message no longer names CloudWatch's SEARCH-discovery window as a "
        "possible cause of the gap")
