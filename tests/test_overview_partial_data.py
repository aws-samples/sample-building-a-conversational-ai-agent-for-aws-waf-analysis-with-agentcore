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

The discriminant already exists (`_has_mitigated_traffic`, a direct `MetricStat` immune to the same
expiry) and is already used this way by the other four; this just wires the same check into the two
that were missing it, plus widens `_top_rules`'s existing gap-detection line to name the 14-day cause
alongside the sub-rule cause it already names.
"""

import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from tools import waf_overview as O

START = datetime(2026, 9, 1, tzinfo=timezone.utc)
END = START + timedelta(hours=1)


class FakeMitigatedCW:
    """Answers only `_has_mitigated_traffic`'s 3-query MetricStat shape (Ids b/c/p)."""

    def __init__(self, total: int):
        self.total = total

    def get_metric_data(self, **kw):
        # `_has_mitigated_traffic` swallows every exception and returns False, so an assertion in
        # here that raised on an unexpected shape would silently read as "no traffic" instead of
        # failing loud. Just answer with the total on the first id; summing every result still
        # yields `self.total`.
        return {"MetricDataResults": [
            {"Id": "b", "Values": [self.total]},
            {"Id": "c", "Values": [0]},
            {"Id": "p", "Values": [0]},
        ]}


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
    def run(mitigated_total: int):
        monkeypatch.setattr(O, "get_client", lambda service, region_name="": FakeWaf())
        import tools.waf_patrol as P
        # No SEARCH rows at all for the configured rule: the exact "index has not caught up" shape.
        monkeypatch.setattr(P, "_get_all_rules_metrics_search",
                            lambda cw, name, s, e, period=86400, scope="CLOUDFRONT", region="": {})
        return O._rate_limits(FakeMitigatedCW(mitigated_total), "acl", START, END, 1440)
    return run


def test_a_configured_rate_rule_with_no_search_rows_but_real_mitigation_discloses_partial_data(rate_limits):
    out = rate_limits(mitigated_total=50)
    assert "PARTIAL DATA" in out and "14 days" in out, out
    assert "no triggers in this period" not in out, (
        "claimed a clean zero while the WebACL had mitigated traffic the breakdown could not explain")


def test_a_configured_rate_rule_with_no_search_rows_and_no_mitigation_is_a_clean_zero(rate_limits):
    out = rate_limits(mitigated_total=0)
    assert "no triggers in this period" in out, out
    assert "PARTIAL DATA" not in out, "flagged uncertainty where there is genuinely nothing to explain"


@pytest.fixture
def challenge_solve_rate(monkeypatch):
    def run(mitigated_total: int):
        import tools.waf_patrol as P
        # ALL bucket absent entirely: the SEARCH result the 14-day expiry actually produces.
        monkeypatch.setattr(P, "_get_all_rules_metrics_search",
                            lambda cw, name, s, e, period=86400, scope="CLOUDFRONT", region="": {})
        monkeypatch.setattr(P, "_get_challenge_solved", lambda cw, name, scope, region, s, e: (0, 0))
        return O._challenge_solve_rate(FakeMitigatedCW(mitigated_total), "acl", "CLOUDFRONT", "", START, END, 1440)
    return run


def test_zero_issued_with_real_mitigation_discloses_partial_data(challenge_solve_rate):
    out = challenge_solve_rate(mitigated_total=50)
    assert "PARTIAL DATA" in out and "14 days" in out, out
    assert "No challenges or CAPTCHAs issued" not in out


def test_zero_issued_with_no_mitigation_is_a_clean_zero(challenge_solve_rate):
    out = challenge_solve_rate(mitigated_total=0)
    assert "No challenges or CAPTCHAs issued" in out, out
    assert "PARTIAL DATA" not in out


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
