# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""COUNT inventory: "0 hits, safe to switch" only for a confirmed zero, and Step 3 really ranked.

WAF publishes a metric only when it is non-zero, and SEARCH discovers only series with data in
the last 14 days. So a Count rule absent from the SEARCH answer is one of three things: it matched
nothing, its CloudWatch metrics are off, or the lookup did not answer. All three became
`metrics.get(rule_id, {})`, a sum of 0, and the line "0 hits in 14 days, safe to switch". Two of the
three are not evidence of anything.

The confirmation reuses `waf_metrics.rule_blocked_per_metrics`, which reads the metric name from
the configuration and refuses a rule whose metrics are off. Only `_metric_sum`, the AWS call, is
faked here, so the metrics-off refusal under test is the real one.
"""

import pytest

from tools import waf_count_eval as C
from tools import waf_metrics as M
from tools import waf_patrol as P


def _rule(name, metrics=True):
    return {"Name": name, "Action": {"Count": {}},
            "VisibilityConfig": {"CloudWatchMetricsEnabled": metrics, "MetricName": name}}


RULES = [_rule("Alpha"), _rule("Bravo"), _rule("Quiet"), _rule("Dark", metrics=False), _rule("Flaky")]
SEARCH = {"Alpha": {"counted": [500]}, "Bravo": {"counted": [2000]}}
METRICSTAT = {"Quiet": (0, ""), "Flaky": (None, "the metric query did not run: ThrottlingException")}


@pytest.fixture
def inventory(monkeypatch):
    monkeypatch.setattr(C, "_get_webacl_rules", lambda region, scope: RULES)
    monkeypatch.setattr(C, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(C, "get_scope", lambda: "CLOUDFRONT")
    monkeypatch.setattr(C, "resolve_region", lambda scope: "us-east-1")
    monkeypatch.setattr(C, "get_client", lambda *a, **k: object())
    monkeypatch.setattr(P, "_get_all_rules_metrics_search", lambda *a, **k: SEARCH)
    asked = []

    def metric_sum(webacl, dimension, metric_name, start, end):
        asked.append((dimension, metric_name))
        return METRICSTAT.get(dimension, (0, ""))
    monkeypatch.setattr(M, "_metric_sum", metric_sum)
    # The call is made by each test, not here. Run inside the fixture, a perturbation that makes
    # `_step_init` raise reports as a setup error, which the perturbation harness reads as a
    # collection failure and not as the assertion catching it.
    return lambda: (C._step_init(), asked)


def _section(out, heading):
    assert heading in out, f"{heading!r} missing:\n{out}"
    return out.split(heading, 1)[1].split("\n### ", 1)[0].split("\n---", 1)[0]


def test_only_a_confirmed_zero_is_called_safe(inventory):
    out, asked = inventory()
    assert ("Quiet", "CountedRequests") in asked, f"the zero was never confirmed: {asked}"
    safe = _section(out, "### Step 1:")
    assert "Quiet" in safe, safe
    assert "Dark" not in safe and "Flaky" not in safe, safe


def test_a_rule_with_no_metric_says_why(inventory):
    out, _ = inventory()
    unknown = _section(out, "### No metric to judge from")
    assert "Dark" in unknown and "CloudWatchMetricsEnabled false" in unknown, unknown
    assert "Flaky" in unknown and "ThrottlingException" in unknown, unknown


def test_a_rule_search_already_counted_is_not_asked_again(inventory):
    _, asked = inventory()
    assert asked, "nothing was confirmed at all, so 'not asked again' is vacuous"
    assert not {d for d, _ in asked} & {"Alpha", "Bravo"}, asked


def test_step_three_is_ranked_by_hit_volume(inventory):
    out, _ = inventory()
    step3 = _section(out, "### Step 3:")
    assert step3.index("Bravo") < step3.index("Alpha"), step3
    assert "Recommend starting with **Bravo**" in out, out
