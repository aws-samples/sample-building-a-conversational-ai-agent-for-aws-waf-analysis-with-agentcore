# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A managed rule group deployed twice: its sub-rule rows are marked as summed, and its overrides
are listed once.

A managed sub-rule's metric (`Rule=<sub-rule>`, `ManagedRuleGroupRule`, the label `*RuleMatch`)
names no instance, so both instances write into one series. Measured 2026-10-16 on
`shield-sample-webacl`, which runs AWSManagedRulesBotControlRuleSet at priorities 10 and 11: over
13 days TGT_TokenAbsent read 3,436 against 2,230 logged requests. `response-id-on-page` runs it once
and read 440 against 440. So with one instance the figure is exact and nothing is marked.
"""

import pytest

from tools import waf_count_eval as C
from tools import waf_metrics as M
from tools import waf_overview as O
from tools import waf_patrol as P

from tests.test_overview_old_window import OLD, HOUR, RetainingCW


def _bot(name):
    return {"Name": name, "Statement": {"ManagedRuleGroupStatement": {
        "VendorName": "AWS", "Name": "AWSManagedRulesBotControlRuleSet",
        "RuleActionOverrides": [{"Name": "CategoryHttpLibrary", "ActionToUse": {"Count": {}}}]}},
        "OverrideAction": {"None": {}}, "VisibilityConfig": {"CloudWatchMetricsEnabled": True, "MetricName": name}}


COMMON = {"Name": "AWS-AWSManagedRulesCommonRuleSet", "Statement": {"ManagedRuleGroupStatement": {
    "VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet",
    "RuleActionOverrides": [{"Name": "SizeRestrictions_BODY", "ActionToUse": {"Count": {}}}]}},
    "OverrideAction": {"None": {}}, "VisibilityConfig": {"CloudWatchMetricsEnabled": True,
                                                         "MetricName": "AWS-AWSManagedRulesCommonRuleSet"}}
TWICE = [_bot("AWS-AWSManagedRulesBotControlRuleSet"), _bot("AWS-AWSManagedRulesBotControlRuleSet-2"), COMMON]
ONCE = [TWICE[0], COMMON]
# What the ManagedRuleGroupRule SEARCH answers, by group: TGT_TokenAbsent is overridden nowhere.
SUB_RULES = {"AWSManagedRulesBotControlRuleSet": ["TGT_TokenAbsent", "CategoryHttpLibrary"],
             "AWSManagedRulesCommonRuleSet": ["SizeRestrictions_BODY"]}


class GroupCW(RetainingCW):
    """RetainingCW plus the `{ManagedRuleGroup, ManagedRuleGroupRule}` SEARCH, rendered with its label."""
    groups_asked = None

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
        expr = MetricDataQueries[0].get("Expression", "")
        if "ManagedRuleGroupRule" not in expr:
            return super().get_metric_data(MetricDataQueries, StartTime, EndTime, **kw)
        group = expr.split('ManagedRuleGroup="', 1)[1].split('"', 1)[0]
        self.groups_asked = (self.groups_asked or []) + [group]
        return {"MetricDataResults": [{"Id": "g", "Label": f"{r}|CountedRequests", "Values": [1], "Timestamps": [StartTime]}
                                      for r in SUB_RULES.get(group, [])]}


DATA = {("TGT_TokenAbsent", "CountedRequests"): 3436, ("AWS-AWSManagedRulesBotControlRuleSet", "BlockedRequests"): 9,
        ("SizeRestrictions_BODY", "CountedRequests"): 12, ("ALL", "AllowedRequests"): 5000}
FOUND = frozenset({("TGT_TokenAbsent", "CountedRequests"), ("SizeRestrictions_BODY", "CountedRequests"),
                   ("ALL", "AllowedRequests")})


def _top_rules(rules, cw=None):
    cw = cw or GroupCW(DATA, discoverable=FOUND)
    return O._top_rules(cw, "acl", OLD, OLD + HOUR, OLD - HOUR, 60, "CLOUDFRONT", "us-east-1", rules, "")


def test_a_sub_rule_of_a_repeated_group_is_marked_summed():
    out = _top_rules(TWICE)
    assert any(l.startswith("TGT_TokenAbsent*") for l in out.splitlines()), out
    assert "AWSManagedRulesBotControlRuleSet runs 2 times" in out, out


def test_a_sub_rule_of_a_group_run_once_is_not_marked():
    """The first version marked every sub-rule once any group repeated, and live count_eval put a *
    on CommonRuleSet's SizeRestrictions_BODY while CommonRuleSet ran once."""
    out = _top_rules(TWICE)
    assert any(l.startswith("SizeRestrictions_BODY ") for l in out.splitlines()), out


def test_the_group_lookup_is_sent_only_for_a_repeated_group():
    cw = GroupCW(DATA, discoverable=FOUND)
    _top_rules(TWICE, cw)
    assert cw.groups_asked == ["AWSManagedRulesBotControlRuleSet"], cw.groups_asked
    cw = GroupCW(DATA, discoverable=FOUND)
    _top_rules(ONCE, cw)
    assert cw.groups_asked is None, "a lookup was sent with no group repeated"


def test_a_failed_group_lookup_still_marks_the_overrides_and_says_so():
    class Failing(GroupCW):
        def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
            if "ManagedRuleGroupRule" in MetricDataQueries[0].get("Expression", ""):
                raise RuntimeError("ThrottlingException: rate exceeded")
            return super().get_metric_data(MetricDataQueries, StartTime, EndTime, **kw)
    cw = Failing({**DATA, ("CategoryHttpLibrary", "CountedRequests"): 65},
                 discoverable=FOUND | {("CategoryHttpLibrary", "CountedRequests")})
    out = _top_rules(TWICE, cw)
    assert any(l.startswith("CategoryHttpLibrary*") for l in out.splitlines()), out
    assert "ThrottlingException" in out, out


def test_a_webacl_rule_is_never_marked():
    out = _top_rules(TWICE)
    assert any(l.startswith("AWS-AWSManagedRulesBotControlRuleSet ") for l in out.splitlines()), out


def test_the_control_one_instance_marks_nothing():
    out = _top_rules(ONCE)
    assert "TGT_TokenAbsent*" not in out and "runs 2 times" not in out, out
    assert any(l.startswith("TGT_TokenAbsent ") for l in out.splitlines()), "the row itself vanished"


def test_an_override_on_a_repeated_group_is_listed_once():
    assert C._get_all_count_rules("us-east-1", "CLOUDFRONT", TWICE) == ["CategoryHttpLibrary", "SizeRestrictions_BODY"]


@pytest.fixture
def inventory(monkeypatch):
    def run(rules):
        monkeypatch.setattr(C, "_get_webacl_rules", lambda region, scope: rules)
        monkeypatch.setattr(C, "get_webacl_name", lambda: "acl")
        monkeypatch.setattr(C, "get_scope", lambda: "CLOUDFRONT")
        monkeypatch.setattr(C, "resolve_region", lambda scope: "us-east-1")
        monkeypatch.setattr(C, "get_client", lambda *a, **k: GroupCW({}))
        monkeypatch.setattr(P, "_get_all_rules_metrics_search",
                            lambda *a, **k: {"CategoryHttpLibrary": {"counted": [65]}})
        monkeypatch.setattr(M, "_metric_sum", lambda *a, **k: (0, ""))
        return C._step_init()
    return run


def test_count_eval_marks_a_repeated_groups_sub_rule(inventory):
    out = inventory(TWICE)
    assert "CategoryHttpLibrary* (65 hits)" in out and "runs 2 times" in out, out
    assert "Found 2 COUNT rules" in out and "SizeRestrictions_BODY*" not in out, out


def test_the_control_count_eval_with_one_instance(inventory):
    out = inventory(ONCE)
    assert "CategoryHttpLibrary (65 hits)" in out and "runs 2 times" not in out, out
