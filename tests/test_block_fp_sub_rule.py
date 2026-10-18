# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The false-positive investigation names the sub-rule of the group that blocked.

A rule group in whole-group Count still logs the sub-rule that matched as its `terminatingRule`,
with the native BLOCK, and evaluation goes on to the next group. So a record holds one
`terminatingRule` per group that matched, in evaluation order, and the group that ended evaluation
is the last. Measured 2026-10-02 to 10-16 on `test-webacl-cwl`, across the 2026-10-13 probe
test that ran every group in Count: in 109 of 109 managed-group blocks the last entry was the
terminating group, and in 6 of the 17 LinuxRuleSet blocks the first entry was another group's
(`ExploitablePaths_URIPATH` 4, `RestrictedExtensions_URIPATH` 2) where `LFI_URIPATH` blocked.

The lookup also read every BLOCK from the IP, so with two groups blocking it the busiest sub-rule
could be the other group's.
"""

import json
import re

from tools import waf_block_fp as F


def _record(rule, groups):
    """A WAF record in WAF's compact JSON. `groups` is [(ruleGroupId, terminating sub-rule or None)]."""
    return json.dumps({"action": "BLOCK", "terminatingRuleId": rule, "terminatingRuleType": "MANAGED_RULE_GROUP",
                       "ruleGroupList": [{"ruleGroupId": g, "terminatingRule": None if s is None else
                                          {"ruleId": s, "action": "BLOCK", "ruleMatchDetails": None},
                                          "nonTerminatingMatchingRules": [], "excludedRules": None}
                                         for g, s in groups],
                       "rateBasedRuleList": []}, separators=(",", ":"))


LINUX = "AWS-AWSManagedRulesLinuxRuleSet"
COMMON = "AWS-AWSManagedRulesCommonRuleSet"
# KnownBadInputs in whole-group Count matched first and logged its sub-rule; Linux blocked.
RECORDS = ([_record(LINUX, [("AWS#AWSManagedRulesKnownBadInputsRuleSet", "ExploitablePaths_URIPATH"),
                            ("AWS#AWSManagedRulesCommonRuleSet", None),
                            ("AWS#AWSManagedRulesLinuxRuleSet", "LFI_URIPATH")])] * 3
           + [_record(LINUX, [("AWS#AWSManagedRulesLinuxRuleSet", "LFI_QUERYSTRING")])] * 2
           # The same IP blocked by CommonRuleSet less often than by Linux, but by one sub-rule more
           # often than by any one of Linux's, so a lookup over every BLOCK picks it.
           + [_record(COMMON, [("AWS#AWSManagedRulesCommonRuleSet", "RestrictedExtensions_URIPATH")])] * 4)


def _cwl(query):
    """Run a CloudWatch query's filter on terminatingRuleId and its `parse` over RECORDS, as the
    engine would, and count by the parsed field."""
    rule = re.search(r"terminatingRuleId = '([^']+)'", query)
    pattern = re.search(r"parse @message /(.*?)/ \|", query).group(1).replace("(?<", "(?P<")
    counts = {}
    for rec in RECORDS:
        if rule and json.loads(rec)["terminatingRuleId"] != rule.group(1):
            continue
        m = re.search(pattern, rec)
        if m:
            counts[m.group("sub_rule")] = counts.get(m.group("sub_rule"), 0) + 1
    return [{"sub_rule": k, "hits": str(v)} for k, v in sorted(counts.items(), key=lambda x: -x[1])]


def _gather(monkeypatch):
    blocks = [{"terminatingRuleId": LINUX, "terminatingRuleType": "MANAGED_RULE_GROUP", "hits": "5"},
              {"terminatingRuleId": COMMON, "terminatingRuleType": "MANAGED_RULE_GROUP", "hits": "4"}]
    monkeypatch.setattr(F, "run_concurrently", lambda jobs: (
        {"block": blocks, "ratio": [{"action": "BLOCK", "hits": "9"}], "freq": [{"peak_rpm": "1"}],
         "multi": blocks, "uri": []}, {}))
    sent = []

    def run(cwl, athena, start, end, limit=25):
        sent.append((cwl, athena))
        return _cwl(cwl)
    monkeypatch.setattr(F, "_run_query", run)
    monkeypatch.setattr(F, "_gather_match_detail", lambda *a: ("", ""))
    monkeypatch.setattr(F, "_get_text_transformations", lambda *a: [])
    from tools import waf_query as Q
    monkeypatch.setattr(Q, "sample_inspection_content", lambda *a, **k: (None, None, False))
    return F._investigate_gather("203.0.113.9", 0, 3600), sent


def test_the_sub_rule_is_the_blocking_groups_not_a_count_groups(monkeypatch):
    d, _ = _gather(monkeypatch)
    assert d["rule_id"] == LINUX and d["sub_rule"] == "LFI_URIPATH", d["sub_rule"]


def test_the_athena_lookup_reads_the_last_matching_group_of_the_blocking_rule(monkeypatch):
    """Athena unnested every group and counted each non-null `terminatingRule`, so the Count group's
    sub-rule was counted beside the blocking one. The fake above cannot run SQL, so this pins the
    shape; the live check is in the commit."""
    _, sent = _gather(monkeypatch)
    athena = next(a for c, a in sent if "sub_rule" in c)
    assert "element_at(filter(rulegrouplist, rg -> rg.terminatingrule IS NOT NULL), -1)" in athena, athena
    assert f"terminatingruleid = '{LINUX}'" in athena and "UNNEST" not in athena, athena
