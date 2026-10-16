# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A rule group overridden to Count as a whole is found by the counted predicate and the rule filter.

`RECORD` is a real WAF log record, trimmed, captured 2026-10-15 after adding
`AWSManagedRulesAdminProtectionRuleSet` to `shield-sample-webacl` as rule `ptest-admin-group-count`
with `OverrideAction: Count` and sending `/admin` requests. Athena logged the same shape for
`response-id-on-page`, the counted predicate matched 5 of 5 there, and `CountedRequests` for the rule
read 5. Kept in WAF's compact serialisation, because the CloudWatch predicates are substring matches
over exactly that text.

The shape is the point: the group's own entry carries the sub-rule's NATIVE action, BLOCK, and no
COUNT at all. The Count is the top-level entry named for the WebACL rule. A predicate that kept only
the nested branches, or a rule filter keyed on the sub-rule's action, would miss it.
"""

import json

from tools.counted import COUNTED_ATHENA, COUNTED_CWL
from tools.waf_aggregate import _RULE_ATHENA, _RULE_CWL
from tools.waf_injection import _count_mode, _injection_rules

RECORD = ('{"action":"ALLOW","terminatingRuleId":"Default_Action","nonTerminatingMatchingRules":[{"ruleId":'
          '"ptest-admin-group-count","action":"COUNT","ruleMatchDetails":[{"conditionType":"REGEX","location":'
          '"URI","matchedData":null,"matchedFieldName":""}]}],"ruleGroupList":[{"ruleGroupId":'
          '"AWS#AWSManagedRulesAdminProtectionRuleSet","terminatingRule":{"ruleId":"AdminProtection_URIPATH",'
          '"action":"BLOCK","ruleMatchDetails":null},"nonTerminatingMatchingRules":[],"excludedRules":null,'
          '"customerConfig":null}],"httpRequest":{"clientIp":"203.0.113.9","uri":"/admin/p1"},"labels":'
          '[{"name":"awswaf:managed:aws:admin-protection:AdminProtection_URIPath"}]}')


def _cwl_literals(predicate):
    import re
    return re.findall(r"@message like '([^']*)'", predicate)


def test_the_record_has_the_measured_shape():
    """The precondition: if this stops holding, the assertions below are about an imagined record."""
    rec = json.loads(RECORD)
    group = rec["ruleGroupList"][0]
    assert group["terminatingRule"]["action"] == "BLOCK" and not group["nonTerminatingMatchingRules"]
    assert rec["nonTerminatingMatchingRules"] == [
        {**rec["nonTerminatingMatchingRules"][0], "ruleId": "ptest-admin-group-count", "action": "COUNT"}]


def test_the_counted_predicate_matches_a_whole_group_count():
    assert any(lit in RECORD for lit in _cwl_literals(COUNTED_CWL)), COUNTED_CWL
    # Athena: the top-level branch is the one this record satisfies; the nested ones cannot.
    assert "any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT')" in COUNTED_ATHENA


def test_the_rule_filter_finds_the_group_by_its_webacl_rule_name():
    lits = _cwl_literals(_RULE_CWL.replace("{v}", "ptest-admin-group-count"))
    assert any(lit in RECORD for lit in lits), lits
    assert "any_match(nonterminatingmatchingrules, r -> r.ruleid = '{v}')" in _RULE_ATHENA


def test_an_injection_group_overridden_to_count_is_a_count_mode_detector():
    rules = [{"Name": "sqli-shadow", "OverrideAction": {"Count": {}},
              "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet"}}}]
    found, _ = _injection_rules(rules)
    assert found == ["sqli-shadow"] and _count_mode(rules) == {"sqli-shadow"}
