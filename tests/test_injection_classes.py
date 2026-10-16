# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Which managed sub-rules are injection detectors, decided per sub-rule rather than per group.

`investigate_injection` took CommonRuleSet and KnownBadInputs whole, so every block by either group
was an injection match. Measured on `shield-sample-webacl` over 14 days to 2026-10-16:
CommonRuleSet blocked 12 times with `RestrictedExtensions_URIPATH` and 2 with `GenericLFI_URIPATH`,
and with no SQLi in a window the tool focused that as "the busiest injection detector".
LinuxRuleSet, UnixRuleSet, WindowsRuleSet and PHPRuleSet were not read at all.

The line, decided 2026-10-16 with the maintainer: a rule family that finds a payload in a request
component is injection (SQLi, XSS, RFI, Log4j, Java deserialisation, React RCE, shell and PowerShell
commands, PHP, EC2 metadata SSRF, and file inclusion in a query, body or header). File inclusion on
the URI path is file probing, `.env` or `.git/config` asked for by name: the maintainer's
2026-10-13 test of 42 such paths matched `LFI_URIPATH` and `GenericLFI_URIPATH` and no payload rule.
So are `RestrictedExtensions`, `ExploitablePaths`, the size limits and the User-Agent, Host and
method checks. Windows' `_RC_COUNT` rules count and label for the rule beside them.
"""

import json
import types

import pytest

from tools import waf_injection as I


@pytest.mark.parametrize("name,expected", [
    ("SQLi_QUERYARGUMENTS", True), ("SQLiExtendedPatterns_QUERYARGUMENTS", True),
    ("CrossSiteScripting_URIPATH", True), ("GenericRFI_URIPATH", True),
    ("GenericLFI_QUERYARGUMENTS", True), ("GenericLFI_BODY", True),
    ("LFI_QUERYSTRING", True), ("LFI_HEADER", True),
    ("GenericLFI_URIPATH", False), ("LFI_URIPATH", False),
    ("Log4JRCE", True), ("Log4JRCE_URIPATH", True), ("JavaDeserializationRCE_HEADER", True), ("ReactJSRCE_BODY", True),
    ("UNIXShellCommandsVariables_BODY", True), ("WindowsShellCommands_QUERYARGUMENTS", True),
    ("PowerShellCommands_COOKIE", True), ("PHPHighRiskMethodsVariables_URIPATH", True),
    ("EC2MetaDataSSRF_QUERYARGUMENTS", True), ("WindowsShellCommands_BODY_RC_COUNT", False),
    ("RestrictedExtensions_URIPATH", False), ("RestrictedExtensions_QUERYARGUMENTS", False),
    ("ExploitablePaths_URIPATH", False), ("SizeRestrictions_BODY", False), ("NoUserAgent_HEADER", False),
    ("UserAgent_BadBots_HEADER", False), ("Host_localhost_HEADER", False), ("PROPFIND_METHOD", False),
])
def test_a_sub_rule_is_injection_by_its_family_and_component(name, expected):
    assert I._is_injection_sub_rule(name) is expected


def _group(name, group, overrides=(), override_action=None):
    rule = {"Name": name, "Statement": {"ManagedRuleGroupStatement": {
        "VendorName": "AWS", "Name": group,
        "RuleActionOverrides": [{"Name": o, "ActionToUse": {"Count": {}}} for o in overrides]}}}
    if override_action:
        rule["OverrideAction"] = {override_action: {}}
    return rule


COMMON = _group("AWS-AWSManagedRulesCommonRuleSet", "AWSManagedRulesCommonRuleSet")


def test_a_mixed_group_contributes_its_injection_sub_rules_not_itself():
    found, _ = I._injection_rules([COMMON])
    assert "AWS-AWSManagedRulesCommonRuleSet" not in found, found
    assert "CrossSiteScripting_QUERYARGUMENTS" in found and "GenericLFI_QUERYARGUMENTS" in found, found
    assert "RestrictedExtensions_URIPATH" not in found and "GenericLFI_URIPATH" not in found, found


@pytest.mark.parametrize("group,sub_rule", [
    ("AWSManagedRulesLinuxRuleSet", "LFI_QUERYSTRING"), ("AWSManagedRulesUnixRuleSet", "UNIXShellCommandsVariables_BODY"),
    ("AWSManagedRulesWindowsRuleSet", "PowerShellCommands_BODY"), ("AWSManagedRulesPHPRuleSet", "PHPHighRiskMethodsVariables_BODY"),
])
def test_the_os_and_php_groups_are_read(group, sub_rule):
    found, _ = I._injection_rules([_group("r", group)])
    assert sub_rule in found, found


def test_a_sub_rule_a_later_version_adds_is_found_through_its_override():
    found, _ = I._injection_rules([_group("r", "AWSManagedRulesSQLiRuleSet", overrides=["SQLi_HEADER"])])
    assert "SQLi_HEADER" in found, found


def test_a_group_in_whole_group_count_puts_its_sub_rules_in_count_mode():
    rules = [_group("sqli-shadow", "AWSManagedRulesSQLiRuleSet", override_action="Count")]
    assert "SQLi_QUERYARGUMENTS" in I._count_mode(rules)


def test_every_listed_sub_rule_belongs_to_a_listed_group():
    """The list is read off describe-managed-rule-group; a group missing from it would contribute
    nothing and say nothing."""
    assert set(I._MANAGED_SUB_RULES) >= set(I._INJECTION_GROUPS)
    assert all(any(I._is_injection_sub_rule(n) for n in I._MANAGED_SUB_RULES[g]) for g in I._INJECTION_GROUPS)


def _investigate(monkeypatch, rules, counts):
    """`counts` maps a rule name to (matches, blocks); the ranking returns it for the names asked."""
    class Waf:
        def list_web_acls(self, Scope):
            return {"WebACLs": [{"Name": "acl", "Id": "1"}]}

        def get_web_acl(self, **kw):
            return {"WebACL": {"Rules": rules}}
    for name, value in [("get_client", lambda *a, **k: Waf()), ("get_webacl_name", lambda: "acl"),
                        ("get_scope", lambda: "CLOUDFRONT"), ("resolve_region", lambda s: "us-east-1")]:
        monkeypatch.setattr(I, name, value)
    from tools import waf_aggregate, waf_logs, waf_metrics, waf_query
    monkeypatch.setattr(waf_query, "check_coarse_partition_block", lambda: None)
    asked = []

    def rank(names, start_time, duration_minutes):
        asked.append(list(names))
        return {n: counts.get(n, (0, 0)) for n in names}, ""
    monkeypatch.setattr(waf_aggregate, "rule_match_counts", rank)
    monkeypatch.setattr(waf_aggregate, "aggregate_logs", types.SimpleNamespace(
        _tool_func=lambda **kw: "x — 1 rows\n\n| v | hits |\n| --- | --- |\n| a | 1 |\n"))
    monkeypatch.setattr(waf_logs, "analyze_ip", types.SimpleNamespace(_tool_func=lambda *a: "profile"))
    warned = []
    monkeypatch.setattr(waf_metrics, "missed_data_warning", lambda *a, **k: warned.append((a[1], k)) or "")
    out = I.investigate_injection._tool_func(start_time="2026-10-13T03:00", duration_minutes=60)
    return out, asked, warned


def test_blocks_by_a_mixed_groups_other_rules_are_not_injection_activity(monkeypatch):
    """The 14-day shape: the group blocked on RestrictedExtensions_URIPATH and nothing else."""
    out, asked, _ = _investigate(monkeypatch, [COMMON], {"RestrictedExtensions_URIPATH": (12, 12),
                                                         "AWS-AWSManagedRulesCommonRuleSet": (14, 14)})
    assert "No injection rule matched anything" in out, out
    assert "AWS-AWSManagedRulesCommonRuleSet" not in asked[0], asked


def test_the_busiest_injection_sub_rule_is_the_focus(monkeypatch):
    out, _, _ = _investigate(monkeypatch, [COMMON], {"CrossSiteScripting_QUERYARGUMENTS": (40, 38),
                                                     "GenericLFI_QUERYARGUMENTS": (3, 3)})
    assert "Focusing **CrossSiteScripting_QUERYARGUMENTS**" in out and "40 matches, 38 blocked" in out, out


def test_a_quiet_window_cross_checks_each_sub_rule_against_its_group_metric(monkeypatch):
    """A managed sub-rule's blocks are not under `Rule=<sub-rule>`, measured empty for
    SQLi_QUERYARGUMENTS on 2026-09-08 while `ManagedRuleGroup`+`ManagedRuleGroupRule` held 122."""
    _, _, warned = _investigate(monkeypatch, [_group("AWS-AWSManagedRulesSQLiRuleSet", "AWSManagedRulesSQLiRuleSet")], {})
    by_rule = {r: k for r, k in warned}
    assert by_rule["SQLi_QUERYARGUMENTS"].get("group") == "AWSManagedRulesSQLiRuleSet", warned


def test_the_group_metric_reads_the_sub_rule_dimensions(monkeypatch):
    from tools import waf_metrics as M
    sent = []

    class CW:
        def get_metric_data(self, MetricDataQueries, **kw):
            sent.append(MetricDataQueries[0]["MetricStat"]["Metric"]["Dimensions"])
            return {"MetricDataResults": [{"Values": [122]}]}
    monkeypatch.setattr(M, "get_client", lambda *a, **k: CW())
    monkeypatch.setattr(M, "get_scope", lambda: "CLOUDFRONT")
    monkeypatch.setattr(M, "resolve_region", lambda s: "us-east-1")
    import time
    start = int(time.time()) // 3600 * 3600 - 7200
    M.missed_data_warning("acl", "SQLi_QUERYARGUMENTS", [], start, start + 3600, log_rows=0,
                          group="AWSManagedRulesSQLiRuleSet")
    assert {"Name": "ManagedRuleGroup", "Value": "AWSManagedRulesSQLiRuleSet"} in sent[0], sent
    assert {"Name": "ManagedRuleGroupRule", "Value": "SQLi_QUERYARGUMENTS"} in sent[0], sent
    assert not any(d["Name"] == "Rule" for d in sent[0]), sent


# --- the batched count ----------------------------------------------------------------

RECORDS = [  # (terminatingRuleId, action, every ruleId in the record)
    ("AWS-AWSManagedRulesCommonRuleSet", "BLOCK", {"CrossSiteScripting_QUERYARGUMENTS"}),
    ("AWS-AWSManagedRulesCommonRuleSet", "BLOCK", {"CrossSiteScripting_QUERYARGUMENTS"}),
    ("Default_Action", "ALLOW", {"SQLi_QUERYARGUMENTS", "TGT_TokenAbsent"}),
    ("my-sqli", "BLOCK", set()),
]


def _cwl_engine(query):
    """Answer a `stats sum(if(...))` query over RECORDS: each field names its rule once and BLOCK
    when it is the blocked count."""
    row = {}
    for alias, body in [(m.group(2), m.group(1)) for m in __import__("re").finditer(r"sum\(if\((.*?), 1, 0\)\) as (\w+)", query)]:
        name = __import__("re").search(r"terminatingRuleId = '([^']+)'", body).group(1)
        assert f"strcontains(@message, '\"ruleId\":\"{name}\"')" in body, body
        block = body.startswith("action = 'BLOCK' and ")
        row[alias] = str(sum(1 for t, a, ids in RECORDS if (t == name or name in ids) and (a == "BLOCK" or not block)))
    return [row]


def test_cloudwatch_counts_matches_and_blocks_for_every_name(monkeypatch):
    from tools import waf_aggregate as A
    from tools import waf_query as Q
    sent = []
    monkeypatch.setattr(Q, "query_logs", lambda cwl, athena, s, e, limit=25, **kw: (sent.append(cwl), _cwl_engine(cwl))[1])
    monkeypatch.setattr(Q, "get_log_type", lambda: "cwl")
    names = ["CrossSiteScripting_QUERYARGUMENTS", "SQLi_QUERYARGUMENTS", "my-sqli", "GenericLFI_BODY"]
    counts, reason = A.rule_match_counts(names, "2026-10-13T03:00", 60)
    assert reason == "" and counts == {"CrossSiteScripting_QUERYARGUMENTS": (2, 2), "SQLi_QUERYARGUMENTS": (1, 0),
                                       "my-sqli": (1, 1), "GenericLFI_BODY": (0, 0)}, counts
    many = [f"PHPHighRiskMethodsVariables_CUSTOM_{i:03d}" for i in range(80)]
    A.rule_match_counts(many, "2026-10-13T03:00", 60)
    assert len(sent) > 2 and all(len(q) <= Q.CWL_QUERY_MAX for q in sent), [len(q) for q in sent]


def test_a_failed_count_is_none_with_its_reason(monkeypatch):
    from tools import waf_aggregate as A
    from tools import waf_query as Q

    def boom(*a, **k):
        raise RuntimeError("ThrottlingException")
    monkeypatch.setattr(Q, "query_logs", boom)
    counts, reason = A.rule_match_counts(["SQLi_BODY"], "2026-10-13T03:00", 60)
    assert counts is None and "ThrottlingException" in reason


def test_athena_counts_each_name_with_the_rule_filter(monkeypatch):
    from tools import waf_aggregate as A
    from tools import waf_query as Q
    sent = []
    monkeypatch.setattr(Q, "get_log_type", lambda: "s3")
    monkeypatch.setattr(Q, "query_logs", lambda cwl, athena, s, e, limit=25, **kw: (sent.append(athena), [{"m0": "3", "b0": "1"}])[1])
    counts, _ = A.rule_match_counts(["SQLi_BODY"], "2026-10-13T03:00", 60)
    assert counts == {"SQLi_BODY": (3, 1)}
    assert "count_if(" + A._RULE_ATHENA.format(v="SQLi_BODY") + ")" in sent[0], sent[0]


def test_the_configured_list_counts_a_groups_sub_rules_rather_than_naming_them(monkeypatch):
    rules = [COMMON, {"Name": "my-sqli", "Action": {"Block": {}},
                      "Statement": {"SqliMatchStatement": {"FieldToMatch": {"Body": {}}}}}]
    out, _, _ = _investigate(monkeypatch, rules, {})
    line = next(l for l in out.splitlines() if l.startswith("Injection rules configured"))
    assert "my-sqli" in line and "13 injection sub-rules of AWSManagedRulesCommonRuleSet" in line, line
