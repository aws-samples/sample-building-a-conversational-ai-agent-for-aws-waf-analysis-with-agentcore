# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`investigate_injection` ranks detectors by what they matched, and says when it could not read.

**Count-mode detectors could never become the focus rule.** Step 1 keeps them on purpose, since a
shadow-mode detector is exactly what you investigate, and then ranked with
`filter_by={"action": "BLOCK"}` over the terminating rule. A Count match ends as ALLOW and is
recorded under the sub-rule's name, nested in `rulegrouplist`. Measured 2026-10-15 on
`test-webacl-s3`, 2026-09-08: 160 `CrossSiteScripting_QUERYARGUMENTS` matches, all Count, all
nested, beside 122 SQLi blocks. A window with only the XSS traffic answered "No injection rule
blocked anything" and stopped. The downstream sections filtered on BLOCK too.

**And three failures read as absences:** a failed WebACL read printed "No injection-detection rule
found ... which is itself the finding", a failed ranking query read as a rule that matched nothing,
and a failed source query classified as "nothing matched this rule".
"""

import json
import types

import pytest

from tools import waf_injection as I

XSS_SUB = "CrossSiteScripting_QUERYARGUMENTS"
ACL_RULES = [
    {"Name": "AWS-AWSManagedRulesSQLiRuleSet",
     "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesSQLiRuleSet"}}},
    {"Name": "AWS-AWSManagedRulesCommonRuleSet",
     "Statement": {"ManagedRuleGroupStatement": {
         "VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet",
         "RuleActionOverrides": [{"Name": XSS_SUB, "ActionToUse": {"Count": {}}}]}}},
    {"Name": "AWS-AWSManagedRulesBotControlRuleSet",
     "Statement": {"ManagedRuleGroupStatement": {
         "VendorName": "AWS", "Name": "AWSManagedRulesBotControlRuleSet",
         "RuleActionOverrides": [{"Name": "CategoryHttpLibrary", "ActionToUse": {"Count": {}}}]}}},
    {"Name": "my-sqli", "Action": {"Block": {}},
     "Statement": {"SqliMatchStatement": {"FieldToMatch": {"Body": {}}}}},
]


def _table(col, rows):
    return (f"x — {len(rows)} rows\n\n| {col} | hits |\n| --- | --- |\n"
            + "".join(f"| {v} | {h} |\n" for v, h in rows))


ZERO = "[rule=x] by action, 60 min returned 0 results.\nPossible reasons: ..."


def _run(monkeypatch, matches, fail=(), acl_error=None, source_fails=False):
    """`matches` maps a rule name to [(action, hits)]. `fail` names rules whose ranking query
    errors. Every `aggregate_logs` call is recorded so the filters can be asserted."""
    class Waf:
        def list_web_acls(self, Scope):
            if acl_error:
                raise acl_error
            return {"WebACLs": [{"Name": "acl", "Id": "1"}]}

        def get_web_acl(self, **kw):
            return {"WebACL": {"Rules": ACL_RULES}}

    for name, value in [("get_client", lambda *a, **k: Waf()), ("get_webacl_name", lambda: "acl"),
                        ("get_scope", lambda: "CLOUDFRONT"), ("resolve_region", lambda s: "us-east-1")]:
        monkeypatch.setattr(I, name, value)
    # Both imported inside the tool function, so the source module is the patch point.
    from tools import waf_aggregate, waf_query
    monkeypatch.setattr(waf_query, "check_coarse_partition_block", lambda: None)
    calls = []

    def agg(start_time, duration_minutes, group_by, filter_by="", **kw):
        f = json.loads(filter_by or "{}")
        calls.append((group_by, f))
        rule = f.get("rule")
        if group_by == "action":
            if rule in fail:
                return "Error: the aggregation query did not run. RuntimeError: throttled"
            rows = matches.get(rule, [])
            return _table("action", rows) if rows else ZERO
        if group_by == "rule":
            # The shape the old ranking asked for: terminating rules, BLOCK only. Answered so the
            # pre-fix code fails on what it concludes rather than on this fake.
            rows = [(r, h) for r, acts in matches.items() for a, h in acts if a == "BLOCK"]
            return _table("terminatingRuleId", rows) if rows else ZERO
        if "," in group_by:
            return ZERO  # the allowed-traffic sections, covered in test_injection_allowed.py
        if group_by == "clientIp" and source_fails:
            return "Error: the aggregation query did not run. RuntimeError: throttled"
        col = {"uri": "httpRequest.uri", "clientIp": "httpRequest.clientIp", "ua": "ua", "ja4": "ja4Fingerprint"}[group_by]
        return _table(col, [("v1", 3)])
    monkeypatch.setattr(waf_aggregate, "aggregate_logs", types.SimpleNamespace(_tool_func=agg))

    def rank(names, start_time, duration_minutes):
        """The ranking's count, from `matches`; one failed name fails the query, as it is one query."""
        if any(n in fail for n in names):
            return None, "RuntimeError: throttled"
        return {n: (sum(h for _, h in matches.get(n, [])), sum(h for a, h in matches.get(n, []) if a == "BLOCK"))
                for n in names}, ""
    monkeypatch.setattr(waf_aggregate, "rule_match_counts", rank)
    from tools import waf_logs, waf_metrics
    monkeypatch.setattr(waf_logs, "analyze_ip", types.SimpleNamespace(_tool_func=lambda *a: "profile"))
    monkeypatch.setattr(waf_metrics, "missed_data_warning", lambda *a, **k: "")
    return I.investigate_injection._tool_func(start_time="2026-09-08T10:00", duration_minutes=60), calls


def test_overridden_sub_rules_of_injection_groups_are_detectors():
    found, _ = I._injection_rules(ACL_RULES)
    assert XSS_SUB in found, found
    assert "CategoryHttpLibrary" not in found, "a Bot Control override is not injection detection"


def test_a_count_mode_detector_with_the_most_matches_is_the_focus(monkeypatch):
    out, calls = _run(monkeypatch, {XSS_SUB: [("ALLOW", 160)], "my-sqli": [("BLOCK", 5)]})
    assert f"Focusing **{XSS_SUB}**" in out or f"Focus rule: **{XSS_SUB}**" in out, out
    assert "Count mode" in out, "the focus rule's Count mode is not stated"
    # The allowed-traffic sections filter on the sources and paths, not on the rule.
    downstream = [f for g, f in calls if g != "action" and "," not in g]
    assert downstream and all(f == {"rule": XSS_SUB} for f in downstream), downstream


def test_the_busiest_detector_wins_over_config_order(monkeypatch):
    """The first live-found defect: config order picked a rule that had matched nothing. Here the
    first detector in the WebACL has 2 matches and a later one 97, so order and count disagree."""
    out, _ = _run(monkeypatch, {"SQLi_QUERYARGUMENTS": [("BLOCK", 2)], "my-sqli": [("BLOCK", 97)]})
    assert "Focusing **my-sqli**" in out, out


def test_a_window_with_only_count_matches_is_not_reported_as_quiet(monkeypatch):
    out, _ = _run(monkeypatch, {XSS_SUB: [("ALLOW", 160)]})
    assert "No injection rule" not in out, out


def test_a_window_with_no_matches_still_stops(monkeypatch):
    """The control for the stop branch."""
    out, _ = _run(monkeypatch, {})
    assert "No injection rule matched anything" in out, out


def test_a_failed_ranking_query_is_not_read_as_no_matches(monkeypatch):
    out, _ = _run(monkeypatch, {}, fail={XSS_SUB})
    assert "No injection rule matched anything" not in out, out
    # One query counts every detector now, so its reason is what is named.
    assert "throttled" in out and "Do NOT report this window as quiet" in out, out


def test_a_failed_webacl_read_is_not_reported_as_no_coverage(monkeypatch):
    out, _ = _run(monkeypatch, {}, acl_error=RuntimeError("AccessDenied"))
    assert "No injection-detection rule found" not in out, out
    assert "AccessDenied" in out and "unknown" in out.lower(), out


def test_a_failed_source_query_is_not_classified_as_no_evidence(monkeypatch):
    out, _ = _run(monkeypatch, {"my-sqli": [("BLOCK", 5)]}, source_fails=True)
    assessment = out.split("### Assessment", 1)[1]
    assert "nothing matched" not in assessment, assessment
    assert "unknown" in assessment.lower() and "throttled" in assessment, assessment
