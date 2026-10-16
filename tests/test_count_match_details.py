# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The Count evaluation shows what a Count rule matched, from its entries' `ruleMatchDetails`.

`terminatingRuleMatchDetails` is empty for a Count match; the details are on the Count entry
itself. Measured on `response-id-on-page`, 2026-09-08 03:00-05:00: 160 of 160
`CrossSiteScripting_QUERYARGUMENTS` Count records carried them, four payload shapes at 40 each
(`< iframe`, `< svg`, `< script`, `onerror alert(1)`, location `ALL_QUERY_ARGS`). On
`shield-sample-webacl` a whole-group Count entry carries one too, `REGEX` at `URI` with
`matchedData` null. The tool read only the inspected component, so the strongest signal for
"attack-shaped or legitimate" was never shown.
"""

import json

import pytest

from tools import session_state as S
from tools import waf_count_eval as C
from tools import waf_query as WQ

RULE = "CrossSiteScripting_QUERYARGUMENTS"


def _entry(rule, details):
    return {"ruleId": rule, "action": "COUNT", "ruleMatchDetails": details}


def _xss(*tokens):
    return {"conditionType": "XSS", "location": "ALL_QUERY_ARGS", "matchedData": list(tokens)}


def _record(top=(), groups=()):
    return {"@message": json.dumps({
        "action": "ALLOW", "nonTerminatingMatchingRules": list(top),
        "ruleGroupList": [{"ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet", "terminatingRule": None,
                           "nonTerminatingMatchingRules": list(g)} for g in groups]}, separators=(",", ":"))}


RECORDS = (
    # A group deployed twice logs the sub-rule's entry twice; it is still one request.
    [_record(groups=[[_entry(RULE, [_xss("<", "script")])], [_entry(RULE, [_xss("<", "script")])]])] * 3
    + [_record(groups=[[_entry(RULE, [_xss("onerror", "alert(1)")])]])] * 2
    # Another rule's details on the same record are not this rule's.
    + [_record(groups=[[_entry("SQLi_QUERYARGUMENTS", [{"conditionType": "SQL_INJECTION",
                                                        "location": "ALL_QUERY_ARGS", "matchedData": ["1", "OR"]}]),
                        _entry(RULE, [_xss("<", "svg")])]])]
)


def _check_clients(monkeypatch, engine, answer):
    monkeypatch.setattr(C, "_get_webacl_rules", lambda *a: [])
    monkeypatch.setattr(C, "get_log_type", lambda: engine)
    monkeypatch.setattr(WQ, "get_log_type", lambda: engine)
    monkeypatch.setattr(C, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: "")
    monkeypatch.setattr(WQ, "sample_inspection_content", lambda *a, **k: (None, None, False))
    monkeypatch.setattr(C, "_count_rule_matches", lambda *a: None)
    monkeypatch.setattr(C, "query_logs", answer)
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1")
    S.set_user_timezone(0.0)
    out = C._step_check_clients(RULE, "2026-09-08T03:00", 120)
    assert "### What the rule matched" in out, out
    return out.split("### What the rule matched", 1)[1].split("###", 1)[0].split("---", 1)[0]


def _cwl(cwl, athena, start, end, limit=25, **kw):
    if "fields @message" in cwl:
        return RECORDS[:limit]
    return [{"httpRequest.clientIp": "203.0.113.9", "hits": "6"}]


def test_cloudwatch_shows_each_matched_payload_once_per_request(monkeypatch):
    section = _check_clients(monkeypatch, "cwl", _cwl)
    assert "[   3 requests] XSS at ALL_QUERY_ARGS: < script" in section, section
    assert "[   2 requests] XSS at ALL_QUERY_ARGS: onerror alert(1)" in section, section
    assert "[   1 requests] XSS at ALL_QUERY_ARGS: < svg" in section, section
    assert "1 OR" not in section, "another rule's match details were attributed to this one"
    assert "6 sampled requests" in section, section


def test_a_regex_entry_says_its_matched_data_is_not_recorded(monkeypatch):
    records = [_record(top=[_entry(RULE, [{"conditionType": "REGEX", "location": "URI", "matchedData": None,
                                           "matchedFieldName": ""}])])]
    section = _check_clients(monkeypatch, "cwl", lambda cwl, *a, **k: records if "fields @message" in cwl else [])
    assert "REGEX at URI: matched data not recorded" in section, section


def test_athena_shows_the_rows_its_query_returns(monkeypatch):
    sent = []

    def athena(cwl, athena_q, start, end, limit=25, **kw):
        sent.append(athena_q)
        if "rulematchdetails" in athena_q:
            return [{"md": "XSS at ALL_QUERY_ARGS: < iframe", "hits": "40"}]
        return [{"httpRequest.clientIp": "203.0.113.9", "hits": "6"}]
    section = _check_clients(monkeypatch, "athena", athena)
    assert "[  40 requests] XSS at ALL_QUERY_ARGS: < iframe" in section, section
    q = next(a for a in sent if "rulematchdetails" in a)
    assert "rg.nonterminatingmatchingrules" in q and "count(DISTINCT httprequest.requestid)" in q, q


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_a_failed_read_says_so_rather_than_none(monkeypatch, engine):
    def answer(cwl, athena, start, end, limit=25, **kw):
        if "fields @message" in cwl or "rulematchdetails" in athena:
            raise RuntimeError("ThrottlingException: rate exceeded")
        return [{"httpRequest.clientIp": "203.0.113.9", "hits": "6"}]
    section = _check_clients(monkeypatch, engine, answer)
    assert "UNKNOWN" in section and "ThrottlingException" in section, section
