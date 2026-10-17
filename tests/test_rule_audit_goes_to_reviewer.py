# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A full rules audit goes to AWS WAF Rules Reviewer, and the knowledge base carries its corrections.

`review_waf_rules_deep` ran a copy of the reviewer's pipeline taken on 2026-05-12, 3,976 lines against
8,577 at the reviewer's v0.9.0, and it gave conclusions the reviewer had since corrected. So the copy is
gone and the prompt names the reviewer. The knowledge base kept statements the reviewer had corrected
too, each checked against AWS documentation on 2026-10-17:

- the SQLi rule set as an upgrade path: the changelog says "Version_2.3 is the successor to Version_1.3,
  not Version_2.0", and 2.0 (2022) is older than 1.2 (2024) and 1.3 (2025);
- the Core rule set as SQLi protection: its rule table has no SQLi rule;
- overlapping rate limits where "only the lowest threshold triggers": AWS documents that each rule
  counts on its own and rules run by priority, not by limit;
- Bot Control's Common level as a User-Agent classifier: AWS calls it "static request data analysis",
  and its rules read the source IP and automated-browser indicators too;
- a quoted Anti-DDoS price with no source, where Shield Advanced's inclusion went unsaid.

A second pass over the files the first did not touch found more, each checked against AWS
documentation or `describe-managed-rule-group` on 2026-10-17: a Fraud Control price 1,000 times too
high and a free tier the pricing examples never deduct; ACFP `AutomatedBrowser` and
`TGT_ML_CoordinatedActivityLow` at Count or Block where AWS ships CAPTCHA and Challenge; every Targeted
rule said to need a token, where `TGT_TokenAbsent` and `TGT_VolumetricIpTokenAbsent` match its absence;
ASN match and JA3/JA4 called unforgeable, where `ForwardedIPConfig` reads a header AWS says attackers
alter and a fingerprint comes from the client's own TLS hello; COUNT as a top-level log action; the
Anti-DDoS rule group said to replace `AWSManagedIPDDoSList`, which the DDoS whitepaper still
recommends; and DDoS traffic said to be free in Count mode too.
"""

import pathlib

import pytest

import agent

ROOT = pathlib.Path(__file__).resolve().parents[1]
REVIEWER = "https://github.com/chenghit/aws-waf-rules-reviewer"


def _kb(name):
    return (ROOT / "kb-docs" / name).read_text()


def test_the_prompt_sends_a_full_audit_to_the_reviewer():
    line = next(l for l in agent.SYSTEM_PROMPT.splitlines() if '"review" / "audit"' in l)
    assert REVIEWER in line and "get_waf_config" in line, line


def test_the_vendored_pipeline_is_gone():
    names = {getattr(t, "tool_name", None) for t in agent._TOOLS}
    assert not names & {"review_waf_rules_deep", "finalize_review_report"}, names
    assert not (ROOT / "scripts").exists() and not (ROOT / "references").exists()
    assert "scripts/" not in (ROOT / "Dockerfile").read_text()
    assert "__get_review_report__" not in (ROOT / "frontend" / "src" / "App.jsx").read_text()


@pytest.mark.parametrize("doc,wrong,right", [
    ("managed-overrides.md", "Recommend upgrading if pinned below 2.0", "SQLi is not an upgrade path"),
    ("managed-overrides.md", "Provides OWASP Top 10 protection (SQLi", "It has no SQL injection rules"),
    ("rate-based.md", "only the rule with the lowest threshold will ever trigger", "rules are evaluated by priority, not by limit"),
    ("rate-based.md", "no upper bound specified", "10 to 2,000,000,000"),
    ("bot-control.md", "Common level is a UA-based classifier", "static request data analysis"),
    ("managed-overrides.md", "Recommend upgrading if pinned below 5.0", "recommend pinning it"),
    ("antiddos-amr.md", "$20/month per AMR instance", "50 billion requests"),
    ("bot-control.md", "by 6.1 the Common level identifies more than 600", "Version_6.1 lists 697 `bot:name:` labels"),
    ("managed-overrides.md", "by 6.1 the Common level identifies more than 600 bots", "Version_6.1 lists 697 `bot:name:` labels"),
    ("bot-control.md", "mostly runs the Common rules plus the ML rules", "`TGT_VolumetricIpTokenAbsent` (Challenge)"),
    ("fraud-control-atp-acfp.md", "$1/request for first 2M", "$0.001 a request"),
    ("fraud-control-atp-acfp.md", "| `AutomatedBrowser` | `signal:automated_browser` | Block |",
     "| `AutomatedBrowser` | `signal:automated_browser` | CAPTCHA |"),
    ("fraud-control-atp-acfp.md", "| Free | First 10,000 | $0 |", "without deducting anything"),
    ("fraud-control-atp-acfp.md", "phone number or custom username formats not supported", "only contains usernames in email format"),
    ("advanced-bot-detection.md", "`TGT_ML_CoordinatedActivityLow` → Count", "`TGT_ML_CoordinatedActivityLow` → Challenge"),
    ("advanced-bot-detection.md", "Keep Low at Count", "Keep Low at its default Challenge"),
    ("advanced-bot-detection.md", "detects bots that self-identify via User-Agent", "static request data"),
    ("bot-control-labels-v5.md", "Yes — requires AWS WAF token for session tracking", "match its absence"),
    ("bot-control-labels-v5.md", "all 700+", "without memorizing them all"),
    ("bot-control-labels-v5.md", "bot farm, recommend immediate Block", "evidence in advanced-bot-detection.md"),
    ("asn-match.md", "ASN match is unforgeable", "might alter the contents of the header"),
    ("asn-match.md", "| JA3/JA4 | No |", "TLS Client Hello"),
    ("common-patterns.md", "ASN match (based on source IP's network).\n", "`ForwardedIPConfig`"),
    ("crawler-seo.md", "unforgeable", "`ForwardedIPConfig`"),
    ("waf-log-field-availability.md", "ALLOW / BLOCK / COUNT / CHALLENGE / CAPTCHA", "`nonTerminatingMatchingRules`"),
    ("ip-reputation.md", "AMR subsumes its functionality", "whitepaper still recommends"),
    ("antiddos-amr.md", "DDoS traffic detected and mitigated is NOT charged", "NOT in Count mode"),
    ("antiddos-amr.md", "$20 a month for each web ACL using it", "prorated hourly"),
])
def test_the_knowledge_base_carries_the_corrected_statement(doc, wrong, right):
    text = _kb(doc)
    assert wrong not in text and right in text, doc


@pytest.mark.parametrize("wrong,right", [
    ("Change to unforgeable (IP set / AWS WAF token / ASN)", "ASN without `ForwardedIPConfig`"),
    ("TGT_* rules only work properly when Targeted level is deployed AND SDK is integrated",
     "TGT_TokenAbsent and TGT_VolumetricIpTokenAbsent match the token's absence"),
])
def test_the_prompt_carries_the_corrected_statement(wrong, right):
    assert wrong not in agent.SYSTEM_PROMPT and right in agent.SYSTEM_PROMPT


def test_the_sidebar_offers_no_audit():
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text()
    guide = app[app.index("const guideItems"):app.index("return (", app.index("const guideItems"))]
    assert "Security patrol" in guide and "安全巡检" in guide, guide
    assert not any(w in guide for w in ("Review my WAF", "audit", "审查", "审计")), guide


def test_the_reviewer_is_named_where_users_look():
    for doc in ("README.md", "README_zh.md", "docs/capabilities.md", "docs/capabilities_zh.md",
                "docs/user-guide.md", "docs/user-guide_zh.md"):
        assert REVIEWER in (ROOT / doc).read_text(), doc
