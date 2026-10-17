#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_rule_audit_goes_to_reviewer.py` fail? The routing and each corrected statement put
back as it was."""

import sys

from _harness import sweep

T = "tests/test_rule_audit_goes_to_reviewer.py"
KB = f"{T}::test_the_knowledge_base_carries_the_corrected_statement"
PROMPT = f"{T}::test_the_prompt_carries_the_corrected_statement"

CASES = [
    ("a full audit routed nowhere",
     [("agent.py", "Point the user to AWS WAF Rules Reviewer, https://github.com/chenghit/aws-waf-rules-reviewer, which",
       "Point the user to a rules reviewer, which")],
     [f"{T}::test_the_prompt_sends_a_full_audit_to_the_reviewer"]),

    ("the vendored pipeline copied into the image again",
     [("Dockerfile", "COPY tools/ ./tools/\n", "COPY tools/ ./tools/\nCOPY scripts/ ./scripts/\n")],
     [f"{T}::test_the_vendored_pipeline_is_gone"]),

    ("SQLi recommended as an upgrade again",
     [("kb-docs/managed-overrides.md", "**SQLi is not an upgrade path.**",
       "**SQLiRuleSet**: Recommend upgrading if pinned below 2.0.")],
     [KB]),

    ("the Core rule set said to cover SQLi again",
     [("kb-docs/managed-overrides.md", "It has no SQL injection rules: those are in `AWSManagedRulesSQLiRuleSet`",
       "Provides OWASP Top 10 protection (SQLi, XSS, etc.)")],
     [KB]),

    ("only the lowest rate limit triggers, again",
     [("kb-docs/rate-based.md", "each rule counts on its own, and rules are evaluated by priority, not by limit.",
       "only the rule with the lowest threshold will ever trigger for the overlapping traffic.")],
     [KB]),

    ("Common level a User-Agent classifier again",
     [("kb-docs/bot-control.md", "- Identifies bots with what AWS calls \"static request data analysis\".",
       "- Identifies self-declared bots by analyzing the User-Agent header.")],
     [KB]),

    ("Bot Control pinned to 5.0 again rather than the latest",
     [("kb-docs/managed-overrides.md", "is the latest static version; recommend pinning it.",
       "is the latest static version. Recommend upgrading if pinned below 5.0.")],
     [KB]),

    ("the Anti-DDoS price quoted with no source again",
     [("kb-docs/antiddos-amr.md", "- A Shield Advanced subscription includes the rule group, with up to 50 billion requests",
       "- A Shield Advanced subscription includes the rule group, with up to some requests")],
     [KB]),

    ("the reviewer dropped from the user guide",
     [("docs/user-guide.md", "Use [AWS WAF Rules Reviewer](https://github.com/chenghit/aws-waf-rules-reviewer), which your coding",
       "Use a rules reviewer, which your coding")],
     [f"{T}::test_the_reviewer_is_named_where_users_look"]),

    ("the sidebar offering the audit again",
     [("frontend/src/App.jsx", "{text: '\"Detect bypass attacks\"',",
       "{text: '\"Review my WAF rules\"', tip: 'Full security audit'}, {text: '\"Detect bypass attacks\"',")],
     [f"{T}::test_the_sidebar_offers_no_audit"]),

    ("the prompt calling ASN unforgeable again",
     [("agent.py", "Change to a condition the client can't set (IP set or ASN without `ForwardedIPConfig`, AWS WAF token)",
       "Change to unforgeable (IP set / AWS WAF token / ASN)")],
     [PROMPT]),

    ("the prompt saying every TGT_ rule needs the SDK again",
     [("agent.py", "  - Most TGT_* rules need a token, so they only work properly when Targeted level is deployed AND SDK is integrated. The TGT_ML_ rules need none, and TGT_TokenAbsent and TGT_VolumetricIpTokenAbsent match the token's absence, so without the SDK the latter challenges API and native-app clients",
       "  - TGT_* rules only work properly when Targeted level is deployed AND SDK is integrated")],
     [PROMPT]),

    ("a bot count AWS doesn't state, again",
     [("kb-docs/bot-control.md", "Version_6.1 lists 697 `bot:name:` labels and Version_7.0, the latest static version, lists 701",
       "by 6.1 the Common level identifies more than 600, and Version_7.0 is the latest static version")],
     [KB]),

    ("Targeted without the SDK said to run only Common and ML rules, again",
     [("kb-docs/bot-control.md", "runs the Common rules, the ML rules and the two token-absent rules.",
       "mostly runs the Common rules plus the ML rules.")],
     [KB]),

    ("Fraud Control priced at $1 a request again",
     [("kb-docs/fraud-control-atp-acfp.md", "$1,000 per million ($0.001 a request) for the first 2M", "$1/request for first 2M")],
     [KB]),

    ("ACFP AutomatedBrowser at Block again",
     [("kb-docs/fraud-control-atp-acfp.md", "| `AutomatedBrowser` | `signal:automated_browser` | CAPTCHA |",
       "| `AutomatedBrowser` | `signal:automated_browser` | Block |")],
     [KB]),

    ("CoordinatedActivityLow at Count again",
     [("kb-docs/advanced-bot-detection.md", "- `TGT_ML_CoordinatedActivityLow` → Challenge\n",
       "- `TGT_ML_CoordinatedActivityLow` → Count\n")],
     [KB]),

    ("every TGT_ rule said to need a token again",
     [("kb-docs/bot-control-labels-v5.md", "| Mostly. Five rules \"only apply when the web request has a token\" and the `TGT_TokenReuse*` rules inspect a token's use, but `TGT_TokenAbsent` and `TGT_VolumetricIpTokenAbsent` match its absence |",
       "| Yes — requires AWS WAF token for session tracking |")],
     [KB]),

    ("ASN match unforgeable again",
     [("kb-docs/asn-match.md", "On the source IP, ASN match reads the address the connection comes from, which the client can't set.",
       "ASN match is unforgeable — attackers cannot spoof their ASN.")],
     [KB]),

    ("an IP set or ASN with a forwarded header unforgeable again",
     [("kb-docs/common-patterns.md", " An IP set or ASN match with `ForwardedIPConfig` reads a header instead, which the client can set.", "")],
     [KB]),

    ("crawler ASN unforgeable again",
     [("kb-docs/crawler-seo.md", "- **ASN** of the source IP can't be set by the client", "- **ASN** is unforgeable")],
     [KB]),

    ("COUNT as a top-level log action again",
     [("kb-docs/waf-log-field-availability.md", "- `action` (ALLOW / BLOCK / CHALLENGE / CAPTCHA)", "- `action` (ALLOW / BLOCK / COUNT / CHALLENGE / CAPTCHA)")],
     [KB]),

    ("AMR said to replace the DDoS IP list again",
     [("kb-docs/ip-reputation.md", "the DDoS resiliency whitepaper still recommends the list", "AMR subsumes its functionality")],
     [KB]),

    ("DDoS traffic free in Count too, again",
     [("kb-docs/antiddos-amr.md", "- The same blog says AWS doesn't charge for requests \"detected as DDoS when protection rules are actively mitigating and are NOT in Count mode\". In Count, DDoS traffic is billed like any other",
       "- DDoS traffic detected and mitigated is NOT charged")],
     [KB]),

    ("the ML rules' 3.0 defaults stated for every version again",
     [("kb-docs/advanced-bot-detection.md", "1. `TGT_ML_CoordinatedActivityHigh` at CAPTCHA on Version_3.0 or later → the default, not a misconfiguration. At Count on an unpinned group, Version_1.0 or 2.0 → that version's default, not an override; recommend pinning Version_7.0",
       "1. `TGT_ML_CoordinatedActivityHigh` at default CAPTCHA → not a misconfiguration (default is correct)")],
     [KB]),

    ("the coordinated-activity label CAPTCHA in every version again",
     [("kb-docs/bot-control-labels-v5.md", "CAPTCHA by default from Version_3.0 and Count before it.", "CAPTCHA by default.")],
     [KB]),

    ("a label scope-down called unforgeable again",
     [("kb-docs/bot-control.md", "using a label applied by an earlier Count rule. The label is only as trustworthy as the condition",
       "using an unforgeable label (e.g., a label applied by an earlier Count rule). The label is only as dependable as the condition")],
     [KB]),

    ("JA3/JA4 said to be something AWS is silent on again",
     [("kb-docs/asn-match.md", "AWS's June 2025 launch blog says attackers are \"evading fingerprinting techniques like TLS JA3 through request-level randomization\"",
       "AWS doesn't address it")],
     [KB]),

    ("the Count-mode billing exception dropped",
     [("kb-docs/antiddos-amr.md", ", with one dated exception: from July 27 to October 24, 2026, the Shield Advanced web ACLs AWS auto-enrolled \"don't incur per-request fees or WCU consumption, even when configured in Count mode\" (AWS Security Blog). A rule group you add yourself pays standard pricing from the moment you enable it\n",
       "\n")],
     [KB]),
]

sys.exit(sweep(CASES))
