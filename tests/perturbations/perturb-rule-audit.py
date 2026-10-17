#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_rule_audit_goes_to_reviewer.py` fail? The routing and each corrected statement put
back as it was."""

import sys

from _harness import sweep

T = "tests/test_rule_audit_goes_to_reviewer.py"
KB = f"{T}::test_the_knowledge_base_carries_the_corrected_statement"

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
]

sys.exit(sweep(CASES))
