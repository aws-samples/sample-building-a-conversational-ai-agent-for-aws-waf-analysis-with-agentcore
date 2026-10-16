# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Three statements about AWS in the system prompt that AWS contradicts.

- Route 53 health checkers: `ip-ranges.json` (createDate 2026-10-16-06-27-06) lists 31
  `ROUTE53_HEALTHCHECKS` prefixes, and inside 15.177 only `15.177.0.0/18` and `15.177.108.0/24`;
  the rest of 15.177 includes EC2, which anyone can rent. The prompt said `15.177.0.0/16`.
- Anti-DDoS AMR: the developer guide and the DDoS resiliency whitepaper say it "establishes
  baselines for each protected resource", "within minutes"; the June 2025 launch blog says it
  "profiles your traffic within 15 minutes". The prompt and the knowledge base said per-IP
  behaviour analysis.
- Scope-down: "You can use any nestable rule in a scope-down statement", and Body and JsonBody are
  ordinary request components with required oversize handling. What holds is that WAF logs never
  contain the body, so a body-based scope-down cannot be checked against them.
"""

import pathlib

import agent

ROOT = pathlib.Path(__file__).resolve().parents[1]
P = agent.SYSTEM_PROMPT
KB_AMR = (ROOT / "kb-docs" / "antiddos-amr.md").read_text()


def test_route53_health_checkers_are_named_by_their_real_prefixes_and_their_label():
    assert "15.177.0.0/16" not in P
    assert "15.177.0.0/18" in P and "15.177.108.0/24" in P and "ip-ranges.json" in P
    assert "bot:name:route53_health_check" in P


def test_the_anti_ddos_baseline_is_per_protected_resource():
    for text in (P, KB_AMR):
        assert "per-IP behavior analysis" not in text and "Per-client-IP behavior analysis" not in text
    assert "per protected resource" in P and "per protected resource" in KB_AMR


def test_a_body_scope_down_is_allowed_and_only_unverifiable_from_logs():
    assert "doesn't inspect body for scope-down" not in P
    assert "body is never logged" in P
