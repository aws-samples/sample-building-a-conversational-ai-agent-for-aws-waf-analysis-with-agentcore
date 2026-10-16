#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_prompt_aws_facts.py` fail? Each corrected statement put back as it was."""

import sys

from _harness import sweep

T = "tests/test_prompt_aws_facts.py"
A = "agent.py"

CASES = [
    ("Route 53 health checkers as all of 15.177 again",
     [(A, "inside 15.177 only 15.177.0.0/18 and 15.177.108.0/24", "15.177.0.0/16 = Route 53 Health Check")],
     [f"{T}::test_route53_health_checkers_are_named_by_their_real_prefixes_and_their_label"]),

    ("the Anti-DDoS baseline per IP again",
     [(A, "- Anti-DDoS AMR: one traffic baseline per protected resource,", "- Anti-DDoS AMR: per-IP behavior analysis,")],
     [f"{T}::test_the_anti_ddos_baseline_is_per_protected_resource"]),

    ("the knowledge base on per-IP analysis again",
     [("kb-docs/antiddos-amr.md", "- One traffic baseline per protected resource (", "- Per-client-IP behavior analysis (")],
     [f"{T}::test_the_anti_ddos_baseline_is_per_protected_resource"]),

    ("a body scope-down called impossible again",
     [(A, "But the body is never logged, so", "AWS WAF doesn't inspect body for scope-down, so")],
     [f"{T}::test_a_body_scope_down_is_allowed_and_only_unverifiable_from_logs"]),
]

sys.exit(sweep(CASES))
