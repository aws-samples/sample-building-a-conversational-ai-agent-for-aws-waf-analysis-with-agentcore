#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.3: break each property `test_investigate_injection.py` claims and require it to notice.

Same contract as the other runners: `ast.parse`, reachability probe, real edit, pytest tail read as
well as exit code. `TEXTUAL` marks a target read from source rather than executed.
"""

import sys

from _harness import sweep

T = "tests/test_investigate_injection.py"
TEXTUAL = "textual"
CASES = [
    (
        "classification by rule NAME instead of statement type",
        "tools/waf_injection.py",
        "        if _has_injection_statement(stmt):",
        '        if "sqli" in name.lower() or "xss" in name.lower():',
        [f"{T}::test_a_custom_rule_is_classified_by_its_statement_not_its_name"],
    ),
    (
        "the statement walk stops at the top level, missing every tuned rule",
        "tools/waf_injection.py",
        '    for key in ("AndStatement", "OrStatement"):\n'
        "        if key in stmt:\n"
        "            if any(_has_injection_statement(sub) for sub in stmt[key].get(\"Statements\", [])):\n"
        "                return True",
        "    pass",
        [f"{T}::test_a_nested_injection_statement_is_found"],
    ),
    (
        "descending into NotStatement, i.e. an allowlist classified as a detector",
        "tools/waf_injection.py",
        '    if "RateBasedStatement" in stmt:',
        '    if "NotStatement" in stmt:\n'
        '        return _has_injection_statement(stmt["NotStatement"].get("Statement", {}))\n'
        '    if "RateBasedStatement" in stmt:',
        [f"{T}::test_an_inverted_injection_statement_is_not_a_detector"],
    ),
    (
        "the Allow exclusion dropped, so an allowlist can still be a detector",
        "tools/waf_injection.py",
        '        if "Allow" in (rule.get("Action") or {}):\n            continue',
        "        pass",
        [f"{T}::test_an_allow_rule_is_never_a_detector_whatever_its_shape"],
    ),
    (
        "ranking by row order again, i.e. the defect that reached production",
        "tools/waf_injection.py",
        "    return [name for name, _ in sorted(pairs, key=lambda p: p[1], reverse=True)]",
        "    return [name for name, _ in pairs]",
        [f"{T}::test_the_busiest_injection_rule_is_chosen_by_count_not_by_row_order"],
    ),
    (
        "an unparseable count dropping the rule instead of ranking it last",
        "tools/waf_injection.py",
        "        except (TypeError, ValueError):\n            out.append((value, 0))",
        "        except (TypeError, ValueError):\n            pass",
        [f"{T}::test_an_unparseable_count_ranks_last_rather_than_vanishing"],
    ),
    (
        "the rate-based scope-down branch dropped",
        "tools/waf_injection.py",
        '    if "RateBasedStatement" in stmt:\n'
        '        return _has_injection_statement(stmt["RateBasedStatement"].get("ScopeDownStatement", {}))',
        "    pass",
        [f"{T}::test_a_nested_injection_statement_is_found"],
    ),
    (
        "an unreadable rule group dropped instead of named",
        "tools/waf_injection.py",
        '        elif "RuleGroupReferenceStatement" in stmt:',
        "        elif False:",
        [f"{T}::test_a_rule_group_that_cannot_be_read_is_named_rather_than_dropped"],
    ),
    (
        "a non-injection managed group treated as injection",
        "tools/waf_injection.py",
        '_INJECTION_GROUPS = (\n    "AWSManagedRulesSQLiRuleSet",',
        '_INJECTION_GROUPS = (\n    "AWSManagedRules",',
        [f"{T}::test_managed_groups_are_matched_by_name_and_only_the_injection_ones"],
    ),
    (
        "no-evidence collapsed back into the no-JA4 branch",
        "tools/waf_injection.py",
        "    if not ip_rows:",
        "    if False:",
        [f"{T}::test_no_evidence_is_not_reported_as_missing_ja4"],
    ),
    (
        "a missing JA4 field reading as one shared fingerprint",
        "tools/waf_injection.py",
        "    if not ja4s:",
        "    if False and not ja4s:",
        [f"{T}::test_a_missing_ja4_field_does_not_read_as_one_shared_fingerprint",
         f"{T}::test_no_evidence_is_not_reported_as_missing_ja4"],
    ),
    (
        "the distributed-bot branch removed from the matrix",
        "tools/waf_injection.py",
        "    if ips >= 5 and len(ja4s) == 1:",
        "    if False:",
        [f"{T}::test_the_classification_matrix_is_in_code_and_covers_every_branch"],
    ),
    (
        "the confidence boundary stops naming what evidence would be needed",
        "tools/waf_injection.py",
        '    "got through, that requires origin logs, response codes or application errors, and you should "\n'
        '    "ask for them rather than infer it here."',
        '    "got through, ask for more evidence."',
        [f"{T}::test_the_confidence_boundary_is_in_code_and_says_what_logs_cannot_show"],
        TEXTUAL,
    ),
    (
        "the boundary softened into a claim WAF logs cannot support",
        "tools/waf_injection.py",
        '"attack-pattern assessment, never a confirmed exploit. If you need to know whether anything "',
        '"attack-pattern assessment. If you need to know whether anything "',
        [f"{T}::test_the_confidence_boundary_is_in_code_and_says_what_logs_cannot_show"],
        TEXTUAL,
    ),
    (
        "the old playbook left in the prompt beside the tool",
        "agent.py",
        "Do NOT hand-assemble this from get_waf_overview and run_logs_query.",
        "1. run_logs_query(query_type='rule_uri_prefix', rule_name='<top blocking rule>')\n"
        "2. run_logs_query(query_type='top_ua_by_action')\n"
        "3. run_logs_query(query_type='rule_block_top_ips', rule_name='<rule>')\n"
        "Many IPs + same JA4 → distributed bot.",
        [f"{T}::test_the_prompt_no_longer_carries_the_playbook_it_replaced"],
        TEXTUAL,
    ),
    (
        "the source profile suggested instead of run",
        "tools/waf_injection.py",
        "                  analyze_ip._tool_func(ips[0], start_time, duration), \"\"]",
        "                  f\"Call analyze_ip(ip='{ips[0]}') next.\", \"\"]",
        [f"{T}::test_every_data_step_goes_through_the_primitive"],
        TEXTUAL,
    ),
    (
        "a data step bypassing the primitive",
        "tools/waf_injection.py",
        "    paths = _agg(group_by=\"uri\", filter_by=blocked)",
        "    from tools.waf_query import query_logs\n"
        "    paths = str(query_logs('a', 'b', 0, 1))",
        [f"{T}::test_every_data_step_goes_through_the_primitive"],
        TEXTUAL,
    ),
    (
        "the record_finding pointer dropped, so findings never reach the report",
        "tools/waf_injection.py",
        "f\"Next: call record_finding(title='Injection activity on {focus}', \"",
        "f\"Done. \"",
        [f"{T}::test_the_output_points_at_record_finding"],
        TEXTUAL,
    ),
]

# A case with no marker gets the reachability probe: the anchor is replaced with a bare raise
# and the targets must go red, or the line never executes and a green result from the real
# perturbation below would say nothing. A marker means the target reads source rather than
# running it, or that reachability is established elsewhere; each one says which in a comment.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
