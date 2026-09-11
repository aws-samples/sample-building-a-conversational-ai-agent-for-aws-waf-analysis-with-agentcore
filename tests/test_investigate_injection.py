# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.3: the playbook's JUDGMENT moved into code, not just its sequence.

4.3 names the way to get this wrong: delete the six prompt steps, leave the step-6 classification
matrix and the injection confidence language behind, and ship the orchestration with none of the
reasoning. Nothing about the tool existing proves the judgment came with it, so that is what most
of this file asserts, and it asserts it against the prompt's absence as well as the code's
presence -- either half alone is satisfied by the state 4.3 warns about.

**The two defects found by running it live, both of which produced a finished-looking answer:**

1. **Step 1 ranked by config order, not by blocks.** `targets[0]` was the first injection rule in
   the WebACL, which on the live account was `KnownBadInputsRuleSet` with zero activity, while the
   SQLi set had the blocks. Four sections printed "0 results" and the assessment ran on no
   evidence. The design said "top blocking injection rule"; config order is not a ranking.
2. **No-evidence classified as no-JA4.** With nothing matched at all, `_classify` answered
   "unknown, no JA4 data", which points the reader at field availability when the truth is that
   nothing matched. Different cause, different next action.
"""

import json

import pytest

import agent
from tools import waf_injection as I


# --- which rules do injection detection, read rather than guessed ------------

def _rule(name, statement):
    return {"Name": name, "Statement": statement}


SQLI = {"SqliMatchStatement": {"FieldToMatch": {"AllQueryArguments": {}}}}
XSS = {"XssMatchStatement": {"FieldToMatch": {"Body": {}}}}
BYTES = {"ByteMatchStatement": {"SearchString": "x"}}


def test_a_custom_rule_is_classified_by_its_statement_not_its_name():
    """The whole reason this reads the WebACL instead of pattern-matching names.

    Both directions are wrong under a name pattern, and both are represented here: a rule doing
    SQLi detection under a name that says nothing, and a rule whose name says SQLi while it does
    something else. A name pattern gets both backwards, and the second is the dangerous one --
    investigating an allowlist as though it were a detector."""
    found, _ = I._injection_rules([
        _rule("block-bad-stuff", SQLI),
        _rule("sqli-allowlist", BYTES),
        _rule("xss-guard", XSS),
    ])
    assert found == ["block-bad-stuff", "xss-guard"], found


@pytest.mark.parametrize("wrapper,build", [
    ("AndStatement", lambda s: {"AndStatement": {"Statements": [BYTES, s]}}),
    ("OrStatement", lambda s: {"OrStatement": {"Statements": [s]}}),
    ("NotStatement", lambda s: {"NotStatement": {"Statement": s}}),
    ("RateBasedStatement scope-down",
     lambda s: {"RateBasedStatement": {"Limit": 100, "ScopeDownStatement": s}}),
    ("nested two deep",
     lambda s: {"AndStatement": {"Statements": [{"OrStatement": {"Statements": [s]}}]}}),
])
def test_a_nested_injection_statement_is_found(wrapper, build):
    """A top-level-only check misses exactly the rules worth finding.

    A tuned injection rule is written as SQLi detection AND a path condition, so the interesting
    case is always nested. Swept over every combinator WAF allows rather than one example, because
    the defect is one missing branch in the recursion and a single example finds that by luck."""
    found, _ = I._injection_rules([_rule("tuned", build(SQLI))])
    assert found == ["tuned"], f"{wrapper} hid the injection statement"


def test_a_rule_group_that_cannot_be_read_is_named_rather_than_dropped():
    """**"No injection rules" and "rules I could not classify" are different answers.**

    A customer-owned rule group's contents are not in `get_web_acl`'s response, so whether it does
    injection detection cannot be read without another call per group. Dropping it would make an
    unknown look like an absence, and only one of those means stop looking."""
    found, unknown = I._injection_rules([
        _rule("mine", {"RuleGroupReferenceStatement": {"ARN": "arn:aws:wafv2:::rulegroup/x"}}),
    ])
    assert found == []
    assert len(unknown) == 1 and "mine" in unknown[0], unknown
    assert "not inspected" in unknown[0].lower(), unknown


@pytest.mark.parametrize("group,expected", [
    ("AWSManagedRulesSQLiRuleSet", True),
    ("AWSManagedRulesCommonRuleSet", True),
    ("AWSManagedRulesKnownBadInputsRuleSet", True),
    ("AWSManagedRulesAmazonIpReputationList", False),
    ("AWSManagedRulesBotControlRuleSet", False),
])
def test_managed_groups_are_matched_by_name_and_only_the_injection_ones(group, expected):
    """Managed groups are matched by name because the sub-rule names inside are AWS's own, so this
    is a documented set rather than a guess at a customer's naming. The negative cases matter as
    much: an IP reputation list is not injection detection, and treating it as one would send the
    investigation at the wrong rule."""
    found, _ = I._injection_rules([
        _rule("r", {"ManagedRuleGroupStatement": {"Name": group, "VendorName": "AWS"}})])
    assert bool(found) is expected, f"{group} classified as injection={bool(found)}"


# --- the step-6 matrix, which 4.3 requires to be in code --------------------

def test_the_classification_matrix_is_in_code_and_covers_every_branch():
    """The prompt's three outcomes, as code, plus the two the prompt did not have.

    4.3's condition for deleting the playbook is that this matrix moved, so each branch is asserted
    on the returned classification rather than on the tool merely running."""
    many_ips = [f"10.0.0.{i}" for i in range(8)]
    assert "distributed bot" in I._classify(many_ips, ["ja4a"])[0]
    assert "concentrated" in I._classify(["10.0.0.1"], ["ja4a"])[0]
    assert "probing" in I._classify(many_ips, ["ja4a", "ja4b", "ja4c"])[0]


def test_no_evidence_is_not_reported_as_missing_ja4():
    """**Found by running it live.** With nothing matched, the first version answered "unknown, no
    JA4 data", which sends the reader after field availability when the truth is that nothing
    matched. The two need different next actions, so they are different branches."""
    nothing = I._classify([], [])
    absent_ja4 = I._classify(["10.0.0.1"], [])
    assert "no evidence" in nothing[0], nothing
    assert "Widen the window" in nothing[1], nothing
    assert "no JA4" in absent_ja4[0], absent_ja4
    assert nothing[0] != absent_ja4[0], "no data and no JA4 field classify identically"


def test_a_missing_ja4_field_does_not_read_as_one_shared_fingerprint():
    """JA4 is absent entirely on API Gateway and AppSync, so an empty fingerprint set and a single
    shared fingerprint are different worlds. Under the prompt's three-outcome matrix both counted
    as "same JA4" and classified as a distributed bot, which is a verdict built on a missing
    field."""
    many_ips = [f"10.0.0.{i}" for i in range(8)]
    assert "distributed bot" not in I._classify(many_ips, [])[0]
    assert "distributed bot" in I._classify(many_ips, ["ja4a"])[0]


# --- the confidence boundary, the other half 4.3 requires -------------------

def test_the_confidence_boundary_is_in_code_and_says_what_logs_cannot_show():
    """The half most easily left behind, because the tool works without it.

    Asserted on content rather than on the constant existing: the point is that the output refuses
    to claim an exploit succeeded and names what evidence would be needed instead."""
    assert "never a confirmed exploit" in I.CONFIDENCE
    for needed in ("origin logs", "response codes", "application errors"):
        assert needed in I.CONFIDENCE, f"the boundary does not say {needed} would be needed"


def test_the_prompt_no_longer_carries_the_playbook_it_replaced():
    """**The other half of 4.3's condition, and the half a code-only test cannot see.**

    Leaving the six steps in the prompt beside the tool is not harmless: the model would have two
    methods for one question and no reason to prefer the one whose sequence is enforced. So the
    inline steps have to be gone, the tool has to be routed, and the reason has to be stated, since
    a bare pointer invites hand-assembly from the generic tools again."""
    prompt = agent._build_system_prompt(9)
    assert "investigate_injection" in prompt
    section = prompt.split("## Injection Attack Investigation")[1].split("\n## ")[0]
    for step in ("rule_uri_prefix", "top_ua_by_action", "rule_block_top_ips"):
        assert step not in section, f"the old playbook step {step} is still in the prompt"
    assert "Do NOT hand-assemble" in section, section
    # The matrix must not be left in the prompt either: duplicated judgment drifts from the code's.
    assert "same JA4" not in section, "the classification matrix is still in the prompt"


def test_the_tool_is_registered_and_reachable():
    assert "investigate_injection" in {t.tool_name for t in agent._TOOLS}


# --- the sequence is code-mandatory, which is the point of the tool ---------

def test_every_data_step_goes_through_the_primitive():
    """**Reuse, don't fork**, which 4.3 lists first among its caveats. Steps 2-4 must route through
    `aggregate_logs` so redaction, partition pruning, the window cap and WebACL scoping stay intact,
    and step 5 must call `analyze_ip` rather than reimplementing the NAT check, the labels and the
    JA4 lookup.

    Structural, because a behavioural test would only cover the paths someone remembered, and the
    failure being guarded against is a fifth step added later that queries directly."""
    import ast
    import pathlib
    src = pathlib.Path(I.__file__).read_text()
    tree = ast.parse(src)
    called = {n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "query_logs" not in called, \
        "a data step bypasses aggregate_logs, losing redaction and partition pruning"
    assert "aggregate_logs" in src and "analyze_ip" in src
    # The profiling step is the one a prompt-driven sequence drops, so its call must be
    # unconditional on having an IP rather than suggested in the output.
    assert "analyze_ip._tool_func" in src, "the source profile is not run in code"


def test_the_output_points_at_record_finding():
    """Every other scenario tool ends by offering to record what it found; the prompt playbook had
    no such step, so injection findings were the ones that did not reach the report."""
    import pathlib
    assert "record_finding(" in pathlib.Path(I.__file__).read_text()
