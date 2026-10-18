"""`evaluate_count_rules` looks for later rules that read a Count rule's labels, and for what a switch
changes. ROADMAP 7.14.

A Count rule whose label a later rule matches is part of a design, often the scope-down this repo's own
false-positive advice recommends: override a sub-rule to Count, block on its label outside the excluded
slice. Switching it to Block ends evaluation there, so the later rule, and every rate-based rule after
it, never sees those requests. And only matches that ended ALLOW change outcome; a match another rule
blocked ends the same way after the switch.

Key semantics, from AWS documentation read 2026-10-18: a key starting `awswaf:` is fully qualified; any
other is resolved in the rule's own context `awswaf:<account>:webacl:<name>:`, so it never reaches a
managed label; a short LABEL key is the end of the label; NAMESPACE matches from the prefix; matching is
case-sensitive. Live on the S3 test WebACL, 2026-10-18, with a temporary rule reading the XSS sub-rule's
label: 160 of the 160 requests that sub-rule counted on 2026-09-08 carry it.
"""

import pytest

from tools import waf_count_eval as C

P = "awswaf:111122223333:webacl:acl:"


@pytest.mark.parametrize("label,scope,key,expected", [
    (P + "test:flag", "LABEL", "flag", True),
    (P + "test:flag", "LABEL", "test:flag", True),
    (P + "test:flag", "LABEL", P + "test:flag", True),
    (P + "ns1:ns2:test:flag", "LABEL", "test:flag", True),          # namespaces between, documented
    (P + "test:flag", "LABEL", "Test:flag", False),                   # case-sensitive
    (P + "test:flagx", "LABEL", "flag", False),
    (P + "test:xflag", "LABEL", "flag", False),                       # whole segments
    ("awswaf:222233334444:webacl:acl:test:flag", "LABEL", "test:flag", False),   # another context
    ("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments", "LABEL",
     "CrossSiteScripting_QueryArguments", False),                     # a short key never reaches managed
    ("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments", "LABEL",
     "awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments", True),
    ("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments", "LABEL",
     "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Query", False),
    ("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments", "NAMESPACE",
     "awswaf:managed:aws:core-rule-set:", True),
    (P + "test:flag", "NAMESPACE", "test:", True),
    (P + "test:flag", "NAMESPACE", P, True),
    (P + "ns1:test:flag", "NAMESPACE", "test:", True),                # a middle run: undocumented, counted
])
def test_label_key_matches(label, scope, key, expected):
    assert C.label_key_matches(label, scope, key, P) is expected


def rule(name, priority, stmt, action="Count", labels=()):
    r = {"Name": name, "Priority": priority, "Statement": stmt, "Action": {action: {}}}
    if labels:
        r["RuleLabels"] = [{"Name": l} for l in labels]
    return r


def match(key, scope="LABEL"):
    return {"LabelMatchStatement": {"Scope": scope, "Key": key}}


CRS = {"Name": "AWS-AWSManagedRulesCommonRuleSet", "Priority": 20, "OverrideAction": {"None": {}},
       "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet",
                     "RuleActionOverrides": [{"Name": "CrossSiteScripting_QUERYARGUMENTS", "ActionToUse": {"Count": {}}}]}}}


def test_a_later_rule_matching_its_label_makes_a_custom_count_rule_by_design():
    rules = [rule("flagger", 10, {"ByteMatchStatement": {}}, labels=["test:flag"]),
             rule("blocker", 30, {"AndStatement": {"Statements": [match("test:flag"), {"NotStatement": {"Statement": {}}}]}}, "Block")]
    assert C.by_design(rules, "flagger", P) == [("blocker", 30, "test:flag")]


def test_a_rule_before_it_cannot_read_its_label():
    rules = [rule("blocker", 5, match("test:flag"), "Block"),
             rule("flagger", 10, {"ByteMatchStatement": {}}, labels=["test:flag"])]
    assert C.by_design(rules, "flagger", P) == []


def test_a_key_for_another_label_is_not_a_reader():
    rules = [rule("flagger", 10, {"ByteMatchStatement": {}}, labels=["test:flag"]),
             rule("other", 30, match("test:other"), "Block")]
    assert C.by_design(rules, "flagger", P) == []


@pytest.mark.parametrize("where", [
    lambda m: m,
    lambda m: {"NotStatement": {"Statement": m}},
    lambda m: {"OrStatement": {"Statements": [{"ByteMatchStatement": {}}, m]}},
    lambda m: {"RateBasedStatement": {"Limit": 100, "AggregateKeyType": "IP", "ScopeDownStatement": m}},
    lambda m: {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": "AWSManagedRulesBotControlRuleSet",
                                             "ScopeDownStatement": m}},
])
def test_a_label_match_is_found_wherever_it_sits(where):
    rules = [rule("flagger", 10, {"ByteMatchStatement": {}}, labels=["test:flag"]),
             rule("reader", 30, where(match("test:flag")))]
    assert [n for n, _, _ in C.by_design(rules, "flagger", P)] == ["reader"]


def test_a_managed_sub_rule_is_positioned_at_its_group():
    rules = [CRS, rule("xss-blocker", 30, match("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments"), "Block"),
             rule("early", 1, match("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments"))]
    readers = C.label_readers(rules, "CrossSiteScripting_QUERYARGUMENTS")
    assert [r[0] for r in readers] == ["xss-blocker"], readers


def test_a_rule_the_configuration_does_not_name_is_read_by_every_label_match():
    """`TGT_TokenAbsent` counts by default, so no override names it and its position is unknown."""
    rules = [rule("early", 5, match("awswaf:managed:token:absent")), CRS,
             rule("token-blocker", 30, match("awswaf:managed:token:absent"), "Block")]
    assert [r[0] for r in C.label_readers(rules, "TGT_TokenAbsent")] == ["early", "token-blocker"]


def test_a_key_outside_waf_charset_is_not_queried():
    rules = [rule("flagger", 10, {}, labels=["a"]), rule("reader", 30, match("a' or 1=1"))]
    assert C.label_readers(rules, "flagger") == []


def test_the_prefix_comes_from_the_selected_webacl(monkeypatch):
    monkeypatch.setattr(C, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr("tools.session_state.get_webacl_arn",
                        lambda: "arn:aws:wafv2:us-east-1:111122223333:global/webacl/acl/0123")
    assert C.label_prefix() == P


# --- the inventory ---------------------------------------------------------------------------------

@pytest.fixture
def inventory(monkeypatch):
    def run(rules, counted):
        monkeypatch.setattr(C, "get_webacl_name", lambda: "acl")
        monkeypatch.setattr(C, "get_scope", lambda: "CLOUDFRONT")
        monkeypatch.setattr(C, "resolve_region", lambda scope: "us-east-1")
        monkeypatch.setattr(C, "get_client", lambda svc, **k: object())
        monkeypatch.setattr(C, "_get_webacl_rules", lambda region, scope: rules)
        monkeypatch.setattr(C, "label_prefix", lambda: P)
        monkeypatch.setattr("tools.waf_patrol._get_all_rules_metrics_search",
                            lambda *a, **k: {r: {"counted": [n], "timestamps": ["2026-10-01 00:00"]} for r, n in counted.items()})
        monkeypatch.setattr("tools.waf_metrics.rule_blocked_per_metrics", lambda *a, **k: (0, ""))
        monkeypatch.setattr("tools.waf_metrics.summed_sub_rules", lambda *a, **k: (set(), ""))
        return C._step_init()
    return run


def test_the_inventory_keeps_a_rule_a_later_rule_reads(inventory):
    rules = [rule("flagger", 10, {"ByteMatchStatement": {}}, labels=["test:flag"]),
             rule("blocker", 30, match("test:flag"), "Block")]
    out = inventory(rules, {"flagger": 0})
    keep = out.split("### Keep in Count by design", 1)[1].split("###", 1)[0]
    assert "flagger — read by blocker (priority 30, key test:flag)" in keep, out
    assert "flagger — 0 hits in 14 days, safe to switch" not in out, out


def test_a_zero_hit_sub_rule_a_later_rule_may_read_is_not_called_safe(inventory):
    rules = [CRS, rule("xss-blocker", 30, match("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments"), "Block")]
    out = inventory(rules, {"CrossSiteScripting_QUERYARGUMENTS": 0})
    assert "CrossSiteScripting_QUERYARGUMENTS — 0 hits in 14 days, safe to switch" not in out, out
    section = out.split("### Later rules that read managed labels", 1)[1]
    assert "CrossSiteScripting_QUERYARGUMENTS (0 hits): xss-blocker" in section and "Not safe" in section, out


def test_the_control_with_no_reader_a_zero_hit_rule_is_still_safe(inventory):
    out = inventory([CRS], {"CrossSiteScripting_QUERYARGUMENTS": 0})
    assert "CrossSiteScripting_QUERYARGUMENTS — 0 hits in 14 days, safe to switch" in out, out


# --- check_low_volume_clients ----------------------------------------------------------------------

@pytest.fixture
def clients(monkeypatch):
    def run(rules, replies, fail_rules=False, count_rule="CrossSiteScripting_QUERYARGUMENTS"):
        monkeypatch.setattr(C, "_has_logging", lambda: True)
        monkeypatch.setattr("tools.waf_query.check_coarse_partition_block", lambda: None)
        monkeypatch.setattr(C, "get_scope", lambda: "CLOUDFRONT")
        monkeypatch.setattr(C, "resolve_region", lambda scope: "us-east-1")
        monkeypatch.setattr(C, "get_webacl_name", lambda: "acl")
        monkeypatch.setattr(C, "label_prefix", lambda: P)

        def acl(region, scope):
            if fail_rules:
                raise RuntimeError("AccessDeniedException: wafv2:GetWebACL")
            return rules
        monkeypatch.setattr(C, "_get_webacl_rules", acl)
        monkeypatch.setattr(C, "_count_rule_matches", lambda *a: None)
        sent = []

        def q(cwl, athena, s, e, limit=25):
            sent.append((cwl, athena))
            for marker, rows in replies.items():
                if marker in cwl:
                    return rows
            return []
        monkeypatch.setattr(C, "query_logs", q)
        monkeypatch.setattr("tools.waf_query.sample_inspection_content", lambda *a, **k: (None, None, False))
        monkeypatch.setattr(C, "_count_match_details", lambda *a: ([], None))
        return C._step_check_clients(count_rule, "2026-09-08T03:00", 60), sent
    return run


READER = rule("xss-blocker", 30, match("awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments"), "Block")


def test_the_requests_a_later_rule_reads_are_counted(clients):
    out, sent = clients([CRS, READER], {"as total": [{"total": "160", "l0": "160"}],
                                        "by action": [{"action": "ALLOW", "n": "160"}]})
    section = out.split("### Later rules that read labels these requests carry", 1)[1].split("###", 1)[0]
    assert "xss-blocker (priority 30, LABEL awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments): " \
           "160 of the 160 requests" in section and "scope-down design" in section, section
    cwl, athena = next(t for t in sent if "as total" in t[0])
    assert 'lbls like /"name":"awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments"/' in cwl, cwl
    assert "regexp_like(l.name, '^awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments$')" in athena, athena


def test_an_unplaced_rule_is_checked_against_every_reader_and_says_why(clients):
    blocker = rule("token-blocker", 30, match("awswaf:managed:token:absent"), "Block")
    out, sent = clients([CRS, blocker], {"as total": [{"total": "50", "l0": "50"}],
                                         "by action": [{"action": "ALLOW", "n": "50"}]}, count_rule="TGT_TokenAbsent")
    section = out.split("### Later rules that read labels these requests carry", 1)[1].split("###", 1)[0]
    assert "no rule after this one matches" not in section, section
    assert "TGT_TokenAbsent is not named in the WebACL's configuration" in section, section
    assert "token-blocker (priority 30, LABEL awswaf:managed:token:absent): 50 of the 50 requests" in section, section


def test_a_placed_rule_does_not_say_its_position_is_unknown(clients):
    out, _ = clients([CRS, READER], {"as total": [{"total": "1", "l0": "1"}], "by action": [{"action": "ALLOW", "n": "1"}]})
    assert "is not named in the WebACL's configuration" not in out, out


def test_with_no_reader_the_section_says_so_and_queries_nothing(clients):
    out, sent = clients([CRS], {"by action": [{"action": "ALLOW", "n": "5"}]})
    assert "(none: no rule after this one matches on a label)" in out
    assert not any("as total" in c for c, _ in sent)


def test_a_failed_rules_read_is_not_a_clean_answer(clients):
    out, _ = clients([], {"by action": [{"action": "ALLOW", "n": "5"}]}, fail_rules=True)
    assert "UNKNOWN: the WebACL's rules could not be read" in out and "Do not recommend Block" in out, out


def test_only_matches_that_ended_allowed_change_outcome(clients):
    out, sent = clients([CRS], {"by action": [{"action": "ALLOW", "n": "40"}, {"action": "BLOCK", "n": "120"}]})
    assert "160 requests counted, 40 of them allowed in the end" in out and "BLOCK 120" in out, out
    tables = [c for c, _ in sent if "by httpRequest.clientIp" in c]
    assert tables and all("and action = 'ALLOW'" in c for c in tables), tables


def test_every_match_stopped_elsewhere_is_named_not_read_as_missing_logs(clients):
    out, _ = clients([CRS], {"by action": [{"action": "BLOCK", "n": "12"}]})
    assert "every request it counted was already stopped by another rule" in out
    assert "check if Log Filter drops COUNT logs" not in out, out
