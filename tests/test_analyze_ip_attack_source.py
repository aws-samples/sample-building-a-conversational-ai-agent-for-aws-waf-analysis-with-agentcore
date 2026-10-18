"""`analyze_ip` names an attack source, counted by attack category. ROADMAP 7.14.

Its verdict ladder ranked bot behaviour only, and its URI count did not filter on action, so a scanner
that probed more than 50 paths was "Probable crawler/scraper" and one at speed "Automated scraper". The
rung added first counts the categories of what blocked the IP (SQL injection, path probing, ...), not
WebACL rule names: a rate limit, a reputation list or Bot Control says nothing about what a request
carried, and one managed group holds several categories. The bot rungs after it leave those blocks out.

Measured 2026-09-08 on the S3 test WebACL: each of 10 scanners took 12 SQL-injection blocks on 2 paths
and one path-probing block against 3 allowed; the false-positive user there took 2 SQL-injection blocks
on 1 path against 35 allowed. Both shapes are fixtures here.
"""

import pytest

from tools import waf_injection as I
from tools import waf_logs as L
from tools import waf_query as WQ

ROW = {"action": "ALLOW", "terminatingRuleId": "r", "cnt": "9", "avg_rpm": "1", "peak_rpm": "1",
       "active_minutes": "1", "ja4Fingerprint": "t13d1516h2", "unique_uris": "1",
       "total_non_static": "1", "args": "?a=1", "hits": "1"}


def managed(group, sub, n, rule=None, uris=1):
    return {"terminatingRuleType": "MANAGED_RULE_GROUP", "terminatingRuleId": rule or f"AWS-{group}",
            "rgid": f"AWS#{group}", "sub_rule": sub, "n": str(n), "uris": str(uris)}


def custom(rule, n, rgid="", sub="", uris=1):
    return {"terminatingRuleType": "REGULAR", "terminatingRuleId": rule, "rgid": rgid, "sub_rule": sub, "n": str(n),
            "uris": str(uris)}


SQLI = managed("AWSManagedRulesSQLiRuleSet", "SQLi_QUERYARGUMENTS", 12, uris=2)
PROBE = managed("AWSManagedRulesKnownBadInputsRuleSet", "ExploitablePaths_URIPATH", 1)
RATE = {"terminatingRuleType": "RATE_BASED", "terminatingRuleId": "rate-limit", "n": "5000"}
REPUTATION = managed("AWSManagedRulesAmazonIpReputationList", "AWSManagedIPReputationList", 40)
# A crawler's numbers, which the bot rungs would name if nothing came first.
SCRAPER = {"request_rate_dynamic": [{"peak_rpm": "300"}], "uri_diversity": [{"unique_uris": "80", "total_non_static": "900"}]}
HAMMER = {"request_rate_dynamic": [{"peak_rpm": "300"}], "uri_diversity": [{"unique_uris": "1", "total_non_static": "900"}]}


class FakeWaf:
    def __init__(self, rules, fails=False):
        self.rules, self.fails, self.reads = rules, fails, 0

    def list_web_acls(self, Scope):
        return {"WebACLs": [{"Name": "acl", "Id": "id1"}]}

    def get_web_acl(self, Name, Scope, Id):
        self.reads += 1
        if self.fails:
            raise RuntimeError("AccessDeniedException: wafv2:GetWebACL")
        return {"WebACL": {"Rules": self.rules}}


def _run(monkeypatch, blocks, allowed=0, waf=None, extra=None, fail=(), truncated=False):
    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: None)
    monkeypatch.setattr("tools.session_state.get_webacl_name", lambda: "acl")
    waf = waf or FakeWaf([], fails=True)
    monkeypatch.setattr("tools.aws_session.get_client", lambda svc, **k: waf)
    seen = {}

    def q(cwl, athena, start, end, limit=25, notes=None, label="", **kw):
        seen[label] = (cwl, athena)
        if label in fail:
            raise RuntimeError(f"{label} query timed out")
        if label == "diversity":
            return [{"ua_count": "1", "ja4_count": "1", "total": "900"}]
        if label == "attack_categories":
            if truncated and notes is not None:
                notes[label] = 100
            return blocks
        if label == "allowed":
            return [{"n": str(allowed)}]
        if extra and label in extra:
            return extra[label]
        return [dict(ROW)]
    monkeypatch.setattr(WQ, "query_logs", q)
    out = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    assert "## Assessment" in out, out
    return out.split("## Assessment", 1)[1], out, seen, waf


def test_the_scanner_is_an_attack_source_before_it_is_a_scraper(monkeypatch):
    verdict, *_ = _run(monkeypatch, [SQLI, PROBE], allowed=3, extra=SCRAPER)
    assert "Attack source or scanner" in verdict and "scraper" not in verdict, verdict
    assert "SQL injection 12, path probing 1" in verdict and "13 blocked requests against 3 allowed" in verdict, verdict


def test_without_its_one_path_probe_it_is_not(monkeypatch):
    """The margin is one request: the scanners' second category rests on a single block."""
    verdict, *_ = _run(monkeypatch, [SQLI], allowed=3)
    assert "Attack source" not in verdict, verdict


def test_the_false_positive_user_is_not_an_attack_source(monkeypatch):
    verdict, *_ = _run(monkeypatch, [managed("AWSManagedRulesSQLiRuleSet", "SQLi_QUERYARGUMENTS", 2)], allowed=35)
    assert "Attack source" not in verdict, verdict


def test_two_categories_on_one_path_are_not_an_attack_source(monkeypatch):
    """A CMS whose every save trips SQL injection and XSS, with almost nothing allowed: two categories,
    a majority of blocks, one path. Summed, the two categories' paths would make two."""
    sqli = managed("AWSManagedRulesSQLiRuleSet", "SQLi_BODY", 40)
    xss = managed("AWSManagedRulesCommonRuleSet", "CrossSiteScripting_BODY", 40)
    verdict, out, *_ = _run(monkeypatch, [sqli, xss], allowed=0)
    assert "Attack source" not in verdict, verdict
    assert "SQL injection 40 on 1 path, cross-site scripting 40 on 1 path" in out, out


def test_a_category_of_several_sub_rules_names_its_widest_and_counts_only_that(monkeypatch):
    """The block query groups by sub-rule, so two SQL-injection sub-rules on one path each read as one
    path, not two. That only makes the rung harder to reach, and the output says which number it is."""
    qa = managed("AWSManagedRulesSQLiRuleSet", "SQLi_QUERYARGUMENTS", 20)
    body = managed("AWSManagedRulesSQLiRuleSet", "SQLi_BODY", 20)
    xss = managed("AWSManagedRulesCommonRuleSet", "CrossSiteScripting_BODY", 1)
    verdict, out, *_ = _run(monkeypatch, [qa, body, xss], allowed=0)
    assert "SQL injection 40 (the widest of its 2 rules on 1 path), cross-site scripting 1 on 1 path" in out, out
    assert "Attack source" not in verdict, verdict


def test_the_paths_are_read_on_both_engines(monkeypatch):
    *_, seen, _ = _run(monkeypatch, [SQLI, PROBE], allowed=3)
    cwl, athena = seen["attack_categories"]
    assert "count_distinct(httpRequest.uri) as uris" in cwl and "count(DISTINCT httprequest.uri) as uris" in athena


def test_two_categories_need_more_blocks_than_allowed_requests(monkeypatch):
    verdict, *_ = _run(monkeypatch, [SQLI, PROBE], allowed=13)
    assert "Attack source" not in verdict, verdict


def test_two_categories_on_the_floor_are_likely_not_certain(monkeypatch):
    """The scanners sat exactly on the floor, 2 categories and 2 paths, in one sample from one script."""
    verdict, *_ = _run(monkeypatch, [SQLI, PROBE], allowed=3)
    assert "**LIKELY: Attack source or scanner.**" in verdict and "HIGH CONFIDENCE" not in verdict, verdict
    assert "one rule's blocks on 2 paths" in verdict, verdict
    assert "2 attack categories is the floor for this verdict, and 2 paths is its floor too." in verdict, verdict
    assert "Ask the user whether the blocked requests are their own application's" in verdict, verdict


def test_two_categories_on_many_paths_do_not_say_the_paths_are_on_the_floor(monkeypatch):
    """LIKELY holds for any two categories; the sentence was written for the scanners' 2 paths and said
    "the floor ... 2 paths" of 40."""
    wide = managed("AWSManagedRulesSQLiRuleSet", "SQLi_QUERYARGUMENTS", 300, uris=40)
    verdict, *_ = _run(monkeypatch, [wide, PROBE], allowed=3)
    assert "**LIKELY: Attack source or scanner.**" in verdict and "one rule's blocks on 40 paths" in verdict, verdict
    assert "2 attack categories is the floor for this verdict." in verdict and "floor too" not in verdict, verdict


def test_an_unknown_rule_names_its_sub_rules(monkeypatch):
    a = {**managed("x", "SQLi_BODY", 20, uris=3), "rgid": "Fortinet#WebExploits", "terminatingRuleId": "fortinet"}
    b = {**a, "sub_rule": "XSS_BODY", "uris": "1"}
    _, out, *_ = _run(monkeypatch, [SQLI, a, b], allowed=3)
    assert "category unknown: fortinet, 40 blocks (the widest of its 2 sub-rules on 3 paths)" in out, out


def test_three_categories_are_high_confidence(monkeypatch):
    xss = managed("AWSManagedRulesCommonRuleSet", "CrossSiteScripting_BODY", 1)
    verdict, *_ = _run(monkeypatch, [SQLI, PROBE, xss], allowed=3)
    assert "**HIGH CONFIDENCE: Attack source or scanner.**" in verdict and "LIKELY" not in verdict, verdict


def test_three_categories_need_no_majority(monkeypatch):
    xss = managed("AWSManagedRulesCommonRuleSet", "CrossSiteScripting_BODY", 1)
    verdict, *_ = _run(monkeypatch, [SQLI, PROBE, xss], allowed=10_000)
    assert "Attack source" in verdict and "3 attack categories" in verdict, verdict


def test_rate_limits_reputation_lists_and_bot_control_are_not_categories(monkeypatch):
    """Three WebACL rules, counted by rule two of them would pass the rung with a majority of blocks: a
    flood source on a reputation list that Bot Control also caught is still hammering, not a scanner. Bot
    Control's blocks fall on several paths, so the path test does not stand in for the category test."""
    bot = managed("AWSManagedRulesBotControlRuleSet", "SignalAutomatedBrowser", 30, uris=3)
    verdict, *_ = _run(monkeypatch, [RATE, REPUTATION, bot], allowed=0, extra=HAMMER)
    assert "Endpoint hammering" in verdict and "Attack source" not in verdict, verdict


def test_one_managed_group_holds_one_category_per_payload_kind(monkeypatch):
    """Two SQL-injection sub-rules of one group are one category, not two."""
    ext = managed("AWSManagedRulesSQLiRuleSet", "SQLiExtendedPatterns_BODY", 30)
    verdict, *_ = _run(monkeypatch, [SQLI, ext], allowed=0)
    assert "Attack source" not in verdict, verdict


def test_a_third_party_group_is_not_classified_by_its_rule_names(monkeypatch):
    vendor = {**managed("x", "SQLi_BODY", 20), "rgid": "Fortinet#WebExploits", "terminatingRuleId": "fortinet"}
    verdict, out, *_ = _run(monkeypatch, [SQLI, vendor], allowed=3)
    assert "CANNOT DETERMINE" in verdict and "fortinet" in verdict and "Fortinet" in verdict, verdict
    assert "category unknown: fortinet" in out, out


def test_custom_rules_are_classified_by_their_statements(monkeypatch):
    waf = FakeWaf([{"Name": "my-sqli", "Statement": {"SqliMatchStatement": {}}},
                   {"Name": "my-xss", "Statement": {"AndStatement": {"Statements": [{"XssMatchStatement": {}}]}}},
                   {"Name": "block-admin", "Statement": {"ByteMatchStatement": {}}}])
    verdict, *_ = _run(monkeypatch, [custom("my-sqli", 5, uris=2), custom("my-xss", 5), custom("block-admin", 50)],
                       allowed=3, waf=waf)
    assert "Attack source" in verdict and "SQL injection 5, cross-site scripting 5" in verdict, verdict


def test_a_whole_group_count_entry_is_not_read_as_the_block(monkeypatch):
    """A custom rule blocked, and an earlier group in whole-group Count logged a `terminatingRule`."""
    waf = FakeWaf([{"Name": "block-admin", "Statement": {"ByteMatchStatement": {}}}])
    row = custom("block-admin", 50, rgid="AWS#AWSManagedRulesSQLiRuleSet", sub="SQLi_QUERYARGUMENTS")
    verdict, out, *_ = _run(monkeypatch, [row, PROBE], allowed=3, waf=waf)
    assert "Attack source" not in verdict and "SQL injection" not in out, out


def test_a_failed_config_read_stops_the_rung_when_it_could_decide_it(monkeypatch):
    verdict, *_ = _run(monkeypatch, [SQLI, custom("my-rule", 9)], allowed=3, waf=FakeWaf([], fails=True))
    assert "CANNOT DETERMINE" in verdict and "AccessDeniedException" in verdict, verdict
    assert "Attack source" not in verdict.split("CANNOT DETERMINE")[0], verdict


def test_a_failed_config_read_does_not_stop_a_rung_already_decided(monkeypatch):
    verdict, *_ = _run(monkeypatch, [SQLI, PROBE, custom("my-rule", 9)], allowed=3, waf=FakeWaf([], fails=True))
    assert "Attack source" in verdict, verdict


def test_the_config_is_read_only_when_a_custom_rule_blocked(monkeypatch):
    waf = FakeWaf([])
    _run(monkeypatch, [SQLI, PROBE, RATE], allowed=3, waf=waf)
    assert waf.reads == 0


def test_a_failed_block_query_stops_the_ladder(monkeypatch):
    verdict, *_ = _run(monkeypatch, [], extra=SCRAPER, fail=("attack_categories",))
    assert "CANNOT DETERMINE" in verdict and "attack_categories" in verdict and "scraper" not in verdict, verdict


def test_a_failed_allowed_count_stops_the_ladder(monkeypatch):
    verdict, out, *_ = _run(monkeypatch, [SQLI], extra=SCRAPER, fail=("allowed",))
    assert "CANNOT DETERMINE" in verdict and "allowed" in verdict, verdict
    assert "**Allowed requests**:\n  UNKNOWN" in out, out


def test_a_block_list_cut_off_at_its_limit_is_not_complete(monkeypatch):
    verdict, *_ = _run(monkeypatch, [SQLI], allowed=3, extra=SCRAPER, truncated=True)
    assert "CANNOT DETERMINE" in verdict and "scraper" not in verdict, verdict


def test_the_bot_rung_queries_leave_out_the_attack_blocks(monkeypatch):
    *_, seen, _ = _run(monkeypatch, [SQLI, PROBE, RATE], allowed=3)
    for label in ("uri_diversity", "request_rate_dynamic", "request_rate_static", "all_uris"):
        cwl, athena = seen[label]
        assert "sub_rule in ['ExploitablePaths_URIPATH', 'SQLi_QUERYARGUMENTS']" in cwl, (label, cwl)
        assert "IN ('ExploitablePaths_URIPATH', 'SQLi_QUERYARGUMENTS')" in athena, (label, athena)
        assert "rate-limit" not in cwl and "rate-limit" not in athena, (label, cwl)
    for label in ("request_rate", "actions", "query_strings"):
        assert "not (action = 'BLOCK'" not in seen[label][0], (label, seen[label][0])


def test_with_nothing_set_aside_the_bot_rung_queries_are_unchanged(monkeypatch):
    *_, seen, _ = _run(monkeypatch, [RATE], allowed=3)
    assert "not (action" not in seen["uri_diversity"][0] and "NOT (action" not in seen["uri_diversity"][1]


def test_the_static_share_is_of_the_requests_the_bot_rungs_read(monkeypatch):
    """With 800 SQL-injection blocks set aside, 50 non-static requests are half of the 100 kept, not
    under a tenth of all 900, so this is not a static-asset client."""
    sqli = managed("AWSManagedRulesSQLiRuleSet", "SQLi_QUERYARGUMENTS", 800)
    extra = {"request_rate_static": [{"peak_rpm": "300"}], "request_rate_dynamic": [{"peak_rpm": "5"}],
             "uri_diversity": [{"unique_uris": "20", "total_non_static": "50"}]}
    verdict, *_ = _run(monkeypatch, [sqli], allowed=100, extra=extra)
    assert "static-asset" not in verdict, verdict


def test_a_rule_name_outside_waf_charset_is_refused_not_quoted():
    with pytest.raises(ValueError):
        L._without_attack_blocks({("x'] or true or [", "")})


def test_not_blocked_and_blocked_by_other_rules_read_differently(monkeypatch):
    _, out, *_ = _run(monkeypatch, [], allowed=3)
    assert "none: it was not blocked" in out, out
    _, out, *_ = _run(monkeypatch, [RATE], allowed=3)
    assert "none: its blocks came from rules that do not inspect" in out, out


# --- the category table -------------------------------------------------------------------------

def test_every_injection_family_has_a_category():
    assert set(I._INJECTION_FAMILIES) == set(I._CATEGORY_OF_FAMILY), \
        set(I._INJECTION_FAMILIES) ^ set(I._CATEGORY_OF_FAMILY)


def test_every_listed_managed_sub_rule_has_a_category():
    names = [n for subs in I._MANAGED_SUB_RULES.values() for n in subs if I._is_injection_sub_rule(n)]
    assert names, "no sub-rules listed, so this proves nothing"
    assert all(I.attack_category(n) for n in names), [n for n in names if not I.attack_category(n)]


@pytest.mark.parametrize("name,expected", [
    ("SQLi_QUERYARGUMENTS", "SQL injection"), ("SQLiExtendedPatterns_BODY", "SQL injection"),
    ("LFI_URIPATH", "path probing"), ("GenericLFI_URIPATH", "path probing"), ("GenericLFI_BODY", "local file inclusion"),
    ("ExploitablePaths_URIPATH", "path probing"), ("RestrictedExtensions_URIPATH", "path probing"),
    ("WindowsShellCommands_BODY", "command injection"), ("UNIXShellCommandsVariables_HEADER", "command injection"),
    ("SignalAutomatedBrowser", None), ("AWSManagedIPReputationList", None), ("SizeRestrictions_BODY", None),
    ("NoUserAgent_HEADER", None), ("SQLi_QUERYSTRING_RC_COUNT", None),
])
def test_attack_category(name, expected):
    assert I.attack_category(name) == expected
