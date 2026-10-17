"""`investigate_block_fp` judges the blocked client, not the whole address. ROADMAP 7.14.

It read the IP's allowed-to-blocked ratio and peak per IP. Behind an office NAT both mix every user's
traffic: the pace rises past the human threshold and other users' allowed requests set the ratio. So an
attacker in a busy office could read as a likely false positive, and a real user there could not be
read at all. The address is now split into clients by User-Agent and JA4, and the signals are the
blocked client's own. Measured 2026-10-16 on the CloudWatch test WebACL: an Amazon office egress
carried 3 clients and 17 allowed requests against 1 block, and the blocked client, a headless Chrome,
had none allowed. The IP's 17:1 read as "suggests legitimate user"; the client's own is 0:1.
"""

import pytest

from tools import waf_block_fp as F

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
SAFARI = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
CURL = "curl/8.4.0"


def counts(*rows):
    return [{"ua": ua, "ja4Fingerprint": ja4, "allow": str(a), "block": str(b)} for ua, ja4, a, b in rows]


def paces(*rows):
    return [{"ua": ua, "ja4Fingerprint": ja4, "peak_rpm": str(p)} for ua, ja4, p in rows]


def rules(*rows):
    return [{"ua": ua, "ja4Fingerprint": ja4, "terminatingRuleId": r, "hits": "1"} for ua, ja4, r in rows]


# --- who is behind the address ------------------------------------------------------------------

def test_one_client_is_judged_on_the_ip():
    assert F._clients(counts((CHROME, "j1", 50, 1)), [], []) == {"n": 1, "basis": "ip"}


def test_several_clients_and_one_blocked_judges_that_client():
    c = F._clients(counts((CHROME, "j1", 400, 0), (SAFARI, "j2", 100, 0), (CURL, "j3", 0, 4)),
                   paces((CHROME, "j1", 30), (SAFARI, "j2", 9), (CURL, "j3", 2)),
                   rules((CURL, "j3", "SQLi"), (CURL, "j3", "XSS")))
    assert c["basis"] == "client" and c["n"] == 3, c
    assert (c["ua"], c["ja4"], c["allow"], c["block"], c["peak"], c["rules"]) == (CURL, "j3", 0, 4, "2", 2), c


def test_blocks_from_several_clients_judge_none_of_them():
    c = F._clients(counts((CHROME, "j1", 400, 1), (SAFARI, "j2", 100, 2), (FIREFOX, "j3", 5, 0)), [], [])
    assert c["basis"] == "several" and "2 of them were blocked" in c["why"], c


def test_a_client_list_cut_off_at_its_limit_judges_none():
    rows = counts(*[(f"UA {i}", f"j{i}", 1, 1 if i == 0 else 0) for i in range(F._CLIENTS)])
    assert F._clients(rows, [], [])["basis"] == "several"


def test_user_agents_differing_only_by_version_are_one_client():
    """Rotation, which `_is_nat_traffic` reads off five or more UAs that share one template."""
    uas = [CHROME.replace("141.0.0.0", f"{v}.0.0.0") for v in range(120, 126)]
    c = F._clients(counts(*[(ua, "j1", 10, 1 if i == 0 else 0) for i, ua in enumerate(uas)]), [], [])
    assert c == {"n": 6, "basis": "ip", "rotation": True}, c


def test_clients_that_disagree_with_the_ip_blocks_say_so():
    c = F._clients(counts((CHROME, "j1", 400, 0), (SAFARI, "j2", 100, 0)), [], [])
    assert c["basis"] == "several" and "disagree" in c["why"], c


# --- the verdict reads the blocked client's own signals ------------------------------------------

BASE = dict(rule_id="SomeRule", rule_type="REGULAR", sub_rule="", avg_rpm="1", uri_results=[], match_detail=[],
            match_detail_note="", text_transforms=[], insp_label=None, insp_samples=None, insp_masked=False)


def _render(**over):
    out = F._render_investigation("203.0.113.9", 0, 3600, dict(BASE, **over))
    return out, out.split("## Directional Judgment", 1)[1].split(F.CONFIDENCE_RULES, 1)[0]


def test_an_attacker_behind_an_office_nat_is_not_a_false_positive_candidate():
    """The dangerous direction: other users' allowed requests made the attacker's ratio 500:1."""
    attacker = {"n": 3, "basis": "client", "ua": CURL, "ja4": "j3", "allow": 0, "block": 1, "peak": "1", "rules": 1}
    whole = dict(allow_count=500, block_count=1, total=501, peak_rpm="5", rules_triggered=1)
    _, before = _render(**whole, clients={"n": 1, "basis": "ip"})
    assert "FP candidate" in before, f"the precondition: on the IP's numbers this is a candidate:\n{before}"
    out, verdict = _render(**whole, clients=attacker)
    assert "FP candidate" not in verdict, verdict
    assert "**Shared address**: 3 clients" in out and "Allow Ratio | 0:1" in out, out


def test_a_real_user_behind_a_busy_nat_is_read_at_their_own_pace():
    user = {"n": 4, "basis": "client", "ua": SAFARI, "ja4": "j2", "allow": 60, "block": 1, "peak": "3", "rules": 1}
    whole = dict(allow_count=5000, block_count=1, total=5001, peak_rpm="90", rules_triggered=1)
    _, before = _render(**whole, clients={"n": 1, "basis": "ip"})
    assert "FP candidate" not in before, before
    _, verdict = _render(**whole, clients=user)
    assert "FP candidate" in verdict, verdict


def test_blocks_from_several_clients_refuse_a_direction():
    several = {"n": 5, "basis": "several", "blocked": 2, "why": "2 of them were blocked"}
    _, verdict = _render(allow_count=500, block_count=3, total=503, peak_rpm="5", rules_triggered=1, clients=several)
    assert "CANNOT DETERMINE" in verdict and "5 clients share this address" in verdict, verdict
    assert "FP candidate" not in verdict


def test_a_rotating_client_is_judged_on_the_ip_and_says_why():
    out, verdict = _render(allow_count=0, block_count=50, total=50, peak_rpm="300", rules_triggered=3,
                           clients={"n": 6, "basis": "ip", "rotation": True})
    assert "One client rotating its User-Agent" in out and "Not a false positive" in verdict, out


def test_the_average_is_not_mixed_with_one_clients_peak():
    client = {"n": 3, "basis": "client", "ua": CURL, "ja4": "j3", "allow": 0, "block": 1, "peak": "2", "rules": 2}
    out, _ = _render(allow_count=17, block_count=1, total=19, peak_rpm="6", rules_triggered=2, clients=client)
    assert "2 req/min (avg not split per client)" in out, out


# --- the queries ---------------------------------------------------------------------------------

def test_the_client_queries_group_by_the_user_agent_and_never_filter_on_it(monkeypatch):
    captured = {}
    monkeypatch.setattr(F, "run_concurrently", lambda jobs: (captured.update(jobs), ({}, {"x": "stop"}))[1])
    with pytest.raises(RuntimeError):
        F._investigate_gather("203.0.113.9", 0, 3600)
    texts = {}
    monkeypatch.setattr(F, "query_logs", lambda cwl, athena, s, e, limit=25: texts.update({len(texts): (cwl, athena)}) or [])
    for label in ("clients", "client_pace", "client_rules"):
        captured[label]()
    assert len(texts) == 3, texts
    for cwl, athena in texts.values():
        assert "by ua, ja4Fingerprint" in cwl and "ua =" not in cwl and "ua like" not in cwl, cwl
        assert "GROUP BY 1, 2" in athena and "= '" + CURL not in athena, athena


def test_the_scan_picks_candidates_at_the_looser_ratio(monkeypatch):
    """6 allowed against 1 block is under the targeted check's 10:1 and over the scan's 5:1, so the
    scan lists it for the targeted check to judge."""
    replies = iter([[{"httpRequest.clientIp": "203.0.113.9", "block_hits": "1"}],
                    [{"httpRequest.clientIp": "203.0.113.9", "allow_hits": "6"}]])
    monkeypatch.setattr(F, "_run_query", lambda *a, **k: next(replies))
    out = F._step_scan(0, 3600, "")
    assert "Candidates Found" in out and "203.0.113.9" in out, out
    assert F.SCAN_ALLOW_RATIO < 6 < F.FP_ALLOW_RATIO
