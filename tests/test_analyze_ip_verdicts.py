# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`analyze_ip` reaches a verdict only from inputs that answered.

Three ways it used to conclude from an absence:

- A failed UA-list query returned `[]`, and `not ua_rows` was read as NAT, "Confidence: HIGH",
  ending the profile. So did a list too short to judge.
- A failed or unparseable rate or URI query became 0, and the verdict ladder ran on the 0. A failed
  URI query plus a real peak over 200 printed "HIGH CONFIDENCE: Endpoint hammering".
- iPhone and iPad UAs contain "Mac OS X", and the Mac branch ran first, so an office of Mac and
  iPhone Safari users read as one OS and one browser, which the heuristic calls UA rotation.

The NAT check is a gate: a shared IP is not profiled, because blocking it hurts every user behind
it. So when the gate cannot decide, the sections still render and the verdict refuses a direction.
"""

import pytest

from tools import waf_logs as L
from tools import waf_query as WQ

ROW = {"action": "ALLOW", "terminatingRuleId": "r", "cnt": "9", "avg_rpm": "1", "peak_rpm": "1",
       "active_minutes": "1", "ja4Fingerprint": "t13d1516h2", "unique_uris": "1",
       "total_non_static": "1", "args": "?a=1", "hits": "1"}

MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
IPAD = "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
IPHONE_16 = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
DIVERSE = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
           MAC, "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", IPHONE]


def _run(monkeypatch, *, diversity=("1", "1"), fail=(), override=None, uas=None):
    """Drive `analyze_ip` offline. `fail` names labels whose query raises; `override` replaces a
    label's rows. Dispatch is on the label `_safe_query` passes, which is the section's identity."""
    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: None)
    seen = []

    def q(cwl, athena, start, end, limit=25, notes=None, label="", **kw):
        seen.append(label)
        if label in fail:
            raise RuntimeError(f"{label} query timed out")
        if override and label in override:
            return override[label]
        if label == "diversity":
            return [{"ua_count": diversity[0], "ja4_count": diversity[1], "total": "900"}]
        if label == "user_agents":
            return [{"ua": u, "cnt": "5"} for u in (uas or [])]
        return [dict(ROW)]
    monkeypatch.setattr(WQ, "query_logs", q)
    out = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    return out, seen


def _assessment(out):
    assert "## Assessment" in out, f"no assessment section, so the verdict cannot be checked:\n{out}"
    return out.split("## Assessment", 1)[1]


# --- the NAT gate ---------------------------------------------------------------

def test_a_failed_ua_list_is_not_read_as_nat(monkeypatch):
    # Inputs that reach "HIGH CONFIDENCE: Endpoint hammering" on their own, so the verdict can only
    # stay undirected because the gate refused it. Quiet inputs fall through to CANNOT DETERMINE
    # with or without the gate, which is how this test first passed with the gate disabled.
    out, seen = _run(monkeypatch, diversity=("6", "5"), fail={"user_agents"},
                     override={"request_rate": [dict(ROW, peak_rpm="300")], "uri_diversity": [dict(ROW, unique_uris="3")]})
    assert "user_agents" in seen, "the UA list was never asked for, so this proves nothing"
    assert "NAT/Shared IP" not in out and "Confidence: HIGH" not in out, out
    assert "user_agents query timed out" in out, "the reason the NAT check could not run is lost"
    verdict = _assessment(out)
    assert "CANNOT DETERMINE" in verdict and "HIGH CONFIDENCE" not in verdict, verdict


def test_a_ua_list_too_short_to_judge_is_not_read_as_nat(monkeypatch):
    out, _ = _run(monkeypatch, diversity=("6", "5"), uas=[MAC, IPHONE],
                  override={"request_rate": [dict(ROW, peak_rpm="300")], "uri_diversity": [dict(ROW, unique_uris="3")]})
    assert "NAT/Shared IP" not in out, out
    verdict = _assessment(out)
    assert "CANNOT DETERMINE" in verdict and "HIGH CONFIDENCE" not in verdict, verdict


def test_genuine_diversity_is_still_nat(monkeypatch):
    """The control: the gate still closes on the evidence it was built for."""
    out, _ = _run(monkeypatch, diversity=("6", "5"), uas=DIVERSE)
    assert "NAT/Shared IP" in out, out


# --- iOS -------------------------------------------------------------------------

def test_mac_and_iphone_safari_users_are_two_operating_systems():
    """The discriminating input: all Safari, so OS is the only diversity there is. With iOS read as
    Mac it collapses to one OS and one browser, and the heuristic returns rotation."""
    assert L._is_nat_traffic([{"ua": u} for u in (MAC, IPHONE, IPAD, IPHONE_16)]) is True


# --- the verdict ladder ------------------------------------------------------------

def test_a_failed_uri_query_does_not_become_endpoint_hammering(monkeypatch):
    out, _ = _run(monkeypatch, fail={"uri_diversity"}, override={"request_rate": [dict(ROW, peak_rpm="300")]})
    verdict = _assessment(out)
    assert "HIGH CONFIDENCE" not in verdict, verdict
    assert "CANNOT DETERMINE" in verdict and "uri_diversity" in verdict, verdict


def test_a_failed_rate_query_does_not_rank_the_ip_on_a_zero_peak(monkeypatch):
    out, _ = _run(monkeypatch, fail={"request_rate"}, override={"uri_diversity": [dict(ROW, unique_uris="80")]})
    verdict = _assessment(out)
    assert "LIKELY" not in verdict and "HIGH CONFIDENCE" not in verdict, verdict
    assert "CANNOT DETERMINE" in verdict and "request_rate" in verdict, verdict


def test_an_unparseable_peak_is_unknown_not_zero(monkeypatch):
    """80 URIs, so a peak read as 0 skips the rate rungs and lands on "LIKELY: crawler". Three
    URIs was the first version of this test and passed on the defect, because 0 and 3 fall through
    every rung to the same CANNOT DETERMINE either way."""
    out, _ = _run(monkeypatch, override={"request_rate": [dict(ROW, peak_rpm="n/a")],
                                         "uri_diversity": [dict(ROW, unique_uris="80")]})
    verdict = _assessment(out)
    assert "LIKELY" not in verdict and "CANNOT DETERMINE" in verdict, verdict


@pytest.mark.parametrize("peak,uris,expected", [("300", "3", "Endpoint hammering"),
                                                ("300", "80", "Automated scraper"),
                                                ("20", "80", "LIKELY")])
def test_answered_inputs_still_reach_their_verdict(monkeypatch, peak, uris, expected):
    """The controls, one per directional rung, so a refusal that fires on every input fails here."""
    out, _ = _run(monkeypatch, override={"request_rate": [dict(ROW, peak_rpm=peak)],
                                         "uri_diversity": [dict(ROW, unique_uris=uris)]})
    assert expected in _assessment(out), out


def test_one_client_rotating_its_ua_is_named(monkeypatch):
    """The first rung. Replacing it with False left this file green."""
    out, _ = _run(monkeypatch, diversity=("3", "1"), override={"request_rate": [dict(ROW, peak_rpm="60")]})
    assert "Bot with UA rotation" in _assessment(out), out


def test_the_control_two_fingerprints_are_not_ua_rotation(monkeypatch):
    out, _ = _run(monkeypatch, diversity=("3", "2"), override={"request_rate": [dict(ROW, peak_rpm="60")]})
    assert "Bot with UA rotation" not in _assessment(out), out


def test_an_ip_sending_only_static_assets_is_ranked_on_cloudwatch(monkeypatch):
    """CloudWatch answers no rows for a `stats` with no group-by over no records, Athena a row of
    zeros. Read as unanswered, 300/min on static assets was CANNOT DETERMINE on CloudWatch and
    "Endpoint hammering" on Athena."""
    out, _ = _run(monkeypatch, override={"request_rate": [dict(ROW, peak_rpm="300")], "uri_diversity": []})
    verdict = _assessment(out)
    assert "Endpoint hammering" in verdict and "did not answer" not in verdict, verdict
