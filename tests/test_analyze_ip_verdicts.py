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
                     override={"request_rate": [dict(ROW, peak_rpm="300")], "request_rate_dynamic": [dict(ROW, peak_rpm="300")],
                               "uri_diversity": [dict(ROW, unique_uris="3")]})
    assert "user_agents" in seen, "the UA list was never asked for, so this proves nothing"
    assert "NAT/Shared IP" not in out and "Confidence: HIGH" not in out, out
    assert "user_agents query timed out" in out, "the reason the NAT check could not run is lost"
    verdict = _assessment(out)
    assert "CANNOT DETERMINE" in verdict and "HIGH CONFIDENCE" not in verdict, verdict


def test_a_ua_list_too_short_to_judge_is_not_read_as_nat(monkeypatch):
    out, _ = _run(monkeypatch, diversity=("6", "5"), uas=[MAC, IPHONE],
                  override={"request_rate": [dict(ROW, peak_rpm="300")], "request_rate_dynamic": [dict(ROW, peak_rpm="300")],
                               "uri_diversity": [dict(ROW, unique_uris="3")]})
    assert "NAT/Shared IP" not in out, out
    verdict = _assessment(out)
    assert "CANNOT DETERMINE" in verdict and "HIGH CONFIDENCE" not in verdict, verdict


def test_the_nat_fixture_reaches_hammering_without_the_gate(monkeypatch):
    """The precondition of the two tests above. Hammering reads the non-static peak, and with only the
    overall one at 300 these inputs reached no verdict, so the gate's refusal was never what they saw."""
    out, _ = _run(monkeypatch, diversity=("6", "5"), uas=[MAC] * 4,
                  override={"request_rate": [dict(ROW, peak_rpm="300")], "request_rate_dynamic": [dict(ROW, peak_rpm="300")],
                            "uri_diversity": [dict(ROW, unique_uris="3")]})
    assert "Endpoint hammering" in _assessment(out), out


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
                                         "request_rate_dynamic": [dict(ROW, peak_rpm=peak)],
                                         "uri_diversity": [dict(ROW, unique_uris=uris, total_non_static="900")]})
    assert expected in _assessment(out), out


def test_one_client_rotating_its_ua_is_named(monkeypatch):
    """The first rung. Replacing it with False left this file green."""
    out, _ = _run(monkeypatch, diversity=("3", "1"), override={"request_rate": [dict(ROW, peak_rpm="60")]})
    assert "Bot with UA rotation" in _assessment(out), out


def test_the_control_two_fingerprints_are_not_ua_rotation(monkeypatch):
    out, _ = _run(monkeypatch, diversity=("3", "2"), override={"request_rate": [dict(ROW, peak_rpm="60")]})
    assert "Bot with UA rotation" not in _assessment(out), out


# Three shapes of a 300/min IP, as each engine answers them. CloudWatch answers a `stats` with no
# group-by over no records with no rows; Athena with one row, "" for `max` and 0 for `count`.
STATIC_ONLY = {"cwl": {"request_rate_dynamic": [], "uri_diversity": []},
               "athena": {"request_rate_dynamic": [{"peak_rpm": ""}],
                          "uri_diversity": [{"unique_uris": "0", "total_non_static": "0"}]}}


NO_STATIC = {"cwl": [], "athena": [{"peak_rpm": ""}]}


def _shape(engine, dynamic, all_uris):
    """`dynamic` is (non-static peak, URIs, non-static requests), or None for static only. The static
    peak is what the 300 leaves, which is exact when both peaks fall in one minute."""
    rows = {"request_rate": [dict(ROW, peak_rpm="300")], "all_uris": [{"unique_uris_all": all_uris}]}
    rows.update(STATIC_ONLY[engine] if dynamic is None else
                {"request_rate_dynamic": [dict(ROW, peak_rpm=dynamic[0])],
                 "uri_diversity": [dict(ROW, unique_uris=dynamic[1], total_non_static=dynamic[2])]})
    static = 300 - int(dynamic[0]) if dynamic else 300
    rows["request_rate_static"] = [dict(ROW, peak_rpm=str(static))] if static else NO_STATIC[engine]
    return rows


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_an_ip_pulling_only_static_files_is_a_static_client_not_hammering(monkeypatch, engine):
    """The URI count reads non-static requests and the rate read all of them, so 0 URIs at 300/min
    was "HIGH CONFIDENCE: Endpoint hammering" about requests it never counted."""
    verdict = _assessment(_run(monkeypatch, override=_shape(engine, None, "2"))[0])
    assert "High-rate static-asset client" in verdict and "same 2 files" in verdict, verdict
    assert "HIGH CONFIDENCE" not in verdict and "hammering" not in verdict.lower(), verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_mostly_static_with_a_few_api_calls_is_judged_on_the_api_part(monkeypatch, engine):
    """300/min of images beside 2 API paths: 2 URIs, under 10, and the old rule called it hammering."""
    verdict = _assessment(_run(monkeypatch, override=_shape(engine, ("2", "2", "20"), "80"))[0])
    assert "High-rate static-asset client" in verdict and "80 distinct URIs" in verdict, verdict
    assert "hammering" not in verdict.lower(), verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_the_control_pure_api_traffic_is_still_hammering(monkeypatch, engine):
    verdict = _assessment(_run(monkeypatch, override=_shape(engine, ("300", "3", "900"), "3"))[0])
    assert "Endpoint hammering" in verdict and "static-asset" not in verdict, verdict


def test_the_rate_the_rungs_compare_reads_the_same_requests_as_the_uri_count():
    import inspect
    src = inspect.getsource(L.analyze_ip._tool_func)
    dyn = src.split("dyn_rate_cwl = (", 1)[1].split(")", 1)[0]
    assert "CWL_EXCLUDE_STATIC" in dyn, dyn
    assert "ATHENA_EXCLUDE_STATIC" in src.split("dyn_rate_athena = (", 1)[1].split("\n    )", 1)[0]


def test_athena_no_minutes_is_a_zero_peak_not_a_failure(monkeypatch):
    """Athena's `max` over no rows is "" in one row. With 80 URIs a zero peak lands on "LIKELY";
    read as unparseable it was CANNOT DETERMINE, "the request_rate query did not answer"."""
    out, _ = _run(monkeypatch, override={"request_rate": [dict(ROW, peak_rpm="", avg_rpm="")],
                                         "uri_diversity": [dict(ROW, unique_uris="80")]})
    assert "LIKELY" in _assessment(out), out


def test_athena_no_records_for_the_ip_is_said_so(monkeypatch):
    """Athena answers a `count(*)` over nothing with one row of 0, so the "no records" return never
    fired there and the profile ran on empty sections."""
    from tools import waf_metrics as M
    monkeypatch.setattr(M, "log_path_warning", lambda *a, **k: "")
    from tools import session_state as SS
    monkeypatch.setattr(SS, "get_webacl_name", lambda: "acl")
    out, seen = _run(monkeypatch, override={"diversity": [{"ua_count": "0", "ja4_count": "0", "total": "0"}]})
    assert "No log records found" in out and "request_rate" not in seen, out


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_many_api_paths_at_a_low_api_rate_are_not_a_high_confidence_scraper(monkeypatch, engine):
    """300/min overall but 5/min to the application, over 60 paths. The scraper rung read the
    overall rate, so the images made it HIGH CONFIDENCE."""
    verdict = _assessment(_run(monkeypatch, override=_shape(engine, ("5", "60", "100"), "400"))[0])
    assert "HIGH CONFIDENCE" not in verdict and "LIKELY" in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_the_crawler_rung_names_the_non_static_rate_it_compared(monkeypatch, engine):
    """The scraper rung reads the non-static peak, so this rung is reached at an overall 300/min,
    and "moderate frequency" was false about the overall rate."""
    verdict = _assessment(_run(monkeypatch, override=_shape(engine, ("150", "60", "180"), "400"))[0])
    assert "Probable crawler" in verdict and "150 non-static req/min" in verdict, verdict
    assert "moderate frequency" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_an_api_burst_in_a_mostly_static_window_is_not_a_static_client(monkeypatch, engine):
    """Peak 210, of which up to 150 non-static: at most 60 static requests in that minute, so the
    fast minute was the API burst and the static share is over the whole window."""
    rows = _shape(engine, ("150", "3", "27"), "3")
    rows["request_rate"] = [dict(ROW, peak_rpm="210")]
    rows["request_rate_static"] = [dict(ROW, peak_rpm="60")]
    verdict = _assessment(_run(monkeypatch, override=rows)[0])
    assert "static-asset" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_the_control_a_static_minute_over_200_is_a_static_client(monkeypatch, engine):
    rows = _shape(engine, ("150", "3", "27"), "3")
    rows["request_rate"] = [dict(ROW, peak_rpm="360")]
    rows["request_rate_static"] = [dict(ROW, peak_rpm="210")]
    verdict = _assessment(_run(monkeypatch, override=rows)[0])
    assert "High-rate static-asset client" in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_a_static_client_whose_api_burst_was_in_another_minute_is_still_named(monkeypatch, engine):
    """Overall peak 250 and non-static peak 100, in different minutes, so the busiest minute held 250
    static requests. The overall peak minus the non-static one is 150, and that floor read it as mixed."""
    rows = _shape(engine, ("100", "3", "54"), "3")
    rows["request_rate"] = [dict(ROW, peak_rpm="250")]
    rows["request_rate_static"] = [dict(ROW, peak_rpm="250")]
    verdict = _assessment(_run(monkeypatch, override=rows)[0])
    assert "High-rate static-asset client" in verdict, verdict


def test_the_static_peak_reads_only_static_requests():
    import inspect
    src = inspect.getsource(L.analyze_ip._tool_func)
    assert "CWL_ONLY_STATIC" in src.split("static_rate_cwl = (", 1)[1].split("\n    )", 1)[0]
    assert "ATHENA_ONLY_STATIC" in src.split("static_rate_athena = (", 1)[1].split("\n    )", 1)[0]


def test_two_unknown_inputs_are_each_named_for_what_went_wrong(monkeypatch):
    """The scraper rung reads both, so one refusal names them together."""
    out, _ = _run(monkeypatch, fail={"request_rate_dynamic"},
                  override={"uri_diversity": [dict(ROW, unique_uris="n/a")]})
    verdict = _assessment(out)
    assert "request_rate_dynamic query did not answer" in verdict, verdict
    assert "uri_diversity query answered without a number" in verdict, verdict


def test_a_failed_distinct_uri_count_does_not_stop_the_ladder(monkeypatch):
    """The static rung's condition never reads it, only its text does."""
    out, _ = _run(monkeypatch, fail={"all_uris"}, override={"request_rate": [dict(ROW, peak_rpm="30")],
                                                           "uri_diversity": [dict(ROW, unique_uris="80")]})
    assert "Probable crawler" in _assessment(out), out


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_a_static_client_is_named_without_its_distinct_uri_count(monkeypatch, engine):
    rows = _shape(engine, None, "2")
    del rows["all_uris"]
    verdict = _assessment(_run(monkeypatch, fail={"all_uris"}, override=rows)[0])
    assert "High-rate static-asset client" in verdict and "distinct URIs" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_a_middle_shape_does_not_say_which_of_nothing(monkeypatch, engine):
    verdict = _assessment(_run(monkeypatch, override=_shape(engine, None, "20"))[0])
    assert "20 distinct URIs" in verdict and "cannot tell which" not in verdict, verdict


def test_a_missing_field_is_unknown_not_zero(monkeypatch):
    """No peak field in the row is a mismatched alias, not a quiet IP. Read as 0, 80 URIs reached
    "LIKELY"."""
    out, _ = _run(monkeypatch, override={"request_rate": [{"avg_rpm": "1"}],
                                         "uri_diversity": [dict(ROW, unique_uris="80")]})
    verdict = _assessment(out)
    assert "LIKELY" not in verdict and "CANNOT DETERMINE" in verdict, verdict


def test_the_ladder_inputs_are_in_the_first_wave(monkeypatch):
    """Five workers for seven jobs, one budget. An input registered sixth starts only when one of the
    first five finishes, so a slow first wave cost it the verdict. The inputs are found by failing each
    query and seeing whether the verdict names it, not listed here."""
    import inspect
    order = []
    real = WQ.run_concurrently

    def spy(jobs, *a, **k):
        order[:] = list(jobs)
        return real(jobs, *a, **k)
    monkeypatch.setattr(WQ, "run_concurrently", spy)
    _run(monkeypatch)
    wave = list(order)
    ladder = {l for l in wave if f"the {l} query did not answer" in _assessment(_run(monkeypatch, fail={l})[0])}
    assert "uri_diversity" in ladder and "request_rate" in ladder, ladder
    workers = inspect.signature(real).parameters["workers"].default
    assert ladder <= set(wave[:workers]), (ladder, wave)
