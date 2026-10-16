# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The bypass investigation's verdict: verified bots are not scrapers, and an unread input stops it.

Two defects with the shape `analyze_ip` had, plus a third that only this tool has:

- The scraper and hammering rungs read no label, so a `bot:verified` search crawler at crawler
  volume was "HIGH CONFIDENCE: Automated scraper". The prompt treats `bot:verified` as ground truth.
- A failed frequency or URI query arrived as `"?"`, which does not parse, and became 0. A failed
  User-Agent query left `is_automation_ua` False, which skips its rung as if it had been checked.
- The verdict's automation-UA list and the scan's were two different lists, so an IP the scan
  surfaced for `libwww-perl` was not an automation UA when investigated.
"""

import re

import pytest

from tools import waf_bypass as B

ROW = {"httpRequest.clientIp": "203.0.113.9", "total": "999", "unique_uris": "888", "hits": "999",
       "cnt": "999", "action": "ALLOW", "Labels": "", "ja4Fingerprint": "t13d1516h2",
       "ua": "Mozilla/5.0", "rule": "SomeRule", "peak_rpm": "300", "avg_rpm": "100",
       "country": "US"}
VERIFIED = "awswaf:managed:aws:bot-control:bot:verified, awswaf:managed:aws:bot-control:bot:name:googlebot"


def _run(monkeypatch, fail=(), **rows):
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)

    def q(cwl, athena, start, end, limit=25, notes=None, label="", **kw):
        if label in fail:
            raise RuntimeError(f"{label} query timed out")
        if label in rows:
            return rows[label]
        return [dict(ROW)]
    monkeypatch.setattr(B, "query_logs", q)
    report = B._step_investigate_ip("203.0.113.9", 0, 3600)
    assert "## Directional Judgment" in report and "## Confidence Rules" in report
    # Ends at the rules legend, not at the next action: the legend itself says "CANNOT DETERMINE"
    # and "LIKELY", which made the first version of this helper satisfy a refusal assertion on
    # every report, whatever the verdict was.
    return report.split("## Directional Judgment")[1].split("## Confidence Rules")[0]


def test_a_verified_crawler_at_scraper_volume_is_a_verified_bot(monkeypatch):
    verdict = _run(monkeypatch, labels=[dict(ROW, Labels=VERIFIED)])
    assert "scraper" not in verdict.lower() and "HIGH CONFIDENCE" not in verdict, verdict
    assert "VERIFIED" in verdict and "googlebot" in verdict, verdict


def test_an_unverified_ip_at_the_same_volume_is_still_a_scraper(monkeypatch):
    """The control: the verified branch keys on the verified label, not on any bot label."""
    verdict = _run(monkeypatch, labels=[dict(ROW, Labels="awswaf:managed:aws:bot-control:bot:unverified")])
    assert "Automated scraper" in verdict, verdict


@pytest.mark.parametrize("label", ["frequency_dynamic", "uri_diversity", "user_agent"])
def test_a_failed_input_stops_the_verdict_instead_of_reading_as_zero(monkeypatch, label):
    """`peak 300` and `888 URIs` reach "Automated scraper" on their own, so each failure below has
    to be what stops it, and the reason has to name the query. The scraper rung reads the
    non-static rate, so that is the frequency it stops on."""
    verdict = _run(monkeypatch, fail={label})
    assert "HIGH CONFIDENCE" not in verdict and "LIKELY" not in verdict, verdict
    assert "CANNOT DETERMINE" in verdict and label in verdict, verdict


def test_an_unread_input_a_rung_does_not_need_does_not_block_it(monkeypatch):
    """Frequency failed, but the IP carries no data-center signal, so the data-center rung is ruled
    out by what is known. The automation-UA rung needs no frequency and has to fire."""
    verdict = _run(monkeypatch, fail={"frequency"}, user_agent=[dict(ROW, ua="curl/8.4.0")])
    assert "automation UA allowed through" in verdict, verdict


def test_an_unparseable_peak_stops_the_verdict(monkeypatch):
    verdict = _run(monkeypatch, frequency_dynamic=[dict(ROW, peak_rpm="n/a")])
    assert "HIGH CONFIDENCE" not in verdict and "CANNOT DETERMINE" in verdict, verdict


def test_answered_inputs_still_reach_the_scraper_verdict(monkeypatch):
    verdict = _run(monkeypatch)
    assert "Automated scraper" in verdict, verdict


@pytest.mark.parametrize("ua", ["libwww-perl/6.72", "Python-urllib/3.11", "curl/8.4.0"])
def test_the_verdict_and_the_scan_agree_on_what_an_automation_ua_is(monkeypatch, ua):
    """One list for both. Checked against the verdict's behaviour and the scan's regex together,
    because a list that only one of them reads is the drift this replaces."""
    verdict = _run(monkeypatch, user_agent=[dict(ROW, ua=ua)])
    assert "automation UA allowed through" in verdict, (ua, verdict)
    scan_cwl = re.search(r"/\(\?i\)\(([^)]*)\)/", B.AUTOMATION_UA_CWL).group(1)
    assert re.search(f"(?i)({scan_cwl.replace(chr(92) + '/', '/')})", ua), (ua, scan_cwl)
    assert re.search(B.AUTOMATION_UA_ATHENA.split("'")[1], ua), (ua, B.AUTOMATION_UA_ATHENA)


def test_both_scan_queries_use_the_shared_pattern():
    src = open(B.__file__).read()
    assert src.count("AUTOMATION_UA_CWL") >= 2 and src.count("AUTOMATION_UA_ATHENA") >= 2
    assert "python-requests|wget" not in src, "a hand-written copy of the list is still in the scan"


DATA_CENTER = "awswaf:managed:aws:bot-control:signal:known_bot_data_center"


def test_a_data_center_ip_with_no_bot_label_is_an_undetected_bot(monkeypatch):
    """The first rung. Replacing it with False left the whole suite green."""
    verdict = _run(monkeypatch, labels=[dict(ROW, Labels=DATA_CENTER)])
    assert "Undetected bot from data center" in verdict, verdict


def test_the_control_no_data_center_signal_is_not_that_rung(monkeypatch):
    verdict = _run(monkeypatch, labels=[dict(ROW, Labels="awswaf:managed:token:absent")])
    assert "Undetected bot from data center" not in verdict, verdict


def test_an_ip_sending_only_static_assets_is_ranked(monkeypatch):
    """On CloudWatch a `stats` with no group-by over no records answers no rows, so the URI query
    answers [] for an IP whose ALLOW traffic is all static. That is 0 URIs, and 300/min on them is
    hammering. Read as unanswered, it told the user to re-run a query that had answered."""
    verdict = _run(monkeypatch, uri_diversity=[])
    assert "Endpoint hammering" in verdict, verdict
    assert "did not answer" not in verdict, verdict


def test_a_value_that_is_not_a_number_is_not_called_unanswered(monkeypatch):
    verdict = _run(monkeypatch, frequency_dynamic=[dict(ROW, peak_rpm="n/a")])
    assert "CANNOT DETERMINE" in verdict and "not a number" in verdict, verdict
    assert "Re-run" not in verdict, verdict


def _count_section(monkeypatch, log_type, rows=(), cwl=None, config=("CategoryHttpLibrary",)):
    """The COUNT section of an investigation. `rows` answer the Athena query; `cwl(query)` answers
    the CloudWatch ones; `config` is the WebACL's Count rules, or an exception to raise."""
    from tools import waf_count_eval as C
    monkeypatch.setattr(B, "get_log_type", lambda: log_type)
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")

    def inventory(region, scope):
        if isinstance(config, Exception):
            raise config
        return list(config)
    monkeypatch.setattr(C, "_get_all_count_rules", inventory)
    seen = {"cwl": []}

    def q(cwl_q, athena, start, end, limit=25, notes=None, label="", **kw):
        if label == "count_rules":
            seen["cwl"].append(cwl_q)
            seen["athena"] = athena
            return cwl(cwl_q) if log_type == "cwl" else list(rows)
        return [dict(ROW)]
    monkeypatch.setattr(B, "query_logs", q)
    report = B._step_investigate_ip("203.0.113.9", 0, 3600)
    return report.split("### COUNT Rules Triggered", 1)[1].split("###", 1)[0], seen


def test_the_count_rules_read_nested_entries_once_per_request(monkeypatch):
    """A managed sub-rule's Count is nested in `rulegrouplist`. Measured 2026-10-16 on
    `response-id-on-page`, 2026-10-01 to 10-16: 5 top-level COUNT entries against 2,142 nested, and
    the Athena query unnested only the top level, so TGT_TokenAbsent's Counts read "(none)"."""
    _, seen = _count_section(monkeypatch, "athena")
    athena = seen["athena"]
    assert "rulegrouplist" in athena and "rg.nonterminatingmatchingrules" in athena, athena
    assert "array_distinct(" in athena, "a group deployed twice would count each request twice"


def _records(per_request):
    """A CloudWatch fake over requests, each a list of the Count rule ids in log order, nested
    entries first as WAF writes them. Answers the parse-and-group query and the per-rule sums the
    way the engine does, from the records."""
    def answer(query):
        if "by first, last" in query:
            # A parse that is not in the query leaves its field empty, as CloudWatch does.
            pairs = {}
            for ids in per_request:
                if ids:
                    key = (ids[0] if "(?<first>" in query else "", ids[-1] if "(?<last>" in query else "")
                    pairs[key] = pairs.get(key, 0) + 1
            return [{"first": f, "last": l, "n": str(n)} for (f, l), n in pairs.items()]
        sums = re.findall(r'"ruleId":"([\w-]+)","action":"COUNT"\'\)\) as (c\d+)', query)
        return [{alias: str(sum(1 for ids in per_request if name in ids)) for name, alias in sums}]
    return answer


def test_cloudwatch_finds_a_top_level_count_rule_behind_a_nested_one(monkeypatch):
    """`ruleGroupList` comes before the top-level entries in the record, so a first-match parse
    always took the nested one: over 24 hours on `shield-sample-webacl` the whole-group Count rule
    `ptest-admin-group-count` read 0 for 5 requests, while TGT_TokenAbsent read 514 for 520."""
    section, _ = _count_section(monkeypatch, "cwl", cwl=_records(
        [["TGT_TokenAbsent", "TGT_TokenAbsent", "ptest-admin-group-count"]] * 5 + [["TGT_TokenAbsent"]] * 2))
    assert "TGT_TokenAbsent (7 hits)" in section and "ptest-admin-group-count (5 hits)" in section, section


def test_cloudwatch_finds_a_middle_count_rule_the_configuration_names(monkeypatch):
    section, seen = _count_section(monkeypatch, "cwl", cwl=_records(
        [["TGT_TokenAbsent", "CategoryHttpLibrary", "SignalNonBrowserUserAgent"]] * 3))
    assert "CategoryHttpLibrary (3 hits)" in section, section


def test_a_failed_configuration_read_is_said_beside_the_list(monkeypatch):
    section, _ = _count_section(monkeypatch, "cwl", cwl=_records([["TGT_TokenAbsent"]]),
                                config=RuntimeError("AccessDeniedException: no"))
    assert "TGT_TokenAbsent (1 hits)" in section and "AccessDeniedException" in section, section


def test_the_control_a_configuration_read_carries_no_caveat(monkeypatch):
    section, _ = _count_section(monkeypatch, "cwl", cwl=_records([["TGT_TokenAbsent"]]))
    assert "could not be read" not in section, section


def test_athena_reads_no_allowed_traffic_as_zero_not_unknown(monkeypatch):
    """Athena answers `max` and `avg` over no rows as "" in one row. Read as not a number, a 0-ALLOW
    IP's peak printed as blank and stopped the verdict on "frequency, uri_diversity ... not a
    number" though both had answered."""
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    rows = {"frequency": [dict(ROW, peak_rpm="", avg_rpm="", active_minutes="0")],
            "frequency_dynamic": [dict(ROW, peak_rpm="")],
            "uri_diversity": [dict(ROW, unique_uris="0", total="0")],
            "all_uris": [{"unique_uris_all": "0"}], "actions": [dict(ROW, action="BLOCK", hits="40")]}
    monkeypatch.setattr(B, "query_logs", lambda cwl, athena, s, e, limit=25, notes=None, label="", **kw:
                        rows.get(label, [dict(ROW)]))
    report = B._step_investigate_ip("203.0.113.9", 0, 3600)
    assert "**Peak frequency**: 0 req/min (avg 0)" in report, report
    assert "not a number" not in report and "NO BYPASS" in report, report


def test_an_ip_with_no_allowed_request_is_no_bypass(monkeypatch):
    verdict = _run(monkeypatch, actions=[dict(ROW, action="BLOCK", hits="500")])
    assert "NO BYPASS" in verdict and "HIGH CONFIDENCE" not in verdict, verdict


def test_the_control_one_allowed_request_is_not_no_bypass(monkeypatch):
    verdict = _run(monkeypatch, actions=[dict(ROW, action="BLOCK", hits="500"), dict(ROW, action="ALLOW", hits="1")])
    assert "NO BYPASS" not in verdict, verdict


def test_a_failed_action_query_is_not_no_bypass(monkeypatch):
    verdict = _run(monkeypatch, fail={"actions"})
    assert "NO BYPASS" not in verdict, verdict


# Three shapes of a 300/min ALLOW IP, as each engine answers them: CloudWatch with no rows for a
# `stats` with no group-by over no records, Athena with one row, "" for `max` and 0 for `count`.
_STATIC_ONLY = {"cwl": {"frequency_dynamic": [], "uri_diversity": []},
                "athena": {"frequency_dynamic": [dict(ROW, peak_rpm="")],
                           "uri_diversity": [dict(ROW, unique_uris="0", total="0")]}}


_NO_STATIC = {"cwl": [], "athena": [dict(ROW, peak_rpm="")]}


def _shape(engine, dynamic, distinct):
    """`dynamic` is (non-static peak, URIs, non-static requests), or None for static only. The static
    peak is what ROW's 300 leaves, which is exact when both peaks fall in one minute."""
    rows = {"actions": [dict(ROW, action="ALLOW", hits="900")], "all_uris": [{"unique_uris_all": distinct}]}
    rows.update(_STATIC_ONLY[engine] if dynamic is None else
                {"frequency_dynamic": [dict(ROW, peak_rpm=dynamic[0])],
                 "uri_diversity": [dict(ROW, unique_uris=dynamic[1], total=dynamic[2])]})
    static = 300 - int(dynamic[0]) if dynamic else 300
    rows["frequency_static"] = [dict(ROW, peak_rpm=str(static))] if static else _NO_STATIC[engine]
    return rows


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_allowed_static_only_traffic_is_not_called_a_bypass(monkeypatch, engine):
    verdict = _run(monkeypatch, **_shape(engine, None, "1"))
    assert "static-asset traffic, not a bypass" in verdict and "same 1 file " in verdict, verdict
    assert "HIGH CONFIDENCE" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_mostly_static_with_a_few_api_calls_is_judged_on_the_api_part(monkeypatch, engine):
    verdict = _run(monkeypatch, **_shape(engine, ("2", "2", "20"), "300"))
    assert "static-asset traffic" in verdict and "300 distinct URIs" in verdict, verdict
    assert "hammering" not in verdict.lower(), verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_the_control_pure_api_traffic_is_still_hammering(monkeypatch, engine):
    verdict = _run(monkeypatch, **_shape(engine, ("300", "3", "900"), "3"))
    assert "Endpoint hammering" in verdict and "static-asset" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_many_api_paths_at_a_low_api_rate_are_not_a_high_confidence_scraper(monkeypatch, engine):
    verdict = _run(monkeypatch, **_shape(engine, ("5", "60", "100"), "400"))
    assert "HIGH CONFIDENCE" not in verdict and "LIKELY" in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_the_probable_scraper_rung_names_the_non_static_rate_it_compared(monkeypatch, engine):
    """The scraper rung reads the non-static peak, so this rung is reached at 300 allowed per
    minute, and "Frequency moderate (300/min)" was false."""
    verdict = _run(monkeypatch, **_shape(engine, ("150", "60", "180"), "400"))
    assert "Probable scraper" in verdict and "150 non-static req/min" in verdict, verdict
    assert "Frequency moderate" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_an_api_burst_in_a_mostly_static_window_is_not_static_traffic(monkeypatch, engine):
    """Peak 210, of which up to 150 non-static: at most 60 static requests in that minute."""
    rows = dict(_shape(engine, ("150", "3", "27"), "3"), frequency_static=[dict(ROW, peak_rpm="60")])
    verdict = _run(monkeypatch, frequency=[dict(ROW, peak_rpm="210")], **rows)
    assert "static-asset" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_the_control_a_static_minute_over_200_is_static_traffic(monkeypatch, engine):
    rows = dict(_shape(engine, ("150", "3", "27"), "3"), frequency_static=[dict(ROW, peak_rpm="210")])
    verdict = _run(monkeypatch, frequency=[dict(ROW, peak_rpm="360")], **rows)
    assert "static-asset traffic, not a bypass" in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_static_traffic_whose_api_burst_was_in_another_minute_is_still_named(monkeypatch, engine):
    """Peak 250 allowed and non-static peak 100, in different minutes: the busiest minute held 250
    static requests, and the overall peak minus the non-static one, 150, read it as mixed."""
    rows = dict(_shape(engine, ("100", "3", "54"), "3"), frequency_static=[dict(ROW, peak_rpm="250")])
    verdict = _run(monkeypatch, frequency=[dict(ROW, peak_rpm="250")], **rows)
    assert "static-asset traffic, not a bypass" in verdict, verdict


def test_a_failed_distinct_uri_count_is_said_in_the_static_verdict(monkeypatch):
    """The investigation shows no distinct-URI section, so the verdict is the only place to say it."""
    rows = _shape("cwl", None, "1")
    del rows["all_uris"]
    verdict = _run(monkeypatch, fail={"all_uris"}, **rows)
    assert "static-asset traffic" in verdict and "all_uris query timed out" in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_static_traffic_is_named_without_its_distinct_uri_count(monkeypatch, engine):
    """The rung's condition never reads the count, only its text does."""
    rows = _shape(engine, None, "1")
    del rows["all_uris"]
    verdict = _run(monkeypatch, fail={"all_uris"}, **rows)
    assert "static-asset traffic, not a bypass" in verdict and "distinct URIs" not in verdict, verdict


@pytest.mark.parametrize("engine", ["cwl", "athena"])
def test_a_middle_shape_does_not_say_which_of_nothing(monkeypatch, engine):
    verdict = _run(monkeypatch, **_shape(engine, None, "20"))
    assert "20 distinct URIs" in verdict and "cannot tell which" not in verdict, verdict


def _report(monkeypatch, **rows):
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    monkeypatch.setattr(B, "query_logs", lambda cwl, athena, s, e, limit=25, notes=None, label="", **kw:
                        rows.get(label, [dict(ROW)]))
    return B._step_investigate_ip("203.0.113.9", 0, 3600)


def test_no_allowed_request_is_not_called_a_partial_bypass(monkeypatch):
    """Any non-ALLOW count is more than five times 0, so the line said "partial bypass" beside
    "NO BYPASS: no request from this IP was allowed"."""
    report = _report(monkeypatch, actions=[dict(ROW, action="BLOCK", hits="120"), dict(ROW, action="CHALLENGE", hits="30")])
    assert "NO BYPASS" in report and "partial bypass" not in report, report


def test_the_control_a_few_allowed_among_many_blocked_is_a_partial_bypass(monkeypatch):
    report = _report(monkeypatch, actions=[dict(ROW, action="BLOCK", hits="600"), dict(ROW, action="ALLOW", hits="10")])
    assert "partial bypass" in report, report


def test_many_count_rules_are_counted_in_queries_under_the_length_limit(monkeypatch):
    """StartQuery rejects a query over 10,000 characters, measured 2026-10-16 with this query's own
    form: 10,000 ran and 10,001 was rejected. Every Count rule the WebACL configures is counted,
    whether this IP hit it or not, so 150 names went into one query and the section was lost. The
    limit applies after `_run_cwl` prefixes the WebACL filter, so the fake rejects on that length
    with the longest WebACL name there can be."""
    from tools.waf_query import scope_cwl_query
    names = [f"ATP-CustomRule-For-Tuning-{i:03d}" for i in range(150)]
    answer = _records([[names[0], names[75], names[149]]] * 3 + [[names[40]]])
    sent = []

    def cwl(query):
        sent.append(query)
        if len(scope_cwl_query(query, "w" * 128)) > 10_000:
            raise RuntimeError("InvalidParameterException: queryString failed to satisfy constraint")
        return answer(query)
    section, _ = _count_section(monkeypatch, "cwl", cwl=cwl, config=names)
    for n, hits in ((names[0], 3), (names[75], 3), (names[149], 3), (names[40], 1)):
        assert f"{n} ({hits} hits)" in section, section
    assert len(sent) > 2, "one counting query: the case does not exceed the limit, so it proves nothing"


def test_a_failed_later_counting_query_loses_the_section_rather_than_shortening_it(monkeypatch):
    """A list from the first query alone reads as every Count rule this IP hit."""
    names = [f"ATP-CustomRule-For-Tuning-{i:03d}" for i in range(150)]
    answer = _records([[names[0], names[149]]] * 3)

    def cwl(query):
        if "as c149" in query:
            raise RuntimeError("ThrottlingException: rate exceeded")
        return answer(query)
    section, seen = _count_section(monkeypatch, "cwl", cwl=cwl, config=names)
    assert not any("as c149" in q and re.search(r"as c0\b", q) for q in seen["cwl"]), "one query: nothing came after the first"
    assert "ThrottlingException" in section and names[0] not in section, section


class _LimitedCwl:
    """A Logs Insights client that applies StartQuery's length rule as measured 2026-10-16: the query
    string plus the ` | limit N` the API limit adds must fit in 10,000 characters (limit 2: 9,990 ran
    and 9,991 was rejected; limit 100000: 9,985 and 9,986). It answers from `answer(query)`."""

    def __init__(self, answer):
        self.answer, self.sent, self.rows = answer, [], {}

    def start_query(self, queryString, limit=None, **kw):
        size = len(queryString) + (len(f" | limit {limit}") if limit is not None else 0)
        self.sent.append(size)
        if size > 10_000:
            raise RuntimeError("InvalidParameterException: Query string must be less than or equal to 10000")
        qid = str(len(self.sent))
        self.rows[qid] = self.answer(queryString)
        return {"queryId": qid}

    def get_query_results(self, queryId):
        return {"status": "Complete", "statistics": {},
                "results": [[{"field": k, "value": v} for k, v in r.items()] for r in self.rows[queryId]]}


def test_the_count_queries_fit_the_limit_with_the_longest_webacl_name(monkeypatch):
    """Through `query_logs` and `_run_cwl` to the client, so the WebACL prefix and the limit suffix are
    the real ones. The budget first left out the suffix, which only a 119-character or longer WebACL
    name and a chunk filled to the last few characters reach, so this tries many configurations."""
    import random
    from tools import waf_count_eval as C
    from tools import waf_query as Q
    monkeypatch.setattr(Q, "get_log_destination", lambda: "arn:aws:logs:r:1:log-group:lg")
    monkeypatch.setattr(Q, "get_webacl_name", lambda: "w" * 128)
    monkeypatch.setattr(Q, "get_user_timezone", lambda: 0.0)
    monkeypatch.setattr(Q, "get_logs_region", lambda: "us-east-1")
    monkeypatch.setattr(Q, "POLL_INTERVAL", 0)
    monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")
    rng = random.Random(7)
    sizes = []
    for _ in range(40):
        names = sorted({"R" + "".join(rng.choice("abcdefghij-_") for _ in range(rng.randint(8, 60)))
                        for _ in range(160)})
        monkeypatch.setattr(C, "_get_all_count_rules", lambda region, scope, names=names: names)
        fake = _LimitedCwl(_records([[names[0], names[-1]]] * 2))
        monkeypatch.setattr(Q, "get_client", lambda *a, fake=fake, **k: fake)
        failures, notes = {}, {}
        hits = B._cwl_count_rules("203.0.113.9", 0, 3600, failures, notes)
        assert not failures, (max(fake.sent), failures)
        assert {"rule": names[-1], "hits": "2"} in hits, hits
        sizes += fake.sent
    assert max(sizes) > 9_985, f"no query came near the limit ({max(sizes)}), so this proves nothing"


def test_the_static_peak_reads_only_static_allowed_requests():
    import inspect
    src = inspect.getsource(B._step_investigate_ip)
    for name, frag in (("static_cwl", "CWL_ONLY_STATIC"), ("static_athena", "ATHENA_ONLY_STATIC")):
        body = src.split(f"{name} = (", 1)[1].split("\n    )", 1)[0]
        assert frag in body and "action = 'ALLOW'" in body, body
