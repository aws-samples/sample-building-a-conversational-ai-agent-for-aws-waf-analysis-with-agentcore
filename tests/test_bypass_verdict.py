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


@pytest.mark.parametrize("label", ["frequency", "uri_diversity", "user_agent"])
def test_a_failed_input_stops_the_verdict_instead_of_reading_as_zero(monkeypatch, label):
    """`peak 300` and `888 URIs` reach "Automated scraper" on their own, so each failure below has
    to be what stops it, and the reason has to name the query."""
    verdict = _run(monkeypatch, fail={label})
    assert "HIGH CONFIDENCE" not in verdict and "LIKELY" not in verdict, verdict
    assert "CANNOT DETERMINE" in verdict and label in verdict, verdict


def test_an_unread_input_a_rung_does_not_need_does_not_block_it(monkeypatch):
    """Frequency failed, but the IP carries no data-center signal, so the data-center rung is ruled
    out by what is known. The automation-UA rung needs no frequency and has to fire."""
    verdict = _run(monkeypatch, fail={"frequency"}, user_agent=[dict(ROW, ua="curl/8.4.0")])
    assert "automation UA allowed through" in verdict, verdict


def test_an_unparseable_peak_stops_the_verdict(monkeypatch):
    verdict = _run(monkeypatch, frequency=[dict(ROW, peak_rpm="n/a")])
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
    verdict = _run(monkeypatch, frequency=[dict(ROW, peak_rpm="n/a")])
    assert "CANNOT DETERMINE" in verdict and "not a number" in verdict, verdict
    assert "Re-run" not in verdict, verdict


def _count_section(monkeypatch, log_type, rows):
    monkeypatch.setattr(B, "get_log_type", lambda: log_type)
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    seen = {}

    def q(cwl, athena, start, end, limit=25, notes=None, label="", **kw):
        if label == "count_rules":
            seen["cwl"], seen["athena"] = cwl, athena
            return rows
        return [dict(ROW)]
    monkeypatch.setattr(B, "query_logs", q)
    report = B._step_investigate_ip("203.0.113.9", 0, 3600)
    return report.split("### COUNT Rules Triggered", 1)[1].split("###", 1)[0], seen


def test_the_count_rules_read_nested_entries_once_per_request(monkeypatch):
    """A managed sub-rule's Count is nested in `rulegrouplist`. Measured 2026-10-16 on
    `response-id-on-page`, 2026-10-01 to 10-16: 5 top-level COUNT entries against 2,142 nested, and
    the Athena query unnested only the top level, so TGT_TokenAbsent's Counts read "(none)"."""
    _, seen = _count_section(monkeypatch, "athena", [])
    athena = seen["athena"]
    assert "rulegrouplist" in athena and "rg.nonterminatingmatchingrules" in athena, athena
    assert "array_distinct(" in athena, "a group deployed twice would count each request twice"


def test_cloudwatch_says_it_lists_the_first_count_rule_only(monkeypatch):
    section, seen = _count_section(monkeypatch, "cwl", [dict(ROW, rule="TGT_TokenAbsent", hits="7")])
    assert "TGT_TokenAbsent (7 hits)" in section and "first Count rule only" in section, section
    assert '"nonTerminatingMatchingRules"' not in seen["cwl"], "the parse still needs the entry to open an array"


def test_the_control_athena_carries_no_first_rule_caveat(monkeypatch):
    section, _ = _count_section(monkeypatch, "athena", [dict(ROW, rule="TGT_TokenAbsent", hits="7")])
    assert "TGT_TokenAbsent (7 hits)" in section and "first Count rule only" not in section, section
