# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Allowed traffic from a cloud provider's addresses is a bypass signal, as data-center traffic is.

The scan and the investigation keyed the signal on `known_bot_data_center` only. Measured on
`test-webacl-s3`, 2026-09-08 03:19-03:29: a 12-host scraper fleet sent 90 allowed requests
each, 1,080 in all, every one labelled `signal:cloud_service_provider:aws`, none
`known_bot_data_center`, and none with a `bot:` label. So neither section saw it.
"""

import json
import re

import pytest

from tools import waf_bypass as B

FLEET = ["awswaf:managed:aws:bot-control:signal:cloud_service_provider:aws", "awswaf:managed:token:absent"]
DATA_CENTER = ["awswaf:managed:aws:bot-control:signal:known_bot_data_center"]
VERIFIED = FLEET + ["awswaf:managed:aws:bot-control:bot:verified"]
BROWSER = ["awswaf:managed:token:absent"]


def _scan_queries(monkeypatch):
    sent = {}

    def q(cwl, athena, start, end, limit=25, notes=None, label="", **kw):
        sent[label] = (cwl, athena)
        return []
    monkeypatch.setattr(B, "query_logs", q)
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    monkeypatch.setattr(B, "_check_coverage_gaps", lambda: [])
    B._step_scan(0, 3600)
    return sent["datacenter"]


def _cwl_selects(query, labels):
    """Evaluate the label part of the CloudWatch filter on one record's labels, as `lbls` holds them:
    the text between `"labels":[` and `]`."""
    lbls = ",".join(json.dumps({"name": n}, separators=(",", ":")) for n in labels)
    cond = re.search(r"filter action = 'ALLOW' and (.*?) \| ", query).group(1)
    expr = re.sub(r"lbls like '([^']*)'", lambda m: repr(m.group(1)) + " in lbls", cond)
    assert re.fullmatch(r"[\s()'a-z_:\-]*(?:(?:in lbls|and|or|not)[\s()'a-z_:\-]*)*", expr), expr
    return eval(expr, {}, {"lbls": lbls})


def _athena_selects(query, labels):
    """Evaluate the label conditions of the Athena WHERE on one record's labels."""
    where = query.split("AND action = 'ALLOW'", 1)[1].split(" GROUP BY", 1)[0]
    like = lambda p: any(re.fullmatch(p.replace("%", ".*"), n) for n in labels)
    expr = re.sub(r"\( labels IS NULL OR none_match\(labels, l -> l\.name LIKE '([^']*)'\) \)",
                  lambda m: f"(not {like(m.group(1))})", where)
    expr = re.sub(r"any_match\(labels, l -> l\.name LIKE '([^']*)'\)", lambda m: str(like(m.group(1))), expr)
    expr = expr.replace(" AND ", " and ").replace(" OR ", " or ").strip()
    expr = expr[len("and "):] if expr.startswith("and ") else expr
    assert re.fullmatch(r"[\s()andortTrueFalse]*", expr), expr
    return eval(expr)


@pytest.mark.parametrize("labels,expected", [(FLEET, True), (DATA_CENTER, True), (VERIFIED, False), (BROWSER, False)])
def test_the_scan_selects_cloud_provider_and_data_center_traffic(monkeypatch, labels, expected):
    """The verified and unlabelled rows are the controls: the filter still excludes what Bot Control
    identified, and still needs a hosting signal."""
    cwl, athena = _scan_queries(monkeypatch)
    assert _cwl_selects(cwl, labels) is expected, cwl
    assert _athena_selects(athena, labels) is expected, athena


ROW = {"total": "999", "unique_uris": "5", "hits": "999", "cnt": "999", "action": "ALLOW", "Labels": "",
       "ja4Fingerprint": "t13d1516h2", "ua": "Mozilla/5.0", "rule": "SomeRule", "peak_rpm": "60",
       "avg_rpm": "30", "country": "US"}


def _verdict(monkeypatch, labels, **rows):
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    rows = {"labels": [dict(ROW, Labels=json.dumps([{"name": n} for n in labels]))] if labels else [],
            "frequency_static": [], **rows}
    monkeypatch.setattr(B, "query_logs", lambda cwl, athena, s, e, limit=25, notes=None, label="", **kw:
                        rows.get(label, [dict(ROW)]))
    report = B._step_investigate_ip("203.0.113.9", 0, 3600)
    return report.split("## Directional Judgment")[1].split("## Confidence Rules")[0]


def test_an_unclassified_ip_on_a_cloud_provider_is_a_likely_undetected_bot(monkeypatch):
    """A host of the fleet: 90 allowed requests to 80 URIs at a peak of 12 a minute, measured on
    Athena. "Probable scraper" would catch it too, without naming the provider."""
    verdict = _verdict(monkeypatch, FLEET, frequency=[dict(ROW, peak_rpm="12")],
                       frequency_dynamic=[dict(ROW, peak_rpm="12")], actions=[dict(ROW, hits="90")],
                       uri_diversity=[dict(ROW, unique_uris="80")])
    assert "LIKELY: Undetected automation from a cloud provider (aws)" in verdict, verdict
    assert "HIGH CONFIDENCE" not in verdict and "office or VPN egress" in verdict, verdict


@pytest.mark.parametrize("allowed,uris,peak", [("60", "25", "8"), ("1500", "40", "30")], ids=["one-person", "office"])
def test_the_control_people_browsing_from_a_cloud_address_are_undetermined(monkeypatch, allowed, uris, peak):
    """An Amazon office egress on `test-webacl-cwl` carries `cloud_service_provider:aws` and real
    browsers. A browsing session passes 50 requests easily, which is why the bar is URIs."""
    verdict = _verdict(monkeypatch, FLEET, frequency=[dict(ROW, peak_rpm=peak)],
                       frequency_dynamic=[dict(ROW, peak_rpm=peak)], actions=[dict(ROW, hits=allowed)],
                       uri_diversity=[dict(ROW, unique_uris=uris)])
    assert "automation" not in verdict and "CANNOT DETERMINE" in verdict, verdict


def test_the_control_the_same_ip_without_the_signal_is_a_scraper_with_no_provider(monkeypatch):
    """The fleet host's shape with the label taken away: the URI bar alone is the scraper rung's."""
    verdict = _verdict(monkeypatch, BROWSER, frequency_dynamic=[dict(ROW, peak_rpm="12")],
                       uri_diversity=[dict(ROW, unique_uris="80")])
    assert "cloud provider" not in verdict and "LIKELY: Probable scraper" in verdict, verdict


def test_a_data_center_ip_is_still_the_high_confidence_rung(monkeypatch):
    verdict = _verdict(monkeypatch, DATA_CENTER)
    assert "HIGH CONFIDENCE: Undetected bot from data center" in verdict, verdict



@pytest.mark.parametrize("provider", ["fastly", "newcdn"])
def test_any_provider_is_named_with_the_cdn_reading_whatever_rung_spoke(monkeypatch, provider):
    """The provider is read off the label, never from a list: `newcdn` is a name no version uses.
    A CDN or proxy egress at scraper volume reaches the HIGH rung before the provider one, so the
    caveat goes after whichever rung spoke."""
    labels = [f"awswaf:managed:aws:bot-control:signal:cloud_service_provider:{provider}"]
    verdict = _verdict(monkeypatch, labels, frequency_dynamic=[dict(ROW, peak_rpm="300")],
                       uri_diversity=[dict(ROW, unique_uris="80")])
    assert "HIGH CONFIDENCE: Automated scraper" in verdict, verdict
    assert f"signal:cloud_service_provider:{provider}. If that is a CDN or proxy service" in verdict, verdict


def test_the_control_no_provider_no_cdn_reading(monkeypatch):
    verdict = _verdict(monkeypatch, BROWSER, frequency_dynamic=[dict(ROW, peak_rpm="300")],
                       uri_diversity=[dict(ROW, unique_uris="80")])
    assert "CDN or proxy" not in verdict, verdict


def test_analyze_ip_names_the_provider_too():
    from tools.waf_logs import _interpret_ip_labels
    out = _interpret_ip_labels([{"Labels": '[{"name":"awswaf:managed:aws:bot-control:signal:cloud_service_provider:newcdn"}]'}])
    assert "cloud provider address (newcdn)" in out and "CDN or proxy" in out, out
