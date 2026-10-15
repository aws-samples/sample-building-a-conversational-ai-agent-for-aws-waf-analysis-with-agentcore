# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The challenge check reports an Anti-DDoS event only on the label that declares one.

It counted any `anti-ddos` text: Athena `LIKE '%anti-ddos%'` over label names, CloudWatch an
unanchored `@message like 'anti-ddos'` that also matches a URI or a header. Measured 2026-10-15 on
`shield-sample-webacl`, 14 days: 640,593 records matched that, every one of them carrying
`awswaf:managed:aws:anti-ddos:challengeable-request`, which AMR applies to the requests it evaluates,
and 0 carried `event-detected`. So every challenge check on a WebACL with the AMR said "Anti-DDoS
event detected ... ChallengeAllDuringEvent was likely active" through a fortnight with no event.
"""

from tools import waf_challenge_check as W

EVENT = "awswaf:managed:aws:anti-ddos:event-detected"


def _run(monkeypatch, labels_present):
    """`labels_present` are the anti-ddos labels the fake log holds. A query counts a hit only if
    the label it names exactly is among them, which is how the two filters differ in reality."""
    monkeypatch.setattr(W, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(W, "get_log_type", lambda: "cwl")
    from tools import waf_query
    monkeypatch.setattr(waf_query, "check_coarse_partition_block", lambda: None)
    seen = []

    def q(cwl, athena, start, end, limit=25, **kw):
        seen.append((cwl, athena))
        if "anti-ddos" in cwl:
            exact = [l for l in labels_present if f'"name":"{l}"' in cwl and f"l.name = '{l}'" in athena]
            loose = "LIKE '%anti-ddos%'" in athena and labels_present
            return [{"hits": "640593" if (exact or loose) else "0"}]
        return [{"httpRequest.uri": "/", "httpRequest.httpMethod": "GET", "hits": "5"}]
    monkeypatch.setattr(W, "query_logs", q)
    out = W.check_challenge_compatibility._tool_func(start_time="2026-10-01T00:00", duration_minutes=60)
    return out, [s for s in seen if "anti-ddos" in s[0]]


def test_challengeable_request_labels_are_not_an_event(monkeypatch):
    out, ddos = _run(monkeypatch, ["awswaf:managed:aws:anti-ddos:challengeable-request"])
    assert ddos, "the Anti-DDoS check never ran, so this proves nothing"
    assert "Anti-DDoS event detected" not in out, out


def test_an_event_detected_label_is_still_reported(monkeypatch):
    out, _ = _run(monkeypatch, [EVENT])
    assert "Anti-DDoS event detected" in out, out


def test_both_dialects_name_the_event_label_exactly(monkeypatch):
    _, ddos = _run(monkeypatch, [])
    (cwl, athena), = ddos
    assert f"@message like '\"name\":\"{EVENT}\"'" in cwl, cwl
    assert f"l.name = '{EVENT}'" in athena and "LIKE" not in athena, athena
