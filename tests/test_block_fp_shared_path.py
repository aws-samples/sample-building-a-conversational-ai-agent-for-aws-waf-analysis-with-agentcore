# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Before an exception is proposed for a false positive, the investigation shows who else the rule
blocks on the same paths.

The investigation handed a confirmed false positive to scope-down design with no look at what else
the rule matched there. Measured on `test-webacl-s3`, 2026-09-08: the false-positive user
took 2 SQLi blocks on `/search` at 03:58, and 10 scanners took 60 more on `/search` at
04:03-04:04. An exception for `/search` lets those 60 through with the user's 2.
"""

import pytest

from tools import waf_block_fp as F

FP = "198.51.100.30"
SQLI = "AWS-AWSManagedRulesSQLiRuleSet"
BASE = dict(rule_id=SQLI, rule_type="MANAGED_RULE_GROUP", sub_rule="SQLi_QUERYARGUMENTS", allow_count=500,
            block_count=2, total=502, peak_rpm="1", avg_rpm="1", rules_triggered=1,
            uri_results=[{"httpRequest.uri": "/search", "httpRequest.httpMethod": "GET", "hits": "2"},
                         {"httpRequest.uri": "/help", "httpRequest.httpMethod": "GET", "hits": "1"}],
            match_detail=[], match_detail_note="", text_transforms=[], insp_label=None, insp_samples=None,
            insp_masked=False)


def _shared(monkeypatch, rows=None, fail=None):
    sent = []

    def run(cwl, athena, start, end, limit=25):
        sent.append((cwl, athena, start, end))
        if fail:
            raise RuntimeError(fail)
        return rows or []
    monkeypatch.setattr(F, "_run_query", run)
    out = F._shared_path_blocks(FP, SQLI, "SQLi_QUERYARGUMENTS", 1000, 4600)
    return out, sent


def test_other_ips_blocked_on_the_same_path_are_counted_by_the_same_sub_rule(monkeypatch):
    """`seen` counts the IP itself, which every row holds, since only its own paths are kept."""
    (shared, reason), sent = _shared(monkeypatch, [{"httpRequest.uri": "/search", "own": "2", "hits": "60", "seen": "11"},
                                                   {"httpRequest.uri": "/help", "own": "1", "hits": "0", "seen": "1"}])
    assert reason == "" and shared == {"/search": (60, 10), "/help": (0, 0)}, shared
    cwl, athena, start, end = sent[0]
    assert f"sum(if(httpRequest.clientIp != '{FP}', 1, 0)) as hits" in cwl and f"terminatingRuleId = '{SQLI}'" in cwl, cwl
    assert "filter sub_rule = 'SQLi_QUERYARGUMENTS'" in cwl and "| filter own > 0" in cwl, cwl
    assert f"count_if(httprequest.clientip <> '{FP}') as hits" in athena and "= 'SQLi_QUERYARGUMENTS'" in athena, athena
    assert f"HAVING count_if(httprequest.clientip = '{FP}') > 0" in athena, athena
    # Widened to the query window cap around the hour asked for, 2.5 hours either side.
    assert start == 1000 - 9000 and end == 4600 + 9000, (start, end)


def test_a_window_ending_now_looks_further_back_rather_than_less(monkeypatch):
    """Centered on the last hour, half the widening would fall in the future."""
    import time
    sent = []
    monkeypatch.setattr(F, "_run_query", lambda cwl, athena, start, end, limit=25: sent.append((start, end)) or [])
    now = int(time.time())
    F._shared_path_blocks(FP, SQLI, "SQLi_QUERYARGUMENTS", now - 3600, now)
    start, end = sent[0]
    assert end - start >= F.MAX_MINUTES * 60 and end <= int(time.time()), (start, end, now)


def test_the_render_warns_that_an_exception_for_the_path_lets_the_others_through():
    out = F._render_investigation(FP, 0, 3600, dict(BASE, shared_paths=({"/search": (60, 10), "/help": (0, 0)}, "")))
    section = out.split("### Other traffic this rule blocks on these paths", 1)[1].split("###", 1)[0]
    assert "/search: 60 blocks from 10 other IPs" in section and "/help: no other IP" in section, section
    assert "would also let those requests through" in section, section
    assert "Other traffic this rule blocks on these paths" in out.split("## Your Next Action", 1)[1]


def test_other_ips_blocks_are_shown_whatever_the_distinct_count_says():
    """`count_distinct` is approximate on CloudWatch, so `seen` may undercount; the blocks decide."""
    out = F._render_investigation(FP, 0, 3600, dict(BASE, shared_paths=({"/search": (60, 0)}, "")))
    assert "/search: no other IP" not in out and "would also let those requests through" in out, out


def test_the_control_no_other_ip_carries_no_warning():
    out = F._render_investigation(FP, 0, 3600, dict(BASE, shared_paths=({"/search": (0, 0), "/help": (0, 0)}, "")))
    assert "would also let those requests through" not in out, out


def test_a_failed_look_says_so_and_keeps_the_rest(monkeypatch):
    (shared, reason), _ = _shared(monkeypatch, fail="ThrottlingException")
    assert shared is None and "ThrottlingException" in reason
    out = F._render_investigation(FP, 0, 3600, dict(BASE, shared_paths=(None, reason)))
    assert "UNKNOWN" in out and "ThrottlingException" in out and "## Directional Judgment" in out, out
