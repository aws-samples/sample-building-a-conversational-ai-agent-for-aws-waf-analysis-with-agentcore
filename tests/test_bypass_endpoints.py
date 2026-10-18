"""The bypass scan marks many sources on one endpoint. ROADMAP 7.14.

Every scan signal was per IP, and the one aggregate signal, a JA4 across many IPs, needs 50 URIs. So a
credential-stuffing run spread over a few hosts was invisible and the scan said nothing about it: on
2026-10-16 on the S3 test WebACL, 6 IPs sent 816 allowed requests to POST /login, 136 each, under every
per-IP threshold. The endpoint section counts sources per path and method and sets them against the
same window a week earlier.

What it says matters as much as what it marks, because the model reads the output, not ROADMAP: the
condition with its numbers and where they were measured, every time; "no IPs a week earlier" only when a
marked endpoint had none; and "a few more sources do not mark a busy endpoint" only when an endpoint that
already had many was not marked. A week-earlier window holding no log at all (a log group kept for less
than a week) would read as zero on every endpoint and mark them all, so it is checked first.
"""

import pytest

from tools import waf_bypass as B

START, END = 1_792_000_000, 1_792_003_600
WEEK = 7 * 86400


def ep(uri, method, total, ips):
    return {"httpRequest.uri": uri, "httpRequest.httpMethod": method, "total": str(total), "unique_ips": str(ips)}


def _section(monkeypatch, rows, before=(), logged=1000, fail=()):
    sent = []

    def q(cwl, athena, s, e, limit=25, notes=None, label="", **kw):
        sent.append((label, cwl, athena, s, e))
        if label in fail:
            raise RuntimeError(f"{label} timed out")
        if label == "endpoints_logged":
            return [{"n": str(logged)}]
        if label == "endpoints_before":
            return [{"httpRequest.uri": u, "httpRequest.httpMethod": m, "unique_ips": str(n)} for u, m, n in before]
        return []
    monkeypatch.setattr(B, "query_logs", q)
    failures = {"endpoints": "timed out"} if "endpoints" in fail else {}
    lines, marked = B._endpoint_section(rows, START, END, failures, {})
    return "\n".join(lines), marked, sent


LOGIN = ep("/login", "POST", 816, 6)


def test_the_credential_stuffing_run_is_marked(monkeypatch):
    out, marked, _ = _section(monkeypatch, [LOGIN])
    assert marked and "| POST   | /login" in out and "|                  0 | yes" in out, out
    assert "either new or newly attacked" in out, out
    assert "does not rule out distributed abuse" not in out, out


@pytest.mark.parametrize("row", [ep("/login", "POST", B.ENDPOINT_MIN_REQUESTS - 1, 6),
                                 ep("/login", "POST", 816, B.ENDPOINT_MIN_IPS - 1)])
def test_below_either_floor_nothing_is_marked(monkeypatch, row):
    out, marked, _ = _section(monkeypatch, [row])
    assert not marked and "newly attacked" not in out, out


def test_growth_marks_and_less_growth_does_not(monkeypatch):
    _, marked, _ = _section(monkeypatch, [LOGIN], before=[("/login", "POST", 2)])
    assert marked
    out, marked, _ = _section(monkeypatch, [LOGIN], before=[("/login", "POST", 3)])
    assert not marked and "newly attacked" not in out, out
    assert "does not rule out distributed abuse" not in out, "3 IPs a week earlier is not a busy endpoint"


def test_a_busy_endpoint_says_a_few_more_sources_do_not_mark_it(monkeypatch):
    out, marked, _ = _section(monkeypatch, [ep("/login", "POST", 9000, 60)], before=[("/login", "POST", 50)])
    assert not marked and "does not rule out distributed abuse on it" in out, out
    assert "newly attacked" not in out


def test_a_week_earlier_holding_no_log_marks_nothing_and_says_why(monkeypatch):
    out, marked, _ = _section(monkeypatch, [LOGIN], logged=0)
    assert not marked and "comparison cannot run" in out and "|                n/a |" in out, out


@pytest.mark.parametrize("label", ["endpoints_before", "endpoints_logged"])
def test_a_failed_baseline_read_marks_nothing(monkeypatch, label):
    out, marked, _ = _section(monkeypatch, [LOGIN], fail=(label,))
    assert not marked and "UNKNOWN, the query for this section failed" in out, out


def test_a_failed_endpoint_query_is_unknown_not_none(monkeypatch):
    out, marked, _ = _section(monkeypatch, [], fail=("endpoints",))
    assert not marked and "UNKNOWN" in out and "no endpoint drew" not in out, out


def test_a_path_a_quote_could_break_out_of_is_not_compared(monkeypatch):
    out, marked, sent = _section(monkeypatch, [LOGIN, ep("/x'y", "GET", 900, 9)])
    before = next(t for t in sent if t[0] == "endpoints_before")
    assert "x'y" not in before[1] and "x'y" not in before[2], before
    assert "1 endpoint(s) not compared" in out and marked, out


def test_the_condition_is_stated_with_its_numbers_every_time(monkeypatch):
    rule = (f"at least {B.ENDPOINT_MIN_IPS} IPs and {B.ENDPOINT_MIN_REQUESTS} allowed requests, and "
            f"{B.ENDPOINT_IP_GROWTH} times the distinct IPs")
    for rows, kw in (([LOGIN], {}), ([], {}), ([LOGIN], {"logged": 0}), ([], {"fail": ("endpoints",)})):
        out, *_ = _section(monkeypatch, rows, **kw)
        assert rule in out and "measured only on low-traffic test WebACLs" in out, out


def test_the_baseline_is_the_same_window_a_week_earlier(monkeypatch):
    _, _, sent = _section(monkeypatch, [LOGIN])
    reads = {label: (s, e) for label, _, _, s, e in sent}
    assert reads["endpoints_before"] == reads["endpoints_logged"] == (START - WEEK, END - WEEK), reads


def test_verified_bots_are_left_out_now_and_a_week_earlier(monkeypatch):
    """Route 53 health checks are `bot:verified` and hit / from 16 IPs every hour."""
    _, _, sent = _section(monkeypatch, [LOGIN])
    cwl, athena = next((c, a) for label, c, a, *_ in sent if label == "endpoints_before")
    assert "bot:verified" in cwl and "bot:verified" in athena   # the current window's: the test below


def test_the_scan_counts_a_marked_endpoint_as_a_candidate(monkeypatch):
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    monkeypatch.setattr(B, "_check_coverage_gaps", lambda: [])

    def q(cwl, athena, s, e, limit=25, notes=None, label="", **kw):
        if label == "endpoints":
            assert "bot:verified" in cwl and "bot:verified" in athena
            return [dict(LOGIN)]
        if label == "endpoints_logged":
            return [{"n": "1000"}]
        return []
    monkeypatch.setattr(B, "query_logs", q)
    out = B._step_scan(START, END)
    assert "No Obvious Bypass Candidates Found" not in out, out
    assert "A marked endpoint → ask whether it is new" in out, out
