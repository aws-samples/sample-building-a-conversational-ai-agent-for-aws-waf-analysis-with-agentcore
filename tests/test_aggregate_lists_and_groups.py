"""aggregate_logs takes a list per filter, an exact-path `uri` filter, several group dimensions, and the
query string as a dimension. ROADMAP 7.14.

Added so `investigate_injection`'s allowed-traffic sections go through the primitive: five source IPs
and five target paths are two queries, not ten, and an empty answer says why the way every aggregate
does. The first version of those sections queried directly and lost the Log Filter warning and the
log-path cross-check: under a Log Filter keeping only BLOCK and COUNT it would have said "nothing they
sent was allowed", which no allowed request could ever have contradicted.
"""

import json

import pytest

from tools import waf_aggregate as AG
from tools import waf_query as Q


def _filters(obj):
    return AG._parse_filters(json.dumps(obj))


# --- lists -----------------------------------------------------------------------------------------

def test_a_list_of_values_is_any_of_them_on_both_engines():
    f, bad = _filters({"ip": ["203.0.113.1", "203.0.113.2"]})
    assert bad is None and f == {"ip": ("203.0.113.1", "203.0.113.2")}, (f, bad)
    cwl, athena = AG._build("uri", "count", f, 5, 25)
    assert "(httpRequest.clientIp = '203.0.113.1' or httpRequest.clientIp = '203.0.113.2')" in cwl, cwl
    assert "(httprequest.clientip = '203.0.113.1' OR httprequest.clientip = '203.0.113.2')" in athena, athena


def test_one_bad_value_refuses_the_whole_filter():
    f, bad = _filters({"ip": ["203.0.113.1", "x' OR '1'='1"]})
    assert bad and f == {}, (f, bad)


@pytest.mark.parametrize("values", [[], [f"203.0.113.{i}" for i in range(AG._FILTER_VALUES_MAX + 1)]])
def test_a_list_is_bounded(values):
    f, bad = _filters({"ip": values})
    assert bad and "give 1 to" in bad and f == {}, (f, bad)


def test_a_list_keeps_the_by_value_predicates():
    """`action: ["COUNT", "BLOCK"]` is the nested-COUNT predicate OR the top-level one, not two copies
    of the template."""
    f, _ = _filters({"action": ["COUNT", "BLOCK"]})
    cwl, athena = AG._build("uri", "count", f, 5, 25)
    assert "action = 'BLOCK'" in cwl and "\"action\":\"COUNT\"" in cwl, cwl


def test_a_single_value_is_unchanged():
    assert _filters({"ip": "203.0.113.1"})[0] == {"ip": "203.0.113.1"}


# --- uri -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,ok", [("/search", True), ("/a%20b/c.json", True), ("/x'y", False),
                                     ('/a"b', False), ("/a b", False), ("/a;b", False), ("/a\\b", False)])
def test_the_uri_filter_takes_a_path_and_nothing_that_leaves_a_literal(path, ok):
    f, bad = _filters({"uri": path})
    assert (bad is None) is ok, (path, f, bad)


# --- several dimensions ----------------------------------------------------------------------------

def test_two_dimensions_are_one_row_per_pair_on_both_engines():
    cwl, athena = AG._build("clientIp,uri", "count", {}, 5, 25)
    assert "by httpRequest.clientIp, httpRequest.uri" in cwl, cwl
    assert 'httprequest.clientip AS "httpRequest.clientIp", httprequest.uri AS "httpRequest.uri", count(*) AS hits' in athena
    assert "GROUP BY httprequest.clientip, httprequest.uri" in athena, athena


@pytest.mark.parametrize("group_by,metric,why", [
    ("clientIp,label", "count", "metric='count' only"), ("clientIp,time_bucket", "count", "metric='count' only"),
    ("clientIp,uri", "ratio", "metric='count' only"), ("clientIp,uri", "percentile", "metric='count' only"),
    ("clientIp,uri,ua,host", "count", "up to 3 different"), ("uri,uri", "count", "up to 3 different")])
def test_several_dimensions_are_refused_where_they_have_no_answer(group_by, metric, why):
    """By reason, not by an `Error:` prefix: with no log destination any later step errors too."""
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", group_by=group_by, metric=metric,
                                       filter_by='{"rule": "X"}')
    assert why in out, out


def test_an_unknown_name_among_several_is_refused_by_name():
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", group_by="clientIp,url")
    assert "'url' is not a group_by dimension" in out, out


# --- args ------------------------------------------------------------------------------------------

def test_args_leaves_out_requests_without_a_query_string_on_both_engines():
    cwl, athena = AG._build("args", "count", {}, 5, 25)
    assert "ispresent(httpRequest.args) and httpRequest.args != ''" in cwl, cwl
    assert "httprequest.args <> ''" in athena, athena


@pytest.mark.parametrize("metric", ["ratio", "percentile"])
def test_args_is_for_counts_only(metric):
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", group_by="args", metric=metric,
                                       filter_by='{"rule": "X"}')
    assert out.startswith("Error:") and "count" in out, out


@pytest.fixture
def run(monkeypatch):
    def go(rows, group_by="args", filter_by="", log_filter=False):
        monkeypatch.setattr(Q, "get_log_type", lambda: "cwl")
        monkeypatch.setattr(Q, "check_coarse_partition_block", lambda: None)
        monkeypatch.setattr(Q, "query_logs", lambda *a, **k: rows)
        monkeypatch.setattr(AG, "is_log_filter_active", lambda: log_filter)
        monkeypatch.setattr("tools.waf_metrics.log_path_warning", lambda *a, **k: "\n<log-path witness>")
        return AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", duration_minutes=60,
                                           group_by=group_by, filter_by=filter_by)
    return go


def test_a_query_string_is_masked_when_rendered(run):
    out = run([{"httpRequest.args": "user=a&password=hunter2secret", "hits": "3"}])
    assert "hunter2secret" not in out and "password=" in out and "HINT:" in out, out


def test_an_attack_payload_in_a_query_string_stays_visible(run):
    out = run([{"httpRequest.args": "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "hits": "3"}])
    assert "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" in out and "HINT:" not in out, out


# --- the defect this was built to close --------------------------------------------------------------

def test_the_injection_sources_section_under_a_log_filter_does_not_say_nothing_was_allowed(run, monkeypatch):
    from tools import waf_injection as I
    monkeypatch.setattr("tools.session_state.get_user_timezone", lambda: 0)
    calls = []

    def agg(**kw):
        calls.append(kw)
        return run([], group_by=kw["group_by"], filter_by=kw["filter_by"], log_filter=True)
    out = "\n".join(I._allowed_sections(agg, ["203.0.113.10"], ["/search"], "2026-09-10T03:00", 60))
    assert len(calls) == 2, calls
    assert out.count("A Log Filter is active") == 2 and out.count("<log-path witness>") == 2, out
    assert "nothing they sent was allowed" not in out, out
