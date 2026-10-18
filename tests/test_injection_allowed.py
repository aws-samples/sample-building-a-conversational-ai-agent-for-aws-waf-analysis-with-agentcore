"""`investigate_injection` reports what got through, not only what was blocked. ROADMAP 7.14.

It found sources only through detector matches, so a source whose payloads all passed every rule was
never a source, and its profile covered the attack's window only, while reconnaissance comes first.
Two sections now follow the source profile: everything the source IPs were allowed, from as far before
the window as the query cap leaves, and allowed requests with a query string on the paths the attack
targeted, from any IP. Live on the CloudWatch test WebACL, 2026-10-13: a sensitive-path probe's allowed
requests included `/.git/config`, `/.ssh/id_rsa` and `/wp-config.php`, which no blocked-traffic view
shows.

Both go through aggregate_logs, so an empty answer says why the way every aggregate does: a Log Filter
that drops ALLOW makes "nothing allowed" a filtering artefact, not a fact, and the log-path cross-check
runs. A first version queried directly and lost both; under a Log Filter keeping only BLOCK and COUNT
it would have said "(none: nothing they sent was allowed)".
"""

import json

from tools import waf_injection as I
from tools.query_limits import MAX_MINUTES

START = "2026-09-08T03:30"


def _run(monkeypatch, ips, paths, duration=60):
    monkeypatch.setattr("tools.session_state.get_user_timezone", lambda: 0)
    calls = []

    def agg(**kw):
        calls.append(kw)
        return f"<table {kw['group_by']}>"
    out = "\n".join(I._allowed_sections(agg, ips, paths, START, duration))
    return out, calls


def test_the_sources_are_read_from_before_the_window_up_to_the_cap(monkeypatch):
    out, calls = _run(monkeypatch, ["203.0.113.10"], [])
    (call,) = calls
    assert call["start_time"] == "2026-09-07T22:30" and call["duration_minutes"] == MAX_MINUTES, call
    assert call["group_by"] == "clientIp,uri", call
    assert json.loads(call["filter_by"]) == {"ip": ["203.0.113.10"], "action": "ALLOW"}, call
    assert "5h00 before the window" in out, out


def test_a_window_at_the_cap_has_no_lookback(monkeypatch):
    out, calls = _run(monkeypatch, ["203.0.113.10"], [], duration=MAX_MINUTES)
    assert calls[0]["start_time"] == START and "0h00 before" in out, (calls, out)


def test_at_most_five_sources_and_only_addresses_reach_the_query(monkeypatch):
    ips = [f"203.0.113.{i}" for i in range(1, 8)]
    out, calls = _run(monkeypatch, ["not-an-ip"] + ips, [])
    assert json.loads(calls[0]["filter_by"])["ip"] == ips[:5], calls
    assert "the top 5" in out


def test_the_target_paths_are_read_with_their_query_strings(monkeypatch):
    out, calls = _run(monkeypatch, [], ["/search", "/login"])
    (call,) = calls
    assert call["group_by"] == "clientIp,uri,args" and call["start_time"] == START, call
    assert json.loads(call["filter_by"]) == {"uri": ["/search", "/login"], "action": "ALLOW"}, call


def test_a_path_the_filter_refuses_is_left_out_and_named(monkeypatch):
    out, calls = _run(monkeypatch, [], ["/search", "/x'y", "/a b"])
    assert json.loads(calls[0]["filter_by"])["uri"] == ["/search"], calls
    assert "2 target path(s) not queried" in out, out


def test_the_tables_are_the_aggregates_own(monkeypatch):
    """The empty-answer handling is aggregate_logs': nothing here writes its own "none"."""
    out, _ = _run(monkeypatch, ["203.0.113.10"], ["/search"])
    assert "<table clientIp,uri>" in out and "<table clientIp,uri,args>" in out
    assert "(none" not in out, out


def test_the_investigation_runs_both_sections():
    """Wired after the source profile with the tool's own tables, not suggested in the output."""
    import inspect
    src = inspect.getsource(I.investigate_injection._tool_func)
    assert "lines += _allowed_sections(aggregate_logs._tool_func, ips, _extract_column(paths, \"httpRequest.uri\")," in src
