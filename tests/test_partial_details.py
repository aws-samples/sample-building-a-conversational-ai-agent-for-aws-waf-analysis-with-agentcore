# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A per-rule detail cell that failed has to say so, not come back as no rows.

ROADMAP 2.3's three poller-side gaps. All three had the same shape as the section-level one
already fixed: an absence standing in for two causes, so the report attributed everything to an
idle WebACL and told the user to go generate traffic.

**The carrier differs by gap, and that was the design question.** The section-keyed channel from
the earlier fix does not fit two of the three. `_poll_log_query` is called per rule per query
type, up to fifteen futures keyed `(rule_name, "ips"|"uris"|"content")`, so a failure there is one
*cell* of a per-rule table: folding it into a section-keyed reason either loses which rule it was
or lets one failure speak for five. Those cells reuse the `[{"_error": ...}]` sentinel row that
`_run_cwl` already established, which needs no new keying because the cell says which rule and
which query. `_get_log_details_athena`'s `table_msg` is not a section at all, and needed splitting
rather than keying: it was carrying an informational aside and a refusal explanation in one string.
"""

import json
import time

import pytest

from tools import query_limits as Q
from tools import report as R
from tools import waf_patrol as P


@pytest.fixture
def no_sleep(monkeypatch):
    """A fake clock, where sleeping advances time, so a 120 s budget costs no wall clock."""
    clock = {"t": 1_000.0}
    monkeypatch.setattr(time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    monkeypatch.setattr(time, "monotonic", lambda: clock["t"])


class FakeCwl:
    """A Logs Insights client whose query never leaves the status it is given."""

    def __init__(self, status, results=None):
        self.status, self.results, self.stopped = status, results or [], []

    def start_query(self, **_):
        return {"queryId": "q-1"}

    def get_query_results(self, queryId):
        return {"status": self.status, "results": self.results}

    def stop_query(self, queryId):
        self.stopped.append(queryId)
        return {"success": True}


# --- gap 3: patrol's poller returned [] ------------------------------------


def test_a_budget_exhausted_detail_query_says_so_instead_of_no_rows(no_sleep):
    """The headline defect. `[]` from a still-running query is indistinguishable from a rule that
    matched nothing, in a table whose only purpose is to show what a rule matched."""
    fake = FakeCwl("Running")
    rows = P._poll_log_query(fake, "lg", 0, 60, "fields @message")
    assert rows != []
    assert "_error" in rows[0]
    assert "did not finish" in rows[0]["_error"]
    assert "rather than for lack of matching requests" in rows[0]["_error"]
    assert fake.stopped == ["q-1"], "and the abandoned query is cancelled"


def test_an_engine_failure_is_distinguished_from_a_budget_timeout(no_sleep):
    """Two causes, two sentences. Both used to be `[]`."""
    timed_out = P._poll_log_query(FakeCwl("Running"), "lg", 0, 60, "q")[0]["_error"]
    failed = P._poll_log_query(FakeCwl("Failed"), "lg", 0, 60, "q")[0]["_error"]
    assert timed_out != failed
    assert "Failed" in failed


def test_a_terminal_status_is_not_stopped_because_there_is_nothing_to_stop(no_sleep):
    fake = FakeCwl("Cancelled")
    P._poll_log_query(fake, "lg", 0, 60, "q")
    assert fake.stopped == []


def test_a_raised_call_says_which_error(no_sleep):
    class Broken:
        def start_query(self, **_):
            raise ConnectionError("socket dropped")

    rows = P._poll_log_query(Broken(), "lg", 0, 60, "q")
    assert "ConnectionError" in rows[0]["_error"]


def test_a_completed_detail_query_still_returns_its_rows(no_sleep):
    """The control. The `_error` paths must not have swallowed the success path, which is how a
    fix that returns an error unconditionally would still pass everything above."""
    fake = FakeCwl("Complete", [[{"field": "cnt", "value": "9"}]])
    assert P._poll_log_query(fake, "lg", 0, 60, "q") == [{"cnt": "9"}]


# --- the fan-out: a raised future, and a cell that never arrived -----------


def test_a_future_that_raised_leaves_a_reason_in_its_own_cell(monkeypatch):
    """Keyed at the cell, not the section: five rules share this table and one failure must not
    speak for the other four."""
    def one_raises(logs_client, log_group, start, end, rule_name):
        if rule_name == "ruleA":
            raise RuntimeError("boom")
        return [{"ip": "1.2.3.4", "cnt": "9"}]

    for fn in ("_query_top_ips_by_rule", "_query_top_uris_by_rule", "_query_content_by_rule"):
        monkeypatch.setattr(P, fn, one_raises)

    details = P._get_log_details(object(), "lg", 0, 60, ["ruleA", "ruleB"])
    assert "_error" in details["ruleA"]["ips"][0]
    assert "RuntimeError" in details["ruleA"]["ips"][0]["_error"]
    # The precondition: the other rule really did succeed, so this is per-cell and not global.
    assert details["ruleB"]["ips"] == [{"ip": "1.2.3.4", "cnt": "9"}]


def test_a_batch_timeout_marks_the_cells_that_never_answered(monkeypatch):
    """`as_completed` giving up used to leave these cells absent, which the report then read as
    "this rule matched nothing"."""
    monkeypatch.setattr(P, "MAX_FANOUT_WAIT", 0.2)

    def hangs(logs_client, log_group, start, end, rule_name):
        time.sleep(3)  # real sleep: as_completed's timeout is real wall clock
        return [{"ip": "1.2.3.4", "cnt": "9"}]

    for fn in ("_query_top_ips_by_rule", "_query_top_uris_by_rule", "_query_content_by_rule"):
        monkeypatch.setattr(P, fn, hangs)

    details = P._get_log_details(object(), "lg", 0, 60, ["ruleA"])
    assert details, "the timeout path must still return the cells it knows about"
    reasons = {qtype: rows[0]["_error"] for qtype, rows in details["ruleA"].items()}
    assert set(reasons) == {"ips", "uris", "content"}
    for why in reasons.values():
        assert "had not answered" in why


# --- the layer between: a real detail query against a failing client -------


DETAIL_RULE = "SQLi_QUERYARGUMENTS"


def test_every_detail_query_hands_the_failure_on_instead_of_an_empty_cell(no_sleep):
    """The gap the two groups above leave between them, and it had a defect in it.

    The fan-out tests replace all three detail functions with fakes, so the real ones never run
    there and the `_error` row they check is injected by `_get_log_details`' own handler. The
    poller tests call `_poll_log_query` directly, one layer below. Nothing ran a real detail
    function against a failing client.

    `_query_content_by_rule` lost the reason in exactly that gap. It is the one detail query that
    parses its rows, and an `_error` row has no `@message`, so `json.loads("")` raised inside a
    loop whose `except Exception: continue` swallowed it, and the reason died in an empty
    `Counter`. Measured 2026-09-13 against a client answering `Failed`: `ips` and `uris` came back
    as `_error` rows and `content` came back `[]`, which the renderer reads as a rule that matched
    nothing. Swept over all three rather than fixed on the one, because the property is that the
    three cells of a row agree about what happened."""
    from tools.waf_query import inspection_location

    # The precondition, and it is load-bearing rather than decorative: `_query_content_by_rule`
    # returns `[]` without querying anything when the rule inspects the URI or is unknown, so
    # with the wrong rule name this test would pass while reaching no query at all.
    loc = inspection_location(DETAIL_RULE)
    assert loc and loc[1] != "uri", f"{DETAIL_RULE} no longer has a non-uri inspected location"

    for fn in (P._query_top_ips_by_rule, P._query_top_uris_by_rule, P._query_content_by_rule):
        rows = fn(FakeCwl("Failed"), "lg", 0, 60, DETAIL_RULE)
        assert rows, f"{fn.__name__} returned nothing, so a failed query reads as an idle rule"
        assert "_error" in rows[0], f"{fn.__name__} dropped the reason: {rows!r}"
        assert "rather than for lack of matching requests" in rows[0]["_error"]


def test_a_detail_query_that_answered_still_returns_its_content(no_sleep):
    """The control for the guard above. Returning the poller's rows before the parse rather than
    only on failure satisfies every assertion there and hands the renderer raw `@message` rows,
    which it prints as `[? hits]` with an empty payload."""
    message = json.dumps({"httpRequest": {"uri": "/login", "args": "id=1%20or%201=1",
                                          "headers": []}})
    fake = FakeCwl("Complete", [[{"field": "@message", "value": message}]])
    assert P._query_content_by_rule(fake, "lg", 0, 60, DETAIL_RULE) == [
        {"content": "id=1%20or%201=1", "cnt": 1}]


# --- gap 1: table_msg carried two different meanings ----------------------


@pytest.fixture
def athena_setup_fails(monkeypatch):
    """Make the helper's first step raise, offline.

    It imports from `tools.waf_athena` *inside* the function, so patching the source module is
    what takes effect. Patched rather than pointed at a nonexistent bucket, which is how this was
    written first: that version made real AWS calls and spent 15 seconds in botocore retries, so
    it was slow, needed credentials, and would have failed for the wrong reason anywhere else.
    """
    from tools import waf_athena

    def boom(*a, **k):
        raise LookupError("no such delivery stream")

    monkeypatch.setattr(waf_athena, "resolve_s3_log_path", boom)


def test_the_athena_helper_returns_named_fields_not_a_two_tuple(athena_setup_fails):
    """`(details, table_msg)` could not express "details are unavailable, and here is why"
    without overloading one of the two, which is what it did."""
    got = P._get_log_details_athena("dest", "acl", "CLOUDFRONT", "us-east-1", None, None, ["r"])
    assert set(got) == {"details", "table_msg", "unavailable"}


def test_a_setup_failure_says_why_instead_of_returning_an_empty_dict(athena_setup_fails):
    """The outer handler used to `return {}, None`, discarding the details already collected and
    any explanation."""
    got = P._get_log_details_athena("dest", "acl", "CLOUDFRONT", "us-east-1", None, None, ["r"])
    assert got["details"] == {}
    assert got["unavailable"], "a failure with no explanation is the defect"
    assert "LookupError" in got["unavailable"], "the engine error has to survive"
    assert "rather than for lack of matching requests" in got["unavailable"]


# --- gap 2: report's poller returned partial rows as if complete ----------


def test_the_report_poller_raises_rather_than_return_a_partial_count(no_sleep):
    """Insights hands back rows for a query still `Running`, so this returned a partial count the
    caller could not tell from a finished one: a wrong number presented as a right one. For a
    count that is worse than no number, and raising makes it impossible to mistake."""
    fake = FakeCwl("Running", [[{"field": "cnt", "value": "3"}]])
    with pytest.raises(R.QueryIncomplete) as e:
        R._poll_log_query(fake, "lg", 0, 60, "q")
    assert "did not finish" in str(e.value)
    assert "rather than because the WebACL was idle" in str(e.value)
    assert fake.stopped == ["q-1"]


def test_the_report_poller_raises_on_an_engine_failure_too(no_sleep):
    with pytest.raises(R.QueryIncomplete) as e:
        R._poll_log_query(FakeCwl("Failed"), "lg", 0, 60, "q")
    assert "Failed" in str(e.value)


def test_the_report_poller_still_answers_a_completed_query(no_sleep):
    """The control, and it covers all three return shapes, since a raise placed one line too
    early would break every caller rather than only the counting one."""
    rows = [[{"field": "cnt", "value": "7"}]]
    assert R._poll_log_query(FakeCwl("Complete", rows), "lg", 0, 60, "q") == 7
    assert R._poll_log_query(FakeCwl("Complete", rows), "lg", 0, 60, "q",
                             return_full=True) == {"cnt": "7"}
    assert R._poll_log_query(FakeCwl("Complete", rows), "lg", 0, 60, "q",
                             return_rows=True) == rows


def test_query_incomplete_is_caught_by_the_broad_handlers_that_already_exist():
    """Why raising is safe here at all. Every caller sits inside `except Exception`, so nothing
    crashes that did not already tolerate a failure. If this stopped being a subclass, three
    report sections would start propagating instead of degrading."""
    assert issubclass(R.QueryIncomplete, Exception)
    assert issubclass(R.QueryIncomplete, RuntimeError)


# --- the consumer has to surface a failed cell, not render it as rows ------


def test_an_error_cell_is_not_rendered_as_a_row_of_question_marks():
    """`{"_error": ...}` has none of the fields the row formatter reads, so rendering it as data
    printed "Top IPs: ? (?)" — the same lie the empty list told, only louder."""
    import inspect
    src = inspect.getsource(P.patrol_scan._tool_func)
    assert "_error" in src, "the detail renderer does not know about failed cells"
    assert "cell_errors" in src
