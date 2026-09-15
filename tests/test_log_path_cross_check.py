# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""An empty answer about an IP, URI, User-Agent or JA4 is not evidence the subject was quiet.

ROADMAP 7.7 item 1's second group. The first group works because a metric shares the tool's subject: ask
about a rule and `BlockedRequests` on that rule answers. **No metric dimension covers an IP, a URI, a
User-Agent or a JA4**, so for `analyze_ip`, `investigate_block_fp`, `detect_bypass` and `aggregate_logs`
there is no witness with the same subject.

What is answerable is a different question, "was the log path returning rows at all in this window", and it
takes two witnesses: the WebACL-level metric for the action, and one control log query with the subject
filter removed. **Either one alone is wrong**, which is measured rather than argued. On 2026-09-08
12:00-13:00 UTC the narrow query returned 0 rows, the control returned 0 rows and the metric returned no
datapoints: the hour was genuinely quiet, so a control-only check would flag every idle window as a broken
path.

Reproduced against the account 2026-09-15, matching what ROADMAP 7.7 recorded a fortnight earlier:

    2026-09-08 12:00-13:00 UTC   metric 0        control 0        silent
    2026-09-08 11:00-12:00 UTC   metric 1        control 1        silent
    2026-09-08 04:00-06:00 UTC   metric 566,070  control 566,070  silent

**The firing cell is reachable here too, and the first draft of this file said it was not.** 2025-08-15
18:00 UTC +6h on `shield-sample-webacl`: the metric reports 476 blocked and 150 allowed, and the control
query returns 0 rows. The WebACL was serving and its logs were not landing in that destination, which is
what a destination change leaves behind. Driven through the real witnesses, the check fires with those
numbers and no stubs.

**Finding it required the fix that shipped an hour earlier, which is worth keeping.** The first search for
this window used a control query with no `webaclId` filter and reported 268 rows, so the window looked like
a partial gap rather than a total one. Those 268 rows belong to `antiddos`, a different WebACL writing to
the same log group. The unscoped query hid the positive control for this check behind another WebACL's
traffic, which is the same defect, in the same log group, one layer away.

The fourth cell, a zero metric beside a non-zero control, is the one with no live example: across fourteen
monthly samples every non-zero window had metric equal to control. It is driven with stubs and said so.
"""

import pytest

from tools import session_state as S
from tools import waf_metrics as M

ACL = "acl"
WINDOW = (1788868800, 1788872400)


@pytest.fixture
def witnesses(monkeypatch):
    """Drive the two witnesses directly. Returns a setter for `(metric, control)`."""
    state = {}

    def set_pair(metric, control, metric_reason="", control_reason=""):
        state["metric"], state["control"] = metric, control
        monkeypatch.setattr(M, "webacl_action_total",
                            lambda *a, **k: (state["metric"], metric_reason))
        monkeypatch.setattr(M, "control_rows",
                            lambda *a, **k: (state["control"], control_reason))
    return set_pair


def _warn(action="BLOCK", rows=0):
    return M.log_path_warning(ACL, action, *WINDOW, narrow_rows=rows)


def test_a_working_path_says_nothing(witnesses):
    """The path works, so the narrow zero is genuine and the tool's own answer already says it."""
    witnesses(566070, 566070)
    assert _warn() == ""


def test_a_window_that_held_nothing_for_anyone_says_nothing(witnesses):
    """**The cell that makes the second witness necessary.** Measured live: 2026-09-08 12:00-13:00 UTC has
    a zero metric and a zero control, and it was a genuinely quiet hour. A control-only check would call
    every quiet hour a broken log path."""
    witnesses(0, 0)
    assert _warn() == ""


def test_a_metric_above_zero_with_an_empty_control_is_the_one_actionable_cell(witnesses):
    """The only cell that speaks, and what it must not say. It is a statement about the log path, so the
    wording has to keep the reader away from concluding anything about the subject that was asked.

    Stubbed here for the wording, and confirmed live on 2025-08-15 18:00 UTC +6h where the real witnesses
    return 476 and 0. See the module docstring for why that window exists."""
    witnesses(1234, 0)
    msg = _warn()
    assert "log path returned nothing for anyone" in msg
    assert "1,234" in msg and ACL in msg
    assert "Do NOT report it as absence" in msg
    assert "Log Filter" in msg and "partition or timezone mismatch" in msg


def test_the_reverse_disagreement_is_one_line_and_not_a_verdict(witnesses):
    """Rows in the logs with a zero metric. Metrics lag by minutes and a dimension mismatch looks the
    same, so this says which evidence is better and stops."""
    witnesses(0, 42)
    msg = _warn()
    assert "Metrics can lag" in msg and "better evidence" in msg
    assert "missed data" not in msg and "Do NOT" not in msg


def test_a_narrow_answer_that_found_rows_is_never_cross_checked(witnesses):
    """The whole check is about an empty answer. Metric 122 beside 40 rows may be a `limit` on the query
    rather than data it missed, and nothing available separates those, which is the same limit the sibling
    checks carry.

    **Driven with the witnesses that would fire**, because the first version used a pair that is silent
    anyway and the sweep reported it HOLLOW: removing the gate changed nothing, so the assertion held for a
    reason that had nothing to do with the gate."""
    witnesses(1234, 0)
    assert _warn(rows=0) != "", "premise: this witness pair is the one that speaks"
    assert _warn(rows=7) == ""


def test_a_witness_that_could_not_answer_produces_silence(witnesses):
    """**A witness that could not answer must never become a claim about the logs**, and each witness
    fails independently: the metric can be beyond retention while the control runs, and the control can
    fail while the metric answers. Both directions, because one `None` check can hide the other."""
    witnesses(None, 0, metric_reason="beyond 455 days")
    assert _warn() == ""
    witnesses(1234, None, control_reason="the control query did not complete")
    assert _warn() == ""
    # **The pair that makes the control guard load-bearing.** With a non-zero metric, `None == 0` is
    # already False and removing the guard changes nothing, which the sweep reported as HOLLOW. With a
    # zero metric the next comparison is `None > 0`, so an unguarded control raises TypeError and the
    # tool loses an answer it had already produced.
    witnesses(0, None, control_reason="Timeout")
    assert _warn() == ""


def test_a_control_that_failed_is_not_a_control_that_found_nothing(witnesses):
    """The distinction stated as its own test, because collapsing it is what would make this check fire on
    a failed query rather than on a broken path. `0` speaks and `None` does not, from the same cell."""
    witnesses(1234, 0)
    assert _warn() != ""
    witnesses(1234, None, control_reason="Timeout")
    assert _warn() == ""


def test_an_action_with_no_metric_is_refused_rather_than_guessed(witnesses):
    """`COUNT` is the one that matters. It is not a terminating action, so a WAF log record's `action`
    field never holds it and `CountedRequests` is not disjoint from the other four. A tool asking about it
    gets silence rather than a comparison against the wrong series."""
    witnesses(1234, 0)
    assert M.log_path_warning(ACL, "COUNT", *WINDOW, narrow_rows=0) == ""
    assert M.log_path_warning(ACL, "EXCLUDED_AS_COUNT", *WINDOW, narrow_rows=0) == ""


def test_no_action_sums_the_four_terminating_ones(monkeypatch):
    """`analyze_ip` and `aggregate_logs` have no action to name, so the witness is "did anything happen".
    The four terminating actions are disjoint and `CountedRequests` is excluded, so the sum is safe.

    It is a presence test and not a total: measured on this account for one week, allowed plus blocked
    came to 918,688 against 919,495 WAF log records. Close enough for "did anything happen", which is the
    only question asked of it."""
    asked = []
    monkeypatch.setattr(M, "webacl_action_total",
                        lambda acl, name, s, e: (asked.append(name), (5, ""))[1])
    monkeypatch.setattr(M, "control_rows", lambda *a, **k: (0, ""))
    msg = M.log_path_warning(ACL, None, *WINDOW, narrow_rows=0)
    assert asked == ["BlockedRequests", "AllowedRequests", "ChallengeRequests", "CaptchaRequests"], asked
    assert "CountedRequests" not in asked, "Count is non-terminating, so adding it double counts"
    assert "20 requests for any action" in msg, msg


def test_the_two_witnesses_must_be_about_the_same_webacl():
    """**The metric witness follows its argument and the control follows session state, twice over**: once
    for the query's WebACL scope and once for the log destination it runs against. A caller naming X while
    the session holds Y does not merely risk a wrong answer, it guarantees one, because X's records are not
    in Y's destination and the control is zero by construction.

    Measured, so the guard has a reachable failure behind it rather than a hypothesis. 2026-09-08, full
    day: `response-id-on-page`'s `BlockedRequests` on `Rule=ALL` is 132, and a control query scoped to
    `response-id-on-page` inside `shield-sample-webacl`'s log group returns 0 rows. Without this guard the
    one cell that speaks fires on that pair and prints a false statement about the log path.

    Refused rather than resolved: running the control for X needs X's own logging configuration, which is
    another API call and a destination this layer cannot query against. The consequence is that a tool
    passing its own name and never writing session state, which is what `patrol_scan` and
    `generate_weekly_report` do, gets silence from this check."""
    S.set_webacl_context("shield-sample-webacl", "arn:x", "CLOUDFRONT", "us-east-1",
                         log_destination="arn:aws:logs:r:1:log-group:aws-waf-logs-group")
    count, why = M.control_rows("response-id-on-page", "BLOCK", *WINDOW)
    assert count is None, "a control about a different WebACL must not be reported as a count"
    assert "response-id-on-page" in why and "shield-sample-webacl" in why, why
    assert M.log_path_warning("response-id-on-page", "BLOCK", *WINDOW, narrow_rows=0) == ""


def test_a_matching_webacl_is_not_refused(monkeypatch):
    """The control for the guard above, because a guard that refuses everything is not a guard. The
    session's own WebACL passes through to the query."""
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1",
                         log_destination="arn:aws:logs:r:1:log-group:lg")
    monkeypatch.setattr("tools.waf_query.query_logs", lambda *a, **k: [{"cnt": "3"}])
    assert M.control_rows("acl", "BLOCK", *WINDOW) == (3, "")


def test_a_row_with_no_count_refuses_rather_than_reading_as_zero(monkeypatch):
    """Zero is the firing value, so a `.get("cnt", 0)` default would turn an unexpected row shape into the
    one verdict this check can get wrong. The key is written by `_control_query` two functions up, so the
    state is unreachable; it refuses anyway, because the cost of being wrong here is a false statement and
    the cost of the check is one comparison.

    An empty result list is a different thing and is a real zero: measured on CloudWatch Logs Insights,
    `stats count(*) as cnt` returns no rows at all over a window with no matching records, and one row with
    the count when there are records."""
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1",
                         log_destination="arn:aws:logs:r:1:log-group:lg")
    monkeypatch.setattr("tools.waf_query.query_logs", lambda *a, **k: [{"total": "3"}])
    count, why = M.control_rows("acl", "BLOCK", *WINDOW)
    assert count is None and "no count in it" in why, why

    monkeypatch.setattr("tools.waf_query.query_logs", lambda *a, **k: [])
    assert M.control_rows("acl", "BLOCK", *WINDOW) == (0, "")


def test_the_control_query_asks_the_same_action_on_both_engines():
    """One control shape rather than a copy of each caller's query with its filter removed, so there is
    nothing to keep in step. Both spellings are pinned because a control that exists on one engine only
    would make the check silent on the other backend and nothing would say so."""
    cwl, athena = M._control_query("BLOCK")
    assert cwl == "filter action = 'BLOCK' | stats count(*) as cnt"
    assert "AND action = 'BLOCK'" in athena and "{PARTITION_FILTER}" in athena
    assert '"timestamp" BETWEEN {START_MS} AND {END_MS}' in athena

    any_cwl, any_athena = M._control_query(None)
    assert any_cwl == "stats count(*) as cnt"
    assert "action =" not in any_athena, "the no-action control must not filter on one"


# Every absence branch group B names, and what each passes as its action. A branch that stops calling the
# check fails the test below rather than going quietly back to reporting absence, which is the failure this
# whole file exists for: the check is worth nothing where nobody asks it.
WIRED = {
    "waf_logs.py::analyze_ip": None,            # looks at every action, so the witness sums four
    "waf_block_fp.py::_step_investigate": "BLOCK",
    "waf_bypass.py::_step_scan": "ALLOW",       # once for the whole scan, not once per section
    "waf_aggregate.py::aggregate_logs": None,   # the action comes from `filters` when it names one
}


def _call_sites() -> dict[str, str]:
    """`module::function` -> the source of every function under `tools/` calling `log_path_warning`."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    out = {}
    for path in sorted(root.glob("tools/*.py")):
        src = path.read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                        and sub.func.id == "log_path_warning"):
                    out[f"{path.name}::{node.name}"] = ast.get_source_segment(src, sub) or ""
    return out


def test_every_absence_branch_group_b_names_asks_the_check():
    """**The inventory, because a check nobody calls is the state this replaced.** Four tools answer from an
    IP, URI, User-Agent or JA4 and every one of them had a branch saying "nothing found" with no way to
    tell that from a log path returning nothing at all."""
    sites = _call_sites()
    assert set(sites) == set(WIRED), (
        f"the set of tools asking the log-path check has changed. New: {sorted(set(sites) - set(WIRED))}. "
        f"Gone: {sorted(set(WIRED) - set(sites))}. Group B is four tools; a fifth must be declared here.")


def test_each_site_passes_the_action_its_own_answer_is_about():
    """**The action decides which metric is the witness**, so a site passing the wrong one compares an
    empty answer against a series about something else. `detect_bypass` is the one worth naming: it reads
    ALLOW traffic in all six of its anomaly sections, and its check sits in the branch where every section
    is empty and no query failed, so it fires once rather than six times."""
    for site, action in WIRED.items():
        call = _call_sites()[site]
        if action is None:
            assert "None" in call or "_action" in call, (site, call)
        else:
            assert f'"{action}"' in call, f"{site} does not pass {action}: {call}"
        assert "narrow_rows=0" in call, (
            f"{site} passes a row count other than zero, and this check is only about an empty answer")
        assert "get_webacl_name()" in call, (
            f"{site} names a WebACL other than the session's, and the control query can only answer "
            f"about the session's destination: {call}")
