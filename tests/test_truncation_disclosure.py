# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A table cut off at its limit must say so, or it reads as the whole set.

ROADMAP 7.7's second item. Every tool here answers with a top-N table and none of them said whether an
N+1th row existed, so "the five IPs that hit this rule" and "five of nine hundred" rendered identically.

**One rule for both engines and both query shapes: ask for `limit + 1`, return at most `limit`,
truncated iff `len(raw) > limit`.** No statistics are involved, which is the correction rather than the
design: an earlier plan compared `statistics.recordsMatched` against `statistics.resultCount`, and
`resultCount` does not exist. Measured 2026-09-13, `GetQueryResults.statistics` returns
`recordsMatched`, `recordsScanned`, `estimatedRecordsSkipped`, `bytesScanned`, `estimatedBytesSkipped`
and `logGroupsScanned`, and botocore's `QueryStatistics` shape declares exactly those six.
`recordsMatched` counts input events, so against an aggregating query's group count it is not comparable
at all.

**Asking for one more row is only sound because the API limit truncates after the sort**, which is
documented nowhere and was measured before this was built: `stats count(*) as cnt by clientIp | sort cnt
desc` at api limit 3 returned exactly the first three rows of the same query at api limit 500, same
order and same counts.

Verified end to end against the live account on the 2026-09-08 window, where eleven IPs were blocked:
`run_logs_query(top_blocked_ips, limit=3)` returned three rows and the disclosure, and the same call at
`limit=25` returned all eleven and stayed silent.
"""

import re

import pytest

from tools import waf_query as Q


# --- the rule ---------------------------------------------------------------


def test_the_extra_row_is_cut_back_off_and_recorded():
    notes: dict = {}
    rows = Q._trim([{"a": 1}, {"a": 2}, {"a": 3}, {"a": 4}], 3, notes, "crawlers")
    assert len(rows) == 3, "the caller asked for three and must get three"
    assert notes == {"crawlers": 3}


def test_a_short_answer_records_nothing():
    """The control. Recording unconditionally would make every section claim truncation, which is the
    always-on failure that makes a warning worthless."""
    notes: dict = {}
    assert Q._trim([{"a": 1}, {"a": 2}], 3, notes, "crawlers") == [{"a": 1}, {"a": 2}]
    assert notes == {}


def test_an_exactly_full_answer_records_nothing():
    """The boundary, and the one an off-by-one gets wrong in the direction that cries wolf. `limit`
    rows back means the engine had no more to give, because it was asked for `limit + 1`."""
    notes: dict = {}
    Q._trim([{"a": 1}, {"a": 2}, {"a": 3}], 3, notes, "crawlers")
    assert notes == {}


def test_an_error_row_is_neither_trimmed_nor_read_as_truncation():
    """A failed query comes back as one `[{"_error": ...}]` row. One row is never more than a limit of
    at least one, so the sentinel survives to be surfaced by `log_query_error` and cannot be reported as
    a cut-off table."""
    notes: dict = {}
    rows = Q._trim([{"_error": "boom"}], 1, notes, "crawlers")
    assert rows == [{"_error": "boom"}]
    assert notes == {}


# --- the sentence -----------------------------------------------------------


def test_the_summary_names_every_cut_section_and_its_limit():
    out = Q.truncation_summary({"crawlers": 10, "distributed": 5})
    assert "crawlers (10)" in out and "distributed (5)" in out
    assert "not the whole set" in out
    assert "do not total them" in out, "naming the wrong use, not just flagging the fact"
    assert "Cut off" not in out, (
        "the wording has to stay neutral: a section that asks for one row on purpose is listed "
        "here too, and it must not read as that section being broken")


def test_the_summary_is_empty_when_nothing_was_cut():
    assert Q.truncation_summary({}) == ""


def test_a_section_that_failed_is_never_reported_as_merely_truncated():
    """**"Showing 25, there are more" reads as a successful partial answer.** On a query that did not
    run it is worse than either fact alone, so the failure wins and `_empty_reason` states it in place.

    Today the two are mutually exclusive by construction, because every failure path returns `[]` or one
    `_error` row and `_trim` records nothing for either. This keeps that true if a partial-result path
    is ever added, and it is one argument rather than a branch in twenty renderers."""
    assert Q.truncation_summary({"crawlers": 10}, {"crawlers": "timed out"}) == ""
    out = Q.truncation_summary({"crawlers": 10, "repeaters": 5}, {"crawlers": "timed out"})
    assert "repeaters (5)" in out and "crawlers" not in out


# --- the funnel asks for one more, on both engines --------------------------


@pytest.fixture
def cwl(monkeypatch):
    """Capture the limit `query_logs` hands the CloudWatch path."""
    seen: dict = {}

    def fake_run_cwl(log_group, query, start, end, limit):
        seen["limit"] = limit
        return [{"n": str(i)} for i in range(limit)]

    monkeypatch.setattr(Q, "_run_cwl", fake_run_cwl)
    monkeypatch.setattr(Q, "get_log_destination", lambda: "arn:aws:logs:r:1:log-group:lg")
    # `get_waf_config` writes the name and the destination together, so a destination with no
    # name is not a state production reaches, and the CWL scope filter needs the name.
    monkeypatch.setattr(Q, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(Q, "get_user_timezone", lambda: 0.0)
    return seen


def test_the_cloudwatch_path_asks_the_engine_for_one_more_than_the_caller_wanted(cwl):
    notes: dict = {}
    rows = Q.query_logs("filter x", "SELECT 1", 0, 3600, 5, notes=notes, label="s")
    assert cwl["limit"] == 6, "the engine has to be asked for the extra row"
    assert len(rows) == 5, "and the caller must not see it"
    assert notes == {"s": 5}


def test_the_athena_path_substitutes_one_more_into_the_limit_placeholder(monkeypatch):
    """The other engine, and the placeholder is the only form that can carry the extra row. A template
    with a hardcoded `LIMIT n` cannot, which is a coverage gap rather than a wrong signal: no output
    reads the absence of this note as proof of completeness. ROADMAP 7.7's third item closes it."""
    seen: dict = {}

    def fake_run_athena(sql):
        seen["sql"] = sql
        return [{"n": str(i)} for i in range(4)]

    monkeypatch.setattr(Q, "_run_athena", fake_run_athena)
    monkeypatch.setattr(Q, "get_log_destination", lambda: "arn:aws:s3:::bucket")
    monkeypatch.setattr(Q, "get_user_timezone", lambda: 0.0)
    monkeypatch.setattr(Q, "_ensure_athena_table", lambda dest: "db.tbl")
    monkeypatch.setattr(Q, "_scan_log_values", lambda rows: rows)
    from tools import waf_athena
    monkeypatch.setattr(waf_athena, "_athena_state", {}, raising=False)
    monkeypatch.setattr(waf_athena, "partition_predicate", lambda a, b: ("", None))

    notes: dict = {}
    rows = Q.query_logs("filter x", "SELECT a FROM {TABLE} LIMIT {LIMIT}", 0, 3600, 3,
                        notes=notes, label="s")
    assert re.search(r"LIMIT 4\b", seen["sql"]), seen["sql"]
    assert len(rows) == 3
    assert notes == {"s": 3}


# --- the tools carry it to the user -----------------------------------------


@pytest.mark.parametrize("module,function", [
    ("tools/waf_bypass.py", "_step_scan"),
    ("tools/waf_bypass.py", "_step_investigate_ip"),
    ("tools/waf_bypass.py", "_step_ja4_ips"),
    ("tools/waf_logs.py", "analyze_ip"),
    ("tools/waf_logs.py", "run_logs_query"),
])
def test_every_tool_that_builds_a_table_appends_the_summary(module, function):
    """**Per output rather than per section, and that is a completeness decision.** Eighteen render
    sites across these two files would each need a judgement about whether they show a list or a single
    value, and several are written `if not rows:` with the table in the `else`. One wrong placement
    leaves a truncated table silent next to sections that speak, which reads as "this one is complete".
    One line at the end covers every section the query layer recorded."""
    import ast
    import pathlib

    src = pathlib.Path(module).read_text()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == function), None)
    assert fn is not None, f"{function} not found in {module}"
    body = ast.get_source_segment(src, fn) or ""
    assert "truncation_summary(" in body, f"{function} never surfaces the truncation record"


def test_the_notes_dict_is_created_wherever_a_failures_dict_is():
    """The pairing. A tool that threads `failures` and not `notes` cannot report truncation at all, and
    the two are keyed the same way precisely so a renderer looks in one place."""
    import pathlib

    # Counted with `re.findall` and an optional underscore, because `str.count` on the bare name also
    # matches inside `_failures:` and reports one more dict than the file has.
    for module in ("tools/waf_bypass.py", "tools/waf_logs.py"):
        src = pathlib.Path(module).read_text()
        failures = re.findall(r"_?failures: dict\[str, str\] = \{\}", src)
        notes = re.findall(r"_?notes: dict\[str, int\] = \{\}", src)
        assert failures, f"{module} has no failures dict, so this test proves nothing"
        assert len(notes) >= len(failures), (
            f"{module}: {len(failures)} failures dicts and {len(notes)} notes dicts")


def test_a_zero_limit_is_refused_rather_than_reporting_a_failure_as_truncation():
    """The precondition the `_error`-row property rests on. At `limit = 0` a single `_error` row is
    `1 > 0`, so a failed query would be reported as a truncated table. Twenty call sites pass an
    explicit limit and none passes zero, but that is a fact about today's callers while the docstring
    reads as a fact about the function."""
    with pytest.raises(AssertionError, match="look like truncation"):
        Q._trim([{"_error": "boom"}], 0, {}, "s")


# --- one limit-writing form, so both engines can be asked for the extra row --


def test_no_athena_template_hardcodes_its_row_limit():
    """**A hardcoded `LIMIT n` makes truncation undetectable on the Athena backend**, because the SQL
    caps at n however many the caller asked for, so `len(rows) > limit` can never be true. Twenty-four
    templates were written that way and all twenty-four agreed with their call site's limit, so
    converting them changed no row count and turned the disclosure on for those sections.

    `waf_patrol` and `report` are excluded by the maintainer's decision, 2026-09-13: those two are
    overview tools and their queries do not change."""
    import pathlib

    offenders = {}
    for path in sorted(pathlib.Path("tools").glob("*.py")):
        if path.name in ("waf_patrol.py", "report.py"):
            continue
        found = re.findall(r"LIMIT \d+", path.read_text())
        if found:
            offenders[path.name] = found
    assert not offenders, (
        f"hardcoded Athena row limits are back: {offenders}. The caller's limit has to reach the SQL "
        f"through {{LIMIT}} or the extra row cannot be requested and the table cannot say it was cut.")


def test_the_cloudwatch_query_string_limit_is_rewritten_to_agree(monkeypatch):
    """**Rewritten rather than trusted or deleted, because AWS documents no precedence.** Measured, the
    API parameter governs and the clause is inert. Leaving it at N caps the engine at N if precedence
    ever flips, and truncation stops being detectable with nothing to notice; deleting it leaves the
    query unbounded under the same flip, which is worse. Both at `limit + 1` is safe either way."""
    seen: dict = {}
    monkeypatch.setattr(Q, "_run_cwl",
                        lambda lg, q, s, e, lim: (seen.update(query=q, limit=lim), [])[1])
    monkeypatch.setattr(Q, "get_log_destination", lambda: "arn:aws:logs:r:1:log-group:lg")
    # `get_waf_config` writes the name and the destination together, so a destination with no
    # name is not a state production reaches, and the CWL scope filter needs the name.
    monkeypatch.setattr(Q, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(Q, "get_user_timezone", lambda: 0.0)

    Q.query_logs("filter x | stats count(*) as c by ip | sort c desc | limit 5", "SELECT 1", 0, 60, 5)
    assert seen["query"].endswith("| limit 6"), seen["query"]
    assert seen["limit"] == 6, "the API parameter and the clause have to say the same number"


def test_a_query_with_no_limit_clause_is_left_alone(monkeypatch):
    """The control. A blanket append would put a `limit` on a single-row aggregation, and rewriting
    anywhere but the end would produce a query CloudWatch rejects, since `limit` must be last."""
    seen: dict = {}
    monkeypatch.setattr(Q, "_run_cwl",
                        lambda lg, q, s, e, lim: (seen.update(query=q), [])[1])
    monkeypatch.setattr(Q, "get_log_destination", lambda: "arn:aws:logs:r:1:log-group:lg")
    # `get_waf_config` writes the name and the destination together, so a destination with no
    # name is not a state production reaches, and the CWL scope filter needs the name.
    monkeypatch.setattr(Q, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(Q, "get_user_timezone", lambda: 0.0)

    Q.query_logs("filter x | stats count(*) as c", "SELECT 1", 0, 60, 5)
    # Ends with the caller's query untouched. The WebACL scope filter is prepended by
    # `scope_cwl_query`, which is a different property with its own tests, so this asserts the
    # suffix rather than the whole string: `endswith` still fails on any appended `limit`.
    assert seen["query"].endswith("filter x | stats count(*) as c"), seen["query"]
    assert "limit" not in seen["query"], seen["query"]
