# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A log query that failed must not read as a log query that found nothing.

The 0.17.0 release fixed this class in `waf_patrol` and `report.py` and did not sweep for
it, so it was still live in `waf_bypass` and `waf_count_eval` on 2026-09-10. Observed
rather than inferred: a bypass scan against a table missing `ja4fingerprint` had 2 of its
6 queries fail with COLUMN_NOT_FOUND and still produced a report asserting no bypass
candidates, with the errors only on stderr.

Two engines reach the failure differently, and the old code handled exactly one of each
badly, so every test here covers both spellings:

- **Athena** raises out of `_run_athena_select`, carrying `poll_timeout_message`.
- **CloudWatch** returns a `[{"_error": ...}]` row, which is *truthy*, so passing it
  through as data made a section render a table row of `?` placeholders.
"""

import pytest

from tools import waf_bypass as B
from tools import waf_count_eval as C

ROW = {"httpRequest.clientIp": "203.0.113.9", "total": "999", "unique_uris": "888",
       "hits": "999", "cnt": "999", "action": "ALLOW", "Labels": "",
       "ja4Fingerprint": "t13d1516h2", "ua": "curl/8.0", "rule": "SomeRule",
       "unique_uas": "9", "unique_ips": "9"}

ATHENA_RAISE = "STOPPED: Athena reported the query as FAILED, so no rows were returned."
CWL_ERROR = "CloudWatch Logs Insights did not finish within 120 seconds."


def fake_query_logs(markers=(), how="raise", empty_markers=()):
    """A `query_logs` stand-in that fails, or returns nothing, per query text.

    Keyed on the query text, never on call order: a test that encodes "the fifth call
    fails" passes for the wrong reason as soon as a query moves, and this file's whole
    subject is which section an error belongs to. An empty marker string matches
    everything, which is the all-queries-fail case.

    `empty_markers` is what makes a per-section claim testable at all. With one failure and
    nothing else empty, "this section's reason" and "any reason" give the same answer
    everywhere, so a lookup that ignores the label passes. A section that is *legitimately*
    empty next to one that failed is the only input that tells them apart."""
    def run(cwl, athena, start, end, limit=25):
        text = f"{cwl}\n{athena}"
        if any(m in text for m in markers):
            if how == "raise":
                raise RuntimeError(ATHENA_RAISE)
            return [{"_error": CWL_ERROR}]
        if any(m in text for m in empty_markers):
            return []
        return [dict(ROW)]
    return run


def _verdict(report: str) -> str:
    """Just the Directional Judgment block.

    The report ends with instructions to the model that themselves mention HIGH
    CONFIDENCE, so an assertion over the whole string cannot tell a verdict from a
    reference to one."""
    assert "## Directional Judgment" in report
    return report.split("## Directional Judgment")[1].split("## Your Next Action")[0]


@pytest.fixture
def offline(monkeypatch):
    """Everything `_step_scan` reaches outside the query layer.

    `_check_coverage_gaps` calls wafv2 and the week-over-week block calls CloudWatch. Left
    live they would spend botocore's retry budget and the test would be slow, credential-
    dependent and green for the wrong reason on a machine with no AWS access."""
    monkeypatch.setattr(B, "_check_coverage_gaps", lambda: [])
    monkeypatch.setattr(B, "get_client", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("no AWS in tests")))
    monkeypatch.setattr(B, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(B, "get_scope", lambda: "CLOUDFRONT")
    monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)


# --- the mechanism ---------------------------------------------------------


@pytest.mark.parametrize("how,expected", [("raise", ATHENA_RAISE), ("error_row", CWL_ERROR)])
def test_safe_query_records_the_reason_and_returns_no_rows(monkeypatch, how, expected):
    monkeypatch.setattr(B, "query_logs", fake_query_logs([""], how))
    failures: dict[str, str] = {}
    rows = B._safe_query("c", "a", 0, 60, failures=failures, label="crawlers")
    # Both halves matter. Returning the `_error` row instead of [] is what rendered a
    # fabricated `| ? | ? | ? |` finding, so "no rows" is as load-bearing as "a reason".
    assert rows == []
    assert list(failures) == ["crawlers"]
    assert expected in failures["crawlers"]


def test_safe_query_on_success_records_nothing(monkeypatch):
    """The precondition for every assertion about `failures` below: it stays empty when
    queries work, so a non-empty `failures` elsewhere means a real failure and not a
    fixture that forgot to patch the query layer. The first draft of this test forgot,
    reached for AWS, and failed for that reason."""
    monkeypatch.setattr(B, "query_logs", fake_query_logs([]))
    failures: dict[str, str] = {}
    rows = B._safe_query("c", "a", 0, 60, failures=failures, label="crawlers")
    assert failures == {}
    assert rows == [ROW]


def test_empty_reason_tells_the_two_kinds_of_empty_apart():
    assert B._empty_reason({}, "crawlers") == "  (none found)"
    assert B._empty_reason({}, "crawlers", "  (not available)") == "  (not available)"
    line = B._empty_reason({"crawlers": "boom"}, "crawlers")
    assert "UNKNOWN" in line and "boom" in line
    assert "none found" not in line


# --- the scan's verdict ----------------------------------------------------


@pytest.mark.parametrize("how", ["raise", "error_row"])
def test_a_scan_whose_queries_all_failed_does_not_report_a_clean_scan(monkeypatch, offline, how):
    """The wrong answer that was shipping. Every section is empty because every query
    failed, and the old code read that as "No IPs matched the anomaly filters"."""
    monkeypatch.setattr(B, "query_logs", fake_query_logs([""], how))
    out = B._step_scan(0, 3600)
    assert "No Obvious Bypass Candidates Found" not in out
    assert "Cannot Say Whether Bypass Candidates Exist" in out
    assert "do NOT report it as clean" in out
    assert "(none found)" not in out


def test_one_failed_query_marks_only_its_own_section(monkeypatch, offline):
    """The other half: a failure must not erase what the other sections did establish.

    The discriminating input is one section that FAILED beside one that is legitimately
    EMPTY. Without the empty one this test passed while `_empty_reason` ignored its label
    entirely, because with a single failure "its own reason" and "any reason" agree
    wherever the else-branch is reached. Found by the perturbation reporting HOLLOW."""
    monkeypatch.setattr(B, "query_logs", fake_query_logs(
        markers=["known_bot_data_center"], how="raise",
        empty_markers=["libwww-perl"]))
    out = B._step_scan(0, 3600)
    datacenter = out.split("### Data-Center IPs Not Caught by Bot Control")[1].split("###")[0]
    auto_ua = out.split("### Automation User-Agents Allowed Through")[1].split("###")[0]
    assert "UNKNOWN" in datacenter and ATHENA_RAISE in datacenter
    # The empty section says empty, and says nothing about the datacenter query.
    assert "(none found)" in auto_ua
    assert "UNKNOWN" not in auto_ua
    # And a section that got rows still reports them.
    assert "203.0.113.9" in out
    assert "Cannot Say Whether Bypass Candidates Exist" not in out


def test_a_fabricated_row_is_never_rendered(monkeypatch, offline):
    """The CloudWatch half of the defect, asserted on the artifact. An `_error` row is
    truthy, so before the fix the six table sections rendered it through `r.get(k, '?')`
    and produced a row of `?` cells that reads as a real bypass candidate."""
    monkeypatch.setattr(B, "query_logs", fake_query_logs([""], "error_row"))
    out = B._step_scan(0, 3600)
    assert "| ?" not in out
    assert "_error" not in out


# --- the investigation's verdict -------------------------------------------


@pytest.mark.parametrize("how", ["raise", "error_row"])
def test_a_failed_label_query_refuses_the_verdict(monkeypatch, how):
    """The worst direction of the defect. `any()` over `[]` is False, so a failed label
    query made `has_bot_label` False, and False is the *permissive* input for two HIGH
    CONFIDENCE branches. A swallowed error therefore pushed the tool toward declaring a
    bypass, which is the false alarm a security tool must not manufacture."""
    monkeypatch.setattr(B, "query_logs",
                        fake_query_logs(["@message like 'labels'"], how))
    verdict = _verdict(B._step_investigate_ip("203.0.113.9", 0, 3600))
    assert "CANNOT DETERMINE: the Bot Control label query failed." in verdict
    # Scoped to the verdict on purpose: "If HIGH CONFIDENCE -> call record_finding" sits in
    # the trailing instructions, so an unscoped assertion here fails for the wrong reason.
    assert "HIGH CONFIDENCE" not in verdict
    assert "No bot detection labels" not in verdict


def test_the_verdict_still_fires_when_the_label_query_succeeds(monkeypatch):
    """The mirror. Without it the assertion above is satisfied by a tool that never
    reaches a verdict at all, which would pass while saying nothing."""
    def run(cwl, athena, start, end, limit=25):
        row = dict(ROW)
        if "labels" in f"{cwl}\n{athena}":
            row["Labels"] = "awswaf:managed:aws:bot-control:signal:known_bot_data_center"
        return [row]
    monkeypatch.setattr(B, "query_logs", run)
    verdict = _verdict(B._step_investigate_ip("203.0.113.9", 0, 3600))
    assert "CANNOT DETERMINE: the Bot Control label query failed." not in verdict
    assert "HIGH CONFIDENCE" in verdict


# --- COUNT evaluation, where the swallow was engine-asymmetric -------------


def test_an_athena_failure_reaches_the_caller_like_a_cloudwatch_one(monkeypatch):
    """The asymmetry itself. CloudWatch failures arrived as an `_error` row and were
    reported; Athena failures arrived as a raised exception and `except Exception: return
    []` turned them into "no clients", a claim about the user's traffic."""
    for how, expected in (("raise", ATHENA_RAISE), ("error_row", CWL_ERROR)):
        monkeypatch.setattr(C, "query_logs", fake_query_logs([""], how))
        with pytest.raises(C.LogQueryFailed) as caught:
            C._run_log_query("c", "a", 0, 3600)
        assert expected in str(caught.value)


def test_the_count_step_says_the_query_failed_instead_of_showing_no_clients(monkeypatch):
    monkeypatch.setattr(C, "_has_logging", lambda: True)
    monkeypatch.setattr(C, "get_log_type", lambda: "s3")
    monkeypatch.setattr(C, "query_logs", fake_query_logs([""], "raise"))
    out = C._step_check_clients("MyRule", "2026-09-08T04:00", 60)
    assert "did not run" in out
    assert "Low-Volume Clients" not in out
    assert ATHENA_RAISE in out


# --- the two tools that had no guard at all --------------------------------
#
# Neither caught exceptions nor checked for the sentinel row, so Athena failures already
# raised while CloudWatch failures were rendered as data. 15 call sites between them, and one
# is the false-positive investigation whose output tells a user whether to unblock traffic.


@pytest.mark.parametrize("module,fn", [("waf_block_fp", "_run_query"),
                                       ("waf_challenge_check", "_run_q")])
def test_the_remaining_wrappers_raise_on_a_cloudwatch_error_row(monkeypatch, module, fn):
    import importlib
    mod = importlib.import_module(f"tools.{module}")
    monkeypatch.setattr(mod, "query_logs", fake_query_logs([""], "error_row"))
    with pytest.raises(RuntimeError) as caught:
        getattr(mod, fn)("c", "a", 0, 3600)
    assert CWL_ERROR in str(caught.value)


@pytest.mark.parametrize("module,fn", [("waf_block_fp", "_run_query"),
                                       ("waf_challenge_check", "_run_q")])
def test_the_remaining_wrappers_still_return_rows(monkeypatch, module, fn):
    """The mirror. Without it, `raise` on everything would satisfy the test above."""
    import importlib
    mod = importlib.import_module(f"tools.{module}")
    monkeypatch.setattr(mod, "query_logs", fake_query_logs([]))
    assert getattr(mod, fn)("c", "a", 0, 3600) == [ROW]
