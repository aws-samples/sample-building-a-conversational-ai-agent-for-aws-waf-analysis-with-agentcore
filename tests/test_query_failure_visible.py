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

import re

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


# --- 3.4: the chain is six queries, not up to sixteen ----------------------


def test_the_scan_issues_no_per_candidate_drill_down(monkeypatch, offline):
    """The whole point of 3.4. The scan used to issue one extra query per JA4 candidate, capped
    at 10, so a run could reach 16 serial Athena queries. Counted rather than inspected, because
    "the loop is gone" is a claim about behaviour and the loop's absence from the source is not
    the same statement."""
    seen = []
    def counting(cwl, athena, start, end, limit=25):
        seen.append(athena or cwl)
        return [dict(ROW)]
    monkeypatch.setattr(B, "query_logs", counting)
    B._step_scan(0, 3600)
    assert len(seen) == 6, [s[:60] for s in seen]
    # And specifically: nothing queried a single fingerprint, which is what the loop did.
    assert not [s for s in seen if "ja4fingerprint = '" in s]


def test_the_scan_names_the_step_that_gets_the_ips(monkeypatch, offline):
    """Removing the Top IPs column would strand the user with a fingerprint and no way to act,
    so the section has to name the replacement. The UA-rotation section is asserted too: it told
    the model to investigate "an IP behind this JA4" while containing no IPs at all, which was
    already unactionable before this change."""
    monkeypatch.setattr(B, "query_logs", fake_query_logs([]))
    out = B._step_scan(0, 3600)
    ja4_section = out.split("### Single Tool Distributed")[1].split("###")[0]
    ua_section = out.split("### UA Rotation")[1].split("## ")[0]
    assert "step='ja4_ips'" in ja4_section
    assert "Top IPs" not in ja4_section
    assert "step='ja4_ips'" in ua_section
    assert "<an IP behind this JA4>" not in ua_section


def test_the_drill_down_step_runs_exactly_one_query(monkeypatch):
    seen = []
    def counting(cwl, athena, start, end, limit=25):
        seen.append(athena)
        return [{"httpRequest.clientIp": "198.51.100.7", "hits": "42"}]
    monkeypatch.setattr(B, "query_logs", counting)
    out = B._step_ja4_ips("t13d1516h2_8daaf6152771_b0da82dd1658", 0, 3600)
    assert len(seen) == 1
    assert "198.51.100.7" in out and "investigate_ip" in out


@pytest.mark.parametrize("bad", ["'; DROP TABLE x--", "a' OR '1'='1", "x-y/z", "t13d*",
                                 "", "   ", "';--", "t13d 1516h2"])
def test_a_malformed_fingerprint_is_refused_and_runs_no_query(monkeypatch, bad):
    """A JA4 arrives as a model-supplied string and is interpolated into SQL, so it is checked
    with `fullmatch` and refused, not stripped of the offending characters.

    **Rejecting matters beyond injection.** Substituting was injection-safe, because the quotes
    went, but it queried a DIFFERENT fingerprint and the report's own header echoed the
    substituted value, so a stray character produced an authoritative-looking answer about a
    fingerprint nobody asked for. `t13d 1516h2`, with an interior space, is the case that
    silently renames the thing being queried. The two comparable sites in this repo,
    `waf_query.py:504` and `waf_patrol.py:593`, already fullmatch-or-refuse.

    **Surrounding whitespace is the deliberate exception and lives in the accepted sweep
    below.** Edge whitespace carries no information, so stripping it recovers the fingerprint
    the user meant rather than inventing a different one, which is the only harm this check
    exists to prevent."""
    seen = []
    monkeypatch.setattr(B, "query_logs", lambda *a, **k: seen.append(1) or [])
    out = B._step_ja4_ips(bad, 0, 3600)
    assert not seen, "a malformed fingerprint reached the query layer"
    assert "not a JA4 fingerprint" in out


@pytest.mark.parametrize("good", ["t13d1516h2_8daaf6152771_b0da82dd1658", "abc123", "A_1",
                                  "  t13d1516h2  ", "t13d1516h2\n"])
def test_a_wellformed_fingerprint_reaches_the_query_intact(monkeypatch, good):
    """The mirror, and it is what stops the check above being satisfied by refusing everything.
    The literal is asserted non-empty before being matched, which is the mechanical version of
    the trap the first draft of this test fell into: with the check removed, the extracted text
    was EMPTY and `[0-9A-Za-z_]*` matched it, so the assertion passed with the fix deleted."""
    seen = []
    def counting(cwl, athena, start, end, limit=25):
        seen.append(athena)
        return []
    monkeypatch.setattr(B, "query_logs", counting)
    B._step_ja4_ips(good, 0, 3600)
    assert seen, "a valid fingerprint issued no query"
    literal = seen[0].split("ja4fingerprint = '")[1].split("'")[0]
    assert literal, "nothing was extracted, so the assertion below would be vacuous"
    assert literal == good.strip()


def test_a_section_note_carries_no_retry_advice():
    """`poll_timeout_message` ends in an ACTION block written for whoever chose the window.
    Nobody chose a chain query's window, so the advice cannot be acted on, and on the second
    consecutive timeout it reads "narrowing is not working" about a window the user never set."""
    from tools import query_limits as Q
    msg = Q.poll_timeout_message("Athena", Q.STOP_CONFIRMED)
    assert "ACTION:" in msg, "the message shape changed, so this test is checking nothing"
    note = B._empty_reason({"distributed": msg}, "distributed")
    assert "ACTION:" not in note
    assert "quarter of the window" not in note
    # The header still has to survive, or the note says nothing about what happened.
    assert "120 seconds" in note


# --- the fifth module, found by ROADMAP 4.6 --------------------------------


def test_analyze_ip_sections_say_the_query_failed_instead_of_going_missing(monkeypatch):
    """`analyze_ip` called `query_logs` at seven sites and checked none of them, for eight
    releases, while `tests/test_window_cap.py` reported the module clean.

    Patched at `tools.waf_query.query_logs` rather than at `waf_logs.query_logs`, because
    `waf_logs._safe_query` imports it inside the function. Worth stating: patching the wrong
    one leaves the real query layer live and the test reaches for AWS."""
    from tools import waf_logs as L
    from tools import waf_query as WQ

    monkeypatch.setattr(WQ, "query_logs", fake_query_logs([""], "error_row"))
    # Patched on `waf_query`, not on `waf_logs`: `analyze_ip` imports both of these
    # inside the function, so the module attribute is the only patch point.
    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: None)
    out = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)

    # The first query failing stops the rest, and what it must NOT say is the sentence it
    # used to: "No log records found for this IP", which is a claim about the traffic.
    assert "No log records found" not in out
    assert "NOT a quiet IP" in out
    assert CWL_ERROR in out


def test_analyze_ip_survives_an_athena_raise(monkeypatch):
    """The other spelling. `query_logs` raising used to propagate out of `analyze_ip` and
    take the whole tool call, so the user got a stack trace instead of six good sections."""
    from tools import waf_logs as L
    from tools import waf_query as WQ

    monkeypatch.setattr(WQ, "query_logs", fake_query_logs([""], "raise"))
    # Patched on `waf_query`, not on `waf_logs`: `analyze_ip` imports both of these
    # inside the function, so the module attribute is the only patch point.
    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: None)
    out = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    assert "## IP Analysis" in out
    assert "UNKNOWN, the query for this section failed" in out


def test_one_failed_section_does_not_erase_the_others(monkeypatch):
    """The per-section claim, which needs a section that legitimately has no rows next to one
    that failed. With everything failing, "this section's reason" and "any reason" give the
    same answer and a lookup that ignores the label would pass."""
    from tools import waf_logs as L
    from tools import waf_query as WQ

    # `avg_rpm` appears only in the request-rate query, so exactly one section fails and the
    # first query still answers. A marker that also matched the diversity query would trip
    # the early return above and this test would prove the opposite of its name.
    monkeypatch.setattr(WQ, "query_logs", fake_query_logs(["avg_rpm"], "error_row"))
    # Patched on `waf_query`, not on `waf_logs`: `analyze_ip` imports both of these
    # inside the function, so the module attribute is the only patch point.
    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: None)
    out = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    # The rate section failed; the action breakdown answered and must still show its row.
    assert out.count("UNKNOWN, the query for this section failed") == 1, out
    assert "**Request rate**" in out
    assert "ALLOW" in out, out
    assert "No log records found" not in out


def test_a_failed_content_sample_is_unavailable_not_absent(monkeypatch):
    """`sample_inspection_content` documents three states: rows, `[]` for none found, and
    `None` for "could not be retrieved". The Athena spelling already produced `None`; the
    CloudWatch `_error` row produced `[]`, so the same failure meant "no matching content" on
    one backend and "could not retrieve" on the other. Six unguarded call sites, in the module
    that DEFINES `log_query_error`, which is why a module-level substring sweep could never
    fail there."""
    from tools import waf_query as WQ

    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "query_logs", fake_query_logs([""], "error_row"))
    label, samples, masked = WQ.sample_inspection_content(
        "AWS-AWSManagedRulesSQLiRuleSet_QUERYARGUMENTS", "filter action='BLOCK'",
        "action='BLOCK'", 0, 3600)
    assert label is not None
    assert samples is None, "an error row must not read as 'no matching content'"


def test_analyze_ip_refuses_a_malformed_address_rather_than_editing_it(monkeypatch):
    """`analyze_ip` used to run `re.sub(r"[^0-9a-fA-F.:]", "", ip)` before building its queries,
    which is the substituting sanitiser the JA4 fix removed from `waf_bypass.py`: stripping the
    characters that do not belong leaves a VALID value naming something else, echoed by every
    section and the header.

    **It was dead defence, not a live defect, and finding that out is why this test exists.**
    `ipaddress.ip_address(ip)` runs first and is a real parser, so nothing malformed reaches the
    substitution. The first attempt at a fix added a `fullmatch`-or-refuse guard and this test
    caught it by failing with the message the EXISTING validator already emits, which is a weaker
    duplicate of a check already being done. So the substitution was deleted rather than replaced.

    Swept over inputs that all sanitise to something valid, because that is the class a
    substituting sanitiser gets wrong while looking careful. If the parser is ever removed, these
    go red."""
    from tools import waf_logs as L
    from tools import waf_query as WQ

    monkeypatch.setattr(WQ, "get_log_type", lambda: "cwl")
    monkeypatch.setattr(WQ, "check_coarse_partition_block", lambda: None)
    monkeypatch.setattr(WQ, "query_logs", lambda *a, **k: [dict(ROW)])
    for bad in ("203.0.113.9x", "203.0.113.9'", "203.0.113.9 OR 1=1", "2003.0.113.9/24",
                " 203.0.113.9 "):
        out = L.analyze_ip._tool_func(bad, "2026-09-10 00:00", 60)
        assert "invalid IP address" in out, f"{bad!r} was not refused: {out[:120]}"
        assert bad in out, "the refusal must echo what the user actually typed"
    ok = L.analyze_ip._tool_func("203.0.113.9", "2026-09-10 00:00", 60)
    assert "invalid IP address" not in ok
    assert "## IP Analysis: 203.0.113.9" in ok, ok[:200]


@pytest.fixture
def webacl_selected(monkeypatch):
    """Both tools refuse before anything else when no WebACL is selected, which is correct
    ordering and would otherwise make every assertion below pass for the wrong reason."""
    from tools import waf_count_eval as C
    from tools import waf_block_fp as F
    for mod in (C, F):
        monkeypatch.setattr(mod, "get_webacl_name", lambda: "acl", raising=False)
    # `investigate_block_fp` also refuses when no logging is configured, before it looks at
    # `rule_name`. Environment preconditions first is the convention in both tools and is left
    # alone; the fixture satisfies them so the assertions reach the guard under test.
    monkeypatch.setattr(F, "get_log_type", lambda: "cwl", raising=False)
    monkeypatch.setattr(C, "_has_logging", lambda: True, raising=False)
    return None


def test_every_step_taking_a_rule_name_refuses_one_that_would_break_out_of_a_literal(
        webacl_selected):
    """`rule_name` is model-supplied and reaches single-quoted literals in both dialects. Three
    call sites escaped it, one substituted characters out of it, and **two did nothing at all**
    while interpolating it into eight query strings between them:
    `waf_count_eval._step_check_clients` (six Athena literals plus three CWL filters) and
    `waf_block_fp._step_scan` (:526, :527). Both reachable from the tool dispatch, and
    `_step_analyze_rule`'s own output tells the model to make the first of those calls with the
    name interpolated in.

    Driven through the public entry points, because that is what the model calls and because the
    validation deliberately lives at the dispatch: one check covering every step beats a copy per
    step, which is the weaker-duplicate mistake `analyze_ip`'s dead `re.sub` was."""
    from tools import waf_count_eval as C
    from tools import waf_block_fp as F

    breaking = ("MyRule'--", "MyRule' OR '1'='1", "x' AND r.action = 'COUNT", 'MyRule"')
    for bad in breaking:
        for step in ("analyze_rule", "check_low_volume_clients"):
            out = C.evaluate_count_rules._tool_func(step=step, rule_name=bad,
                                                    start_time="2026-09-10 00:00")
            assert "is not a rule name" in out, f"count_eval {step} accepted {bad!r}: {out[:110]}"
        for step in ("investigate", "scan"):
            out = F.investigate_block_fp._tool_func(step=step, ip="203.0.113.9",
                                                   start_time="2026-09-10 00:00", rule_name=bad)
            assert "is not a rule name" in out, f"block_fp {step} accepted {bad!r}: {out[:110]}"


def test_a_legitimate_rule_name_still_gets_through():
    """The other side, or the guard is just a wall. Managed rule-group sub-rule names carry dots
    and hyphens, so those must pass; `investigate_block_fp` also takes no rule name at all.

    **The tolerated-whitespace case is asserted together with what it returns, because splitting
    those two is the defect below.** An earlier version asserted only that a padded name is
    accepted, which pinned the accepting half while every consumer interpolated the padding
    verbatim."""
    from tools.waf_query import checked_rule_name

    for good in ("SizeRestrictions_BODY", "AWS-AWSManagedRulesCommonRuleSet",
                 "CrossSiteScripting_BODY", "my.rule.v2", "Rule-1_x"):
        assert checked_rule_name(good) == (good, None), good
    assert checked_rule_name("  SizeRestrictions_BODY  ") == ("SizeRestrictions_BODY", None), \
        "edge whitespace must be tolerated AND removed, not tolerated and passed on"
    for bad in ("", "   ", None):
        name, err = checked_rule_name(bad)
        assert err is not None, repr(bad)
        assert name == "", "a refused name must come back empty, never echoed back for use"


@pytest.mark.parametrize("padded,clean", [("SizeRestrictions_BODY ", "SizeRestrictions_BODY"),
                                          (" MyRule", "MyRule"),
                                          ("\tMyRule\n", "MyRule")])
def test_a_padded_rule_name_reaches_the_query_without_its_padding(padded, clean, webacl_selected,
                                                                 monkeypatch):
    """The pair to the assertion above, and the half that was missing.

    `checked_rule_name` decided on a stripped copy and returned only a verdict, so a trailing space
    passed the guard and `_step_check_clients` queried `r.ruleid = 'SizeRestrictions_BODY '` while
    `_step_scan` queried `terminatingruleid = 'MyRule '`. Neither matches anything.

    **The consequence lands in the direction that matters, which is why this is asserted on the
    built query rather than on the return value.** `check_low_volume_clients` exists to produce an
    FP signal, and "no low-volume clients" pushes the verdict toward confirmed attack and safe to
    Block; a scan's empty result reads as a clean audit. A stray space turns a query that would
    have found clients into a zero that nothing distinguishes from a real one.

    Captured at `query_logs`, the one place both dialects pass through, so the assertion covers
    the Athena literals and the CloudWatch filters in one place."""
    from tools import waf_block_fp as F
    from tools import waf_query as WQ

    seen: list[str] = []

    def capture(cwl, athena, *a, **k):
        seen.extend([cwl, athena])
        return []

    # Patched in every module that binds the name, because both tools do
    # `from tools.waf_query import query_logs` at import time. `WQ` is patched too so
    # `sample_inspection_content`'s own calls are captured rather than reaching AWS.
    for mod in (C, F, WQ):
        monkeypatch.setattr(mod, "query_logs", capture)
        monkeypatch.setattr(mod, "get_log_type", lambda: "cwl", raising=False)
    monkeypatch.setattr(F, "_check_coverage_gaps", lambda *a, **k: [], raising=False)
    monkeypatch.setattr(F, "get_client", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("no AWS in tests")), raising=False)

    C.evaluate_count_rules._tool_func(step="check_low_volume_clients", rule_name=padded,
                                      start_time="2026-09-10 00:00")
    F.investigate_block_fp._tool_func(step="scan", start_time="2026-09-10 00:00",
                                      rule_name=padded)

    assert seen, "no query was built, so this proves nothing about what reaches one"
    named = [q for q in seen if clean in q]
    assert named, f"no query mentions {clean!r} at all: {seen[:1]}"
    for q in named:
        assert padded not in q, f"the padding reached the query: {q[:160]}"


def test_an_all_whitespace_rule_name_is_refused_not_read_as_no_filter(webacl_selected):
    """`investigate_block_fp` treats an empty `rule_name` as "audit every rule", so normalising
    before the truthiness check would turn `"   "` into a silently WIDER scan. Refusing is the
    house rule, and the widening is the substitution it exists to prevent: a one-rule audit the
    user asked for coming back as an all-rule audit is a different answer, not a degraded one."""
    from tools import waf_block_fp as F

    out = F.investigate_block_fp._tool_func(step="scan", start_time="2026-09-10 00:00",
                                           rule_name="   ")
    assert "is not a rule name" in out, out[:160]


def test_the_permanent_count_gate_reads_the_name_the_user_typed(webacl_selected):
    r"""`_step_analyze_rule` compared a *rewritten* name against `PERMANENT_COUNT_RULES`, and the
    branch it guards returns "Keep as Count, do NOT switch to Block" plus a `record_finding` call.

    **The direction is bounded and worth stating:** every listed name already matches
    `[a-zA-Z0-9_\-.]+`, so stripping left it intact and the gate could never be made to MISS.
    Only false firing was reachable, which is what this asserts."""
    from tools import waf_count_eval as C

    assert "PERMANENT COUNT" in C._step_analyze_rule("SizeRestrictions_BODY")
    out = C.evaluate_count_rules._tool_func(step="analyze_rule", rule_name="SizeRestrictions_BODY'")
    assert "PERMANENT COUNT" not in out
    assert "is not a rule name" in out
