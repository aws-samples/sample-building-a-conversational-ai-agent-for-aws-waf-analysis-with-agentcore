# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The weekly report names a failed lookup as a failure, and its total includes CAPTCHA.

Four `except Exception: pass` handlers each turned a failure into a statement about the WebACL:

- the Challenge/CAPTCHA solved counts became "solved: 0";
- a failed logging-configuration read left no log group, which the Anti-DDoS reason then explained
  as "this WebACL logs to S3 or Firehose";
- a failed Bot Control section was attributed to CloudWatch's 14-day metric discovery;
- a failed DDoS event count became "🟢 No events", in a security report.

And the total was allowed + blocked + challenge while "mitigated" added CAPTCHA too, so the
mitigated share was computed against a denominator missing part of its own numerator.
"""

import pathlib

import pytest

from tools import report as R
from tools import session_state as S

NO_EVENTS = R._I18N["en"]["no_events"]


class _CW:
    def __init__(self, raise_ids):
        self.raise_ids = raise_ids

    def get_metric_data(self, MetricDataQueries, **kw):
        ids = {q["Id"] for q in MetricDataQueries}
        if ids & self.raise_ids or any(i.startswith(tuple(self.raise_ids)) for i in ids):
            raise RuntimeError("ThrottlingException: rate exceeded")
        return {"MetricDataResults": []}


class _WAF:
    def __init__(self, logging_fails):
        self.logging_fails = logging_fails

    def list_web_acls(self, Scope):
        return {"WebACLs": [{"Name": "acl", "ARN": "arn:aws:wafv2:us-east-1:1:global/webacl/acl/1"}]}

    def get_logging_configuration(self, ResourceArn):
        if self.logging_fails:
            raise RuntimeError("AccessDeniedException: not authorized")
        return {"LoggingConfiguration": {"LogDestinationConfigs": []}}


@pytest.fixture
def report(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def run(*, totals=None, raise_ids=frozenset(), logging_fails=False, caps=None):
        week = totals or {"allowed": 100, "blocked": 0, "challenge": 0, "captcha": 0}
        clients = {"cloudwatch": _CW(set(raise_ids)), "wafv2": _WAF(logging_fails), "logs": object()}
        monkeypatch.setattr(R, "get_client", lambda svc, **k: clients[svc])
        for name, value in [("_get_weekly_totals", lambda *a, **k: dict(week)),
                            ("_get_daily_breakdown", lambda *a, **k: []),
                            ("_get_top_countries", lambda *a, **k: []),
                            ("_get_top_rules", lambda *a, **k: []),
                            ("_get_attack_timeseries", lambda *a, **k: {"series": {}}),
                            ("_get_ddos_chart_data", lambda *a, **k: "")]:
            monkeypatch.setattr(R, name, value)
        for name, value in [("get_log_destination", lambda: ""),
                            ("get_capabilities", lambda: caps or {"bot_control": "none"}),
                            ("resolve_region", lambda scope: "us-east-1"),
                            ("get_user_timezone", lambda: 0)]:
            monkeypatch.setattr(S, name, value)
        out = R.generate_weekly_report._tool_func(webacl_name="acl", start_time="2026-09-01", lang="en")
        html = next(pathlib.Path(tmp_path).glob("*.html")).read_text()
        return out, html
    return run


def _why(out, section):
    assert "WHY_EACH_ONE_IS_EMPTY:" in out, f"no partial-data block:\n{out}"
    block = out.split("WHY_EACH_ONE_IS_EMPTY:", 1)[1]
    line = next((l for l in block.splitlines() if l.startswith(f"- {section}:")), None)
    assert line, f"{section} is not listed as missing:\n{block}"
    return line


def test_the_total_includes_captcha(report):
    out, _ = report(totals={"allowed": 100, "blocked": 0, "challenge": 0, "captcha": 100})
    assert "Total requests: 200" in out and "(50.0% of traffic)" in out, out


def test_a_failed_solved_count_is_not_zero(report):
    out, _ = report(raise_ids={"cs", "cas"})
    assert "Challenge solved: 0" not in out and "CAPTCHA solved: 0" not in out, out
    assert "ThrottlingException" in _why(out, "challenge_solved")


def test_a_failed_ddos_event_count_is_not_no_events(report):
    out, html = report(raise_ids={"raw_evt"})
    assert NO_EVENTS not in html, "a failed event count rendered as no events"
    assert "ThrottlingException" in _why(out, "ddos_event_count")


def test_a_quiet_ddos_count_still_says_no_events(report):
    """The control: no failure, no event, the green card stays."""
    _, html = report()
    assert NO_EVENTS in html


def test_a_failed_logging_read_is_not_explained_as_an_s3_destination(report):
    out, _ = report(logging_fails=True, caps={"bot_control": "none", "anti_ddos_amr": True})
    why = _why(out, "anti_ddos_events")
    assert "S3 or Firehose" not in why and "AccessDeniedException" in why, why


def test_a_failed_bot_section_names_its_failure_not_metric_discovery(report):
    out, _ = report(raise_ids={"bl", "l", "b", "tgt", "fbv", "v", "u"}, caps={"bot_control": "common"})
    why = _why(out, "bot_control")
    assert "auto-discovery" not in why and "ThrottlingException" in why, why


def test_the_summary_tool_does_not_ask_for_the_roi_language_the_report_bans():
    """The docstring is the schema the model reads. It asked "Is the investment worth it?" while
    the data block the same model receives bans "worth the investment"."""
    import inspect
    doc = R.set_report_summary._tool_func.__doc__ or ""
    assert "worth" not in doc.lower().replace('"worth the investment" language', ""), doc
    assert "'worth the investment'" in inspect.getsource(R.generate_weekly_report._tool_func), \
        "the ban this guards against contradicting has moved"
