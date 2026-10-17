# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The HTML reports render every string they are given as text, whatever key it arrives under.

ROADMAP 5.3 parked this while no attacker-controlled string reached a template, pinning the keys the
patrol renderer reads instead. One did reach the weekly report: `set_report_summary` ran the model's
Markdown through `markdown.markdown`, which passes raw HTML through, and the model writes that summary
from log content it is told not to trust. The patrol renderer now escapes its whole input at entry,
and the weekly report escapes each string it interpolates and every JSON it puts in a script.

The check is structural: rendered with a hostile string in every slot, the page has the same elements
and attributes as with a plain one, so no value became markup.
"""

import html.parser
import pathlib
from datetime import datetime, timezone

import pytest

from tools import report as R
from tools import session_state as S
from tools import waf_patrol as P
from tools.html_safe import escaped, script_json

HOSTILE = "\"'><img src=x onerror=alert(1)></script><script>alert(2)</script>\\"


class _Shape(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, tuple(sorted(a for a, _ in attrs))))

    def handle_endtag(self, tag):
        self.tags.append(("/" + tag,))


def _shape(page):
    p = _Shape()
    p.feed(page)
    return p.tags


def _patrol(s):
    wr = {"name": s, "scope": s, "region": s,
          "totals": {"blocked": 5, "challenge": 1, "captcha": 1, "counted": 2, "allowed": 90},
          "bot_data": {"unverified_blocked": 1, "unverified_challenged": 1, "unverified_captchaed": 1,
                       "verified_allowed": 3, "unverified_allowed": 4,
                       "targeted_signals": {s: {"BlockedRequests": 2, "AllowedRequests": 1}},
                       "bot_names": {s: 7}},
          "rules_table": [{"name": s, "blocked": 3, "challenge": 0, "captcha": 0, "counted": 1}],
          "chart_data": {"labels": [s], "series": {s: [1]}},
          "rate_limits": [{"name": s, "limit": 100, "window": 300, "total_blocked": 4}],
          "detection_tools": [{"status": "ok", "detail": s, "layer": s, "rule_name": s, "mode": s}]}
    failed = {"name": s, "scope": s, "error": s}
    items = [{"severity": "critical", "rule": s, "text": s, "suggestion": s, "webacl": s}]
    t = datetime(2026, 10, 1, tzinfo=timezone.utc)
    return P._render_patrol_html_v2([wr, failed], items, t, t, 24, "en")


def test_the_patrol_report_renders_every_string_as_text():
    plain, hostile = _patrol("plain-value"), _patrol(HOSTILE)
    assert "plain-value" in plain and "onerror" in hostile, "the precondition: the values reached the page"
    assert _shape(hostile) == _shape(plain), "a value became markup"
    assert "</script><script>alert(2)" not in hostile and "\"'>" not in hostile


def test_the_patrol_report_json_keeps_the_raw_values():
    """The embedded report data is for reading back, so it holds what was measured, not entities."""
    import json
    page = _patrol(HOSTILE)
    data = json.loads(page.split('<script type="application/json" id="report-data">', 1)[1].split("</script>", 1)[0])
    assert data["webacls"][0]["action_items"][0]["text"] == HOSTILE


class _WAF:
    def __init__(self, name):
        self.name = name

    def list_web_acls(self, Scope):
        return {"WebACLs": [{"Name": self.name, "ARN": "arn:aws:wafv2:us-east-1:1:global/webacl/acl/1"}]}

    def get_logging_configuration(self, ResourceArn):
        return {"LoggingConfiguration": {"LogDestinationConfigs": []}}


class _CW:
    def get_metric_data(self, MetricDataQueries, **kw):
        return {"MetricDataResults": []}


def _weekly(monkeypatch, tmp_path, s):
    monkeypatch.chdir(tmp_path)
    # The WebACL name is a filename here and WAF allows only letters, digits, `-` and `_` in it.
    clients = {"cloudwatch": _CW(), "wafv2": _WAF("acl"), "logs": object()}
    monkeypatch.setattr(R, "get_client", lambda svc, **k: clients[svc])
    for name, value in [("_get_weekly_totals", lambda *a, **k: {"allowed": 100, "blocked": 5, "challenge": 0, "captcha": 0}),
                        ("_get_daily_breakdown", lambda *a, **k: []),
                        ("_get_top_countries", lambda *a, **k: []),
                        ("_get_top_rules", lambda *a, **k: []),
                        ("_get_attack_timeseries", lambda *a, **k: {"labels": [s], "series": {s: [5]}}),
                        ("_get_ddos_chart_data", lambda *a, **k: "")]:
        monkeypatch.setattr(R, name, value)
    for name, value in [("get_log_destination", lambda: ""), ("get_capabilities", lambda: {"bot_control": "none"}),
                        ("resolve_region", lambda scope: "us-east-1"), ("get_user_timezone", lambda: 0)]:
        monkeypatch.setattr(S, name, value)
    R.generate_weekly_report._tool_func(webacl_name="acl", start_time="2026-09-01", lang="en")
    path = next(pathlib.Path(tmp_path).glob("*.html"))
    R.set_report_summary(str(path), f"**Summary** for {s}.")
    return path.read_text()


def test_the_weekly_report_renders_every_string_as_text(monkeypatch, tmp_path):
    (tmp_path / "plain").mkdir(), (tmp_path / "hostile").mkdir()
    plain = _weekly(monkeypatch, tmp_path / "plain", "plain-value")
    hostile = _weekly(monkeypatch, tmp_path / "hostile", HOSTILE)
    assert "plain-value" in plain and "onerror" in hostile, "the precondition: the values reached the page"
    assert "<strong>Summary</strong>" in hostile, "the summary's Markdown still renders"
    assert _shape(hostile) == _shape(plain), "a value became markup"
    assert "</script><script>alert(2)" not in hostile


@pytest.mark.parametrize("value", [HOSTILE, {HOSTILE: [HOSTILE, (HOSTILE,)]}])
def test_escaped_reaches_every_string_keys_included(value):
    out = repr(escaped(value))
    assert "<" not in out and "\"" not in out and "&quot;" in out and "&#92;" in out, out


def test_escaped_leaves_everything_else_alone():
    assert escaped({"n": 7, "x": None, "f": 1.5}) == {"n": 7, "x": None, "f": 1.5}


def test_script_json_cannot_close_its_element_and_reads_back_the_same():
    import json
    text = script_json({"a": HOSTILE})
    assert "<" not in text and ">" not in text and json.loads(text) == {"a": HOSTILE}
