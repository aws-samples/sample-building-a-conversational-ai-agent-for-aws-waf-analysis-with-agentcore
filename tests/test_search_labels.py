# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every SEARCH query names its label, and every parser reads the named shape.

A SEARCH result's default label has no fixed format. Measured 2026-10-15:

- bot names on `shield-sample-webacl` (three bots) came back `go_http`, `googlebot`,
  `route53_health_check`; on `response-id-on-page` (one bot) the only series came back
  `AllowedRequests`, so `get_waf_overview(bot_names)` listed a bot called AllowedRequests;
- one geo label with two metrics came back `AllowRuleMatch` and `AllowedRequests`, so
  `top_labels` printed `awswaf:clientip:geo:country:US` twice;
- the same CountedRequests SEARCH came back `ALL` and `TGT_TokenAbsent` alone in a call, and
  `ALL CountedRequests` and `TGT_TokenAbsent CountedRequests` beside four other SEARCH queries; a
  lone series came back `CountedRequests`, which a rule-name parser reads as a rule.

`search_label` gives a `|`-joined template on every call. The fake below fills a template in, and
without one returns the measured default for a lone series, the metric name, so a query that loses
its template reads a metric name as a dimension value here exactly as it did live.
"""

import ast
import pathlib
import re
from datetime import datetime, timedelta, timezone

from tests.test_overview_old_window import render_label
from tools import report as R
from tools import waf_overview as O

ROOT = pathlib.Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc)
START, END = NOW - timedelta(hours=1), NOW


class LabelCW:
    """SEARCH over `series`, a list of `(dimensions, metric, value)` with WebACL implied. Every
    other query answers one zero point, which is what FILL gives a quiet series."""

    def __init__(self, series):
        self.series = series

    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
        out = []
        for q in MetricDataQueries:
            expr = q.get("Expression", "")
            if not expr.startswith("SEARCH("):
                if q.get("ReturnData", True):
                    out.append({"Id": q["Id"], "Label": "", "Values": [0], "Timestamps": [StartTime]})
                continue
            keys = set(re.search(r"\{AWS/WAFV2,([^}]*)\}", expr).group(1).split(",")) - {"WebACL"}
            filters = {k: v for k, v in re.findall(r'(\w+)="([^"]*)"', expr) if k != "WebACL"}
            any_of = re.search(r"MetricName=\(([^)]*)\)", expr)
            hits = [(d, m, v) for d, m, v in self.series if set(d) == keys
                    and (not any_of or m in re.findall(r'"(\w+)"', any_of.group(1)))
                    and all((m if k == "MetricName" else d.get(k)) == val for k, val in filters.items())]
            for d, m, v in hits:
                out.append({"Id": q["Id"], "Label": render_label(q, d, m, len(hits)),
                            "Values": [v], "Timestamps": [StartTime]})
        return {"MetricDataResults": out}


def _search_dicts(tree):
    """Dict literals whose `Expression` is a literal SEARCH."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = [k.value for k in node.keys if isinstance(k, ast.Constant)]
        if "Expression" not in keys:
            continue
        expr = node.values[keys.index("Expression")]
        head = expr.values[0] if isinstance(expr, ast.JoinedStr) and expr.values else expr
        if isinstance(head, ast.Constant) and str(head.value).startswith("SEARCH("):
            yield node, keys


def test_every_search_query_in_the_tools_names_its_label():
    found, missing = 0, []
    for path in sorted((ROOT / "tools").glob("*.py")):
        for node, keys in _search_dicts(ast.parse(path.read_text())):
            found += 1
            if "Label" not in keys:
                missing.append(f"{path.name}:{node.lineno}")
    assert found >= 20, f"the sweep found only {found} SEARCH queries; its matcher has drifted"
    assert not missing, missing


def test_report_top_rules_names_its_label():
    """The one SEARCH built in a variable, which the sweep above cannot see."""
    cw = LabelCW([({"Rule": "OnlyRule"}, "BlockedRequests", 9)])
    rows = R._get_top_rules(cw, "acl", START, END)
    assert [r["rule"] for r in rows] == ["OnlyRule"], rows


def test_a_lone_bot_is_named_not_called_by_its_metric():
    ns = "awswaf:managed:aws:bot-control:bot:name"
    cw = LabelCW([({"LabelName": "route53_health_check", "LabelNamespace": ns}, "AllowedRequests", 1893)])
    out = O._bot_names(cw, "acl", START, END, 60)
    assert "route53_health_check" in out and "AllowedRequests" not in out, out


def test_a_label_with_two_metrics_is_one_row_counted_once():
    us = {"LabelName": "US", "LabelNamespace": "awswaf:clientip:geo:country"}
    cw = LabelCW([(us, "AllowRuleMatch", 727), (us, "AllowedRequests", 727)])
    out = O._top_labels(cw, "acl", START, END, 60)
    rows = [l for l in out.splitlines() if "geo:country:US" in l]
    assert len(rows) == 1 and rows[0].split()[-1] == "727", out


def test_a_signal_is_not_counted_once_per_metric_family():
    """BlockRuleMatch counts matches, not requests: `LFI_URIPath` had 34 against 17 blocked."""
    sig = {"LabelName": "SignalAutomatedBrowser", "LabelNamespace": "awswaf:managed:aws:bot-control"}
    cw = LabelCW([(sig, "BlockedRequests", 17), (sig, "BlockRuleMatch", 34)])
    out = O._targeted_signals(cw, "acl", START, END, 60)
    row = next(l for l in out.splitlines() if l.startswith("SignalAutomatedBrowser"))
    assert row.split()[1] == "17", out


def test_an_attack_type_with_two_actions_is_one_row():
    cw = LabelCW([({"Attack": "SQLi"}, "BlockedRequests", 5), ({"Attack": "SQLi"}, "ChallengeRequests", 3)])
    out = O._attack_types(cw, "acl", START, END, 60)
    rows = [l for l in out.splitlines() if l.strip().startswith("SQLi")]
    assert len(rows) == 1 and rows[0].split()[-1] == "8", out


def test_the_report_names_a_lone_country_and_attack_type():
    cw = LabelCW([({"Country": "US"}, "BlockedRequests", 12), ({"Attack": "XSS"}, "BlockedRequests", 4)])
    assert R._get_top_countries(cw, "acl", START, END) == [{"country": "US", "count": 12}]
    assert list(R._get_attack_timeseries(cw, "acl", START, END)["series"]) == ["XSS"]


# --- the weekly report's bot section, which the label fix made reachable -------------------------

import pathlib as _pathlib

import pytest

from tools import session_state as S

TGT = {"LabelNamespace": "awswaf:managed:aws:bot-control", "LabelName": "TGT_TokenAbsent"}


def _fbv(name, org, verified):
    return {"BotCategory": "bot:category:monitoring", "BotName": name, "Intent": "bot:intent:x",
            "Organization": org, "VerificationStatus": "bot:verified" if verified else "bot:unverified"}


class _WAF:
    def list_web_acls(self, Scope):
        return {"WebACLs": [{"Name": "acl", "ARN": "arn:aws:wafv2:us-east-1:1:global/webacl/acl/1"}]}

    def get_logging_configuration(self, ResourceArn):
        return {"LoggingConfiguration": {"LogDestinationConfigs": []}}


@pytest.fixture
def bot_html(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def run(series):
        cw = LabelCW(series)
        monkeypatch.setattr(R, "get_client", lambda svc, **k: {"cloudwatch": cw, "wafv2": _WAF(), "logs": object()}[svc])
        for name, value in [("_get_weekly_totals", lambda *a, **k: {"allowed": 100, "blocked": 0, "challenge": 0, "captcha": 0}),
                            ("_get_daily_breakdown", lambda *a, **k: []), ("_get_top_countries", lambda *a, **k: []),
                            ("_get_top_rules", lambda *a, **k: []), ("_get_attack_timeseries", lambda *a, **k: {"series": {}}),
                            ("_get_ddos_chart_data", lambda *a, **k: "")]:
            monkeypatch.setattr(R, name, value)
        for name, value in [("get_log_destination", lambda: ""), ("get_capabilities", lambda: {"bot_control": "targeted"}),
                            ("resolve_region", lambda scope: "us-east-1"), ("get_user_timezone", lambda: 0)]:
            monkeypatch.setattr(S, name, value)
        R.generate_weekly_report._tool_func(webacl_name="acl", start_time="2026-10-01", lang="en")
        return next(_pathlib.Path(tmp_path).glob("*.html")).read_text()
    return run


def test_the_targeted_card_counts_requests_not_rule_matches(bot_html):
    """Measured for 2026-10-14: 7 requests carried TGT_TokenAbsent and CountRuleMatch said 14."""
    html = bot_html([(TGT, "AllowedRequests", 1174), (TGT, "BlockedRequests", 34), (TGT, "CountRuleMatch", 2413)])
    card = html.split("🎯 Advanced Bot Detection", 1)[1].split('<div class="card"', 1)[0]
    assert "<strong>1,208</strong>" in card and "2,413" not in card, card
    assert "Ended allowed" in card and "whichever rule ended it" in card, card


def test_a_name_claimed_by_an_unverified_client_is_not_a_good_bot(bot_html):
    html = bot_html([(_fbv("googlebot", "bot:organization:google", True), "SampleAllowedRequest", 50),
                     (_fbv("googlebot", "UNSPECIFIED", False), "SampleAllowedRequest", 40)])
    good = html.split("const gbd = ", 1)[1].split(";", 1)[0]
    unverified = html.split("const ubd = ", 1)[1].split(";", 1)[0]
    assert "Googlebot" in good and "Googlebot" in unverified, (good, unverified)


def test_a_short_report_reads_no_further_than_its_window(monkeypatch, tmp_path):
    """Every weekly figure was read at 604800 whatever `days` was, and a period longer than the
    window reads past its end (measured 2026-10-15: an hour at 604800 answered 130,678 allowed where
    the hour held 1,896). So a 3-day report counted 7 days, and its previous window ran into it."""
    monkeypatch.chdir(tmp_path)
    reads = []

    class Recording:
        def get_metric_data(self, MetricDataQueries, StartTime, EndTime, **kw):
            for q in MetricDataQueries:
                expr = q.get("Expression", "")
                period = (q["MetricStat"]["Period"] if "MetricStat" in q else
                          int(expr.rsplit(",", 1)[1].strip(" )")) if "SEARCH(" in expr else None)
                if period:
                    reads.append((period, (EndTime - StartTime).total_seconds(), q["Id"]))
            return {"MetricDataResults": []}
    monkeypatch.setattr(R, "get_client", lambda svc, **k: {"cloudwatch": Recording(), "wafv2": _WAF(), "logs": object()}[svc])
    for name, value in [("get_log_destination", lambda: ""), ("get_capabilities", lambda: {"bot_control": "targeted"}),
                        ("resolve_region", lambda scope: "us-east-1"), ("get_user_timezone", lambda: 0)]:
        monkeypatch.setattr(S, name, value)
    R.generate_weekly_report._tool_func(webacl_name="acl", start_time="2026-09-01", days=3, lang="en")
    assert len(reads) > 20, reads
    long = [r for r in reads if r[0] > r[1]]
    assert not long, long
