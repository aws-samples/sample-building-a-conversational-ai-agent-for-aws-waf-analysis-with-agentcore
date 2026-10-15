# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Patrol's per-rule assessment: the WebACL's own row is skipped on any account, and the baseline
text names the baseline it uses.

`_assess_rules_v2` skipped `{"ALL", "shield-sample-webacl"}`, the developer's WebACL, so on every
other account the WebACL-level row was assessed as if it were a rule. The table builder further
down already skipped `{"ALL", webacl_name}`. And the Chinese text said "昨日无基线" (no baseline
yesterday) for a baseline that is the same window seven days earlier.
"""

import ast
import pathlib

from tools import waf_patrol as P

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUSY = {"blocked": [900], "counted": [], "challenge": [], "captcha": []}


def test_the_webacl_row_is_skipped_for_the_webacl_being_scanned():
    items = P._assess_rules_v2({"my-acl": BUSY, "SomeRule": BUSY}, {}, [], None, "en", webacl_name="my-acl")
    rules = {i["rule"] for i in items}
    assert "SomeRule" in rules, f"the control: a real rule with no baseline is still assessed: {items}"
    assert "my-acl" not in rules, items


def test_no_literal_webacl_name_is_wired_into_the_tools():
    """Any account-specific name in executable code is this defect again. Docstrings are excluded
    (several cite measurements taken on that WebACL); comments never reach the AST."""
    hits = []
    for path in sorted((ROOT / "tools").glob("*.py")):
        tree = ast.parse(path.read_text())
        docs = {id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and n.body and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
        hits += [(path.name, n.lineno) for n in ast.walk(tree)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs
                 and n.value in ("shield-sample-webacl", "response-id-on-page")]
    assert not hits, hits


def test_the_no_baseline_text_names_the_week_earlier_window():
    items = P._assess_rules_v2({"SomeRule": BUSY}, {}, [], None, "zh", webacl_name="acl")
    text = next(i["text"] for i in items if i["rule"] == "SomeRule")
    assert "昨日" not in text and "上周同期" in text, text
    en = P._assess_rules_v2({"SomeRule": BUSY}, {}, [], None, "en", webacl_name="acl")
    assert "a week earlier" in next(i["text"] for i in en if i["rule"] == "SomeRule")


def _render(totals):
    from datetime import datetime, timezone
    wr = {"name": "acl", "scope": "CLOUDFRONT", "region": "us-east-1", "rules_table": [],
          "rate_limits": [], "detection_tools": [], "totals": totals}
    t = datetime(2026, 10, 1, tzinfo=timezone.utc)
    return P._render_patrol_html_v2([wr], [], t, t, 24, "en")


def test_the_traffic_donut_does_not_count_counted_requests_twice():
    """A counted request ends as allowed or blocked, so it is already in one of those. 100 blocked
    and 900 allowed is 1,000 requests, whatever Count matched; the donut said 1,050 and drew Count
    as a third slice."""
    import re
    html = _render({"blocked": 100, "challenge": 0, "captcha": 0, "counted": 50, "allowed": 900})
    assert "Total Requests: 1,000" in html, re.findall(r"Total Requests: [0-9,]+", html)
    donut = re.search(r'donut\("donut_acl",(\[[^\]]*\])', html)
    assert donut and donut.group(1) == "[100, 900]", donut and donut.group(1)
    assert "50" in html.split("donut-legend", 1)[1].split("</div>", 1)[0], "the Count figure vanished"


# --- per-rule metrics for a window whose rules have been quiet for 14 days ----------------------

class _CW:
    """SEARCH finds only `ALL`'s allowed series, which is what it returned for 2026-09-08 04:00 on
    the live account. An explicit MetricStat for the SQLi group answers 120 blocks."""
    def __init__(self):
        self.ids = []

    def get_metric_data(self, MetricDataQueries, **kw):
        from datetime import datetime, timezone
        ts = [datetime(2026, 9, 8, 4, tzinfo=timezone.utc)]
        self.ids = [q["Id"] for q in MetricDataQueries]
        out = [{"Id": "allowed", "Label": "ALL AllowedRequests", "Values": [1923], "Timestamps": ts}]
        for q in MetricDataQueries:
            stat = q.get("MetricStat")
            if stat and stat["Metric"]["MetricName"] == "BlockedRequests":
                rule = next(d["Value"] for d in stat["Metric"]["Dimensions"] if d["Name"] == "Rule")
                out.append({"Id": q["Id"], "Values": [120] if rule == "SQLiMetric" else [], "Timestamps": ts if rule == "SQLiMetric" else []})
        return {"MetricDataResults": out}


ACL = [{"Name": "AWS-AWSManagedRulesSQLiRuleSet",
        "VisibilityConfig": {"CloudWatchMetricsEnabled": True, "MetricName": "SQLiMetric"}},
       {"Name": "dark", "VisibilityConfig": {"CloudWatchMetricsEnabled": False, "MetricName": "dark"}}]


def test_a_rule_quiet_for_fourteen_days_is_still_read_for_an_old_window():
    from datetime import datetime, timezone
    cw = _CW()
    s, e = datetime(2026, 9, 8, 4, tzinfo=timezone.utc), datetime(2026, 9, 8, 5, tzinfo=timezone.utc)
    m = P._get_all_rules_metrics_search(cw, "acl", s, e, period=3600, rules=ACL)
    assert sum(m.get("SQLiMetric", {}).get("blocked", [])) == 120, m
    assert sum(m["ALL"]["allowed"]) == 1923, "the SEARCH answer was lost in the merge"


def test_a_rule_with_metrics_off_is_not_queried():
    from datetime import datetime, timezone
    cw = _CW()
    P._get_all_rules_metrics_search(cw, "acl", datetime(2026, 9, 8, tzinfo=timezone.utc),
                                    datetime(2026, 9, 9, tzinfo=timezone.utc), rules=ACL)
    assert len([i for i in cw.ids if i.startswith("x")]) == 10, cw.ids  # ALL and SQLiMetric, five metrics each


def test_without_rules_only_search_is_asked():
    from datetime import datetime, timezone
    cw = _CW()
    P._get_all_rules_metrics_search(cw, "acl", datetime(2026, 9, 8, tzinfo=timezone.utc),
                                    datetime(2026, 9, 9, tzinfo=timezone.utc))
    assert cw.ids == ["blocked", "counted", "challenge", "captcha", "allowed"], cw.ids


def test_patrol_passes_the_webacl_rules_to_both_windows():
    import ast, inspect
    calls = [n for n in ast.walk(ast.parse(inspect.getsource(P.patrol_scan._tool_func)))
             if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_get_all_rules_metrics_search"]
    assert len(calls) == 2, len(calls)
    assert all(any(k.arg == "rules" for k in c.keywords) for c in calls), [ast.unparse(c) for c in calls]
