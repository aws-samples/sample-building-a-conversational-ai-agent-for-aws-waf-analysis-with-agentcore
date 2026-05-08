"""Weekly Report generation tool."""

import json
import re
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client

REPORT_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WAF Weekly Report — {webacl_name}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1"></script>
<style>
:root {{ --bg: #0d1117; --fg: #e6edf3; --card: #161b22; --border: #30363d; --accent: #58a6ff; --green: #3fb950; --red: #f85149; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--fg); padding: 2rem; max-width: 1200px; margin: 0 auto; }}
h1 {{ color: var(--accent); margin-bottom: .5rem; }}
h2 {{ color: var(--accent); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; }}
.subtitle {{ color: #8b949e; margin-bottom: 2rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }}
.card .label {{ color: #8b949e; font-size: .85rem; margin-bottom: .3rem; }}
.card .value {{ font-size: 1.8rem; font-weight: 700; }}
.card .change {{ font-size: .85rem; margin-top: .3rem; }}
.up {{ color: var(--red); }}
.down {{ color: var(--green); }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card); border-radius: 6px; overflow: hidden; }}
th {{ background: var(--border); text-align: left; padding: .6rem .8rem; font-size: .85rem; }}
td {{ padding: .5rem .8rem; border-top: 1px solid var(--border); }}
.chart-container {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
canvas {{ max-height: 300px; }}
@media print {{ body {{ background: #fff; color: #000; }} .card {{ border-color: #ddd; }} }}
</style>
</head>
<body>
<h1>WAF Weekly Report</h1>
<p class="subtitle">{webacl_name} — {date_range}</p>

<h2>Executive Summary</h2>
<p>{executive_summary}</p>

<h2>Traffic Overview</h2>
<div class="grid">
  <div class="card"><div class="label">Total Requests</div><div class="value">{total_requests}</div><div class="change {total_change_class}">{total_change}</div></div>
  <div class="card"><div class="label">Blocked</div><div class="value">{blocked_requests}</div><div class="change {blocked_change_class}">{blocked_change}</div></div>
  <div class="card"><div class="label">Block Rate</div><div class="value">{block_rate}%</div></div>
  <div class="card"><div class="label">Challenged</div><div class="value">{challenge_requests}</div></div>
</div>

<div class="chart-container"><canvas id="dailyChart"></canvas></div>

<h2>Top Countries (Blocked)</h2>
<table>
<tr><th>Country</th><th>Blocked Requests</th><th>% of Total Blocked</th></tr>
{country_rows}
</table>

<h2>Top Rules Triggered</h2>
<table>
<tr><th>Rule</th><th>Count</th><th>Action</th></tr>
{rule_rows}
</table>

<script>
const dailyData = {daily_data_json};
new Chart(document.getElementById('dailyChart'), {{
  type: 'bar',
  data: {{
    labels: dailyData.map(d => d.date),
    datasets: [
      {{ label: 'Allowed', data: dailyData.map(d => d.allowed), backgroundColor: '#3fb950' }},
      {{ label: 'Blocked', data: dailyData.map(d => d.blocked), backgroundColor: '#f85149' }},
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{ title: {{ display: true, text: 'Daily Request Volume', color: '#e6edf3' }} }},
    scales: {{ x: {{ stacked: true, ticks: {{ color: '#8b949e' }} }}, y: {{ stacked: true, ticks: {{ color: '#8b949e' }} }} }}
  }}
}});
</script>
</body>
</html>
"""


@tool
def generate_weekly_report(webacl_name: str, scope: str = "CLOUDFRONT") -> str:
    """Generate a WAF weekly report as HTML with charts.

    Queries CloudWatch Metrics for the past 7 days and produces an HTML report
    showing traffic overview, block rates, top countries, and top rules.

    Args:
        webacl_name: Name of the WebACL to report on.
        scope: WAF scope — "CLOUDFRONT" or "REGIONAL".

    Returns:
        Path to the generated HTML file, or error message.
    """
    region = "us-east-1" if scope == "CLOUDFRONT" else "us-east-1"  # TODO: support regional
    cw = get_client("cloudwatch", region_name=region)

    end = datetime.now(timezone.utc)
    start_this_week = end - timedelta(days=7)
    start_last_week = start_this_week - timedelta(days=7)

    # Fetch this week + last week metrics
    this_week = _get_weekly_totals(cw, webacl_name, start_this_week, end)
    last_week = _get_weekly_totals(cw, webacl_name, start_last_week, start_this_week)

    # Daily breakdown
    daily = _get_daily_breakdown(cw, webacl_name, start_this_week, end)

    # Top countries (blocked)
    countries = _get_top_countries(cw, webacl_name, start_this_week, end)

    # Top rules
    rules = _get_top_rules(cw, webacl_name, start_this_week, end)

    # Calculate changes
    total_this = this_week["allowed"] + this_week["blocked"]
    total_last = last_week["allowed"] + last_week["blocked"]
    blocked_this = this_week["blocked"]
    blocked_last = last_week["blocked"]

    def fmt_change(current, previous):
        if previous == 0:
            return "N/A", ""
        pct = ((current - previous) / previous) * 100
        arrow = "↑" if pct > 0 else "↓"
        cls = "up" if pct > 0 else "down"
        return f"{arrow} {abs(pct):.1f}% vs last week", cls

    total_change, total_change_class = fmt_change(total_this, total_last)
    blocked_change, blocked_change_class = fmt_change(blocked_this, blocked_last)
    block_rate = f"{(blocked_this / total_this * 100):.1f}" if total_this > 0 else "0"

    # Build country rows
    country_rows = ""
    for c in countries[:10]:
        pct = f"{c['count'] / blocked_this * 100:.1f}" if blocked_this > 0 else "0"
        country_rows += f"<tr><td>{c['country']}</td><td>{c['count']:,}</td><td>{pct}%</td></tr>\n"

    # Build rule rows
    rule_rows = ""
    for r in rules[:10]:
        rule_rows += f"<tr><td>{r['rule']}</td><td>{r['count']:,}</td><td>{r['action']}</td></tr>\n"

    # Executive summary placeholder (to be filled by LLM in agent loop)
    executive_summary = (
        f"This week WAF processed {total_this:,} requests, blocking {blocked_this:,} "
        f"({block_rate}% block rate). "
    )
    if total_last > 0:
        executive_summary += f"Compared to last week: total traffic {total_change.lower()}."

    date_range = f"{start_this_week.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}"

    html = REPORT_TEMPLATE.format(
        webacl_name=webacl_name,
        date_range=date_range,
        executive_summary=executive_summary,
        total_requests=f"{total_this:,}",
        total_change=total_change,
        total_change_class=total_change_class,
        blocked_requests=f"{blocked_this:,}",
        blocked_change=blocked_change,
        blocked_change_class=blocked_change_class,
        block_rate=block_rate,
        challenge_requests=f"{this_week.get('challenge', 0):,}",
        country_rows=country_rows,
        rule_rows=rule_rows,
        daily_data_json=json.dumps(daily),
    )

    # Write to file
    output_path = f"waf-weekly-report-{webacl_name}-{end.strftime('%Y%m%d')}.html"
    with open(output_path, "w") as f:
        f.write(html)

    return f"Report generated: {output_path}\n\nSummary: {executive_summary}"


def _get_weekly_totals(cw, webacl_name: str, start, end) -> dict:
    """Get total allowed/blocked/challenge for a time range."""
    queries = []
    for i, metric in enumerate(["AllowedRequests", "BlockedRequests", "ChallengeRequests"]):
        queries.append({
            "Id": f"m{i}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/WAFV2",
                    "MetricName": metric,
                    "Dimensions": [
                        {"Name": "WebACL", "Value": webacl_name},
                        {"Name": "Rule", "Value": "ALL"},
                    ],
                },
                "Period": 604800,  # 7 days
                "Stat": "Sum",
            },
        })

    resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end)
    results = {r["Id"]: sum(r.get("Values", [0])) for r in resp["MetricDataResults"]}
    return {
        "allowed": int(results.get("m0", 0)),
        "blocked": int(results.get("m1", 0)),
        "challenge": int(results.get("m2", 0)),
    }


def _get_daily_breakdown(cw, webacl_name: str, start, end) -> list:
    """Get daily allowed/blocked counts."""
    queries = []
    for i, metric in enumerate(["AllowedRequests", "BlockedRequests"]):
        queries.append({
            "Id": f"d{i}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/WAFV2",
                    "MetricName": metric,
                    "Dimensions": [
                        {"Name": "WebACL", "Value": webacl_name},
                        {"Name": "Rule", "Value": "ALL"},
                    ],
                },
                "Period": 86400,
                "Stat": "Sum",
            },
        })

    resp = cw.get_metric_data(
        MetricDataQueries=queries, StartTime=start, EndTime=end, ScanBy="TimestampAscending"
    )

    allowed_data = {}
    blocked_data = {}
    for r in resp["MetricDataResults"]:
        for ts, val in zip(r.get("Timestamps", []), r.get("Values", [])):
            day = ts.strftime("%m/%d")
            if r["Id"] == "d0":
                allowed_data[day] = int(val)
            else:
                blocked_data[day] = int(val)

    days = sorted(set(list(allowed_data.keys()) + list(blocked_data.keys())))
    return [{"date": d, "allowed": allowed_data.get(d, 0), "blocked": blocked_data.get(d, 0)} for d in days]


def _get_top_countries(cw, webacl_name: str, start, end) -> list:
    """Get top countries by blocked requests using SEARCH."""
    # WebACL names are alphanumeric + hyphen; reject anything else
    if not re.match(r'^[\w-]+$', webacl_name):
        return []
    expression = (
        f"SEARCH('{{AWS/WAFV2,Country,WebACL}} "
        f"MetricName=\"BlockedRequests\" WebACL=\"{webacl_name}\"', 'Sum', 604800)"
    )
    resp = cw.get_metric_data(
        MetricDataQueries=[{"Id": "countries", "Expression": expression}],
        StartTime=start,
        EndTime=end,
    )

    results = []
    for r in resp.get("MetricDataResults", []):
        total = sum(r.get("Values", []))
        if total > 0:
            # Label format is typically "BlockedRequests WebACL=xxx Country=US"
            label = r.get("Label", "")
            country = _extract_dimension_from_label(label, "Country") or label
            results.append({"country": country, "count": int(total)})

    return sorted(results, key=lambda x: x["count"], reverse=True)


def _get_top_rules(cw, webacl_name: str, start, end) -> list:
    """Get top rules by hit count using SEARCH."""
    results = []
    for action in ["BlockedRequests", "CountedRequests"]:
        expression = (
            f"SEARCH('{{AWS/WAFV2,Rule,WebACL}} "
            f"MetricName=\"{action}\" WebACL=\"{webacl_name}\"', 'Sum', 604800)"
        )
        resp = cw.get_metric_data(
            MetricDataQueries=[{"Id": f"rules_{action}", "Expression": expression}],
            StartTime=start,
            EndTime=end,
        )
        for r in resp.get("MetricDataResults", []):
            total = sum(r.get("Values", []))
            if total > 0:
                label = r.get("Label", "")
                rule = _extract_dimension_from_label(label, "Rule") or label
                if rule == "ALL":
                    continue
                act = "BLOCK" if "Blocked" in action else "COUNT"
                results.append({"rule": rule, "count": int(total), "action": act})

    return sorted(results, key=lambda x: x["count"], reverse=True)


def _extract_dimension_from_label(label: str, dimension: str) -> str:
    """Extract dimension value from CloudWatch metric label string."""
    # Label format: "MetricName DimName=Value DimName2=Value2"
    for part in label.split():
        if part.startswith(f"{dimension}="):
            return part.split("=", 1)[1]
    return ""
