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
:root.dark {{ --bg: #0d1117; --fg: #e6edf3; --card: #161b22; --border: #30363d; --accent: #58a6ff; --green: #3fb950; --red: #f85149; --muted: #8b949e; --chart-text: #e6edf3; }}
:root.light {{ --bg: #ffffff; --fg: #1f2328; --card: #f6f8fa; --border: #d0d7de; --accent: #0969da; --green: #1a7f37; --red: #cf222e; --muted: #656d76; --chart-text: #1f2328; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--fg); padding: 2rem; max-width: 1200px; margin: 0 auto; line-height: 1.6; }}
h1 {{ color: var(--accent); margin-bottom: .5rem; }}
h2 {{ color: var(--accent); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; }}
.subtitle {{ color: var(--muted); margin-bottom: 2rem; }}
.theme-toggle {{ position: fixed; top: 1rem; right: 1rem; background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: .4rem .8rem; cursor: pointer; color: var(--fg); font-size: .85rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }}
.card .label {{ color: var(--muted); font-size: .85rem; margin-bottom: .3rem; }}
.card .value {{ font-size: 1.8rem; font-weight: 700; }}
.card .change {{ font-size: .85rem; margin-top: .3rem; }}
.up {{ color: var(--red); }}
.down {{ color: var(--green); }}
.neutral {{ color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card); border-radius: 6px; overflow: hidden; }}
th {{ background: var(--border); text-align: left; padding: .6rem .8rem; font-size: .85rem; }}
td {{ padding: .5rem .8rem; border-top: 1px solid var(--border); }}
.chart-container {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
canvas {{ max-height: 300px; }}
.highlight {{ background: var(--accent); color: #fff; padding: .1rem .4rem; border-radius: 3px; font-weight: 600; }}
.roi-box {{ background: var(--card); border: 2px solid var(--green); border-radius: 8px; padding: 1.5rem; margin: 1rem 0; text-align: center; }}
.roi-box .value {{ font-size: 2.5rem; font-weight: 700; color: var(--green); }}
@media print {{ .theme-toggle {{ display: none; }} }}
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Theme</button>
<h1>WAF Weekly Report</h1>
<p class="subtitle">{webacl_name} — {date_range}</p>

<h2>Executive Summary</h2>
<p>{executive_summary}</p>

<h2>Protection Value (ROI)</h2>
<div class="grid">
  <div class="roi-box"><div class="label">Threats Mitigated</div><div class="value">{threats_mitigated}</div><div class="change">Blocked + Challenged</div></div>
  <div class="card"><div class="label">Challenges Issued</div><div class="value">{challenge_total}</div><div class="change">Challenge {challenge_count} + CAPTCHA {captcha_count}</div></div>
  <div class="card"><div class="label">Bot Requests Identified</div><div class="value">{bot_requests}</div><div class="change">{bot_pct}% of total traffic</div></div>
  <div class="card"><div class="label">Attack Requests Blocked</div><div class="value">{blocked_requests}</div><div class="change">{block_rate}% block rate</div></div>
</div>

<h2>Traffic Overview</h2>
<div class="grid">
  <div class="card"><div class="label">Total Requests</div><div class="value">{total_requests}</div><div class="change {total_change_class}">{total_change}</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value">{allowed_requests}</div></div>
  <div class="card"><div class="label">Blocked</div><div class="value">{blocked_requests}</div><div class="change {blocked_change_class}">{blocked_change}</div></div>
  <div class="card"><div class="label">Challenged</div><div class="value">{challenge_total}</div></div>
</div>

<div class="chart-container"><canvas id="dailyChart"></canvas></div>

<h2>Challenge / CAPTCHA</h2>
<div class="grid">
  <div class="card"><div class="label">Challenge Issued</div><div class="value">{challenge_count}</div></div>
  <div class="card"><div class="label">CAPTCHA Issued</div><div class="value">{captcha_count}</div></div>
  <div class="card"><div class="label">Challenge Solved (token acquired)</div><div class="value">{challenge_solved}</div></div>
</div>

{antiddos_section}

<h2>Top Attack Sources (Countries)</h2>
<table>
<tr><th>Country</th><th>Blocked Requests</th><th>% of Total Blocked</th></tr>
{country_rows}
</table>

<h2>Protection Breakdown (Rules)</h2>
<table>
<tr><th>Rule</th><th>Requests Handled</th><th>Action</th></tr>
{rule_rows}
</table>

<script>
const dailyData = {daily_data_json};
const chartTextColor = getComputedStyle(document.documentElement).getPropertyValue('--chart-text').trim() || '#e6edf3';
new Chart(document.getElementById('dailyChart'), {{
  type: 'bar',
  data: {{
    labels: dailyData.map(d => d.date),
    datasets: [
      {{ label: 'Allowed', data: dailyData.map(d => d.allowed), backgroundColor: '#3fb950' }},
      {{ label: 'Blocked', data: dailyData.map(d => d.blocked), backgroundColor: '#cf222e' }},
      {{ label: 'Challenged', data: dailyData.map(d => d.challenged), backgroundColor: '#d29922' }},
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{ title: {{ display: true, text: 'Daily Request Volume by Action', color: chartTextColor }}, legend: {{ labels: {{ color: chartTextColor }} }} }},
    scales: {{ x: {{ stacked: true, ticks: {{ color: chartTextColor }} }}, y: {{ stacked: true, ticks: {{ color: chartTextColor }} }} }}
  }}
}});

function toggleTheme() {{
  const root = document.documentElement;
  root.classList.toggle('dark');
  root.classList.toggle('light');
}}
document.documentElement.classList.add('{default_theme}');
</script>
</body>
</html>
"""


@tool
def generate_weekly_report(webacl_name: str, scope: str = "CLOUDFRONT", theme: str = "dark") -> str:
    """Generate a WAF weekly report as HTML with charts showing protection value (ROI).

    Queries CloudWatch Metrics for the past 7 days and produces an HTML report
    focused on demonstrating WAF value: threats mitigated, challenge effectiveness,
    bot detection rates, and week-over-week trends.

    Args:
        webacl_name: Name of the WebACL to report on.
        scope: WAF scope — "CLOUDFRONT" or "REGIONAL".
        theme: Default theme — "dark" (for projection) or "light" (for PDF). User can toggle in browser.

    Returns:
        Path to the generated HTML file, or error message.
    """
    region = "us-east-1" if scope == "CLOUDFRONT" else region
    from tools.session_state import get_metrics_region
    if scope != "CLOUDFRONT":
        region = get_metrics_region()
    cw = get_client("cloudwatch", region_name=region)

    end = datetime.now(timezone.utc)
    start_this_week = end - timedelta(days=7)
    start_last_week = start_this_week - timedelta(days=7)

    this_week = _get_weekly_totals(cw, webacl_name, start_this_week, end)
    last_week = _get_weekly_totals(cw, webacl_name, start_last_week, start_this_week)
    daily = _get_daily_breakdown(cw, webacl_name, start_this_week, end)
    countries = _get_top_countries(cw, webacl_name, start_this_week, end)
    rules = _get_top_rules(cw, webacl_name, start_this_week, end)

    total_this = this_week["allowed"] + this_week["blocked"] + this_week["challenge"]
    total_last = last_week["allowed"] + last_week["blocked"] + last_week["challenge"]

    # Challenge total
    challenge_total = this_week["challenge"] + this_week["captcha"]

    # Challenge/CAPTCHA solved — query logs for token:accepted after challenge
    challenge_solved = 0
    captcha_solved = 0
    if challenge_total > 0:
        log_dest = None
        from tools.session_state import get_log_destination
        log_dest = get_log_destination()
        if log_dest and ":log-group:" in log_dest:
            import time
            log_group = log_dest.split(":log-group:")[-1].rstrip(":*")
            logs_client = get_client("logs", region_name=region)
            log_end = int(end.timestamp())
            log_start = int(start_this_week.timestamp())
            # Count requests with valid challenge token (= solved challenge)
            try:
                resp = logs_client.start_query(
                    logGroupName=log_group, startTime=log_start, endTime=log_end,
                    queryString="filter @message like 'token:accepted' | stats count(*) as cnt",
                    limit=1,
                )
                time.sleep(8)
                result = logs_client.get_query_results(queryId=resp["queryId"])
                for row in result.get("results", []):
                    d = {f["field"]: f["value"] for f in row}
                    challenge_solved = int(d.get("cnt", 0))
            except Exception:
                pass

    # Bot requests — narrow matching to avoid false matches (e.g., VulnerabilityCategory)
    bot_keywords = ("CategoryHttpLibrary", "CategoryBot", "CategorySocialMedia", "CategorySearchEngine",
                    "CategorySeo", "CategoryAdvertising", "CategoryArchiver", "CategoryContentFetcher",
                    "SignalNonBrowserUserAgent", "SignalAutomatedBrowser", "TGT_")
    bot_rules = [r for r in rules if any(k in r["rule"] for k in bot_keywords) and r["action"] == "COUNT"]
    bot_requests = bot_rules[0]["count"] if bot_rules else 0
    bot_pct = f"{(bot_requests / total_this * 100):.1f}" if total_this > 0 else "0"

    # Threats mitigated = blocked + challenged
    threats_mitigated = this_week["blocked"] + challenge_total

    def fmt_change(current, previous):
        if previous == 0:
            return "N/A (no data last week)", "neutral"
        pct = ((current - previous) / previous) * 100
        arrow = "↑" if pct > 0 else "↓"
        cls = "up" if pct > 0 else "down"
        return f"{arrow} {abs(pct):.1f}% vs last week", cls

    total_change, total_change_class = fmt_change(total_this, total_last)
    blocked_change, blocked_change_class = fmt_change(this_week["blocked"], last_week["blocked"])
    block_rate = f"{(this_week['blocked'] / total_this * 100):.1f}" if total_this > 0 else "0"

    # Anti-DDoS AMR events — query label metrics
    antiddos_section = ""
    ddos_events = 0
    if challenge_total > 0:  # Only check if we have log access
        try:
            from tools.session_state import get_log_destination as _get_log_dest
            log_dest = _get_log_dest()
            if log_dest and ":log-group:" in log_dest:
                import time as _time
                _log_group = log_dest.split(":log-group:")[-1].rstrip(":*")
                _logs = get_client("logs", region_name=region)
                _log_end = int(end.timestamp())
                _log_start = int(start_this_week.timestamp())
                resp = _logs.start_query(
                    logGroupName=_log_group, startTime=_log_start, endTime=_log_end,
                    queryString="filter @message like 'anti-ddos:event-detected' | stats count(*) as cnt, min(@timestamp) as first, max(@timestamp) as last",
                    limit=1,
                )
                _time.sleep(8)
                result = _logs.get_query_results(queryId=resp["queryId"])
                for row in result.get("results", []):
                    d = {f["field"]: f["value"] for f in row}
                    ddos_events = int(d.get("cnt", 0))
                    if ddos_events > 0:
                        antiddos_section = (
                            f'<h2>Anti-DDoS Events</h2>'
                            f'<div class="grid">'
                            f'<div class="roi-box"><div class="label">DDoS Events Detected</div><div class="value">{ddos_events:,}</div></div>'
                            f'<div class="card"><div class="label">First Detected</div><div class="value">{d.get("first", "N/A")}</div></div>'
                            f'<div class="card"><div class="label">Last Detected</div><div class="value">{d.get("last", "N/A")}</div></div>'
                            f'</div>'
                        )
        except Exception:
            pass

    country_rows = ""
    for c in countries[:10]:
        pct = f"{c['count'] / max(this_week['blocked'], 1) * 100:.1f}"
        country_rows += f"<tr><td>{c['country']}</td><td>{c['count']:,}</td><td>{pct}%</td></tr>\n"

    # Separate BLOCK rules from COUNT rules for clarity
    rule_rows = ""
    block_rules = [r for r in rules if r["action"] == "BLOCK"]
    count_rules = [r for r in rules if r["action"] == "COUNT"]
    challenge_rules = [r for r in rules if r["action"] == "CHALLENGE"]
    for r in block_rules[:5]:
        rule_rows += f"<tr><td>{r['rule']}</td><td>{r['count']:,}</td><td>🚫 Block</td></tr>\n"
    for r in challenge_rules[:5]:
        rule_rows += f"<tr><td>{r['rule']}</td><td>{r['count']:,}</td><td>⚡ Challenge</td></tr>\n"
    for r in count_rules[:5]:
        rule_rows += f"<tr><td>{r['rule']}</td><td>{r['count']:,}</td><td>🏷️ Labeled</td></tr>\n"

    executive_summary = "{{EXECUTIVE_SUMMARY}}"

    date_range = f"{start_this_week.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}"

    html = REPORT_TEMPLATE.format(
        webacl_name=webacl_name,
        date_range=date_range,
        default_theme=theme,
        executive_summary=executive_summary,
        total_requests=f"{total_this:,}",
        allowed_requests=f"{this_week['allowed']:,}",
        total_change=total_change,
        total_change_class=total_change_class,
        blocked_requests=f"{this_week['blocked']:,}",
        blocked_change=blocked_change,
        blocked_change_class=blocked_change_class,
        block_rate=block_rate,
        threats_mitigated=f"{threats_mitigated:,}",
        challenge_total=f"{challenge_total:,}",
        challenge_count=f"{this_week['challenge']:,}",
        captcha_count=f"{this_week['captcha']:,}",
        challenge_solved=f"{challenge_solved:,}",
        antiddos_section=antiddos_section,
        bot_requests=f"{bot_requests:,}",
        bot_pct=bot_pct,
        country_rows=country_rows,
        rule_rows=rule_rows,
        daily_data_json=json.dumps(daily),
    )

    output_path = f"waf-weekly-report-{webacl_name}-{end.strftime('%Y%m%d')}.html"
    with open(output_path, "w") as f:
        f.write(html)

    return (
        f"Report generated: {output_path}\n\n"
        f"## Data for Executive Summary (write this, then call set_report_summary)\n"
        f"- Total requests: {total_this:,}\n"
        f"- Threats mitigated: {threats_mitigated:,} (blocked {this_week['blocked']:,} + challenged {challenge_total:,})\n"
        f"- Bot/suspicious requests identified: {bot_requests:,} ({bot_pct}% of traffic)\n"
        f"- Top attack sources: {', '.join(c['country'] for c in countries[:3])}\n"
        f"- Top blocking rules: {', '.join(r['rule'] + '=' + str(r['count']) for r in [r for r in rules if r['action']=='BLOCK'][:3])}\n"
        f"- Week-over-week: {total_change}\n"
        f"- Challenge issued: {challenge_total:,}\n"
        f"- Daily trend: {'spike on ' + max(daily, key=lambda d: d['blocked']+d['challenged'])['date'] if daily else 'steady'}\n\n"
        f"Write a compelling executive summary (2-3 sentences) answering: What happened? What did WAF protect? Is the money well spent? "
        f"Then call set_report_summary(path='{output_path}', summary='your summary here') to finalize the report."
    )


def _get_weekly_totals(cw, webacl_name: str, start, end) -> dict:
    """Get total allowed/blocked/challenge/captcha for a time range."""
    queries = []
    metrics = ["AllowedRequests", "BlockedRequests", "ChallengeRequests", "CaptchaRequests"]
    for i, metric in enumerate(metrics):
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
                "Period": 604800,
                "Stat": "Sum",
            },
        })

    resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end)
    results = {r["Id"]: sum(r.get("Values", [0])) for r in resp["MetricDataResults"]}
    return {
        "allowed": int(results.get("m0", 0)),
        "blocked": int(results.get("m1", 0)),
        "challenge": int(results.get("m2", 0)),
        "captcha": int(results.get("m3", 0)),
    }


def _get_daily_breakdown(cw, webacl_name: str, start, end) -> list:
    """Get daily allowed/blocked/challenged counts."""
    queries = []
    for i, metric in enumerate(["AllowedRequests", "BlockedRequests", "ChallengeRequests"]):
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

    data = {}
    for r in resp["MetricDataResults"]:
        for ts, val in zip(r.get("Timestamps", []), r.get("Values", [])):
            day = ts.strftime("%m/%d")
            if day not in data:
                data[day] = {"date": day, "allowed": 0, "blocked": 0, "challenged": 0}
            if r["Id"] == "d0":
                data[day]["allowed"] = int(val)
            elif r["Id"] == "d1":
                data[day]["blocked"] = int(val)
            elif r["Id"] == "d2":
                data[day]["challenged"] = int(val)

    return [data[d] for d in sorted(data.keys())]


def _get_top_countries(cw, webacl_name: str, start, end) -> list:
    """Get top countries by blocked requests using SEARCH."""
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
            label = r.get("Label", "")
            country = _extract_dimension_from_label(label, "Country") or label
            results.append({"country": country, "count": int(total)})

    return sorted(results, key=lambda x: x["count"], reverse=True)


def _get_top_rules(cw, webacl_name: str, start, end) -> list:
    """Get top rules by hit count using SEARCH."""
    if not re.match(r'^[\w-]+$', webacl_name):
        return []
    results = []
    for action in ["BlockedRequests", "CountedRequests", "ChallengeRequests"]:
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
                act_map = {"BlockedRequests": "BLOCK", "CountedRequests": "COUNT", "ChallengeRequests": "CHALLENGE"}
                results.append({"rule": rule, "count": int(total), "action": act_map.get(action, "?")})

    return sorted(results, key=lambda x: x["count"], reverse=True)


def _extract_dimension_from_label(label: str, dimension: str) -> str:
    """Extract dimension value from CloudWatch metric label string."""
    for part in label.split():
        if part.startswith(f"{dimension}="):
            return part.split("=", 1)[1]
    return ""


@tool
def set_report_summary(path: str, summary: str) -> str:
    """Finalize a weekly report by injecting the executive summary.

    Call this after generate_weekly_report, with a compelling executive summary
    that answers: What happened this week? What did WAF protect? Is the investment worth it?

    Args:
        path: Path to the HTML report file (returned by generate_weekly_report).
        summary: Executive summary text (HTML allowed for emphasis, 2-4 sentences).

    Returns:
        Confirmation message.
    """
    try:
        with open(path, "r") as f:
            html = f.read()
        html = html.replace("{{EXECUTIVE_SUMMARY}}", summary)
        with open(path, "w") as f:
            f.write(html)
        return f"Report finalized: {path}"
    except FileNotFoundError:
        return f"Error: Report file not found at {path}"
