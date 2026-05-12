# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF ROI Report generation tool."""

import json
import re
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client

# Module-level storage for the latest report HTML (served via GET /report)
_latest_report_html: str | None = None

# Human-readable names for AWS WAF rule labels (management-friendly)
_FRIENDLY_NAMES = {
    "CategoryHttpLibrary": "HTTP Libraries (curl, python-requests)",
    "CategorySearchEngine": "Search Engines (Google, Bing)",
    "CategorySeo": "SEO Crawlers",
    "CategorySocialMedia": "Social Media Bots",
    "CategoryAdvertising": "Advertising Bots",
    "CategoryArchiver": "Web Archivers",
    "CategoryContentFetcher": "Content Fetchers",
    "CategoryScrapingFramework": "Scraping Frameworks",
    "CategoryMonitoring": "Monitoring Services",
    "CategorySecurity": "Security Scanners",
    "CategoryAI": "AI Crawlers",
    "CategoryMiscellaneous": "Miscellaneous Bots",
    "CategoryEmailClient": "Email Clients",
    "CategoryPagePreview": "Page Preview Bots",
    "CategoryLinkChecker": "Link Checkers",
    "CategoryWebhooks": "Webhook Services",
    "SignalNonBrowserUserAgent": "Non-Browser User Agents",
    "SignalAutomatedBrowser": "Automated Browsers",
    "SignalKnownBotDataCenter": "Known Bot Data Centers",
    "TGT_VolumetricIpTokenAbsent": "High-Volume Requests Without Token",
    "TGT_TokenAbsent": "Requests Missing Security Token",
    "TGT_VolumetricSession": "Abnormal Session Volume",
    "TGT_VolumetricSessionMaximum": "Session Volume Exceeded Maximum",
    "TGT_SignalAutomatedBrowser": "Browser Automation Detected",
    "TGT_SignalBrowserInconsistency": "Browser Fingerprint Mismatch",
    "TGT_SignalBrowserAutomationExtension": "Automation Extension Detected",
    "TGT_TokenReuseIpHigh": "Token Reused Across IPs (High)",
    "TGT_TokenReuseIpMedium": "Token Reused Across IPs (Medium)",
    "TGT_TokenReuseIpLow": "Token Reused Across IPs (Low)",
    "TGT_TokenReuseAsnHigh": "Token Reused Across Networks (High)",
    "TGT_TokenReuseAsnMedium": "Token Reused Across Networks (Medium)",
    "TGT_TokenReuseAsnLow": "Token Reused Across Networks (Low)",
    "TGT_TokenReuseCountryHigh": "Token Reused Across Countries (High)",
    "TGT_TokenReuseCountryMedium": "Token Reused Across Countries (Medium)",
    "TGT_TokenReuseCountryLow": "Token Reused Across Countries (Low)",
    "TGT_ML_CoordinatedActivityHigh": "Coordinated Bot Activity (High)",
    "TGT_ML_CoordinatedActivityMedium": "Coordinated Bot Activity (Medium)",
    "TGT_ML_CoordinatedActivityLow": "Coordinated Bot Activity (Low)",
}

REPORT_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WAF ROI Report — {webacl_name}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1"></script>
<script src="https://cdn.jsdelivr.net/npm/hammerjs@2.0.8"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.2.0"></script>
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
.summary p {{ margin-bottom: 1rem; line-height: 1.8; }}
.summary strong {{ color: var(--accent); }}
.roi-box {{ background: var(--card); border: 2px solid var(--green); border-radius: 8px; padding: 1.5rem; margin: 1rem 0; text-align: center; }}
.roi-box .value {{ font-size: 2.5rem; font-weight: 700; color: var(--green); }}
@media print {{ .theme-toggle {{ display: none; }} }}
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Theme</button>
<h1>AWS WAF Weekly Business Report</h1>
<p class="subtitle">{webacl_name} — {date_range}</p>

<h2>Executive Summary</h2>
<div class="summary">{executive_summary}</div>

<h2>Weekly Highlights</h2>
<div class="grid">
  <div class="roi-box"><div class="label">Threats Mitigated</div><div class="value">{threats_mitigated}</div><div class="change">Blocked + Challenged</div></div>
  <div class="card"><div class="label">Challenges Issued</div><div class="value">{challenge_total}</div><div class="change">{challenge_effectiveness}</div></div>
  <div class="card"><div class="label">Bot Requests Identified</div><div class="value">{bot_requests}</div><div class="change">{bot_pct}% of total traffic</div></div>
  <div class="card"><div class="label">Attack Requests Blocked</div><div class="value">{blocked_requests}</div><div class="change">{block_rate}% block rate</div></div>
</div>

{antiddos_section}

{bot_section}

<h2>Traffic Overview</h2>
<div class="grid">
  <div class="card"><div class="label">Total Requests</div><div class="value">{total_requests}</div><div class="change {total_change_class}">{total_change}</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value">{allowed_requests}</div></div>
  <div class="card"><div class="label">Blocked</div><div class="value">{blocked_requests}</div><div class="change {blocked_change_class}">{blocked_change}</div></div>
  <div class="card"><div class="label">Challenged</div><div class="value">{challenge_count}</div></div>
  <div class="card"><div class="label">CAPTCHA</div><div class="value">{captcha_count}</div></div>
</div>

<div class="chart-container"><canvas id="dailyChart"></canvas></div>
<p style="color:var(--muted);font-size:.8rem;text-align:center;">10-minute sum · Scroll to zoom, drag to pan</p>

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
const thisWeek = {daily_data_json};
const lastWeek = {daily_data_last_week_json};
const chartTextColor = getComputedStyle(document.documentElement).getPropertyValue('--chart-text').trim() || '#e6edf3';

const trafficChart = new Chart(document.getElementById('dailyChart'), {{
  type: 'line',
  data: {{
    labels: thisWeek.map(d => d.date),
    datasets: [
      {{ label: 'Allowed', data: thisWeek.map(d => d.allowed || 0), borderColor: '#3fb950', borderWidth: 1.5, backgroundColor: 'rgba(63,185,80,0.1)', fill: true, tension: 0.3, pointRadius: 0 }},
      {{ label: 'Blocked', data: thisWeek.map(d => d.blocked || 0), borderColor: '#f85149', borderWidth: 1.5, backgroundColor: 'rgba(248,81,73,0.1)', fill: true, tension: 0.3, pointRadius: 0 }},
      {{ label: 'Challenged', data: thisWeek.map(d => d.challenged || 0), borderColor: '#d29922', borderWidth: 1.5, backgroundColor: 'rgba(210,153,34,0.1)', fill: true, tension: 0.3, pointRadius: 0 }},
      {{ label: 'CAPTCHA', data: thisWeek.map(d => d.captcha || 0), borderColor: '#a371f7', borderWidth: 1.5, backgroundColor: 'rgba(163,113,247,0.1)', fill: true, tension: 0.3, pointRadius: 0 }},
      {{ label: 'Allowed (last week)', data: lastWeek.map(d => d.allowed || 0), borderColor: '#3fb950', borderWidth: 1.5, borderDash: [5,5], pointRadius: 0, tension: 0.3 }},
      {{ label: 'Blocked (last week)', data: lastWeek.map(d => d.blocked || 0), borderColor: '#f85149', borderWidth: 1.5, borderDash: [5,5], pointRadius: 0, tension: 0.3 }},
      {{ label: 'Challenged (last week)', data: lastWeek.map(d => d.challenged || 0), borderColor: '#d29922', borderWidth: 1.5, borderDash: [5,5], pointRadius: 0, tension: 0.3 }},
      {{ label: 'CAPTCHA (last week)', data: lastWeek.map(d => d.captcha || 0), borderColor: '#a371f7', borderWidth: 1.5, borderDash: [5,5], pointRadius: 0, tension: 0.3 }},
    ]
  }},
  options: {{
    responsive: true,
    interaction: {{ mode: 'index', intersect: false }},
    plugins: {{
      title: {{ display: true, text: 'Traffic Overview (solid = this week, dashed = last week)', color: chartTextColor }},
      legend: {{ labels: {{ color: chartTextColor }} }},
      tooltip: {{ mode: 'index', intersect: false, callbacks: {{ label: function(ctx) {{ return ctx.dataset.label + ': ' + ctx.raw.toLocaleString(); }} }} }},
      zoom: {{ zoom: {{ wheel: {{ enabled: true }}, pinch: {{ enabled: true }}, mode: 'x' }}, pan: {{ enabled: true, mode: 'x' }} }}
    }},
    scales: {{
      x: {{ ticks: {{ color: chartTextColor, maxTicksLimit: 14 }} }},
      y: {{ type: 'logarithmic', ticks: {{ color: chartTextColor }}, title: {{ display: true, text: 'Requests (log scale)', color: chartTextColor }} }}
    }}
  }}
}});

function toggleTheme() {{
  const root = document.documentElement;
  root.classList.toggle('dark');
  root.classList.toggle('light');
  const c = getComputedStyle(root).getPropertyValue('--chart-text').trim() || '#1f2328';
  Chart.helpers.each(Chart.instances, function(chart) {{
    chart.options.plugins.title.color = c;
    chart.options.plugins.legend.labels.color = c;
    chart.options.scales.x.ticks.color = c;
    chart.options.scales.y.ticks.color = c;
    if (chart.options.scales.y.title) chart.options.scales.y.title.color = c;
    chart.update();
  }});
}}
document.documentElement.classList.add('{default_theme}');
</script>
</body>
</html>
"""


@tool
def generate_weekly_report(webacl_name: str, scope: str = "CLOUDFRONT", theme: str = "dark") -> str:
    """Generate a AWS WAF ROI report as HTML with charts showing protection value (ROI).

    Queries CloudWatch Metrics for the past 7 days and produces an HTML report
    focused on demonstrating AWS WAF value: threats mitigated, challenge effectiveness,
    bot detection rates, and week-over-week trends.

    Args:
        webacl_name: Name of the WebACL to report on.
        scope: AWS WAF scope — "CLOUDFRONT" or "REGIONAL".
        theme: Default theme — "dark" (for projection) or "light" (for PDF). User can toggle in browser.

    Returns:
        Path to the generated HTML file, or error message.
    """
    from tools.session_state import get_metrics_region, get_log_destination, get_capabilities
    region = "us-east-1" if scope == "CLOUDFRONT" else get_metrics_region()
    cw = get_client("cloudwatch", region_name=region)

    end = datetime.now(timezone.utc)
    start_this_week = end - timedelta(days=7)
    start_last_week = start_this_week - timedelta(days=7)

    this_week = _get_weekly_totals(cw, webacl_name, start_this_week, end)
    last_week = _get_weekly_totals(cw, webacl_name, start_last_week, start_this_week)
    daily = _get_daily_breakdown(cw, webacl_name, start_this_week, end)
    daily_last_week = _get_daily_breakdown(cw, webacl_name, start_last_week, start_this_week)

    # 5-min resolution traffic for chart (this week + last week)
    traffic_5min = _get_5min_traffic(cw, webacl_name, start_this_week, end)
    traffic_5min_last_week = _get_5min_traffic(cw, webacl_name, start_last_week, start_this_week)
    countries = _get_top_countries(cw, webacl_name, start_this_week, end)
    rules = _get_top_rules(cw, webacl_name, start_this_week, end)

    total_this = this_week["allowed"] + this_week["blocked"] + this_week["challenge"]
    total_last = last_week["allowed"] + last_week["blocked"] + last_week["challenge"]

    # Challenge total
    challenge_total = this_week["challenge"] + this_week["captcha"]

    # Challenge/CAPTCHA solved — use dedicated CloudWatch metrics
    challenge_solved = 0
    captcha_solved = 0
    for metric_id, metric_name in [("cs", "ChallengesSolved"), ("cas", "CaptchasSolved")]:
        try:
            resp = cw.get_metric_data(
                MetricDataQueries=[{
                    "Id": metric_id,
                    "MetricStat": {
                        "Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric_name,
                                   "Dimensions": [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]},
                        "Period": 604800, "Stat": "Sum",
                    },
                }],
                StartTime=start_this_week, EndTime=end,
            )
            for r in resp.get("MetricDataResults", []):
                val = int(sum(r.get("Values", [0])))
                if metric_id == "cs":
                    challenge_solved = val
                else:
                    captcha_solved = val
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
        if abs(pct) > 1000:
            return f"{previous:,} → {current:,}", "up" if pct > 0 else "down"
        arrow = "↑" if pct > 0 else "↓"
        cls = "up" if pct > 0 else "down"
        return f"{arrow} {abs(pct):.1f}% vs last week", cls

    total_change, total_change_class = fmt_change(total_this, total_last)
    blocked_change, blocked_change_class = fmt_change(this_week["blocked"], last_week["blocked"])
    block_rate = f"{(this_week['blocked'] / total_this * 100):.1f}" if total_this > 0 else "0"

    # Anti-DDoS AMR events — only if AMR is deployed
    antiddos_section = ""
    ddos_num_events = 0
    ddos_total = 0
    ddos_event_first = ""
    ddos_event_last = ""
    ddos_duration_min = 0
    caps = get_capabilities()
    log_dest = get_log_destination()
    # Auto-discover log destination if not already set
    if not log_dest:
        try:
            waf_client = get_client("wafv2", region_name=region)
            waf_scope = "CLOUDFRONT" if scope == "CLOUDFRONT" else "REGIONAL"
            acls = waf_client.list_web_acls(Scope=waf_scope)["WebACLs"]
            acl = next((a for a in acls if a["Name"] == webacl_name), None)
            if acl:
                log_resp = waf_client.get_logging_configuration(ResourceArn=acl["ARN"])
                dests = log_resp["LoggingConfiguration"]["LogDestinationConfigs"]
                if dests:
                    log_dest = dests[0]
        except Exception:
            pass
    log_group = log_dest.split(":log-group:")[-1].rstrip(":*") if log_dest and ":log-group:" in log_dest else None
    logs_client = get_client("logs", region_name=region) if log_group else None
    log_end = int(end.timestamp()) if log_group else 0
    log_start = int(start_this_week.timestamp()) if log_group else 0
    if caps.get("anti_ddos_amr") and log_group:
        try:

            # Event time range + total requests during event
            event_cnt = _poll_log_query(logs_client, log_group, log_start, log_end,
                "filter @message like 'anti-ddos:event-detected' | stats count(*) as cnt, min(@timestamp) as first, max(@timestamp) as last",
                return_full=True)

            if event_cnt and int(event_cnt.get("cnt", 0)) > 0:
                event_first = event_cnt.get("first", "N/A")
                event_last = event_cnt.get("last", "N/A")
                total_during_event = int(event_cnt["cnt"])

                # Count distinct events by looking for time gaps > 10 min between bins
                event_count_result = _poll_log_query(logs_client, log_group, log_start, log_end,
                    "filter @message like 'anti-ddos:event-detected' | stats count(*) as cnt by bin(5m) | sort @timestamp asc",
                    return_rows=True)
                num_events = 1 if event_count_result else 0
                prev_ts = None
                for row in event_count_result or []:
                    d = {f["field"]: f["value"] for f in row}
                    ts_str = d.get("bin(5m)", "")
                    if ts_str and prev_ts:
                        try:
                            cur = datetime.fromisoformat(ts_str.replace(" ", "T").rstrip("Z"))
                            prev = datetime.fromisoformat(prev_ts.replace(" ", "T").rstrip("Z"))
                            if (cur - prev).total_seconds() > 600:
                                num_events += 1
                        except (ValueError, TypeError):
                            pass
                    if ts_str:
                        prev_ts = ts_str

                # DDoS request breakdown by suspicion level
                ddos_result = _poll_log_query(logs_client, log_group, log_start, log_end,
                    "filter @message like 'anti-ddos:ddos-request' | stats count(*) as total, sum(strcontains(@message, 'high-suspicion')) as high, sum(strcontains(@message, 'medium-suspicion')) as medium, sum(strcontains(@message, 'low-suspicion')) as low",
                    return_full=True)
                ddos_total = int(float(ddos_result.get("total", 0))) if ddos_result else 0
                ddos_high = int(float(ddos_result.get("high", 0))) if ddos_result else 0
                ddos_medium = int(float(ddos_result.get("medium", 0))) if ddos_result else 0
                ddos_low = int(float(ddos_result.get("low", 0))) if ddos_result else 0

                # Build suspicion breakdown — only show distinct levels
                suspicion_cards = ""
                if ddos_high == ddos_medium == ddos_low and ddos_high > 0:
                    # All same = AMR classified all as high (high ⊃ medium ⊃ low)
                    suspicion_cards = f'<div class="card"><div class="label">Suspicion Level</div><div class="value">All High</div></div>'
                else:
                    if ddos_high > 0:
                        suspicion_cards += f'<div class="card"><div class="label">High Suspicion</div><div class="value">{ddos_high:,}</div></div>'
                    if ddos_medium > ddos_high:
                        suspicion_cards += f'<div class="card"><div class="label">Medium Suspicion</div><div class="value">{ddos_medium - ddos_high:,}</div></div>'
                    if ddos_low > ddos_medium:
                        suspicion_cards += f'<div class="card"><div class="label">Low Suspicion</div><div class="value">{ddos_low - ddos_medium:,}</div></div>'

                antiddos_section = (
                    f'<h2>Anti-DDoS Protection</h2>'
                    f'<div class="grid">'
                    f'<div class="roi-box"><div class="label">DDoS Events This Week</div><div class="value">{num_events}</div></div>'
                    f'<div class="card"><div class="label">DDoS Requests Identified</div><div class="value">{ddos_total:,}</div></div>'
                    f'{suspicion_cards}'
                    f'<div class="card"><div class="label">Total Requests During Events</div><div class="value">{total_during_event:,}</div></div>'
                    f'</div>'
                )

                # DDoS timeline chart (full week, 5-min sum)
                try:
                    import json as _json
                    ddos_chart_resp = cw.get_metric_data(
                        MetricDataQueries=[
                            {"Id": "total", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" Rule=\"ALL\" MetricName=(\"AllowedRequests\" OR \"BlockedRequests\" OR \"ChallengeRequests\")', 'Sum', 600),0))"},
                            {"Id": "evtdet", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:anti-ddos\" LabelName=\"event-detected\"', 'Sum', 600),0))"},
                            {"Id": "ddosreq", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:anti-ddos\" LabelName=\"ddos-request\"', 'Sum', 600),0))"},
                        ],
                        StartTime=start_this_week, EndTime=end, ScanBy="TimestampAscending",
                    )
                    ddos_chart_data = {"labels": [], "total": [], "event": [], "ddos": []}
                    for r in ddos_chart_resp.get("MetricDataResults", []):
                        if r["Id"] == "total":
                            ddos_chart_data["labels"] = [t.strftime("%m/%d %H:%M") for t in r.get("Timestamps", [])]
                            ddos_chart_data["total"] = [int(v) for v in r.get("Values", [])]
                        elif r["Id"] == "evtdet":
                            ddos_chart_data["event"] = [int(v) for v in r.get("Values", [])]
                        elif r["Id"] == "ddosreq":
                            ddos_chart_data["ddos"] = [int(v) for v in r.get("Values", [])]
                    if ddos_chart_data["labels"]:
                        antiddos_section += (
                            f'<div class="chart-container"><canvas id="ddosChart"></canvas></div>'
                            f'<p style="color:var(--muted);font-size:.8rem;text-align:center;">10-minute sum · Scroll to zoom, drag to pan</p>'
                            f'<script>'
                            f'(function(){{'
                            f'const ddosData = {_json.dumps(ddos_chart_data)};'
                            f'const c = getComputedStyle(document.documentElement).getPropertyValue("--chart-text").trim() || "#e6edf3";'
                            f'new Chart(document.getElementById("ddosChart"), {{'
                            f'  type: "line",'
                            f'  data: {{ labels: ddosData.labels, datasets: ['
                            f'    {{ label: "DDoS Requests", data: ddosData.ddos, borderColor: "#f85149", borderWidth: 1.5, fill: true, backgroundColor: "rgba(248,81,73,0.25)", tension: 0.2, pointRadius: 0 }},'
                            f'  ] }},'
                            f'  options: {{ responsive: true, interaction: {{ mode: "index", intersect: false }}, plugins: {{ title: {{ display: true, text: "Anti-DDoS: DDoS Requests Identified (full week)", color: c }}, legend: {{ labels: {{ color: c }} }}, tooltip: {{ mode: "index", intersect: false }}, zoom: {{ zoom: {{ wheel: {{ enabled: true }}, pinch: {{ enabled: true }}, mode: "x" }}, pan: {{ enabled: true, mode: "x" }} }} }}, scales: {{ x: {{ ticks: {{ color: c, maxTicksLimit: 14 }} }}, y: {{ beginAtZero: true, ticks: {{ color: c }} }} }} }}'
                            f'}});'
                            f'}})();'
                            f'</script>'
                        )
                except Exception:
                    pass
                ddos_num_events = num_events
                ddos_event_first = event_first
                ddos_event_last = event_last
                try:
                    t1 = datetime.fromisoformat(event_first.replace(" ", "T"))
                    t2 = datetime.fromisoformat(event_last.replace(" ", "T"))
                    ddos_duration_min = max(1, int((t2 - t1).total_seconds() / 60))
                except Exception:
                    ddos_duration_min = 0
        except Exception:
            pass

    # Bot Control section — query label metrics for bot classification
    bot_section = ""
    bot_data = {}
    bot_orgs = {}
    bot_categories = {}
    bot_names = {}
    bot_names_detail = {}
    overridden_bots = []
    common_total_blocked = 0
    common_total_allowed = 0
    targeted_total_blocked = 0
    targeted_total_counted = 0
    if caps.get("bot_control") != "none":
        try:
            # Query main bot-control namespace (has multiple LabelNames → SEARCH label = "{LabelName} {MetricName}")
            bot_label_resp = cw.get_metric_data(
                MetricDataQueries=[{"Id": "bc", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} LabelNamespace=\"awswaf:managed:aws:bot-control\" WebACL=\"{webacl_name}\"', 'Sum', 604800)"}],
                StartTime=start_this_week, EndTime=end,
            )

            # Parse: label format is "{LabelName} {MetricName}" e.g. "CategoryHttpLibrary AllowedRequests"
            bot_data = {}
            for r in bot_label_resp.get("MetricDataResults", []):
                total = int(sum(r.get("Values", [])))
                if total <= 0:
                    continue
                label = r.get("Label", "")
                parts = label.split()
                if len(parts) < 2:
                    continue
                name = parts[0]
                metric = parts[1]  # e.g. AllowedRequests, BlockedRequests, BlockRuleMatch, ChallengeRequests, CountRuleMatch
                # Normalize metric to action
                if "Block" in metric:
                    action = "Blocked"
                elif "Challenge" in metric:
                    action = "Challenge"
                elif "Count" in metric:
                    action = "Count"
                else:
                    action = "Allowed"
                if name not in bot_data:
                    bot_data[name] = {}
                bot_data[name][action] = bot_data[name].get(action, 0) + total

            # Discover bot organizations via list_metrics (SEARCH unreliable for single-LabelName namespaces)
            bot_orgs = {}
            org_metrics = cw.list_metrics(
                Namespace="AWS/WAFV2",
                Dimensions=[
                    {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot:organization"},
                    {"Name": "WebACL", "Value": webacl_name},
                ],
            ).get("Metrics", [])
            # Get unique org names
            org_names = set()
            for m in org_metrics:
                for d in m["Dimensions"]:
                    if d["Name"] == "LabelName":
                        org_names.add(d["Value"])
            # Query each org's total
            if org_names:
                org_queries = []
                for i, org_name in enumerate(list(org_names)[:10]):
                    org_queries.append({"Id": f"org{i}", "MetricStat": {
                        "Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": [
                            {"Name": "LabelName", "Value": org_name},
                            {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot:organization"},
                            {"Name": "WebACL", "Value": webacl_name},
                        ]}, "Period": 604800, "Stat": "Sum",
                    }})
                org_resp = cw.get_metric_data(MetricDataQueries=org_queries, StartTime=start_this_week, EndTime=end)
                for i, org_name in enumerate(list(org_names)[:10]):
                    for r in org_resp.get("MetricDataResults", []):
                        if r.get("Id") == f"org{i}":
                            total = int(sum(r.get("Values", [])))
                            if total > 0:
                                bot_orgs[org_name] = total

            # Human-readable names for bot rules
            # Detect overridden bot rules (set to Count instead of Block)
            overridden_bots = []
            for name, d in bot_data.items():
                if not (name.startswith("Category") or name.startswith("Signal")):
                    continue
                allowed = d.get("Allowed", 0) + d.get("Count", 0)
                blocked = d.get("Blocked", 0) + d.get("Challenge", 0)
                if allowed > 0 and blocked == 0:
                    overridden_bots.append(name)
                elif allowed > blocked * 5:
                    overridden_bots.append(name)

            # Classify by prefix: Category*/Signal* = Common, TGT_* = Targeted
            common_rows = ""
            common_total_blocked = 0
            common_total_allowed = 0
            targeted_rows = ""
            targeted_total_blocked = 0
            targeted_total_counted = 0

            for rule_name, d in sorted(bot_data.items(), key=lambda x: sum(x[1].values()), reverse=True):
                blocked = d.get("Blocked", 0) + d.get("Challenge", 0)
                counted = d.get("Count", 0)
                allowed = d.get("Allowed", 0)
                total_hits = blocked + counted + allowed
                if total_hits == 0:
                    continue
                display_name = _FRIENDLY_NAMES.get(rule_name, rule_name)

                if rule_name.startswith("TGT_"):
                    targeted_total_blocked += blocked
                    targeted_total_counted += counted
                    action_str = f"🚫 {blocked:,} blocked" if blocked > 0 else f"👁️ {counted:,} monitored"
                    targeted_rows += f"<tr><td>{display_name}</td><td>{total_hits:,}</td><td>{action_str}</td></tr>\n"
                elif rule_name.startswith("Category") or rule_name.startswith("Signal"):
                    common_total_blocked += blocked
                    common_total_allowed += allowed + counted
                    action_str = "🚫 Blocked" if blocked > 0 else "👁️ Monitored"
                    common_rows += f"<tr><td>{display_name}</td><td>{total_hits:,}</td><td>{action_str}</td></tr>\n"

            # Bot organizations detected
            org_rows = ""
            for org, count in sorted(bot_orgs.items(), key=lambda x: x[1], reverse=True)[:10]:
                org_rows += f"<tr><td>{org}</td><td>{count:,}</td></tr>\n"

            # Discover bot categories via list_metrics (bot:category namespace)
            bot_categories = {}
            cat_metrics = cw.list_metrics(
                Namespace="AWS/WAFV2",
                Dimensions=[
                    {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot:category"},
                    {"Name": "WebACL", "Value": webacl_name},
                ],
            ).get("Metrics", [])
            cat_names = set()
            for m in cat_metrics:
                for d in m["Dimensions"]:
                    if d["Name"] == "LabelName":
                        cat_names.add(d["Value"])
            if cat_names:
                cat_queries = []
                for i, cat_name in enumerate(list(cat_names)[:20]):
                    cat_queries.append({"Id": f"cat{i}", "MetricStat": {
                        "Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": [
                            {"Name": "LabelName", "Value": cat_name},
                            {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot:category"},
                            {"Name": "WebACL", "Value": webacl_name},
                        ]}, "Period": 604800, "Stat": "Sum",
                    }})
                cat_resp = cw.get_metric_data(MetricDataQueries=cat_queries, StartTime=start_this_week, EndTime=end)
                for i, cat_name in enumerate(list(cat_names)[:20]):
                    for r in cat_resp.get("MetricDataResults", []):
                        if r.get("Id") == f"cat{i}":
                            total = int(sum(r.get("Values", [])))
                            if total > 0:
                                bot_categories[cat_name] = total

            # Discover bot names via list_metrics (bot:name namespace)
            bot_names_detail = {}  # {name: {allowed: N, blocked: N, challenged: N}}
            name_metrics = cw.list_metrics(
                Namespace="AWS/WAFV2",
                Dimensions=[
                    {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot:name"},
                    {"Name": "WebACL", "Value": webacl_name},
                ],
            ).get("Metrics", [])
            # Group by bot name and metric
            name_metric_map = {}  # {(name, metric): True}
            for m in name_metrics:
                dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
                bn = dims.get("LabelName", "")
                if bn:
                    name_metric_map[(bn, m["MetricName"])] = True
            # Query all
            name_queries = []
            name_query_keys = []
            for (bn, metric), _ in list(name_metric_map.items())[:30]:
                qid = f"bn{len(name_queries)}"
                name_queries.append({"Id": qid, "MetricStat": {
                    "Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric, "Dimensions": [
                        {"Name": "LabelName", "Value": bn},
                        {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot:name"},
                        {"Name": "WebACL", "Value": webacl_name},
                    ]}, "Period": 604800, "Stat": "Sum",
                }})
                name_query_keys.append((qid, bn, metric))
            if name_queries:
                name_resp = cw.get_metric_data(MetricDataQueries=name_queries, StartTime=start_this_week, EndTime=end)
                for r in name_resp.get("MetricDataResults", []):
                    for qid, bn, metric in name_query_keys:
                        if r.get("Id") == qid:
                            total = int(sum(r.get("Values", [])))
                            if total > 0:
                                if bn not in bot_names_detail:
                                    bot_names_detail[bn] = {"allowed": 0, "blocked": 0, "challenged": 0}
                                if "Allowed" in metric:
                                    bot_names_detail[bn]["allowed"] += total
                                elif "Blocked" in metric:
                                    bot_names_detail[bn]["blocked"] += total
                                elif "Challenge" in metric:
                                    bot_names_detail[bn]["challenged"] += total
            # For backward compat (data_lines uses bot_names)
            bot_names = {bn: sum(d.values()) for bn, d in bot_names_detail.items()}

            if common_rows or targeted_rows:
                bot_section = '<h2>Bot Control</h2>'

                # Query verified/unverified totals from metrics
                verified_total = 0
                unverified_total = 0
                try:
                    vu_resp = cw.get_metric_data(
                        MetricDataQueries=[
                            {"Id": "vf", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": [
                                {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"},
                                {"Name": "LabelName", "Value": "verified"},
                                {"Name": "WebACL", "Value": webacl_name},
                            ]}, "Period": 604800, "Stat": "Sum"}},
                            {"Id": "uv", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": [
                                {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"},
                                {"Name": "LabelName", "Value": "unverified"},
                                {"Name": "WebACL", "Value": webacl_name},
                            ]}, "Period": 604800, "Stat": "Sum"}},
                        ],
                        StartTime=start_this_week, EndTime=end,
                    )
                    for r in vu_resp.get("MetricDataResults", []):
                        val = int(sum(r.get("Values", [])))
                        if r["Id"] == "vf":
                            verified_total = val
                        elif r["Id"] == "uv":
                            unverified_total = val
                except Exception:
                    pass

                # Query per-bot-name verification + category from logs
                bot_verification = {}  # {name: {"vs": ..., "category": ...}}
                if log_group:
                    try:
                        bot_ver_result = _poll_log_query(logs_client, log_group, log_start, log_end,
                            'filter @message like "bot-control:bot:name:" | parse @message /bot:name:(?<botName>[a-z0-9_]+)/ | parse @message /bot:(?<vs>verified|unverified)/ | parse @message /bot:category:(?<category>[a-z_]+)/ | stats count(*) as cnt by botName, vs, category | sort cnt desc',
                            return_rows=True)
                        for row in bot_ver_result or []:
                            d = {f["field"]: f["value"] for f in row}
                            bn = d.get("botName", "")
                            if bn:
                                bot_verification[bn] = {"vs": d.get("vs", ""), "category": d.get("category", "")}
                    except Exception:
                        pass

                # Summary cards
                bot_section += (
                    f'<div class="grid">'
                    f'<div class="card"><div class="label">Verified Bots (legitimate)</div><div class="value">{verified_total:,}</div></div>'
                    f'<div class="card"><div class="label">Unverified Bots</div><div class="value">{unverified_total:,}</div></div>'
                    f'<div class="card"><div class="label">Illegitimate Bots Blocked</div><div class="value">{common_total_blocked:,}</div></div>'
                    f'</div>'
                )

                # Build unified bot table: Name / Category / Verification / Requests / Action
                _CAT_FRIENDLY = {"http_library": "HTTP Library", "monitoring": "Monitoring",
                                 "search_engine": "Search Engine", "seo": "SEO", "advertising": "Advertising",
                                 "social_media": "Social Media", "ai": "AI Crawler", "content_fetcher": "Content Fetcher",
                                 "scraping_framework": "Scraper", "security": "Security Scanner",
                                 "archiver": "Archiver", "link_checker": "Link Checker", "miscellaneous": "Misc"}
                name_rows = ""
                if bot_names_detail:
                    for bn, d in sorted(bot_names_detail.items(), key=lambda x: sum(x[1].values()), reverse=True)[:15]:
                        total = d["allowed"] + d["blocked"] + d["challenged"]
                        display = bn.replace("_", " ").title()
                        info = bot_verification.get(bn, {})
                        vs = info.get("vs", "")
                        cat = info.get("category", "")
                        vs_badge = "✅ Verified" if vs == "verified" else ("⚠️ Unverified" if vs == "unverified" else "—")
                        cat_display = _CAT_FRIENDLY.get(cat, cat.replace("_", " ").title()) if cat else "—"
                        if d["blocked"] > 0 and d["allowed"] == 0:
                            action = "🚫 Blocked"
                        elif d["blocked"] > 0 and d["allowed"] > 0:
                            action = f"🚫 {d['blocked']:,} blocked, ✅ {d['allowed']:,} allowed"
                        elif d["challenged"] > 0:
                            action = "⚡ Challenged"
                        else:
                            action = "✅ Allowed"
                        name_rows += f"<tr><td>{display}</td><td>{cat_display}</td><td>{vs_badge}</td><td>{total:,}</td><td>{action}</td></tr>\n"

                # Add NonBrowserUA without bot:name (the "neither" case — fake bot UAs)
                if log_group:
                    try:
                        nb_result = _poll_log_query(logs_client, log_group, log_start, log_end,
                            'filter @message like "SignalNonBrowserUserAgent" | parse @message /bot:name:(?<bn>[a-z0-9_]+)/ | stats count(*) as total, sum(strlen(bn) > 0) as named',
                            return_full=True)
                        nb_total_log = int(float(nb_result.get("total", 0))) if nb_result else 0
                        nb_named = int(float(nb_result.get("named", 0))) if nb_result else 0
                        nonbrowser_unnamed = nb_total_log - nb_named
                    except Exception:
                        nonbrowser_unnamed = 0
                else:
                    nonbrowser_unnamed = 0
                if nonbrowser_unnamed > 0:
                    name_rows += f'<tr><td><em>Unknown Non-Browser UA</em></td><td>Non-Browser</td><td>— (neither)</td><td>{nonbrowser_unnamed:,}</td><td>👁️ Monitored</td></tr>\n'

                if name_rows:
                    bot_section += (
                        f'<h3>Individual Bots</h3>'
                        f'<table><tr><th>Bot Name</th><th>Category</th><th>Verification</th><th>Requests</th><th>Action</th></tr>{name_rows}</table>'
                    )

                # Targeted detection rules
                if targeted_rows:
                    bot_section += (
                        f'<h3>Targeted Detection (behavioral analysis)</h3>'
                        f'<div class="grid">'
                        f'<div class="card"><div class="label">Advanced Bots Blocked/Challenged</div><div class="value">{targeted_total_blocked:,}</div></div>'
                        f'<div class="card"><div class="label">Suspicious (Counted)</div><div class="value">{targeted_total_counted:,}</div></div>'
                        f'</div>'
                        f'<table><tr><th>Detection Rule</th><th>Requests</th><th>Action</th></tr>{targeted_rows}</table>'
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
        name = _FRIENDLY_NAMES.get(r["rule"], r["rule"])
        rule_rows += f"<tr><td>{name}</td><td>{r['count']:,}</td><td>👁️ Monitored</td></tr>\n"

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
        challenge_effectiveness=f"Solved: {challenge_solved:,}" if challenge_solved > 0 else "All blocked (automation)",
        antiddos_section=antiddos_section,
        bot_section=bot_section,
        bot_requests=f"{bot_requests:,}",
        bot_pct=bot_pct,
        country_rows=country_rows,
        rule_rows=rule_rows,
        daily_data_json=json.dumps(traffic_5min),
        daily_data_last_week_json=json.dumps(traffic_5min_last_week),
    )

    output_path = f"waf-roi-report-{webacl_name}-{end.strftime('%Y%m%d')}.html"
    with open(output_path, "w") as f:
        f.write(html)

    # Build rich data summary for Agent to write executive summary
    data_lines = [
        f"Report generated: {output_path}\n",
        "## Data for Executive Summary\n",
        f"- Total requests: {total_this:,} (allowed {this_week['allowed']:,}, blocked {this_week['blocked']:,}, challenged {challenge_total:,})",
        f"- Threats mitigated: {threats_mitigated:,} ({(threats_mitigated/total_this*100):.1f}% of traffic)" if total_this > 0 else f"- Threats mitigated: {threats_mitigated:,}",
        f"- Week-over-week change: {total_change}",
        f"- Top attack sources (countries): {', '.join(c['country'] + '=' + str(c['count']) for c in countries[:5])}",
        f"- Top blocking rules: {', '.join(r['rule'] + '=' + str(r['count']) for r in [r for r in rules if r['action']=='BLOCK'][:5])}",
        f"- Challenge issued: {challenge_total:,}, Challenge solved: {challenge_solved:,}, CAPTCHA solved: {captcha_solved:,}",
        f"- Daily trend: {'spike on ' + max(daily, key=lambda d: d['blocked']+d['challenged'])['date'] if daily else 'steady'}",
    ]

    # Anti-DDoS data
    if antiddos_section:
        data_lines.append(f"- Anti-DDoS: {ddos_num_events} event(s) detected, {ddos_total:,} DDoS requests identified, duration: ~{ddos_duration_min} minutes")

    # Bot Control data
    if bot_section:
        common_labels = [name for name in bot_data if name.startswith("Category") or name.startswith("Signal")]
        targeted_labels = [name for name in bot_data if name.startswith("TGT_")]
        data_lines.append(f"- Bot Control Common: {len(common_labels)} categories detected, {common_total_blocked:,} blocked, {common_total_allowed:,} monitored/allowed")
        data_lines.append(f"- Bot verification: {verified_total:,} verified (legitimate, allowed by design), {unverified_total:,} unverified")
        data_lines.append(f"- Bot Control Targeted: {len(targeted_labels)} rules triggered, {targeted_total_blocked:,} blocked/challenged, {targeted_total_counted:,} counted")
        if bot_orgs:
            data_lines.append(f"- Bot organizations: {', '.join(f'{k}={v:,}' for k,v in sorted(bot_orgs.items(), key=lambda x: x[1], reverse=True)[:5])}")
        if bot_categories:
            data_lines.append(f"- Bot categories visiting site: {', '.join(f'{k}={v:,}' for k,v in sorted(bot_categories.items(), key=lambda x: x[1], reverse=True))}")
        if bot_names:
            data_lines.append(f"- Individual bots identified: {', '.join(f'{k}={v:,}' for k,v in sorted(bot_names.items(), key=lambda x: x[1], reverse=True)[:10])}")
        if overridden_bots:
            friendly = [_FRIENDLY_NAMES.get(b, b) for b in overridden_bots]
            data_lines.append(f"- ⚠️ IMPORTANT: These bot rules are set to Count/Allow (NOT blocking): {', '.join(friendly)}. Bots matching these rules (curl, python-requests, okhttp, etc.) are being ALLOWED through. This is either intentional or a misconfiguration — do NOT describe this as 'correctly handled'.")

    data_lines.append(f"- Bot/suspicious requests: {bot_requests:,} ({bot_pct}% of traffic)")
    data_lines.append("")
    data_lines.append("## Instructions")
    data_lines.append("Write an executive summary for management (4-5 paragraphs). Use **bold** for key numbers. Do NOT use bullet lists (- or *) — use flowing prose paragraphs only.")
    data_lines.append("Required paragraph structure:")
    data_lines.append("1. Overview: What happened this week? (traffic volume, trends, anomalies)")
    data_lines.append("2. DDoS/Attacks: What attacks were detected and blocked? (specific numbers)")
    data_lines.append("3. Bot Traffic (MUST be a separate paragraph): What bots are visiting? Include both illegitimate bots blocked AND legitimate bots allowed (search engines, monitoring, AI crawlers). Management cares about WHO is crawling their site.")
    data_lines.append("4. Risks/Recommendations: Anything to worry about?")
    data_lines.append("5. ROI conclusion: Is the money well spent?")
    data_lines.append("")
    data_lines.append("## Domain knowledge (use when writing about DDoS/Bot)")
    data_lines.append("- Anti-DDoS AMR DDoSRequests rule blocks ANY high-frequency IP (including JS-capable browser automation like Playwright) as long as per-IP volume deviates significantly from baseline.")
    data_lines.append("- Only highly distributed attacks (tens of thousands of IPs, each sending low volume indistinguishable from baseline) can evade Anti-DDoS AMR. ONLY in that scenario is Targeted Bot Control needed as a complement.")
    data_lines.append("- Do NOT suggest 'attackers upgrading to browser automation' as a risk if Anti-DDoS AMR is deployed — AMR handles high-volume automation regardless of JS capability.")
    data_lines.append("")
    data_lines.append(f"Then call set_report_summary(path='{output_path}', summary='your summary here')")

    return "\n".join(data_lines)



def _poll_log_query(logs_client, log_group, start, end, query, return_full=False, return_rows=False, max_wait=120):
    """Run a CWL query with polling. Returns count (int), full row (dict), or all rows (list)."""
    import time
    resp = logs_client.start_query(logGroupName=log_group, startTime=start, endTime=end, queryString=query, limit=1000)
    query_id = resp["queryId"]
    elapsed = 0
    while elapsed < max_wait:
        time.sleep(2)
        elapsed += 2
        result = logs_client.get_query_results(queryId=query_id)
        if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
    results = result.get("results", [])
    if not results:
        if return_full:
            return {}
        if return_rows:
            return []
        return 0
    if return_rows:
        return results
    row = {f["field"]: f["value"] for f in results[0]}
    if return_full:
        return row
    return int(float(row.get("cnt", 0)))

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


def _get_5min_traffic(cw, webacl_name: str, start, end) -> list:
    """Get 5-min resolution traffic data using SEARCH (same approach as AWS WAF native dashboard)."""
    try:
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "allowed", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" Rule=\"ALL\" MetricName=\"AllowedRequests\"', 'Sum', 600),0))"},
                {"Id": "blocked", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" Rule=\"ALL\" MetricName=\"BlockedRequests\"', 'Sum', 600),0))"},
                {"Id": "challenged", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" Rule=\"ALL\" MetricName=\"ChallengeRequests\"', 'Sum', 600),0))"},
                {"Id": "captcha", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" Rule=\"ALL\" MetricName=\"CaptchaRequests\"', 'Sum', 600),0))"},
            ],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        data = {}
        for r in resp.get("MetricDataResults", []):
            for ts, val in zip(r.get("Timestamps", []), r.get("Values", [])):
                key = ts.strftime("%m/%d %H:%M")
                if key not in data:
                    data[key] = {"date": key, "allowed": 0, "blocked": 0, "challenged": 0, "captcha": 0}
                data[key][r["Id"]] = int(val)
        return [data[k] for k in sorted(data.keys())]
    except Exception:
        return []


def _get_daily_breakdown(cw, webacl_name: str, start, end) -> list:
    """Get daily allowed/blocked/challenged/captcha counts."""
    queries = []
    for i, metric in enumerate(["AllowedRequests", "BlockedRequests", "ChallengeRequests", "CaptchaRequests"]):
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
                data[day] = {"date": day, "allowed": 0, "blocked": 0, "challenged": 0, "captcha": 0}
            if r["Id"] == "d0":
                data[day]["allowed"] = int(val)
            elif r["Id"] == "d1":
                data[day]["blocked"] = int(val)
            elif r["Id"] == "d2":
                data[day]["challenged"] = int(val)
            elif r["Id"] == "d3":
                data[day]["captcha"] = int(val)

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
    that answers: What happened this week? What did AWS WAF protect? Is the investment worth it?

    Args:
        path: Path to the HTML report file (returned by generate_weekly_report).
        summary: Executive summary in Markdown format. Use **bold** for emphasis, paragraphs separated by blank lines.

    Returns:
        Confirmation message.
    """
    try:
        import markdown
        with open(path, "r") as f:
            html = f.read()
        # Convert Markdown to HTML
        summary_html = markdown.markdown(summary, extensions=["smarty"])
        html = html.replace("{{EXECUTIVE_SUMMARY}}", summary_html)
        with open(path, "w") as f:
            f.write(html)
        # Store in module-level variable for /report endpoint
        global _latest_report_html
        _latest_report_html = html
        return "Report finalized successfully. User can download it via the report button."
    except FileNotFoundError:
        return f"Error: Report file not found at {path}"
