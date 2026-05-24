# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Weekly Summary generation tool."""

import json
import re
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client

# Module-level storage for the latest report HTML (served via GET /report)
_latest_report_html: str | None = None

# i18n strings
_I18N = {
    "en": {
        "title": "Executive Summary",
        "exec_summary": "Executive Summary",
        "highlights": "Weekly Highlights",
        "total_requests": "Total Requests",
        "threats_mitigated": "Threats Mitigated",
        "ddos_protection": "DDoS Protection",
        "common_bot": "Declared Bot Requests",
        "of_traffic": "of traffic",
        "of_total_traffic": "of total traffic",
        "top_attack": "Top Attack Sources",
        "attack_chart_note": "15-minute sum · Scroll to zoom, drag to pan · Excludes Anti-DDoS challenges (shown in DDoS chart below) · Count-mode rules not included · {tz}",
        "country_note": "Blocked requests by country · Does not include Anti-DDoS challenged requests",
        "attack_chart_title": "Threats Mitigated by Attack Type",
        "antiddos": "Anti-DDoS Protection",
        "antiddos_chart_note": "15-minute sum · Scroll to zoom, drag to pan · DDoS requests identified by Anti-DDoS AMR · {tz}",
        "antiddos_no_data": "No Anti-DDoS AMR metrics available.",
        "antiddos_not_deployed": "Anti-DDoS AMR not deployed.",
        "antiddos_title": "Anti-DDoS: Requests Identified",
        "bot_control": "Bot Control",
        "good_bots": "✅ Verified (Declared)",
        "unverified_bots": "⚠️ Unverified (Declared)",
        "counted": "Counted",
        "mitigated": "Mitigated",
        "targeted": "🎯 Advanced Bot Detection",
        "targeted_mitigated": "🚫 Mitigated",
        "targeted_counted": "👁️ Counted",
        "requests": "requests",
        "bot_disclaimer": "Note: Per-bot distribution charts are based on sampled data. Relative proportions are indicative; absolute numbers may differ from actual counts. Summary totals (card numbers) are exact.",
        "no_events": "🟢 No events",
        "events": "event(s)",
        "blocked": "blocked",
        "delay_note": "CloudWatch metrics have ~5 min delay. Data may change after report generation.",
        "no_data_search": "⚠️ No data — this WebACL had no matching traffic in the last 14 days. CloudWatch metric index expired. Generate traffic and re-run.",
        "generated": "Generated",
        "ddos_events_label": "DDoS Events This Week",
        "ddos_requests_label": "DDoS Requests Identified",
        "ddos_suspicion_label": "Suspicion Level",
        "ddos_total_during_label": "Total Requests During Events",
    },
    "zh": {
        "title": "管理层周报",
        "exec_summary": "摘要",
        "highlights": "本周概览",
        "total_requests": "总请求量",
        "threats_mitigated": "威胁拦截",
        "ddos_protection": "DDoS 防护",
        "common_bot": "自声明机器人请求",
        "of_traffic": "占总流量",
        "of_total_traffic": "占总流量",
        "top_attack": "攻击来源",
        "attack_chart_note": "15 分钟总计 · 滚轮缩放，拖拽平移 · 不含 Anti-DDoS 质询（见下方 DDoS 图表）· 不含 Count 模式规则 · {tz}",
        "country_note": "按国家统计的拦截请求 · 不含 Anti-DDoS 质询请求",
        "attack_chart_title": "按攻击类型拦截分布",
        "antiddos": "Anti-DDoS 防护",
        "antiddos_chart_note": "15 分钟总计 · 滚轮缩放，拖拽平移 · Anti-DDoS AMR 识别的 DDoS 请求 · {tz}",
        "antiddos_no_data": "无 Anti-DDoS AMR 指标数据。",
        "antiddos_not_deployed": "未部署 Anti-DDoS AMR。",
        "antiddos_title": "Anti-DDoS：识别的 DDoS 请求",
        "bot_control": "Bot Control",
        "good_bots": "✅ 已验证（自声明）",
        "unverified_bots": "⚠️ 未验证（自声明）",
        "counted": "监控中",
        "mitigated": "已拦截",
        "targeted": "🎯 高级机器人检测",
        "targeted_mitigated": "🚫 已拦截",
        "targeted_counted": "👁️ 监控中",
        "requests": "次请求",
        "bot_disclaimer": "注：机器人分布图表基于采样数据，比例关系仅供参考，绝对数字可能与实际有偏差。卡片上的汇总数字为精确值。",
        "no_events": "🟢 本周无事件",
        "events": "次事件",
        "blocked": "次拦截",
        "delay_note": "CloudWatch 指标延迟约 5 分钟，数据可能在报告生成后有变化。",
        "no_data_search": "⚠️ 无数据 — 该 WebACL 最近 14 天无此类流量，CloudWatch 指标索引已过期。请产生流量后重新生成报告。",
        "generated": "生成时间",
        "ddos_events_label": "本周 DDoS 事件",
        "ddos_requests_label": "识别的 DDoS 请求",
        "ddos_suspicion_label": "可疑等级",
        "ddos_total_during_label": "事件期间总请求",
    },
}


def _dims(webacl: str, scope: str, region: str, rule: str = "ALL") -> list[dict]:
    """Build CloudWatch metric dimensions. Omit Region for CLOUDFRONT scope."""
    d = [{"Name": "WebACL", "Value": webacl}, {"Name": "Rule", "Value": rule}]
    if scope != "CLOUDFRONT":
        d.append({"Name": "Region", "Value": region})
    return d


def _build_country_map_svg(countries: list) -> str:
    """Build inline SVG world map with countries colored by blocked request count."""
    import os
    map_path = os.path.join(os.path.dirname(__file__), "world_map_paths.json")
    try:
        with open(map_path) as f:
            map_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ""
    
    viewbox = map_data["viewBox"]
    paths = map_data["paths"]
    
    # Color scale: top country = darkest red, others proportional
    max_count = countries[0]["count"] if countries else 1
    
    colored = {c["country"].upper() for c in countries[:10] if c["country"].upper() in paths}
    
    neutral_paths = []
    colored_paths = []
    for cc, d in paths.items():
        if cc in colored:
            continue
        neutral_paths.append(f'<path d="{d}" fill="var(--border)" stroke="var(--card)" stroke-width="0.3" data-tip="{cc}"/>')
    
    for c in countries[:10]:
        cc = c["country"].upper()
        if cc in paths:
            intensity = c["count"] / max_count
            alpha = 0.3 + 0.7 * intensity
            colored_paths.append(f'<path d="{paths[cc]}" fill="rgba(248,81,73,{alpha:.2f})" stroke="var(--card)" stroke-width="0.3" data-tip="{cc}: {c["count"]:,} blocked"/>')
    
    all_paths = neutral_paths + colored_paths
    
    svg = f'<svg viewBox="{viewbox}" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto">{"".join(all_paths)}</svg>'
    return (
        f'<div class="map-wrap">{svg}<div class="map-tooltip" id="mapTip"></div></div>'
        f'<script>document.querySelectorAll("svg path[data-tip]").forEach(p=>{{p.onmouseenter=e=>{{const t=document.getElementById("mapTip");t.textContent=p.dataset.tip;t.style.opacity=1}};p.onmouseleave=()=>{{document.getElementById("mapTip").style.opacity=0}}}})</script>'
    )

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
<html lang="en" class="{default_theme}">
<head>
<meta charset="UTF-8">
<title>{L_title} — {webacl_name}</title>
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
.subtitle {{ color: var(--muted); margin-bottom: .5rem; }}
.theme-toggle {{ position: fixed; top: 1rem; right: 1rem; background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: .4rem .8rem; cursor: pointer; color: var(--fg); font-size: .85rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }}
.card .label {{ color: var(--muted); font-size: 1rem; margin-bottom: .3rem; }}
.card .value {{ font-size: 1.8rem; font-weight: 700; }}
.card .change {{ font-size: 1rem; margin-top: .3rem; }}
.up {{ color: var(--red); }}
.down {{ color: var(--green); }}
.neutral {{ color: var(--muted); }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card); border-radius: 6px; overflow: hidden; }}
th {{ background: var(--border); text-align: left; padding: .6rem .8rem; font-size: .85rem; }}
td {{ padding: .5rem .8rem; border-top: 1px solid var(--border); }}
.chart-container {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
canvas {{ max-height: 300px; }}
.highlight {{ background: var(--accent); color: #fff; padding: .1rem .4rem; border-radius: 3px; font-weight: 600; }}
svg path[data-tip]:hover {{ opacity: 0.8; cursor: pointer; }}
.map-wrap {{ position: relative; }}
.map-tooltip {{ position: absolute; top: 8px; right: 8px; background: var(--card); border: 1px solid var(--border); border-radius: 4px; padding: .3rem .6rem; font-size: 1rem; color: var(--fg); pointer-events: none; opacity: 0; transition: opacity .15s; }}
.map-wrap:has(path:hover) .map-tooltip {{ opacity: 1; }}
.summary p {{ margin-bottom: 1rem; line-height: 1.8; }}
.summary strong {{ color: var(--accent); }}
.roi-box {{ background: var(--card); border: 2px solid var(--green); border-radius: 8px; padding: 1.2rem; }}
.roi-box .value {{ font-size: 1.8rem; font-weight: 700; color: var(--green); }}
@media print {{ .theme-toggle {{ display: none; }} }}
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()">🌓 Toggle Theme</button>
<h1>{L_title}</h1>
<p class="subtitle">{webacl_name} ({scope}) — {date_range}</p>
<p style="color:var(--muted)">{L_generated}: {gen_time} {tz_label} · {L_delay_note}</p>

<h2>{L_exec_summary}</h2>
<div class="summary"><p>{executive_summary}</p></div>

<h2>{L_highlights}</h2>
<div class="grid">
  <div class="roi-box"><div class="label">{L_total_requests}</div><div class="value">{total_requests}</div><div class="change {total_change_class}">{total_change}</div></div>
  <div class="roi-box"><div class="label">{L_threats_mitigated}</div><div class="value">{threats_mitigated}</div><div class="change">{mitigated_pct}% {L_of_traffic}</div></div>
  <div class="card"><div class="label">{L_ddos_protection}</div><div class="value">{ddos_status}</div></div>
  <div class="card"><div class="label">{L_common_bot}</div><div class="value">{bot_requests}</div><div class="change">{bot_pct}% {L_of_total_traffic}</div></div>
</div>

<div class="chart-container"><canvas id="attackChart"></canvas></div>
<p style="color:var(--muted);font-size:1rem;text-align:center;">{L_attack_chart_note}</p>

<h2>{L_top_attack}</h2>
<div class="chart-container">{country_map_svg}</div>
<p style="color:var(--muted);font-size:1rem;text-align:center;">{L_country_note}</p>

{antiddos_section}
{antiddos_chart_section}

{bot_section}

<script>
const attackData = {attack_data_json};
const chartTextColor = getComputedStyle(document.documentElement).getPropertyValue('--chart-text').trim() || '#e6edf3';

// Attack type color palette
const attackColors = {{
  'Volumetric': {{ border: '#f85149', bg: 'rgba(248,81,73,0.6)' }},
  'BadBots': {{ border: '#d29922', bg: 'rgba(210,153,34,0.6)' }},
  'XSS': {{ border: '#e3b341', bg: 'rgba(227,179,65,0.6)' }},
  'GenericLFI': {{ border: '#a371f7', bg: 'rgba(163,113,247,0.6)' }},
  'KnownBadInputs': {{ border: '#58a6ff', bg: 'rgba(88,166,255,0.6)' }},
  'Other': {{ border: '#8b949e', bg: 'rgba(139,148,158,0.4)' }},
}};
const defaultColor = {{ border: '#79c0ff', bg: 'rgba(121,192,255,0.5)' }};

// Chart 1: Attack Types stacked area
if (attackData.labels && attackData.labels.length > 0) {{
  const datasets = Object.entries(attackData.series).map(([name, values]) => {{
    const c = attackColors[name] || defaultColor;
    return {{ label: name, data: values, borderColor: c.border, backgroundColor: c.bg, borderWidth: 1, fill: true, tension: 0.2, pointRadius: 0 }};
  }});
  new Chart(document.getElementById('attackChart'), {{
    type: 'line',
    data: {{ labels: attackData.labels, datasets: datasets }},
    options: {{
      responsive: true,
      interaction: {{ mode: 'index', intersect: false }},
      plugins: {{
        title: {{ display: true, text: '{L_attack_chart_title} ({webacl_name})', color: chartTextColor }},
        legend: {{ labels: {{ color: chartTextColor }} }},
        tooltip: {{ mode: 'index', intersect: false, callbacks: {{ label: function(ctx) {{ return ctx.dataset.label + ': ' + ctx.raw.toLocaleString(); }} }} }},
        zoom: {{ zoom: {{ wheel: {{ enabled: true }}, pinch: {{ enabled: true }}, mode: 'x' }}, pan: {{ enabled: true, mode: 'x' }} }}
      }},
      scales: {{
        x: {{ ticks: {{ color: chartTextColor, maxTicksLimit: 14 }} }},
        y: {{ stacked: true, beginAtZero: true, ticks: {{ color: chartTextColor }}, title: {{ display: true, text: 'Requests', color: chartTextColor }} }}
      }}
    }}
  }});
}} else {{
  document.getElementById('attackChart').parentElement.innerHTML = '<p class="muted">{L_no_data_search}</p>';
}}

function toggleTheme() {{
  const root = document.documentElement;
  root.classList.toggle('dark');
  root.classList.toggle('light');
  const c = getComputedStyle(root).getPropertyValue('--chart-text').trim() || '#1f2328';
  Chart.helpers.each(Chart.instances, function(chart) {{
    if (chart.options.plugins.title) chart.options.plugins.title.color = c;
    if (chart.options.plugins.legend && chart.options.plugins.legend.labels) chart.options.plugins.legend.labels.color = c;
    if (chart.options.scales && chart.options.scales.x) chart.options.scales.x.ticks.color = c;
    if (chart.options.scales && chart.options.scales.y) {{
      chart.options.scales.y.ticks.color = c;
      if (chart.options.scales.y.title) chart.options.scales.y.title.color = c;
    }}
    chart.update();
  }});
}}

</script>
</body>
</html>
"""


@tool
def generate_weekly_report(webacl_name: str, start_time: str, days: int = 7, scope: str = "CLOUDFRONT", theme: str = "dark", lang: str = "zh") -> str:
    """Generate an AWS WAF Weekly Summary as HTML with charts showing security posture.

    IMPORTANT: You MUST provide start_time. Ask the user for the reporting period.
    Max window is 7 days. WoW comparison uses the same duration from the previous period.

    Args:
        webacl_name: Name of the WebACL to report on.
        start_time: Start date for the report (e.g., "2026-05-08"). REQUIRED — ask user if not provided.
        days: Duration in days from start_time (default 7, max 7).
        scope: AWS WAF scope — "CLOUDFRONT" or "REGIONAL".
        theme: Default theme — "dark" (for projection) or "light" (for PDF).
        lang: Language for report labels — "zh" (Chinese) or "en" (English).

    Returns:
        Path to the generated HTML file, or error message.
    """
    if not start_time:
        return "Error: start_time is required. Ask the user which period to report on.\nExample: generate_weekly_report(webacl_name=\"my-acl\", start_time=\"2026-05-08\", days=7)"
    days = min(days, 7)

    # Parse start_time (use session timezone)
    from tools.session_state import get_metrics_region, get_log_destination, get_capabilities, get_user_timezone
    _tz_off = get_user_timezone()
    _user_tz = timezone(timedelta(hours=_tz_off)) if _tz_off is not None else timezone.utc
    try:
        if "T" in start_time:
            dt = datetime.fromisoformat(start_time)
            _st = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=_user_tz).astimezone(timezone.utc)
        else:
            _st = datetime.fromisoformat(start_time + "T00:00:00").replace(tzinfo=_user_tz).astimezone(timezone.utc)
    except ValueError:
        return f"Error: invalid start_time format '{start_time}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM."

    L = _I18N.get(lang, _I18N["en"])
    _tz_offset = timedelta(hours=_tz_off) if _tz_off is not None else timedelta(0)
    tz_label = f"UTC{_tz_off:+g}" if _tz_off is not None and _tz_off != 0 else "UTC"
    L = {k: v.format(tz=tz_label) if isinstance(v, str) and "{tz}" in v else v for k, v in L.items()}
    region = "us-east-1" if scope == "CLOUDFRONT" else get_metrics_region()
    cw = get_client("cloudwatch", region_name=region)
    # Region dimension: required for REGIONAL, omitted for CLOUDFRONT
    _region_dim = [{"Name": "Region", "Value": region}] if scope != "CLOUDFRONT" else []

    end = min(_st + timedelta(days=days), datetime.now(timezone.utc))
    actual_days = (end - _st).total_seconds() / 86400
    start_this_week = _st
    start_last_week = start_this_week - timedelta(days=days)

    this_week = _get_weekly_totals(cw, webacl_name, start_this_week, end, scope, region)
    last_week = _get_weekly_totals(cw, webacl_name, start_last_week, start_this_week, scope, region)
    daily = _get_daily_breakdown(cw, webacl_name, start_this_week, end, scope, region)

    countries = _get_top_countries(cw, webacl_name, start_this_week, end)
    # rules: used in data_lines for LLM summary context (not rendered in HTML)
    rules = _get_top_rules(cw, webacl_name, start_this_week, end, scope, region)

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
                                   "Dimensions": _dims(webacl_name, scope, region)},
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

    # Bot requests — will be computed in bot section below, default to 0
    bot_requests = 0

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
                    suspicion_cards = f'<div class="card"><div class="label">{L["ddos_suspicion_label"]}</div><div class="value">All High</div></div>'
                else:
                    if ddos_high > 0:
                        suspicion_cards += f'<div class="card"><div class="label">High</div><div class="value">{ddos_high:,}</div></div>'
                    if ddos_medium > ddos_high:
                        suspicion_cards += f'<div class="card"><div class="label">Medium</div><div class="value">{ddos_medium - ddos_high:,}</div></div>'
                    if ddos_low > ddos_medium:
                        suspicion_cards += f'<div class="card"><div class="label">Low</div><div class="value">{ddos_low - ddos_medium:,}</div></div>'

                antiddos_section = (
                    f'<h2>{L["antiddos"]}</h2>'
                    f'<div class="grid">'
                    f'<div class="roi-box"><div class="label">{L["ddos_events_label"]}</div><div class="value">{num_events}</div></div>'
                    f'<div class="card"><div class="label">{L["ddos_requests_label"]}</div><div class="value">{ddos_total:,}</div></div>'
                    f'{suspicion_cards}'
                    f'<div class="card"><div class="label">{L["ddos_total_during_label"]}</div><div class="value">{total_during_event:,}</div></div>'
                    f'</div>'
                )

                # DDoS chart is rendered by _get_ddos_chart_data() (antiddos_chart_section)
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

    # Bot Control section — Free Bot Visibility metrics + label metrics
    bot_section = ""
    bot_requests = 0
    overridden_bots = []
    if caps.get("bot_control") != "none":
        try:
            # 1. Precise totals from label metrics
            verified_allowed = 0
            unverified_allowed = 0
            unverified_blocked = 0
            unverified_challenged = 0
            unverified_captchaed = 0
            label_queries = []
            for i, (label, metric) in enumerate([
                ("verified", "AllowedRequests"), ("unverified", "AllowedRequests"),
                ("unverified", "BlockedRequests"), ("unverified", "ChallengeRequests"),
                ("unverified", "CaptchaRequests"),
            ]):
                label_queries.append({"Id": f"bl{i}", "MetricStat": {
                    "Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric, "Dimensions": [
                        {"Name": "LabelName", "Value": label},
                        {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"},
                        {"Name": "WebACL", "Value": webacl_name},
                    ] + _region_dim}, "Period": 604800, "Stat": "Sum",
                }})
            bl_resp = cw.get_metric_data(MetricDataQueries=label_queries, StartTime=start_this_week, EndTime=end)
            for r in bl_resp.get("MetricDataResults", []):
                val = int(sum(r.get("Values", [])))
                if r["Id"] == "bl0": verified_allowed = val
                elif r["Id"] == "bl1": unverified_allowed = val
                elif r["Id"] == "bl2": unverified_blocked = val
                elif r["Id"] == "bl3": unverified_challenged = val
                elif r["Id"] == "bl4": unverified_captchaed = val

            # 2. Targeted bot control totals from label metrics
            targeted_blocked = 0
            targeted_challenged = 0
            targeted_counted = 0
            tgt_resp = cw.get_metric_data(
                MetricDataQueries=[{"Id": "tgt", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} LabelNamespace=\"awswaf:managed:aws:bot-control\" WebACL=\"{webacl_name}\"', 'Sum', 604800)"}],
                StartTime=start_this_week, EndTime=end,
            )
            tgt_rules = {}  # {rule_name: {blocked, challenged, captchaed, counted}}
            for r in tgt_resp.get("MetricDataResults", []):
                total = int(sum(r.get("Values", [])))
                if total <= 0:
                    continue
                parts = r.get("Label", "").split()
                if len(parts) < 2 or not parts[0].startswith("TGT_"):
                    continue
                rule_name = parts[0]
                metric = parts[1]
                if rule_name not in tgt_rules:
                    tgt_rules[rule_name] = {"blocked": 0, "challenged": 0, "captchaed": 0, "counted": 0}
                if "Block" in metric and "Match" not in metric:
                    tgt_rules[rule_name]["blocked"] += total
                elif "Challenge" in metric and "Match" not in metric:
                    tgt_rules[rule_name]["challenged"] += total
                elif "Captcha" in metric and "Match" not in metric:
                    tgt_rules[rule_name]["captchaed"] += total
                elif "Count" in metric:
                    tgt_rules[rule_name]["counted"] += total
            targeted_mitigated = 0
            targeted_counted = 0
            for d in tgt_rules.values():
                targeted_mitigated += d["blocked"] + d["challenged"] + d["captchaed"]
                targeted_counted += d["counted"]

            # 3. Free Bot Visibility (sampled) — per-bot classification
            fbv_resp = cw.get_metric_data(
                MetricDataQueries=[
                    {"Id": "ba", "Expression": f"SEARCH('{{AWS/WAFV2,BotCategory,BotName,Intent,Organization,VerificationStatus,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"SampleAllowedRequest\"', 'Sum', 604800)"},
                    {"Id": "bb", "Expression": f"SEARCH('{{AWS/WAFV2,BotCategory,BotName,Intent,Organization,VerificationStatus,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"SampleBlockedRequest\"', 'Sum', 604800)"},
                    {"Id": "bc", "Expression": f"SEARCH('{{AWS/WAFV2,BotCategory,BotName,Intent,Organization,VerificationStatus,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"SampleChallengeRequest\"', 'Sum', 604800)"},
                    {"Id": "bd", "Expression": f"SEARCH('{{AWS/WAFV2,BotCategory,BotName,Intent,Organization,VerificationStatus,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"SampleCaptchaRequest\"', 'Sum', 604800)"},
                ],
                StartTime=start_this_week, EndTime=end,
            )
            bots = {}
            for r in fbv_resp.get("MetricDataResults", []):
                total = int(sum(r.get("Values", [])))
                if total <= 0:
                    continue
                parts = r.get("Label", "").split()
                if len(parts) < 6:
                    continue
                bot_name = parts[1]
                if bot_name in ("ALL_BOTS", "NON_BOT"):
                    continue
                if bot_name not in bots:
                    bots[bot_name] = {"category": parts[0].replace("bot:category:", ""), "org": parts[3],
                                      "verified": parts[4] == "bot:verified",
                                      "s_allowed": 0, "s_blocked": 0, "s_challenged": 0}
                if r["Id"] == "ba": bots[bot_name]["s_allowed"] += total
                elif r["Id"] in ("bb",): bots[bot_name]["s_blocked"] += total
                elif r["Id"] in ("bc", "bd"): bots[bot_name]["s_challenged"] += total

            # 4. Group bots
            good_bots = [(n, b) for n, b in bots.items() if b["verified"] and b["s_blocked"] == 0]
            bad_bots = [(n, b) for n, b in bots.items() if (b["s_blocked"] > 0 or b["s_challenged"] > 0) and b["s_allowed"] == 0 and not b["verified"]]
            counted_bots = [(n, b) for n, b in bots.items() if not b["verified"] and b["s_allowed"] > 0]
            good_bots.sort(key=lambda x: x[1]["s_allowed"], reverse=True)
            bad_bots.sort(key=lambda x: x[1]["s_blocked"] + x[1]["s_challenged"], reverse=True)
            counted_bots.sort(key=lambda x: x[1]["s_allowed"], reverse=True)

            # 5. Compute percentages for counted bots
            counted_sampled_total = sum(b["s_allowed"] for _, b in counted_bots)

            mitigated_bot_total = unverified_blocked + unverified_challenged + unverified_captchaed
            bot_requests = verified_allowed + unverified_allowed + mitigated_bot_total

            # 6. Build HTML
            def _bot_display(name, b):
                display = name.replace("_", " ").title()
                org = f" ({b['org']})" if b["org"] != "UNSPECIFIED" else ""
                return f"{display}{org}"

            good_list = ", ".join(_bot_display(n, b) for n, b in good_bots[:3])
            bad_list = ", ".join(_bot_display(n, b) for n, b in bad_bots[:5])

            # Counted bots chart data (horizontal bar with percentages)
            counted_chart = {"labels": [], "values": []}
            for n, b in counted_bots[:6]:
                pct = round(b["s_allowed"] / max(counted_sampled_total, 1) * 100)
                counted_chart["labels"].append(n.replace("_", " ").title())
                counted_chart["values"].append(pct)

            bot_section = f'<h2>{L["bot_control"]}</h2>'
            bot_section += '<div class="grid" style="grid-template-columns: 1fr 1fr; align-items: stretch; overflow: hidden;">'

            # Good Bots doughnut chart
            good_chart = {"labels": [], "values": []}
            for n, b in good_bots[:8]:
                good_chart["labels"].append(n.replace("_", " ").title())
                good_chart["values"].append(b["s_allowed"])
            bot_section += (
                f'<div class="card" style="border-left:3px solid var(--green)">'
                f'<div class="label">{L["good_bots"]} — <strong>{verified_allowed:,}</strong></div>'
                f'<div class="chart-container" style="padding:0.5rem"><canvas id="goodBotChart"></canvas></div>'
                f'</div>'
            )

            # Unverified Bots stacked horizontal bar (counted + mitigated per bot)
            unverified_total_all = unverified_allowed + mitigated_bot_total
            all_unverified = {}
            for n, b in counted_bots + bad_bots:
                if n not in all_unverified:
                    all_unverified[n] = {"s_allowed": 0, "s_blocked": 0, "s_challenged": 0}
                all_unverified[n]["s_allowed"] += b["s_allowed"]
                all_unverified[n]["s_blocked"] += b["s_blocked"]
                all_unverified[n]["s_challenged"] += b["s_challenged"]
            sorted_unverified = sorted(all_unverified.items(), key=lambda x: sum(x[1].values()), reverse=True)[:8]

            unverified_chart = {"labels": [], "counted": [], "mitigated": []}
            for n, b in sorted_unverified:
                bot_total = b["s_allowed"] + b["s_blocked"] + b["s_challenged"]
                counted_pct = round(b["s_allowed"] / max(bot_total, 1) * 100)
                mitigated_pct_bot = 100 - counted_pct
                unverified_chart["labels"].append(f'{n.replace("_", " ").title()}')
                unverified_chart["counted"].append(b["s_allowed"])
                unverified_chart["mitigated"].append(b["s_blocked"] + b["s_challenged"])

            bot_section += (
                f'<div class="card" style="border-left:3px solid var(--accent);overflow:hidden">'
                f'<div class="label">{L["unverified_bots"]} — <strong>{unverified_total_all:,}</strong></div>'
                f'<div class="chart-container" style="padding:0.5rem;overflow:hidden"><canvas id="unverifiedBotChart"></canvas></div>'
                f'</div>'
            )

            bot_section += '</div>'

            # Charts JS
            bot_section += (
                f'<script>(function(){{'
                f'const c = getComputedStyle(document.documentElement).getPropertyValue("--chart-text").trim() || "#e6edf3";'
                f'const colors = ["#3fb950","#58a6ff","#d29922","#a371f7","#79c0ff","#f0883e","#8b949e","#db61a2"];'
                f'const gbd = {json.dumps(good_chart)};'
                f'new Chart(document.getElementById("goodBotChart"), {{'
                f'  type: "doughnut",'
                f'  data: {{ labels: gbd.labels, datasets: [{{ data: gbd.values, backgroundColor: colors.slice(0, gbd.labels.length), borderWidth: 0 }}] }},'
                f'  options: {{ responsive: true, plugins: {{ legend: {{ position: "right", labels: {{ color: c, boxWidth: 12 }} }}, tooltip: {{ enabled: false }} }} }}'
                f'}});'
                f'const ubd = {json.dumps(unverified_chart)};'
                f'new Chart(document.getElementById("unverifiedBotChart"), {{'
                f'  type: "bar",'
                f'  data: {{ labels: ubd.labels, datasets: ['
                f'    {{ label: "{L["counted"]}", data: ubd.counted, backgroundColor: "rgba(210,153,34,0.7)" }},'
                f'    {{ label: "{L["mitigated"]}", data: ubd.mitigated, backgroundColor: "rgba(248,81,73,0.7)" }}'
                f'  ] }},'
                f'  options: {{ indexAxis: "y", responsive: true, plugins: {{ legend: {{ labels: {{ color: c, boxWidth: 12 }} }}, tooltip: {{ callbacks: {{ label: function(ctx) {{ return ctx.dataset.label; }} }} }} }}, scales: {{ x: {{ stacked: true, ticks: {{ color: c }} }}, y: {{ stacked: true, ticks: {{ color: c }} }} }} }}'
                f'}});'
                f'}})();</script>'
            )

            # Disclaimer for sampled charts (between common bots and targeted)
            bot_section += f'<p style="color:var(--muted);font-size:1rem;margin:1rem 0 2rem">{L["bot_disclaimer"]}</p>'

            # Targeted Bot Detection section — progress bar style
            if targeted_mitigated + targeted_counted > 0:
                tgt_total = targeted_mitigated + targeted_counted
                tgt_pct = round(targeted_mitigated / max(tgt_total, 1) * 100)
                bot_section += (
                    f'<div class="card" style="margin-top:1rem;padding:5rem 1.5rem">'
                    f'<div class="label" style="font-size:1rem">{L["targeted"]} — <strong>{tgt_total:,}</strong> {L["requests"]}</div>'
                    f'<div style="background:var(--border);border-radius:6px;height:40px;margin:1rem 0;overflow:hidden;display:flex">'
                    f'<div style="width:{tgt_pct}%;background:#f85149;display:flex;align-items:center;justify-content:center;color:#fff;font-size:1rem;font-weight:600">{targeted_mitigated:,}</div>'
                    f'<div style="flex:1;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:1rem">{targeted_counted:,}</div>'
                    f'</div>'
                    f'<div style="display:flex;justify-content:space-between;font-size:1rem;color:var(--muted)">'
                    f'<span>{L["targeted_mitigated"]} ({tgt_pct}%)</span>'
                    f'<span>{L["targeted_counted"]} ({100-tgt_pct}%)</span>'
                    f'</div>'
                    f'</div>'
                )
        except Exception:
            pass

    # Attack type timeseries for stacked area chart
    attack_ts = _get_attack_timeseries(cw, webacl_name, start_this_week, end, tz_offset=_tz_offset, scope=scope, region=region)

    # DDoS chart (always rendered)
    antiddos_chart_section = _get_ddos_chart_data(cw, webacl_name, start_this_week, end, L, tz_offset=_tz_offset)

    # Country map SVG
    country_map_svg = _build_country_map_svg(countries) if countries else f'<p class="muted">{L["no_data_search"]}</p>'

    # DDoS event count from metrics — count distinct events by looking for gaps in event-detected label
    ddos_event_count = 0
    try:
        _ddos_resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "raw_evt", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests",
                    "Dimensions": [{"Name": "WebACL", "Value": webacl_name},
                                   {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                                   {"Name": "LabelName", "Value": "event-detected"}]}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "evt", "Expression": "FILL(raw_evt,0)"},
            ],
            StartTime=start_this_week, EndTime=end, ScanBy="TimestampAscending",
        )
        for r in _ddos_resp.get("MetricDataResults", []):
            values = r.get("Values", [])
            # Count events: consecutive non-zero windows = 1 event, gap = new event
            in_event = False
            for v in values:
                if v > 0:
                    if not in_event:
                        ddos_event_count += 1
                        in_event = True
                else:
                    in_event = False
    except Exception:
        pass
    ddos_status = f"🔴 {ddos_event_count} {L['events']}" if ddos_event_count > 0 else L["no_events"]

    # Executive Summary — LLM generates, limited to 3-5 sentences
    mitigated_pct = f"{(threats_mitigated/total_this*100):.1f}" if total_this > 0 else "0"
    bot_pct = f"{(bot_requests / total_this * 100):.1f}" if total_this > 0 else "0"
    executive_summary = "{{EXECUTIVE_SUMMARY}}"

    date_range = f"{start_this_week.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')}"
    from datetime import datetime as _dt
    gen_time = _dt.now(timezone(timedelta(hours=_tz_off)) if _tz_off else timezone.utc).strftime('%Y-%m-%d %H:%M')

    html = REPORT_TEMPLATE.format(
        webacl_name=webacl_name,
        scope=scope,
        date_range=date_range,
        gen_time=gen_time,
        tz_label=tz_label,
        default_theme=theme,
        executive_summary=executive_summary,
        total_requests=f"{total_this:,}",
        total_change=total_change,
        total_change_class=total_change_class,
        threats_mitigated=f"{threats_mitigated:,}",
        mitigated_pct=mitigated_pct,
        ddos_status=ddos_status,
        antiddos_section=antiddos_section,
        antiddos_chart_section=antiddos_chart_section,
        bot_section=bot_section,
        bot_requests=f"{bot_requests:,}",
        bot_pct=bot_pct,
        top_country_count=len(countries),
        country_map_svg=country_map_svg,
        attack_data_json=json.dumps(attack_ts),
        L_title=L["title"],
        L_delay_note=L["delay_note"],
        L_generated=L["generated"],
        L_no_data_search=L["no_data_search"],
        L_exec_summary=L["exec_summary"],
        L_highlights=L["highlights"],
        L_total_requests=L["total_requests"],
        L_threats_mitigated=L["threats_mitigated"],
        L_ddos_protection=L["ddos_protection"],
        L_common_bot=L["common_bot"],
        L_of_traffic=L["of_traffic"],
        L_of_total_traffic=L["of_total_traffic"],
        L_top_attack=L["top_attack"],
        L_attack_chart_note=L["attack_chart_note"],
        L_country_note=L["country_note"],
        L_attack_chart_title=L["attack_chart_title"],
    )

    output_path = f"waf-weekly-summary-{webacl_name}-{end.strftime('%Y%m%d')}.html"
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
        data_lines.append(f"- Bot requests: {bot_requests:,} ({bot_pct}% of traffic)")
        data_lines.append(f"- Verified bots: {verified_allowed:,}, Unverified allowed: {unverified_allowed:,}, Unverified mitigated: {mitigated_bot_total:,}")

    data_lines.append("")
    data_lines.append("## Instructions")
    data_lines.append("Write 3-5 sentences for management. Use **bold** for key numbers. Flowing prose, no bullet lists.")
    data_lines.append("Cover: 1) traffic volume + week-over-week trend, 2) DDoS/attacks blocked, 3) bot situation, 4) brief conclusion on overall security posture.")
    data_lines.append("Tone: factual and concise. State what happened and what was protected. Do NOT use phrases like 'money well spent', 'ROI', or 'worth the investment'.")
    data_lines.append("Language: match user's language.")
    data_lines.append("")
    data_lines.append(f"Then call set_report_summary(path='{output_path}', summary='your summary here')")

    truncation_note = ""
    if actual_days < days - 0.1:
        truncation_note = f"\n⚠️ Note: requested {days} days but only {actual_days:.1f} days of data available (end capped at current time). WoW comparison uses full {days}-day previous period."

    # Detect missing sections
    missing = []
    if not countries:
        missing.append("country_map")
    if not attack_ts.get("series"):
        missing.append("attack_types")
    if not bot_requests:
        missing.append("bot_control")

    partial_note = ""
    if missing:
        partial_note = (f"\n\nPARTIAL_DATA: true\nMISSING_SECTIONS: {missing}\n"
                        "REASON: CloudWatch metric discovery index expired (no matching traffic in ~14 days).\n"
                        "ACTION: Inform user that some sections are empty due to lack of recent traffic. Suggest generating test traffic and re-running.")

    return "\n".join(data_lines) + truncation_note + partial_note



def _poll_log_query(logs_client, log_group, start, end, query, return_full=False, return_rows=False, max_wait=120):
    """Run a CWL query with polling. Returns count (int), full row (dict), or all rows (list)."""
    import time
    resp = logs_client.start_query(logGroupName=log_group, startTime=start, endTime=end, queryString=query, limit=1000)
    query_id = resp["queryId"]
    elapsed = 0
    while elapsed < max_wait:
        time.sleep(2)  # nosemgrep: arbitrary-sleep — polling for CWL query
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

def _get_weekly_totals(cw, webacl_name: str, start, end, scope: str = "CLOUDFRONT", region: str = "us-east-1") -> dict:
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
                    "Dimensions": _dims(webacl_name, scope, region),
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


def _get_traffic_timeseries(cw, webacl_name: str, start, end, scope: str = "CLOUDFRONT", region: str = "") -> list:
    """Get 15-min resolution traffic data using SEARCH."""
    try:
        _dims = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
        if scope == "REGIONAL" and region:
            _dims.append({"Name": "Region", "Value": region})
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "raw_a", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": _dims}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "allowed", "Expression": "FILL(raw_a,0)"},
                {"Id": "raw_b", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests", "Dimensions": _dims}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "blocked", "Expression": "FILL(raw_b,0)"},
                {"Id": "raw_c", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "challenged", "Expression": "FILL(raw_c,0)"},
                {"Id": "raw_p", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchaRequests", "Dimensions": _dims}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "captcha", "Expression": "FILL(raw_p,0)"},
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


def _get_attack_timeseries(cw, webacl_name: str, start, end, tz_offset=None, scope: str = "CLOUDFRONT", region: str = "") -> dict:
    """Get 15-min resolution attack type breakdown using {Attack, WebACL} dimension.

    Returns: {"labels": [...], "series": {"BadBots": [...], "XSS": [...], ...}}
    DDoS (Anti-DDoS AMR challenge) is excluded — shown separately in DDoS chart.
    """
    if scope == "REGIONAL" and region:
        rule_dim_set = "{AWS/WAFV2,Rule,WebACL,Region}"
        rule_extra = f' Region="{region}"'
    else:
        rule_dim_set = "{AWS/WAFV2,Rule,WebACL}"
        rule_extra = ""
    try:
        _dims_rule = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
        if scope == "REGIONAL" and region:
            _dims_rule.append({"Name": "Region", "Value": region})
        _dims_ddos = [{"Name": "WebACL", "Value": webacl_name},
                      {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                      {"Name": "LabelName", "Value": "ddos-request"}]
        _dims_ddos_fb = [{"Name": "WebACL", "Value": webacl_name},
                         {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                         {"Name": "LabelName", "Value": "challengeable-request"}]
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "attacks", "Expression": f"SEARCH('{{AWS/WAFV2,Attack,WebACL}} WebACL=\"{webacl_name}\" MetricName=(\"BlockedRequests\" OR \"ChallengeRequests\" OR \"CaptchaRequests\")', 'Sum', 900)"},
                {"Id": "rb", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests", "Dimensions": _dims_rule}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "rc", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims_rule}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "rp", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchaRequests", "Dimensions": _dims_rule}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "total_m", "Expression": "FILL(rb,0)+FILL(rc,0)+FILL(rp,0)"},
                {"Id": "raw_ddos", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims_ddos}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "raw_ddos_fb", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims_ddos_fb}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "ddos_c", "Expression": "IF(SUM(raw_ddos)>0, FILL(raw_ddos,0), FILL(raw_ddos_fb,0))"},
            ],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        # Build time axis from total_m (has all timestamps via FILL)
        labels = []
        total_values = []
        ddos_values = []
        attack_raw = {}  # {attack_type: {timestamp_str: value}}
        _user_tz = timezone(tz_offset) if tz_offset else timezone.utc
        for r in resp.get("MetricDataResults", []):
            if r["Id"] == "total_m":
                for ts, val in zip(r.get("Timestamps", []), r.get("Values", [])):
                    key = ts.astimezone(_user_tz).strftime("%m/%d %H:%M")
                    labels.append(key)
                    total_values.append(int(val))
            elif r["Id"] == "ddos_c":
                for ts, val in zip(r.get("Timestamps", []), r.get("Values", [])):
                    ddos_values.append(int(val))
            elif r["Id"] == "attacks":
                raw_label = r.get("Label", "Unknown")
                # Strip trailing MetricName if present (e.g. "BadBots BlockedRequests" → "BadBots")
                attack_type = raw_label.split(" ")[0] if any(raw_label.endswith(m) for m in ("BlockedRequests", "ChallengeRequests", "CaptchaRequests")) else raw_label
                if attack_type not in attack_raw:
                    attack_raw[attack_type] = {}
                for ts, val in zip(r.get("Timestamps", []), r.get("Values", [])):
                    key = ts.astimezone(_user_tz).strftime("%m/%d %H:%M")
                    attack_raw[attack_type][key] = attack_raw[attack_type].get(key, 0) + int(val)

        if not labels:
            return {"labels": [], "series": {}}

        # Pad ddos_values if needed
        if len(ddos_values) < len(labels):
            ddos_values.extend([0] * (len(labels) - len(ddos_values)))

        # Align attack series to labels, fill missing with 0
        series = {}
        for atype, ts_map in attack_raw.items():
            series[atype] = [ts_map.get(lbl, 0) for lbl in labels]

        # Compute "Other" = total - known_attack_types - DDoS_challenge
        other = []
        for i in range(len(labels)):
            known_sum = sum(s[i] for s in series.values())
            other.append(max(0, total_values[i] - known_sum - ddos_values[i]))
        if any(v > 0 for v in other):
            series["Other"] = other

        return {"labels": labels, "series": series}
    except Exception:
        return {"labels": [], "series": {}}


def _get_ddos_chart_data(cw, webacl_name: str, start, end, L: dict, tz_offset=None) -> str:
    """Build DDoS chart HTML section. Always renders (flat line if no events)."""
    import json as _json
    try:
        _dims_ddos = [{"Name": "WebACL", "Value": webacl_name},
                      {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                      {"Name": "LabelName", "Value": "ddos-request"}]
        _dims_ddos_fb = [{"Name": "WebACL", "Value": webacl_name},
                         {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                         {"Name": "LabelName", "Value": "challengeable-request"}]
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "raw_ddos", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims_ddos}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "raw_ddos_fb", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims_ddos_fb}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "ddosreq", "Expression": "IF(SUM(raw_ddos)>0, FILL(raw_ddos,0), FILL(raw_ddos_fb,0))"},
            ],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        ddos_chart_data = {"labels": [], "ddos": []}
        _user_tz = timezone(tz_offset) if tz_offset else timezone.utc
        for r in resp.get("MetricDataResults", []):
            if r["Id"] == "ddosreq":
                ddos_chart_data["labels"] = [t.astimezone(_user_tz).strftime("%m/%d %H:%M") for t in r.get("Timestamps", [])]
                ddos_chart_data["ddos"] = [int(v) for v in r.get("Values", [])]
        if not ddos_chart_data["labels"]:
            return f'<h2>{L["antiddos"]}</h2><p style="color:var(--muted)">{L["antiddos_no_data"]}</p>'
        return (
            f'<h2>{L["antiddos"]}</h2>'
            f'<div class="chart-container"><canvas id="ddosChart"></canvas></div>'
            f'<p style="color:var(--muted);font-size:1rem;text-align:center;">{L["antiddos_chart_note"]}</p>'
            f'<script>'
            f'(function(){{'
            f'const ddosData = {_json.dumps(ddos_chart_data)};'
            f'const c = getComputedStyle(document.documentElement).getPropertyValue("--chart-text").trim() || "#e6edf3";'
            f'new Chart(document.getElementById("ddosChart"), {{'
            f'  type: "line",'
            f'  data: {{ labels: ddosData.labels, datasets: ['
            f'    {{ label: "DDoS Requests", data: ddosData.ddos, borderColor: "#f85149", borderWidth: 1.5, fill: true, backgroundColor: "rgba(248,81,73,0.25)", tension: 0.2, pointRadius: 0 }},'
            f'  ] }},'
            f'  options: {{ responsive: true, interaction: {{ mode: "index", intersect: false }}, plugins: {{ title: {{ display: true, text: "{L["antiddos_title"]}", color: c }}, legend: {{ labels: {{ color: c }} }}, tooltip: {{ mode: "index", intersect: false }}, zoom: {{ zoom: {{ wheel: {{ enabled: true }}, pinch: {{ enabled: true }}, mode: "x" }}, pan: {{ enabled: true, mode: "x" }} }} }}, scales: {{ x: {{ ticks: {{ color: c, maxTicksLimit: 14 }} }}, y: {{ beginAtZero: true, ticks: {{ color: c }} }} }} }}'
            f'}});'
            f'}})();'
            f'</script>'
        )
    except Exception:
        return f'<h2>{L["antiddos"]}</h2><p style="color:var(--muted);">{L["antiddos_not_deployed"]}</p>'


def _get_daily_breakdown(cw, webacl_name: str, start, end, scope: str = "CLOUDFRONT", region: str = "us-east-1") -> list:
    """Get daily allowed/blocked/challenged/captcha counts."""
    queries = []
    for i, metric in enumerate(["AllowedRequests", "BlockedRequests", "ChallengeRequests", "CaptchaRequests"]):
        queries.append({
            "Id": f"d{i}",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/WAFV2",
                    "MetricName": metric,
                    "Dimensions": _dims(webacl_name, scope, region),
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
    """Get top countries by mitigated requests (Block + Challenge + Captcha)."""
    if not re.match(r'^[\w-]+$', webacl_name):
        return []
    resp = cw.get_metric_data(
        MetricDataQueries=[
            {"Id": "blocked", "Expression": f"SEARCH('{{AWS/WAFV2,Country,WebACL}} MetricName=\"BlockedRequests\" WebACL=\"{webacl_name}\"', 'Sum', 604800)"},
            {"Id": "challenged", "Expression": f"SEARCH('{{AWS/WAFV2,Country,WebACL}} MetricName=\"ChallengeRequests\" WebACL=\"{webacl_name}\"', 'Sum', 604800)"},
            {"Id": "captcha", "Expression": f"SEARCH('{{AWS/WAFV2,Country,WebACL}} MetricName=\"CaptchaRequests\" WebACL=\"{webacl_name}\"', 'Sum', 604800)"},
        ],
        StartTime=start, EndTime=end,
    )
    country_totals = {}
    for r in resp.get("MetricDataResults", []):
        total = sum(r.get("Values", []))
        if total <= 0:
            continue
        label = r.get("Label", "")
        # Label format: "{CountryCode} {MetricName}"
        parts = label.split(" ")
        country = parts[0] if parts else label
        if country in ("BlockedRequests", "ChallengeRequests", "CaptchaRequests"):
            continue
        country_totals[country] = country_totals.get(country, 0) + int(total)
    sorted_countries = sorted(country_totals.items(), key=lambda x: x[1], reverse=True)
    return [{"country": c, "count": cnt} for c, cnt in sorted_countries[:10]]


def _get_top_rules(cw, webacl_name: str, start, end, scope: str = "CLOUDFRONT", region: str = "") -> list:
    """Get top rules by hit count using SEARCH."""
    if not re.match(r'^[\w-]+$', webacl_name):
        return []
    # CLOUDFRONT uses {Rule,WebACL}; REGIONAL uses {Rule,WebACL,Region}
    if scope == "REGIONAL" and region:
        dim_set = "{AWS/WAFV2,Rule,WebACL,Region}"
        extra_filter = f' Region="{region}"'
    else:
        dim_set = "{AWS/WAFV2,Rule,WebACL}"
        extra_filter = ""
    results = []
    for action in ["BlockedRequests", "CountedRequests", "ChallengeRequests"]:
        expression = (
            f"SEARCH('{dim_set} "
            f"MetricName=\"{action}\" WebACL=\"{webacl_name}\"{extra_filter}', 'Sum', 604800)"
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
