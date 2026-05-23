# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Overview tool — fast metrics-based answers for common questions."""

import sys
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_metrics_region, get_scope, get_user_timezone


def _log(msg: str):
    print(f"[waf_overview] {msg}", file=sys.stderr, flush=True)


@tool
def get_waf_overview(query_type: str, webacl_name: str, hours: int = 24, start_time: str = "", scope: str = "") -> str:
    """Fast metrics-based overview of WAF activity. No log queries — answers in 2-3 seconds.

    Use this for "what happened" questions. For "who did it" (IPs, URIs, request details),
    use run_logs_query or run_athena_query instead.

    Args:
        query_type: Type of overview to return:
            - top_rules: Rules ranked by mitigation volume + WoW comparison
            - attack_types: Attack type distribution (XSS, SQLi, LFI, etc.)
            - bot_summary: Verified/unverified/targeted bot overview
            - bot_names: Top bot names by request volume
            - targeted_signals: Targeted Bot Control detection signals breakdown
            - rate_limits: Rate-limit rule trigger counts
            - challenge_solve_rate: Challenge/CAPTCHA solve rates
        webacl_name: Name of the WebACL to query.
        hours: Time window in hours (default 24, max 336 = 14 days).
        start_time: Optional start time (e.g. "2026-05-09" or "2026-05-09T14:00").
            If provided, queries from start_time to start_time + hours.
            If omitted, queries from (now - hours) to now.
        scope: "CLOUDFRONT" or "REGIONAL". Auto-detected from session if empty.

    Returns:
        Formatted overview data. For deeper analysis of specific IPs/URIs,
        use run_logs_query with start_time.
    """
    _log(f"query_type={query_type} webacl={webacl_name} hours={hours} start_time={start_time}")
    if not scope:
        scope = get_scope() or "CLOUDFRONT"
    region = "us-east-1" if scope == "CLOUDFRONT" else get_metrics_region()
    cw = get_client("cloudwatch", region_name=region)

    hours = min(hours, 336)
    if start_time:
        tz_offset = get_user_timezone()
        user_tz = timezone(timedelta(hours=tz_offset)) if tz_offset is not None else timezone.utc
        try:
            if "T" in start_time:
                start = datetime.fromisoformat(start_time).replace(tzinfo=user_tz).astimezone(timezone.utc)
            else:
                start = datetime.strptime(start_time, "%Y-%m-%d").replace(tzinfo=user_tz).astimezone(timezone.utc)
        except ValueError:
            return f"Error: invalid start_time '{start_time}'. Use format YYYY-MM-DD or YYYY-MM-DDTHH:MM."
        end = start + timedelta(hours=hours)
        # Clamp end to now if in the future
        now = datetime.now(timezone.utc)
        if end > now:
            end = now
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
    prev_start = start - timedelta(hours=hours)

    if query_type == "top_rules":
        return _top_rules(cw, webacl_name, start, end, prev_start, hours, scope, region)
    elif query_type == "attack_types":
        return _attack_types(cw, webacl_name, start, end, hours)
    elif query_type == "bot_summary":
        return _bot_summary(cw, webacl_name, start, end, hours)
    elif query_type == "bot_names":
        return _bot_names(cw, webacl_name, start, end, hours)
    elif query_type == "targeted_signals":
        return _targeted_signals(cw, webacl_name, start, end, hours)
    elif query_type == "rate_limits":
        return _rate_limits(cw, webacl_name, scope, start, end, hours)
    elif query_type == "challenge_solve_rate":
        return _challenge_solve_rate(cw, webacl_name, scope, region, start, end, hours)
    else:
        return f"Error: unknown query_type '{query_type}'. Available: top_rules, attack_types, bot_summary, bot_names, targeted_signals, rate_limits, challenge_solve_rate"


def _calc_period(hours: float) -> int:
    """Calculate a sensible CloudWatch period for the given time window.

    Returns period in seconds that gives meaningful granularity:
    - ≤6h  → 300s  (5-min, ~72 data points max)
    - ≤72h → 3600s (1-hour, up to 72 data points)
    - >72h → 86400s (1-day)
    """
    if hours <= 6:
        return 300
    elif hours <= 72:
        return 3600
    else:
        return 86400


def _top_rules(cw, webacl_name, start, end, prev_start, hours, scope="CLOUDFRONT", region=""):
    from tools.waf_patrol import _get_all_rules_metrics_search
    period = _calc_period(hours)
    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope, region=region)
    last_week = _get_all_rules_metrics_search(cw, webacl_name, prev_start, start, period=period, scope=scope, region=region)

    rows = []
    for rule, data in this_week.items():
        if rule == "ALL":
            continue
        blocked = sum(data.get("blocked", []))
        challenged = sum(data.get("challenge", []))
        captcha = sum(data.get("captcha", []))
        counted = sum(data.get("counted", []))
        mitigated = blocked + challenged + captcha
        if mitigated == 0 and counted == 0:
            continue
        # WoW
        lw = last_week.get(rule, {})
        lw_mit = sum(lw.get("blocked", [])) + sum(lw.get("challenge", [])) + sum(lw.get("captcha", []))
        wow = f"{mitigated/lw_mit:.1f}x" if lw_mit > 0 else "new"
        rows.append((mitigated, rule, blocked, challenged, captcha, counted, wow))

    rows.sort(reverse=True)
    lines = [f"Top Rules (past {hours}h) for {webacl_name}:", ""]
    lines.append(f"{'Rule':<40} {'Blocked':>8} {'Challenge':>10} {'Captcha':>8} {'Counted':>8} {'WoW':>6}")
    lines.append("-" * 85)
    for _, rule, b, ch, cap, cnt, wow in rows[:15]:
        lines.append(f"{rule:<40} {b:>8,} {ch:>10,} {cap:>8,} {cnt:>8,} {wow:>6}")

    # Totals
    all_data = this_week.get("ALL", {})
    tot_b = sum(all_data.get("blocked", []))
    tot_ch = sum(all_data.get("challenge", []))
    tot_cap = sum(all_data.get("captcha", []))
    tot_a = sum(all_data.get("allowed", []))

    if tot_b + tot_ch + tot_cap + tot_a == 0 and not rows:
        return f"No metrics data for {webacl_name} in this time window (start_time + {hours}h). Verify the WebACL name and time range."

    lines.append("-" * 85)
    lines.append(f"Total: mitigated {tot_b + tot_ch + tot_cap:,} (blocked {tot_b:,} + challenge {tot_ch:,} + captcha {tot_cap:,}) | allowed {tot_a:,}")

    # Time-series breakdown (peak detection)
    timestamps = all_data.get("timestamps", [])
    ch_series = all_data.get("challenge", [])
    b_series = all_data.get("blocked", [])
    if timestamps and len(timestamps) > 1:
        # Combine blocked + challenge per period for peak detection
        combined = [b + c for b, c in zip(b_series, ch_series)] if len(b_series) == len(ch_series) else ch_series or b_series
        if combined and len(combined) <= len(timestamps):
            peak_idx = combined.index(max(combined))
            lines.append("")
            lines.append(f"Time granularity: {period}s ({period//60}min) | {len(timestamps)} data points")
            lines.append(f"Peak period: {timestamps[peak_idx]} ({max(combined):,} mitigated requests)")

    lines.append("")
    lines.append("→ For IP/URI details on a specific rule, use run_logs_query(query_type='count_rule_top_ips', rule_name='...', start_time='...')")
    return "\n".join(lines)


def _attack_types(cw, webacl_name, start, end, hours):
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "attacks", "Expression": f"SEARCH('{{AWS/WAFV2,Attack,WebACL}} WebACL=\"{webacl_name}\"', 'Sum', {_calc_period(hours)})"},
    ], StartTime=start, EndTime=end)

    types = {}
    for r in resp.get("MetricDataResults", []):
        label = r.get("Label", "")
        parts = label.split(" ")
        atype = parts[0] if parts else label
        val = int(sum(r.get("Values", [])))
        if val > 0:
            types[atype] = types.get(atype, 0) + val

    sorted_types = sorted(types.items(), key=lambda x: x[1], reverse=True)
    lines = [f"Attack Types (past {hours}h) for {webacl_name}:", ""]
    for atype, count in sorted_types:
        lines.append(f"  {atype:<25} {count:>10,}")
    if not sorted_types:
        lines.append("  No attack data in this period.")
    lines.append("")
    lines.append("→ For timeline details, use get_waf_overview(query_type='top_rules') or run patrol_scan for full report.")
    return "\n".join(lines)


def _bot_summary(cw, webacl_name, start, end, hours):
    period = _calc_period(hours)
    queries = [
        {"Id": "v_a", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": [
            {"Name": "LabelName", "Value": "verified"}, {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"}, {"Name": "WebACL", "Value": webacl_name}]}, "Period": period, "Stat": "Sum"}},
        {"Id": "u_a", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": [
            {"Name": "LabelName", "Value": "unverified"}, {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"}, {"Name": "WebACL", "Value": webacl_name}]}, "Period": period, "Stat": "Sum"}},
        {"Id": "u_b", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests", "Dimensions": [
            {"Name": "LabelName", "Value": "unverified"}, {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"}, {"Name": "WebACL", "Value": webacl_name}]}, "Period": period, "Stat": "Sum"}},
        {"Id": "u_ch", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": [
            {"Name": "LabelName", "Value": "unverified"}, {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"}, {"Name": "WebACL", "Value": webacl_name}]}, "Period": period, "Stat": "Sum"}},
        {"Id": "u_cap", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchaRequests", "Dimensions": [
            {"Name": "LabelName", "Value": "unverified"}, {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"}, {"Name": "WebACL", "Value": webacl_name}]}, "Period": period, "Stat": "Sum"}},
    ]
    resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end)
    vals = {r["Id"]: int(sum(r.get("Values", []))) for r in resp.get("MetricDataResults", [])}

    v_a = vals.get("v_a", 0)
    u_a = vals.get("u_a", 0)
    u_b = vals.get("u_b", 0)
    u_ch = vals.get("u_ch", 0)
    u_cap = vals.get("u_cap", 0)
    u_mit = u_b + u_ch + u_cap

    lines = [f"Bot Summary (past {hours}h) for {webacl_name}:", ""]
    lines.append(f"  ✅ Verified (self-declared):     {v_a:>10,} allowed")
    lines.append(f"  ⚠️ Unverified allowed:           {u_a:>10,}")
    lines.append(f"  🚫 Unverified mitigated:         {u_mit:>10,} (blocked {u_b:,} + challenge {u_ch:,} + captcha {u_cap:,})")
    if v_a + u_a + u_mit == 0:
        lines.append("  No bot data — Bot Control may not be deployed.")
    lines.append("")
    lines.append("→ For bot name breakdown: get_waf_overview(query_type='bot_names')")
    lines.append("→ For targeted detection signals: get_waf_overview(query_type='targeted_signals')")
    return "\n".join(lines)


def _bot_names(cw, webacl_name, start, end, hours):
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "names", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:bot:name\"', 'Sum', {_calc_period(hours)})"},
    ], StartTime=start, EndTime=end)

    bots = {}
    for r in resp.get("MetricDataResults", []):
        label = r.get("Label", "")
        parts = label.split(" ")
        name = parts[0] if len(parts) >= 3 else label
        val = int(sum(r.get("Values", [])))
        if val > 0:
            bots[name] = bots.get(name, 0) + val

    sorted_bots = sorted(bots.items(), key=lambda x: x[1], reverse=True)
    lines = [f"Bot Names (past {hours}h) for {webacl_name}:", ""]
    for name, count in sorted_bots[:15]:
        lines.append(f"  {name:<30} {count:>10,}")
    if not sorted_bots:
        lines.append("  No bot name data — Bot Control may not be deployed.")
    lines.append("")
    lines.append("→ For IP-level analysis of a specific bot, use run_logs_query(query_type='label_top_ips', label='bot:name:<name>', start_time='...')")
    return "\n".join(lines)


def _targeted_signals(cw, webacl_name, start, end, hours):
    period = _calc_period(hours)
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "ctrl", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control\"', 'Sum', {period})"},
        {"Id": "sig", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal\"', 'Sum', {period})"},
        {"Id": "csp", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal:cloud_service_provider\"', 'Sum', {period})"},
        {"Id": "vol", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:ip\"', 'Sum', {period})"},
    ], StartTime=start, EndTime=end)

    signals = {}
    for r in resp.get("MetricDataResults", []):
        label = r.get("Label", "")
        parts = label.split(" ")
        if len(parts) < 3:
            continue
        name, metric = parts[0], parts[2]
        # Filter: only TGT_*, Signal*, CSP names
        if name.endswith("Low") or name == "TGT_TokenAbsent":
            continue
        if not (name.startswith("TGT_") or name.startswith("Signal") or name in ("token_absent", "non_browser_user_agent") or "cloud_service_provider" in parts[1]):
            continue
        val = int(sum(r.get("Values", [])))
        if val == 0:
            continue
        if name not in signals:
            signals[name] = {}
        signals[name][metric] = signals[name].get(metric, 0) + val

    sorted_sigs = sorted(signals.items(), key=lambda x: sum(x[1].values()), reverse=True)
    lines = [f"Targeted Bot Signals (past {hours}h) for {webacl_name}:", ""]
    lines.append(f"{'Signal':<35} {'Blocked':>8} {'Challenge':>10} {'Captcha':>8} {'NotBlocked':>10}")
    lines.append("-" * 75)
    for name, metrics in sorted_sigs:
        b = metrics.get("BlockedRequests", 0) + metrics.get("BlockRuleMatch", 0)
        ch = metrics.get("ChallengeRequests", 0) + metrics.get("ChallengeRuleMatch", 0)
        cap = metrics.get("CaptchaRequests", 0) + metrics.get("CaptchaRuleMatch", 0)
        a = metrics.get("AllowedRequests", 0)
        lines.append(f"{name:<35} {b:>8,} {ch:>10,} {cap:>8,} {a:>10,}")
    if not sorted_sigs:
        lines.append("  No targeted bot signals — Targeted Bot Control may not be deployed.")
    lines.append("")
    lines.append("→ For IP details on challenged traffic, use run_logs_query(query_type='ip_cross_query', start_time='...')")
    return "\n".join(lines)


def _rate_limits(cw, webacl_name, scope, start, end, hours):
    from tools.waf_patrol import _get_all_rules_metrics_search
    region = "us-east-1" if scope == "CLOUDFRONT" else get_metrics_region()
    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=_calc_period(hours), scope=scope, region=region)

    # Get rate-based rule names from WebACL config
    rate_rule_names = set()
    try:
        region = "us-east-1" if scope == "CLOUDFRONT" else get_metrics_region()
        waf = get_client("wafv2", region_name=region)
        resp = waf.list_web_acls(Scope="CLOUDFRONT" if scope == "CLOUDFRONT" else "REGIONAL")
        arn = next((w["ARN"] for w in resp.get("WebACLs", []) if w["Name"] == webacl_name), None)
        if arn:
            webacl_data = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=arn.split("/")[-1])["WebACL"]
            for rule in webacl_data.get("Rules", []):
                if "RateBasedStatement" in rule.get("Statement", {}):
                    rate_rule_names.add(rule.get("Name", ""))
    except Exception:
        pass

    lines = [f"Rate-Limit Rules (past {hours}h) for {webacl_name}:", ""]
    found = False
    for rule, metrics in sorted(data.items(), key=lambda x: sum(x[1].get("blocked", [])), reverse=True):
        if rule == "ALL":
            continue
        blocked = sum(metrics.get("blocked", []))
        challenged = sum(metrics.get("challenge", []))
        total = blocked + challenged
        if rule in rate_rule_names:
            lines.append(f"  {rule}: {total:,} mitigated (blocked {blocked:,} + challenge {challenged:,})")
            found = True
    if not found:
        if rate_rule_names:
            lines.append("  Rate-limit rules deployed but no triggers in this period.")
        else:
            lines.append("  No rate-limit rules detected in WebACL config.")
    return "\n".join(lines)


def _challenge_solve_rate(cw, webacl_name, scope, region, start, end, hours):
    from tools.waf_patrol import _get_challenge_solved, _get_all_rules_metrics_search
    cs, cas = _get_challenge_solved(cw, webacl_name, scope, region, start, end)
    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=_calc_period(hours), scope=scope, region=region)
    all_data = data.get("ALL", {})
    tot_ch = sum(all_data.get("challenge", []))
    tot_cap = sum(all_data.get("captcha", []))

    lines = [f"Challenge/CAPTCHA Solve Rate (past {hours}h) for {webacl_name}:", ""]
    lines.append(f"  Challenges issued:  {tot_ch:>10,}")
    lines.append(f"  Challenges solved:  {cs:>10,}" + (f"  ({cs*100//tot_ch}% solve rate)" if tot_ch > 0 else ""))
    lines.append(f"  CAPTCHAs issued:    {tot_cap:>10,}")
    lines.append(f"  CAPTCHAs solved:    {cas:>10,}" + (f"  ({cas*100//tot_cap}% solve rate)" if tot_cap > 0 else ""))
    lines.append("")
    if tot_ch > 0 and cs > 0:
        rate = cs * 100 // tot_ch
        if rate > 80:
            lines.append(f"⚠️ High solve rate ({rate}%) — challenges may be hitting real users, not bots.")
        elif rate < 10:
            lines.append(f"✅ Low solve rate ({rate}%) — challenges are effectively blocking automated traffic.")
        else:
            lines.append(f"ℹ️ Moderate solve rate ({rate}%) — mix of bots and real users being challenged.")
    return "\n".join(lines)
