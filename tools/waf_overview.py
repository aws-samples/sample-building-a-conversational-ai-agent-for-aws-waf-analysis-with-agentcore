# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Overview tool — fast metrics-based answers for common questions."""

import sys
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_scope, get_user_timezone


def _log(msg: str):
    print(f"[waf_overview] {msg}", file=sys.stderr, flush=True)


def _to_local_ts(timestamps):
    """Convert CloudWatch timestamps to user's session timezone."""
    tz_off = get_user_timezone()
    if tz_off is not None:
        user_tz = timezone(timedelta(hours=tz_off))
        return [t.astimezone(user_tz).isoformat() for t in timestamps]
    return [t.isoformat() for t in timestamps]


@tool
def get_waf_overview(query_type: str, webacl_name: str, minutes: int = 1440, start_time: str = "", scope: str = "") -> str:
    """Fast metrics-based overview of WAF activity. No log queries — answers in 2-3 seconds.

    Use this for "what happened" questions. For "who did it" (IPs, URIs, request details),
    use run_logs_query instead.

    Args:
        query_type: Type of overview to return:
            - top_rules: Rules ranked by mitigation volume + vs-previous-period comparison + full time-series
            - attack_types: Attack type distribution (XSS, SQLi, LFI, etc.)
            - bot_summary: Verified/unverified/targeted bot overview
            - bot_names: Top bot names by request volume
            - targeted_signals: Targeted Bot Control detection signals breakdown
            - rate_limits: Rate-limit rule trigger counts
            - challenge_solve_rate: Challenge/CAPTCHA solve rates
            - top_labels: All labels with hit counts (Anti-DDoS, Bot Control, token status) — use to verify which managed rules are active
        webacl_name: Name of the WebACL to query.
        minutes: Time window in minutes (default 1440 = 24h, max 20160 = 14 days).
            Use 60 for 1 hour (1-min granularity), 240 for 4 hours (5-min), 1440 for 1 day (15-min).
            Zoom in to shorter windows for finer granularity.
        start_time: Optional start time (e.g. "2026-05-09" or "2026-05-09T14:00").
            If provided, queries from start_time to start_time + minutes.
            If omitted, queries from (now - minutes) to now.
        scope: "CLOUDFRONT" or "REGIONAL". Auto-detected from session if empty.

    Returns:
        Formatted overview data with time-series. For deeper analysis of specific IPs/URIs,
        use run_logs_query with start_time.
    """
    _log(f"query_type={query_type} webacl={webacl_name} minutes={minutes} start_time={start_time}")
    if not scope:
        scope = get_scope() or "CLOUDFRONT"
    from tools.session_state import resolve_region
    region = resolve_region(scope)
    if region is None:
        return ("Error: REGIONAL scope requires get_waf_config to be called first "
                "(need to know which region the WebACL is in). "
                "Call get_waf_config(webacl_name='...') first.")

    # Validate WebACL exists
    try:
        waf = get_client("wafv2", region_name=region)
        waf_scope = "CLOUDFRONT" if scope == "CLOUDFRONT" else "REGIONAL"
        acls = waf.list_web_acls(Scope=waf_scope)["WebACLs"]
        if not any(a["Name"] == webacl_name for a in acls):
            available = [a["Name"] for a in acls]
            return (f"Error: WebACL '{webacl_name}' not found (scope={scope}, region={region}).\n"
                    f"Available WebACLs: {available}\n"
                    "ACTION: Ask the user to confirm the correct WebACL name from the list above.")
    except Exception as e:
        return f"Error: Failed to validate WebACL: {e}"

    cw = get_client("cloudwatch", region_name=region)

    minutes = min(minutes, 20160)  # max 14 days
    if start_time:
        tz_offset = get_user_timezone()
        user_tz = timezone(timedelta(hours=tz_offset)) if tz_offset is not None else timezone.utc
        try:
            if "T" in start_time:
                dt = datetime.fromisoformat(start_time)
                start = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=user_tz).astimezone(timezone.utc)
            else:
                start = datetime.strptime(start_time, "%Y-%m-%d").replace(tzinfo=user_tz).astimezone(timezone.utc)
        except ValueError:
            return f"Error: invalid start_time '{start_time}'. Use format YYYY-MM-DD or YYYY-MM-DDTHH:MM."
        end = start + timedelta(minutes=minutes)
        # Clamp end to now if in the future
        now = datetime.now(timezone.utc)
        if end > now:
            end = now
    else:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
    prev_start = start - timedelta(minutes=minutes)

    if query_type == "top_rules":
        return _top_rules(cw, webacl_name, start, end, prev_start, minutes, scope, region)
    elif query_type == "attack_types":
        return _attack_types(cw, webacl_name, start, end, minutes, scope, region)
    elif query_type == "bot_summary":
        return _bot_summary(cw, webacl_name, start, end, minutes)
    elif query_type == "bot_names":
        return _bot_names(cw, webacl_name, start, end, minutes, scope, region)
    elif query_type == "targeted_signals":
        return _targeted_signals(cw, webacl_name, start, end, minutes, scope, region)
    elif query_type == "rate_limits":
        return _rate_limits(cw, webacl_name, start, end, minutes, scope, region)
    elif query_type == "challenge_solve_rate":
        return _challenge_solve_rate(cw, webacl_name, scope, region, start, end, minutes)
    elif query_type == "top_labels":
        return _top_labels(cw, webacl_name, start, end, minutes, scope, region)
    else:
        return f"Error: unknown query_type '{query_type}'. Available: top_rules, attack_types, bot_summary, bot_names, targeted_signals, rate_limits, challenge_solve_rate, top_labels"


def _calc_period(minutes: int) -> int:
    """Calculate CloudWatch period for the given time window.

    Returns period in seconds:
    - ≤60min  → 60s   (1-min, up to 60 points)
    - ≤360min → 300s  (5-min, up to 72 points)
    - ≤4320min→ 900s  (15-min, up to 288 points)
    - ≤10080min→3600s (1-hour, up to 168 points)
    - >10080min→14400s(4-hour)
    """
    if minutes <= 60:
        return 60
    elif minutes <= 360:
        return 300
    elif minutes <= 4320:
        return 900
    elif minutes <= 10080:
        return 3600
    else:
        return 14400


def _fmt_window(minutes: int) -> str:
    """Format time window for display."""
    if minutes < 60:
        return f"{minutes}min"
    elif minutes % 60 == 0:
        return f"{minutes // 60}h"
    else:
        return f"{minutes}min"


def _has_mitigated_traffic(cw, webacl_name, start, end, scope="CLOUDFRONT", region="") -> bool:
    """Quick MetricStat check: did this WebACL have any blocked/challenged/captcha'd traffic?"""
    _dims = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    if scope == "REGIONAL" and region:
        _dims.append({"Name": "Region", "Value": region})
    try:
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "b", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests", "Dimensions": _dims}, "Period": int((end - start).total_seconds()), "Stat": "Sum"}},
                {"Id": "c", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims}, "Period": int((end - start).total_seconds()), "Stat": "Sum"}},
                {"Id": "p", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchaRequests", "Dimensions": _dims}, "Period": int((end - start).total_seconds()), "Stat": "Sum"}},
            ],
            StartTime=start, EndTime=end,
        )
        total = sum(int(v) for r in resp.get("MetricDataResults", []) for v in r.get("Values", []))
        return total > 0
    except Exception:
        return False


def _top_rules(cw, webacl_name, start, end, prev_start, minutes, scope="CLOUDFRONT", region=""):
    from tools.waf_patrol import _get_all_rules_metrics_search
    period = _calc_period(minutes)
    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope, region=region)
    last_week = _get_all_rules_metrics_search(cw, webacl_name, prev_start, start, period=period, scope=scope, region=region)

    # Get Rule=ALL totals via MetricStat (immune to 14-day SEARCH index expiry)
    _dims = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    if scope == "REGIONAL" and region:
        _dims.append({"Name": "Region", "Value": region})
    try:
        _ms_resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "raw_a", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "AllowedRequests", "Dimensions": _dims}, "Period": period, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "ms_a", "Expression": "FILL(raw_a,0)"},
                {"Id": "raw_b", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests", "Dimensions": _dims}, "Period": period, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "ms_b", "Expression": "FILL(raw_b,0)"},
                {"Id": "raw_c", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims}, "Period": period, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "ms_c", "Expression": "FILL(raw_c,0)"},
                {"Id": "raw_p", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchaRequests", "Dimensions": _dims}, "Period": period, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "ms_p", "Expression": "FILL(raw_p,0)"},
            ],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        from tools.session_state import get_user_timezone
        from datetime import timezone, timedelta
        _tz_off = get_user_timezone()
        _user_tz = timezone(timedelta(hours=_tz_off)) if _tz_off is not None else timezone(timedelta(0))
        ms_all = {"blocked": [], "challenge": [], "captcha": [], "allowed": [], "timestamps": []}
        for r in _ms_resp.get("MetricDataResults", []):
            vals = [int(v) for v in r.get("Values", [])]
            ts = [t.astimezone(_user_tz).isoformat() for t in r.get("Timestamps", [])]
            if r["Id"] == "ms_a":
                ms_all["allowed"] = vals
                ms_all["timestamps"] = ts
            elif r["Id"] == "ms_b":
                ms_all["blocked"] = vals
            elif r["Id"] == "ms_c":
                ms_all["challenge"] = vals
            elif r["Id"] == "ms_p":
                ms_all["captcha"] = vals
        # Override SEARCH-derived ALL with MetricStat ALL (always accurate)
        this_week["ALL"] = ms_all
    except Exception:
        pass  # Fall back to SEARCH-derived ALL

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
        # vs previous period
        lw = last_week.get(rule, {})
        lw_mit = sum(lw.get("blocked", [])) + sum(lw.get("challenge", [])) + sum(lw.get("captcha", []))
        wow = f"{mitigated/lw_mit:.1f}x" if lw_mit > 0 else "new"
        rows.append((mitigated, rule, blocked, challenged, captcha, counted, wow))

    rows.sort(reverse=True)
    lines = [f"Top Rules (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    lines.append(f"{'Rule':<40} {'Blocked':>8} {'Challenge':>10} {'Captcha':>8} {'Counted':>8} {'Change':>7}")
    lines.append("-" * 85)
    for _, rule, b, ch, cap, cnt, wow in rows[:15]:
        lines.append(f"{rule:<40} {b:>8,} {ch:>10,} {cap:>8,} {cnt:>8,} {wow:>7}")

    # Totals
    all_data = this_week.get("ALL", {})
    tot_b = sum(all_data.get("blocked", []))
    tot_ch = sum(all_data.get("challenge", []))
    tot_cap = sum(all_data.get("captcha", []))
    tot_a = sum(all_data.get("allowed", []))

    if tot_b + tot_ch + tot_cap + tot_a == 0 and not rows:
        return f"No metrics data for {webacl_name} in this time window (start_time + {_fmt_window(minutes)}). Verify the WebACL name and time range."

    lines.append("-" * 85)
    lines.append(f"Total: mitigated {tot_b + tot_ch + tot_cap:,} (blocked {tot_b:,} + challenge {tot_ch:,} + captcha {tot_cap:,}) | allowed {tot_a:,}")

    # Gap detection: warn if visible rules don't account for most mitigated traffic
    total_mitigated = tot_b + tot_ch + tot_cap
    visible_mitigated = sum(r[0] for r in rows[:15])
    if total_mitigated > 0 and visible_mitigated < total_mitigated * 0.5:
        gap = total_mitigated - visible_mitigated
        lines.append(f"\n⚠️ {gap:,} mitigated requests ({gap*100//total_mitigated}%) not attributed to visible rules — likely from managed rule group sub-rules (e.g., AMR ChallengeAllDuringEvent). Use ip_cross_query on top IPs to identify the actual terminating rule.")

    # Time-series breakdown
    timestamps = all_data.get("timestamps", [])
    ch_series = all_data.get("challenge", [])
    b_series = all_data.get("blocked", [])
    cap_series = all_data.get("captcha", [])
    a_series = all_data.get("allowed", [])
    if timestamps and len(timestamps) > 1:
        lines.append("")
        lines.append(f"Time-series ({period//60}min granularity, {len(timestamps)} points):")
        lines.append(f"{'Time':<25} {'Blocked':>8} {'Challenge':>10} {'Captcha':>8} {'Allowed':>8} {'Mitigated':>10}")
        shown = 0
        for i, ts in enumerate(timestamps):
            b = b_series[i] if i < len(b_series) else 0
            c = ch_series[i] if i < len(ch_series) else 0
            cap = cap_series[i] if i < len(cap_series) else 0
            a = a_series[i] if i < len(a_series) else 0
            if b + c + cap + a > 0:
                lines.append(f"{ts:<25} {b:>8,} {c:>10,} {cap:>8,} {a:>8,} {b+c+cap:>10,}")
                shown += 1
        if shown == 0:
            lines.append("  (all zeros)")

    lines.append("")
    lines.append("→ For IP/URI details on a specific rule, use run_logs_query(query_type='top_ips_by_volume', start_time='<peak_time>', duration_minutes=60)")
    return "\n".join(lines)


def _attack_types(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region=""):
    period = _calc_period(minutes)
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "attacks", "Expression": f"SEARCH('{{AWS/WAFV2,Attack,WebACL}} WebACL=\"{webacl_name}\"', 'Sum', {period})"},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    # Collect per-type time-series
    type_series = {}  # {attack_type: {timestamps: [], values: []}}
    for r in resp.get("MetricDataResults", []):
        label = r.get("Label", "")
        parts = label.split(" ")
        atype = parts[0] if parts else label
        values = [int(v) for v in r.get("Values", [])]
        timestamps = _to_local_ts(r.get("Timestamps", []))
        if sum(values) > 0:
            type_series[atype] = {"timestamps": timestamps, "values": values, "total": sum(values)}

    sorted_types = sorted(type_series.items(), key=lambda x: x[1]["total"], reverse=True)
    lines = [f"Attack Types (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    for atype, data in sorted_types:
        lines.append(f"  {atype:<25} {data['total']:>10,}")
    if not sorted_types:
        if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):
            lines.append("  ⚠️ PARTIAL DATA: Attack-type breakdown unavailable (CloudWatch only retains per-type index for 14 days).")
            lines.append("  ACTION: Tell the user that per-attack-type details are unavailable for this time range, but total mitigated count is available. Then call top_rules to show the totals, and offer to query logs for IP/URI-level details.")
        else:
            lines.append("  No attack data in this period.")
        return "\n".join(lines)

    # Time-series for top attack type
    if sorted_types:
        top_type, top_data = sorted_types[0]
        ts = top_data["timestamps"]
        vals = top_data["values"]
        if len(ts) > 1:
            lines.append(f"\nTime-series for '{top_type}' ({period//60}min granularity):")
            lines.append(f"{'Time':<25} {'Count':>8}")
            for i, t in enumerate(ts):
                if vals[i] > 0:
                    lines.append(f"{t:<25} {vals[i]:>8,}")

    return "\n".join(lines)


def _bot_summary(cw, webacl_name, start, end, minutes):
    period = _calc_period(minutes)
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
    resp = cw.get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    # Collect totals and time-series
    series = {}
    totals = {}
    for r in resp.get("MetricDataResults", []):
        rid = r["Id"]
        values = [int(v) for v in r.get("Values", [])]
        timestamps = _to_local_ts(r.get("Timestamps", []))
        totals[rid] = sum(values)
        series[rid] = {"timestamps": timestamps, "values": values}

    v_a = totals.get("v_a", 0)
    u_a = totals.get("u_a", 0)
    u_b = totals.get("u_b", 0)
    u_ch = totals.get("u_ch", 0)
    u_cap = totals.get("u_cap", 0)
    u_mit = u_b + u_ch + u_cap

    lines = [f"Bot Summary (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    lines.append(f"  ✅ Verified (self-declared):     {v_a:>10,} allowed")
    lines.append(f"  ⚠️ Unverified allowed:           {u_a:>10,}")
    lines.append(f"  🚫 Unverified mitigated:         {u_mit:>10,} (blocked {u_b:,} + challenge {u_ch:,} + captcha {u_cap:,})")
    if v_a + u_a + u_mit == 0:
        lines.append("  No bot data — Bot Control may not be deployed.")

    # Time-series: unverified allowed (most actionable — bots getting through)
    ua_series = series.get("u_a", {})
    ts = ua_series.get("timestamps", [])
    vals = ua_series.get("values", [])
    if ts and len(ts) > 1 and u_a > 0:
        lines.append(f"\nUnverified-allowed time-series ({period//60}min granularity):")
        lines.append(f"{'Time':<25} {'Count':>8}")
        for i, t in enumerate(ts):
            if vals[i] > 0:
                lines.append(f"{t:<25} {vals[i]:>8,}")

    lines.append("")
    lines.append("→ For bot name breakdown: get_waf_overview(query_type='bot_names')")
    return "\n".join(lines)


def _bot_names(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region=""):
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "names", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:bot:name\"', 'Sum', {_calc_period(minutes)})"},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    bots = {}
    for r in resp.get("MetricDataResults", []):
        label = r.get("Label", "")
        parts = label.split(" ")
        name = parts[0] if len(parts) >= 3 else label
        val = int(sum(r.get("Values", [])))
        if val > 0:
            bots[name] = bots.get(name, 0) + val

    sorted_bots = sorted(bots.items(), key=lambda x: x[1], reverse=True)
    lines = [f"Bot Names (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    for name, count in sorted_bots[:15]:
        lines.append(f"  {name:<30} {count:>10,}")
    if not sorted_bots:
        if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):
            lines.append("  ⚠️ PARTIAL DATA: Bot name breakdown unavailable (CloudWatch only retains per-bot index for 14 days).")
            lines.append("  ACTION: Tell the user that per-bot-name details are unavailable for this time range, but bot totals are available. Then call bot_summary to show verified/unverified counts, and offer to query logs for bot identification.")
        else:
            lines.append("  No bot name data — Bot Control may not be deployed, or no bot traffic in this period.")
    lines.append("")
    lines.append("→ For IP-level analysis of a specific bot, use run_logs_query(query_type='label_top_ips', label='bot:name:<name>', start_time='...')")
    return "\n".join(lines)


def _targeted_signals(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region=""):
    period = _calc_period(minutes)
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "ctrl", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control\"', 'Sum', {period})"},
        {"Id": "sig", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal\"', 'Sum', {period})"},
        {"Id": "csp", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal:cloud_service_provider\"', 'Sum', {period})"},
        {"Id": "vol", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:ip\"', 'Sum', {period})"},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

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
    lines = [f"Targeted Bot Signals (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    lines.append(f"{'Signal':<35} {'Blocked':>8} {'Challenge':>10} {'Captcha':>8} {'NotBlocked':>10}")
    lines.append("-" * 75)
    for name, metrics in sorted_sigs:
        b = metrics.get("BlockedRequests", 0) + metrics.get("BlockRuleMatch", 0)
        ch = metrics.get("ChallengeRequests", 0) + metrics.get("ChallengeRuleMatch", 0)
        cap = metrics.get("CaptchaRequests", 0) + metrics.get("CaptchaRuleMatch", 0)
        a = metrics.get("AllowedRequests", 0)
        lines.append(f"{name:<35} {b:>8,} {ch:>10,} {cap:>8,} {a:>10,}")
    if not sorted_sigs:
        if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):
            lines.append("  ⚠️ PARTIAL DATA: Targeted bot signal breakdown unavailable (CloudWatch only retains per-signal index for 14 days).")
            lines.append("  ACTION: Tell the user that per-signal details are unavailable for this time range. Then call top_rules to show totals, and offer to query logs.")
        else:
            lines.append("  No targeted bot signals — Targeted Bot Control may not be deployed, or no activity in this period.")
    lines.append("")
    lines.append("→ For IP details on challenged traffic, use run_logs_query(query_type='ip_cross_query', start_time='...')")
    return "\n".join(lines)


def _rate_limits(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region=""):
    from tools.waf_patrol import _get_all_rules_metrics_search
    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=_calc_period(minutes), scope=scope, region=region)

    # Get rate-based rule names from WebACL config
    rate_rule_names = set()
    try:
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

    period = _calc_period(minutes)
    lines = [f"Rate-Limit Rules (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    found = False
    for rule, metrics in sorted(data.items(), key=lambda x: sum(x[1].get("blocked", [])), reverse=True):
        if rule == "ALL":
            continue
        blocked_series = metrics.get("blocked", [])
        challenge_series = metrics.get("challenge", [])
        timestamps = metrics.get("timestamps", [])
        blocked = sum(blocked_series)
        challenged = sum(challenge_series)
        total = blocked + challenged
        if rule in rate_rule_names and total > 0:
            lines.append(f"  {rule}: {total:,} mitigated (blocked {blocked:,} + challenge {challenged:,})")
            # Time-series
            if timestamps and len(timestamps) > 1:
                lines.append(f"    Time-series ({period//60}min):")
                for i, ts in enumerate(timestamps):
                    b = blocked_series[i] if i < len(blocked_series) else 0
                    c = challenge_series[i] if i < len(challenge_series) else 0
                    if b + c > 0:
                        lines.append(f"    {ts}  {b + c:,}")
            found = True
    if not found:
        if rate_rule_names:
            lines.append("  Rate-limit rules deployed but no triggers in this period.")
        else:
            lines.append("  No rate-limit rules detected in WebACL config.")
    return "\n".join(lines)


def _challenge_solve_rate(cw, webacl_name, scope, region, start, end, minutes):
    from tools.waf_patrol import _get_challenge_solved, _get_all_rules_metrics_search
    period = _calc_period(minutes)
    cs, cas = _get_challenge_solved(cw, webacl_name, scope, region, start, end)
    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope, region=region)
    all_data = data.get("ALL", {})
    ch_series = all_data.get("challenge", [])
    cap_series = all_data.get("captcha", [])
    timestamps = all_data.get("timestamps", [])
    tot_ch = sum(ch_series)
    tot_cap = sum(cap_series)

    lines = [f"Challenge/CAPTCHA Solve Rate (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
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

    # Time-series: challenge issued per period
    if timestamps and len(timestamps) > 1 and tot_ch > 0:
        lines.append(f"\nChallenge issued time-series ({period//60}min granularity):")
        lines.append(f"{'Time':<25} {'Issued':>8}")
        for i, ts in enumerate(timestamps):
            v = ch_series[i] if i < len(ch_series) else 0
            if v > 0:
                lines.append(f"{ts:<25} {v:>8,}")

    return "\n".join(lines)


def _top_labels(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region=""):
    """Get all labels with hit counts — useful for identifying which managed rules/features are active."""
    period = _calc_period(minutes)
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "labels", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\"', 'Sum', {period})"},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    label_counts = []
    for r in resp.get("MetricDataResults", []):
        raw_label = r.get("Label", "")
        total = sum(int(v) for v in r.get("Values", []))
        if total > 0:
            # Label format from SEARCH: "{LabelName} {LabelNamespace} {MetricName}"
            parts = raw_label.split(" ")
            if len(parts) >= 2:
                label = f"{parts[1]}:{parts[0]}"  # e.g. "awswaf:managed:aws:anti-ddos:event-detected"
            else:
                label = raw_label
            label_counts.append((total, label))

    label_counts.sort(reverse=True)
    lines = [f"Top Labels (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    lines.append(f"{'Label':<70} {'Count':>10}")
    lines.append("-" * 82)
    for count, label in label_counts[:30]:
        lines.append(f"{label:<70} {count:>10,}")

    if not label_counts:
        if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region):
            lines.append("  ⚠️ PARTIAL DATA: Label breakdown unavailable (CloudWatch only retains per-label index for 14 days).")
            lines.append("  ACTION: Tell the user that per-label details are unavailable for this time range, but mitigated traffic exists. Then call top_rules to show totals, and offer run_logs_query(query_type='ip_label_breakdown') for per-request labels.")
        else:
            lines.append("  No label metrics found. Labels are only emitted by managed rule groups (Bot Control, Anti-DDoS AMR, etc.).")

    lines.append("")
    lines.append("Key namespaces: awswaf:managed:aws:anti-ddos: (DDoS), awswaf:managed:aws:bot-control: (Bot), awswaf:managed:token: (Token)")
    return "\n".join(lines)
