# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Overview tool — fast metrics-based answers for common questions."""

import sys
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import declare_query_subject, get_scope, get_user_timezone


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
            CloudWatch keeps coarser points for older data: at least 5-min past 15 days, 1-hour past
            63, nothing past 455. A window that is not whole points is widened, and the output says
            which window it covers.
            Zoom in to shorter windows for finer granularity.
        start_time: Optional start time (e.g. "2026-05-09" or "2026-05-09T14:00").
            If provided, queries from start_time to start_time + minutes.
            If omitted, queries from (now - minutes) to now.
        scope: "CLOUDFRONT" or "REGIONAL". Auto-detected from session if empty.

    Returns:
        Formatted overview data with time-series. For deeper analysis of specific IPs/URIs,
        use run_logs_query with start_time.
    """
    declare_query_subject(webacl_name)
    _log(f"query_type={query_type} webacl={webacl_name} minutes={minutes} start_time={start_time}")
    if not scope:
        scope = get_scope() or "CLOUDFRONT"
    from tools.session_state import resolve_region, refuse_if_regional
    if (msg := refuse_if_regional(scope)):
        return msg
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
        acl = next((a for a in acls if a["Name"] == webacl_name), None)
        if acl is None:
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
    from tools.waf_metrics import _period_for_window
    if _period_for_window(int(start.timestamp())) is None:
        return (f"No metrics for {webacl_name} in this window: CloudWatch keeps WAF metrics for 455 "
                "days, and this window starts before that. Query the logs for it instead.")

    # The window sent is the one CloudWatch will answer, and the reader is told when it differs.
    # For top_rules the earlier window is the older one, so it sets the step for both. Moving the
    # window makes its oldest point older, which can cross a retention line and need a coarser
    # step, so this repeats until the step holds; it can only grow, so it stops.
    asked_start, asked_end = start, end
    oldest = lambda s, e: s - (e - s) if query_type == "top_rules" else s
    unit = _calc_period(minutes, oldest(start, end))
    while True:
        start, end = _whole_points(asked_start, asked_end, unit, oldest(start, end))
        if _calc_period(minutes, oldest(start, end)) == unit:
            break
        unit = _calc_period(minutes, oldest(start, end))
    prev_start = start - (end - start)
    note = _window_note(asked_start, asked_end, start, end, unit)

    # Every configured rule is read directly, because SEARCH discovers only metrics with data in
    # the last 14 days counted from now. None, with the reason, when the read failed.
    rules, rules_error = None, ""
    if query_type in ("top_rules", "rate_limits"):
        try:
            rules = waf.get_web_acl(Name=webacl_name, Scope=waf_scope, Id=acl["Id"])["WebACL"].get("Rules", [])
        except Exception as e:
            rules_error = f"{type(e).__name__}: {e}"

    if query_type == "top_rules":
        out = _top_rules(cw, webacl_name, start, end, prev_start, minutes, scope, region, rules, rules_error, unit)
    elif query_type == "attack_types":
        out = _attack_types(cw, webacl_name, start, end, minutes, scope, region, unit)
    elif query_type == "bot_summary":
        out = _bot_summary(cw, webacl_name, start, end, minutes, unit)
    elif query_type == "bot_names":
        out = _bot_names(cw, webacl_name, start, end, minutes, scope, region, unit)
    elif query_type == "targeted_signals":
        out = _targeted_signals(cw, webacl_name, start, end, minutes, scope, region, unit)
    elif query_type == "rate_limits":
        out = _rate_limits(cw, webacl_name, start, end, minutes, scope, region, rules, rules_error, unit)
    elif query_type == "challenge_solve_rate":
        out = _challenge_solve_rate(cw, webacl_name, scope, region, start, end, minutes, unit)
    elif query_type == "top_labels":
        out = _top_labels(cw, webacl_name, start, end, minutes, scope, region, unit)
    else:
        return f"Error: unknown query_type '{query_type}'. Available: top_rules, attack_types, bot_summary, bot_names, targeted_signals, rate_limits, challenge_solve_rate, top_labels"
    return out + note


def _whole_points(start, end, period: int, oldest):
    """The window CloudWatch answers in whole `period` points, as (start, end).

    **The first point is StartTime rounded down to the resolution CloudWatch still keeps**, a
    minute for 15 days, five minutes to 63 and an hour after, and points follow every `period` for
    as long as they start before EndTime. Measured 2026-10-16 on `response-id-on-page`, StartTime
    hh:07:17: points began at 01:07 at 2 and 10 days old with periods of 900, 3600 and 14400, at
    01:05 at 37 days with 900, 3600 and 14400, and at 01:00 at 70 and 97 days with 3600 and 14400.
    So a window that is not whole points from there reads more than it names, and the window sent
    is this one. `oldest` is the oldest point any read of the call asks for: rounding to its
    resolution rounds to every finer one too.
    """
    from tools.waf_metrics import _period_for_window
    step = _period_for_window(int(oldest.timestamp())) or 3600
    start = start - timedelta(seconds=int(start.timestamp()) % step, microseconds=start.microsecond)
    points = -(-int((end - start).total_seconds()) // period)
    return start, start + timedelta(seconds=points * period)


def _window_note(asked_start, asked_end, start, end, period: int) -> str:
    """A line saying which window the figures cover, when it is not the one asked for. A window
    ending at now that runs past it reads nothing more, so that alone is not a difference."""
    read_end = min(end, datetime.now(timezone.utc))
    if abs((start - asked_start).total_seconds()) < 60 and abs((read_end - asked_end).total_seconds()) < 60:
        return ""
    tz_offset = get_user_timezone()
    tz = timezone(timedelta(hours=tz_offset)) if tz_offset is not None else timezone.utc
    fmt = lambda t: t.astimezone(tz).strftime("%Y-%m-%d %H:%M")
    return (f"\n\nNote: CloudWatch answers this window in whole {period // 60}-minute points, so every figure "
            f"above covers {fmt(start)} to {fmt(read_end)}, not the requested {fmt(asked_start)} to "
            f"{fmt(asked_end)}.")


def _calc_period(minutes: int, start) -> int:
    """Calculate CloudWatch period for the given time window.

    Returns period in seconds:
    - ≤60min  → 60s   (1-min, up to 60 points)
    - ≤360min → 300s  (5-min, up to 72 points)
    - ≤4320min→ 900s  (15-min, up to 288 points)
    - ≤10080min→3600s (1-hour, up to 168 points)
    - >10080min→14400s(4-hour)

    **Never finer than CloudWatch still keeps for `start`.** One-minute points last 15 days and
    five-minute points 63. Measured 2026-10-15, a 60-minute window 37 days old: `Period=60` answered
    `StatusCode: Complete` with 60 zeros, and 300 and 3600 both answered 1,923. Every larger choice
    here is a multiple of the retained period it replaces, so taking the larger is always valid.
    """
    from tools.waf_metrics import _period_for_window
    if minutes <= 60:
        period = 60
    elif minutes <= 360:
        period = 300
    elif minutes <= 4320:
        period = 900
    elif minutes <= 10080:
        period = 3600
    else:
        period = 14400
    return max(period, _period_for_window(int(start.timestamp())) or 3600)


def _fmt_window(minutes: int) -> str:
    """Format time window for display."""
    if minutes < 60:
        return f"{minutes}min"
    elif minutes % 60 == 0:
        return f"{minutes // 60}h"
    else:
        return f"{minutes}min"


def _has_mitigated_traffic(cw, webacl_name, start, end, scope="CLOUDFRONT", region="") -> bool:
    """Direct MetricStat check, immune to SEARCH's 14-day discovery window: did the WebACL block,
    challenge or CAPTCHA anything in the window? Raises when the check could not be made.

    **The period is the finest CloudWatch still keeps, and the points are summed.** It was the
    window's length in seconds. A window clipped at now is not a whole number of minutes, and
    measured 2026-10-15 that is a `ValidationError`, which an `except` here returned as False, so
    every clipped window read as "no activity". A period longer than the window reads past its end
    (a 30-minute window at `Period=3600` answered the whole hour), so rounding up is not the fix.
    """
    from tools.waf_metrics import _period_for_window
    _dims = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    if scope == "REGIONAL" and region:
        _dims.append({"Name": "Region", "Value": region})
    period = _period_for_window(int(start.timestamp())) or 3600
    resp = cw.get_metric_data(
        MetricDataQueries=[
            {"Id": f"m{i}", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": name, "Dimensions": _dims}, "Period": period, "Stat": "Sum"}}
            for i, name in enumerate(("BlockedRequests", "ChallengeRequests", "CaptchaRequests"))
        ],
        StartTime=start, EndTime=end,
    )
    return sum(int(v) for r in resp.get("MetricDataResults", []) for v in r.get("Values", [])) > 0


def _explain_empty(cw, webacl_name, start, end, scope, region, partial: list, none: str) -> list:
    """The lines for a SEARCH breakdown that came back empty: `partial` when the WebACL did
    mitigate traffic in the window, `none` when it did not, and neither when the check failed."""
    try:
        return partial if _has_mitigated_traffic(cw, webacl_name, start, end, scope, region) else [none]
    except Exception as e:
        return [f"  ⚠️ The breakdown is empty, and the direct metric check that tells an unindexed "
                f"breakdown from no activity failed ({type(e).__name__}: {e}). Do not read this as no "
                f"activity; retry, or query the logs for this window."]


def _top_rules(cw, webacl_name, start, end, prev_start, minutes, scope="CLOUDFRONT", region="",
               rules=None, rules_error="", period=None):
    from tools.waf_metrics import _period_for_window
    from tools.waf_patrol import _get_all_rules_metrics_search
    period = period or _calc_period(minutes, prev_start)
    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope,
                                              region=region, rules=rules)
    # The earlier window is older, so it can need a coarser period; past 455 days it has none.
    last_week = None
    if _period_for_window(int(prev_start.timestamp())):
        last_week = _get_all_rules_metrics_search(cw, webacl_name, prev_start, start, period=period,
                                                  scope=scope, region=region, rules=rules)

    # **Whether the denominator is exact is now load-bearing, so it is tracked.** ROADMAP 4.2 puts
    # a hit rate in this table, and the rate's denominator is this Rule=ALL total. The `except:
    # pass` below falls back to the SEARCH-derived ALL, which is subject to the same 14-day index
    # expiry this MetricStat call exists to avoid, so a rate computed on it could be wrong with
    # nothing saying so. The column is omitted rather than guessed when this stays False.
    denom_exact = False
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
        denom_exact = True
    except Exception:
        pass  # Fall back to SEARCH-derived ALL

    # **The verified hit-rate denominator, ROADMAP 4.2.** The four mutually exclusive terminal
    # outcomes at Rule=ALL, and only those. `PassedRequests` is a per-rule-group metric that reads
    # 0 here and double-counts a request already in `AllowedRequests`; `CountedRequests` is
    # non-terminal, so a counted request also ends in Allowed or Blocked and adding it inflates the
    # denominator. Both exclusions were verified live, see the roadmap.
    _all = this_week.get("ALL", {})
    denom = (sum(_all.get("allowed", [])) + sum(_all.get("blocked", []))
             + sum(_all.get("challenge", [])) + sum(_all.get("captcha", [])))

    def _rate(matched: int) -> str:
        """A rule's share of evaluated requests, or why there is no share.

        **`<0.01%` rather than `0.00%` for a small nonzero rate.** Rounding a real match down to a
        printed zero is the same defect as every other false zero in this project: the output a
        genuine zero would produce. Measured on the live WebACL, the IP-reputation list ran at
        10/45513, which is 0.022%, and a rule an order of magnitude quieter would print 0.00%.

        The denominator here is the one `tests/test_hit_rate.py` pins, so the two agree. This said
        45515 first, which was also a real measurement: the two live runs were minutes apart and
        `allowed` moved by two. Both numbers were true and one of them drifted anyway, which is why
        the figure is quoted once and the test owns it."""
        if not denom:
            return "-"
        pct = matched * 100 / denom
        if 0 < pct < 0.01:
            return "<0.01%"
        return f"{pct:.2f}%"

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
        lw = (last_week or {}).get(rule, {})
        lw_mit = sum(lw.get("blocked", [])) + sum(lw.get("challenge", [])) + sum(lw.get("captcha", []))
        wow = "n/a" if last_week is None else f"{mitigated/lw_mit:.1f}x" if lw_mit > 0 else "new"
        # A rule takes ONE action per request, so its four buckets are disjoint and summing them
        # is the rule's match count. `counted` belongs in the numerator even though it is excluded
        # from the denominator: a counted request was still evaluated, and it reaches the
        # denominator through whichever terminal action it ended in.
        rows.append((mitigated, rule, blocked, challenged, captcha, counted, wow,
                     _rate(mitigated + counted)))

    rows.sort(reverse=True)
    from tools.waf_metrics import summed_sub_rules
    summed, repeated = summed_sub_rules(cw, webacl_name, rules or [], scope, region)
    lines = [f"Top Rules (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    _hdr = f"{'Rule':<40} {'Blocked':>8} {'Challenge':>10} {'Captcha':>8} {'Counted':>8} {'Change':>7}"
    lines.append(_hdr + (f" {'Hit rate':>9}" if denom_exact else ""))
    lines.append("-" * (95 if denom_exact else 85))
    for _, rule, b, ch, cap, cnt, wow, rate in rows[:15]:
        rule = rule + "*" if rule in summed else rule
        row = f"{rule:<40} {b:>8,} {ch:>10,} {cap:>8,} {cnt:>8,} {wow:>7}"
        lines.append(row + (f" {rate:>9}" if denom_exact else ""))

    # Totals
    all_data = this_week.get("ALL", {})
    tot_b = sum(all_data.get("blocked", []))
    tot_ch = sum(all_data.get("challenge", []))
    tot_cap = sum(all_data.get("captcha", []))
    tot_a = sum(all_data.get("allowed", []))

    if tot_b + tot_ch + tot_cap + tot_a == 0 and not rows:
        return f"No metrics data for {webacl_name} in this time window (start_time + {_fmt_window(minutes)}). Verify the WebACL name and time range."

    lines.append("-" * (95 if denom_exact else 85))
    if any(r[1] in summed for r in rows[:15]):
        lines.append(repeated)
    if rules is None:
        lines.append(f"⚠️ The WebACL configuration could not be read ({rules_error}), so the rules above "
                     "are only those CloudWatch SEARCH discovered, and SEARCH misses any rule with no "
                     "data in the last 14 days.")
    lines.append(f"Total: mitigated {tot_b + tot_ch + tot_cap:,} (blocked {tot_b:,} + challenge {tot_ch:,} + captcha {tot_cap:,}) | allowed {tot_a:,}")
    # The denominator is printed so the rate can be checked rather than taken on faith, and its
    # absence is given a REASON rather than leaving a column quietly missing.
    if denom_exact:
        lines.append(f"Hit rate = a rule's matches (blocked + challenge + captcha + counted) "
                     f"as a share of {denom:,} evaluated requests. Counted requests are in the "
                     f"numerator but not the denominator: a counted request is still evaluated "
                     f"and reaches the denominator through the action that terminated it.")
    else:
        lines.append("Hit rate omitted: the Rule=ALL totals came from the metric SEARCH fallback "
                     "rather than a direct query, and that source is subject to a 14-day index "
                     "expiry, so the denominator may be understated. The per-rule counts above "
                     "are unaffected.")

    # Gap detection: warn if visible rules don't account for most mitigated traffic
    total_mitigated = tot_b + tot_ch + tot_cap
    visible_mitigated = sum(r[0] for r in rows[:15])
    if total_mitigated > 0 and visible_mitigated < total_mitigated * 0.5:
        gap = total_mitigated - visible_mitigated
        lines.append(f"\n⚠️ {gap:,} mitigated requests ({gap*100//total_mitigated}%) not attributed to visible rules. Likely causes: managed rule group sub-rules that don't publish their own per-rule metric (e.g., AMR ChallengeAllDuringEvent), or a managed sub-rule whose metric CloudWatch's SEARCH-based discovery has not indexed in the last 14 days (rules in the WebACL's configuration are read directly). Use ip_cross_query on top IPs to identify the actual terminating rule.")

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


def _attack_types(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region="", period=None):
    period = period or _calc_period(minutes, start)
    from tools.waf_metrics import search_label
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "attacks", "Expression": f"SEARCH('{{AWS/WAFV2,Attack,WebACL}} WebACL=\"{webacl_name}\" MetricName=(\"BlockedRequests\" OR \"ChallengeRequests\" OR \"CaptchaRequests\")', 'Sum', {period})",
         "Label": search_label("Attack")},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    # Per-type time-series, summed across the three mitigating actions
    points = {}  # {attack_type: {timestamp: value}}
    for r in resp.get("MetricDataResults", []):
        atype = r.get("Label", "").split("|")[0]
        for ts, v in zip(_to_local_ts(r.get("Timestamps", [])), r.get("Values", [])):
            points.setdefault(atype, {})[ts] = points.get(atype, {}).get(ts, 0) + int(v)
    type_series = {}  # {attack_type: {timestamps: [], values: []}}
    for atype, by_ts in points.items():
        if sum(by_ts.values()) > 0:
            ts = sorted(by_ts)
            type_series[atype] = {"timestamps": ts, "values": [by_ts[t] for t in ts], "total": sum(by_ts.values())}

    sorted_types = sorted(type_series.items(), key=lambda x: x[1]["total"], reverse=True)
    lines = [f"Attack Types (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    for atype, data in sorted_types:
        lines.append(f"  {atype:<25} {data['total']:>10,}")
    if not sorted_types:
        lines += _explain_empty(cw, webacl_name, start, end, scope, region, [
            "  ⚠️ PARTIAL DATA: Attack-type breakdown unavailable (CloudWatch only retains per-type index for 14 days).",
            "  ACTION: Tell the user that per-attack-type details are unavailable for this time range, but total mitigated count is available. Then call top_rules to show the totals, and offer to query logs for IP/URI-level details."],
            "  No attack data in this period.")
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


def _bot_summary(cw, webacl_name, start, end, minutes, period=None):
    period = period or _calc_period(minutes, start)
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


def _bot_names(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region="", period=None):
    from tools.waf_metrics import REQUEST_METRIC_FILTER, search_label
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "names", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:bot:name\" {REQUEST_METRIC_FILTER}', 'Sum', {period or _calc_period(minutes, start)})",
         "Label": search_label("LabelName")},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    bots = {}
    for r in resp.get("MetricDataResults", []):
        name = r.get("Label", "").partition("|")[0]
        val = int(sum(r.get("Values", [])))
        if val > 0:
            bots[name] = bots.get(name, 0) + val

    sorted_bots = sorted(bots.items(), key=lambda x: x[1], reverse=True)
    lines = [f"Bot Names (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    for name, count in sorted_bots[:15]:
        lines.append(f"  {name:<30} {count:>10,}")
    if not sorted_bots:
        lines += _explain_empty(cw, webacl_name, start, end, scope, region, [
            "  ⚠️ PARTIAL DATA: Bot name breakdown unavailable (CloudWatch only retains per-bot index for 14 days).",
            "  ACTION: Tell the user that per-bot-name details are unavailable for this time range, but bot totals are available. Then call bot_summary to show verified/unverified counts, and offer to query logs for bot identification."],
            "  No bot name data — Bot Control may not be deployed, or no bot traffic in this period.")
    lines.append("")
    lines.append("→ For IP-level analysis of a specific bot, use run_logs_query(query_type='label_top_ips', label='bot:name:<name>', start_time='...')")
    return "\n".join(lines)


def _targeted_signals(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region="", period=None):
    from tools.waf_metrics import REQUEST_METRICS, search_label
    period = period or _calc_period(minutes, start)
    label = search_label("LabelNamespace", "LabelName")
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "ctrl", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control\"', 'Sum', {period})",
         "Label": label},
        {"Id": "sig", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal\"', 'Sum', {period})",
         "Label": label},
        {"Id": "csp", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal:cloud_service_provider\"', 'Sum', {period})",
         "Label": label},
        {"Id": "vol", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:ip\"', 'Sum', {period})",
         "Label": label},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    signals = {}
    for r in resp.get("MetricDataResults", []):
        parts = r.get("Label", "").split("|")
        if len(parts) != 3 or parts[2] not in REQUEST_METRICS:
            continue
        namespace, name, metric = parts
        # Filter: only TGT_*, Signal*, CSP names
        if name.endswith("Low") or name == "TGT_TokenAbsent":
            continue
        if not (name.startswith("TGT_") or name.startswith("Signal") or name in ("token_absent", "non_browser_user_agent") or "cloud_service_provider" in namespace):
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
        b = metrics.get("BlockedRequests", 0)
        ch = metrics.get("ChallengeRequests", 0)
        cap = metrics.get("CaptchaRequests", 0)
        a = metrics.get("AllowedRequests", 0)
        lines.append(f"{name:<35} {b:>8,} {ch:>10,} {cap:>8,} {a:>10,}")
    if not sorted_sigs:
        lines += _explain_empty(cw, webacl_name, start, end, scope, region, [
            "  ⚠️ PARTIAL DATA: Targeted bot signal breakdown unavailable (CloudWatch only retains per-signal index for 14 days).",
            "  ACTION: Tell the user that per-signal details are unavailable for this time range. Then call top_rules to show totals, and offer to query logs."],
            "  No targeted bot signals — Targeted Bot Control may not be deployed, or no activity in this period.")
    lines.append("")
    lines.append("→ For IP details on challenged traffic, use run_logs_query(query_type='ip_cross_query', start_time='...')")
    return "\n".join(lines)


def _rate_limits(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region="", rules=None, rules_error="",
                 period=None):
    """Each rate-based rule's matches, read by its `VisibilityConfig.MetricName`, which is the
    metric's dimension and need not equal the rule's name. Every action counts: a rate rule can
    block, challenge, CAPTCHA or only count."""
    from tools.waf_patrol import _get_all_rules_metrics_search
    lines = [f"Rate-Limit Rules (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    if rules is None:
        lines.append(f"  ⚠️ The WebACL configuration could not be read ({rules_error}), so which rules "
                     "are rate-based is unknown. Do not read this as no rate-limit rules.")
        return "\n".join(lines)
    rate = [r for r in rules if "RateBasedStatement" in (r.get("Statement") or {})]
    if not rate:
        lines.append("  No rate-limit rules detected in WebACL config.")
        return "\n".join(lines)
    lit = {(r.get("VisibilityConfig") or {}).get("MetricName") or r["Name"]: r["Name"] for r in rate
           if (r.get("VisibilityConfig") or {}).get("CloudWatchMetricsEnabled", True)}
    dark = [r["Name"] for r in rate if r["Name"] not in lit.values()]
    period = period or _calc_period(minutes, start)
    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope,
                                         region=region, rules=rate)

    found = False
    keys = ("blocked", "challenge", "captcha", "counted")
    for metric, name in sorted(lit.items(), key=lambda x: -sum(sum(data.get(x[0], {}).get(k, [])) for k in keys)):
        series = data.get(metric, {})
        b, ch, cap, cnt = (sum(series.get(k, [])) for k in keys)
        if b + ch + cap + cnt == 0:
            continue
        found = True
        lines.append(f"  {name}: {b + ch + cap + cnt:,} matched (blocked {b:,} + challenge {ch:,} + "
                     f"captcha {cap:,} + counted {cnt:,})")
        timestamps = series.get("timestamps", [])
        if len(timestamps) > 1:
            lines.append(f"    Time-series ({period//60}min):")
            for i, ts in enumerate(timestamps):
                v = sum(series.get(k, [0] * len(timestamps))[i] for k in keys)
                if v > 0:
                    lines.append(f"    {ts}  {v:,}")
    if not found and lit:
        lines.append("  Rate-limit rules deployed but no triggers in this period.")
    if dark:
        lines.append(f"  ⚠️ {', '.join(dark)}: CloudWatch metrics are disabled on this rule, so its "
                     "triggers cannot be read from metrics. Query the logs for it.")
    return "\n".join(lines)


def _challenge_solve_rate(cw, webacl_name, scope, region, start, end, minutes, period=None):
    from tools.waf_patrol import _get_challenge_solved, _get_all_rules_metrics_search
    period = period or _calc_period(minutes, start)
    try:
        cs, cas = _get_challenge_solved(cw, webacl_name, scope, region, start, end)
        solved_error = ""
    except Exception as e:
        cs = cas = None
        solved_error = f"{type(e).__name__}: {e}"
    # `rules=[]` still reads `ALL` directly, which is the only series used here.
    data = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=period, scope=scope, region=region, rules=[])
    all_data = data.get("ALL", {})
    ch_series = all_data.get("challenge", [])
    cap_series = all_data.get("captcha", [])
    timestamps = all_data.get("timestamps", [])
    tot_ch = sum(ch_series)
    tot_cap = sum(cap_series)

    lines = [f"Challenge/CAPTCHA Solve Rate (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    lines.append(f"  Challenges issued:  {tot_ch:>10,}")
    if solved_error:
        lines.append(f"  Challenges solved:  {'unknown':>10}")
    else:
        lines.append(f"  Challenges solved:  {cs:>10,}" + (f"  ({cs*100//tot_ch}% solve rate)" if tot_ch > 0 else ""))
    lines.append(f"  CAPTCHAs issued:    {tot_cap:>10,}")
    if solved_error:
        lines.append(f"  CAPTCHAs solved:    {'unknown':>10}")
        lines.append(f"  ⚠️ The solved counts could not be read ({solved_error}), so no solve rate is given.")
    else:
        lines.append(f"  CAPTCHAs solved:    {cas:>10,}" + (f"  ({cas*100//tot_cap}% solve rate)" if tot_cap > 0 else ""))
    lines.append("")
    if tot_ch == 0 and tot_cap == 0:
        lines.append("  No challenges or CAPTCHAs issued in this period.")
    if tot_ch > 0 and not solved_error:  # none solved is the low-rate case, not a missing one
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


def _top_labels(cw, webacl_name, start, end, minutes, scope="CLOUDFRONT", region="", period=None):
    """Get all labels with hit counts — useful for identifying which managed rules/features are active."""
    from tools.waf_metrics import REQUEST_METRIC_FILTER, search_label
    period = period or _calc_period(minutes, start)
    resp = cw.get_metric_data(MetricDataQueries=[
        {"Id": "labels", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" {REQUEST_METRIC_FILTER}', 'Sum', {period})",
         "Label": search_label("LabelNamespace", "LabelName")},
    ], StartTime=start, EndTime=end, ScanBy="TimestampAscending")

    # One row per label: the requests that carried it, whatever their outcome. The search asks
    # for the request metrics only, so a rule-match series never arrives to be added.
    totals = {}
    for r in resp.get("MetricDataResults", []):
        parts = r.get("Label", "").split("|")
        if len(parts) == 3:
            label = f"{parts[0]}:{parts[1]}"  # e.g. "awswaf:managed:aws:anti-ddos:event-detected"
            totals[label] = totals.get(label, 0) + sum(int(v) for v in r.get("Values", []))
    label_counts = [(total, label) for label, total in totals.items() if total > 0]

    label_counts.sort(reverse=True)
    lines = [f"Top Labels (past {_fmt_window(minutes)}) for {webacl_name}:", ""]
    lines.append(f"{'Label':<70} {'Count':>10}")
    lines.append("-" * 82)
    for count, label in label_counts[:30]:
        lines.append(f"{label:<70} {count:>10,}")

    if not label_counts:
        lines += _explain_empty(cw, webacl_name, start, end, scope, region, [
            "  ⚠️ PARTIAL DATA: Label breakdown unavailable (CloudWatch only retains per-label index for 14 days).",
            "  ACTION: Tell the user that per-label details are unavailable for this time range, but mitigated traffic exists. Then call top_rules to show totals, and offer run_logs_query(query_type='ip_label_breakdown') for per-request labels."],
            "  No label metrics found. Labels are only emitted by managed rule groups (Bot Control, Anti-DDoS AMR, etc.).")

    lines.append("")
    lines.append("Key namespaces: awswaf:managed:aws:anti-ddos: (DDoS), awswaf:managed:aws:bot-control: (Bot), awswaf:managed:token: (Token)")
    return "\n".join(lines)
