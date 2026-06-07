# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Security patrol scan — comprehensive weekly security event summary."""

import json
import time
import concurrent.futures
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client

_latest_patrol_html: str | None = None

# i18n for patrol report
_PATROL_I18N = {
    "en": {
        "title": "Security Patrol Report",
        "period": "Period",
        "generated": "Generated",
        "delay_note": "CloudWatch Metrics delay: ~5 min. Data may have changed since generation.",
        "no_data_search": "⚠️ No data for this section. CloudWatch can only discover metrics that had activity in the last 14 days. Historical data may exist — generate a few matching requests to reactivate the metric index, then re-run.",
        "action_items": "Action Items",
        "no_action": "🟢 No action required",
        "detection_tools": "Detection Tools Status",
        "per_rule": "Per-Rule Breakdown",
        "rate_limit": "Rate-Limit Effectiveness",
        "attack_chart": "Threats Mitigated by Attack Type",
        "total_requests": "Total Requests",
        "mitigated": "Mitigated",
        "counted": "Counted",
        "not_blocked": "Not Blocked",
        "allowed": "Allowed",
        "blocked": "Blocked",
        "challenge": "Challenge",
        "captcha": "Captcha",
        "wow": "WoW",
        "rule": "Rule",
        "layer": "Layer",
        "mode": "Mode",
        "threshold": "Threshold",
        "total_blocked": "Total Blocked",
        "hours_active": "Hours Active",
        "status": "Status",
        "critical": "critical",
        "moderate": "moderate",
        "items_attention": "items need attention",
        "all_nominal": "All systems nominal — no action required",
        "bot_activity": "Bot Activity (Self-Declared)",
        "bot_verified": "✅ Verified",
        "bot_unverified_allowed": "⚠️ Unverified Allowed",
        "bot_unverified_mitigated": "🚫 Unverified Mitigated",
        "bot_targeted": "Targeted Bot Detection",
        "bot_category": "Bot Names",
    },
    "zh": {
        "title": "安全巡检报告",
        "period": "巡检周期",
        "generated": "生成时间",
        "delay_note": "CloudWatch 指标延迟约 5 分钟，数据可能在报告生成后有变化。",
        "no_data_search": "⚠️ 该部分无数据。CloudWatch 仅能自动发现最近 14 天内有活动的指标。如果近期没有此类流量，历史数据将无法自动发现。可尝试产生少量匹配流量以重新激活指标索引，然后重新生成报告。",
        "action_items": "待办事项",
        "no_action": "🟢 本周期无需操作",
        "detection_tools": "防护层状态",
        "per_rule": "规则明细",
        "rate_limit": "限速规则效果",
        "attack_chart": "按攻击类型拦截分布",
        "total_requests": "总请求量",
        "mitigated": "已拦截",
        "counted": "监控中",
        "not_blocked": "未拦截",
        "allowed": "放行",
        "blocked": "拦截",
        "challenge": "质询",
        "captcha": "验证码",
        "wow": "环比",
        "rule": "规则",
        "layer": "防护层",
        "mode": "模式",
        "threshold": "阈值",
        "total_blocked": "拦截总量",
        "hours_active": "触发时段",
        "status": "状态",
        "critical": "严重",
        "moderate": "注意",
        "items_attention": "项需要关注",
        "all_nominal": "所有系统正常，无需操作",
        "bot_activity": "Bot 活动（自声明）",
        "bot_verified": "✅ 已验证",
        "bot_unverified_allowed": "⚠️ 未验证放行",
        "bot_unverified_mitigated": "🚫 未验证拦截",
        "bot_targeted": "Targeted Bot 检测",
        "bot_category": "Bot 名称分布",
    },
}

# Thresholds for anomaly detection (v1 — absolute, used as cold-start fallback)
DAILY_BLOCK_ATTENTION = 500
DAILY_BLOCK_SEVERE = 5000
IP_CONCENTRATION_ATTENTION = 0.30
IP_CONCENTRATION_SEVERE = 0.60

# WoW anomaly detection thresholds (v2)
WOW_ATTENTION = 3.0   # 3x increase vs last week
WOW_SEVERE = 10.0     # 10x increase
SPIKE_RATIO_ATTENTION = 5.0  # max day / avg day


def _assess_rules_v2(this_week: dict, last_week: dict, detection_tools: list[dict], ddos_event_windows: list[tuple] | None = None, lang: str = "en") -> list[dict]:
    """Assess per-rule metrics with WoW comparison. Returns action_items list.

    Each item: {severity, rule, text, suggestion, context?}
    severity: "critical" | "moderate" | "low"
    ddos_event_windows: list of (start_idx, end_idx) tuples indicating DDoS event periods in daily data
    """
    action_items = []
    skip_rules = {"ALL", "shield-sample-webacl"}  # WebACL-level aggregates

    # --- From Detection Tools (config issues) ---
    for tool in detection_tools:
        if tool["status"] == "warning":
            action_items.append({
                "severity": "moderate",
                "rule": tool["rule_name"],
                "text": f"{tool['layer']} 处于 {tool['mode']} 模式" if lang == "zh" else f"{tool['layer']} in {tool['mode']} mode",
                "suggestion": "确认是否应切换为 Block" if lang == "zh" else "Confirm whether this should be switched to Block",
                "source": "config",
            })
        elif tool["status"] == "missing" and tool["layer"] != "Logging":
            action_items.append({
                "severity": "low",
                "rule": "—",
                "text": f"{tool['layer']} 未部署" if lang == "zh" else f"{tool['layer']} not deployed",
                "suggestion": "建议部署以增强防护" if lang == "zh" else "Consider deploying for additional protection",
                "source": "config",
            })
        elif tool["status"] == "missing" and tool["layer"] == "Logging":
            action_items.append({
                "severity": "moderate",
                "rule": "—",
                "text": "WAF 日志未配置" if lang == "zh" else "WAF logging not configured",
                "suggestion": "启用 CWL 日志以支持 IP 级分析" if lang == "zh" else "Enable CWL logging for IP-level analysis",
                "source": "config",
            })

    # --- From Per-Rule Metrics (WoW comparison) ---
    for rule_name, data in this_week.items():
        if rule_name in skip_rules:
            continue

        tw_blocked = sum(data.get("blocked", []))
        tw_counted = sum(data.get("counted", []))
        tw_challenge = sum(data.get("challenge", []))
        tw_captcha = sum(data.get("captcha", []))
        tw_mitigated = tw_blocked + tw_challenge + tw_captcha

        # Last week comparison
        lw_data = last_week.get(rule_name, {})
        lw_blocked = sum(lw_data.get("blocked", []))
        lw_challenge = sum(lw_data.get("challenge", []))
        lw_captcha = sum(lw_data.get("captcha", []))
        lw_mitigated = lw_blocked + lw_challenge + lw_captcha
        lw_counted = sum(lw_data.get("counted", []))

        # --- WoW change for mitigated (blocked + challenged) ---
        if tw_mitigated > 50:  # ignore noise
            if lw_mitigated == 0:
                # No baseline from previous period
                action_items.append({
                    "severity": "moderate",
                    "rule": rule_name,
                    "text": f"昨日无基线，本期拦截 {tw_mitigated:,} 次" if lang == "zh" else f"No baseline from previous period — {tw_mitigated:,} requests mitigated",
                    "suggestion": "确认是否为新攻击模式或新规则部署" if lang == "zh" else "Verify: new attack pattern or new rule deployment?",
                })
            elif lw_mitigated > 0:
                wow = tw_mitigated / lw_mitigated
                if wow >= WOW_SEVERE:
                    action_items.append({
                        "severity": "critical",
                        "rule": rule_name,
                        "text": f"拦截量环比暴增 {wow:.0f}x（{lw_mitigated:,} → {tw_mitigated:,}）" if lang == "zh" else f"Mitigated requests surged {wow:.0f}x vs previous period ({lw_mitigated:,} → {tw_mitigated:,})",
                        "suggestion": "需要调查——可能是新攻击活动" if lang == "zh" else "Investigate — possible new attack campaign",
                    })
                elif wow >= WOW_ATTENTION:
                    action_items.append({
                        "severity": "moderate",
                        "rule": rule_name,
                        "text": f"拦截量环比增长 {wow:.1f}x（{lw_mitigated:,} → {tw_mitigated:,}）" if lang == "zh" else f"Mitigated requests increased {wow:.1f}x vs previous period ({lw_mitigated:,} → {tw_mitigated:,})",
                        "suggestion": "持续观察趋势" if lang == "zh" else "Monitor — check if trend continues",
                    })

        # --- Spike detection (max day vs avg) ---
        blocked_daily = data.get("blocked", [])
        challenge_daily = data.get("challenge", [])
        captcha_daily = data.get("captcha", [])
        n = max(len(blocked_daily), len(challenge_daily), len(captcha_daily))
        blocked_daily += [0] * (n - len(blocked_daily))
        challenge_daily += [0] * (n - len(challenge_daily))
        captcha_daily += [0] * (n - len(captcha_daily))
        daily_mitigated = [b + c + p for b, c, p in zip(blocked_daily, challenge_daily, captcha_daily)]
        if daily_mitigated and len(daily_mitigated) > 1:
            avg_day = sum(daily_mitigated) / len(daily_mitigated)
            max_day = max(daily_mitigated)
            if avg_day > 0 and max_day / avg_day >= SPIKE_RATIO_ATTENTION and max_day > 100:
                # Find which day had the spike
                spike_idx = daily_mitigated.index(max_day)
                ts_list = data.get("timestamps", [])
                spike_date = ts_list[spike_idx][:10] if spike_idx < len(ts_list) else "unknown"
                # Don't duplicate if already flagged by WoW
                existing = [a for a in action_items if a["rule"] == rule_name and ("surge" in a.get("text", "") or "暴增" in a.get("text", ""))]
                if not existing:
                    action_items.append({
                        "severity": "moderate",
                        "rule": rule_name,
                        "text": f"检测到尖峰：峰值时段（{spike_date}）为均值的 {max_day/avg_day:.1f}x" if lang == "zh" else f"Spike detected: peak ({spike_date}) was {max_day/avg_day:.1f}x average",
                        "suggestion": "检查尖峰是否与特定事件相关" if lang == "zh" else "Check if spike correlates with a specific event",
                    })

        # --- Count rule went to zero ---
        if tw_counted == 0 and lw_counted > 100:
            action_items.append({
                "severity": "moderate",
                "rule": rule_name,
                "text": f"Count 规则停止触发（上期: {lw_counted:,}，本期: 0）" if lang == "zh" else f"Count rule stopped triggering (previous: {lw_counted:,}, current: 0)",
                "suggestion": "检查规则是否被删除、禁用或 scope-down 变更" if lang == "zh" else "Check if rule was deleted, disabled, or scope-down changed",
            })

        # --- Count rule spiked (potential new attack pattern) ---
        if tw_counted > 100 and lw_counted > 0:
            wow_count = tw_counted / lw_counted
            if wow_count >= WOW_ATTENTION:
                action_items.append({
                    "severity": "moderate",
                    "rule": rule_name,
                    "text": f"Count 规则命中环比增长 {wow_count:.1f}x（{lw_counted:,} → {tw_counted:,}）" if lang == "zh" else f"Count rule hits increased {wow_count:.1f}x ({lw_counted:,} → {tw_counted:,})",
                    "suggestion": "评估是否应将此规则切换为 Block" if lang == "zh" else "Review if this rule should be switched to Block",
                })

    # --- Cold-start fallback (no last week data) ---
    if not last_week:
        for rule_name, data in this_week.items():
            if rule_name in skip_rules:
                continue
            tw_blocked = sum(data.get("blocked", []))
            tw_challenge = sum(data.get("challenge", []))
            tw_captcha = sum(data.get("captcha", []))
            daily_avg = (tw_blocked + tw_challenge + tw_captcha) / max(len(data.get("blocked", [1])), 1)
            if daily_avg >= DAILY_BLOCK_SEVERE:
                action_items.append({
                    "severity": "critical",
                    "rule": rule_name,
                    "text": f"拦截量高: {tw_blocked + tw_challenge + tw_captcha:,}（均值 {daily_avg:,.0f}/时段），无历史基线" if lang == "zh" else f"High mitigation volume: {tw_blocked + tw_challenge + tw_captcha:,} (avg {daily_avg:,.0f}/period), no baseline",
                    "suggestion": "调查主要来源" if lang == "zh" else "Investigate top sources",
                })
            elif daily_avg >= DAILY_BLOCK_ATTENTION:
                action_items.append({
                    "severity": "moderate",
                    "rule": rule_name,
                    "text": f"拦截量偏高: {tw_blocked + tw_challenge + tw_captcha:,}（均值 {daily_avg:,.0f}/时段），无历史基线" if lang == "zh" else f"Elevated mitigation: {tw_blocked + tw_challenge + tw_captcha:,} (avg {daily_avg:,.0f}/period), no baseline",
                    "suggestion": "持续观察趋势" if lang == "zh" else "Monitor trend",
                })

    # Sort: critical first, then moderate, then low
    severity_order = {"critical": 0, "moderate": 1, "low": 2}
    action_items.sort(key=lambda x: severity_order.get(x["severity"], 9))

    # DDoS context tag: if spike coincides with DDoS event, add context
    if ddos_event_windows:
        for item in action_items:
            if "spike" in item.get("text", "").lower() or "surge" in item.get("text", "").lower():
                item["context"] = "⚡ May coincide with DDoS event — verify independently"

    return action_items


def _detect_ddos_windows(cw, webacl_name: str, start, end) -> list[int]:
    """Detect DDoS event windows from event-detected label metric.

    Returns list of day indices (0-based) where DDoS event was active.
    """
    try:
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "raw_evt", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests",
                    "Dimensions": [{"Name": "WebACL", "Value": webacl_name},
                                   {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                                   {"Name": "LabelName", "Value": "event-detected"}]}, "Period": 86400, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "evt", "Expression": "FILL(raw_evt,0)"},
            ],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        for r in resp.get("MetricDataResults", []):
            return [i for i, v in enumerate(r.get("Values", [])) if v > 0]
    except Exception:
        pass
    return []







def _get_all_rules_metrics_search(cw, webacl_name: str, start, end, period: int = 86400,
                                   scope: str = "CLOUDFRONT", region: str = "") -> dict:
    """Get per-rule metrics for all rules using SEARCH (single API call).

    Returns: {rule_name: {blocked: [daily], counted: [daily], challenge: [daily], captcha: [daily]}}
    Also returns 'ALL' key for WebACL-level totals.
    """
    # CLOUDFRONT uses {Rule,WebACL}; REGIONAL uses {Rule,WebACL,Region}
    if scope == "REGIONAL" and region:
        dim_set = "{AWS/WAFV2,Rule,WebACL,Region}"
        extra_filter = f' Region="{region}"'
    else:
        dim_set = "{AWS/WAFV2,Rule,WebACL}"
        extra_filter = ""

    resp = cw.get_metric_data(
        MetricDataQueries=[
            {"Id": "blocked", "Expression": f"SEARCH('{dim_set} WebACL=\"{webacl_name}\"{extra_filter} MetricName=\"BlockedRequests\"', 'Sum', {period})"},
            {"Id": "counted", "Expression": f"SEARCH('{dim_set} WebACL=\"{webacl_name}\"{extra_filter} MetricName=\"CountedRequests\"', 'Sum', {period})"},
            {"Id": "challenge", "Expression": f"SEARCH('{dim_set} WebACL=\"{webacl_name}\"{extra_filter} MetricName=\"ChallengeRequests\"', 'Sum', {period})"},
            {"Id": "captcha", "Expression": f"SEARCH('{dim_set} WebACL=\"{webacl_name}\"{extra_filter} MetricName=\"CaptchaRequests\"', 'Sum', {period})"},
            {"Id": "allowed", "Expression": f"SEARCH('{dim_set} WebACL=\"{webacl_name}\"{extra_filter} MetricName=\"AllowedRequests\"', 'Sum', {period})"},
        ],
        StartTime=start, EndTime=end, ScanBy="TimestampAscending",
    )

    rules = {}  # {rule_name: {blocked: [...], counted: [...], challenge: [...], captcha: [...], allowed: [], timestamps: []}}
    metric_map = {"blocked": "blocked", "counted": "counted", "challenge": "challenge", "captcha": "captcha", "allowed": "allowed"}

    # Phase 1: collect time-indexed data per rule per metric
    from tools.session_state import get_user_timezone
    _tz_off = get_user_timezone()
    _user_tz = timezone(timedelta(hours=_tz_off)) if _tz_off is not None else timezone.utc

    _raw = {}  # {rule_name: {metric: {ts_str: value}}}
    for r in resp.get("MetricDataResults", []):
        qid = r["Id"]
        if qid not in metric_map:
            continue
        label = r.get("Label", "")
        parts = label.rsplit(" ", 1)
        rule_name = parts[0] if len(parts) == 2 else label
        values = [int(v) for v in r.get("Values", [])]
        timestamps = [t.astimezone(_user_tz).isoformat() for t in r.get("Timestamps", [])]

        if rule_name not in _raw:
            _raw[rule_name] = {}
        _raw[rule_name][metric_map[qid]] = dict(zip(timestamps, values))

    # Phase 2: build aligned arrays per rule (union of all timestamps, sorted)
    for rule_name, metrics_data in _raw.items():
        all_ts = sorted(set(ts for m in metrics_data.values() for ts in m.keys()))
        rules[rule_name] = {
            "timestamps": all_ts,
            "blocked": [metrics_data.get("blocked", {}).get(ts, 0) for ts in all_ts],
            "counted": [metrics_data.get("counted", {}).get(ts, 0) for ts in all_ts],
            "challenge": [metrics_data.get("challenge", {}).get(ts, 0) for ts in all_ts],
            "captcha": [metrics_data.get("captcha", {}).get(ts, 0) for ts in all_ts],
            "allowed": [metrics_data.get("allowed", {}).get(ts, 0) for ts in all_ts],
        }

    return rules


def _get_challenge_solved(cw, webacl_name: str, scope: str, region: str, start, end) -> tuple[int, int]:
    """Get ChallengesSolved and CaptchasSolved (WebACL level). Returns (challenge_solved, captcha_solved)."""
    dims = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    if scope != "CLOUDFRONT":
        dims.append({"Name": "Region", "Value": region})
    try:
        resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "cs", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengesSolved", "Dimensions": dims}, "Period": 604800, "Stat": "Sum"}},
                {"Id": "cas", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchasSolved", "Dimensions": dims}, "Period": 604800, "Stat": "Sum"}},
            ],
            StartTime=start, EndTime=end,
        )
        cs = cas = 0
        for r in resp.get("MetricDataResults", []):
            val = int(sum(r.get("Values", [])))
            if r["Id"] == "cs":
                cs = val
            elif r["Id"] == "cas":
                cas = val
        return cs, cas
    except Exception:
        return 0, 0



# Known AMR rule groups and their expected deployment
_EXPECTED_AMRS = {
    "AWSManagedRulesCommonRuleSet": "Web Exploits (CRS)",
    "AWSManagedRulesKnownBadInputsRuleSet": "Known Bad Inputs",
    "AWSManagedRulesBotControlRuleSet": "Bot Control",
    "AWSManagedRulesAntiDDoSRuleSet": "Anti-DDoS",
    "AWSManagedRulesAnonymousIpList": "Anonymous IP (VPN/Tor/Proxy)",
    "AWSManagedRulesAmazonIpReputationList": "IP Reputation (Amazon)",
    "AWSManagedRulesSQLiRuleSet": "SQL Injection",
    "AWSManagedRulesLinuxRuleSet": "Linux OS",
    "AWSManagedRulesAdminProtectionRuleSet": "Admin Protection",
}


def _analyze_detection_tools(webacl_data: dict, logging_type: str, log_dest: str | None, lang: str = "en") -> list[dict]:
    """Analyze WebACL config to produce Detection Tools Status table.

    Returns list of dicts: {layer, rule_name, mode, status, detail}
    - status: "ok" | "warning" | "missing"
    """
    tools = []
    deployed_amrs = set()

    _d = {
        "override_count": "覆盖为 Count — 未实际拦截" if lang == "zh" else "Override to Count — not actively blocking",
        "excluded": "已排除: " if lang == "zh" else "Excluded: ",
        "more": "更多" if lang == "zh" else "more",
        "level": "级别" if lang == "zh" else "level",
        "not_deployed": "未部署" if lang == "zh" else "Not deployed",
    }

    for rule in webacl_data.get("Rules", []):
        name = rule.get("Name", "")
        stmt = rule.get("Statement", {})
        override = rule.get("OverrideAction", {})
        action = rule.get("Action", {})

        # Managed Rule Group
        if "ManagedRuleGroupStatement" in stmt:
            mrg = stmt["ManagedRuleGroupStatement"]
            mrg_name = mrg.get("Name", "")
            vendor = mrg.get("VendorName", "AWS")
            deployed_amrs.add(mrg_name)

            # Determine mode
            if "Count" in override:
                mode = "Count"
                status = "warning"
                detail = _d["override_count"]
            elif "None" in override:
                mode = "Block"
                status = "ok"
                detail = ""
            else:
                mode = "Block"
                status = "ok"
                detail = ""

            # Bot Control: detect inspection level (Common vs Targeted)
            if mrg_name == "AWSManagedRulesBotControlRuleSet":
                inspection_level = "Common"
                for cfg in mrg.get("ManagedRuleGroupConfigs", []):
                    payload = cfg.get("AWSManagedRulesBotControlRuleSet", {})
                    if payload.get("InspectionLevel") == "TARGETED":
                        inspection_level = "Targeted"
                detail = f"{inspection_level} {_d['level']}" + (f"; {detail}" if detail else "")

            # Check excluded rules
            excluded = mrg.get("ExcludedRules", [])
            if excluded:
                excluded_names = [r.get("Name", "") for r in excluded]
                detail = f"{_d['excluded']}{', '.join(excluded_names[:3])}" + (f" +{len(excluded_names)-3} {_d['more']}" if len(excluded_names) > 3 else "")

            layer = _EXPECTED_AMRS.get(mrg_name, f"{vendor}/{mrg_name}")
            tools.append({"layer": layer, "rule_name": name, "mode": mode, "status": status, "detail": detail})

        # Rate-based rule
        elif "RateBasedStatement" in stmt:
            rbs = stmt["RateBasedStatement"]
            limit = rbs.get("Limit", 0)
            window = rbs.get("EvaluationWindowSec", 300)
            agg = rbs.get("AggregateKeyType", "IP")

            # Determine action
            if "Block" in action:
                mode = f"Block ({limit}/{window}s, {agg})"
                status = "ok"
            elif "Count" in action:
                mode = f"Count ({limit}/{window}s)"
                status = "warning"
            elif "Challenge" in action:
                mode = f"Challenge ({limit}/{window}s)"
                status = "ok"
            elif "Captcha" in action:
                mode = f"Captcha ({limit}/{window}s)"
                status = "ok"
            else:
                mode = f"Block ({limit}/{window}s)"
                status = "ok"

            tools.append({"layer": "Rate Limiting", "rule_name": name, "mode": mode, "status": status, "detail": ""})

        # Custom rule with Challenge/Captcha action
        elif "Challenge" in action:
            tools.append({"layer": "Custom (Challenge)", "rule_name": name, "mode": "Challenge", "status": "ok", "detail": ""})
        elif "Captcha" in action:
            tools.append({"layer": "Custom (Captcha)", "rule_name": name, "mode": "Captcha", "status": "ok", "detail": ""})

    # Check for missing common AMRs
    for amr_name, layer in _EXPECTED_AMRS.items():
        if amr_name not in deployed_amrs and amr_name in (
            "AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
            "AWSManagedRulesBotControlRuleSet", "AWSManagedRulesAntiDDoSRuleSet",
            "AWSManagedRulesAmazonIpReputationList",
        ):
            tools.append({"layer": layer, "rule_name": "—", "mode": _d["not_deployed"], "status": "missing", "detail": ""})

    # Logging status
    if logging_type == "cwl":
        log_name = log_dest.split(":log-group:")[-1].rstrip(":*") if log_dest else ""
        tools.append({"layer": "Logging", "rule_name": f"CWL: {log_name}", "mode": "—", "status": "ok", "detail": ""})
    elif logging_type == "s3":
        tools.append({"layer": "Logging", "rule_name": "S3/Firehose", "mode": "—", "status": "ok", "detail": "IP-level analysis requires Athena"})
    else:
        tools.append({"layer": "Logging", "rule_name": "—", "mode": "Not configured", "status": "missing", "detail": "Enable logging for detailed analysis"})

    return tools


def _get_log_details_athena(log_dest: str, webacl_name: str, scope: str, region: str, start, end, attention_rules: list[str]) -> tuple[dict, str | None]:
    """Query top IPs/URIs via Athena for S3-stored logs. Auto-creates permanent table.

    Returns: (details_dict, table_created_msg or None)
    """
    table_msg = None
    try:
        from tools.waf_athena import _resolve_s3_path, _try_standard_path, _get_account_id, \
            _find_existing_table, _validate_waf_log, _detect_partitions, _create_named_table, \
            _run_athena_select, _ensure_database
        import re as _re

        # Resolve S3 path
        s3_base = _resolve_s3_path(log_dest)
        bucket = s3_base.replace("s3://", "").split("/")[0]
        s3_path = None
        if ":s3:::" in log_dest:
            account_id = _get_account_id()
            s3_path = _try_standard_path(bucket, account_id, scope, webacl_name, region)
        if not s3_path:
            s3_path = s3_base

        # Find or create table
        full_table = _find_existing_table(s3_path, region)
        part_fmt = None
        if not full_table:
            if not _validate_waf_log(s3_path):
                return {}, None
            storage_template, part_fmt, part_unit, part_interval = _detect_partitions(s3_path)
            _ensure_database(region, "primary")
            safe_name = _re.sub(r"[^a-zA-Z0-9]", "_", webacl_name).lower()
            full_table = _create_named_table(s3_path, storage_template, part_fmt, part_unit, part_interval, region, "primary", f"waf_logs_{safe_name}")
            table_msg = f"Created permanent Athena table: {full_table} (reusable for future queries)"
        else:
            # Detect partition format from existing table's S3 path
            _, part_fmt, _, _ = _detect_partitions(s3_path)

        # Block queries on hourly partitions
        if part_fmt == "yyyy/MM/dd/HH":
            return {}, "⚠️ Firehose hourly partition detected — log-level details skipped (timeout risk). See docs/firehose-minute-partitioning.md to optimize."

        # Build time filter WITH partition pruning (critical for performance)
        start_ms = int(start.timestamp()) * 1000
        end_ms = int(end.timestamp()) * 1000
        time_cond = f'"timestamp" BETWEEN {start_ms} AND {end_ms}'
        if part_fmt:
            if "mm" in part_fmt:
                sp = start.strftime("%Y/%m/%d/%H/%M")
                ep = end.strftime("%Y/%m/%d/%H/%M")
            else:
                sp = start.strftime("%Y/%m/%d/%H")
                ep = end.strftime("%Y/%m/%d/%H")
            time_cond += f" AND log_time >= '{sp}' AND log_time <= '{ep}'"
        # If the table location is shared by multiple WebACLs (e.g. a Firehose
        # bucket-root prefix), scope to this WebACL by webaclid so per-rule top
        # IPs/URIs don't include another WebACL's hits on the same managed rule.
        # webaclid is the full ARN containing the WebACL name as a path segment.
        webacl_scoped = webacl_name.lower() in s3_path.lower()
        if not webacl_scoped and _re.fullmatch(r"[A-Za-z0-9_-]+", webacl_name):
            time_cond += f" AND webaclid LIKE '%/{webacl_name}/%'"

        # Query top IPs and URIs per rule (parallel)
        from tools.waf_query import inspection_location, athena_content_expr
        details = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for rule_name in attention_rules[:5]:
                safe_rule = rule_name.replace("'", "''")
                ip_sql = f'SELECT httprequest.clientip AS "httpRequest.clientIp", COUNT(*) AS cnt FROM {full_table} WHERE {time_cond} AND terminatingruleid = \'{safe_rule}\' GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT 5'
                uri_sql = f'SELECT httprequest.uri AS "httpRequest.uri", COUNT(*) AS cnt FROM {full_table} WHERE {time_cond} AND terminatingruleid = \'{safe_rule}\' GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT 5'
                futures[executor.submit(_run_athena_select, ip_sql, region)] = (rule_name, "ips")
                futures[executor.submit(_run_athena_select, uri_sql, region)] = (rule_name, "uris")
                # Inspected content (the WHY) for rules whose name encodes a
                # location — covers BLOCK (terminating) and COUNT (non-terminating).
                loc = inspection_location(rule_name)
                if loc and loc[1] != "uri":  # uri already shown above
                    expr = athena_content_expr(loc[1])
                    rule_pred = (
                        f"(terminatingruleid = '{safe_rule}'"
                        f" OR any_match(nonterminatingmatchingrules, r -> r.ruleid = '{safe_rule}')"
                        f" OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules, r -> r.ruleid = '{safe_rule}')))"
                    )
                    content_sql = (f"SELECT {expr} AS content, COUNT(*) AS cnt FROM {full_table}"
                                   f" WHERE {time_cond} AND {rule_pred} AND {expr} <> ''"
                                   f" GROUP BY {expr} ORDER BY cnt DESC LIMIT 5")
                    futures[executor.submit(_run_athena_select, content_sql, region)] = (rule_name, "content")
            for future in concurrent.futures.as_completed(futures, timeout=120):
                rule_name, qtype = futures[future]
                try:
                    result = future.result()
                    if qtype == "content" and result:
                        # Redact secret values before storing — the Athena query
                        # returns RAW args/cookie/header. Align with the CWL path
                        # so the "redacted" label is truthful on both backends.
                        from tools.waf_query import _redact
                        _loc = inspection_location(rule_name)
                        _kind = _loc[1] if _loc else "args"
                        for _row in result:
                            _red, _ = _redact(_kind, _row.get("content", ""))
                            _row["content"] = _red
                    if rule_name not in details:
                        details[rule_name] = {}
                    details[rule_name][qtype] = result
                except Exception:
                    pass
        return details, table_msg
    except Exception:
        return {}, None


def _classify_rules(webacl_data: dict) -> list[dict]:
    """Extract and classify rules into 5 user-friendly categories."""
    rules = []
    for rule in webacl_data.get("Rules", webacl_data.get("rules", [])):
        name = rule.get("Name", rule.get("name", ""))
        stmt = rule.get("Statement", rule.get("statement", {}))
        rule_type = "custom"
        if "ManagedRuleGroupStatement" in stmt or "managed_rule_group_statement" in stmt:
            mrg = stmt.get("ManagedRuleGroupStatement", stmt.get("managed_rule_group_statement", {}))
            mrg_name = mrg.get("Name", mrg.get("name", ""))
            # Web Exploits: CRS, KnownBadInputs, SQLi, AdminProtection, OS/platform rules
            if any(k in mrg_name for k in ("CommonRuleSet", "KnownBadInputs", "SQLi", "AdminProtection",
                                            "LinuxRuleSet", "UnixRuleSet", "WindowsRuleSet", "PHPRuleSet", "WordPressRuleSet")):
                rule_type = "web_exploits"
            # Bot & Automation: BotControl, ATP, ACFP
            elif any(k in mrg_name for k in ("BotControl", "AccountTakeover", "AccountCreationFraud", "ATP", "ACFP")):
                rule_type = "bot"
            # DDoS
            elif "AntiDDoS" in mrg_name or "anti-ddos" in mrg_name.lower():
                rule_type = "ddos"
            # IP Reputation
            elif any(k in mrg_name for k in ("IpReputation", "AnonymousIp")):
                rule_type = "ip_reputation"
            else:
                rule_type = "web_exploits"  # unknown managed → treat as web exploits
        elif "RateBasedStatement" in stmt or "rate_based_statement" in stmt:
            rule_type = "ddos"  # rate-based → DDoS category
        rules.append({"name": name, "type": rule_type})
    return rules


def _poll_log_query(logs_client, log_group: str, start: int, end: int, query: str, max_wait: int = 60) -> list[dict]:
    """Run a Logs Insights query and wait for results."""
    try:
        resp = logs_client.start_query(logGroupName=log_group, startTime=start, endTime=end, queryString=query, limit=10)
        query_id = resp["queryId"]
        for _ in range(max_wait // 2):
            time.sleep(2)
            result = logs_client.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
        if result["status"] != "Complete":
            return []
        return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]
    except Exception:
        return []


def _query_top_ips_by_rule(logs_client, log_group: str, start: int, end: int, rule_name: str) -> list[dict]:
    """Get top 5 IPs blocked by a specific rule."""
    safe_name = rule_name.replace("'", "\\'")
    query = f"filter terminatingRuleId = '{safe_name}' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit 5"
    return _poll_log_query(logs_client, log_group, start, end, query)


def _query_top_uris_by_rule(logs_client, log_group: str, start: int, end: int, rule_name: str) -> list[dict]:
    """Get top 5 URIs blocked by a specific rule."""
    safe_name = rule_name.replace("'", "\\'")
    query = f"filter terminatingRuleId = '{safe_name}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit 5"
    return _poll_log_query(logs_client, log_group, start, end, query)


def _query_content_by_rule(logs_client, log_group: str, start: int, end: int, rule_name: str) -> list[dict]:
    """Get the inspected request component (the WHY) for a rule, redacted.
    Fetches matching messages and extracts the location keyed by the rule name."""
    import json as _json
    from collections import Counter
    from tools.waf_query import inspection_location, _redact
    loc = inspection_location(rule_name)
    if not loc or loc[1] == "uri":  # uri already shown separately
        return []
    kind = loc[1]
    safe_name = rule_name.replace("'", "\\'")
    query = f"filter terminatingRuleId = '{safe_name}' | fields @message | limit 25"
    rows = _poll_log_query(logs_client, log_group, start, end, query)
    counter = Counter()
    for r in rows:
        try:
            rec = _json.loads(r.get("@message", ""))
        except Exception:
            continue
        hr = rec.get("httpRequest", {})
        if kind == "args":
            raw = hr.get("args", "")
        elif kind == "cookie":
            raw = "; ".join(h.get("value", "") for h in hr.get("headers", []) if h.get("name", "").lower() == "cookie")
        elif kind == "header":
            raw = _json.dumps(hr.get("headers", []))
        else:
            raw = ""
        if raw:
            red, _ = _redact(kind, raw)
            if red:
                counter[red] += 1
    return [{"content": c, "cnt": n} for c, n in counter.most_common(5)]


def _get_log_details(logs_client, log_group: str, start: int, end: int, attention_rules: list[str]) -> dict:
    """Query log details for rules that need attention. Parallel execution."""
    details = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for rule_name in attention_rules[:5]:  # max 5 rules
            futures[executor.submit(_query_top_ips_by_rule, logs_client, log_group, start, end, rule_name)] = (rule_name, "ips")
            futures[executor.submit(_query_top_uris_by_rule, logs_client, log_group, start, end, rule_name)] = (rule_name, "uris")
            futures[executor.submit(_query_content_by_rule, logs_client, log_group, start, end, rule_name)] = (rule_name, "content")
        for future in concurrent.futures.as_completed(futures, timeout=120):
            rule_name, query_type = futures[future]
            try:
                result = future.result()
                if rule_name not in details:
                    details[rule_name] = {}
                details[rule_name][query_type] = result
            except Exception:
                pass
    return details



@tool
def patrol_scan(webacl_name: str, scope: str = "CLOUDFRONT", start_time: str = "", hours: int = 24, lang: str = "zh") -> str:
    """Run a security patrol scan for a specific WebACL.
    Produces a deterministic HTML report with action items, detection tools status,
    per-rule breakdown, and attack timeline chart.

    Use this ONLY when user asks for a patrol report, security summary, or weekly review.
    Do NOT use for specific questions about individual attacks, IPs, or rules.

    IMPORTANT: You MUST specify start_time. Ask the user which time period to scan.
    The scan covers [start_time, start_time + hours]. Max hours is 24.
    WoW comparison always uses the same duration from the previous week.

    Examples:
      patrol_scan(webacl_name="my-acl", start_time="2026-05-09", hours=24)  → scans May 9 full day
      patrol_scan(webacl_name="my-acl", start_time="2026-05-09T14:00", hours=6)  → scans 14:00-20:00

    Args:
        webacl_name: Name of the WebACL to scan.
        scope: AWS WAF scope — "CLOUDFRONT" or "REGIONAL".
        start_time: Start date/time for the scan period (e.g., "2026-05-09" or "2026-05-09T14:00"). REQUIRED — ask user if not provided.
        hours: Duration in hours from start_time (default 24, max 24). For weekly overview use 24 and check WoW comparison in the report.
        lang: Language for report — "zh" (Chinese) or "en" (English). Match user's language.
    """
    # Validate start_time
    if not start_time:
        return "Error: start_time is required. Ask the user which time period to scan.\nExample: patrol_scan(webacl_name=\"...\", start_time=\"2026-05-09\", hours=24)"

    # Parse start_time
    from tools.session_state import get_user_timezone
    _tz_off = get_user_timezone()
    _user_tz = timezone(timedelta(hours=_tz_off)) if _tz_off is not None else timezone.utc
    try:
        if "T" in start_time:
            dt = datetime.fromisoformat(start_time)
            start = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=_user_tz).astimezone(timezone.utc)
        else:
            start = datetime.fromisoformat(start_time + "T00:00:00").replace(tzinfo=_user_tz).astimezone(timezone.utc)
    except ValueError:
        return f"Error: invalid start_time format '{start_time}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM."

    # Cap hours at 24
    hours = min(hours, 24)
    end = start + timedelta(hours=hours)
    start_last = start - timedelta(days=7)  # WoW: same day last week
    end_last = end - timedelta(days=7)

    from tools.session_state import resolve_region
    region = resolve_region(scope)
    if region is None:
        return ("Error: REGIONAL scope requires get_waf_config to be called first "
                "(need to know which region the WebACL is in). "
                "Call get_waf_config(webacl_name='...') first.")

    global _latest_patrol_html

    # 1. Get WebACL config
    waf = get_client("wafv2", region_name=region)
    try:
        acls = waf.list_web_acls(Scope=scope)["WebACLs"]
        acl = next((a for a in acls if a["Name"] == webacl_name), None)
        if not acl:
            return f"WebACL '{webacl_name}' not found (scope={scope}, region={region})"
        acl_resp = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=acl["Id"])
        webacl_data = acl_resp.get("WebACL", {})
    except Exception as e:
        return f"Error getting WebACL config: {e}"

    # 2. Check logging
    log_dest = None
    try:
        log_resp = waf.get_logging_configuration(ResourceArn=webacl_data.get("ARN", ""))
        log_dest = log_resp.get("LoggingConfiguration", {}).get("LogDestinationConfigs", [None])[0]
    except Exception:
        pass
    logging_type = "none"
    if log_dest and ":log-group:" in log_dest:
        logging_type = "cwl"
    elif log_dest and ("s3:" in log_dest or "firehose" in log_dest.lower()):
        logging_type = "s3"

    # 3. Detection Tools Status
    detection_tools = _analyze_detection_tools(webacl_data, logging_type, log_dest, lang)

    # 4. Per-rule metrics (this period + same period last week for WoW)
    cw = get_client("cloudwatch", region_name=region)
    this_week_metrics = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=3600, scope=scope, region=region)
    last_week_metrics = _get_all_rules_metrics_search(cw, webacl_name, start_last, end_last, period=3600, scope=scope, region=region)

    # 5. Challenge/Captcha solved
    challenge_solved, captcha_solved = _get_challenge_solved(cw, webacl_name, scope, region, start, end)

    # 6. DDoS event detection + Action Items
    ddos_windows = _detect_ddos_windows(cw, webacl_name, start, end)
    action_items = _assess_rules_v2(this_week_metrics, last_week_metrics, detection_tools, ddos_windows if ddos_windows else None, lang)

    # 7. Top IPs/URIs for attention rules (CWL or Athena)
    # Only query logs for traffic anomalies (rules with actual metrics data), not config issues
    log_details = {}
    table_msg = None
    traffic_attention_rules = [a["rule"] for a in action_items
                               if a["severity"] in ("critical", "moderate")
                               and a["rule"] != "—"
                               and a.get("source") != "config"
                               and a["rule"] in this_week_metrics]
    if logging_type == "cwl" and traffic_attention_rules:
        log_group = log_dest.split(":log-group:")[-1].rstrip(":*")
        logs_client = get_client("logs", region_name=region)
        log_start = int(start.timestamp())
        log_end = int(end.timestamp())
        log_details = _get_log_details(logs_client, log_group, log_start, log_end, traffic_attention_rules)
    elif logging_type == "s3" and traffic_attention_rules:
        log_details, table_msg = _get_log_details_athena(log_dest, webacl_name, scope, region, start, end, traffic_attention_rules)

    # 8. Build per-rule table + rate-limit info
    rules_table = []
    rate_limit_info = []
    skip = {"ALL", webacl_name}
    for rule_name, data in this_week_metrics.items():
        if rule_name in skip:
            continue
        tw_b = sum(data.get("blocked", []))
        tw_c = sum(data.get("counted", []))
        tw_ch = sum(data.get("challenge", []))
        tw_cap = sum(data.get("captcha", []))
        tw_total = tw_b + tw_c + tw_ch + tw_cap
        if tw_total == 0:
            continue
        lw = last_week_metrics.get(rule_name, {})
        lw_total = sum(lw.get("blocked", [])) + sum(lw.get("counted", [])) + sum(lw.get("challenge", [])) + sum(lw.get("captcha", []))
        wow = tw_total / lw_total if lw_total > 0 else None
        rules_table.append({
            "name": rule_name, "blocked": tw_b, "counted": tw_c,
            "challenge": tw_ch, "captcha": tw_cap, "total": tw_total,
            "wow": wow, "log_detail": log_details.get(rule_name, {}),
        })
    rules_table.sort(key=lambda x: x["total"], reverse=True)

    for rule in webacl_data.get("Rules", []):
        stmt = rule.get("Statement", {})
        if "RateBasedStatement" in stmt:
            rbs = stmt["RateBasedStatement"]
            rname = rule.get("Name", "")
            limit = rbs.get("Limit", 0)
            window = rbs.get("EvaluationWindowSec", 300)
            rule_data = this_week_metrics.get(rname, {})
            blocked_daily = rule_data.get("blocked", [])
            rate_limit_info.append({
                "name": rname, "limit": limit, "window": window,
                "triggered_days": sum(1 for v in blocked_daily if v > 0),
                "total_blocked": sum(blocked_daily),
                "max_daily": max(blocked_daily) if blocked_daily else 0,
            })

    # 9. Totals
    all_data = this_week_metrics.get("ALL", {})
    totals = {
        "blocked": sum(all_data.get("blocked", [])),
        "counted": sum(all_data.get("counted", [])),
        "challenge": sum(all_data.get("challenge", [])),
        "captcha": sum(all_data.get("captcha", [])),
        "allowed": sum(all_data.get("allowed", [])),
        "challenge_solved": challenge_solved,
        "captcha_solved": captcha_solved,
    }

    # 10. Attack chart data
    _dims_rule = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    if scope == "REGIONAL" and region:
        _dims_rule.append({"Name": "Region", "Value": region})
    chart_data = None
    try:
        chart_resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "attacks", "Expression": f"SEARCH('{{AWS/WAFV2,Attack,WebACL}} WebACL=\"{webacl_name}\" MetricName=(\"BlockedRequests\" OR \"ChallengeRequests\" OR \"CaptchaRequests\")', 'Sum', 900)"},
                {"Id": "rb", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests", "Dimensions": _dims_rule}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "rc", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests", "Dimensions": _dims_rule}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "rp", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "CaptchaRequests", "Dimensions": _dims_rule}, "Period": 900, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "total_m", "Expression": "FILL(rb,0)+FILL(rc,0)+FILL(rp,0)"},
            ],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        labels = []
        total_values = []
        attack_raw = {}
        _tz_user = timezone(timedelta(hours=get_user_timezone())) if get_user_timezone() is not None else timezone.utc
        for r in chart_resp.get("MetricDataResults", []):
            if r["Id"] == "total_m":
                labels = [t.astimezone(_tz_user).strftime("%m/%d %H:%M") for t in r.get("Timestamps", [])]
                total_values = [int(v) for v in r.get("Values", [])]
            elif r["Id"] == "attacks":
                raw_label = r.get("Label", "Unknown")
                atype = raw_label.split(" ")[0] if any(raw_label.endswith(m) for m in ("BlockedRequests", "ChallengeRequests", "CaptchaRequests")) else raw_label
                if atype not in attack_raw:
                    attack_raw[atype] = {}
                for t, v in zip(r.get("Timestamps", []), r.get("Values", [])):
                    k = t.astimezone(_tz_user).strftime("%m/%d %H:%M")
                    attack_raw[atype][k] = attack_raw[atype].get(k, 0) + int(v)
        if labels:
            series = {a: [ts_map.get(l, 0) for l in labels] for a, ts_map in attack_raw.items()}
            other = [max(0, total_values[i] - sum(s[i] for s in series.values())) for i in range(len(labels))]
            if any(v > 0 for v in other):
                series["Other"] = other
            chart_data = {"labels": labels, "series": series}
    except Exception:
        pass

    # 10b. Bot Activity (label metrics — precise, not sampled)
    bot_data = None
    try:
        _region_dim = [{"Name": "Region", "Value": region}] if scope != "CLOUDFRONT" else []
        bot_queries = []
        for i, (lbl, metric) in enumerate([
            ("verified", "AllowedRequests"), ("unverified", "AllowedRequests"),
            ("unverified", "BlockedRequests"), ("unverified", "ChallengeRequests"),
            ("unverified", "CaptchaRequests"),
        ]):
            bot_queries.append({"Id": f"b{i}", "MetricStat": {
                "Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric, "Dimensions": [
                    {"Name": "LabelName", "Value": lbl},
                    {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:bot-control:bot"},
                    {"Name": "WebACL", "Value": webacl_name},
                ] + _region_dim}, "Period": int(hours * 3600), "Stat": "Sum",
            }})
        bot_resp = cw.get_metric_data(MetricDataQueries=bot_queries, StartTime=start, EndTime=end)
        vals = {}
        for r in bot_resp.get("MetricDataResults", []):
            vals[r["Id"]] = int(sum(r.get("Values", [])))
        v_allowed = vals.get("b0", 0)
        u_allowed = vals.get("b1", 0)
        u_blocked = vals.get("b2", 0)
        u_challenged = vals.get("b3", 0)
        u_captchaed = vals.get("b4", 0)
        if v_allowed + u_allowed + u_blocked + u_challenged + u_captchaed > 0:
            bot_data = {
                "verified_allowed": v_allowed,
                "unverified_allowed": u_allowed,
                "unverified_blocked": u_blocked,
                "unverified_challenged": u_challenged,
                "unverified_captchaed": u_captchaed,
            }
            # Targeted bot: query rule-level TGT_ labels + signals via SEARCH
            try:
                tgt_resp = cw.get_metric_data(MetricDataQueries=[
                    {"Id": "tgt_rules", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control\"', 'Sum', {int(hours*3600)})"},
                    {"Id": "tgt_sig", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal\"', 'Sum', {int(hours*3600)})"},
                    {"Id": "tgt_csp", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:signal:cloud_service_provider\"', 'Sum', {int(hours*3600)})"},
                    {"Id": "tgt_vol", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:targeted:aggregate:volumetric:ip\"', 'Sum', {int(hours*3600)})"},
                ], StartTime=start, EndTime=end)
                # Parse: group by LabelName, aggregate by action type
                targeted_signals = {}  # {label_name: {metric: count}}
                for r in tgt_resp.get("MetricDataResults", []):
                    val = int(sum(r.get("Values", [])))
                    if val == 0:
                        continue
                    label_str = r.get("Label", "")
                    # Label format: "LabelName LabelNamespace MetricName"
                    parts = label_str.split(" ")
                    if len(parts) >= 3:
                        lbl_name, _, metric_name = parts[0], parts[1], parts[2]
                    else:
                        continue
                    # Skip low-severity informational signals (only show medium/high)
                    if lbl_name.endswith("Low") or lbl_name == "TGT_TokenAbsent":
                        continue
                    if lbl_name.startswith("TGT_") or lbl_name.startswith("Signal") or lbl_name in ("token_absent", "non_browser_user_agent") or parts[1].endswith("cloud_service_provider"):
                        if lbl_name not in targeted_signals:
                            targeted_signals[lbl_name] = {}
                        targeted_signals[lbl_name][metric_name] = targeted_signals[lbl_name].get(metric_name, 0) + val
                if targeted_signals:
                    bot_data["targeted_signals"] = targeted_signals
            except Exception:
                pass
            # Bot categories: use SEARCH to discover all bot names dynamically
            try:
                cat_resp = cw.get_metric_data(MetricDataQueries=[
                    {"Id": "names", "Expression": f"SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:bot-control:bot:name\"', 'Sum', {int(hours*3600)})"},
                ], StartTime=start, EndTime=end)
                bot_names = {}
                for r in cat_resp.get("MetricDataResults", []):
                    label = r.get("Label", "")
                    # Format: "LabelName LabelNamespace MetricName"
                    parts = label.split(" ")
                    bot_name = parts[0] if len(parts) >= 3 else label
                    val = int(sum(r.get("Values", [])))
                    if val > 0:
                        bot_names[bot_name] = bot_names.get(bot_name, 0) + val
                if bot_names:
                    bot_data["bot_names"] = bot_names
            except Exception:
                pass
    except Exception:
        pass

    # 10c. Bot-derived action items
    if bot_data:
        # Unverified bots allowed while Bot Control is in Count mode
        u_allowed = bot_data.get("unverified_allowed", 0)
        bc_in_count = any(t["layer"] == "Bot Control" and t["status"] == "warning" for t in detection_tools)
        if bc_in_count and u_allowed > 100:
            action_items.append({
                "severity": "moderate",
                "rule": "Bot Control",
                "text": f'{u_allowed:,} 个未验证 bot 请求被放行（Bot Control 处于 Count 模式）' if lang == "zh" else f'{u_allowed:,} unverified bot requests allowed (Bot Control in Count mode)',
                "suggestion": "评估切换到 Block 模式以拦截未验证 bot" if lang == "zh" else "Evaluate switching to Block mode to mitigate unverified bots",
                "source": "traffic",
            })
        # High CSP traffic (any label under cloud_service_provider namespace)
        tgt_sigs = bot_data.get("targeted_signals", {})
        for name, metrics in tgt_sigs.items():
            if name.lower() in ("aws", "gcp", "azure", "oracle"):
                csp_total = sum(metrics.values())
                if csp_total > 1000:
                    action_items.append({
                        "severity": "moderate",
                        "rule": "Bot Control",
                        "text": f'来自 {name.upper()} 数据中心的请求 {csp_total:,} 次' if lang == "zh" else f'{csp_total:,} requests from {name.upper()} data center',
                        "suggestion": "确认是否为合法服务调用（监控、API），否则考虑拦截" if lang == "zh" else "Verify if legitimate service calls (monitoring, API); consider blocking otherwise",
                        "source": "traffic",
                    })
        # High targeted challenge/captcha volume
        for name, metrics in tgt_sigs.items():
            if name.startswith("TGT_"):
                challenged = metrics.get("ChallengeRequests", 0) + metrics.get("ChallengeRuleMatch", 0)
                captchaed = metrics.get("CaptchaRequests", 0) + metrics.get("CaptchaRuleMatch", 0)
                blocked = metrics.get("BlockedRequests", 0) + metrics.get("BlockRuleMatch", 0)
                mitigated = challenged + captchaed + blocked
                if mitigated > 5000:
                    action_items.append({
                        "severity": "moderate",
                        "rule": name,
                        "text": f'高级 bot 检测触发 {mitigated:,} 次（质询 {challenged:,} · 验证码 {captchaed:,} · 拦截 {blocked:,}）' if lang == "zh" else f'Targeted bot detection triggered {mitigated:,} times (challenge {challenged:,} · captcha {captchaed:,} · block {blocked:,})',
                        "suggestion": "确认 challenge/captcha 解决率，判断是否为有效拦截" if lang == "zh" else "Check challenge/captcha solve rate to determine if mitigation is effective",
                        "source": "traffic",
                    })

    # Re-sort action items
    severity_order = {"critical": 0, "moderate": 1, "low": 2}
    action_items.sort(key=lambda x: severity_order.get(x["severity"], 9))

    # 11. Render HTML
    wr = {
        "name": webacl_name, "scope": scope, "region": region,
        "detection_tools": detection_tools, "action_items": action_items,
        "rules_table": rules_table, "totals": totals, "logging": logging_type,
        "rate_limits": rate_limit_info, "chart_data": chart_data, "bot_data": bot_data,
    }
    all_action_items = [{**a, "webacl": webacl_name} for a in action_items]
    _latest_patrol_html = _render_patrol_html_v2([wr], all_action_items, start, end, hours, lang)

    # 12. Return summary
    n_critical = sum(1 for a in action_items if a["severity"] == "critical")
    n_moderate = sum(1 for a in action_items if a["severity"] == "moderate")

    if n_critical > 0:
        status = f"🔴 {n_critical} critical + {n_moderate} moderate items need attention"
    elif n_moderate > 0:
        status = f"⚠️ {n_moderate} items need attention"
    else:
        status = "🟢 All systems nominal — no action required"

    summary = f"**Patrol Report Generated**\n\n"
    summary += f"WebACL: {webacl_name} ({scope})\n"
    summary += f"Period: {start.strftime('%Y-%m-%d %H:%M')} to {end.strftime('%Y-%m-%d %H:%M')} UTC ({hours}h)\n"
    summary += f"Status: {status}\n\n"

    if action_items:
        summary += "**Top Action Items:**\n"
        for item in action_items[:5]:
            icon = "🔴" if item["severity"] == "critical" else "⚠️" if item["severity"] == "moderate" else "💡"
            summary += f"- {icon} [{item['rule']}] {item['text']}\n"
        if len(action_items) > 5:
            summary += f"- ... and {len(action_items) - 5} more (see full report)\n"

    # Per-rule log detail (top IPs / URIs / inspected content). The HTML report
    # does not yet render this (see #7 refactor); surface it in the text the
    # agent reads so weekly reports judge attack vs FP from real payloads, not
    # guesses. Content values are already redacted by the detail queries.
    detail_lines = []
    from tools.waf_query import inspection_location
    for rule in rules_table:
        ld = rule.get("log_detail") or {}
        ips, uris, content = ld.get("ips") or [], ld.get("uris") or [], ld.get("content") or []
        if not (ips or uris or content):
            continue
        detail_lines.append(f"\n### {rule['name']} (blocked {rule['blocked']}, counted {rule['counted']})")
        if ips:
            top_ips = ", ".join(f"{r.get('httpRequest.clientIp', '?')} ({r.get('cnt', '?')})" for r in ips[:5])
            detail_lines.append(f"  Top IPs: {top_ips}")
        if uris:
            top_uris = ", ".join(f"{r.get('httpRequest.uri', '?')} ({r.get('cnt', '?')})" for r in uris[:5])
            detail_lines.append(f"  Top URIs: {top_uris}")
        if content:
            loc = inspection_location(rule["name"])
            label = loc[0] if loc else "content"
            detail_lines.append(f"  Inspected {label} (raw, redacted — show to user, do NOT verdict):")
            for r in content[:5]:
                detail_lines.append(f"    [{r.get('cnt', '?')} hits] {str(r.get('content', ''))[:200]}")
    if detail_lines:
        summary += "\n\n**Per-Rule Detail (attention rules):**" + "\n".join(detail_lines) + "\n"

    if table_msg:
        summary += f"\n📋 {table_msg}\n"
    summary += "\nFull HTML report is ready for download."

    # Detect missing sections
    missing = []
    if not chart_data:
        missing.append("attack_chart")
    if not wr.get("bot_data", {}).get("bot_names"):
        missing.append("bot_names")
    if not wr.get("bot_data", {}).get("targeted_signals"):
        missing.append("targeted_signals")
    if missing:
        summary += (f"\n\nPARTIAL_DATA: true\nMISSING_SECTIONS: {missing}\n"
                    "REASON: CloudWatch metric auto-discovery requires recent activity (last 14 days). These sections had no matching traffic recently.\n"
                    "ACTION: Inform user that some sections are empty due to a CloudWatch limitation. Continuous traffic ensures all sections populate correctly.")

    return summary


def _render_patrol_html_v2(webacl_results: list, all_action_items: list, start, end, hours: int, lang: str = "en") -> str:
    """Render deterministic patrol report HTML — chart-first, minimal tables."""
    L = _PATROL_I18N.get(lang, _PATROL_I18N["en"])
    now = datetime.now(timezone.utc)
    from tools.session_state import get_user_timezone
    _tz_off = get_user_timezone()
    tz_offset = timedelta(hours=_tz_off) if _tz_off is not None else timedelta(0)
    tz_label = f"UTC{_tz_off:+g}" if _tz_off is not None and _tz_off != 0 else "UTC"

    n_critical = sum(1 for a in all_action_items if a["severity"] == "critical")
    n_moderate = sum(1 for a in all_action_items if a["severity"] == "moderate")

    if n_critical > 0:
        banner_class = "banner-critical"
        banner_text = f"🔴 {n_critical} {L['critical']} + {n_moderate} {L['moderate']} {L['items_attention']}"
    elif n_moderate > 0:
        banner_class = "banner-warning"
        banner_text = f"⚠️ {n_moderate} {L['items_attention']}"
    else:
        banner_class = "banner-ok"
        banner_text = f"🟢 {L['all_nominal']}"

    # Build sections per WebACL
    webacl_sections = ""
    for wr in webacl_results:
        if "error" in wr:
            webacl_sections += f'<h2>{wr["name"]} ({wr["scope"]})</h2><p class="muted">Error: {wr["error"]}</p>'
            continue

        tot = wr["totals"]
        total_reqs = tot["blocked"] + tot["challenge"] + tot["captcha"] + tot["counted"] + tot["allowed"]
        mitigated = tot["blocked"] + tot["challenge"] + tot["captcha"]

        # --- 1. Traffic Distribution (donut) + Bot Activity (donut) side by side ---
        donut_id = f'donut_{wr["name"].replace("-","_")}'
        webacl_sections += f'''
<h2>{wr["name"]} <span class="muted">({wr["scope"]}, {wr["region"]})</span></h2>
<div class="chart-row">
  <div class="chart-box">
    <div class="chart-title">{L["total_requests"]}: {total_reqs:,}</div>
    <canvas id="{donut_id}" width="220" height="220"></canvas>
    <div class="donut-legend">
      <span class="dot" style="background:#f85149"></span>{L["mitigated"]}: {mitigated:,}<br>
      <span class="dot" style="background:#d29922"></span>{L["counted"]}: {tot["counted"]:,}<br>
      <span class="dot" style="background:#3fb950"></span>{L["allowed"]}: {tot["allowed"]:,}
    </div>
  </div>
'''
        if wr.get("bot_data"):
            bd = wr["bot_data"]
            u_mit = bd["unverified_blocked"] + bd["unverified_challenged"] + bd["unverified_captchaed"]
            bot_id = f'bot_{wr["name"].replace("-","_")}'
            bot_detail = (f'{L["blocked"]} {bd["unverified_blocked"]:,} · '
                         f'{L["challenge"]} {bd["unverified_challenged"]:,} · '
                         f'{L["captcha"]} {bd["unverified_captchaed"]:,}')
            webacl_sections += f'''
  <div class="chart-box">
    <div class="chart-title">{L["bot_activity"]}</div>
    <canvas id="{bot_id}" width="220" height="220"></canvas>
    <div class="donut-legend">
      <span class="dot" style="background:#3fb950"></span>{L["bot_verified"]}: {bd["verified_allowed"]:,}<br>
      <span class="dot" style="background:#d29922"></span>{L["bot_unverified_allowed"]}: {bd["unverified_allowed"]:,}<br>
      <span class="dot" style="background:#f85149"></span>{L["bot_unverified_mitigated"]}: {u_mit:,}
    </div>
    <div class="muted" style="text-align:center;margin-top:4px">{bot_detail}</div>
  </div>
'''
        webacl_sections += '</div>\n'

        # Targeted bot + categories (below donut row)
        if wr.get("bot_data"):
            bd = wr["bot_data"]
            extra_bot = ""
            # Targeted bot signals chart
            if bd.get("targeted_signals"):
                sigs = bd["targeted_signals"]
                sorted_sigs = sorted(sigs.items(), key=lambda x: sum(x[1].values()), reverse=True)
                tgt_labels = []
                tgt_blocked = []
                tgt_challenged = []
                tgt_captcha = []
                tgt_allowed = []
                for name, metrics in sorted_sigs:
                    blocked = metrics.get("BlockedRequests", 0) + metrics.get("BlockRuleMatch", 0)
                    challenged = metrics.get("ChallengeRequests", 0) + metrics.get("ChallengeRuleMatch", 0)
                    captchaed = metrics.get("CaptchaRequests", 0) + metrics.get("CaptchaRuleMatch", 0)
                    allowed = metrics.get("AllowedRequests", 0)
                    if blocked + challenged + captchaed + allowed == 0:
                        continue
                    tgt_labels.append(name[:30])
                    tgt_blocked.append(blocked)
                    tgt_challenged.append(challenged)
                    tgt_captcha.append(captchaed)
                    tgt_allowed.append(allowed)
                if tgt_labels:
                    tgt_id = f'tgtsig_{wr["name"].replace("-","_")}'
                    tgt_height = 40 * len(tgt_labels) + 50
                    extra_bot += f'''<h3>{L["bot_targeted"]}</h3>
<div class="chart-wide"><canvas id="{tgt_id}" height="{tgt_height}"></canvas></div>
<script>
(function(){{const c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#e6edf3';
new Chart(document.getElementById('{tgt_id}'),{{type:'bar',data:{{labels:{json.dumps(tgt_labels)},datasets:[
  {{label:"{L["blocked"]}",data:{json.dumps(tgt_blocked)},backgroundColor:"#f85149",maxBarThickness:28}},
  {{label:"{L["challenge"]}",data:{json.dumps(tgt_challenged)},backgroundColor:"#d29922",maxBarThickness:28}},
  {{label:"{L["captcha"]}",data:{json.dumps(tgt_captcha)},backgroundColor:"#a371f7",maxBarThickness:28}},
  {{label:"{L["not_blocked"]}",data:{json.dumps(tgt_allowed)},backgroundColor:"#8b949e",maxBarThickness:28}}
]}},options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:c}}}}}},scales:{{x:{{stacked:true,ticks:{{color:c}}}},y:{{stacked:true,ticks:{{color:c,font:{{size:11}}}}}}}}}}}});}})();
</script>
'''
            # Bot names bar chart
            if bd.get("bot_names"):
                names = bd["bot_names"]
                # Sort by volume, top 10
                sorted_names = sorted(names.items(), key=lambda x: x[1], reverse=True)[:10]
                cat_id = f'botcat_{wr["name"].replace("-","_")}'
                cat_labels = json.dumps([n for n, _ in sorted_names])
                cat_values = json.dumps([v for _, v in sorted_names])
                cat_height = max(80, 35 * len(sorted_names) + 40)
                extra_bot += f'''
<h3>{L["bot_category"]}</h3>
<div class="chart-wide"><canvas id="{cat_id}" height="{cat_height}"></canvas></div>
<script>
(function(){{const c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#e6edf3';
new Chart(document.getElementById('{cat_id}'),{{type:'bar',data:{{labels:{cat_labels},datasets:[
  {{label:"Requests",data:{cat_values},backgroundColor:"#58a6ff",maxBarThickness:28}}
]}},options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{x:{{beginAtZero:true,ticks:{{color:c}}}},y:{{ticks:{{color:c}}}}}}}}}});}})();
</script>
'''
            if extra_bot:
                webacl_sections += extra_bot

        # --- 2. Top Rules (horizontal stacked bar) ---
        rules_sorted = sorted(wr["rules_table"], key=lambda r: r["blocked"] + r["challenge"] + r["captcha"], reverse=True)[:10]
        if rules_sorted:
            bar_id = f'rules_{wr["name"].replace("-","_")}'
            bar_labels = json.dumps([r["name"][:30] for r in rules_sorted])
            bar_blocked = json.dumps([r["blocked"] for r in rules_sorted])
            bar_challenge = json.dumps([r["challenge"] for r in rules_sorted])
            bar_captcha = json.dumps([r["captcha"] for r in rules_sorted])
            bar_counted = json.dumps([r["counted"] for r in rules_sorted])
            bar_height = 40 * len(rules_sorted) + 50
            webacl_sections += f'''
<h3>{L["per_rule"]} (Top 10)</h3>
<div class="chart-wide"><canvas id="{bar_id}" height="{bar_height}"></canvas></div>
<script>
(function(){{const c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#e6edf3';
new Chart(document.getElementById('{bar_id}'),{{type:'bar',data:{{labels:{bar_labels},datasets:[
  {{label:"{L["blocked"]}",data:{bar_blocked},backgroundColor:"#f85149",maxBarThickness:28}},
  {{label:"{L["challenge"]}",data:{bar_challenge},backgroundColor:"#d29922",maxBarThickness:28}},
  {{label:"{L["captcha"]}",data:{bar_captcha},backgroundColor:"#a371f7",maxBarThickness:28}},
  {{label:"{L["not_blocked"]}",data:{bar_counted},backgroundColor:"#8b949e",maxBarThickness:28}}
]}},options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:c}}}}}},scales:{{x:{{stacked:true,ticks:{{color:c}}}},y:{{stacked:true,ticks:{{color:c,font:{{size:11}}}}}}}}}}}});}})();
</script>
'''

        # --- 3. Attack Timeline (stacked area) ---
        if wr.get("chart_data") and wr["chart_data"].get("labels"):
            cd = wr["chart_data"]
            colors = {"Volumetric": "#f85149", "BadBots": "#d29922", "XSS": "#e3b341", "GenericLFI": "#a371f7", "KnownBadInputs": "#58a6ff", "Other": "#8b949e"}
            datasets_js = ""
            for atype, values in cd["series"].items():
                color = colors.get(atype, "#79c0ff")
                datasets_js += f'{{label:"{atype}",data:{json.dumps(values)},borderColor:"{color}",backgroundColor:"{color}99",fill:true,tension:0.2,pointRadius:0}},'
            webacl_sections += f'''
<h3>{L["attack_chart"]}</h3>
<div class="chart-wide"><canvas id="attackChart_{wr['name'].replace('-','_')}"></canvas></div>
<p class="muted" style="text-align:center">{tz_label}</p>
<script>
(function(){{const c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#e6edf3';
new Chart(document.getElementById('attackChart_{wr["name"].replace("-","_")}'),{{type:'line',data:{{labels:{json.dumps(cd["labels"])},datasets:[{datasets_js}]}},options:{{responsive:true,interaction:{{mode:'index',intersect:false}},plugins:{{legend:{{labels:{{color:c}}}},zoom:{{zoom:{{wheel:{{enabled:true}},mode:'x'}},pan:{{enabled:true,mode:'x'}}}}}},scales:{{x:{{ticks:{{color:c,maxTicksLimit:14}}}},y:{{stacked:true,beginAtZero:true,ticks:{{color:c}}}}}}}}}});}})();
</script>
'''

        # --- 4. Rate-Limit (horizontal bar with threshold in label) ---
        if wr.get("rate_limits"):
            rl_id = f'rl_{wr["name"].replace("-","_")}'
            # Label format: "rule-name (100/300s)" — threshold embedded in label
            rl_labels = json.dumps([f'{rl["name"][:20]} ({rl["limit"]:,}/{rl["window"]}s)' for rl in wr["rate_limits"]])
            rl_blocked = json.dumps([rl["total_blocked"] for rl in wr["rate_limits"]])
            rl_height = max(80, 40 * len(wr["rate_limits"]) + 40)
            webacl_sections += f'''
<h3>{L["rate_limit"]}</h3>
<div class="chart-wide"><canvas id="{rl_id}" height="{rl_height}"></canvas></div>
<script>
(function(){{const c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#e6edf3';
new Chart(document.getElementById('{rl_id}'),{{type:'bar',data:{{labels:{rl_labels},datasets:[
  {{label:"{L["total_blocked"]}",data:{rl_blocked},backgroundColor:"#f85149",maxBarThickness:36}}
]}},options:{{indexAxis:'y',responsive:true,plugins:{{legend:{{display:false}}}},scales:{{x:{{beginAtZero:true,ticks:{{color:c}}}},y:{{ticks:{{color:c,font:{{size:11}}}}}}}}}}}});}})();
</script>
'''

        # --- 5. Detection Tools (compact table) ---
        dt_rows = ""
        for t in wr["detection_tools"]:
            icon = "✅" if t["status"] == "ok" else "⚠️" if t["status"] == "warning" else "❌"
            detail = f' ({t["detail"]})' if t["detail"] else ""
            dt_rows += f'<tr><td>{icon} {t["layer"]}</td><td>{t["rule_name"]}</td><td>{t["mode"]}{detail}</td></tr>\n'
        webacl_sections += f'<h3>{L["detection_tools"]}</h3>\n<table><tr><th>{L["layer"]}</th><th>{L["rule"]}</th><th>{L["mode"]}</th></tr>{dt_rows}</table>\n'

    # Action Items
    action_html = ""
    if all_action_items:
        action_html = '<div class="action-items">'
        for item in all_action_items:
            icon = "🔴" if item["severity"] == "critical" else "⚠️" if item["severity"] == "moderate" else "💡"
            action_html += f'<div class="action-item {item["severity"]}"><strong>{icon} {item["rule"]}</strong>: {item["text"]}<br><span class="muted">→ {item["suggestion"]}</span></div>'
        action_html += "</div>"
    else:
        action_html = f'<p class="banner banner-ok">{L["no_action"]}</p>'

    # Embedded JSON
    report_json = json.dumps({
        "version": "2.0",
        "generated_at": now.isoformat(),
        "period": {"start": start.isoformat(), "end": end.isoformat(), "hours": hours},
        "webacls": [{
            "name": wr["name"], "scope": wr.get("scope", ""),
            "action_items": [a for a in all_action_items if a.get("webacl") == wr["name"]],
        } for wr in webacl_results if "error" not in wr],
    }, default=str)

    # Donut init script
    donut_calls = []
    for wr in webacl_results:
        if "error" in wr:
            continue
        tot = wr["totals"]
        mit = tot["blocked"] + tot["challenge"] + tot["captcha"]
        did = f'donut_{wr["name"].replace("-","_")}'
        donut_calls.append(f'donut("{did}",{json.dumps([mit, tot["counted"], tot["allowed"]])},{json.dumps([L["mitigated"], L["counted"], L["allowed"]])},["#f85149","#d29922","#3fb950"]);')
        if wr.get("bot_data"):
            bd = wr["bot_data"]
            u_m = bd["unverified_blocked"] + bd["unverified_challenged"] + bd["unverified_captchaed"]
            bid = f'bot_{wr["name"].replace("-","_")}'
            donut_calls.append(f'donut("{bid}",{json.dumps([bd["verified_allowed"], bd["unverified_allowed"], u_m])},{json.dumps([L["bot_verified"], L["bot_unverified_allowed"], L["bot_unverified_mitigated"]])},["#3fb950","#d29922","#f85149"]);')
    donut_script = f'<script>{" ".join(donut_calls)}</script>' if donut_calls else ""

    return f'''<!DOCTYPE html>
<html class="dark"><head><meta charset="utf-8"><title>{L["title"]}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1"></script>
<script src="https://cdn.jsdelivr.net/npm/hammerjs@2.0.8"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.2.0"></script>
<style>
:root.dark {{ --bg: #0d1117; --fg: #e6edf3; --card: #161b22; --border: #30363d; --accent: #58a6ff; --green: #3fb950; --red: #f85149; --muted: #8b949e; }}
:root.light {{ --bg: #ffffff; --fg: #1f2328; --card: #f6f8fa; --border: #d0d7de; --accent: #0969da; --green: #1a7f37; --red: #cf222e; --muted: #656d76; }}
body {{ font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg); max-width: 1100px; margin: 0 auto; padding: 2rem; line-height: 1.6; font-size: 1rem; }}
h1 {{ color: var(--accent); }} h2 {{ color: var(--accent); margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; }} h3 {{ margin-top: 1.5rem; }}
.muted {{ color: var(--muted); }}
.chart-row {{ display: flex; gap: 1.5rem; margin: 1rem 0; align-items: stretch; }}
.chart-box {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; flex: 1 1 0; text-align: center; min-width: 0; }}
.chart-title {{ font-weight: 600; margin-bottom: .5rem; }}
.chart-wide {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
.donut-legend {{ margin-top: .5rem; text-align: left; padding-left: 1rem; }}
.dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 4px; }}
.wow-notes {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: .8rem 1rem; margin: .5rem 0; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card); border-radius: 6px; overflow: hidden; }}
th {{ background: var(--border); text-align: left; padding: .5rem .7rem; }} td {{ padding: .4rem .7rem; border-top: 1px solid var(--border); }}
.banner {{ padding: 1rem; border-radius: 8px; margin: 1rem 0; font-size: 1.1rem; font-weight: 600; }}
.banner-ok {{ background: rgba(63,185,80,0.1); border: 1px solid var(--green); color: var(--green); }}
.banner-warning {{ background: rgba(210,153,34,0.1); border: 1px solid #d29922; color: #d29922; }}
.banner-critical {{ background: rgba(248,81,73,0.1); border: 1px solid var(--red); color: var(--red); }}
.action-items {{ margin: 1rem 0; }} .action-item {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: .8rem 1rem; margin: .5rem 0; }}
.action-item.critical {{ border-left: 3px solid var(--red); }} .action-item.moderate {{ border-left: 3px solid #d29922; }} .action-item.low {{ border-left: 3px solid var(--muted); }}
.footer {{ color: var(--muted); font-size: .85rem; margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; }}
</style></head><body>
<h1>🛡️ {L["title"]}</h1>
<button onclick="document.documentElement.classList.toggle('dark');document.documentElement.classList.toggle('light');this.textContent=document.documentElement.classList.contains('light')?'🌙':'☀️';var c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim();Chart.helpers.each(Chart.instances,function(ch){{if(ch.options.plugins.legend&&ch.options.plugins.legend.labels)ch.options.plugins.legend.labels.color=c;if(ch.options.scales&&ch.options.scales.x)ch.options.scales.x.ticks.color=c;if(ch.options.scales&&ch.options.scales.y)ch.options.scales.y.ticks.color=c;ch.update()}})" style="position:fixed;top:1rem;right:1rem;font-size:1.5rem;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.4rem .7rem;cursor:pointer;z-index:99">☀️</button>
<p class="muted">{webacl_results[0]["name"]} ({webacl_results[0]["scope"]}) · {L["period"]}: {start.astimezone(timezone(tz_offset)).strftime('%Y-%m-%d %H:%M')} — {end.astimezone(timezone(tz_offset)).strftime('%Y-%m-%d %H:%M')} {tz_label} ({hours}h)</p>
<p class="muted">{L["generated"]}: {now.astimezone(timezone(tz_offset)).strftime('%Y-%m-%d %H:%M')} {tz_label} · {L["delay_note"]}</p>

<div class="banner {banner_class}">{banner_text}</div>

<h2>{L["action_items"]}</h2>
{action_html}

{webacl_sections}

<div class="footer">{"由 AWS WAF Agent 生成" if lang == "zh" else "Generated by AWS WAF Agent"} · {now.strftime('%Y-%m-%d %H:%M UTC')}</div>
<script>
function donut(id,data,labels,colors){{const c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#e6edf3';new Chart(document.getElementById(id),{{type:'doughnut',data:{{labels:labels,datasets:[{{data:data,backgroundColor:colors,borderWidth:0}}]}},options:{{responsive:false,cutout:'60%',plugins:{{legend:{{display:false}}}}}}}});}}
</script>
{donut_script}
<script type="application/json" id="report-data">{report_json}</script>
</body></html>'''
