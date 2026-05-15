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
_patrol_chart_data: dict = {}  # Stored between patrol_scan and finalize_patrol_report

# Thresholds for anomaly detection (v1 — absolute, used as cold-start fallback)
DAILY_BLOCK_ATTENTION = 500
DAILY_BLOCK_SEVERE = 5000
IP_CONCENTRATION_ATTENTION = 0.30
IP_CONCENTRATION_SEVERE = 0.60

# WoW anomaly detection thresholds (v2)
WOW_ATTENTION = 3.0   # 3x increase vs last week
WOW_SEVERE = 10.0     # 10x increase
SPIKE_RATIO_ATTENTION = 5.0  # max day / avg day


def _assess_rules_v2(this_week: dict, last_week: dict, detection_tools: list[dict]) -> list[dict]:
    """Assess per-rule metrics with WoW comparison. Returns action_items list.

    Each item: {severity, rule, text, suggestion, context?}
    severity: "critical" | "moderate" | "low"
    """
    action_items = []
    skip_rules = {"ALL", "shield-sample-webacl"}  # WebACL-level aggregates

    # --- From Detection Tools (config issues) ---
    for tool in detection_tools:
        if tool["status"] == "warning":
            action_items.append({
                "severity": "moderate",
                "rule": tool["rule_name"],
                "text": f"{tool['layer']} in {tool['mode']} mode",
                "suggestion": "Confirm whether this should be switched to Block",
            })
        elif tool["status"] == "missing" and tool["layer"] != "Logging":
            action_items.append({
                "severity": "low",
                "rule": "—",
                "text": f"{tool['layer']} not deployed",
                "suggestion": "Consider deploying for additional protection",
            })
        elif tool["status"] == "missing" and tool["layer"] == "Logging":
            action_items.append({
                "severity": "moderate",
                "rule": "—",
                "text": "WAF logging not configured",
                "suggestion": "Enable CWL logging for IP-level analysis",
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
                # First time this rule mitigated anything
                action_items.append({
                    "severity": "moderate",
                    "rule": rule_name,
                    "text": f"First-time mitigation: {tw_mitigated:,} requests (blocked+challenged)",
                    "suggestion": "Verify this is expected — new attack pattern or new rule deployment?",
                })
            elif lw_mitigated > 0:
                wow = tw_mitigated / lw_mitigated
                if wow >= WOW_SEVERE:
                    action_items.append({
                        "severity": "critical",
                        "rule": rule_name,
                        "text": f"Mitigated requests surged {wow:.0f}x vs last week ({lw_mitigated:,} → {tw_mitigated:,})",
                        "suggestion": "Investigate — possible new attack campaign",
                    })
                elif wow >= WOW_ATTENTION:
                    action_items.append({
                        "severity": "moderate",
                        "rule": rule_name,
                        "text": f"Mitigated requests increased {wow:.1f}x vs last week ({lw_mitigated:,} → {tw_mitigated:,})",
                        "suggestion": "Monitor — check if trend continues",
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
                existing = [a for a in action_items if a["rule"] == rule_name and "surge" in a.get("text", "")]
                if not existing:
                    action_items.append({
                        "severity": "moderate",
                        "rule": rule_name,
                        "text": f"Spike detected: peak day ({spike_date}) was {max_day/avg_day:.1f}x average",
                        "suggestion": "Check if spike correlates with a specific event",
                    })

        # --- Count rule went to zero ---
        if tw_counted == 0 and lw_counted > 100:
            action_items.append({
                "severity": "moderate",
                "rule": rule_name,
                "text": f"Count rule stopped triggering (last week: {lw_counted:,}, this week: 0)",
                "suggestion": "Check if rule was deleted, disabled, or scope-down changed",
            })

        # --- Count rule spiked (potential new attack pattern) ---
        if tw_counted > 100 and lw_counted > 0:
            wow_count = tw_counted / lw_counted
            if wow_count >= WOW_ATTENTION:
                action_items.append({
                    "severity": "moderate",
                    "rule": rule_name,
                    "text": f"Count rule hits increased {wow_count:.1f}x ({lw_counted:,} → {tw_counted:,})",
                    "suggestion": "Review if this rule should be switched to Block",
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
                    "text": f"High mitigation volume: {tw_blocked + tw_challenge + tw_captcha:,} (avg {daily_avg:,.0f}/day)",
                    "suggestion": "Investigate top sources",
                })
            elif daily_avg >= DAILY_BLOCK_ATTENTION:
                action_items.append({
                    "severity": "moderate",
                    "rule": rule_name,
                    "text": f"Elevated mitigation: {tw_blocked + tw_challenge + tw_captcha:,} (avg {daily_avg:,.0f}/day)",
                    "suggestion": "Monitor trend",
                })

    # Sort: critical first, then moderate, then low
    severity_order = {"critical": 0, "moderate": 1, "low": 2}
    action_items.sort(key=lambda x: severity_order.get(x["severity"], 9))
    return action_items


def _get_metric_sum(cw, webacl_name: str, metric: str, rule: str, start, end, region: str = "us-east-1", scope: str = "REGIONAL", period: int = 86400) -> list[float]:
    """Get sums for a metric/rule combination."""
    dimensions = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": rule}]
    if scope != "CLOUDFRONT":
        dimensions.append({"Name": "Region", "Value": region})
    resp = cw.get_metric_data(
        MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric, "Dimensions": dimensions}, "Period": period, "Stat": "Sum"}, "ReturnData": True}],
        StartTime=start, EndTime=end,
    )
    values = resp.get("MetricDataResults", [{}])[0].get("Values", [])
    return values


def _get_metric_timeseries(cw, webacl_name: str, metric: str, rule: str, start, end, region: str = "us-east-1", scope: str = "REGIONAL") -> tuple[list[str], list[float]]:
    """Get 15-min timeseries (timestamps + values) for charts."""
    dimensions = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": rule}]
    if scope != "CLOUDFRONT":
        dimensions.append({"Name": "Region", "Value": region})
    resp = cw.get_metric_data(
        MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric, "Dimensions": dimensions}, "Period": 900, "Stat": "Sum"}, "ReturnData": True}],
        StartTime=start, EndTime=end,
    )
    result = resp.get("MetricDataResults", [{}])[0]
    timestamps = [t.isoformat() for t in result.get("Timestamps", [])]
    values = result.get("Values", [])
    # Sort by timestamp (CloudWatch returns reverse order)
    paired = sorted(zip(timestamps, values))
    if paired:
        timestamps, values = zip(*paired)
        return list(timestamps), [int(v) for v in values]
    return [], []


# Category display names and colors
CATEGORY_META = {
    "web_exploits": {"label": "Web Exploits", "color": "#ef5350"},
    "bot": {"label": "Bot & Automation", "color": "#ffa726"},
    "ddos": {"label": "DDoS", "color": "#ab47bc"},
    "ip_reputation": {"label": "IP Reputation", "color": "#42a5f5"},
    "custom": {"label": "Custom Rules", "color": "#78909c"},
}


def _get_category_timeseries(cw, webacl_name: str, rules: list[dict], start, end, region: str, scope: str) -> dict:
    """Get 1-hour blocked timeseries per category for stacked area chart."""
    # Group rules by category
    category_rules: dict[str, list[str]] = {}
    for rule in rules:
        cat = rule["type"]
        if cat not in category_rules:
            category_rules[cat] = []
        category_rules[cat].append(rule["name"])

    # Collect all timestamps across all rules, then align by timestamp key
    all_timestamps: set[str] = set()
    raw_data: dict[str, dict[str, int]] = {}  # {category: {iso_timestamp: value}}

    for cat, rule_names in category_rules.items():
        cat_data: dict[str, int] = {}
        for rule_name in rule_names:
            dimensions = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": rule_name}]
            if scope != "CLOUDFRONT":
                dimensions.append({"Name": "Region", "Value": region})
            try:
                resp = cw.get_metric_data(
                    MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "BlockedRequests", "Dimensions": dimensions}, "Period": 3600, "Stat": "Sum"}, "ReturnData": True}],
                    StartTime=start, EndTime=end,
                )
                result = resp.get("MetricDataResults", [{}])[0]
                for ts, val in zip(result.get("Timestamps", []), result.get("Values", [])):
                    key = ts.isoformat()
                    all_timestamps.add(key)
                    cat_data[key] = cat_data.get(key, 0) + int(val)
            except Exception:
                continue
        if cat_data:
            raw_data[cat] = cat_data

    # Align all categories to the same sorted timestamp list
    sorted_timestamps = sorted(all_timestamps)
    category_ts = {}
    for cat, cat_data in raw_data.items():
        category_ts[cat] = [cat_data.get(ts, 0) for ts in sorted_timestamps]

    return {"timestamps": sorted_timestamps, "categories": category_ts}


def _get_all_rules_metrics_search(cw, webacl_name: str, start, end, period: int = 86400) -> dict:
    """Get per-rule metrics for all rules using SEARCH (single API call).

    Returns: {rule_name: {blocked: [daily], counted: [daily], challenge: [daily], captcha: [daily]}}
    Also returns 'ALL' key for WebACL-level totals.
    """
    resp = cw.get_metric_data(
        MetricDataQueries=[
            {"Id": "blocked", "Expression": f"SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"BlockedRequests\"', 'Sum', {period})"},
            {"Id": "counted", "Expression": f"SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"CountedRequests\"', 'Sum', {period})"},
            {"Id": "challenge", "Expression": f"SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"ChallengeRequests\"', 'Sum', {period})"},
            {"Id": "captcha", "Expression": f"SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"CaptchaRequests\"', 'Sum', {period})"},
            {"Id": "allowed", "Expression": f"SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" MetricName=\"AllowedRequests\"', 'Sum', {period})"},
        ],
        StartTime=start, EndTime=end, ScanBy="TimestampAscending",
    )

    rules = {}  # {rule_name: {blocked: [...], counted: [...], challenge: [...], captcha: [...], allowed: [...]}}
    metric_map = {"blocked": "blocked", "counted": "counted", "challenge": "challenge", "captcha": "captcha", "allowed": "allowed"}

    for r in resp.get("MetricDataResults", []):
        qid = r["Id"]
        if qid not in metric_map:
            continue
        label = r.get("Label", "")
        # Label format: "{RuleName} {MetricName}" — parse rule name
        parts = label.rsplit(" ", 1)
        rule_name = parts[0] if len(parts) == 2 else label
        values = [int(v) for v in r.get("Values", [])]
        timestamps = [t.isoformat() for t in r.get("Timestamps", [])]

        if rule_name not in rules:
            rules[rule_name] = {"blocked": [], "counted": [], "challenge": [], "captcha": [], "allowed": [], "timestamps": []}
        rules[rule_name][metric_map[qid]] = values
        if timestamps and not rules[rule_name]["timestamps"]:
            rules[rule_name]["timestamps"] = timestamps

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


def _get_all_metrics(cw, webacl_name: str, rules: list[dict], start, end, region: str = "us-east-1", scope: str = "REGIONAL") -> dict:
    """Get Block/Count/Challenge metrics for all rules over the period."""
    results = {}
    for rule in rules:
        name = rule["name"]
        blocked = _get_metric_sum(cw, webacl_name, "BlockedRequests", name, start, end, region, scope)
        counted = _get_metric_sum(cw, webacl_name, "CountedRequests", name, start, end, region, scope)
        results[name] = {
            "blocked_total": int(sum(blocked)),
            "counted_total": int(sum(counted)),
            "blocked_daily": [int(v) for v in blocked],
            "type": rule.get("type", "custom"),
        }
    # WebACL-level challenge metrics
    for metric_pair in [("ChallengeRequests", "challenge_requests"), ("ChallengesSolved", "challenges_solved")]:
        vals = _get_metric_sum(cw, webacl_name, metric_pair[0], "ALL", start, end, region, scope)
        results[metric_pair[1]] = int(sum(vals))
    return results


# Known AMR rule groups and their expected deployment
_EXPECTED_AMRS = {
    "AWSManagedRulesCommonRuleSet": "Web Exploits (CRS)",
    "AWSManagedRulesKnownBadInputsRuleSet": "Known Bad Inputs",
    "AWSManagedRulesBotControlRuleSet": "Bot Control",
    "AWSManagedRulesAntiDDoSRuleSet": "Anti-DDoS",
    "AWSManagedRulesAnonymousIpList": "IP Reputation",
    "AWSManagedRulesAmazonIpReputationList": "IP Reputation (Amazon)",
    "AWSManagedRulesSQLiRuleSet": "SQL Injection",
    "AWSManagedRulesLinuxRuleSet": "Linux OS",
    "AWSManagedRulesAdminProtectionRuleSet": "Admin Protection",
}


def _analyze_detection_tools(webacl_data: dict, logging_type: str, log_dest: str | None) -> list[dict]:
    """Analyze WebACL config to produce Detection Tools Status table.

    Returns list of dicts: {layer, rule_name, mode, status, detail}
    - status: "ok" | "warning" | "missing"
    """
    tools = []
    deployed_amrs = set()

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
                detail = "Override to Count — not actively blocking"
            elif "None" in override:
                mode = "Block"
                status = "ok"
                detail = ""
            else:
                mode = "Block"
                status = "ok"
                detail = ""

            # Check excluded rules
            excluded = mrg.get("ExcludedRules", [])
            if excluded:
                excluded_names = [r.get("Name", "") for r in excluded]
                detail = f"Excluded: {', '.join(excluded_names[:3])}" + (f" +{len(excluded_names)-3} more" if len(excluded_names) > 3 else "")

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
            "AWSManagedRulesAnonymousIpList",
        ):
            tools.append({"layer": layer, "rule_name": "—", "mode": "Not deployed", "status": "missing", "detail": ""})

    # Logging status
    if logging_type == "cwl":
        log_name = log_dest.split(":log-group:")[-1].rstrip(":*") if log_dest else ""
        tools.append({"layer": "Logging", "rule_name": f"CWL: {log_name}", "mode": "—", "status": "ok", "detail": ""})
    elif logging_type == "s3":
        tools.append({"layer": "Logging", "rule_name": "S3/Firehose", "mode": "—", "status": "ok", "detail": "IP-level analysis requires Athena"})
    else:
        tools.append({"layer": "Logging", "rule_name": "—", "mode": "Not configured", "status": "missing", "detail": "Enable logging for detailed analysis"})

    return tools


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


def _get_log_details(logs_client, log_group: str, start: int, end: int, attention_rules: list[str]) -> dict:
    """Query log details for rules that need attention. Parallel execution."""
    details = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for rule_name in attention_rules[:5]:  # max 5 rules
            futures[executor.submit(_query_top_ips_by_rule, logs_client, log_group, start, end, rule_name)] = (rule_name, "ips")
            futures[executor.submit(_query_top_uris_by_rule, logs_client, log_group, start, end, rule_name)] = (rule_name, "uris")
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


def _assess_events(metrics: dict, rules: list[dict], days: int) -> list[dict]:
    """Assess metrics and produce event list with severity."""
    events = []
    for rule in rules:
        name = rule["name"]
        data = metrics.get(name, {})
        if not isinstance(data, dict) or "blocked_total" not in data:
            continue
        blocked = data["blocked_total"]
        counted = data["counted_total"]
        daily_avg = blocked / max(days, 1)
        daily_values = data.get("blocked_daily", [])
        max_day = max(daily_values) if daily_values else 0
        avg_day = sum(daily_values) / len(daily_values) if daily_values else 0
        spike_ratio = max_day / avg_day if avg_day > 0 else 0

        severity = "normal"
        if daily_avg >= DAILY_BLOCK_SEVERE:
            severity = "severe"
        elif daily_avg >= DAILY_BLOCK_ATTENTION:
            severity = "attention"
        elif spike_ratio > 5:
            severity = "attention"

        events.append({
            "rule": name,
            "type": rule["type"],
            "blocked": blocked,
            "counted": counted,
            "daily_avg": round(daily_avg),
            "spike_ratio": round(spike_ratio, 1),
            "severity": severity,
        })

    # Challenge assessment
    challenge_req = metrics.get("challenge_requests", 0)
    challenges_solved = metrics.get("challenges_solved", 0)
    if challenge_req > 0:
        fail_rate = (challenge_req - challenges_solved) / challenge_req
        severity = "normal"
        if fail_rate >= CHALLENGE_FAIL_SEVERE:
            severity = "severe"
        elif fail_rate >= CHALLENGE_FAIL_ATTENTION:
            severity = "attention"
        events.append({
            "rule": "Challenge (all rules)",
            "type": "challenge",
            "blocked": challenge_req - challenges_solved,
            "counted": challenges_solved,
            "daily_avg": round((challenge_req - challenges_solved) / max(days, 1)),
            "fail_rate": round(fail_rate * 100),
            "severity": severity,
        })

    return events


@tool
def patrol_scan(days: int = 7) -> str:
    """Run a comprehensive security patrol scan across all WebACLs.
    Produces a full security event summary for the specified period.

    Use this ONLY when user asks for a patrol report, security summary, or weekly review.
    Do NOT use for specific questions about individual attacks, IPs, or rules.

    Args:
        days: Number of days to scan (default 7).
    """
    from tools.session_state import get_state

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    # 1. Discover WebACLs (CLOUDFRONT + current region)
    global _patrol_chart_data
    _patrol_chart_data = {}
    webacls_info = []
    state = get_state()
    agent_region = state.get("region", "ap-northeast-1") if state else "ap-northeast-1"

    for scope, region in [("CLOUDFRONT", "us-east-1"), ("REGIONAL", agent_region)]:
        try:
            waf = get_client("wafv2", region_name=region)
            resp = waf.list_web_acls(Scope=scope, Limit=100)
            for acl in resp.get("WebACLs", []):
                webacls_info.append({"name": acl["Name"], "id": acl["Id"], "scope": scope, "region": region})
        except Exception:
            continue

    if not webacls_info:
        return "No WebACLs found. Cannot perform patrol scan."

    # 2. Analyze each WebACL
    all_events = []
    webacl_summaries = []

    for acl_info in webacls_info:
        waf = get_client("wafv2", region_name=acl_info["region"])
        try:
            acl_resp = waf.get_web_acl(Name=acl_info["name"], Scope=acl_info["scope"], Id=acl_info["id"])
            webacl_data = acl_resp.get("WebACL", {})
        except Exception:
            webacl_summaries.append({"name": acl_info["name"], "scope": acl_info["scope"], "error": "Failed to get WebACL config"})
            continue

        # Classify rules
        rules = _classify_rules(webacl_data)

        # Check logging
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

        # Get metrics
        cw = get_client("cloudwatch", region_name=acl_info["region"])
        metrics = _get_all_metrics(cw, acl_info["name"], rules, start, end, acl_info["region"], acl_info["scope"])

        # Assess events
        events = _assess_events(metrics, rules, days)

        # Get log details for attention/severe rules (CWL only for now)
        log_details = {}
        attention_rules = [e["rule"] for e in events if e["severity"] in ("attention", "severe") and e["type"] != "challenge"]
        if logging_type == "cwl" and attention_rules:
            log_group = log_dest.split(":log-group:")[-1].rstrip(":*")
            logs_client = get_client("logs", region_name=acl_info["region"])
            log_start = int(start.timestamp())
            log_end = int(end.timestamp())
            log_details = _get_log_details(logs_client, log_group, log_start, log_end, attention_rules)

        # Enrich events with log details
        for event in events:
            if event["rule"] in log_details:
                detail = log_details[event["rule"]]
                ips = detail.get("ips", [])
                if ips:
                    top_ip = ips[0]
                    top_ip_pct = int(top_ip.get("cnt", 0)) / max(event["blocked"], 1)
                    event["top_ip"] = top_ip.get("httpRequest.clientIp", "unknown")
                    event["top_ip_pct"] = round(top_ip_pct * 100)
                    if top_ip_pct >= IP_CONCENTRATION_SEVERE:
                        event["severity"] = "severe"
                    elif top_ip_pct >= IP_CONCENTRATION_ATTENTION and event["severity"] == "normal":
                        event["severity"] = "attention"
                uris = detail.get("uris", [])
                if uris:
                    event["top_uri"] = uris[0].get("httpRequest.uri", "unknown")


        # Collect 15-min timeseries for charts (first WebACL only to limit API calls)
        if not _patrol_chart_data.get("block_ts"):
            _patrol_chart_data["block_ts"] = _get_metric_timeseries(cw, acl_info["name"], "BlockedRequests", "ALL", start, end, acl_info["region"], acl_info["scope"])
            _patrol_chart_data["allow_ts"] = _get_metric_timeseries(cw, acl_info["name"], "AllowedRequests", "ALL", start, end, acl_info["region"], acl_info["scope"])
            _patrol_chart_data["challenge_ts"] = _get_metric_timeseries(cw, acl_info["name"], "ChallengeRequests", "ALL", start, end, acl_info["region"], acl_info["scope"])
            _patrol_chart_data["challenge_solved_ts"] = _get_metric_timeseries(cw, acl_info["name"], "ChallengesSolved", "ALL", start, end, acl_info["region"], acl_info["scope"])
            _patrol_chart_data["category_ts"] = _get_category_timeseries(cw, acl_info["name"], rules, start, end, acl_info["region"], acl_info["scope"])
            _patrol_chart_data["webacl_name"] = acl_info["name"]

        webacl_summaries.append({
            "name": acl_info["name"],
            "scope": acl_info["scope"],
            "region": acl_info["region"],
            "rules_count": len(rules),
            "logging": logging_type,
            "events": events,
            "rule_types": {r["type"] for r in rules},
        })
        all_events.extend([{**e, "webacl": acl_info["name"]} for e in events])

    # 3. Build structured output for LLM
    attention_events = [e for e in all_events if e["severity"] in ("attention", "severe")]
    type_totals = {}
    for e in all_events:
        t = e["type"]
        if t not in type_totals:
            type_totals[t] = {"blocked": 0, "counted": 0}
        type_totals[t]["blocked"] += e.get("blocked", 0)
        type_totals[t]["counted"] += e.get("counted", 0)

    result = f"""## Patrol Scan Complete

**Period**: {start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')} ({days} days)
**WebACLs scanned**: {len(webacl_summaries)}

### Defense Overview (totals across all WebACLs)

| Category | Blocked/Detected | Status |
|----------|-----------------|--------|
"""
    type_names = {"web_exploits": "Web Exploits", "bot": "Bot & Automation", "ddos": "DDoS", "ip_reputation": "IP Reputation", "challenge": "Challenge Failed", "custom": "Custom Rules"}
    for t, totals in sorted(type_totals.items(), key=lambda x: x[1]["blocked"], reverse=True):
        status = "✅ Normal"
        for e in all_events:
            if e["type"] == t and e["severity"] == "severe":
                status = "🔴 Severe"
                break
            elif e["type"] == t and e["severity"] == "attention":
                status = "⚠️ Attention"
        result += f"| {type_names.get(t, t)} | {totals['blocked']:,} | {status} |\n"

    if attention_events:
        result += "\n### Events Requiring Attention\n\n"
        for i, e in enumerate(sorted(attention_events, key=lambda x: x["blocked"], reverse=True)[:10], 1):
            sev = "🔴" if e["severity"] == "severe" else "⚠️"
            result += f"**{i}. [{sev} {type_names.get(e['type'], e['type'])}] {e['rule']}** — {e['blocked']:,} blocked (avg {e['daily_avg']:,}/day)\n"
            if e.get("top_ip"):
                result += f"   - Top source: {e['top_ip']} ({e.get('top_ip_pct', 0)}% of blocks)\n"
            if e.get("top_uri"):
                result += f"   - Top target: {e['top_uri']}\n"
            if e.get("fail_rate"):
                result += f"   - Failure rate: {e['fail_rate']}%\n"
            if e.get("spike_ratio", 0) > 3:
                result += f"   - Spike detected: peak day was {e['spike_ratio']}x average\n"
            result += "\n"
    else:
        result += "\n### No events requiring attention.\n\nAll defense metrics are within normal ranges.\n"

    # WebACL config notes
    no_logging = [s for s in webacl_summaries if s.get("logging") == "none"]
    s3_logging = [s for s in webacl_summaries if s.get("logging") == "s3"]
    if no_logging:
        result += "\n### Configuration Notes\n\n"
        for s in no_logging:
            result += f"- **{s['name']}**: No logging configured. Enable AWS WAF logging for detailed analysis.\n"
    if s3_logging:
        if not no_logging:
            result += "\n### Configuration Notes\n\n"
        for s in s3_logging:
            result += f"- **{s['name']}**: Logs in S3. Detailed IP/URI breakdown requires Athena (not queried in this scan). Use conversation mode for deep investigation.\n"

    result += f"""
---
**Instructions**: Write a natural language security patrol report based on the above data. Include:
1. Executive summary (1-2 sentences: overall status)
2. For each "Attention" or "Severe" event: what happened, source, target, recommendation
3. For normal events: one line summary
4. Configuration recommendations (if any)
5. Conclusion
6. End with a "Need more details?" section with 2-3 example questions the user can ask for deeper investigation

Then call finalize_patrol_report(your_report_markdown) to generate the HTML report.
"""
    return result


@tool
def finalize_patrol_report(report_md: str) -> str:
    """Finalize the security patrol report by rendering it as downloadable HTML.
    MUST be called after patrol_scan with your written report as the argument.

    Args:
        report_md: Your patrol report in Markdown format.
    """
    global _latest_patrol_html

    now = datetime.now(timezone.utc)
    _latest_patrol_html = _render_patrol_html(report_md, now)
    return "Patrol report generated. User can download the full HTML report.\n---\nHints:\nCall ask_user() tool to ask: Would you like to download the patrol report?"


def _render_patrol_html(md: str, generated_at: datetime) -> str:
    """Render patrol report markdown to styled HTML with Chart.js charts."""
    try:
        import markdown
        body = markdown.markdown(md, extensions=["tables", "smarty"])
    except ImportError:
        import html as html_mod
        body = f"<pre>{html_mod.escape(md)}</pre>"

    # Build chart JS
    chart_js = ""
    block_ts = _patrol_chart_data.get("block_ts", ([], []))
    allow_ts = _patrol_chart_data.get("allow_ts", ([], []))
    challenge_ts = _patrol_chart_data.get("challenge_ts", ([], []))
    challenge_solved_ts = _patrol_chart_data.get("challenge_solved_ts", ([], []))
    category_ts = _patrol_chart_data.get("category_ts", {})
    webacl_name = _patrol_chart_data.get("webacl_name", "")

    if block_ts[0]:
        labels_json = json.dumps(block_ts[0])
        blocked_json = json.dumps(block_ts[1])
        allowed_json = json.dumps(allow_ts[1] if allow_ts[0] else [])
        challenge_json = json.dumps(challenge_ts[1] if challenge_ts[0] else [])
        challenge_solved_json = json.dumps(challenge_solved_ts[1] if challenge_solved_ts[0] else [])

        # Category chart data (1-hour granularity)
        cat_labels_json = json.dumps(category_ts.get("timestamps", []))
        cat_datasets_js = ""
        for cat, values in category_ts.get("categories", {}).items():
            meta = CATEGORY_META.get(cat, {"label": cat, "color": "#78909c"})
            cat_datasets_js += f"      {{ label: '{meta['label']}', data: {json.dumps(values)}, borderColor: '{meta['color']}', backgroundColor: '{meta['color']}33', fill: true, tension: 0.3, pointRadius: 0 }},\n"

        chart_js = f"""
<script>
const labels = {labels_json}.map(t => new Date(t).toLocaleString(undefined, {{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}}));
const catLabels = {cat_labels_json}.map(t => new Date(t).toLocaleString(undefined, {{month:'short',day:'numeric',hour:'2-digit'}}));
const c = getComputedStyle(document.documentElement).getPropertyValue('--fg').trim() || '#e0e0e0';
const zoomOpts = {{ zoom: {{ wheel: {{ enabled: true }}, pinch: {{ enabled: true }}, mode: 'x' }}, pan: {{ enabled: true, mode: 'x' }} }};

new Chart(document.getElementById('trafficChart'), {{
  type: 'line',
  data: {{
    labels: labels,
    datasets: [
      {{ label: 'Blocked', data: {blocked_json}, borderColor: '#ef5350', backgroundColor: 'rgba(239,83,80,0.1)', fill: true, tension: 0.3, pointRadius: 0 }},
      {{ label: 'Allowed', data: {allowed_json}, borderColor: '#66bb6a', backgroundColor: 'rgba(102,187,106,0.05)', fill: true, tension: 0.3, pointRadius: 0 }},
    ]
  }},
  options: {{
    responsive: true,
    interaction: {{ mode: 'index', intersect: false }},
    plugins: {{
      title: {{ display: true, text: 'Traffic: Blocked vs Allowed ({webacl_name})', color: c }},
      legend: {{ labels: {{ color: c }} }},
      tooltip: {{ mode: 'index', intersect: false }},
      zoom: zoomOpts
    }},
    scales: {{
      x: {{ ticks: {{ color: c, maxTicksLimit: 28, maxRotation: 45 }} }},
      y: {{ beginAtZero: true, ticks: {{ color: c }}, title: {{ display: true, text: 'Requests per 15 min', color: c }} }}
    }}
  }}
}});

new Chart(document.getElementById('categoryChart'), {{
  type: 'line',
  data: {{
    labels: catLabels,
    datasets: [
{cat_datasets_js}    ]
  }},
  options: {{
    responsive: true,
    interaction: {{ mode: 'index', intersect: false }},
    plugins: {{
      title: {{ display: true, text: 'Threats by Category ({webacl_name})', color: c }},
      legend: {{ labels: {{ color: c }} }},
      tooltip: {{ mode: 'index', intersect: false }},
      zoom: zoomOpts
    }},
    scales: {{
      x: {{ stacked: true, ticks: {{ color: c, maxTicksLimit: 28, maxRotation: 45 }} }},
      y: {{ stacked: true, beginAtZero: true, ticks: {{ color: c }}, title: {{ display: true, text: 'Blocked per hour', color: c }} }}
    }}
  }}
}});

new Chart(document.getElementById('challengeChart'), {{
  type: 'line',
  data: {{
    labels: labels,
    datasets: [
      {{ label: 'Challenge Issued', data: {challenge_json}, borderColor: '#ffa726', backgroundColor: 'rgba(255,167,38,0.1)', fill: true, tension: 0.3, pointRadius: 0 }},
      {{ label: 'Challenge Solved', data: {challenge_solved_json}, borderColor: '#4fc3f7', backgroundColor: 'rgba(79,195,247,0.1)', fill: true, tension: 0.3, pointRadius: 0 }},
    ]
  }},
  options: {{
    responsive: true,
    interaction: {{ mode: 'index', intersect: false }},
    plugins: {{
      title: {{ display: true, text: 'Challenge Effectiveness ({webacl_name})', color: c }},
      legend: {{ labels: {{ color: c }} }},
      tooltip: {{ mode: 'index', intersect: false }},
      zoom: zoomOpts
    }},
    scales: {{
      x: {{ ticks: {{ color: c, maxTicksLimit: 28, maxRotation: 45 }} }},
      y: {{ beginAtZero: true, ticks: {{ color: c }}, title: {{ display: true, text: 'Requests per 15 min', color: c }} }}
    }}
  }}
}});
</script>
"""

    charts_html = ""
    if block_ts[0]:
        charts_html = """
<div class="chart-container">
  <canvas id="trafficChart" height="80"></canvas>
  <div class="chart-note">Data granularity: 15 min | Statistic: Sum (total requests per 15-min window) | Scroll to zoom, drag to pan</div>
</div>
<div class="chart-container">
  <canvas id="categoryChart" height="80"></canvas>
  <div class="chart-note">Data granularity: 1 hour | Stacked area — each color represents a threat category | Scroll to zoom, drag to pan</div>
</div>
<div class="chart-container">
  <canvas id="challengeChart" height="80"></canvas>
  <div class="chart-note">Data granularity: 15 min | Statistic: Sum | Gap between lines = unsolved challenges (likely bots or non-browser clients)</div>
</div>
<hr>
"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Patrol Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1"></script>
<script src="https://cdn.jsdelivr.net/npm/hammerjs@2.0.8"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.2.0"></script>
<style>
:root {{ --bg: #1a1a2e; --fg: #e0e0e0; --accent: #4fc3f7; --card-bg: #16213e; --border: #2a3a5e; --success: #66bb6a; --warning: #ffa726; --danger: #ef5350; }}
body {{ font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); max-width: 1000px; margin: 0 auto; padding: 2rem 1rem; line-height: 1.6; }}
h1 {{ color: var(--accent); border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; }}
h2 {{ color: var(--accent); margin-top: 2rem; }}
h3 {{ color: var(--fg); }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid var(--border); padding: 0.6rem 1rem; text-align: left; }}
th {{ background: var(--card-bg); color: var(--accent); }}
tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
strong {{ color: var(--accent); }}
hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
.chart-container {{ background: var(--card-bg); border-radius: 8px; padding: 1rem; margin: 1.5rem 0; }}
.chart-note {{ color: #888; font-size: 0.75rem; margin-top: 0.5rem; text-align: center; }}
.footer {{ color: #888; font-size: 0.8rem; margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; }}
ul, ol {{ padding-left: 1.5rem; }}
li {{ margin: 0.3rem 0; }}
</style></head><body>
<h1>🛡️ Security Patrol Report</h1>
{charts_html}
{body}
<div class="footer">Generated by AWS WAF Agent · {generated_at.strftime('%Y-%m-%d %H:%M UTC')}</div>
{chart_js}
</body></html>"""
