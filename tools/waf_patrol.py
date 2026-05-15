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

# Thresholds for anomaly detection (v1 — absolute, used as cold-start fallback)
DAILY_BLOCK_ATTENTION = 500
DAILY_BLOCK_SEVERE = 5000
IP_CONCENTRATION_ATTENTION = 0.30
IP_CONCENTRATION_SEVERE = 0.60

# WoW anomaly detection thresholds (v2)
WOW_ATTENTION = 3.0   # 3x increase vs last week
WOW_SEVERE = 10.0     # 10x increase
SPIKE_RATIO_ATTENTION = 5.0  # max day / avg day

# Legacy thresholds (used by _assess_events for backward compat)
CHALLENGE_FAIL_ATTENTION = 0.40
CHALLENGE_FAIL_SEVERE = 0.70


def _assess_rules_v2(this_week: dict, last_week: dict, detection_tools: list[dict], ddos_event_windows: list[tuple] | None = None) -> list[dict]:
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
                "text": f"{tool['layer']} in {tool['mode']} mode",
                "suggestion": "Confirm whether this should be switched to Block",
                "source": "config",
            })
        elif tool["status"] == "missing" and tool["layer"] != "Logging":
            action_items.append({
                "severity": "low",
                "rule": "—",
                "text": f"{tool['layer']} not deployed",
                "suggestion": "Consider deploying for additional protection",
                "source": "config",
            })
        elif tool["status"] == "missing" and tool["layer"] == "Logging":
            action_items.append({
                "severity": "moderate",
                "rule": "—",
                "text": "WAF logging not configured",
                "suggestion": "Enable CWL logging for IP-level analysis",
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
                    "text": f"High mitigation volume: {tw_blocked + tw_challenge + tw_captcha:,} (avg {daily_avg:,.0f}/day) (baseline not yet established)",
                    "suggestion": "Investigate top sources",
                })
            elif daily_avg >= DAILY_BLOCK_ATTENTION:
                action_items.append({
                    "severity": "moderate",
                    "rule": rule_name,
                    "text": f"Elevated mitigation: {tw_blocked + tw_challenge + tw_captcha:,} (avg {daily_avg:,.0f}/day) (baseline not yet established)",
                    "suggestion": "Monitor trend",
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
            MetricDataQueries=[{"Id": "evt", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,LabelName,LabelNamespace,WebACL}} WebACL=\"{webacl_name}\" LabelNamespace=\"awswaf:managed:aws:anti-ddos\" LabelName=\"event-detected\"', 'Sum', 86400),0))"}],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        for r in resp.get("MetricDataResults", []):
            return [i for i, v in enumerate(r.get("Values", [])) if v > 0]
    except Exception:
        pass
    return []







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

            # Bot Control: detect inspection level (Common vs Targeted)
            if mrg_name == "AWSManagedRulesBotControlRuleSet":
                inspection_level = "Common"
                for cfg in mrg.get("ManagedRuleGroupConfigs", []):
                    payload = cfg.get("AWSManagedRulesBotControlRuleSet", {})
                    if payload.get("InspectionLevel") == "TARGETED":
                        inspection_level = "Targeted"
                detail = f"{inspection_level} level" + (f"; {detail}" if detail else "")

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


def _get_log_details_athena(log_dest: str, webacl_name: str, scope: str, region: str, start, end, attention_rules: list[str]) -> tuple[dict, str | None]:
    """Query top IPs/URIs via Athena for S3-stored logs. Auto-creates permanent table.

    Returns: (details_dict, table_created_msg or None)
    """
    table_msg = None
    try:
        from tools.waf_athena import _resolve_s3_path, _try_standard_path, _get_account_id, \
            _find_existing_table, _validate_waf_log, _detect_partitions, _create_named_table, \
            _run_athena_select, _athena_state, _ensure_database
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
            storage_template, part_fmt, part_unit = _detect_partitions(s3_path)
            _ensure_database(region, "primary")
            safe_name = _re.sub(r"[^a-zA-Z0-9]", "_", webacl_name).lower()
            full_table = _create_named_table(s3_path, storage_template, part_fmt, part_unit, region, "primary", f"waf_logs_{safe_name}")
            table_msg = f"Created permanent Athena table: {full_table} (reusable for future queries)"
        else:
            # Detect partition format from existing table's S3 path
            _, part_fmt, _ = _detect_partitions(s3_path)

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

        # Query top IPs and URIs per rule (parallel)
        details = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for rule_name in attention_rules[:5]:
                safe_rule = rule_name.replace("'", "''")
                ip_sql = f'SELECT httprequest.clientip AS "httpRequest.clientIp", COUNT(*) AS cnt FROM {full_table} WHERE {time_cond} AND terminatingruleid = \'{safe_rule}\' GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT 5'
                uri_sql = f'SELECT httprequest.uri AS "httpRequest.uri", COUNT(*) AS cnt FROM {full_table} WHERE {time_cond} AND terminatingruleid = \'{safe_rule}\' GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT 5'
                futures[executor.submit(_run_athena_select, ip_sql, region)] = (rule_name, "ips")
                futures[executor.submit(_run_athena_select, uri_sql, region)] = (rule_name, "uris")
            for future in concurrent.futures.as_completed(futures, timeout=120):
                rule_name, qtype = futures[future]
                try:
                    result = future.result()
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



@tool
def patrol_scan(webacl_name: str, scope: str = "CLOUDFRONT", start_time: str = "", hours: int = 24) -> str:
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
    """
    from tools.session_state import get_metrics_region

    # Validate start_time
    if not start_time:
        return "Error: start_time is required. Ask the user which time period to scan.\nExample: patrol_scan(webacl_name=\"...\", start_time=\"2026-05-09\", hours=24)"

    # Parse start_time
    try:
        if "T" in start_time:
            start = datetime.fromisoformat(start_time).replace(tzinfo=timezone.utc)
        else:
            start = datetime.fromisoformat(start_time + "T00:00:00").replace(tzinfo=timezone.utc)
    except ValueError:
        return f"Error: invalid start_time format '{start_time}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM."

    # Cap hours at 24
    hours = min(hours, 24)
    end = start + timedelta(hours=hours)
    start_last = start - timedelta(days=7)  # WoW: same day last week
    end_last = end - timedelta(days=7)

    region = "us-east-1" if scope == "CLOUDFRONT" else get_metrics_region()

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
    detection_tools = _analyze_detection_tools(webacl_data, logging_type, log_dest)

    # 4. Per-rule metrics (this period + same period last week for WoW)
    cw = get_client("cloudwatch", region_name=region)
    this_week_metrics = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=3600)
    last_week_metrics = _get_all_rules_metrics_search(cw, webacl_name, start_last, end_last, period=3600)

    # 5. Challenge/Captcha solved
    challenge_solved, captcha_solved = _get_challenge_solved(cw, webacl_name, scope, region, start, end)

    # 6. DDoS event detection + Action Items
    ddos_windows = _detect_ddos_windows(cw, webacl_name, start, end)
    action_items = _assess_rules_v2(this_week_metrics, last_week_metrics, detection_tools, ddos_windows if ddos_windows else None)

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
    chart_data = None
    try:
        chart_resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "attacks", "Expression": f"SEARCH('{{AWS/WAFV2,Attack,WebACL}} WebACL=\"{webacl_name}\" MetricName=(\"BlockedRequests\" OR \"ChallengeRequests\" OR \"CaptchaRequests\")', 'Sum', 900)"},
                {"Id": "total_m", "Expression": f"SUM(FILL(SEARCH('{{AWS/WAFV2,Rule,WebACL}} WebACL=\"{webacl_name}\" Rule=\"ALL\" MetricName=(\"BlockedRequests\" OR \"ChallengeRequests\" OR \"CaptchaRequests\")', 'Sum', 900),0))"},
            ],
            StartTime=start, EndTime=end, ScanBy="TimestampAscending",
        )
        labels = []
        total_values = []
        attack_raw = {}
        for r in chart_resp.get("MetricDataResults", []):
            if r["Id"] == "total_m":
                labels = [t.strftime("%m/%d %H:%M") for t in r.get("Timestamps", [])]
                total_values = [int(v) for v in r.get("Values", [])]
            elif r["Id"] == "attacks":
                raw_label = r.get("Label", "Unknown")
                atype = raw_label.split(" ")[0] if any(raw_label.endswith(m) for m in ("BlockedRequests", "ChallengeRequests", "CaptchaRequests")) else raw_label
                if atype not in attack_raw:
                    attack_raw[atype] = {}
                for t, v in zip(r.get("Timestamps", []), r.get("Values", [])):
                    k = t.strftime("%m/%d %H:%M")
                    attack_raw[atype][k] = attack_raw[atype].get(k, 0) + int(v)
        if labels:
            series = {a: [ts_map.get(l, 0) for l in labels] for a, ts_map in attack_raw.items()}
            other = [max(0, total_values[i] - sum(s[i] for s in series.values())) for i in range(len(labels))]
            if any(v > 0 for v in other):
                series["Other"] = other
            chart_data = {"labels": labels, "series": series}
    except Exception:
        pass

    # 11. Render HTML
    wr = {
        "name": webacl_name, "scope": scope, "region": region,
        "detection_tools": detection_tools, "action_items": action_items,
        "rules_table": rules_table, "totals": totals, "logging": logging_type,
        "rate_limits": rate_limit_info, "chart_data": chart_data,
    }
    all_action_items = [{**a, "webacl": webacl_name} for a in action_items]
    _latest_patrol_html = _render_patrol_html_v2([wr], all_action_items, start, end, hours)

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

    if table_msg:
        summary += f"\n📋 {table_msg}\n"
    summary += "\nFull HTML report is ready for download."
    return summary


def _render_patrol_html_v2(webacl_results: list, all_action_items: list, start, end, hours: int) -> str:
    """Render deterministic patrol report HTML from structured data."""
    now = datetime.now(timezone.utc)
    n_critical = sum(1 for a in all_action_items if a["severity"] == "critical")
    n_moderate = sum(1 for a in all_action_items if a["severity"] == "moderate")

    if n_critical > 0:
        banner_class = "banner-critical"
        banner_text = f"🔴 {n_critical} critical + {n_moderate} moderate items need attention"
    elif n_moderate > 0:
        banner_class = "banner-warning"
        banner_text = f"⚠️ {n_moderate} items need attention"
    else:
        banner_class = "banner-ok"
        banner_text = "🟢 All systems nominal — no action required"

    # Build sections per WebACL
    webacl_sections = ""
    for wr in webacl_results:
        if "error" in wr:
            webacl_sections += f'<h2>{wr["name"]} ({wr["scope"]})</h2><p class="muted">Error: {wr["error"]}</p>'
            continue

        # Detection Tools table
        dt_rows = ""
        for t in wr["detection_tools"]:
            icon = "✅" if t["status"] == "ok" else "⚠️" if t["status"] == "warning" else "❌"
            detail = f' <span class="muted">({t["detail"]})</span>' if t["detail"] else ""
            dt_rows += f'<tr><td>{icon} {t["layer"]}</td><td>{t["rule_name"]}</td><td>{t["mode"]}{detail}</td></tr>\n'

        # Per-rule table
        rule_rows = ""
        for r in wr["rules_table"]:
            wow_str = f'{r["wow"]:.1f}x' if r["wow"] is not None else "new"
            wow_class = "up" if r["wow"] and r["wow"] > 3 else ""
            # Top IP/URI from log details
            extra = ""
            ld = r.get("log_detail", {})
            if ld.get("ips"):
                ip = ld["ips"][0].get("httpRequest.clientIp", "")
                cnt = ld["ips"][0].get("cnt", "")
                if ip:
                    extra += f'<br><span class="muted">Top IP: {ip} ({cnt})</span>'
            if ld.get("uris"):
                uri = ld["uris"][0].get("httpRequest.uri", "")
                if uri:
                    extra += f'<br><span class="muted">Top URI: {uri}</span>'
            rule_rows += (
                f'<tr><td>{r["name"]}{extra}</td>'
                f'<td>{r["blocked"]:,}</td><td>{r["challenge"]:,}</td>'
                f'<td>{r["captcha"]:,}</td><td>{r["counted"]:,}</td>'
                f'<td class="{wow_class}">{wow_str}</td></tr>\n'
            )

        # Totals
        tot = wr["totals"]
        total_reqs = tot["blocked"] + tot["challenge"] + tot["captcha"] + tot["counted"] + tot["allowed"]
        mitigated = tot["blocked"] + tot["challenge"] + tot["captcha"]

        webacl_sections += f'''
<h2>{wr["name"]} <span class="muted">({wr["scope"]}, {wr["region"]})</span></h2>
<div class="grid">
  <div class="card"><div class="label">Total Requests</div><div class="value">{total_reqs:,}</div></div>
  <div class="card"><div class="label">Mitigated</div><div class="value">{mitigated:,}</div><div class="muted">Block {tot["blocked"]:,} + Challenge {tot["challenge"]:,} + Captcha {tot["captcha"]:,}</div></div>
  <div class="card"><div class="label">Counted</div><div class="value">{tot["counted"]:,}</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value">{tot["allowed"]:,}</div></div>
</div>
<h3>Detection Tools Status</h3>
<table><tr><th>Layer</th><th>Rule</th><th>Mode</th></tr>{dt_rows}</table>
<h3>Per-Rule Breakdown</h3>
<table><tr><th>Rule</th><th>Blocked</th><th>Challenge</th><th>Captcha</th><th>Counted</th><th>WoW</th></tr>{rule_rows}</table>
'''

        # Attack chart
        if wr.get("chart_data") and wr["chart_data"].get("labels"):
            cd = wr["chart_data"]
            colors = {"Volumetric": "#f85149", "BadBots": "#d29922", "XSS": "#e3b341", "GenericLFI": "#a371f7", "KnownBadInputs": "#58a6ff", "Other": "#8b949e"}
            datasets_js = ""
            for atype, values in cd["series"].items():
                color = colors.get(atype, "#79c0ff")
                datasets_js += f'{{label:"{atype}",data:{json.dumps(values)},borderColor:"{color}",backgroundColor:"{color}99",fill:true,tension:0.2,pointRadius:0}},'
            webacl_sections += f'''
<h3>Threats Mitigated by Attack Type</h3>
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;margin:1rem 0">
<canvas id="attackChart_{wr['name'].replace('-','_')}"></canvas>
</div>
<script>
(function(){{const c=getComputedStyle(document.documentElement).getPropertyValue('--fg').trim()||'#e6edf3';
new Chart(document.getElementById('attackChart_{wr["name"].replace("-","_")}'),{{type:'line',data:{{labels:{json.dumps(cd["labels"])},datasets:[{datasets_js}]}},options:{{responsive:true,interaction:{{mode:'index',intersect:false}},plugins:{{legend:{{labels:{{color:c}}}},zoom:{{zoom:{{wheel:{{enabled:true}},mode:'x'}},pan:{{enabled:true,mode:'x'}}}}}},scales:{{x:{{ticks:{{color:c,maxTicksLimit:14}}}},y:{{stacked:true,beginAtZero:true,ticks:{{color:c}}}}}}}}}});}})();
</script>
'''

        # Rate-Limit Effectiveness
        if wr.get("rate_limits"):
            rl_rows = ""
            for rl in wr["rate_limits"]:
                status = "✅ Active" if rl["triggered_days"] > 0 else "⚠️ Never triggered"
                rl_rows += f'<tr><td>{rl["name"]}</td><td>{rl["limit"]:,} / {rl["window"]}s</td><td>{rl["total_blocked"]:,}</td><td>{rl["triggered_days"]}/{hours}h</td><td>{status}</td></tr>\n'
            webacl_sections += f'<h3>Rate-Limit Effectiveness</h3>\n<table><tr><th>Rule</th><th>Threshold</th><th>Total Blocked</th><th>Hours Active</th><th>Status</th></tr>{rl_rows}</table>\n'

    # Action Items section
    action_html = ""
    if all_action_items:
        action_html = '<div class="action-items">'
        for item in all_action_items:
            icon = "🔴" if item["severity"] == "critical" else "⚠️" if item["severity"] == "moderate" else "💡"
            action_html += f'<div class="action-item {item["severity"]}"><strong>{icon} {item["rule"]}</strong>: {item["text"]}<br><span class="muted">→ {item["suggestion"]}</span></div>'
        action_html += "</div>"
    else:
        action_html = '<p class="banner banner-ok">🟢 No action required this week</p>'

    # Embedded JSON for programmatic access
    report_json = json.dumps({
        "version": "1.0",
        "generated_at": now.isoformat(),
        "period": {"start": start.isoformat(), "end": end.isoformat(), "hours": hours},
        "webacls": [{
            "name": wr["name"], "scope": wr.get("scope", ""),
            "action_items": [a for a in all_action_items if a.get("webacl") == wr["name"]],
        } for wr in webacl_results if "error" not in wr],
    }, default=str)

    return f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Patrol Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.5.1"></script>
<script src="https://cdn.jsdelivr.net/npm/hammerjs@2.0.8"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-zoom@2.2.0"></script>
<style>
:root {{ --bg: #0d1117; --fg: #e6edf3; --card: #161b22; --border: #30363d; --accent: #58a6ff; --green: #3fb950; --red: #f85149; --muted: #8b949e; }}
body {{ font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg); max-width: 1100px; margin: 0 auto; padding: 2rem; line-height: 1.6; }}
h1 {{ color: var(--accent); }} h2 {{ color: var(--accent); margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: .3rem; }} h3 {{ margin-top: 1.5rem; }}
.muted {{ color: var(--muted); font-size: .85rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
.card .label {{ color: var(--muted); font-size: .85rem; }} .card .value {{ font-size: 1.5rem; font-weight: 700; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card); border-radius: 6px; overflow: hidden; font-size: .9rem; }}
th {{ background: var(--border); text-align: left; padding: .5rem .7rem; }} td {{ padding: .4rem .7rem; border-top: 1px solid var(--border); }}
.up {{ color: var(--red); font-weight: 600; }}
.banner {{ padding: 1rem; border-radius: 8px; margin: 1rem 0; font-size: 1.1rem; font-weight: 600; }}
.banner-ok {{ background: rgba(63,185,80,0.1); border: 1px solid var(--green); color: var(--green); }}
.banner-warning {{ background: rgba(210,153,34,0.1); border: 1px solid #d29922; color: #d29922; }}
.banner-critical {{ background: rgba(248,81,73,0.1); border: 1px solid var(--red); color: var(--red); }}
.action-items {{ margin: 1rem 0; }} .action-item {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: .8rem 1rem; margin: .5rem 0; }}
.action-item.critical {{ border-left: 3px solid var(--red); }} .action-item.moderate {{ border-left: 3px solid #d29922; }} .action-item.low {{ border-left: 3px solid var(--muted); }}
.footer {{ color: var(--muted); font-size: .8rem; margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; }}
</style></head><body>
<h1>🛡️ Security Patrol Report</h1>
<p class="muted">{start.strftime('%Y-%m-%d')} to {end.strftime('%Y-%m-%d')} ({hours}h) · Generated {now.strftime('%Y-%m-%d %H:%M UTC')}</p>
<p class="muted">CloudWatch Metrics delay: ~5 min. Data may have changed since generation.</p>

<div class="banner {banner_class}">{banner_text}</div>

<h2>Action Items</h2>
{action_html}

{webacl_sections}

<div class="footer">Generated by AWS WAF Agent · {now.strftime('%Y-%m-%d %H:%M UTC')}</div>
<script type="application/json" id="report-data">{report_json}</script>
</body></html>'''

