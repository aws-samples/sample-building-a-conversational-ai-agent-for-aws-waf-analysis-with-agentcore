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

# Thresholds for anomaly detection
DAILY_BLOCK_ATTENTION = 500
DAILY_BLOCK_SEVERE = 5000
IP_CONCENTRATION_ATTENTION = 0.30
IP_CONCENTRATION_SEVERE = 0.60
CHALLENGE_FAIL_ATTENTION = 0.40
CHALLENGE_FAIL_SEVERE = 0.70


def _get_metric_sum(cw, webacl_name: str, metric: str, rule: str, start, end, region: str = "us-east-1", scope: str = "REGIONAL", period: int = 86400) -> list[float]:
    """Get daily sums for a metric/rule combination."""
    dimensions = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": rule}]
    if scope != "CLOUDFRONT":
        dimensions.append({"Name": "Region", "Value": region})
    resp = cw.get_metric_data(
        MetricDataQueries=[{"Id": "m1", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric, "Dimensions": dimensions}, "Period": period, "Stat": "Sum"}, "ReturnData": True}],
        StartTime=start, EndTime=end,
    )
    values = resp.get("MetricDataResults", [{}])[0].get("Values", [])
    return values


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


def _classify_rules(webacl_data: dict) -> list[dict]:
    """Extract and classify rules from WebACL config."""
    rules = []
    for rule in webacl_data.get("Rules", webacl_data.get("rules", [])):
        name = rule.get("Name", rule.get("name", ""))
        stmt = rule.get("Statement", rule.get("statement", {}))
        rule_type = "custom"
        if "ManagedRuleGroupStatement" in stmt or "managed_rule_group_statement" in stmt:
            mrg = stmt.get("ManagedRuleGroupStatement", stmt.get("managed_rule_group_statement", {}))
            mrg_name = mrg.get("Name", mrg.get("name", ""))
            if "CommonRuleSet" in mrg_name or "KnownBadInputs" in mrg_name:
                rule_type = "owasp"
            elif "BotControl" in mrg_name:
                rule_type = "bot"
            elif "AntiDDoS" in mrg_name or "anti-ddos" in mrg_name.lower():
                rule_type = "ddos"
            elif "IpReputation" in mrg_name or "AnonymousIp" in mrg_name:
                rule_type = "ip_reputation"
            else:
                rule_type = "managed_other"
        elif "RateBasedStatement" in stmt or "rate_based_statement" in stmt:
            rule_type = "rate"
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
                    total_from_top = sum(int(r.get("cnt", 0)) for r in ips)
                    top_ip = ips[0] if ips else {}
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
    type_names = {"owasp": "OWASP (SQLi/XSS/LFI)", "bot": "Bot Control", "ddos": "Anti-DDoS", "rate": "Rate Limiting", "ip_reputation": "IP Reputation", "challenge": "Challenge Failed", "custom": "Custom Rules", "managed_other": "Other Managed Rules"}
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
    """Render patrol report markdown to styled HTML."""
    try:
        import markdown
        body = markdown.markdown(md, extensions=["tables", "smarty"])
    except ImportError:
        import html as html_mod
        body = f"<pre>{html_mod.escape(md)}</pre>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Patrol Report</title>
<style>
:root {{ --bg: #1a1a2e; --fg: #e0e0e0; --accent: #4fc3f7; --card-bg: #16213e; --border: #2a3a5e; --success: #66bb6a; --warning: #ffa726; --danger: #ef5350; }}
body {{ font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); max-width: 900px; margin: 0 auto; padding: 2rem 1rem; line-height: 1.6; }}
h1 {{ color: var(--accent); border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; }}
h2 {{ color: var(--accent); margin-top: 2rem; }}
h3 {{ color: var(--fg); }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid var(--border); padding: 0.6rem 1rem; text-align: left; }}
th {{ background: var(--card-bg); color: var(--accent); }}
tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
strong {{ color: var(--accent); }}
hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
.footer {{ color: #888; font-size: 0.8rem; margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; }}
code {{ background: var(--card-bg); padding: 2px 6px; border-radius: 3px; }}
ul, ol {{ padding-left: 1.5rem; }}
li {{ margin: 0.3rem 0; }}
</style></head><body>
<h1>🛡️ Security Patrol Report</h1>
{body}
<div class="footer">Generated by AWS WAF Agent · {generated_at.strftime('%Y-%m-%d %H:%M UTC')}</div>
</body></html>"""
