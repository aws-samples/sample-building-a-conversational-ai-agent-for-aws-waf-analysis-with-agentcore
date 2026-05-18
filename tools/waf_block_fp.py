# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Block false positive investigation tool — targeted verification and proactive scan."""

import json
import time
import threading
from strands import tool
from tools.aws_session import get_client
from tools.session_state import (
    get_log_destination, get_logs_region, get_webacl_name, get_scope,
    is_log_filter_active,
)
from tools.waf_query import query_logs, get_log_type

_cwl_semaphore = threading.Semaphore(8)
MAX_POLL = 120
POLL_INTERVAL = 2

CONFIDENCE_RULES = """\
## Confidence Rules
- HIGH: frequency >200/min, zero ALLOW, scanner UA, attack paths → state directly
- PRESENT-ONLY: match detail fragments, URI semantics, encoding → show user, no verdict
- ASK: anything else → "I cannot determine this. [evidence]. Please confirm: ..."
"""


@tool
def investigate_block_fp(step: str = "investigate", ip: str = "", start_time: str = "", hours_ago: int = 6, rule_name: str = "") -> str:
    """Investigate whether a blocked request is a false positive, or proactively scan for suspected FPs.

    This tool provides evidence for human judgment — do not make definitive FP/TP verdicts
    without quantifiable signal support.

    Steps:
    - "investigate": User reports a specific IP being blocked. Collects evidence for that IP.
    - "scan": Proactive audit — find IPs in BLOCK logs that don't look like attackers.

    Args:
        step: "investigate" (targeted) or "scan" (proactive audit).
        ip: Client IP address (required for investigate).
        start_time: Start time for log query (required).
        hours_ago: Duration in hours (default 6, max 6).
        rule_name: Optional — filter to a specific rule.
    """
    from tools.waf_logs import _parse_start_time

    # Validate logging
    if get_log_type() == "none":
        return ("Error: No logging configured (neither CWL nor S3/Firehose). "
                "Cannot investigate block FPs without logs. Enable WAF logging first.")

    if not start_time:
        return "Error: start_time is required. Ask the user which time period to investigate."

    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'."

    hours_ago = min(hours_ago, 6)
    end_epoch = start_epoch + (hours_ago * 3600)

    # Check ALLOW log availability for both steps
    if is_log_filter_active():
        test_cwl = "filter action = 'ALLOW' | stats count(*) as cnt"
        test_athena = "SELECT count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} AND action = 'ALLOW'"
        test_results = _run_query(test_cwl, test_athena, start_epoch, end_epoch)
        allow_count = int(test_results[0].get("cnt", 0)) if test_results else 0
        if allow_count == 0:
            return (
                "## Cannot Proceed — ALLOW Logs Unavailable\n\n"
                "⚠️  A Log Filter is active and ALLOW logs appear to be filtered out (0 ALLOW records found).\n"
                "Without ALLOW data, I cannot compute Allow Ratio — the strongest signal for FP detection.\n\n"
                "**Two paths forward:**\n"
                "1. If you've already confirmed this is a false positive → I can help design a scope-down rule. "
                "Just tell me which rule and URI to exclude.\n"
                "2. If you're unsure → remove the log filter (or add ALLOW to KEEP filters) and observe for 24-48h, "
                "then re-run this analysis.\n\n"
                "I will not guess without data."
            )

    if step == "investigate":
        if not ip:
            return "Error: ip is required for step='investigate'. Ask the user which IP to check."
        return _step_investigate(ip, start_epoch, end_epoch, rule_name)
    elif step == "scan":
        return _step_scan(start_epoch, end_epoch, rule_name)
    else:
        return f"Error: unknown step '{step}'. Available: investigate, scan"


def _step_investigate(ip: str, start_epoch: int, end_epoch: int, rule_name: str) -> str:
    """Targeted investigation of a specific blocked IP."""

    # 1. Find what blocked this IP
    block_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'"
        " | stats count(*) as hits by terminatingRuleId, terminatingRuleType"
        " | sort hits desc | limit 10"
    )
    block_athena = (
        f"SELECT terminatingruleid as \"terminatingRuleId\", terminatingruletype as \"terminatingRuleType\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
        f" AND httprequest.clientip = '{ip}' AND action = 'BLOCK'"
        f" GROUP BY terminatingruleid, terminatingruletype ORDER BY hits DESC LIMIT 10"
    )
    block_results = _run_query(block_cwl, block_athena, start_epoch, end_epoch)

    if not block_results:
        return (f"No BLOCK records found for IP {ip} in this time window.\n"
                "The IP may not have been blocked during this period, or BLOCK logs are filtered.")

    # 2. If managed rule group, find sub-rule
    primary_rule = block_results[0]
    rule_id = primary_rule.get("terminatingRuleId", "?")
    rule_type = primary_rule.get("terminatingRuleType", "?")
    sub_rule = ""

    if rule_type == "MANAGED_RULE_GROUP":
        sub_cwl = (
            f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'"
            " | parse @message /\"ruleGroupList\":\\[.*?\"terminatingRule\":\\{\"ruleId\":\"(?<sub_rule>[^\"]+)\"/"
            " | filter ispresent(sub_rule)"
            " | stats count(*) as hits by sub_rule"
            " | sort hits desc | limit 5"
        )
        sub_athena = (
            f"SELECT rg.terminatingrule.ruleid as sub_rule, count(*) as hits"
            f" FROM {{TABLE}} CROSS JOIN UNNEST(rulegrouplist) AS t(rg)"
            f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
            f" AND httprequest.clientip = '{ip}' AND action = 'BLOCK'"
            f" AND rg.terminatingrule.ruleid IS NOT NULL"
            f" GROUP BY rg.terminatingrule.ruleid ORDER BY hits DESC LIMIT 5"
        )
        sub_results = _run_query(sub_cwl, sub_athena, start_epoch, end_epoch)
        if sub_results:
            sub_rule = sub_results[0].get("sub_rule", "")

    # 3. Allow Ratio
    ratio_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by action"
        " | sort hits desc"
    )
    ratio_athena = (
        f"SELECT action, count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY action ORDER BY hits DESC"
    )
    ratio_results = _run_query(ratio_cwl, ratio_athena, start_epoch, end_epoch)
    action_counts = {r.get("action", ""): int(r.get("hits", 0)) for r in ratio_results}
    allow_count = action_counts.get("ALLOW", 0)
    block_count = action_counts.get("BLOCK", 0)
    total = sum(action_counts.values())

    # 4. Request frequency
    freq_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by bin(1m)"
        " | stats max(hits) as peak_rpm, avg(hits) as avg_rpm"
    )
    freq_athena = (
        f"SELECT max(cnt) as peak_rpm, avg(cnt) as avg_rpm FROM ("
        f"  SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as minute, count(*) as cnt"
        f"  FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
        f"  AND httprequest.clientip = '{ip}'"
        f"  GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i')"
        f")"
    )
    freq_results = _run_query(freq_cwl, freq_athena, start_epoch, end_epoch)
    peak_rpm = freq_results[0].get("peak_rpm", "?") if freq_results else "?"
    avg_rpm = freq_results[0].get("avg_rpm", "?") if freq_results else "?"

    # 5. Multi-rule check
    multi_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action != 'ALLOW'"
        " | stats count(*) as hits by terminatingRuleId"
        " | sort hits desc | limit 10"
    )
    multi_athena = (
        f"SELECT terminatingruleid as \"terminatingRuleId\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
        f" AND httprequest.clientip = '{ip}' AND action != 'ALLOW'"
        f" GROUP BY terminatingruleid ORDER BY hits DESC LIMIT 10"
    )
    multi_results = _run_query(multi_cwl, multi_athena, start_epoch, end_epoch)
    rules_triggered = len(multi_results)

    # 6. URI distribution for blocked requests
    uri_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'"
        " | stats count(*) as hits by httpRequest.uri, httpRequest.httpMethod"
        " | sort hits desc | limit 10"
    )
    uri_athena = (
        f"SELECT httprequest.uri as \"httpRequest.uri\", httprequest.httpmethod as \"httpRequest.httpMethod\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
        f" AND httprequest.clientip = '{ip}' AND action = 'BLOCK'"
        f" GROUP BY httprequest.uri, httprequest.httpmethod ORDER BY hits DESC LIMIT 10"
    )
    uri_results = _run_query(uri_cwl, uri_athena, start_epoch, end_epoch)

    # 7. Match detail (SQLi/XSS only) — CWL only (Athena struct access is complex)
    match_detail = ""
    if sub_rule and ("SQLi" in sub_rule or "XSS" in sub_rule or "CrossSiteScripting" in sub_rule):
        md_cwl = (
            f"filter httpRequest.clientIp = '{ip}' and action = 'BLOCK'"
            " | parse @message /\"terminatingRuleMatchDetails\":\\[(?<md>.*?)\\]/"
            " | filter ispresent(md) and md != ''"
            " | limit 3"
        )
        md_athena = (
            f"SELECT CAST(terminatingrulematchdetails AS VARCHAR) as md"
            f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
            f" AND httprequest.clientip = '{ip}' AND action = 'BLOCK'"
            f" AND cardinality(terminatingrulematchdetails) > 0"
            f" LIMIT 3"
        )
        md_results = _run_query(md_cwl, md_athena, start_epoch, end_epoch)
        if md_results:
            match_detail = "\n".join(r.get("md", "") for r in md_results[:3])

    # 8. Get text transformation config
    text_transforms = _get_text_transformations(rule_id, sub_rule)

    # Build output
    display_rule = f"{sub_rule} (inside {rule_id})" if sub_rule else rule_id
    allow_ratio = f"{allow_count}:{block_count}" if block_count > 0 else f"{allow_count}:0"

    lines = [
        f"## Block FP Investigation: {ip}",
        "",
        f"**Blocked by**: {display_rule}",
        f"**Rule type**: {rule_type}",
        f"**Time window**: {start_epoch} - {end_epoch} (epoch)",
        "",
        "### Quantifiable Signals",
        "",
        f"| Signal | Value | Interpretation |",
        f"| ------ | ----- | -------------- |",
    ]

    # Allow Ratio interpretation
    if allow_count == 0 and block_count > 0:
        ratio_interp = "⚠️ Zero ALLOW — could be attacker OR user blocked on first visit"
    elif allow_count > 0 and allow_count / max(block_count, 1) > 10:
        ratio_interp = "🟡 High ratio — suggests legitimate user occasionally triggering rule"
    else:
        ratio_interp = "Neutral"
    lines.append(f"| Allow Ratio | {allow_ratio} (total {total} requests) | {ratio_interp} |")

    # Frequency interpretation
    try:
        peak_val = float(peak_rpm)
        if peak_val > 200:
            freq_interp = "🔴 Machine speed (>200/min)"
        elif peak_val < 10:
            freq_interp = "🟡 Human speed (<10/min)"
        else:
            freq_interp = "Neutral"
    except (ValueError, TypeError):
        freq_interp = "Unknown"
    lines.append(f"| Peak Frequency | {peak_rpm} req/min (avg {avg_rpm}) | {freq_interp} |")

    # Multi-rule interpretation
    if rules_triggered >= 3:
        multi_interp = "🔴 Triggers ≥3 rules — scanning/probing pattern"
    elif rules_triggered == 1:
        multi_interp = "🟡 Single rule — specific content trigger, not scanning"
    else:
        multi_interp = "Neutral"
    lines.append(f"| Rules Triggered | {rules_triggered} distinct rules | {multi_interp} |")

    # URIs
    lines.append("")
    lines.append("### Blocked Request URIs")
    if uri_results:
        lines.append(f"| {'URI':<35} | {'Method':<6} | {'Hits':>5} |")
        lines.append(f"| {'-'*35} | {'-'*6} | {'-'*5} |")
        for r in uri_results:
            lines.append(f"| {r.get('httpRequest.uri', '?')[:35]:<35} | {r.get('httpRequest.httpMethod', '?'):<6} | {r.get('hits', '?'):>5} |")
    else:
        lines.append("(no URI data)")

    # Match detail
    if match_detail:
        lines.append("")
        lines.append("### Match Detail (raw fragments — do NOT interpret, show to user)")
        if text_transforms:
            lines.append(f"⚠️  Text Transformations applied: {text_transforms}")
            lines.append("→ Fragments below are POST-transformation. Original request content may differ.")
        lines.append(f"```\n{match_detail}\n```")

    # Directional judgment
    lines.append("")
    lines.append("---")
    lines.append("## Directional Judgment")
    lines.append("")

    # Auto-judge only on strong quantifiable signals
    try:
        peak_val = float(peak_rpm)
    except (ValueError, TypeError):
        peak_val = 0

    if allow_count == 0 and peak_val > 200 and rules_triggered >= 3:
        lines.append("**HIGH CONFIDENCE: Not a false positive.**")
        lines.append("Evidence: zero ALLOW, machine-speed frequency, multi-rule scanning pattern.")
    elif allow_count > 0 and allow_count / max(block_count, 1) > 10 and peak_val < 10 and rules_triggered == 1:
        lines.append("**LIKELY FALSE POSITIVE** (needs user confirmation).")
        lines.append(f"Evidence: high Allow Ratio ({allow_ratio}), human-speed frequency, single rule trigger.")
        lines.append("→ Ask user to confirm the blocked URIs are legitimate business paths.")
    else:
        lines.append("**CANNOT DETERMINE** — signals are mixed or insufficient.")
        lines.append(f"Evidence: Allow Ratio {allow_ratio}, frequency {peak_rpm}/min, {rules_triggered} rules triggered.")
        lines.append("→ Need user to verify: are the blocked URIs legitimate? Is this IP a known customer/partner?")

    lines.append("")
    lines.append(CONFIDENCE_RULES)
    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Present the evidence table and directional judgment to the user.")
    lines.append("If LIKELY FP or CANNOT DETERMINE, ask:")
    lines.append("1. \"Are these URIs part of your normal business flow?\"")
    lines.append("2. \"Is this IP a known customer, partner, or internal service?\"")
    lines.append("3. \"Does this endpoint expect content that might look like an attack? (HTML, XML, SQL-like syntax)\"")
    lines.append("")
    lines.append("If user confirms FP → use search_waf_knowledge to help design scope-down exclusion.")
    lines.append("If user confirms NOT FP → call record_finding with 'correct block' conclusion.")

    return "\n".join(lines)


def _step_scan(start_epoch: int, end_epoch: int, rule_name: str) -> str:
    """Proactive scan: find blocked IPs that don't look like attackers."""

    rule_filter_cwl = f" and terminatingRuleId = '{rule_name}'" if rule_name else ""
    rule_filter_athena = f" AND terminatingruleid = '{rule_name}'" if rule_name else ""

    block_cwl = (
        f"filter action = 'BLOCK'{rule_filter_cwl}"
        " | stats count(*) as block_hits by httpRequest.clientIp"
        " | filter block_hits < 10"
        " | sort block_hits asc | limit 25"
    )
    block_athena = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as block_hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
        f" AND action = 'BLOCK'{rule_filter_athena}"
        f" GROUP BY httprequest.clientip HAVING count(*) < 10"
        f" ORDER BY block_hits ASC LIMIT 25"
    )
    block_results = _run_query(block_cwl, block_athena, start_epoch, end_epoch)

    if not block_results:
        return (
            "## Proactive FP Scan — No Candidates Found\n\n"
            "No low-volume blocked IPs found in this time window.\n\n"
            "⚠️  This does NOT guarantee no false positives exist. It means:\n"
            "- No IPs were blocked fewer than 10 times in this window, OR\n"
            "- The time window may not cover the relevant traffic period.\n\n"
            "Consider scanning a different time window (e.g., business hours)."
        )

    # Batch query: get ALLOW counts for all candidate IPs in one query
    candidate_ips = [r.get("httpRequest.clientIp", "") for r in block_results[:10] if r.get("httpRequest.clientIp")]
    if not candidate_ips:
        return (
            "## Proactive FP Scan — No Candidates Found\n\n"
            "No valid IPs in block results.\n"
        )

    ip_list_cwl = " or ".join(f"httpRequest.clientIp = '{ip}'" for ip in candidate_ips)
    ip_list_athena = ", ".join(f"'{ip}'" for ip in candidate_ips)

    allow_cwl = (
        f"filter ({ip_list_cwl}) and action = 'ALLOW'"
        " | stats count(*) as allow_hits by httpRequest.clientIp"
    )
    allow_athena = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as allow_hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}"
        f" AND action = 'ALLOW' AND httprequest.clientip IN ({ip_list_athena})"
        f" GROUP BY httprequest.clientip"
    )
    allow_results = _run_query(allow_cwl, allow_athena, start_epoch, end_epoch)
    allow_map = {r.get("httpRequest.clientIp", ""): int(r.get("allow_hits", 0)) for r in allow_results}

    # Build candidates
    candidates = []
    block_map = {r.get("httpRequest.clientIp", ""): int(r.get("block_hits", 0)) for r in block_results[:10]}
    for ip in candidate_ips:
        allow_hits = allow_map.get(ip, 0)
        block_hits = block_map.get(ip, 0)
        if allow_hits == 0:
            continue
        ratio = allow_hits / max(block_hits, 1)
        if ratio > 5:
            candidates.append({
                "ip": ip,
                "allow": allow_hits,
                "block": block_hits,
                "ratio": f"{ratio:.0f}:1",
            })

    if not candidates:
        return (
            "## Proactive FP Scan — No Candidates Found\n\n"
            "Checked low-volume blocked IPs but none had a high Allow Ratio (>5:1).\n"
            "This suggests blocked traffic is predominantly from dedicated attackers.\n\n"
            "⚠️  This does NOT guarantee no false positives exist — only that none match "
            "the statistical profile of a legitimate user (high ALLOW, low BLOCK).\n\n" +
            CONFIDENCE_RULES
        )

    lines = [
        "## Proactive FP Scan — Candidates Found",
        "",
        f"Found **{len(candidates)}** IPs with high Allow Ratio that were also blocked:",
        "",
        f"| {'IP':<15} | {'ALLOW':>6} | {'BLOCK':>6} | {'Ratio':>7} |",
        f"| {'-'*15} | {'-'*6} | {'-'*6} | {'-'*7} |",
    ]
    for c in candidates:
        lines.append(f"| {c['ip']:<15} | {c['allow']:>6} | {c['block']:>6} | {c['ratio']:>7} |")

    lines.append("")
    lines.append("These IPs have mostly-allowed traffic but occasional blocks — pattern consistent with legitimate users occasionally triggering a rule.")
    lines.append("")
    lines.append("⚠️  **This is NOT confirmation of false positives.** These are candidates that need user verification.")
    lines.append("")
    lines.append("---")
    lines.append(CONFIDENCE_RULES)
    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Present the candidate list to the user. For each candidate, ask:")
    lines.append("1. \"Do you recognize this IP? Is it a customer, partner, or internal service?\"")
    lines.append("2. \"Should I investigate this IP in detail?\" (if yes, call investigate_block_fp(step='investigate', ip='...'))")
    lines.append("")
    lines.append("Do NOT conclude these are false positives without user confirmation.")

    return "\n".join(lines)


def _get_text_transformations(rule_group_name: str, sub_rule_name: str) -> str:
    """Extract text transformation config for a rule from WebACL JSON."""
    webacl_name = get_webacl_name()
    scope = get_scope()
    if not webacl_name:
        return ""

    waf_region = "us-east-1" if scope == "CLOUDFRONT" else get_logs_region()
    waf = get_client("wafv2", region_name=waf_region)

    try:
        acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
        match = next((a for a in acls if a["Name"].lower() == webacl_name.lower()), None)
        if not match:
            return ""
        resp = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=match["Id"])
        rules = resp["WebACL"].get("Rules", [])

        for r in rules:
            stmt = r.get("Statement", {})
            mgr = stmt.get("ManagedRuleGroupStatement", {})
            if mgr and mgr.get("Name", "") in rule_group_name:
                # Managed rule groups don't expose individual rule text transformations via API
                # But we can note the group is managed
                return "(managed rule group — text transformations defined internally by AWS)"

            # Custom rules
            if r.get("Name", "") == rule_group_name:
                transforms = _extract_transforms_from_statement(stmt)
                if transforms:
                    return ", ".join(transforms)
    except Exception:
        pass
    return ""


def _extract_transforms_from_statement(stmt: dict) -> list[str]:
    """Recursively extract text transformations from a rule statement."""
    transforms = []
    # Direct match statements
    for key in ("ByteMatchStatement", "SqliMatchStatement", "XssMatchStatement",
                "SizeConstraintStatement", "RegexMatchStatement", "RegexPatternSetReferenceStatement"):
        if key in stmt:
            for t in stmt[key].get("TextTransformations", []):
                transforms.append(t.get("Type", "NONE"))
            return transforms

    # Nested statements (AND/OR/NOT)
    for key in ("AndStatement", "OrStatement"):
        if key in stmt:
            for sub in stmt[key].get("Statements", []):
                transforms.extend(_extract_transforms_from_statement(sub))
    if "NotStatement" in stmt:
        transforms.extend(_extract_transforms_from_statement(stmt["NotStatement"].get("Statement", {})))

    return transforms


def _run_query(cwl: str, athena: str, start_epoch: int, end_epoch: int) -> list[dict]:
    """Execute log query via unified layer (CWL or Athena)."""
    results = query_logs(cwl, athena, start_epoch, end_epoch, limit=25)
    return results if results is not None else []
