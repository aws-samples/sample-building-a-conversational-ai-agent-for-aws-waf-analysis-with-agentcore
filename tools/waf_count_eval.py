# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""COUNT-to-BLOCK evaluation workflow tool — guided skill for LLM."""

import json
import time
import os
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_logs_region, get_webacl_name, get_scope, is_log_filter_active
from tools.waf_query import query_logs, get_log_type

# Rules that should NEVER be recommended to switch from Count.
# These have known high false-positive rates in production environments.
PERMANENT_COUNT_RULES = {
    # CRS Body Size Restriction — triggers on legitimate large uploads (file uploads, rich text editors)
    "SizeRestrictions_BODY",
    # Anonymous IP — blocks hosting/cloud provider IPs that include legitimate services (VPNs, corporate proxies)
    "HostingProviderIPList",
    # Bot Control Common — blocks non-browser UAs which include legitimate native apps, SDKs, health checks
    "SignalNonBrowserUserAgent",
}

# Rules with known low false-positive rates — safe to recommend Block without deep log analysis
LOW_FP_RULES = {
    "Log4JRCE", "Log4JRCE_HEADER", "Log4JRCE_QUERYSTRING", "Log4JRCE_BODY", "Log4JRCE_URI",
    "JavaDeserializationRCE_HEADER", "JavaDeserializationRCE_BODY", "JavaDeserializationRCE_QUERYSTRING", "JavaDeserializationRCE_URI",
}


def _run_log_query(query_cwl: str, query_athena: str, start_epoch: int, end_epoch: int, limit: int = 25) -> list[dict]:
    """Execute a log query via unified layer (CWL or Athena). Returns [] on error, raises QueryCapError if Athena cap hit."""
    try:
        results = query_logs(query_cwl, query_athena, start_epoch, end_epoch, limit)
    except Exception:
        return []
    if results is None:
        return []
    if results and isinstance(results[0], dict) and "_error" in results[0]:
        raise QueryCapError(results[0]["_error"])
    return results


class QueryCapError(Exception):
    """Raised when Athena query window cap is hit."""
    pass


def _has_logging() -> bool:
    """Check if any logging (CWL or S3) is configured."""
    return get_log_type() != "none"


@tool
def evaluate_count_rules(step: str = "init", rule_name: str = "", start_time: str = "", duration_hours: float = 1, hours_ago: float = None) -> str:
    """Guided workflow for evaluating whether COUNT rules are ready to switch to BLOCK.

    This is a multi-step skill. Call with step="init" for bulk evaluation (all COUNT rules),
    or jump directly to step="analyze_rule" for a single specific rule.

    Steps:
    - "init": Inventory all COUNT rules, classify them, find peak hour. Returns full assessment plan.
    - "analyze_rule": Deep-dive a specific rule during its peak hour. Requires rule_name. Can be called directly without init.
    - "check_low_volume_clients": Check low-volume clients for a rule (FP signal). Requires rule_name + start_time.

    Args:
        step: Workflow step to execute.
        rule_name: Rule name (required for analyze_rule and check_low_volume_clients).
        start_time: Start time for log queries (required for check_low_volume_clients).
        duration_hours: Duration in hours (default 1, max 6).
    """
    hours_ago = hours_ago if hours_ago is not None else duration_hours
    if step == "init":
        return _step_init(rule_name=rule_name)
    elif step == "analyze_rule":
        if not rule_name:
            return "Error: rule_name is required for step='analyze_rule'."
        return _step_analyze_rule(rule_name)
    elif step == "check_low_volume_clients":
        if not rule_name or not start_time:
            return "Error: rule_name and start_time are required for step='check_low_volume_clients'."
        return _step_check_clients(rule_name, start_time, min(hours_ago, 6))
    else:
        return f"Error: unknown step '{step}'. Available: init, analyze_rule, check_low_volume_clients"


def _step_init(rule_name: str = "") -> str:
    """Step 0+1+2: Inventory COUNT rules, classify, find peak hours.
    If rule_name is provided, only evaluate that specific rule (or comma-separated list)."""

    # If user specified specific rules, filter to just those
    target_rules = set()
    if rule_name:
        target_rules = {r.strip() for r in rule_name.split(",") if r.strip()}

    # Get all COUNT rules from WebACL config
    webacl_name = get_webacl_name()
    scope = get_scope()
    region = get_logs_region()
    waf_region = "us-east-1" if scope == "CLOUDFRONT" else region
    all_count_rules = _get_all_count_rules(waf_region, scope)

    # Filter to target rules if specified
    if target_rules:
        all_count_rules = [r for r in all_count_rules if r in target_rules]
        if not all_count_rules:
            return f"Error: specified rule(s) {target_rules} not found in COUNT mode. Available COUNT rules: use step='init' without rule_name to see all."

    if not all_count_rules:
        return "No COUNT rules found in this WebACL."

    # Get hit counts from CloudWatch Metrics (accurate, works for both CWL and S3 users)
    from datetime import datetime as dt, timedelta, timezone as tz
    from tools.waf_patrol import _get_all_rules_metrics_search
    cw = get_client("cloudwatch", region_name="us-east-1" if scope == "CLOUDFRONT" else region)
    end_dt = dt.now(tz.utc)
    start_dt = end_dt - timedelta(days=14)
    metrics = _get_all_rules_metrics_search(cw, webacl_name, start_dt, end_dt, period=14 * 86400, scope=scope, region=region)

    # Build hit count map from metrics
    found_rules = {}
    for rule_id in all_count_rules:
        rule_metrics = metrics.get(rule_id, {})
        counted = sum(rule_metrics.get("counted", []))
        found_rules[rule_id] = counted

    # Classify rules
    permanent_count = []
    zero_hit = []
    low_fp_nonzero = []
    needs_analysis = []

    for rule_id in all_count_rules:
        hits = found_rules.get(rule_id, 0)
        if rule_id in PERMANENT_COUNT_RULES:
            permanent_count.append((rule_id, hits))
        elif hits == 0:
            zero_hit.append(rule_id)
        elif rule_id in LOW_FP_RULES or any(rule_id.startswith(p) for p in ("CVE_", "CVE-")):
            low_fp_nonzero.append((rule_id, hits))
        else:
            needs_analysis.append((rule_id, hits))

    # For top rule needing analysis, find peak hour (requires logging)
    peak_info = ""
    if needs_analysis and _has_logging() and not is_log_filter_active():
        top_rule = needs_analysis[0][0]
        end_epoch = int(time.time())
        start_epoch = end_epoch - (14 * 86400)
        peak_info = _find_peak_hour(top_rule, start_epoch, end_epoch)

    # Build response
    lines = [
        "## COUNT Rule Evaluation — Inventory Complete",
        f"Analyzed 14 days of CloudWatch Metrics. Found {len(all_count_rules)} COUNT rules total.",
        "",
        "### Step 0: Permanent COUNT (never switch — known high FP)",
    ]
    if permanent_count:
        for r, h in permanent_count:
            lines.append(f"  - {r} ({h:,} hits) — KEEP as Count permanently")
    else:
        lines.append("  (none found)")

    lines.append("")
    lines.append("### Step 1: Zero Hits (safe to switch to default action)")
    if zero_hit:
        for r in zero_hit:
            lines.append(f"  - {r} — 0 hits in 14 days, safe to switch")
    else:
        lines.append("  (all COUNT rules had at least 1 hit)")

    lines.append("")
    lines.append("### Step 2: Low-FP Rules with Hits (safe to switch based on rule-type prior)")
    if low_fp_nonzero:
        for r, h in low_fp_nonzero:
            lines.append(f"  - {r} ({h:,} hits) — known low-FP, safe to switch")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("### Step 3: Rules Requiring Log Analysis (ranked by hit volume)")
    if needs_analysis:
        for r, h in needs_analysis:
            lines.append(f"  - {r} ({h:,} hits)")
    else:
        lines.append("  (none — all rules classified above)")

    lines.append("")
    lines.append("---")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Present the above classification to the user. Then:")
    lines.append("")

    if not needs_analysis:
        lines.append("All rules are classified. No further log analysis needed.")
        lines.append("Summarize recommendations and call record_finding() for each.")
    else:
        lines.append(f"Recommend starting with **{needs_analysis[0][0]}** ({needs_analysis[0][1]:,} hits — highest volume).")
        lines.append("")
        lines.append("**IMPORTANT: Analyze ONE rule at a time.** Do NOT call analyze_rule for multiple rules in parallel.")
        lines.append("After completing one rule, ask the user if they want to continue with the next.")
        if peak_info:
            lines.append(f"\nPeak hour identified: {peak_info}")
            lines.append("")
            lines.append(f"Ask the user: \"I recommend analyzing {needs_analysis[0][0]} during its peak hour ({peak_info}). Proceed?\"")
            lines.append("")
            lines.append(f"When confirmed, call: evaluate_count_rules(step='analyze_rule', rule_name='{needs_analysis[0][0]}')")
        else:
            lines.append("\nCould not determine peak hour. Ask the user for a time window.")
            lines.append(f"When confirmed, call: evaluate_count_rules(step='analyze_rule', rule_name='{needs_analysis[0][0]}')")

    return "\n".join(lines)


def _step_analyze_rule(rule_name: str) -> str:
    """Step 4-5: Find peak hour for this rule, then get client distribution."""
    import re as _re
    rule_name = _re.sub(r"[^a-zA-Z0-9_\-.]", "", rule_name)
    # Step 0 gate: check if this rule should never leave Count
    if rule_name in PERMANENT_COUNT_RULES:
        return (
            f"## Rule: {rule_name} — PERMANENT COUNT\n\n"
            f"This rule is in the permanent-Count list due to known high false-positive rates:\n"
            f"- SizeRestrictions_BODY: triggers on legitimate large uploads (file uploads, rich text)\n"
            f"- HostingProviderIPList: blocks hosting/cloud IPs that include legitimate services\n"
            f"- SignalNonBrowserUserAgent: blocks non-browser UAs including legitimate native apps/SDKs\n\n"
            f"**Recommendation**: Keep as Count. Do NOT switch to Block.\n\n"
            f"---\n## Your Next Action\n"
            f"Tell the user this rule should remain in Count mode and explain why. "
            f"Call record_finding(title='{rule_name} should remain Count', severity='info', "
            f"conclusion='Permanent Count — known high FP rate', evidence='Rule-type prior', "
            f"recommendation='Keep as Count permanently')."
        )

    # Check if it's a known low-FP rule
    if rule_name in LOW_FP_RULES or any(rule_name.startswith(p) for p in ("CVE_", "CVE-")):
        return (
            f"## Rule: {rule_name} — LOW FALSE-POSITIVE\n\n"
            f"This rule has a known low false-positive rate. It targets specific vulnerability signatures "
            f"that legitimate traffic should never match.\n\n"
            f"**Recommendation**: Safe to switch to Block without deep log analysis.\n\n"
            f"---\n## Your Next Action\n"
            f"Tell the user this rule is safe to switch. "
            f"Call record_finding(title='{rule_name} safe to Block', severity='info', "
            f"conclusion='Low-FP rule type — safe to switch', evidence='Rule-type prior', "
            f"recommendation='Switch to Block')."
        )

    if not _has_logging():
        # Give what we can without logs: rule-type prior assessment
        prior = _get_rule_type_prior(rule_name)
        return (
            f"## Rule: {rule_name} — No Logging Available\n\n"
            f"⚠️  Cannot perform log-level analysis (no logging configured).\n\n"
            f"**Rule-type assessment**: {prior}\n\n"
            f"**What I can still check**: Use get_waf_overview(query_type='top_rules') to see this rule's "
            f"hit volume and week-over-week trend. Stable low volume with no spikes suggests low risk.\n\n"
            f"**What I cannot determine without logs**: Whether hits are from legitimate users or attackers, "
            f"IP patterns, URI patterns, false positive signals.\n\n"
            f"## Your Next Action\n"
            f"Tell the user: to make a confident decision on this rule, enable WAF logging. "
            f"In the meantime, here is the best assessment based on available data."
        )

    # Check if log filter might drop COUNT logs
    if is_log_filter_active():
        return (
            f"## Rule: {rule_name} — Log Filter Warning\n\n"
            f"⚠️  A Log Filter is active on this WebACL. COUNT logs may be filtered out.\n"
            f"Log-level analysis for this rule may return 0 results even if the rule has hits.\n\n"
            f"**Attempting query anyway** — if results are empty, this confirms the filter is dropping COUNT logs.\n\n"
            f"## Your Next Action\n"
            f"Cross-validate with get_waf_overview(query_type='top_rules'). If overview shows hits but logs show 0,\n"
            f"tell the user: COUNT logs are being filtered. Cannot perform client-level analysis.\n"
            f"Fall back to rule-type prior assessment only.\n\n"
            f"If you still want to attempt the log query, call:\n"
            f"evaluate_count_rules(step='check_low_volume_clients', rule_name='{rule_name}', start_time='<peak_time>')"
        )

    end_epoch = int(time.time())
    start_epoch = end_epoch - (14 * 86400)

    # Find peak hour
    peak_hour_str = _find_peak_hour(rule_name, start_epoch, end_epoch)
    if not peak_hour_str:
        return (f"Could not find peak hour for rule '{rule_name}'. "
                "The rule may have very sparse hits. Ask the user for a specific time window, "
                "then call evaluate_count_rules(step='check_low_volume_clients', "
                f"rule_name='{rule_name}', start_time='...').")

    # Parse peak hour to epoch
    from tools.waf_logs import _parse_start_time
    peak_epoch = _parse_start_time(peak_hour_str)
    if peak_epoch is None:
        return f"Error parsing peak hour '{peak_hour_str}'."

    # Query: client IP distribution in peak hour (both top and bottom)
    cwl_top = (
        f"filter @message like '{rule_name}' and @message like 'COUNT'"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits desc | limit 10"
    )
    athena_top = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f" GROUP BY httprequest.clientip ORDER BY hits DESC LIMIT 10"
    )
    cwl_bottom = (
        f"filter @message like '{rule_name}' and @message like 'COUNT'"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits asc | limit 10"
    )
    athena_bottom = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f" GROUP BY httprequest.clientip ORDER BY hits ASC LIMIT 10"
    )
    cwl_total = (
        f"filter @message like '{rule_name}' and @message like 'COUNT'"
        " | stats count(*) as total_hits, count_distinct(httpRequest.clientIp) as unique_ips"
    )
    athena_total = (
        f"SELECT count(*) as total_hits, count(DISTINCT httprequest.clientip) as unique_ips"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
    )

    peak_end = peak_epoch + 3600  # 1 hour window
    top_clients = _run_log_query(cwl_top, athena_top, peak_epoch, peak_end, limit=10)
    bottom_clients = _run_log_query(cwl_bottom, athena_bottom, peak_epoch, peak_end, limit=10)
    totals = _run_log_query(cwl_total, athena_total, peak_epoch, peak_end, limit=1)

    total_hits = totals[0].get("total_hits", "?") if totals else "?"
    unique_ips = totals[0].get("unique_ips", "?") if totals else "?"

    lines = [
        f"## Rule Analysis: {rule_name}",
        f"**Peak hour**: {peak_hour_str}",
        f"**Total hits in peak hour**: {total_hits}",
        f"**Unique client IPs**: {unique_ips}",
        "",
        "### High-Volume Clients (likely automation/attack)",
    ]
    if top_clients:
        for r in top_clients:
            lines.append(f"  {r.get('httpRequest.clientIp', '?'):>15}  {r.get('hits', '?'):>6} hits")
    else:
        lines.append("  (no data)")

    lines.append("")
    lines.append("### Low-Volume Clients (check for false positives)")
    if bottom_clients:
        for r in bottom_clients:
            lines.append(f"  {r.get('httpRequest.clientIp', '?'):>15}  {r.get('hits', '?'):>6} hits")
    else:
        lines.append("  (no data)")

    lines.append("")
    lines.append("---")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("**Check low-volume clients first** (higher FP probability):")
    lines.append("For each low-volume client IP, use run_logs_query(query_type='ip_cross_query', ip='...', start_time='...') to check:")
    lines.append("1. Does this IP trigger OTHER rules? (if yes → likely attacker)")
    lines.append("2. Does this IP have ALLOW requests too? (if yes → likely legitimate user with occasional trigger)")
    lines.append("3. What URIs does this IP access? (business URIs = FP signal; sensitive paths = attack signal)")
    lines.append("")
    lines.append("**Then confirm with high-volume clients** (lower FP probability):")
    lines.append("If high-volume clients show >200 req/hour or >50 unique URIs/hour → automation, not FP.")
    lines.append("")
    lines.append("**Conclusion criteria:**")
    lines.append("- ALL low-volume clients show attack signals → safe to Block")
    lines.append("- ANY low-volume client shows FP signals → recommend scope-down exclusion, keep Count for now")
    lines.append("- Mixed signals → ask user for business context on the affected URIs")
    lines.append("")
    lines.append("After concluding, call record_finding() with your assessment, then ask the user if they want to evaluate the next rule.")

    return "\n".join(lines)


def _step_check_clients(rule_name: str, start_time: str, hours_ago: float) -> str:
    """Step 6: Detailed client check for a specific time window."""
    if not _has_logging():
        return "Error: No logging configured. Cannot perform log-level analysis."

    from tools.waf_logs import _parse_start_time
    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'."

    end_epoch = start_epoch + (hours_ago * 3600)

    # Get both ends of client distribution
    cwl_bottom = (
        f"filter @message like '{rule_name}' and @message like 'COUNT'"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits asc | limit 5"
    )
    athena_bottom = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f" GROUP BY httprequest.clientip ORDER BY hits ASC LIMIT 5"
    )
    cwl_top = (
        f"filter @message like '{rule_name}' and @message like 'COUNT'"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits desc | limit 5"
    )
    athena_top = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f" GROUP BY httprequest.clientip ORDER BY hits DESC LIMIT 5"
    )

    try:
        bottom = _run_log_query(cwl_bottom, athena_bottom, start_epoch, end_epoch, limit=5)
        top = _run_log_query(cwl_top, athena_top, start_epoch, end_epoch, limit=5)
    except QueryCapError as e:
        return str(e)

    lines = [
        f"## Client Distribution: {rule_name}",
        f"**Window**: {start_time} + {hours_ago}h",
        "",
        "### Low-Volume Clients (check these for FP first)",
    ]
    if bottom:
        for r in bottom:
            lines.append(f"  {r.get('httpRequest.clientIp', '?'):>15}  {r.get('hits', '?'):>6} hits")
    else:
        lines.append("  (no results — check if Log Filter drops COUNT logs)")

    lines.append("")
    lines.append("### High-Volume Clients (double-confirm)")
    if top:
        for r in top:
            lines.append(f"  {r.get('httpRequest.clientIp', '?'):>15}  {r.get('hits', '?'):>6} hits")
    else:
        lines.append("  (no results)")

    lines.append("")
    lines.append("---")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("For each low-volume client, call run_logs_query(query_type='ip_cross_query', ip='<IP>', start_time='...') to cross-validate.")
    lines.append("Then apply the conclusion criteria from the previous step.")

    return "\n".join(lines)


# Known rule-type priors for no-logging fallback
_RULE_PRIORS = {
    "CrossSiteScripting_BODY": "Medium-high FP rate. Rich text editors and HTML form submissions commonly trigger this. Recommend enabling logging before switching.",
    "CrossSiteScripting_QUERYARGUMENTS": "Medium FP rate. Some web apps pass HTML fragments in query strings. Recommend logging verification.",
    "CrossSiteScripting_COOKIE": "Low-medium FP rate. Less common in legitimate traffic.",
    "SQLi_BODY": "Medium FP rate. JSON payloads with SQL-like syntax can trigger. Recommend logging verification.",
    "SQLi_QUERYARGUMENTS": "Medium FP rate. Search queries and filter parameters can trigger.",
    "SQLi_COOKIE": "Low FP rate. Rarely triggered by legitimate traffic.",
    "GenericLFI_QUERYARGUMENTS": "Medium-high FP rate. File path parameters in legitimate apps trigger this.",
    "GenericLFI_BODY": "Medium FP rate. File upload forms may trigger.",
    "GenericRFI_QUERYARGUMENTS": "Medium-high FP rate. URLs in query parameters trigger this.",
    "GenericRFI_BODY": "Medium FP rate. URLs in POST bodies trigger this.",
    "RestrictedExtensions_QUERYARGUMENTS": "Low-medium FP rate. Depends on application file handling.",
    "EC2MetaDataSSRF_BODY": "Low FP rate. Legitimate traffic rarely contains EC2 metadata paths.",
    "EC2MetaDataSSRF_QUERYARGUMENTS": "Low FP rate. Same as above.",
    "NoUserAgent_HEADER": "Medium FP rate. Health checks, internal services, and some mobile apps omit User-Agent.",
}


def _get_rule_type_prior(rule_name: str) -> str:
    """Return a rule-type prior assessment string."""
    if rule_name in PERMANENT_COUNT_RULES:
        return "Known high-FP rule. Should remain in Count permanently."
    if rule_name in LOW_FP_RULES or any(rule_name.startswith(p) for p in ("CVE_", "CVE-")):
        return "Known low-FP rule. Safe to switch to Block without log analysis."
    if rule_name in _RULE_PRIORS:
        return _RULE_PRIORS[rule_name]
    return "No specific prior available for this rule. Log analysis recommended before switching."


def _find_peak_hour(rule_name: str, start_epoch: int, end_epoch: int) -> str:
    """Find the hour with most hits for a given rule in the time range."""
    cwl = (
        f"filter @message like '{rule_name}' and @message like 'COUNT'"
        " | stats count(*) as hits by bin(1h)"
        " | sort hits desc | limit 1"
    )
    athena = (
        f"SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%dT%H:00') as hour, count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT')"
        f" GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%dT%H:00')"
        f" ORDER BY hits DESC LIMIT 1"
    )
    results = _run_log_query(cwl, athena, start_epoch, end_epoch, limit=1)
    if results:
        # CWL returns "bin(1h)" key, Athena returns "hour" key
        ts = results[0].get("bin(1h)", "") or results[0].get("hour", "")
        if ts:
            # Normalize to YYYY-MM-DDTHH:MM format
            return ts[:16].replace(" ", "T")
    return ""


def _get_all_count_rules(waf_region: str, scope: str) -> list[str]:
    """Get all rule IDs that are in COUNT mode from the WebACL config."""
    webacl_name = get_webacl_name()
    if not webacl_name:
        return []

    waf = get_client("wafv2", region_name=waf_region)
    acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
    match = next((a for a in acls if a["Name"].lower() == webacl_name.lower()), None)
    if not match:
        return []

    resp = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=match["Id"])
    webacl = resp["WebACL"]
    rules = webacl.get("Rules", [])

    count_rules = []
    for r in rules:
        # Custom rules with Count action
        action = r.get("Action", {})
        if "Count" in action:
            count_rules.append(r["Name"])

        # Managed rule groups — check for RuleActionOverrides to Count
        stmt = r.get("Statement", {})
        mgr = stmt.get("ManagedRuleGroupStatement", {})
        if mgr:
            # Entire group overridden to Count
            override_action = r.get("OverrideAction", {})
            if "Count" in override_action:
                count_rules.append(r["Name"])
            # Individual rule overrides within the group
            for rao in mgr.get("RuleActionOverrides", []):
                if "Count" in rao.get("ActionToUse", {}):
                    count_rules.append(rao["Name"])

    return count_rules



