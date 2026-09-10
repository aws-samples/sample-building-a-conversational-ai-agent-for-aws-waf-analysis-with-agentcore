# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bypass/evasion detection tool — find malicious traffic that WAF is allowing through."""

import re
import sys
import time
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_webacl_name, get_scope, resolve_region, is_log_filter_active
from tools.waf_query import query_logs, log_query_error, get_log_type, run_concurrently
from tools.query_limits import MAX_MINUTES
from tools.static_assets import ATHENA_EXCLUDE_STATIC, CWL_EXCLUDE_STATIC


def _safe_query(cwl: str, athena: str, start: int, end: int, limit: int = 10, *,
                failures: dict | None = None, label: str = "") -> list[dict]:
    """Run a log query, return its rows, and record why if there are none.

    Still never raises, which is what a report assembled from many independent queries
    needs. What it no longer does is destroy the reason: a query that failed and a query
    that matched nothing both arrived as `[]`, and this file renders `[]` as
    `(none found)`, which is a claim about the traffic rather than a report of what we
    know. Measured on 2026-09-10 against a table missing `ja4fingerprint`: two of six
    queries failed with COLUMN_NOT_FOUND and the scan produced a full report asserting no
    bypass candidates, with the errors visible only on stderr.

    Both spellings of failure land here. An **exception** is the Athena path, where
    `_run_athena_select` raises on a stop or an engine failure. An **`_error` row** is the
    CloudWatch path, and passing that through as data was the worse of the two: the row is
    truthy, so a section rendered it as a table row of `?` placeholders, which is a
    fabricated finding rather than a missing one.
    """
    def _record(reason: str) -> list[dict]:
        print(f"[waf_bypass] {label or 'log query'} failed: {reason}",
              file=sys.stderr, flush=True)
        if failures is not None:
            failures[label] = reason
        return []

    try:
        rows = query_logs(cwl, athena, start, end, limit)
    except Exception as e:
        return _record(f"{type(e).__name__}: {e}")
    reason = log_query_error(rows)
    if reason:
        return _record(reason)
    return rows or []


def _empty_reason(failures: dict, label: str, none_text: str = "  (none found)") -> str:
    """The line an empty section shows, which depends on why it is empty.

    Every `none_text` in this file is a statement about the traffic: "(none found)",
    "(not available)", "(no query strings on ALLOW traffic)". A failed query supports no
    statement about the traffic at all, so the two must not read alike.

    **The retry choreography is stripped, and that is the point of the transform.**
    `poll_timeout_message` ends in an `ACTION:` block telling the reader to retry once with a
    quarter of the window, which is written for whoever *chose* the window. Nobody chose this
    one: the tool issues these queries itself with the scan's window. Rendering that advice into
    a section note asks the model to act on a decision it did not make, and on two adjacent slow
    queries in one scan the second message reads "that is 2 timeouts in a row, so narrowing is
    not working", which is a statement about the user's window that the user never set.

    The counter behind that count is shared session state and is still incremented by a chain
    query, so a slow scan can still change what the next user-driven question is told. That half
    needs the poller to know who chose the window, which is ROADMAP 2.1's remaining piece."""
    reason = failures.get(label)
    if reason:
        first = reason.split("\nACTION:")[0].strip()
        return f"  UNKNOWN, the query for this section failed: {first}"
    return none_text

CONFIDENCE_RULES = """\
## Confidence Rules
- HIGH: automation UA + ALLOW, data-center IP + high freq + no bot labels → state directly
- LIKELY: high URI diversity + no bot labels, regular intervals → "probable bot, needs confirmation"
- CANNOT DETERMINE: browser UA + browser JA4 + moderate frequency → ask user
- PRESENT-ONLY: volume trends, IP distribution → show data, user decides if expected
"""

# Anomaly thresholds (hardcoded, not LLM judgment)
WOW_ANOMALY_MODERATE = 2.0
WOW_ANOMALY_SIGNIFICANT = 3.0
UNIQUE_IP_ANOMALY = 2.0


@tool
def detect_bypass(step: str = "scan", ip: str = "", start_time: str = "",
                  duration_minutes: int = 180, ja4: str = "") -> str:
    """Detect potential WAF bypass — find malicious traffic in ALLOW logs.

    This tool provides evidence for human judgment. It does NOT make definitive
    bypass verdicts without quantifiable signal support. For ALLOW traffic it also
    surfaces the top query strings (redacted) as a bypass signal.

    Prerequisite: call get_waf_config first (after selecting the WebACL). This tool
    reads session state populated there; without it scan/investigate_ip error out.

    Steps:
    - "scan": Proactive check — run anomaly filters on ALLOW traffic to find suspicious IPs.
    - "ja4_ips": The IPs behind one JA4 fingerprint from the scan's JA4 tables. Requires ja4.
    - "investigate_ip": Deep-dive a specific IP's behavior in ALLOW logs.
    - "volume_anomaly": Check for traffic volume anomalies (DDoS/scraping indicators).

    Args:
        step: "scan", "ja4_ips", "investigate_ip", or "volume_anomaly".
        ip: Client IP (required for investigate_ip).
        ja4: JA4 fingerprint (required for ja4_ips), copied from the scan's JA4 table.
        start_time: Start time for log queries (required for scan and investigate_ip).
        duration_minutes: Duration in minutes (default 180, max 360 for CWL, 60 for Athena).
    """
    from tools.waf_logs import _parse_start_time

    if step == "volume_anomaly":
        return _step_volume_anomaly()

    # Ensure session state is populated
    if not get_webacl_name():
        return ("Error: No WebACL selected. Call get_waf_config(webacl_name='...') first, "
                "or call list_webacls() to see available WebACLs.")

    # scan and investigate_ip require logging
    if get_log_type() == "none":
        return ("Error: No logging configured for this WebACL. Cannot analyze ALLOW traffic without logs.\n"
                "Enable WAF logging (S3 or CloudWatch Logs) first.\n"
                "For a metrics-only volume check, call detect_bypass(step='volume_anomaly').")
    from tools.waf_query import check_coarse_partition_block
    coarse_err = check_coarse_partition_block()
    if coarse_err:
        return coarse_err

    if is_log_filter_active():
        # Check if ALLOW logs are available
        test_cwl = "filter action = 'ALLOW' | stats count(*) as cnt"
        test_athena = "SELECT count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'ALLOW'"
        if start_time:
            start_epoch = _parse_start_time(start_time)
            if start_epoch:
                end_epoch = start_epoch + min(duration_minutes, 60) * 60
                results = _safe_query(test_cwl, test_athena, start_epoch, end_epoch, limit=1)
                if not results or int(results[0].get("cnt", 0)) == 0:
                    return ("## Cannot Proceed — ALLOW Logs Unavailable\n\n"
                            "⚠️  Log Filter is active and ALLOW logs appear filtered out.\n"
                            "Bypass detection requires ALLOW logs. Remove the filter or add ALLOW to KEEP filters.\n"
                            "For a metrics-only volume check, call detect_bypass(step='volume_anomaly').")

    if not start_time:
        return "Error: start_time is required. Ask the user which time period to analyze."

    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'."

    _duration = min(duration_minutes, MAX_MINUTES)
    end_epoch = min(start_epoch + _duration * 60, int(time.time()))

    if step == "scan":
        return _step_scan(start_epoch, end_epoch)
    elif step == "ja4_ips":
        if not ja4:
            return ("Error: ja4 is required for step='ja4_ips'. Copy a fingerprint from the "
                    "JA4 table in the scan output.")
        return _step_ja4_ips(ja4, start_epoch, end_epoch)
    elif step == "investigate_ip":
        if not ip:
            return "Error: ip is required for step='investigate_ip'. Ask the user which IP to check."
        import ipaddress as _ipa
        try:
            _ipa.ip_address(ip)
        except ValueError:
            return f"Error: invalid IP address '{ip}'"
        return _step_investigate_ip(ip, start_epoch, end_epoch)
    else:
        return (f"Error: unknown step '{step}'. Available: scan, ja4_ips, investigate_ip, "
                f"volume_anomaly")


def _step_ja4_ips(ja4: str, start_epoch: int, end_epoch: int) -> str:
    """The IPs behind one JA4 fingerprint. One query, for one fingerprint the user chose.

    This is the drill-down that used to run eagerly for every candidate the scan found, up to
    ten extra serial queries on top of the scan's six. The measurement that mattered is that
    chain length dominates cost, so the lever is not making each query cheaper but issuing
    fewer of them, and the user almost never wants all ten.

    Splitting it out also fixed a reporting bug the loop had: every iteration recorded its
    failures under the single label `distributed_ips`, so if two fingerprints failed the report
    kept one reason and silently dropped the other."""
    failures: dict[str, str] = {}
    # Reject, do not substitute. `re.sub` of the disallowed characters is injection-safe, since
    # the quotes go, but it then queries a DIFFERENT fingerprint: paste `t13d…h2 ` with a stray
    # character and the report's own header names a fingerprint the user never typed, which
    # reads as authoritative. The two comparable places in this repo already do it this way,
    # `waf_query.py:504` and `waf_patrol.py:593`, both fullmatch-or-refuse before a
    # user-derived string reaches SQL. A legitimate JA4 is alphanumeric with underscores, so
    # this costs a real one nothing.
    # `.strip()` and nothing more. Surrounding whitespace is a paste artifact carrying no
    # information, so removing it recovers the fingerprint the user meant. An INTERIOR
    # stray character changes which fingerprint is named, and that is the case refused.
    safe_ja4 = ja4.strip()
    if not re.fullmatch(r"[0-9a-zA-Z_]+", safe_ja4):
        return (f"Error: '{ja4}' is not a JA4 fingerprint. They are letters, digits and "
                f"underscores only. Copy one from the scan's JA4 table without editing it.")

    cwl = (
        f"filter action = 'ALLOW' and ja4Fingerprint = '{safe_ja4}'"
        f"{CWL_EXCLUDE_STATIC}"
        " and @message not like 'bot:verified'"
        " | stats count(*) as hits by httpRequest.clientIp"
        " | sort hits desc | limit 10"
    )
    athena = (
        f"SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as hits"
        f" FROM {{TABLE}}"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND action = 'ALLOW' AND ja4fingerprint = '{safe_ja4}'"
        f"{ATHENA_EXCLUDE_STATIC}"
        f" AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        f" GROUP BY httprequest.clientip ORDER BY hits DESC LIMIT 10"
    )
    rows = _safe_query(cwl, athena, start_epoch, end_epoch, limit=10,
                       failures=failures, label="ja4_ips")

    lines = [f"## IPs behind JA4 {safe_ja4}", ""]
    if failures:
        lines.append(_empty_reason(failures, "ja4_ips"))
        return "\n".join(lines)
    if not rows:
        lines.append("  (no ALLOW traffic from this fingerprint in this window)")
        lines.append("  The fingerprint came from the scan's window; if you widened or moved the "
                     "window since, use the scan's window here.")
        return "\n".join(lines)

    lines.append(f"| {'IP':<15} | {'Requests':>8} |")
    lines.append(f"| {'-'*15} | {'-'*8} |")
    for r in rows:
        lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('hits', '?'):>8} |")
    lines.append("")
    lines.append("→ Pick one and call detect_bypass(step='investigate_ip', ip='<IP>') for its "
                 "behaviour, labels and query strings.")
    return "\n".join(lines)


def _step_volume_anomaly() -> str:
    """Metrics-based volume anomaly detection. No logs needed."""
    webacl_name = get_webacl_name()
    if not webacl_name:
        return "Error: No WebACL configured. Call get_waf_config first."

    scope = get_scope()
    region = resolve_region(scope)
    cw = get_client("cloudwatch", region_name=region)

    from tools.waf_patrol import _get_all_rules_metrics_search

    # This week vs last week (7 days each)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)
    prev_start = start - timedelta(days=7)

    this_week = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=7 * 86400, scope=scope, region=region)
    last_week = _get_all_rules_metrics_search(cw, webacl_name, prev_start, start, period=7 * 86400, scope=scope, region=region)

    # Extract totals
    tw_all = this_week.get("ALL", {})
    lw_all = last_week.get("ALL", {})
    tw_allowed = sum(tw_all.get("allowed", []))
    lw_allowed = sum(lw_all.get("allowed", []))
    tw_blocked = sum(tw_all.get("blocked", [])) + sum(tw_all.get("challenge", [])) + sum(tw_all.get("captcha", []))
    lw_blocked = sum(lw_all.get("blocked", [])) + sum(lw_all.get("challenge", [])) + sum(lw_all.get("captcha", []))

    wow_allowed = tw_allowed / max(lw_allowed, 1)
    wow_blocked = tw_blocked / max(lw_blocked, 1)

    # Check Anti-DDoS event
    antiddos_detected = False
    try:
        evt_resp = cw.get_metric_data(
            MetricDataQueries=[
                {"Id": "raw_evt", "MetricStat": {"Metric": {"Namespace": "AWS/WAFV2", "MetricName": "ChallengeRequests",
                    "Dimensions": [{"Name": "WebACL", "Value": webacl_name},
                                   {"Name": "LabelNamespace", "Value": "awswaf:managed:aws:anti-ddos"},
                                   {"Name": "LabelName", "Value": "event-detected"}]}, "Period": 86400, "Stat": "Sum"}, "ReturnData": False},
                {"Id": "evt", "Expression": "FILL(raw_evt,0)"},
            ],
            StartTime=start, EndTime=end,
        )
        for r in evt_resp.get("MetricDataResults", []):
            if sum(r.get("Values", [])) > 0:
                antiddos_detected = True
    except Exception:
        pass

    # Build output
    lines = [
        "## Volume Anomaly Analysis",
        f"**Period**: last 7 days vs previous 7 days",
        f"**WebACL**: {webacl_name}",
        "",
        "### Traffic Comparison",
        f"| Metric | This Week | Last Week | WoW Ratio |",
        f"| ------ | --------- | --------- | --------- |",
        f"| ALLOW | {tw_allowed:,.0f} | {lw_allowed:,.0f} | {wow_allowed:.1f}x |",
        f"| Mitigated (Block+Challenge+Captcha) | {tw_blocked:,.0f} | {lw_blocked:,.0f} | {wow_blocked:.1f}x |",
        "",
    ]

    if antiddos_detected:
        lines.append("⚠️  **Anti-DDoS event-detected label appeared this week** — DDoS event was active.")
        lines.append("")

    # Classify
    if wow_allowed < WOW_ANOMALY_MODERATE:
        lines.append("### Assessment: No Significant Volume Anomaly")
        lines.append(f"ALLOW traffic is {wow_allowed:.1f}x last week — within normal range.")
        lines.append("")
        lines.append("## Your Next Action")
        lines.append("If user still suspects bypass, run detect_bypass(step='scan', start_time='...') for per-IP analysis.")
    elif wow_allowed < WOW_ANOMALY_SIGNIFICANT:
        lines.append("### Assessment: Moderate Increase")
        lines.append(f"ALLOW traffic is {wow_allowed:.1f}x last week. Could be legitimate growth or early-stage attack.")
        lines.append("")
        lines.append("## Your Next Action")
        lines.append("Ask user: \"Is this expected growth (marketing campaign, product launch, seasonal event)?\"")
        lines.append("If unexpected → run detect_bypass(step='scan', start_time='...') to identify suspicious IPs.")
    else:
        lines.append("### Assessment: Significant Anomaly")
        lines.append(f"⚠️  ALLOW traffic is **{wow_allowed:.1f}x** last week — significant deviation from baseline.")
        lines.append("")
        lines.append("**Preliminary classification (from metrics only):**")
        if antiddos_detected:
            lines.append("- Anti-DDoS event detected → DDoS attack confirmed by AMR")
        if wow_blocked > WOW_ANOMALY_SIGNIFICANT:
            lines.append(f"- Mitigated traffic also spiked ({wow_blocked:.1f}x) → WAF IS catching some of it")
        else:
            lines.append(f"- Mitigated traffic did NOT spike ({wow_blocked:.1f}x) → traffic is bypassing WAF rules")
        lines.append("")
        lines.append("**To classify attack type, ask user for a time window then call detect_bypass(step='scan').**")
        lines.append("The scan will determine IP distribution and URI patterns to distinguish:")
        lines.append("- IP distribution FLAT + URI concentrated → Classic distributed DDoS")
        lines.append("  → Recommend: Anti-DDoS AMR, rate-based rules")
        lines.append("- IP distribution FLAT + URI diversity HIGH (random paths) → Cache-bypass DDoS")
        lines.append("  → Recommend: Cache 403/404 in CloudFront, rate-based rule, Anti-DDoS AMR")
        lines.append("- IP distribution CONCENTRATED + URI diversity HIGH → Scraper/crawler")
        lines.append("  → Recommend: Bot Control (Targeted), custom rate-based rule")

    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Always ask: \"Is this expected traffic growth (marketing campaign, product launch, seasonal event)?\"")
    lines.append("If user confirms unexpected → ask which day/hour was worst, then call detect_bypass(step='scan', start_time='...', duration_minutes=60).")
    lines.append("Use a 1-2 hour window around the peak for best signal-to-noise ratio.")

    lines.append("")
    lines.append(CONFIDENCE_RULES)
    return "\n".join(lines)


def _step_scan(start_epoch: int, end_epoch: int) -> str:
    """Proactive scan: find suspicious IPs in ALLOW traffic."""

    # Why a section is empty, keyed by the section. Six sections render an empty
    # list as "(none found)", which is a claim about the traffic, so a failed query
    # has to be told apart from a query that matched nothing.
    failures: dict[str, str] = {}

    # ROADMAP 4.6. The six anomaly filters are independent: none reads another's output, so
    # the serial chain's wall time was the sum for no reason. Each is registered here as a
    # thunk and they all start together below.
    #
    # Deferred in place rather than by hoisting the six query strings to the top. Moving them
    # would be a hundred-line diff whose review burden is entirely in the movement, and the
    # queries read better next to the comment explaining what each one looks for.
    jobs: dict[str, object] = {}

    def later(label: str, cwl: str, athena: str, limit: int = 10):
        """Queue one independent query. Nothing runs until `run_concurrently` below.

        `_safe_query` is what makes the fan-out safe to write this way: it never raises, and
        it records its own reason under `label`, so six threads write six distinct keys of
        `failures`. Distinct-key dict assignment is atomic under the GIL, so no lock is
        needed here; a job that MUTATED a shared value would need one."""
        jobs[label] = lambda: _safe_query(cwl, athena, start_epoch, end_epoch, limit=limit,
                                          failures=failures, label=label)

    # 0. Quick coverage check (config-based) + WoW volume check
    coverage_gaps = _check_coverage_gaps()

    # Check WoW — if 3x+ spike, suggest volume_anomaly first
    wow_note = ""
    try:
        webacl_name = get_webacl_name()
        scope = get_scope()
        region = resolve_region(scope)
        cw = get_client("cloudwatch", region_name=region)
        from tools.waf_patrol import _get_all_rules_metrics_search
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=7)
        prev_dt = start_dt - timedelta(days=7)
        tw = _get_all_rules_metrics_search(cw, webacl_name, start_dt, end_dt, period=7*86400, scope=scope, region=region)
        lw = _get_all_rules_metrics_search(cw, webacl_name, prev_dt, start_dt, period=7*86400, scope=scope, region=region)
        tw_a = sum(tw.get("ALL", {}).get("allowed", []))
        lw_a = sum(lw.get("ALL", {}).get("allowed", []))
        wow = tw_a / max(lw_a, 1)
        if wow >= WOW_ANOMALY_SIGNIFICANT:
            wow_note = (f"⚠️  ALLOW traffic is {wow:.1f}x last week (significant spike). "
                        f"Consider calling detect_bypass(step='volume_anomaly') for aggregate analysis first.")
    except Exception:
        pass

    # 1. Run anomaly filters (exclusions built into queries)
    crawlers_cwl = (
        "filter action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " and @message not like 'bot:verified'"
        " | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp"
        " | filter unique_uris > 50"
        " | sort unique_uris desc | limit 10"
    )
    crawlers_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total,"
        " count(DISTINCT httprequest.uri) as unique_uris"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY httprequest.clientip"
        " HAVING count(DISTINCT httprequest.uri) > 50"
        " ORDER BY unique_uris DESC LIMIT 10"
    )

    repeaters_cwl = (
        "filter action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " and @message not like 'bot:verified'"
        " | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp"
        " | filter total > 200 and unique_uris < 10"
        " | sort total desc | limit 10"
    )
    repeaters_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total,"
        " count(DISTINCT httprequest.uri) as unique_uris"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY httprequest.clientip"
        " HAVING count(*) > 200 AND count(DISTINCT httprequest.uri) < 10"
        " ORDER BY total DESC LIMIT 10"
    )

    # Data-center IPs not caught by Bot Control
    datacenter_cwl = (
        "filter action = 'ALLOW' and @message like 'known_bot_data_center'"
        " and @message not like 'bot:verified' and @message not like 'bot:unverified'"
        " | stats count(*) as total by httpRequest.clientIp"
        " | filter total > 50"
        " | sort total desc | limit 10"
    )
    datacenter_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND any_match(labels, l -> l.name LIKE '%known_bot_data_center%')"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:unverified%') )"
        " GROUP BY httprequest.clientip HAVING count(*) > 50"
        " ORDER BY total DESC LIMIT 10"
    )

    later("crawlers", crawlers_cwl, crawlers_athena)
    later("repeaters", repeaters_cwl, repeaters_athena)
    later("datacenter", datacenter_cwl, datacenter_athena)

    # Automation UA filter (curl, python-requests, wget, etc. that are ALLOW'd)
    auto_ua_cwl = (
        "filter action = 'ALLOW'"
        " | parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}/"
        " | filter ua like /(?i)(curl|python-requests|wget|httpie|go-http-client|java\\/|okhttp|libwww-perl)/"
        " | stats count(*) as total by httpRequest.clientIp, ua"
        " | filter total > 10"
        " | sort total desc | limit 10"
    )
    auto_ua_athena = (
        "SELECT httprequest.clientip as \"httpRequest.clientIp\","
        " element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value as ua,"
        " count(*) as total"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND regexp_like(element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value,"
        " '(?i)(curl|python-requests|wget|httpie|go-http-client|java/|okhttp|libwww-perl)')"
        " GROUP BY httprequest.clientip,"
        " element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value"
        " HAVING count(*) > 10"
        " ORDER BY total DESC LIMIT 10"
    )
    later("auto_ua", auto_ua_cwl, auto_ua_athena)

    # Single tool distributed across many IPs (JA4 aggregation)
    # Require high URI diversity per JA4 to filter out normal browser traffic sharing common fingerprints
    distributed_cwl = (
        "filter action = 'ALLOW' and ispresent(ja4Fingerprint) and ja4Fingerprint != ''"
        f"{CWL_EXCLUDE_STATIC}"
        " and @message not like 'bot:verified'"
        " | stats count(*) as total, count_distinct(httpRequest.clientIp) as unique_ips,"
        " count_distinct(httpRequest.uri) as unique_uris by ja4Fingerprint"
        " | filter unique_ips > 10 and total > 500 and unique_uris > 50"
        " | sort total desc | limit 10"
    )
    distributed_athena = (
        "SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as total,"
        " count(DISTINCT httprequest.clientip) as unique_ips,"
        " count(DISTINCT httprequest.uri) as unique_uris"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND ja4fingerprint IS NOT NULL AND ja4fingerprint != ''"
        f"{ATHENA_EXCLUDE_STATIC}"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY ja4fingerprint"
        " HAVING count(DISTINCT httprequest.clientip) > 10 AND count(*) > 500"
        " AND count(DISTINCT httprequest.uri) > 50"
        " ORDER BY total DESC LIMIT 10"
    )
    later("distributed", distributed_cwl, distributed_athena)

    # The per-JA4 drill-down loop used to live here: one extra query per candidate, capped
    # at 10, so a scan issued up to 16 serial Athena queries. The full-chain measurement found
    # the dominant cost is the NUMBER of queries run back to back rather than the partition
    # layout, and this loop was the unbounded part of it, firing hardest at production volume
    # where diverse fingerprints actually qualify. It is now `step="ja4_ips"`, one query for one
    # fingerprint the user picked, which bounds the chain by construction instead of by a cap.
    # UA rotation: one TLS fingerprint (JA4) behind many different User-Agents.
    # A real client has a stable UA per TLS stack; many UAs on a single JA4 means
    # one client faking multiple browsers (UA spoofing/rotation). JA4 is much
    # harder to forge than the UA string, so this is a low-false-positive signal.
    # Keep unique_ips low to avoid flagging large NAT/CDN egress points that
    # legitimately share a JA4 across many real users.
    ua_rotation_cwl = (
        "filter action = 'ALLOW' and ispresent(ja4Fingerprint) and ja4Fingerprint != ''"
        " and @message not like 'bot:verified'"
        " | parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}/"
        " | stats count(*) as total, count_distinct(ua) as unique_uas,"
        " count_distinct(httpRequest.clientIp) as unique_ips by ja4Fingerprint"
        " | filter unique_uas > 5 and unique_ips < 5"
        " | sort unique_uas desc | limit 10"
    )
    ua_rotation_athena = (
        "SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as total,"
        " count(DISTINCT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value) as unique_uas,"
        " count(DISTINCT httprequest.clientip) as unique_ips"
        " FROM {TABLE}"
        " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
        " AND action = 'ALLOW'"
        " AND ja4fingerprint IS NOT NULL AND ja4fingerprint != ''"
        " AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )"
        " GROUP BY ja4fingerprint"
        " HAVING count(DISTINCT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value) > 5"
        " AND count(DISTINCT httprequest.clientip) < 5"
        " ORDER BY unique_uas DESC LIMIT 10"
    )
    later("ua_rotation", ua_rotation_cwl, ua_rotation_athena)

    # All six at once. `reasons` carries the labels that never answered inside the batch
    # budget, which is a THIRD way to have no rows alongside "failed" and "matched
    # nothing", and it has to reach the section note or a batch timeout renders as
    # "(none found)", the exact wrong answer 0.17.0 removed from the other two paths.
    results, reasons = run_concurrently(jobs)
    failures.update(reasons)
    crawlers = results.get("crawlers") or []
    repeaters = results.get("repeaters") or []
    datacenter = results.get("datacenter") or []
    auto_ua = results.get("auto_ua") or []
    distributed = results.get("distributed") or []
    ua_rotation = results.get("ua_rotation") or []

    # Build output
    lines = ["## Bypass Scan Results", ""]

    if wow_note:
        lines.append(wow_note)
        lines.append("")

    if coverage_gaps:
        lines.append("### Coverage Gaps Detected")
        for gap in coverage_gaps:
            lines.append(f"  - {gap}")
        lines.append("")

    lines.append("### High URI Diversity (probable scrapers/crawlers)")
    if crawlers:
        lines.append(f"| {'IP':<15} | {'Requests':>8} | {'Unique URIs':>11} |")
        lines.append(f"| {'-'*15} | {'-'*8} | {'-'*11} |")
        for r in crawlers:
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('total', '?'):>8} | {r.get('unique_uris', '?'):>11} |")
    else:
        lines.append(_empty_reason(failures, "crawlers"))

    lines.append("")
    lines.append("### High Frequency + Low URI Diversity (endpoint hammering)")
    if repeaters:
        lines.append(f"| {'IP':<15} | {'Requests':>8} | {'Unique URIs':>11} |")
        lines.append(f"| {'-'*15} | {'-'*8} | {'-'*11} |")
        for r in repeaters:
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('total', '?'):>8} | {r.get('unique_uris', '?'):>11} |")
    else:
        lines.append(_empty_reason(failures, "repeaters"))

    lines.append("")
    lines.append("### Data-Center IPs Not Caught by Bot Control")
    if datacenter:
        lines.append(f"| {'IP':<15} | {'Requests':>8} |")
        lines.append(f"| {'-'*15} | {'-'*8} |")
        for r in datacenter:
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {r.get('total', '?'):>8} |")
        lines.append("  (signal:known_bot_data_center label present but not classified as bot)")
    else:
        lines.append(_empty_reason(failures, "datacenter"))

    lines.append("")
    lines.append("### Automation User-Agents Allowed Through")
    if auto_ua:
        lines.append(f"| {'IP':<15} | {'UA':<30} | {'Requests':>8} |")
        lines.append(f"| {'-'*15} | {'-'*30} | {'-'*8} |")
        for r in auto_ua:
            lines.append(f"| {r.get('httpRequest.clientIp', '?'):<15} | {str(r.get('ua', '?'))[:30]:<30} | {r.get('total', '?'):>8} |")
    else:
        lines.append(_empty_reason(failures, "auto_ua"))

    lines.append("")
    lines.append("### Single Tool Distributed Across Many IPs (JA4 aggregation)")
    if distributed:
        lines.append(f"| {'JA4 Fingerprint':<34} | {'Requests':>8} | {'Unique IPs':>10} | {'Unique URIs':>11} |")
        lines.append(f"| {'-'*34} | {'-'*8} | {'-'*10} | {'-'*11} |")
        for r in distributed:
            lines.append(f"| {r.get('ja4Fingerprint', '?'):<34} | {r.get('total', '?'):>8} | {r.get('unique_ips', '?'):>10} | {r.get('unique_uris', '?'):>11} |")
        lines.append("  ⚠️  Candidate signal: single TLS fingerprint + high URI diversity across many IPs. Needs IP-level investigation to confirm.")
        lines.append("  → Ask the user which fingerprint to look at, then call "
                     "detect_bypass(step='ja4_ips', ja4='<fingerprint>') for the IPs behind it, "
                     "then investigate_ip on one of those. Do NOT walk the whole table: each "
                     "fingerprint costs a query and the user rarely wants all of them.")
    else:
        lines.append(_empty_reason(failures, "distributed"))

    lines.append("")
    lines.append("### UA Rotation — Single JA4 Behind Many User-Agents (UA spoofing)")
    if ua_rotation:
        lines.append(f"| {'JA4 Fingerprint':<34} | {'Requests':>8} | {'Unique UAs':>10} | {'Unique IPs':>10} |")
        lines.append(f"| {'-'*34} | {'-'*8} | {'-'*10} | {'-'*10} |")
        for r in ua_rotation:
            lines.append(f"| {r.get('ja4Fingerprint', '?'):<34} | {r.get('total', '?'):>8} | {r.get('unique_uas', '?'):>10} | {r.get('unique_ips', '?'):>10} |")
        lines.append("  ⚠️  Candidate signal: one TLS fingerprint faking many User-Agents from few IPs. JA4 is hard to forge, so this is a strong UA-spoofing indicator. Needs IP-level investigation to confirm.")
        lines.append("  → This section has no IPs in it, so do not invent one: call "
                     "detect_bypass(step='ja4_ips', ja4='<fingerprint>') first, then "
                     "investigate_ip on one of the IPs it returns.")
    else:
        lines.append(_empty_reason(failures, "ua_rotation"))

    if not crawlers and not repeaters and not datacenter and not auto_ua and not distributed and not ua_rotation:
        lines.append("")
        if failures:
            # The emptiness guard, and it is the whole point of recording the reasons.
            # Every section came back empty and at least one query failed, so this scan
            # supports no verdict at all. Reporting it as clean is the wrong answer that
            # was shipping: on 2026-09-10 two failed queries produced exactly this block.
            lines.append("### Cannot Say Whether Bypass Candidates Exist")
            lines.append(f"Every section is empty and {len(failures)} of this scan's log "
                         f"queries failed ({', '.join(sorted(failures))}), so there is no "
                         f"evidence either way.")
            lines.append("Tell the user the scan did not complete and do NOT report it as clean.")
        else:
            lines.append("### No Obvious Bypass Candidates Found")
            lines.append("No IPs matched the anomaly filters in this time window.")
            lines.append("⚠️  This does NOT guarantee no bypass exists — only that no IP exceeded the detection thresholds.")

    lines.append("")
    lines.append("---")
    lines.append(CONFIDENCE_RULES)
    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    if crawlers or repeaters or datacenter or auto_ua or distributed or ua_rotation:
        lines.append("Present candidates to user. For each:")
        lines.append("- HIGH CONFIDENCE candidates (automation UA, data-center IP) → call record_finding")
        lines.append("- LIKELY/CANNOT DETERMINE → ask user: \"Do you recognize this IP? Is this expected traffic?\"")
        lines.append("- For deeper analysis → call detect_bypass(step='investigate_ip', ip='...', start_time='...')")
    else:
        lines.append("Tell user: no obvious bypass detected in this window.")
        lines.append("If user still suspects bypass, try a shorter/different time window (1-2h around the suspected incident).")
        lines.append("Tip: use get_waf_overview or volume_anomaly to identify peak traffic hours first.")

    return "\n".join(lines)


def _step_investigate_ip(ip: str, start_epoch: int, end_epoch: int) -> str:
    """Deep-dive a specific IP's behavior in ALLOW logs."""

    # Same channel as _step_scan. It matters more here: the verdict block at the
    # bottom reads `not has_bot_label`, and a failed `labels` query makes that True,
    # so a swallowed error pushed the conclusion TOWARD declaring a bypass with HIGH
    # CONFIDENCE. Absence of evidence was being read as evidence of absence, in the
    # direction that produces a false alarm.
    failures: dict[str, str] = {}

    # 1. Frequency (ALLOW only — bypass context)
    freq_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        " | stats count(*) as hits by bin(1m)"
        " | stats max(hits) as peak_rpm, avg(hits) as avg_rpm, count(*) as active_minutes"
    )
    freq_athena = (
        f"SELECT max(cnt) as peak_rpm, avg(cnt) as avg_rpm, count(*) as active_minutes FROM ("
        f"  SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as minute, count(*) as cnt"
        f"  FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f"  AND httprequest.clientip = '{ip}' AND action = 'ALLOW'"
        f"  GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i')"
        f")"
    )
    freq = _safe_query(freq_cwl, freq_athena, start_epoch, end_epoch, limit=1, failures=failures, label="frequency")
    peak_rpm = freq[0].get("peak_rpm", "?") if freq else "?"
    avg_rpm = freq[0].get("avg_rpm", "?") if freq else "?"

    # 2. URI diversity (ALLOW only)
    uri_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        f"{CWL_EXCLUDE_STATIC}"
        " | stats count_distinct(httpRequest.uri) as unique_uris, count(*) as total"
    )
    uri_athena = (
        f"SELECT count(DISTINCT httprequest.uri) as unique_uris, count(*) as total"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}' AND action = 'ALLOW'"
        f"{ATHENA_EXCLUDE_STATIC}"
    )
    uri_data = _safe_query(uri_cwl, uri_athena, start_epoch, end_epoch, limit=1, failures=failures, label="uri_diversity")
    unique_uris = uri_data[0].get("unique_uris", "?") if uri_data else "?"
    total_reqs = uri_data[0].get("total", "?") if uri_data else "?"

    # 2b. Query strings on ALLOW traffic — attack-like payloads that were NOT
    # blocked are a direct bypass signal. Sensitive params redacted below.
    qs_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and action = 'ALLOW'"
        " and ispresent(httpRequest.args) and httpRequest.args != ''"
        " | stats count(*) as hits by httpRequest.args | sort hits desc | limit 8"
    )
    qs_athena = (
        f"SELECT httprequest.args as args, count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}' AND action = 'ALLOW' AND httprequest.args <> ''"
        f" GROUP BY httprequest.args ORDER BY hits DESC LIMIT 8"
    )
    qs_data = _safe_query(qs_cwl, qs_athena, start_epoch, end_epoch, limit=8, failures=failures, label="query_strings")

    # 3. Action breakdown
    action_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by action"
    )
    action_athena = (
        f"SELECT action, count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY action"
    )
    actions = _safe_query(action_cwl, action_athena, start_epoch, end_epoch, limit=10, failures=failures, label="actions")
    action_map = {r.get("action", ""): int(r.get("hits", 0)) for r in actions}

    # 4. Labels (bot detection)
    labels_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and @message like 'labels'"
        " | parse @message '\"labels\":[*]' as Labels"
        " | filter ispresent(Labels)"
        " | stats count(*) as cnt by Labels"
        " | sort cnt desc | limit 5"
    )
    labels_athena = (
        f"SELECT json_format(cast(labels as json)) as Labels, count(*) as cnt"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" AND labels IS NOT NULL AND cardinality(labels) > 0"
        f" GROUP BY json_format(cast(labels as json)) ORDER BY cnt DESC LIMIT 5"
    )
    labels = _safe_query(labels_cwl, labels_athena, start_epoch, end_epoch, limit=5, failures=failures, label="labels")

    # 5. Country
    country_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by httpRequest.country"
        " | limit 1"
    )
    country_athena = (
        f"SELECT httprequest.country as \"httpRequest.country\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY httprequest.country LIMIT 1"
    )
    country_data = _safe_query(country_cwl, country_athena, start_epoch, end_epoch, limit=1, failures=failures, label="country")
    country = country_data[0].get("httpRequest.country", "?") if country_data else "?"

    # 6. User-Agent
    ua_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}/"
        " | stats count(*) as hits by ua"
        " | sort hits desc | limit 3"
    )
    ua_athena = (
        f"SELECT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value as ua,"
        f" count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value"
        f" ORDER BY hits DESC LIMIT 3"
    )
    ua_data = _safe_query(ua_cwl, ua_athena, start_epoch, end_epoch, limit=3, failures=failures, label="user_agent")

    # 7. JA4 fingerprint
    ja4_cwl = (
        f"filter httpRequest.clientIp = '{ip}'"
        " | stats count(*) as hits by ja4Fingerprint"
        " | sort hits desc | limit 3"
    )
    ja4_athena = (
        f"SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}'"
        f" GROUP BY ja4fingerprint ORDER BY hits DESC LIMIT 3"
    )
    ja4_data = _safe_query(ja4_cwl, ja4_athena, start_epoch, end_epoch, limit=3, failures=failures, label="ja4")

    # 8. COUNT rules triggered (nonTerminatingMatchingRules)
    count_rules_cwl = (
        f"filter httpRequest.clientIp = '{ip}' and @message like 'COUNT'"
        " | parse @message /\"nonTerminatingMatchingRules\":\\[\\{\"ruleId\":\"(?<rule>[^\"]+)\",\"action\":\"COUNT\"/"
        " | filter ispresent(rule)"
        " | stats count(*) as hits by rule"
        " | sort hits desc | limit 5"
    )
    count_rules_athena = (
        f"SELECT t.ruleid as rule, count(*) as hits"
        f" FROM {{TABLE}} CROSS JOIN UNNEST(nonterminatingmatchingrules) AS t(t)"
        f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{ip}' AND t.action = 'COUNT'"
        f" GROUP BY t.ruleid ORDER BY hits DESC LIMIT 5"
    )
    count_rules = _safe_query(count_rules_cwl, count_rules_athena, start_epoch, end_epoch, limit=5, failures=failures, label="count_rules")

    # Build output
    lines = [
        f"## Bypass Investigation: {ip}",
        f"**Country**: {country}",
        f"**Total ALLOW requests (non-static)**: {total_reqs}",
        f"**Unique URIs**: {unique_uris}",
        f"**Peak frequency**: {peak_rpm} req/min (avg {avg_rpm})",
        "",
        "### Action Breakdown",
    ]
    allow_count = action_map.get("ALLOW", 0)
    non_allow_count = sum(v for k, v in action_map.items() if k != "ALLOW")
    for action, count in sorted(action_map.items(), key=lambda x: x[1], reverse=True):
        lines.append(f"  {action}: {count:,}")
    if non_allow_count > allow_count * 5:
        lines.append(f"\n  ⚠️ This IP has {non_allow_count:,} non-ALLOW requests vs {allow_count:,} ALLOW — primarily an attacker being mitigated, with partial bypass.")

    lines.append("")
    lines.append("### User-Agent")
    is_automation_ua = False
    if ua_data:
        for r in ua_data:
            ua = r.get("ua", "?")
            lines.append(f"  {ua} ({r.get('hits', '?')} requests)")
            if any(t in ua.lower() for t in ("curl", "python", "wget", "httpie", "go-http", "java/", "okhttp")):
                is_automation_ua = True
    else:
        lines.append(_empty_reason(failures, "user_agent", "  (not available)"))

    lines.append("")
    lines.append("### JA4 Fingerprint")
    if ja4_data:
        for r in ja4_data:
            lines.append(f"  {r.get('ja4Fingerprint', r.get('ja4fingerprint', '?'))} ({r.get('hits', '?')} requests)")
    else:
        lines.append(_empty_reason(failures, "ja4", "  (not available)"))

    lines.append("")
    lines.append("### COUNT Rules Triggered (matched but not blocked)")
    if count_rules:
        for r in count_rules:
            lines.append(f"  {r.get('rule', '?')} ({r.get('hits', '?')} hits)")
    else:
        lines.append(_empty_reason(failures, "count_rules", "  (none, no COUNT rule matches for this IP)"))

    lines.append("")
    lines.append("### Bot Control Labels")
    bot_categories = set()
    bot_names = set()
    if labels:
        has_bot_labels = False
        for r in labels:
            label_str = r.get("Labels", "")
            if "bot:" in label_str or "signal:" in label_str:
                has_bot_labels = True
            # Extract bot category and name
            import re
            for cat in re.findall(r'bot:category:([^"}\s,]+)', label_str):
                bot_categories.add(cat)
            for name in re.findall(r'bot:name:([^"}\s,]+)', label_str):
                bot_names.add(name)
            lines.append(f"  {label_str} ({r.get('cnt', '?')} requests)")
        if bot_categories or bot_names:
            lines.append(f"\n  **Bot classification**: category={', '.join(bot_categories) or 'unknown'}, name={', '.join(bot_names) or 'unknown'}")
        if not has_bot_labels:
            lines.append("  ⚠️  No bot detection labels — Bot Control did not classify this IP")
    else:
        lines.append(_empty_reason(failures, "labels", "  (no labels found, Bot Control may not be deployed or IP has no label matches)"))

    # Directional judgment
    lines.append("")
    lines.append("### Query Strings on ALLOW Traffic (bypass signal if attack-like)")
    if qs_data:
        from tools.waf_query import _redact, PRIVACY_MASK_HINT
        _qs_masked = False
        for r in qs_data[:8]:
            red, m = _redact("args", r.get("args", ""))
            _qs_masked = _qs_masked or m
            if red:
                lines.append(f"  [{r.get('hits', '?')} hits] {red[:200]}")
        if _qs_masked:
            lines.append(f"  HINT: {PRIVACY_MASK_HINT}")
    else:
        lines.append(_empty_reason(failures, "query_strings", "  (no query strings on ALLOW traffic)"))

    lines.append("")
    lines.append("---")
    lines.append("## Directional Judgment")
    lines.append("")

    try:
        peak_val = float(peak_rpm)
    except (ValueError, TypeError):
        peak_val = 0
    try:
        uri_val = int(unique_uris)
    except (ValueError, TypeError):
        uri_val = 0

    # `any()` over an empty list is False, and `labels` is empty both when Bot Control
    # applied no labels and when the label query failed. Every branch below that reads
    # `not has_bot_label` treats False as "Bot Control did not classify this IP", so on a
    # failed query the verdict moved TOWARD declaring a bypass at HIGH CONFIDENCE. Refuse
    # to conclude instead: a security verdict must not be built on an unread input.
    labels_unknown = "labels" in failures
    has_bot_label = any("bot:" in r.get("Labels", "") for r in labels)
    has_datacenter = any("known_bot_data_center" in r.get("Labels", "") for r in labels)

    if labels_unknown:
        lines.append("**CANNOT DETERMINE: the Bot Control label query failed.**")
        lines.append(f"Reason: {failures['labels']}")
        lines.append("Every confidence rule here turns on whether Bot Control labelled this "
                     "IP, and that is exactly what could not be read. An unlabelled IP and an "
                     "unread label set look identical from here, and reading the second as the "
                     "first is what produces a false bypass call.")
        lines.append("→ Re-run this investigation once the query succeeds. Do NOT report a "
                     "verdict from this run.")
    elif has_datacenter and peak_val > 50 and not has_bot_label:
        lines.append("**HIGH CONFIDENCE: Undetected bot from data center.**")
        lines.append("Evidence: data-center IP (signal:known_bot_data_center) + high frequency + no bot classification.")
        lines.append("→ Bot Control is not catching this IP.")
    elif is_automation_ua and not has_bot_label:
        lines.append("**HIGH CONFIDENCE: Bot Control bypass — automation UA allowed through.**")
        lines.append("Evidence: known automation User-Agent but no bot detection label applied.")
        lines.append("→ Bot Control may not be deployed, or SignalNonBrowserUserAgent is set to Count.")
    elif peak_val > 200 and uri_val > 50:
        lines.append("**HIGH CONFIDENCE: Automated scraper/crawler.**")
        lines.append(f"Evidence: {peak_rpm} req/min + {unique_uris} unique URIs — far exceeds human behavior.")
    elif peak_val > 200 and uri_val < 10:
        lines.append("**HIGH CONFIDENCE: Endpoint hammering (possible DDoS participant or brute-force).**")
        lines.append(f"Evidence: {peak_rpm} req/min concentrated on few URIs.")
    elif uri_val > 50 and not has_bot_label:
        lines.append("**LIKELY: Probable scraper** (needs user confirmation).")
        lines.append(f"Evidence: {unique_uris} unique URIs, no bot labels. Frequency moderate ({peak_rpm}/min).")
        lines.append("→ Ask user if this IP is a known partner/crawler.")
    else:
        lines.append("**CANNOT DETERMINE** — signals are mixed or insufficient.")
        lines.append(f"Evidence: {peak_rpm} req/min, {unique_uris} URIs, country={country}.")
        lines.append("→ Ask user: is this IP expected? Is this a known service/partner?")

    lines.append("")
    lines.append(CONFIDENCE_RULES)
    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Present findings to user.")
    lines.append("If HIGH CONFIDENCE → call record_finding, then suggest remediation:")
    lines.append("  - Bot Control not deployed → 'Deploy Bot Control'")
    lines.append("  - Bot Control deployed but missed → 'Upgrade to Targeted level'")
    lines.append("  - High frequency → 'Add rate-based rule'")
    lines.append("")
    lines.append("If this IP has high URI diversity but moderate frequency:")
    lines.append("  → 'This IP may be part of a distributed scraping operation.")
    lines.append("     Want me to scan for more IPs with similar patterns?'")
    lines.append("  → If yes, call detect_bypass(step='scan', start_time='...')")

    return "\n".join(lines)


def _check_coverage_gaps() -> list[str]:
    """Quick config check for missing protection layers."""
    gaps = []
    webacl_name = get_webacl_name()
    scope = get_scope()
    if not webacl_name:
        return gaps

    region = resolve_region(scope)
    waf = get_client("wafv2", region_name=region)

    try:
        acls = waf.list_web_acls(Scope=scope).get("WebACLs", [])
        match = next((a for a in acls if a["Name"].lower() == webacl_name.lower()), None)
        if not match:
            return gaps
        resp = waf.get_web_acl(Name=webacl_name, Scope=scope, Id=match["Id"])
        rules = resp["WebACL"].get("Rules", [])

        has_bot_control = False
        has_rate_based = False
        has_antiddos = False
        for r in rules:
            stmt = r.get("Statement", {})
            mgr = stmt.get("ManagedRuleGroupStatement", {})
            if mgr.get("Name") == "AWSManagedRulesBotControlRuleSet":
                has_bot_control = True
            if mgr.get("Name") == "AWSManagedRulesAntiDDoSRuleSet":
                has_antiddos = True
            if "RateBasedStatement" in stmt:
                has_rate_based = True

        if not has_bot_control:
            gaps.append("Bot Control not deployed — automated traffic may not be detected")
        if not has_rate_based:
            gaps.append("No rate-based rules — high-frequency IPs are not throttled")
        if not has_antiddos:
            gaps.append("Anti-DDoS AMR not deployed — DDoS attacks may not be mitigated")
    except Exception:
        pass
    return gaps


def _label_dim_set() -> str:
    """Return correct dimension set for label metrics (no Region needed)."""
    return "{AWS/WAFV2,LabelName,LabelNamespace,WebACL}"
