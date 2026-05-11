"""WAF CloudWatch Logs Insights query tool — template-based."""

import time
import re
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_logs_region, get_log_destination

MAX_RESULTS = 25
POLL_INTERVAL = 2
MAX_POLL = 600
MAX_HOURS = 168  # 7 days max per query — use Athena for longer ranges

# Concurrency control: max 8 concurrent CWL queries (CWL limit is 10 TPS, ~30 concurrent)
_cwl_semaphore = threading.Semaphore(8)

# Parameterized query templates. LLM picks a query_type + provides parameters.
TEMPLATES = {
    "count_rule_top_ips": {
        "query": "filter @message like '{rule_name}' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "params": ["rule_name"],
        "description": "Top IPs triggering a specific COUNT rule",
    },
    "count_rule_top_uris": {
        "query": "filter @message like '{rule_name}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}",
        "params": ["rule_name"],
        "description": "Top URIs where a COUNT rule is triggered",
    },
    "count_rule_top_uas": {
        "query": "parse @message /(?i)\\{{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}}/ | filter @message like '{rule_name}' | stats count(*) as cnt by ua | sort cnt desc | limit {limit}",
        "params": ["rule_name"],
        "description": "Top User-Agents triggering a COUNT rule",
    },
    "ip_cross_query": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by action, terminatingRuleId | sort cnt desc | limit {limit}",
        "params": ["ip"],
        "description": "All actions/rules for a specific IP (cross-validation)",
    },
    "ip_uri_breakdown": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}",
        "params": ["ip"],
        "description": "URI breakdown for a specific IP",
    },
    "top_blocked_ips": {
        "query": "filter action = 'BLOCK' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "params": [],
        "description": "Top IPs being blocked",
    },
    "top_blocked_rules": {
        "query": "filter action = 'BLOCK' | stats count(*) as cnt by terminatingRuleId | sort cnt desc | limit {limit}",
        "params": [],
        "description": "Top rules doing the blocking",
    },
    "top_allowed_ips": {
        "query": "filter action = 'ALLOW' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "params": [],
        "description": "Top IPs being allowed (find potential attack traffic)",
    },
    "top_countries_blocked": {
        "query": "filter action = 'BLOCK' | stats count(*) as cnt by httpRequest.country | sort cnt desc | limit {limit}",
        "params": [],
        "description": "Top countries being blocked",
    },
    "ip_ja4_fingerprints": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by ja4Fingerprint | sort cnt desc | limit {limit}",
        "params": ["ip"],
        "description": "JA4 fingerprints for a specific IP",
    },
    "label_top_ips": {
        "query": "filter @message like '{label}' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "params": ["label"],
        "description": "Top IPs matching a specific WAF label",
    },
    "ip_labels": {
        "query": "filter httpRequest.clientIp = '{ip}' | parse @message '\"labels\":[*]' as Labels | filter ispresent(Labels) | stats count(*) as cnt by Labels | sort cnt desc | limit {limit}",
        "params": ["ip"],
        "description": "All WAF labels applied to a specific IP — shows Bot Control, Anti-DDoS, and other managed rule detections",
    },
    "action_timeline": {
        "query": "filter action = '{action}' | stats count(*) as cnt by bin(5m) | sort @timestamp asc | limit {limit}",
        "params": ["action"],
        "description": "Timeline of a specific action (5-min buckets)",
    },
    "ip_request_rate": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by bin(1m) | sort @timestamp asc | limit {limit}",
        "params": ["ip"],
        "description": "Per-minute request rate for a specific IP (detect automation)",
    },
    "ip_unique_uris": {
        "query": "filter httpRequest.clientIp = '{ip}' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ | stats count_distinct(httpRequest.uri) as unique_uris, count(*) as total_requests, min(@timestamp) as first_seen, max(@timestamp) as last_seen",
        "params": ["ip"],
        "description": "Unique non-static URI count and time span for an IP (excludes JS/CSS/images)",
    },
    # ip_diversity intentionally NOT exposed — use analyze_ip which has proper NAT detection logic
    "top_allowed_by_volume": {
        "query": "filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ | stats count(*) as cnt, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "params": [],
        "description": "Top ALLOW IPs with unique non-static URI count (find high-volume bypasses)",
    },
    "top_allowed_crawlers": {
        "query": "filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ and @message not like 'bot:verified' | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris, min(@timestamp) as first_seen, max(@timestamp) as last_seen by httpRequest.clientIp | filter unique_uris > 50 | sort unique_uris desc | limit {limit}",
        "params": [],
        "description": "Find IPs with high URI diversity (likely content crawlers) — excludes verified bots and static resources",
    },
    "top_allowed_repeaters": {
        "query": "filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ and @message not like 'bot:verified' | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris, min(@timestamp) as first_seen, max(@timestamp) as last_seen by httpRequest.clientIp | filter total > 200 and unique_uris < 10 | sort total desc | limit {limit}",
        "params": [],
        "description": "Find IPs hitting few URIs at high frequency (ticket scalpers, flash sale bots, quant trading) — excludes verified bots",
    },
    "token_reuse_ips": {
        "query": "filter @message like 'token:accepted' | parse @message '\"name\":\"cookie\",\"value\":\"*\"' as cookie | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by cookie | sort ip_count desc | limit {limit}",
        "params": [],
        "description": "Detect token reuse — same session cookie used from multiple IPs (approximate)",
    },
    "host_traffic_profile": {
        "query": "parse @message /\\{{\"name\":\"(H|h)ost\",\"value\":\"(?<host>.*?)\"\\}}/ | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris, sum(strcontains(httpRequest.httpMethod, 'POST') + strcontains(httpRequest.httpMethod, 'PUT') + strcontains(httpRequest.httpMethod, 'DELETE')) as write_requests by host | sort total desc | limit {limit}",
        "params": [],
        "description": "Traffic profile per Host header — identify frontend vs backend/API domains",
    },
    "host_uri_pattern": {
        "query": "parse @message /\\{{\"name\":\"(H|h)ost\",\"value\":\"(?<host>.*?)\"\\}}/ | filter host = '{host}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}",
        "params": ["host"],
        "description": "Top URIs for a specific host — determine if frontend (HTML pages) or backend (API endpoints)",
    },
    "host_method_distribution": {
        "query": "parse @message /\\{{\"name\":\"(H|h)ost\",\"value\":\"(?<host>.*?)\"\\}}/ | filter host = '{host}' | stats count(*) as cnt by httpRequest.httpMethod | sort cnt desc | limit {limit}",
        "params": ["host"],
        "description": "HTTP method distribution for a host — high POST/PUT = API, mostly GET = frontend",
    },
}


def _validate_ip(ip: str) -> bool:
    """Validate IP format (IPv4 and IPv6)."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _sanitize_param(value: str) -> str:
    """Sanitize parameter value for CWL query injection prevention."""
    # Remove characters that could break out of the query string
    return re.sub(r"['\"|;`\\]", "", value)


def _parse_start_time(value: str) -> int | None:
    """Parse a date/datetime string to epoch seconds using user's timezone. Returns None on failure."""
    from datetime import datetime, timezone, timedelta
    tz_offset = int(os.environ.get("WAF_AGENT_TIMEZONE_OFFSET", "8"))  # default UTC+8
    user_tz = timezone(timedelta(hours=tz_offset))
    value = value.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=user_tz)
            return int(dt.timestamp())
        except ValueError:
            continue
    return None


@tool
def run_logs_query(
    query_type: str,
    log_group: str = "",
    rule_name: str = "",
    ip: str = "",
    label: str = "",
    action: str = "",
    host: str = "",
    hours_ago: int = 24,
    start_time: str = "",
    limit: int = 25,
) -> str:
    """Run a predefined WAF log query against CloudWatch Logs Insights.

    Args:
        query_type: Type of query to run. Available types:
            - count_rule_top_ips: Top IPs triggering a COUNT rule (needs rule_name)
            - count_rule_top_uris: Top URIs for a COUNT rule (needs rule_name)
            - count_rule_top_uas: Top User-Agents for a COUNT rule (needs rule_name)
            - ip_cross_query: All actions/rules for an IP (needs ip)
            - ip_uri_breakdown: URI breakdown for an IP (needs ip)
            - ip_ja4_fingerprints: JA4 fingerprints for an IP (needs ip)
            - ip_request_rate: Per-minute request rate for an IP (needs ip) — detect automation
            - ip_unique_uris: Unique URI count + time span for an IP (needs ip) — frequency anomaly
            - top_blocked_ips: Top blocked IPs
            - top_blocked_rules: Top blocking rules
            - top_allowed_ips: Top allowed IPs
            - top_allowed_by_volume: Top ALLOW IPs with unique URI count — find bypasses
            - top_allowed_crawlers: IPs with high URI diversity (content crawlers, scrapers)
            - top_allowed_repeaters: IPs hitting few URIs at high frequency (scalpers, flash sale bots)
            - top_countries_blocked: Top blocked countries
            - label_top_ips: Top IPs for a WAF label (needs label)
            - ip_labels: All WAF labels on a specific IP — Bot Control, Anti-DDoS, signals (needs ip)
            - action_timeline: Timeline of an action (needs action)
            - token_reuse_ips: Detect token reuse across multiple IPs
            - host_traffic_profile: Traffic profile per Host — identify frontend vs backend domains
            - host_uri_pattern: Top URIs for a specific host (needs host param)
            - host_method_distribution: HTTP method distribution for a host (needs host param)
        log_group: CW Logs log group name. Auto-detected from WebACL config if empty.
        rule_name: Rule name (for count_rule_* queries).
        ip: Client IP address (for ip_* queries).
        label: WAF label name (for label_top_ips).
        action: Action value — BLOCK, ALLOW, COUNT (for action_timeline).
        host: Hostname (for host_uri_pattern, host_method_distribution).
        hours_ago: How far back to query (default 24h), or duration from start_time if start_time is given. Bypass detection queries capped at 24h max.
        start_time: Specific start date (e.g., "2026-05-09" or "2026-05-09T14:00"). Overrides hours_ago direction. Pass the user's date directly.
        limit: Max results (default 25, max 25).

    Returns:
        Query results as a table, or error message.
    """
    # Validate query_type
    if query_type not in TEMPLATES:
        available = ", ".join(TEMPLATES.keys())
        return f"Unknown query_type '{query_type}'. Available: {available}"

    template = TEMPLATES[query_type]

    # Validate required params
    params = {"limit": min(limit, MAX_RESULTS)}
    for p in template["params"]:
        value = locals().get(p, "")
        if not value:
            return f"query_type '{query_type}' requires parameter '{p}'"
        if p == "ip" and not _validate_ip(value):
            return f"Invalid IP format: '{value}'"
        params[p] = _sanitize_param(value)

    # Resolve log group
    if not log_group:
        dest = get_log_destination()
        if dest and ":log-group:" in dest:
            # Extract log group name from ARN
            log_group = dest.split(":log-group:")[-1].rstrip(":*")
        elif dest:
            return f"Log destination is not CW Logs (found: {dest}). Use Athena for S3 logs."
        else:
            return "No log group specified and none auto-detected. Run get_waf_config first."

    # Build query
    query = template["query"].format(**params)

    # Execute
    region = get_logs_region()
    client = get_client("logs", region_name=region)

    if hours_ago > MAX_HOURS:
        return f"Error: max time range is {MAX_HOURS} hours (7 days). For longer ranges, use Athena. Requested: {hours_ago}h"

    # Hard cap: bypass/crawler queries max 24 hours (prevent expensive full-week scans)
    _NARROW_TYPES = {"top_allowed_crawlers", "top_allowed_repeaters", "top_allowed_by_volume",
                     "ip_unique_uris", "ip_request_rate", "ip_uri_breakdown"}
    if query_type in _NARROW_TYPES and hours_ago > 24:
        hours_ago = 24

    # Time range calculation
    end_epoch = int(time.time())
    if start_time:
        # Parse user-provided date (e.g., "2026-05-09", "2026-05-09T14:00")
        start_epoch = _parse_start_time(start_time)
        if start_epoch is None:
            return f"Error: cannot parse start_time '{start_time}'. Use format: YYYY-MM-DD or YYYY-MM-DDTHH:MM"
        # hours_ago becomes "duration from start" (default 24h if not specified)
        end_epoch = min(start_epoch + (hours_ago * 3600), int(time.time()))
    else:
        start_epoch = end_epoch - (hours_ago * 3600)

    with _cwl_semaphore:
        resp = client.start_query(
            logGroupName=log_group,
            startTime=start_epoch,
            endTime=end_epoch,
            queryString=query,
            limit=params["limit"],
        )
        query_id = resp["queryId"]

        # Poll
        elapsed = 0
        while elapsed < MAX_POLL:
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            result = client.get_query_results(queryId=query_id)
            status = result["status"]
            if status in ("Complete", "Failed", "Cancelled", "Timeout"):
                break

    if status != "Complete":
        return f"Query {status}. QueryId: {query_id}"

    results = result.get("results", [])
    stats = result.get("statistics", {})

    if not results:
        return f"Query returned 0 results. (scanned {stats.get('bytesScanned', 0) / 1e6:.1f} MB, query: {query_type})"

    # Format as table
    columns = [f["field"] for f in results[0] if not f["field"].startswith("@ptr")]
    lines = [
        f"Query '{query_type}' returned {len(results)} results (scanned {stats.get('bytesScanned', 0) / 1e6:.1f} MB)\n",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in results[:MAX_RESULTS]:
        row_dict = {f["field"]: f["value"] for f in row}
        values = [row_dict.get(col, "") for col in columns]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines)


def _is_nat_traffic(ua_rows: list[dict]) -> bool:
    """Determine if UA diversity indicates real NAT (multiple users) vs UA rotation (one bot).

    Real NAT: diverse OS/browser combos (Windows+Mac+iPhone, Chrome+Safari+Firefox)
    UA rotation: same template with only version numbers changing, or sequential versions.

    Returns True if likely NAT, False if suspicious (possible rotation).
    """
    uas = [row.get("ua", "") for row in ua_rows if row.get("ua")]
    if len(uas) < 4:
        return True  # too few to judge, assume NAT

    # Extract OS and browser base signatures (strip version numbers)
    os_set = set()
    browser_set = set()
    version_pattern_count = 0

    for ua in uas:
        # OS detection
        if "Windows" in ua:
            os_set.add("Windows")
        elif "Macintosh" in ua or "Mac OS" in ua:
            os_set.add("Mac")
        elif "iPhone" in ua or "iPad" in ua:
            os_set.add("iOS")
        elif "Android" in ua:
            os_set.add("Android")
        elif "Linux" in ua:
            os_set.add("Linux")

        # Browser detection (base, ignoring version)
        if "Firefox/" in ua:
            browser_set.add("Firefox")
        elif "Edg/" in ua:
            browser_set.add("Edge")
        elif "Chrome/" in ua and "Safari/" in ua:
            browser_set.add("Chrome")
        elif "Safari/" in ua and "Chrome/" not in ua:
            browser_set.add("Safari")

    # Check for version-only rotation: strip version numbers and see how many unique templates remain
    version_re = re.compile(r'\d+\.\d+[\.\d]*')
    templates = set()
    for ua in uas:
        template = version_re.sub("X", ua)
        templates.add(template)

    # Heuristics:
    # Real NAT: multiple OS (≥2) OR multiple browsers (≥2) AND multiple templates (≥3)
    # UA rotation: single OS + single browser + few templates (1-2) despite many UAs
    if len(templates) <= 2 and len(uas) >= 5:
        return False  # Same template, only versions differ → rotation
    if len(os_set) >= 2 and len(browser_set) >= 2:
        return True  # Genuine diversity → NAT
    if len(os_set) <= 1 and len(browser_set) <= 1 and len(templates) <= 2:
        return False  # Single OS + single browser + same template → rotation

    # Edge case: many templates but all same OS/browser (could be version rotation with minor diffs)
    if len(os_set) <= 1 and len(browser_set) <= 1:
        return False  # Suspicious even with template diversity

    return True  # Default: assume NAT if genuinely diverse


def _execute_query_internal(client, log_group: str, start_time: int, end_time: int, query: str, limit: int = 25) -> list:
    """Internal: execute a CWL query with semaphore and polling. Returns list of row dicts or empty list."""
    with _cwl_semaphore:
        resp = client.start_query(
            logGroupName=log_group, startTime=start_time, endTime=end_time,
            queryString=query, limit=limit,
        )
        query_id = resp["queryId"]
        elapsed = 0
        while elapsed < MAX_POLL:
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            result = client.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
        if result["status"] != "Complete":
            return []
        return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]


@tool
def analyze_ip(ip: str, hours_ago: int = 6, start_time: str = "") -> str:
    """Analyze a single IP address with parallel queries. Two-phase: diversity check first (NAT detection), then full analysis if not NAT.

    This is a composite tool that runs multiple queries in one call to minimize
    LLM round-trips. Use this instead of calling run_logs_query multiple times for the same IP.

    Args:
        ip: IP address to analyze.
        hours_ago: Time window duration (default 6h). When start_time is given, this is duration from start. Capped at 24h.
        start_time: Specific start date (e.g., "2026-05-09"). Overrides hours_ago direction. Pass user's date directly.

    Returns:
        Formatted analysis: NAT status, action breakdown, request rate, JA4 fingerprints, top URIs.
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"Error: invalid IP address '{ip}'"

    # Hard cap at 24 hours
    hours_ago = min(hours_ago, 24)

    log_dest = get_log_destination()
    if not log_dest or ":log-group:" not in log_dest:
        return "Error: no CWL log group configured. Run get_waf_config first."
    log_group = log_dest.split(":log-group:")[-1].rstrip(":*")

    region = get_logs_region()
    client = get_client("logs", region_name=region)
    end_epoch = int(time.time())
    if start_time:
        parsed = _parse_start_time(start_time)
        if parsed:
            start_epoch = parsed
            end_epoch = min(start_epoch + (hours_ago * 3600), int(time.time()))
        else:
            start_epoch = end_epoch - (hours_ago * 3600)
    else:
        start_epoch = end_epoch - (hours_ago * 3600)
    safe_ip = re.sub(r"[^0-9a-fA-F.:]", "", ip)

    # Phase 1: Diversity check (NAT vs UA-rotation detection)
    diversity_query = f'filter httpRequest.clientIp = "{safe_ip}" | parse @message /(?i)\\{{"name":"user-agent","value":"(?<ua>.*?)"\\}}/ | stats count_distinct(ua) as ua_count, count_distinct(ja4Fingerprint) as ja4_count, count(*) as total'
    diversity = _execute_query_internal(client, log_group, start_epoch, end_epoch, diversity_query, 1)

    if not diversity:
        return f"Error: diversity query returned no results for {ip}"

    d = diversity[0]
    ua_count = int(d.get("ua_count", "0"))
    ja4_count = int(d.get("ja4_count", "0"))
    total = int(d.get("total", "0"))

    # High diversity → could be NAT or UA rotation. Need deeper check.
    if ua_count > 3 and ja4_count > 3:
        # Fetch actual UAs to detect rotation pattern
        ua_list_query = f'filter httpRequest.clientIp = "{safe_ip}" | parse @message /(?i)\\{{"name":"user-agent","value":"(?<ua>.*?)"\\}}/ | stats count(*) as cnt by ua | sort cnt desc | limit 20'
        ua_rows = _execute_query_internal(client, log_group, start_epoch, end_epoch, ua_list_query, 20)
        if ua_rows and not _is_nat_traffic(ua_rows):
            pass  # Suspicious — continue to Phase 2
        else:
            return f"## {ip} — NAT/Shared IP (skipped)\n\nMultiple UAs ({ua_count}) + multiple JA4s ({ja4_count}) = shared IP (NAT gateway).\nTotal requests: {total}\n\nNo further analysis needed."

    # Phase 2: Parallel queries (only if not NAT)
    queries = {
        "cross_query": f'filter httpRequest.clientIp = "{safe_ip}" | stats count(*) as cnt by action, terminatingRuleId | sort cnt desc | limit 15',
        "request_rate": f'filter httpRequest.clientIp = "{safe_ip}" | stats count(*) as req_per_min by bin(1m) | stats avg(req_per_min) as avg_rpm, max(req_per_min) as peak_rpm, count(*) as active_minutes',
        "ja4": f'filter httpRequest.clientIp = "{safe_ip}" | stats count(*) as cnt by ja4Fingerprint | sort cnt desc | limit 5',
        "uri_diversity": f'filter httpRequest.clientIp = "{safe_ip}" and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ | stats count_distinct(httpRequest.uri) as unique_uris, count(*) as total_non_static',
    }

    results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(_execute_query_internal, client, log_group, start_epoch, end_epoch, q, 25): name
            for name, q in queries.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception:
                results[name] = []

    # Format output
    lines = [f"## IP Analysis: {ip}", f"Time window: last {hours_ago} hours", ""]

    # Diversity summary
    lines.append(f"**Diversity**: {ua_count} UAs, {ja4_count} JA4 fingerprints, {total} total requests")
    if ua_count > 1 and ja4_count == 1:
        lines.append("⚠️ Multiple UAs but single JA4 = likely UA spoofing (same tool)")
    elif ua_count == 1 and ja4_count == 1:
        lines.append("Single UA + single JA4 = single client")
    lines.append("")

    # Action breakdown
    lines.append("**Action breakdown**:")
    for row in results.get("cross_query", [])[:10]:
        lines.append(f"  {row.get('action', '?')} / {row.get('terminatingRuleId', 'default')} : {row.get('cnt', '0')}")
    lines.append("")

    # Request rate
    rate = results.get("request_rate", [{}])
    if rate:
        r = rate[0]
        avg_rpm = r.get("avg_rpm", "0")
        peak_rpm = r.get("peak_rpm", "0")
        active_min = r.get("active_minutes", "0")
        lines.append(f"**Request rate**: avg {avg_rpm} req/min, peak {peak_rpm} req/min, active {active_min} minutes")
        try:
            if float(peak_rpm) > 200:
                lines.append("🚨 Peak > 200 req/min — likely automation")
        except (ValueError, TypeError):
            pass
    lines.append("")

    # JA4 fingerprints
    lines.append("**JA4 fingerprints**:")
    for row in results.get("ja4", [])[:5]:
        lines.append(f"  {row.get('ja4Fingerprint', 'N/A')} : {row.get('cnt', '0')} requests")
    lines.append("")

    # URI diversity (crawler indicator)
    uri_div = results.get("uri_diversity", [{}])
    if uri_div and uri_div[0]:
        u = uri_div[0]
        unique = u.get("unique_uris", "0")
        total_ns = u.get("total_non_static", "0")
        lines.append(f"**URI diversity** (non-static): {unique} unique URIs out of {total_ns} requests")
        try:
            if int(unique) > 200:
                lines.append("🚨 >200 unique URIs — very likely crawler/scraper")
            elif int(unique) > 50:
                lines.append("⚠️ >50 unique URIs — suspicious, may be crawler")
        except (ValueError, TypeError):
            pass

    return "\n".join(lines)
