"""WAF CloudWatch Logs Insights query tool — template-based."""

import time
import re
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_logs_region, get_log_destination

MAX_RESULTS = 25
POLL_INTERVAL = 2
MAX_POLL = 600
MAX_HOURS = 168  # 7 days max per query — use Athena for longer ranges

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
        "query": "parse @message '\"name\":\"user-agent\",\"value\":\"*\"' as ua | filter @message like '{rule_name}' | stats count(*) as cnt by ua | sort cnt desc | limit {limit}",
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
        "query": "filter httpRequest.clientIp = '{ip}' and not httpRequest.uri like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ | stats count_distinct(httpRequest.uri) as unique_uris, count(*) as total_requests, min(@timestamp) as first_seen, max(@timestamp) as last_seen",
        "params": ["ip"],
        "description": "Unique non-static URI count and time span for an IP (excludes JS/CSS/images)",
    },
    "ip_diversity": {
        "query": "filter httpRequest.clientIp = '{ip}' | parse @message '\"name\":\"user-agent\",\"value\":\"*\"' as ua | stats count_distinct(ua) as unique_uas, count_distinct(ja4Fingerprint) as unique_ja4s, count(*) as total_requests",
        "params": ["ip"],
        "description": "UA and JA4 diversity for an IP — high diversity = NAT/shared IP, low = single bot",
    },
    "top_allowed_by_volume": {
        "query": "filter action = 'ALLOW' and not httpRequest.uri like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ | stats count(*) as cnt, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "params": [],
        "description": "Top ALLOW IPs with unique non-static URI count (find high-volume bypasses)",
    },
    "token_reuse_ips": {
        "query": "filter @message like 'token:accepted' | parse @message '\"name\":\"cookie\",\"value\":\"*\"' as cookie | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by cookie | sort ip_count desc | limit {limit}",
        "params": [],
        "description": "Detect token reuse — same session cookie used from multiple IPs (approximate)",
    },
    "host_traffic_profile": {
        "query": "parse @message '\"name\":\"host\",\"value\":\"*\"' as host | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris, sum(strcontains(httpRequest.httpMethod, 'POST') + strcontains(httpRequest.httpMethod, 'PUT') + strcontains(httpRequest.httpMethod, 'DELETE')) as write_requests by host | sort total desc | limit {limit}",
        "params": [],
        "description": "Traffic profile per Host header — identify frontend vs backend/API domains",
    },
    "host_uri_pattern": {
        "query": "parse @message '\"name\":\"host\",\"value\":\"*\"' as host | filter host = '{host}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}",
        "params": ["host"],
        "description": "Top URIs for a specific host — determine if frontend (HTML pages) or backend (API endpoints)",
    },
    "host_method_distribution": {
        "query": "parse @message '\"name\":\"host\",\"value\":\"*\"' as host | filter host = '{host}' | stats count(*) as cnt by httpRequest.httpMethod | sort cnt desc | limit {limit}",
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
            - top_countries_blocked: Top blocked countries
            - label_top_ips: Top IPs for a WAF label (needs label)
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
        hours_ago: How far back to query (default 24 hours).
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

    end_time = int(time.time())
    start_time = end_time - (hours_ago * 3600)

    resp = client.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=end_time,
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
