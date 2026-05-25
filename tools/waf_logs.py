# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF CloudWatch Logs Insights query tool — template-based."""

import time
import re
import os
import sys
import threading
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_logs_region, get_log_destination, is_log_filter_active

MAX_RESULTS = 25
POLL_INTERVAL = 2
MAX_POLL = 600
MAX_MINUTES = 360  # Hard cap for CWL queries (6 hours)

# Concurrency control: max 8 concurrent CWL queries (CWL limit is 10 TPS, ~30 concurrent)
_cwl_semaphore = threading.Semaphore(8)


def _log(msg: str):
    """Log tool execution details to stderr for debugging."""
    print(f"[waf_logs] {msg}", file=sys.stderr, flush=True)


# Parameterized query templates. LLM picks a query_type + provides parameters.
TEMPLATES = {
    "count_rule_top_ips": {
        "query": "filter @message like '{rule_name}' and @message like 'COUNT' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT') GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["rule_name"],
        "description": "Top IPs triggering a COUNT rule",
    },
    "count_rule_top_uris": {
        "query": "filter @message like '{rule_name}' and @message like 'COUNT' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.uri as \"httpRequest.uri\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT') GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["rule_name"],
        "description": "Top URIs where a COUNT rule is triggered",
    },
    "count_rule_top_uas": {
        "query": "parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>.*?)\"\\}/ | filter @message like '{rule_name}' | stats count(*) as cnt by ua | sort cnt desc | limit {limit}",
        "athena": "SELECT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value as ua, count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}' AND r.action = 'COUNT') GROUP BY element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["rule_name"],
        "description": "Top User-Agents triggering a COUNT rule",
    },
    "ip_cross_query": {
        "query": "filter httpRequest.clientIp = '{ip}' | parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>[^\"]*)\"}/ | stats count(*) as cnt, earliest(ua) as user_agent by action, terminatingRuleId | sort cnt desc | limit {limit}",
        "athena": "SELECT action, terminatingruleid as \"terminatingRuleId\", count(*) as cnt, arbitrary(h.value) as user_agent FROM {TABLE} CROSS JOIN UNNEST(httprequest.headers) AS t(h) WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' AND lower(h.name) = 'user-agent' GROUP BY action, terminatingruleid ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "All actions/rules for a specific IP with User-Agent (cross-validation)",
    },
    "ip_uri_breakdown": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.uri as \"httpRequest.uri\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "URI breakdown for a specific IP",
    },
    "ip_uri_prefix": {
        "query": "filter httpRequest.clientIp = '{ip}' | parse httpRequest.uri \"/*/*/**\" as seg1, seg2, rest | stats count(*) as hits, count_distinct(httpRequest.uri) as unique_uris by seg1, seg2 | sort hits desc | limit {limit}",
        "athena": "SELECT COALESCE(NULLIF(regexp_extract(httprequest.uri, '^(/[^/]*/[^/]*)', 1), ''), httprequest.uri) as prefix, count(*) as hits, count(DISTINCT httprequest.uri) as unique_uris FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' GROUP BY COALESCE(NULLIF(regexp_extract(httprequest.uri, '^(/[^/]*/[^/]*)', 1), ''), httprequest.uri) ORDER BY hits DESC LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "URI path prefix clustering for an IP — shows crawl/scrape patterns without hitting result limits",
    },
    "rule_uri_prefix": {
        "query": "filter @message like '{rule_name}' | parse httpRequest.uri \"/*/*/**\" as seg1, seg2, rest | stats count(*) as hits, count_distinct(httpRequest.uri) as unique_uris by seg1, seg2 | sort hits desc | limit {limit}",
        "athena": "SELECT COALESCE(NULLIF(regexp_extract(httprequest.uri, '^(/[^/]*/[^/]*)', 1), ''), httprequest.uri) as prefix, count(*) as hits, count(DISTINCT httprequest.uri) as unique_uris FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND (terminatingruleid = '{rule_name}' OR any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}')) GROUP BY COALESCE(NULLIF(regexp_extract(httprequest.uri, '^(/[^/]*/[^/]*)', 1), ''), httprequest.uri) ORDER BY hits DESC LIMIT {LIMIT}",
        "params": ["rule_name"],
        "description": "URI path prefix clustering for a rule — shows which paths trigger it (FP vs attack signal)",
    },
    "top_ua_by_action": {
        "query": "parse @message /(?i)\\{\"name\":\"user-agent\",\"value\":\"(?<ua>[^\"]*)\"}/ | stats count(*) as hits by action, ua | sort hits desc | limit {limit}",
        "athena": "SELECT action, h.value as ua, count(*) as hits FROM {TABLE} CROSS JOIN UNNEST(httprequest.headers) AS t(h) WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND lower(h.name) = 'user-agent' GROUP BY action, h.value ORDER BY hits DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top User-Agents grouped by action — find suspicious UAs in ALLOW traffic or bot patterns",
    },
    "ip_request_timeline": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as hits by action, bin(1m) as minute | sort minute | limit {limit}",
        "athena": "SELECT action, from_unixtime((\"timestamp\" / 60000) * 60) as minute, count(*) as hits FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' GROUP BY action, (\"timestamp\" / 60000) * 60 ORDER BY minute LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "Per-minute action timeline for an IP — see when BLOCK/Challenge kicked in",
    },
    "ip_label_breakdown": {
        "query": "filter httpRequest.clientIp = '{ip}' | parse @message /\"labels\":\\[(?<lbls>[^\\]]*)\\]/ | filter ispresent(lbls) | parse lbls /\"name\":\"(?<lbl>[^\"]*)\"/  | stats count(*) as hits by lbl | sort hits desc | limit {limit}",
        "athena": "SELECT l.name as label, count(*) as hits FROM {TABLE} CROSS JOIN UNNEST(labels) AS t(l) WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' GROUP BY l.name ORDER BY hits DESC LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "All WAF labels applied to an IP's requests — bot signals, Anti-DDoS, token status. CWL: first label per request only; Athena: all labels (more accurate)",
    },
    "host_top_ips": {
        "query": "filter @message like '{host}' | stats count(*) as hits by httpRequest.clientIp, action | sort hits desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", action, count(*) as hits FROM {TABLE} CROSS JOIN UNNEST(httprequest.headers) AS t(h) WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND lower(h.name) = 'host' AND h.value = '{host}' GROUP BY httprequest.clientip, action ORDER BY hits DESC LIMIT {LIMIT}",
        "params": ["host"],
        "description": "Top IPs for a specific host/domain — identify per-domain attackers in multi-domain WebACLs",
    },
    "top_blocked_ips": {
        "query": "filter action = 'BLOCK' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'BLOCK' GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top IPs being blocked",
    },
    "top_blocked_rules": {
        "query": "filter action = 'BLOCK' | stats count(*) as cnt by terminatingRuleId | sort cnt desc | limit {limit}",
        "athena": "SELECT terminatingruleid as \"terminatingRuleId\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'BLOCK' GROUP BY terminatingruleid ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top rules doing the blocking",
    },
    "top_allowed_ips": {
        "query": "filter action = 'ALLOW' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'ALLOW' GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top IPs being allowed (find potential attack traffic)",
    },
    "top_countries_blocked": {
        "query": "filter action = 'BLOCK' | stats count(*) as cnt by httpRequest.country | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.country as \"httpRequest.country\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'BLOCK' GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top countries being blocked",
    },
    "top_challenged_ips": {
        "query": "filter action = 'CHALLENGE' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'CHALLENGE' GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top IPs being challenged (DDoS/bot traffic)",
    },
    "top_challenged_countries": {
        "query": "filter action = 'CHALLENGE' | stats count(*) as cnt by httpRequest.country | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.country as \"httpRequest.country\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'CHALLENGE' GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top countries being challenged",
    },
    "top_captcha_ips": {
        "query": "filter action = 'CAPTCHA' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'CAPTCHA' GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top IPs receiving CAPTCHA",
    },
    "top_captcha_countries": {
        "query": "filter action = 'CAPTCHA' | stats count(*) as cnt by httpRequest.country | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.country as \"httpRequest.country\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'CAPTCHA' GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top countries receiving CAPTCHA",
    },
    "top_counted_ips": {
        "query": "filter nonTerminatingMatchingRules.0.action = 'COUNT' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT') GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top IPs triggering COUNT rules (by request count, not rule count)",
    },
    "top_counted_countries": {
        "query": "filter nonTerminatingMatchingRules.0.action = 'COUNT' | stats count(*) as cnt by httpRequest.country | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.country as \"httpRequest.country\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT') GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top countries triggering COUNT rules",
    },
    "top_ips_by_volume": {
        "query": "filter ispresent(httpRequest.clientIp) | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top IPs by total request volume (ALL actions combined) — use for DDoS source identification",
    },
    "top_countries_by_volume": {
        "query": "filter ispresent(httpRequest.country) | stats count(*) as cnt by httpRequest.country | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.country as \"httpRequest.country\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top countries by total request volume (ALL actions) — use for DDoS geo-distribution",
    },
    "ip_ja4_fingerprints": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by ja4Fingerprint | sort cnt desc | limit {limit}",
        "athena": "SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' GROUP BY ja4fingerprint ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "JA4 fingerprints for a specific IP",
    },
    "label_top_ips": {
        "query": "filter @message like '{label}' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND any_match(labels, l -> l.name LIKE '%{label}%') GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["label"],
        "description": "Top IPs matching a specific AWS WAF label",
    },
    "ip_labels": {
        "query": "filter httpRequest.clientIp = '{ip}' | parse @message '\"labels\":[*]' as Labels | filter ispresent(Labels) | stats count(*) as cnt by Labels | sort cnt desc | limit {limit}",
        "athena": "SELECT json_format(cast(labels as json)) as \"Labels\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' AND labels IS NOT NULL AND cardinality(labels) > 0 GROUP BY json_format(cast(labels as json)) ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "All AWS WAF labels applied to a specific IP",
    },
    "action_timeline": {
        "query": "filter action = '{action}' | stats count(*) as cnt by bin(5m) | sort @timestamp asc | limit {limit}",
        "athena": "SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as time_bucket, count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = '{action}' GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') ORDER BY time_bucket ASC LIMIT {LIMIT}",
        "params": ["action"],
        "description": "Timeline of a specific action (5-min buckets)",
    },
    "ip_request_rate": {
        "query": "filter httpRequest.clientIp = '{ip}' | stats count(*) as cnt by bin(1m) | sort @timestamp asc | limit {limit}",
        "athena": "SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as minute, count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') ORDER BY minute ASC LIMIT {LIMIT}",
        "params": ["ip"],
        "description": "Per-minute request rate for a specific IP (detect automation)",
    },
    "ip_unique_uris": {
        "query": "filter httpRequest.clientIp = '{ip}' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ | stats count_distinct(httpRequest.uri) as unique_uris, count(*) as total_requests, min(@timestamp) as first_seen, max(@timestamp) as last_seen",
        "athena": "SELECT count(DISTINCT httprequest.uri) as unique_uris, count(*) as total_requests, min(from_unixtime(\"timestamp\"/1000)) as first_seen, max(from_unixtime(\"timestamp\"/1000)) as last_seen FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND httprequest.clientip = '{ip}' AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$')",
        "params": ["ip"],
        "description": "Unique non-static URI count and time span for an IP",
    },
    "top_allowed_by_volume": {
        "query": "filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ | stats count(*) as cnt, count_distinct(httpRequest.uri) as unique_uris by httpRequest.clientIp | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as cnt, count(DISTINCT httprequest.uri) as unique_uris FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'ALLOW' AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$') GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Top ALLOW IPs with unique non-static URI count",
    },
    "top_allowed_crawlers": {
        "query": "filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ and @message not like 'bot:verified' | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris, min(@timestamp) as first_seen, max(@timestamp) as last_seen by httpRequest.clientIp | filter unique_uris > 50 | sort unique_uris desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total, count(DISTINCT httprequest.uri) as unique_uris FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'ALLOW' AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$') AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') ) GROUP BY httprequest.clientip HAVING count(DISTINCT httprequest.uri) > 50 ORDER BY unique_uris DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Find IPs with high URI diversity (likely crawlers)",
    },
    "top_allowed_repeaters": {
        "query": "filter action = 'ALLOW' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/ and @message not like 'bot:verified' | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris, min(@timestamp) as first_seen, max(@timestamp) as last_seen by httpRequest.clientIp | filter total > 200 and unique_uris < 10 | sort total desc | limit {limit}",
        "athena": "SELECT httprequest.clientip as \"httpRequest.clientIp\", count(*) as total, count(DISTINCT httprequest.uri) as unique_uris FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND action = 'ALLOW' AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$') AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') ) GROUP BY httprequest.clientip HAVING count(*) > 200 AND count(DISTINCT httprequest.uri) < 10 ORDER BY total DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Find IPs hitting few URIs at high frequency",
    },
    "token_reuse_ips": {
        "query": "filter @message like 'token:accepted' | parse @message '\"name\":\"cookie\",\"value\":\"*\"' as cookie | stats count_distinct(httpRequest.clientIp) as ip_count, count(*) as total by cookie | sort ip_count desc | limit {limit}",
        "athena": "SELECT element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value as cookie, count(DISTINCT httprequest.clientip) as ip_count, count(*) as total FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND any_match(labels, l -> l.name LIKE '%token:accepted%') GROUP BY element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value ORDER BY ip_count DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Detect token reuse across multiple IPs",
    },
    "host_traffic_profile": {
        "query": "parse @message /\\{\"name\":\"(H|h)ost\",\"value\":\"(?<host>.*?)\"\\}/ | stats count(*) as total, count_distinct(httpRequest.uri) as unique_uris, sum(strcontains(httpRequest.httpMethod, 'POST') + strcontains(httpRequest.httpMethod, 'PUT') + strcontains(httpRequest.httpMethod, 'DELETE')) as write_requests by host | sort total desc | limit {limit}",
        "athena": "SELECT element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value as host, count(*) as total, count(DISTINCT httprequest.uri) as unique_uris, sum(CASE WHEN httprequest.httpmethod IN ('POST','PUT','DELETE') THEN 1 ELSE 0 END) as write_requests FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} GROUP BY element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value ORDER BY total DESC LIMIT {LIMIT}",
        "params": [],
        "description": "Traffic profile per Host header",
    },
    "host_uri_pattern": {
        "query": "parse @message /\\{\"name\":\"(H|h)ost\",\"value\":\"(?<host>.*?)\"\\}/ | filter host = '{host}' | stats count(*) as cnt by httpRequest.uri | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.uri as \"httpRequest.uri\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value = '{host}' GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["host"],
        "description": "Top URIs for a specific host",
    },
    "host_method_distribution": {
        "query": "parse @message /\\{\"name\":\"(H|h)ost\",\"value\":\"(?<host>.*?)\"\\}/ | filter host = '{host}' | stats count(*) as cnt by httpRequest.httpMethod | sort cnt desc | limit {limit}",
        "athena": "SELECT httprequest.httpmethod as \"httpRequest.httpMethod\", count(*) as cnt FROM {TABLE} WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER} AND element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value = '{host}' GROUP BY httprequest.httpmethod ORDER BY cnt DESC LIMIT {LIMIT}",
        "params": ["host"],
        "description": "HTTP method distribution for a host",
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
    """Parse a date/datetime string to epoch seconds. Supports explicit offset or falls back to session/env. Returns None on failure."""
    from datetime import datetime, timezone, timedelta
    from tools.session_state import get_user_timezone
    value = value.strip()
    # If value contains explicit offset (e.g., +08:00, Z), use it directly
    for fmt in ("%Y-%m-%dT%H:%M%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M%z"):
        try:
            dt = datetime.strptime(value, fmt)
            # Auto-remember timezone from first explicit offset
            if get_user_timezone() is None:
                from tools.session_state import set_user_timezone
                set_user_timezone(dt.utcoffset().total_seconds() / 3600)
            return int(dt.timestamp())
        except ValueError:
            continue
    # Also try Python's fromisoformat for "+08:00" style
    try:
        if "+" in value[10:] or value.endswith("Z"):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if get_user_timezone() is None:
                from tools.session_state import set_user_timezone
                set_user_timezone(dt.utcoffset().total_seconds() / 3600)
            return int(dt.timestamp())
    except (ValueError, IndexError):
        pass
    # No explicit offset — use session state > env var > UTC+0
    session_tz = get_user_timezone()
    tz_offset = session_tz if session_tz is not None else float(os.environ.get("WAF_AGENT_TIMEZONE_OFFSET", "0"))
    user_tz = timezone(timedelta(hours=tz_offset))
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
    start_time: str,
    duration_minutes: int = 180,
    log_group: str = "",
    rule_name: str = "",
    ip: str = "",
    label: str = "",
    action: str = "",
    host: str = "",
    limit: int = 25,
) -> str:
    """Run a predefined AWS WAF log query against CloudWatch Logs Insights.

    IMPORTANT: You MUST provide start_time. Ask the user for the time period to investigate.
    Default window is 180 min (3h). Athena backend auto-caps at 60 min.

    Args:
        query_type: Type of query to run. Available types:
            - count_rule_top_ips: Top IPs triggering a COUNT rule (needs rule_name)
            - count_rule_top_uris: Top URIs for a COUNT rule (needs rule_name)
            - count_rule_top_uas: Top User-Agents for a COUNT rule (needs rule_name)
            - ip_cross_query: All actions/rules for an IP (needs ip)
            - ip_uri_breakdown: URI breakdown for an IP (needs ip)
            - ip_uri_prefix: URI path prefix clustering for an IP — shows crawl patterns (needs ip)
            - rule_uri_prefix: URI prefix clustering for a rule — which paths trigger it (needs rule_name)
            - top_ua_by_action: Top User-Agents grouped by action — find suspicious UAs
            - ip_request_timeline: Per-minute action timeline for an IP (needs ip)
            - ip_label_breakdown: All WAF labels on an IP — bot signals, Anti-DDoS, tokens (needs ip)
            - host_top_ips: Top IPs for a specific host/domain (needs host)
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
            - top_challenged_ips: Top IPs being challenged (DDoS/bot traffic) — USE THIS FOR DDOS
            - top_challenged_countries: Top countries being challenged
            - top_captcha_ips: Top IPs receiving CAPTCHA
            - top_captcha_countries: Top countries receiving CAPTCHA
            - top_counted_ips: Top IPs triggering COUNT rules
            - top_counted_countries: Top countries triggering COUNT rules
            - top_ips_by_volume: Top IPs by total request volume (ALL actions) — BEST for DDoS source ID
            - top_countries_by_volume: Top countries by total volume (ALL actions)
            - label_top_ips: Top IPs for an AWS WAF label (needs label)
            - ip_labels: All AWS WAF labels on a specific IP — Bot Control, Anti-DDoS, signals (needs ip)
            - action_timeline: Timeline of an action (needs action)
            - token_reuse_ips: Detect token reuse across multiple IPs
            - host_traffic_profile: Traffic profile per Host — identify frontend vs backend domains
            - host_uri_pattern: Top URIs for a specific host (needs host param)
            - host_method_distribution: HTTP method distribution for a host (needs host param)
        start_time: Start date/time for the query (e.g., "2026-05-09" or "2026-05-09T14:00"). REQUIRED — ask user if not provided.
        duration_minutes: Duration in minutes from start_time (default 180, max 360 for CWL, 60 for Athena). The query covers [start_time, start_time + duration_minutes].
        log_group: CW Logs log group name. Auto-detected from WebACL config if empty.
        rule_name: Rule name (for count_rule_* queries).
        ip: Client IP address (for ip_* queries).
        label: AWS WAF label name (for label_top_ips).
        action: Action value — BLOCK, ALLOW, COUNT (for action_timeline).
        host: Hostname (for host_uri_pattern, host_method_distribution).
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
        if not dest:
            # Auto-init: try to call get_waf_config if webacl_name is known
            from tools.session_state import get_webacl_name, get_scope
            wn = get_webacl_name()
            if wn:
                _log(f"auto-init: calling get_waf_config({wn})")
                from tools.waf_config import get_waf_config
                get_waf_config(webacl_name=wn, scope=get_scope() or "CLOUDFRONT")
                dest = get_log_destination()
            if not dest:
                _log(f"ABORT: no log destination in session state.")
                return "Error: No WebACL configured. Call get_waf_config(webacl_name='...') first to set up the session context (logging destination, capabilities)."
    else:
        dest = None  # explicit log_group provided

    # Build CWL query
    query = template["query"]
    for k, v in params.items():
        query = query.replace(f"{{{k}}}", str(v))
    # Resolve duration
    _duration = min(duration_minutes, MAX_MINUTES)
    _log(f"query_type={query_type} start_time={start_time} duration={_duration}min dest={dest or log_group}")

    # Execute via unified query layer (routes to CWL or Athena automatically)
    from tools.waf_query import query_logs, get_log_type, check_hourly_partition_block

    if not start_time:
        return "Error: start_time is required. Ask the user which time period to investigate.\nExample: run_logs_query(query_type=\"...\", start_time=\"2026-05-09T14:00\", duration_minutes=60)"

    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'. Use format: YYYY-MM-DD or YYYY-MM-DDTHH:MM"
    end_epoch = min(start_epoch + _duration * 60, int(time.time()))

    # Build Athena query with params substituted (only user params, not TABLE/START_MS/END_MS/PARTITION_FILTER)
    athena_query = template.get("athena", "")
    if athena_query:
        for k, v in params.items():
            if k == "limit":
                continue
            athena_query = athena_query.replace(f"{{{k}}}", str(v))
        athena_query = athena_query.replace("{LIMIT}", str(params["limit"]))

    # If explicit log_group provided, force CWL path
    if log_group:
        region = get_logs_region()
        client = get_client("logs", region_name=region)
        with _cwl_semaphore:
            resp = client.start_query(
                logGroupName=log_group, startTime=start_epoch, endTime=end_epoch,
                queryString=query, limit=params["limit"],
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
            return f"Query {result['status']}. QueryId: {query_id}"
        try:
            results = [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]
        except (KeyError, TypeError):
            results = []
    else:
        log_type = get_log_type()
        hourly_err = check_hourly_partition_block()
        if hourly_err:
            return hourly_err
        _log(f"routing via unified layer: log_type={log_type} start={start_epoch} end={end_epoch}")
        try:
            results = query_logs(query, athena_query, start_epoch, end_epoch, limit=params["limit"])
        except Exception as e:
            _log(f"ERROR in query_logs: {type(e).__name__}: {e}")
            return f"Log query failed: {type(e).__name__}: {e}"
        if not results:
            results = []
        elif results and isinstance(results[0], dict) and "_error" in results[0]:
            _log(f"query_logs returned error: {results[0]['_error']}")
            return results[0]["_error"]
        else:
            _log(f"query_logs returned {len(results)} results")

    if not results:
        msg = f"Query returned 0 results. (query: {query_type})"
        if is_log_filter_active():
            msg += "\n⚠️  A Log Filter is active on this WebACL — 0 results may be due to filtered-out log entries, not absence of traffic. Cross-check with get_waf_overview metrics."
        else:
            msg += "\nPossible reasons: (1) The action filter doesn't match — e.g. DDoS traffic uses CHALLENGE not BLOCK, try top_challenged_ips instead of top_blocked_ips. (2) Time window is wrong — verify start_time and timezone. (3) No traffic matching this filter exists in this period."
        return msg

    # Format as table (results is list[dict] from unified query layer)
    # Use row with most keys for column headers (some rows may lack group-by field)
    columns = [k for k in max(results[:MAX_RESULTS], key=lambda r: len(r)).keys() if not k.startswith("@ptr")]
    lines = [
        f"Query '{query_type}' returned {len(results)} results\n",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in results[:MAX_RESULTS]:
        values = [str(row.get(col, "")) for col in columns]
        lines.append("| " + " | ".join(values) + " |")

    # Append deterministic interpretation for specific query types
    interpretation = _interpret_results(query_type, results[:MAX_RESULTS])
    if interpretation:
        lines.append("\n" + interpretation)

    return "\n".join(lines)


def _interpret_results(query_type: str, rows: list[dict]) -> str:
    """Append deterministic interpretation + contextual hints to query results."""
    parts = []

    if query_type == "ip_labels":
        parts.append(_interpret_ip_labels(rows))
    elif query_type == "host_traffic_profile":
        parts.append(_interpret_host_profile(rows))

    # Contextual hints based on query type
    hint = _get_hint(query_type, rows)
    if hint:
        parts.append(hint)

    return "\n".join(parts)


def _get_hint(query_type: str, rows: list[dict]) -> str:
    """Return follow-up hints based on what was just queried."""
    hints = {
        "top_allowed_crawlers": "---\nNext:\n- Use analyze_ip on the top suspicious IPs above\n- Call ask_user() to ask: is there a specific URI path being targeted?",
        "top_allowed_repeaters": "---\nNext:\n- Use analyze_ip on the top suspicious IPs above\n- Call ask_user() to ask: is this a known API endpoint? Could be legitimate polling.",
        "top_blocked_ips": "---\nNext:\n- If user wants details on a specific IP, use analyze_ip\n- Call ask_user() to ask: are any of these IPs expected (partners, monitoring)?",
        "host_traffic_profile": "---\nNext:\n- Call ask_user() to ask: is the site SPA? Is AWS WAF Client SDK integrated?\n- For API hosts: Challenge/CAPTCHA won't work, recommend Block-based rules only",
        "count_rule_top_ips": "---\nNext:\n- Cross-validate top IPs with ip_cross_query\n- Call ask_user() to ask: is this rule protecting a file upload or rich-text endpoint? (likely FP if yes)",
    }
    return hints.get(query_type, "")


def _parse_interpolated_headers(inserted: str) -> list[str]:
    """Parse bot classification from requestHeadersInserted (Dynamic Label Interpolation).

    Returns list of findings, or empty list if no relevant headers found.
    Isolated from main logic — errors here must not affect label-based analysis.
    """
    findings = []
    # Look for common interpolation header patterns
    if "bot-category" in inserted:
        # Extract value after bot-category header name
        import re
        m = re.search(r'bot-category["\s:]+([^",}\]]+)', inserted)
        if m and m.group(1).strip():
            findings.append(f"🏷️ Bot Category (interpolated): {m.group(1).strip()}")
    if "bot-name" in inserted:
        import re
        m = re.search(r'bot-name["\s:]+([^",}\]]+)', inserted)
        if m and m.group(1).strip():
            findings.append(f"🏷️ Bot Name (interpolated): {m.group(1).strip()}")
    if "bot-signals" in inserted:
        import re
        m = re.search(r'bot-signals["\s:]+([^"}\]]+)', inserted)
        if m and m.group(1).strip():
            findings.append(f"🏷️ Bot Signals (interpolated): {m.group(1).strip()}")
    return findings


def _interpret_ip_labels(rows: list[dict]) -> str:
    """Classify AWS WAF labels into categories for the LLM."""
    all_labels = " ".join(row.get("Labels", "") for row in rows)
    findings = []

    # Enrichment: if requestHeadersInserted contains interpolated bot headers, use them directly
    try:
        inserted = " ".join(row.get("requestHeadersInserted", "") for row in rows)
        if inserted.strip():
            header_findings = _parse_interpolated_headers(inserted)
            if header_findings:
                findings.extend(header_findings)
                findings.append("(source: requestHeadersInserted via Dynamic Label Interpolation)")
                return "---\nLabel Interpretation:\n" + "\n".join(f"- {f}" for f in findings)
    except Exception:
        pass  # Fallback to labels-based analysis below

    # Bot Control
    if "bot:verified" in all_labels:
        findings.append("✅ Bot Control: VERIFIED bot (legitimate, should be allowed)")
    elif "bot:unverified" in all_labels:
        findings.append("⚠️ Bot Control: UNVERIFIED bot (claims bot identity but fails verification)")
    if "signal:non_browser_user_agent" in all_labels:
        findings.append("⚠️ Signal: Non-browser User-Agent detected")
    if "signal:automated_browser" in all_labels:
        findings.append("🔴 Signal: Automated browser detected")

    # Targeted Bot Control
    tgt_signals = []
    if "TGT_VolumetricSession" in all_labels:
        tgt_signals.append("VolumetricSession (abnormal session behavior)")
    if "TGT_SignalAutomatedBrowser" in all_labels:
        tgt_signals.append("AutomatedBrowser")
    if "TGT_TokenReuseIP" in all_labels:
        tgt_signals.append("TokenReuseIP (token shared across IPs)")
    if "TGT_TokenAbsent" in all_labels:
        tgt_signals.append("TokenAbsent (no AWS WAF token)")
    if "TGT_VolumetricIpTokenAbsent" in all_labels:
        tgt_signals.append("VolumetricIpTokenAbsent (5+ tokenless from same IP)")
    if tgt_signals:
        findings.append("🎯 Targeted Bot Control: " + ", ".join(tgt_signals))

    # Anti-DDoS
    if "event-detected" in all_labels:
        findings.append("🔴 Anti-DDoS: Event detected (AMR triggered)")
    if "high-suspicion" in all_labels:
        findings.append("🔴 Anti-DDoS: HIGH suspicion (blocked by default)")
    elif "medium-suspicion" in all_labels:
        findings.append("⚠️ Anti-DDoS: MEDIUM suspicion")
    elif "low-suspicion" in all_labels:
        findings.append("ℹ️ Anti-DDoS: LOW suspicion")
    if "ddos-request" in all_labels and "high-suspicion" not in all_labels:
        findings.append("⚠️ Anti-DDoS: Flagged as DDoS request")

    # No detection
    if not findings:
        findings.append("ℹ️ No managed rule labels detected — Bot Control/AMR did not flag this IP")

    return "---\nLabel Interpretation:\n" + "\n".join(f"- {f}" for f in findings)


def _interpret_host_profile(rows: list[dict]) -> str:
    """Classify each host as Web/API/Mixed based on write ratio."""
    findings = []
    for row in rows:
        host = row.get("host", "?")
        total = int(row.get("total", "0") or "0")
        writes = int(row.get("write_requests", "0") or "0")
        if total == 0:
            continue
        ratio = writes / total
        if ratio > 0.3:
            traffic_type = "API/Backend"
            note = "Challenge/CAPTCHA ineffective; use Block-based rules only"
        elif ratio > 0.1:
            traffic_type = "Mixed (Web + API)"
            note = "needs scope-down to separate browser vs API traffic"
        else:
            traffic_type = "Web/Frontend"
            note = "Challenge/Bot Control Targeted effective"
        findings.append(f"- {host}: **{traffic_type}** (write ratio {ratio:.0%}) — {note}")

    if not findings:
        return ""
    return "---\nTraffic Type:\n" + "\n".join(findings)


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
            time.sleep(POLL_INTERVAL)  # nosemgrep: arbitrary-sleep — polling for CWL query
            elapsed += POLL_INTERVAL
            result = client.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
        if result["status"] != "Complete":
            return []
        return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]


@tool
def analyze_ip(ip: str, start_time: str, duration_minutes: int = 180) -> str:
    """Analyze a single IP address — full behavioral profile across all actions.

    Two-phase: diversity check first (NAT detection), then full analysis if not NAT.
    Use this for general IP investigation (any action). For bypass-specific analysis
    (ALLOW-only), use detect_bypass(step='investigate_ip').

    Args:
        ip: IP address to analyze.
        start_time: Start date/time for the query (e.g., "2026-05-09" or "2026-05-09T14:00"). REQUIRED.
        duration_minutes: Duration in minutes from start_time (default 180, max 360 for CWL, 60 for Athena).

    Returns:
        Formatted analysis: NAT status, action breakdown, request rate, JA4 fingerprints, top URIs.
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return f"Error: invalid IP address '{ip}'"

    if not start_time:
        return "Error: start_time is required. Ask the user which time period to investigate.\nExample: analyze_ip(ip=\"1.2.3.4\", start_time=\"2026-05-09T14:00\", duration_minutes=60)"

    from tools.waf_query import query_logs, get_log_type, check_hourly_partition_block
    if get_log_type() == "none":
        return "Error: no logging configured. Run get_waf_config first."
    hourly_err = check_hourly_partition_block()
    if hourly_err:
        return hourly_err

    _duration = min(duration_minutes, MAX_MINUTES)
    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'. Use format: YYYY-MM-DD or YYYY-MM-DDTHH:MM"
    end_epoch = min(start_epoch + _duration * 60, int(time.time()))
    safe_ip = re.sub(r"[^0-9a-fA-F.:]", "", ip)

    # Phase 1: Diversity check (NAT detection)
    div_cwl = (
        f'filter httpRequest.clientIp = "{safe_ip}"'
        ' | parse @message /(?i)\\{"name":"user-agent","value":"(?<ua>.*?)"\\}/'
        ' | stats count_distinct(ua) as ua_count, count_distinct(ja4Fingerprint) as ja4_count, count(*) as total'
    )
    div_athena = (
        f"SELECT count(DISTINCT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value) as ua_count,"
        f" count(DISTINCT ja4fingerprint) as ja4_count, count(*) as total"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{safe_ip}'"
    )
    try:
        diversity = query_logs(div_cwl, div_athena, start_epoch, end_epoch, limit=1)
    except RuntimeError as e:
        return f"Log query failed: {e}"

    if not diversity:
        return f"No log records found for {ip} in this time window."

    d = diversity[0]
    ua_count = int(d.get("ua_count", "0"))
    ja4_count = int(d.get("ja4_count", "0"))
    total = int(d.get("total", "0"))

    # High diversity → check if NAT or UA rotation
    if ua_count > 3 and ja4_count > 3:
        ua_list_cwl = (
            f'filter httpRequest.clientIp = "{safe_ip}"'
            ' | parse @message /(?i)\\{"name":"user-agent","value":"(?<ua>.*?)"\\}/'
            ' | stats count(*) as cnt by ua | sort cnt desc | limit 20'
        )
        ua_list_athena = (
            f"SELECT element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value as ua,"
            f" count(*) as cnt"
            f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
            f" AND httprequest.clientip = '{safe_ip}'"
            f" GROUP BY element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value"
            f" ORDER BY cnt DESC LIMIT 20"
        )
        ua_rows = query_logs(ua_list_cwl, ua_list_athena, start_epoch, end_epoch, limit=20)
        if not ua_rows or _is_nat_traffic(ua_rows):
            lines = [
                f"## {ip} — NAT/Shared IP (skipped)",
                "",
                f"Multiple UAs ({ua_count}) + multiple JA4s ({ja4_count}) = shared IP (NAT gateway).",
                f"Total requests: {total}",
                "",
                "**Confidence: HIGH** — genuine OS/browser diversity confirms multiple real users behind this IP.",
                "No further analysis needed — blocking this IP would affect multiple legitimate users.",
            ]
            if is_log_filter_active():
                lines.append("\n⚠️  Log Filter active — diversity counts may be incomplete.")
            return "\n".join(lines)

    # Phase 2: Full analysis (not NAT)
    cross_cwl = (
        f'filter httpRequest.clientIp = "{safe_ip}"'
        ' | stats count(*) as cnt by action, terminatingRuleId | sort cnt desc | limit 15'
    )
    cross_athena = (
        f"SELECT action, terminatingruleid as \"terminatingRuleId\", count(*) as cnt"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{safe_ip}'"
        f" GROUP BY action, terminatingruleid ORDER BY cnt DESC LIMIT 15"
    )

    rate_cwl = (
        f'filter httpRequest.clientIp = "{safe_ip}"'
        ' | stats count(*) as req_per_min by bin(1m)'
        ' | stats avg(req_per_min) as avg_rpm, max(req_per_min) as peak_rpm, count(*) as active_minutes'
    )
    rate_athena = (
        f"SELECT max(cnt) as peak_rpm, avg(cnt) as avg_rpm, count(*) as active_minutes FROM ("
        f"  SELECT date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i') as minute, count(*) as cnt"
        f"  FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f"  AND httprequest.clientip = '{safe_ip}'"
        f"  GROUP BY date_format(from_unixtime(\"timestamp\"/1000), '%Y-%m-%d %H:%i')"
        f")"
    )

    ja4_cwl = (
        f'filter httpRequest.clientIp = "{safe_ip}"'
        ' | stats count(*) as cnt by ja4Fingerprint | sort cnt desc | limit 5'
    )
    ja4_athena = (
        f"SELECT ja4fingerprint as \"ja4Fingerprint\", count(*) as cnt"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{safe_ip}'"
        f" GROUP BY ja4fingerprint ORDER BY cnt DESC LIMIT 5"
    )

    uri_cwl = (
        f'filter httpRequest.clientIp = "{safe_ip}"'
        ' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/'
        ' | stats count_distinct(httpRequest.uri) as unique_uris, count(*) as total_non_static'
    )
    uri_athena = (
        f"SELECT count(DISTINCT httprequest.uri) as unique_uris, count(*) as total_non_static"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND httprequest.clientip = '{safe_ip}'"
        f" AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$')"
    )

    # Run queries (sequential via unified layer — each is fast with IP filter)
    cross = query_logs(cross_cwl, cross_athena, start_epoch, end_epoch, limit=15) or []
    rate = query_logs(rate_cwl, rate_athena, start_epoch, end_epoch, limit=1) or []
    ja4 = query_logs(ja4_cwl, ja4_athena, start_epoch, end_epoch, limit=5) or []
    uri_div = query_logs(uri_cwl, uri_athena, start_epoch, end_epoch, limit=1) or []

    # Format output
    lines = [f"## IP Analysis: {ip}", f"Time window: {_duration}min from {start_time}", ""]

    # Diversity summary
    lines.append(f"**Diversity**: {ua_count} UAs, {ja4_count} JA4 fingerprints, {total} total requests")
    if ua_count > 1 and ja4_count == 1:
        lines.append("⚠️ Multiple UAs but single JA4 = likely UA spoofing (same TLS stack)")
    elif ua_count == 1 and ja4_count == 1:
        lines.append("Single UA + single JA4 = single client")
    lines.append("")

    # Action breakdown
    lines.append("**Action breakdown**:")
    for row in cross[:10]:
        lines.append(f"  {row.get('action', '?')} / {row.get('terminatingRuleId', 'default')} : {row.get('cnt', '0')}")
    lines.append("")

    # Request rate
    if rate:
        r = rate[0]
        avg_rpm = r.get("avg_rpm", "0")
        peak_rpm = r.get("peak_rpm", "0")
        active_min = r.get("active_minutes", "0")
        lines.append(f"**Request rate**: avg {avg_rpm} req/min, peak {peak_rpm} req/min, active {active_min} minutes")
    lines.append("")

    # JA4 fingerprints
    lines.append("**JA4 fingerprints**:")
    for row in ja4[:5]:
        lines.append(f"  {row.get('ja4Fingerprint', 'N/A')} : {row.get('cnt', '0')} requests")
    lines.append("")

    # URI diversity
    if uri_div and uri_div[0]:
        u = uri_div[0]
        unique = u.get("unique_uris", "0")
        total_ns = u.get("total_non_static", "0")
        lines.append(f"**URI diversity** (non-static): {unique} unique URIs out of {total_ns} requests")
    lines.append("")

    # Confidence assessment
    lines.append("---")
    lines.append("## Assessment")
    try:
        peak_val = float(rate[0].get("peak_rpm", "0")) if rate else 0
    except (ValueError, TypeError):
        peak_val = 0
    try:
        uri_val = int(uri_div[0].get("unique_uris", "0")) if uri_div else 0
    except (ValueError, TypeError):
        uri_val = 0

    if ua_count > 1 and ja4_count == 1 and peak_val > 50:
        lines.append("**HIGH CONFIDENCE: Bot with UA rotation.** Multiple UAs but single JA4 fingerprint = same TLS client spoofing User-Agent.")
    elif peak_val > 200 and uri_val > 50:
        lines.append("**HIGH CONFIDENCE: Automated scraper.** Peak >200 req/min + >50 unique URIs.")
    elif peak_val > 200 and uri_val < 10:
        lines.append("**HIGH CONFIDENCE: Endpoint hammering.** Peak >200 req/min concentrated on few URIs.")
    elif uri_val > 50:
        lines.append("**LIKELY: Probable crawler/scraper.** High URI diversity but moderate frequency. Needs user confirmation.")
    else:
        lines.append("**CANNOT DETERMINE** — signals are mixed. Ask user for business context on this IP.")

    lines.append("")
    lines.append("→ If malicious: suggest user add IP to block list or adjust rate-limit threshold.")
    lines.append("→ For JA4 fingerprint analysis: lookup_ja4(fingerprints=[...])")
    if is_log_filter_active():
        lines.append("\n⚠️  Log Filter active — this analysis only covers logged actions. Some requests may be filtered out.")
    return "\n".join(lines)
