# Design: SEARCH → MetricStat Migration

## Problem

CloudWatch SEARCH expressions depend on the `ListMetrics` index. If a metric has no new data points for ~14 days, it disappears from the index and SEARCH returns empty results — even though the underlying data is retained for 63 days (at 5-min rollup).

This causes empty reports for users in test/demo environments with intermittent traffic.

## Solution

Two-phase approach focused on user expectation management, not over-engineering:

1. **Phase 1**: Convert fixed-dimension SEARCH queries to MetricStat (extends queryable window from 14 days to 63 days for core metrics)
2. **Phase 2**: Add missing-data indicators in reports + structured hints to LLM when SEARCH returns empty

**Explicitly NOT doing**: Dimension caching, DynamoDB/S3 storage, list_metrics fallback. The 14-day SEARCH limitation is acceptable for test environments — users just need to know they need traffic.

## Retention Rules (Confirmed)

| Storage Resolution | Retention | Query Period Requirement |
|---|---|---|
| 1 minute (WAF default) | 15 days | period ≥ 60 |
| 5 minutes (rollup) | 63 days | period ≥ 300 |
| 1 hour (rollup) | 455 days | period ≥ 3600 |

- SEARCH/ListMetrics index: ~14 days after last data point
- MetricStat (explicit dimensions): full retention (63 days at 5-min)
- WAF publishes at 1-min resolution, only when value > 0 (sparse)

## SEARCH Inventory

### Category A: Fixed Dimensions (Phase 1 — convert to MetricStat)

These have known, static dimension values. Convert immediately.

| # | File | Line | Current SEARCH | Dimensions |
|---|------|------|----------------|------------|
| A1 | report.py | 939-942 | `SUM(FILL(SEARCH(... Rule="ALL" MetricName="AllowedRequests"), 0))` (×4 metrics) | WebACL, Rule=ALL |
| A2 | report.py | 974 | `SUM(FILL(SEARCH(... Rule="ALL" MetricName=("Blocked" OR "Challenge" OR "Captcha")), 0))` | WebACL, Rule=ALL |
| A3 | report.py | 765 | `SUM(FILL(SEARCH(... LabelName="event-detected"), 0))` | WebACL, LabelNamespace=anti-ddos, LabelName=event-detected |
| A4 | report.py | 975 | `SUM(FILL(SEARCH(... LabelName="ddos-request" MetricName="ChallengeRequests"), 0))` | WebACL, LabelNamespace=anti-ddos, LabelName=ddos-request |
| A5 | report.py | 1035 | `SUM(FILL(SEARCH(... LabelName="ddos-request"), 0))` | Same as A4 |
| A6 | waf_patrol.py | 280 | `SUM(FILL(SEARCH(... LabelName="event-detected"), 0))` | Same as A3 |
| A7 | waf_patrol.py | 846 | `SUM(FILL(SEARCH(... Rule="ALL" MetricName=("Blocked" OR "Challenge" OR "Captcha")), 0))` | Same as A2 |
| A8 | waf_bypass.py | 151 | `SUM(FILL(SEARCH(... LabelName=...), 0))` | WebACL, LabelNamespace, LabelName (from function params) |

#### Implementation detail: FILL behavior

Current code uses `SUM(FILL(SEARCH(...), 0))` which produces dense time series (zeros for missing intervals). MetricStat alone returns sparse data. To preserve dense arrays for chart code:

```python
# Define MetricStat with ReturnData=False, then wrap in FILL expression
{"Id": "raw", "MetricStat": {...}, "ReturnData": False},
{"Id": "filled", "Expression": "FILL(raw, 0)", "ReturnData": True},
```

This is required for A2, A3, A4, A5, A6, A7 where chart code expects dense arrays.

#### Implementation detail: A4/A5 ddos-request fallback

DDoS mitigation may use Challenge OR Block. The current code (commit ae38887) has fallback logic: if `ddos-request` returns empty, try `challengeable-request`. The MetricStat conversion must preserve this:

```python
# Primary: ddos-request + ChallengeRequests
# Fallback: challengeable-request + ChallengeRequests
```

### Category B: Semi-Dynamic (rule names from WebACL config)

Rule names are known from `get_web_acl` response. **Not converting in Phase 1** — these remain as SEARCH. Phase 2 adds indicators if they return empty.

| # | File | Line | Current SEARCH | Notes |
|---|------|------|----------------|-------|
| B1 | waf_patrol.py | 312-316 | `SEARCH({Rule,WebACL} ... MetricName="BlockedRequests")` ×5 metrics | `_get_all_rules_metrics_search` — most complex SEARCH consumer. Returns per-rule breakdown for ALL rules simultaneously. High-risk conversion (would need one MetricStat per rule × 5 metrics). Excluded from Phase 1. |
| B2 | report.py | 1150 | `SEARCH({Rule,WebACL} ...)` for top rules | Same pattern as B1 |

### Category C: Dynamic Dimensions (remain as SEARCH, Phase 2 adds indicators)

Dimension values are unknown upfront. These remain as SEARCH. Phase 2 adds user-facing warnings when they return empty.

| # | File | Line | Dimension | Values (example) |
|---|------|------|-----------|-----------------|
| C1 | report.py | 973 | Attack | XSS, SQLi, GenericLFI, Volumetric, KnownBadInputs |
| C2 | report.py | 1114-1116 | Country | US, IE, SG, AU, BR, JP, NL, DE, RU |
| C3 | report.py | 574 | LabelName (bot-control) | CategoryAI, TGT_VolumetricIpTokenAbsent, ... |
| C4 | report.py | 606-609 | BotName | route53_health_check, chatgpt_user, claudebot, ... |
| C5 | waf_patrol.py | 845 | Attack | Same as C1 |
| C6 | waf_patrol.py | 912-915 | LabelName (targeted signals) | Same as C3 |
| C7 | waf_patrol.py | 944 | LabelName (bot:name) | Same as C4 |
| C8 | waf_overview.py | 215 | Attack | Same as C1 |
| C9 | waf_overview.py | 310 | LabelName (bot:name) | Same as C4 |
| C10 | waf_overview.py | 336-339 | LabelName (targeted) | Same as C3 |
| C11 | waf_overview.py | 472 | LabelName (all) | All labels for WebACL |

## Implementation Plan

### Phase 1: Fixed Dimensions → MetricStat

Convert Category A queries (~8 locations). Straightforward replacement.

Key implementation details:
- Use `MetricStat` + `FILL(id, 0)` expression to maintain dense time series
- A4/A5: preserve ddos-request → challengeable-request fallback logic
- Handle CLOUDFRONT (no Region dim) vs REGIONAL (Region dim required)

Files: `report.py`, `waf_patrol.py`, `waf_bypass.py`

### Phase 2: Missing Data Indicators

Add empty-result detection to Category B and C SEARCH queries:
- If SEARCH returns 0 results for a section, render a user-friendly warning in the report HTML
- Add structured hint to tool return string so LLM can explain to user

**In report HTML:**
```html
<p class="muted">⚠️ 无数据 — 该 WebACL 最近 14 天无此类流量，CloudWatch 指标索引已过期。
请产生流量后重新生成报告。</p>
```

**In tool return to LLM:**
```
PARTIAL_DATA: true
MISSING_SECTIONS: ["attack_types", "country_map"]
REASON: CloudWatch metric discovery index expired (no traffic in ~14 days for these dimensions).
ACTION: Inform user that some sections are empty because the WebACL had no matching traffic recently. Suggest generating test traffic and re-running.
```

Files: `report.py`, `waf_patrol.py`

## Test Results (2026-05-24)

**⚠️ IMPORTANT CAVEAT**: SEARCH results below are valid ONLY because we generated traffic on 5/24, which re-populated the ListMetrics index. Before that traffic, SEARCH for Country returned empty for 5/9 data while MetricStat still returned correct results. This confirms the core problem.

All queries tested against `shield-sample-webacl` for 2026-05-09 (15 days ago):

| Query Type | SEARCH | MetricStat | Category |
|---|---|---|---|
| Rule=ALL (Blocked) | 22,858 | 22,858 | A (fixed) |
| Rule=ALL (Challenge) | 383,221 | 383,221 | A (fixed) |
| event-detected | 317,195 | 317,195 | A (fixed) |
| ddos-request | 317,116 | 317,116 | A (fixed) |
| Per-rule (rate-limit) | 22,715 | 22,715 | B (semi-dynamic) |
| Per-rule (BotControl) | 43,085 | 43,085 | B (semi-dynamic) |
| Attack (XSS) | 15 | 15 | C (dynamic) |
| Attack (Volumetric) | 22,715 | 22,715 | C (dynamic) |
| Country (US) | 140,897 | 140,897 | C (dynamic) |
| Country (IE) | 129,384 | 129,384 | C (dynamic) |
| Bot names | 17 found | 17 found | C (dynamic) |
| Targeted signals | 10 labels | 10 labels | C (dynamic) |

## Risks

1. **FILL behavior**: MetricStat without FILL returns sparse arrays. Chart code expects dense arrays. Must use `FILL(metricstat_id, 0)` expression wrapper. Tested and confirmed working.
2. **CLOUDFRONT scope**: CloudFront WAF metrics are always in us-east-1 with NO Region dimension. Regional WAF requires Region dimension. Code already handles both — preserve this.
3. **ddos-request vs challengeable-request**: DDoS label name depends on AMR version and mitigation mode. Must preserve existing fallback logic.
4. **GetMetricData 500-query limit**: Phase 1 adds at most ~10 queries per call. Well within limits.
