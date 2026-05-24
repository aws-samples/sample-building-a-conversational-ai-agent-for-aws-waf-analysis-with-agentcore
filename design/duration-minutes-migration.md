# Design: duration_hours → duration_minutes Migration

## Problem

All log-query tools use `duration_hours` (float, min 1h granularity) for time window control. In high-traffic environments (1B+ requests/day), even 1 hour = 41M log entries — queries are slow and expensive.

LLM needs minute-level control (5/15/60 min) to adapt query window to traffic volume. Currently it can only pass `duration_hours=0.25` for 15 minutes, which is unintuitive and poorly documented.

## Solution

Rename `duration_hours` → `duration_minutes` (int) across all tools. Default from 60 (1 hour). Remove `hours_ago` backward-compat alias entirely.

Additionally, `_step_analyze_rule` in `waf_count_eval.py` should NOT auto-query logs. It should return peak hour + hit count, letting LLM decide the query window.

## Files Affected

| File | Functions | Current Interface |
|------|-----------|-------------------|
| `agent.py` | System prompt | References `duration_hours` in 6+ places |
| `tools/waf_logs.py` | `run_logs_query`, `analyze_ip` | `duration_hours: float = 6, hours_ago: float = None` |
| `tools/waf_athena.py` | `run_athena_query`, `_time_filter`, `_build_query` | `hours_ago: int = 6` |
| `tools/waf_bypass.py` | `detect_bypass` | `duration_hours: float = 6, hours_ago: float = None` |
| `tools/waf_block_fp.py` | `investigate_block_fp` | `duration_hours: float = 6, hours_ago: float = None` |
| `tools/waf_count_eval.py` | `evaluate_count_rules`, `_step_check_clients`, `_step_analyze_rule` | `duration_hours: float = 1, hours_ago: float = None` |
| `tools/waf_challenge_check.py` | challenge check | `duration_hours` |
| `tools/waf_overview.py` | Hint text only | References `duration_hours=1` in output |
| `tools/waf_query.py` | Hint text only | References `duration_hours=1` in output |

## New Interface

```python
# Before
run_logs_query(query_type="top_ips_by_volume", start_time="2026-05-09T14:00", duration_hours=2)

# After
run_logs_query(query_type="top_ips_by_volume", start_time="2026-05-09T14:00", duration_minutes=60)
```

### Parameters

- `duration_minutes: int` — Query window in minutes from start_time. Default 60. Max 360 (6 hours).
- Remove `hours_ago` alias entirely (dead weight, confusing name).

### Defaults

| Tool | Old Default | New Default | Rationale |
|------|-------------|-------------|-----------|
| `run_logs_query` | 6h | 60 min | LLM should choose based on traffic volume |
| `run_athena_query` | 6h | 60 min | Same |
| `detect_bypass` | 6h | 60 min | Bypass scan should be focused |
| `investigate_block_fp` | 6h | 60 min | Same |
| `evaluate_count_rules` | 1h | 60 min | Same (was already 1h) |
| `analyze_ip` | 6h | 60 min | Same |

### Max Window

**Unified 60-minute max for both CWL and Athena.** No distinction between log backends.

Current state:
- Athena: code-enforced 1h max in `waf_query.py` (returns `_error` if > 1.1h)
- CWL: code allows 6h (`MAX_HOURS = 6`) — but CWL Insights also has 15-min timeout risk on high-volume log groups

New state:
- Both: max 60 minutes. `MAX_MINUTES = 60` replaces `MAX_HOURS = 6`.
- Remove the separate Athena cap in `waf_query.py` (redundant once all callers are capped at 60 min).
- If LLM needs longer window → split into multiple calls (already documented in agent.py prompt).

## LLM Guidance (agent.py changes)

Replace all `duration_hours` references with `duration_minutes`. Add adaptive window guidance:

```
- Choose duration_minutes based on traffic volume:
  - < 1K hits in peak hour → duration_minutes=60
  - 1K-10K hits in peak hour → duration_minutes=15
  - > 10K hits in peak hour → duration_minutes=5
- If query times out, halve duration_minutes and retry.
- Use get_waf_overview(query_type='top_rules') first to gauge traffic volume before choosing window.
```

## _step_analyze_rule Refactor

### Before (current)
1. Find peak hour via metrics (period=3600)
2. Auto-query logs for that hour
3. Return IP distribution

### After
1. Find peak hour via metrics (period=3600)
2. Return peak hour + hit count + suggested duration_minutes
3. LLM decides window, calls `check_low_volume_clients(duration_minutes=N)`

Return format:
```
## Rule Analysis: {rule_name}
Peak hour: 2026-05-09T14:00
Hits in peak hour: 8,432

## Your Next Action
Based on hit volume (8,432/hour ≈ 140/min), recommend duration_minutes=15.
Call: evaluate_count_rules(step='check_low_volume_clients', rule_name='...', start_time='2026-05-09T14:00', duration_minutes=15)
```

## waf_block_fp.py Adaptive Hint

Add volume-based narrowing hint (like bypass already has):
```python
if result_count > 500:
    lines.append(f"⚠️ High result volume ({result_count}). Consider narrowing: "
                 f"investigate_block_fp(..., duration_minutes={duration_minutes // 2})")
```

## Implementation Order

1. `tools/waf_logs.py` — core interface change (run_logs_query, analyze_ip)
2. `tools/waf_athena.py` — same change (run_athena_query)
3. `tools/waf_count_eval.py` — interface + _step_analyze_rule refactor
4. `tools/waf_bypass.py` — interface change
5. `tools/waf_block_fp.py` — interface + adaptive hint
6. `tools/waf_challenge_check.py` — interface change
7. `tools/waf_overview.py`, `tools/waf_query.py` — hint text updates
8. `agent.py` — system prompt updates (all duration_hours refs + adaptive guidance)

## Backward Compatibility

None needed. The LLM is the only caller — it reads the function signature from the tool definition. Once we change the parameter name, the LLM will use the new name immediately. No external API consumers.

## Risks

1. **LLM might default to large windows out of habit** — Mitigate with strong guidance in agent.py system prompt.
2. **5-minute window might have too few samples for FP analysis** — Tool should warn if < 10 unique IPs found: "Low sample size. Consider increasing duration_minutes."
3. **Athena partition pruning** — Athena partitions are typically hourly. A 5-minute query still scans the full hour partition. Cost is the same, but result set is smaller (faster transfer). This is fine.

## Lessons from Previous Migration (hours_ago → duration_hours)

Commit history: `0dbb384` → `1daa4f9` → `810eea8` → `ee28c47`

**Bug encountered**: `duration_hours` was declared as `float` so LLM could pass `0.25` (15 min) or `0.5` (30 min). But `float * 3600` produced float epoch values, causing `ParamValidationError` from CloudWatch and Athena APIs (require int). Fix was wrapping all epoch calculations in `int()`.

**Why `duration_minutes: int` avoids this**: Integer minutes × 60 = integer seconds. No float arithmetic anywhere in the chain. Cleaner, no `int()` wrappers needed.
