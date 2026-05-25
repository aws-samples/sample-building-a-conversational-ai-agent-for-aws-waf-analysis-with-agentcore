# Changelog

## 0.9.0 (2026-05-25)

### Breaking Change: `duration_hours` → `duration_minutes`

- All 6 log-querying tools renamed: `duration_hours` (float) → `duration_minutes` (int)
- `hours_ago` backward-compat alias removed entirely
- Integer arithmetic eliminates float→ParamValidationError bug class
- CWL: default 180 min, max 360 min. Athena: default 60 min, max 60 min (hard cap)

### New Query Types (6 added, total 36)

- `ip_uri_prefix` — URI path prefix clustering for an IP (crawl/scrape pattern detection)
- `rule_uri_prefix` — URI prefix clustering for a rule (FP vs attack signal for COUNT-to-BLOCK)
- `top_ua_by_action` — Global User-Agent distribution by action (bot/bypass detection)
- `ip_request_timeline` — Per-minute action timeline for an IP (rate-limit/DDoS analysis)
- `ip_label_breakdown` — All WAF labels on an IP (bot signals, Anti-DDoS, token status)
- `host_top_ips` — Top IPs per host/domain (multi-domain WebACL attack attribution)

### IP Attribution & Route 53 Misidentification Fix

- `ip_cross_query` now returns User-Agent in both CWL and Athena
- System prompt: mandatory IP identity verification before concluding malicious
- DDoS methodology step 6b: exclude benign services (Route 53 health checks, monitoring) using `bot:verified` label
- Query Type Selection Guide added to system prompt

### MetricStat for `top_rules` Totals

- `_top_rules` now gets `Rule=ALL` totals via MetricStat (immune to 14-day SEARCH index expiry)
- Previously, if Anti-DDoS rules hadn't fired in 14 days, weekly overview showed "0 mitigated" — now always accurate
- Gap warning fires correctly when per-rule SEARCH attribution is missing

### SEARCH Index Expiry Detection

- `attack_types`, `bot_names`, `targeted_signals`, `top_labels` now detect when SEARCH returns empty but MetricStat shows traffic exists
- Explicit ACTION hints guide LLM to inform user and use alternative queries (top_rules, bot_summary, logs)
- No false warnings when data genuinely doesn't exist

### Athena Reliability

- Auto-resolve Athena output location from WAF log bucket (fallback when workgroup not configured)
- Validate table path on reuse — detect log delivery method changes (Firehose ↔ Vended Logs)
- Validate partition format + interval on reuse — detect S3 structure changes
- Block queries on hourly partitions — guide user to configure minute-level partitioning
- `s3:PutObject` permission added (scoped to `athena-results/*` prefix only)
- Silent `return None` replaced with `RuntimeError` — errors now surface to LLM instead of showing "0 results"

### Build & Deployment

- Build-time version injection (`version.json` with commit hash + timestamp)
- System prompt shows `Agent version: <commit> (<time>)` — users can verify container is current
- Deployment guide updated: always use unique commit hash tags (not `:latest`)
- `--build-arg BUILD_COMMIT` and `BUILD_TIME` documented for both Docker and finch

### `_step_analyze_rule` Refactor

- No longer auto-queries logs — returns peak hour + hit count + suggested `duration_minutes`
- LLM decides window size based on volume, then calls `check_low_volume_clients`

### Documentation

- User guide: metric discovery 14-day limitation, Athena output location, version check
- IAM permissions: `s3:PutObject` for Athena results, `glue:DeleteTable` restored
- Firehose minute-level partitioning guide (new doc)
- No-data caution rewritten to be user-friendly with actionable next steps

### Bug Fixes

- `_athena_cap_hit` dead code removed from `waf_bypass.py`
- Athena partition format mismatch — validate existing table before reuse
- Athena partition interval detection — use actual S3 interval (5min) not hardcoded 1
- Chinese IAM doc stale references fixed (`waf_agent_temp` → `waf_analysis_tmp`)

## 0.8.0 (2026-05-24)

### Breaking Change: `get_waf_overview` parameter renamed

- `hours` parameter renamed to `minutes` for finer granularity control
- Existing callers must update: `hours=24` → `minutes=1440`

### Time-Series Output & Zoom-In Capability

- **All metric functions now output full time-series data** — LLM can see spike shapes, duration, and timing
- **5-tier granularity**: 1-min (≤60min), 5-min (≤6h), 15-min (≤3d), 1-hour (≤1w), 4-hour (>1w)
- **Zoom-in methodology**: LLM guided to progressively narrow windows (1440→240→60 minutes) to locate exact spike timing before querying logs
- Functions with time-series: `top_rules`, `attack_types`, `bot_summary`, `rate_limits`, `challenge_solve_rate`

### DDoS Investigation Methodology

- **Explicit AMR rule identification**: LLM must verify rule names (ChallengeAllDuringEvent, ChallengeDDoSRequests, DDoSRequests) — prevents misattribution of custom rules to AMR
- **`top_labels` query type**: Lists all managed rule group labels with hit counts — confirms AMR/Bot Control involvement without guessing
- **`top_ips_by_volume` / `top_countries_by_volume`**: Action-agnostic DDoS source queries (works regardless of Challenge/Block/Count config)
- **Result validation step**: Flags when top IPs have low counts vs metrics (wrong time window)

### Timezone Handling

- **Timezone confirmation overlay**: User must select timezone before chatting, locked for session duration
- **Session timezone injected into system prompt**: LLM always sees "Session timezone: UTC+8" — eliminates double-conversion bugs
- **localStorage persistence**: Remembers last timezone choice, pre-selects browser TZ for first-time users

### Bug Fixes

- **fix: TypeError in `run_logs_query`** — results were double-parsed as CWL raw format
- **fix: `top_ips_by_volume` missing IP column** — CWL null group-by field caused column loss; added `filter ispresent()`
- **fix: KeyError TABLE when routing CWL queries** — `.format()` replaced with `.replace()` for user params only
- **fix: metric granularity** — was using entire window as one data point (`period=hours*3600`)
- **fix: checkbox double-toggle** — `stopPropagation` moved from `onChange` to `onClick`
- **fix: `ScanBy=TimestampAscending`** — time-series output now chronological in all functions
- **fix: query injection** — IP validation added to `waf_bypass`, `waf_block_fp`; rule_name sanitized in `waf_count_eval`
- **fix: timezone `.replace(tzinfo=utc)` discarding explicit offset** — now uses `.astimezone()` for tz-aware strings
- **fix: half-hour timezone support** — offset stored as float (India +5.5, Nepal +5.75)
- **fix: guard all `query_logs` callers** — RuntimeError from Athena no longer crashes tools

### New Query Types

- `top_challenged_ips` / `top_challenged_countries` — Challenge action sources
- `top_captcha_ips` / `top_captcha_countries` — CAPTCHA action sources
- `top_counted_ips` / `top_counted_countries` — COUNT action sources
- `top_ips_by_volume` / `top_countries_by_volume` — All actions combined
- `top_labels` — All managed rule group labels with hit counts
- `ip_uri_prefix` — URI path prefix clustering for an IP (crawl/scrape pattern detection)
- `rule_uri_prefix` — URI prefix clustering for a rule (FP vs attack signal for COUNT-to-BLOCK)
- `top_ua_by_action` — Global User-Agent distribution by action (bot/bypass detection)
- `ip_request_timeline` — Per-minute action timeline for an IP (rate-limit/DDoS analysis)
- `ip_label_breakdown` — All WAF labels on an IP (bot signals, Anti-DDoS, token status)
- `host_top_ips` — Top IPs per host/domain (multi-domain WebACL attack attribution)

### Other

- Removed unused `strands-agents-tools` dependency (42% smaller lock file)
- Added stderr logging to `waf_logs`, `waf_overview`, `waf_bypass` for debugging
- Frontend: connection status indicator with auto-retry
- Frontend: sidebar tooltips for quick-start items
- `js-cookie` override to 3.0.7 (CVE fix)

### Athena Performance & Robustness

- **Unified query window caps**: Athena hard-capped at 60 min, CWL defaults to 180 min (max 360 min). Enforced at tool level — no separate cap in `waf_query.py`.
- **Partition pruning fix**: `_ensure_athena_table` now detects partition format for existing tables (was only set during table creation, causing full scans on pre-existing tables).
- **Error surfacing**: Query errors bubble up to LLM (previously `detect_bypass` and `evaluate_count_rules` silently returned empty results).
- **Metrics-based peak detection**: `evaluate_count_rules(step='analyze_rule')` returns peak hour + hit count only — does NOT auto-query logs. LLM decides window based on volume.
- **Improved timeout message**: Suggests `duration_minutes=30` or `duration_minutes=15` instead of generic "timed out".
- **User expectation management**: LLM proactively informs user about Athena latency after `get_waf_config`.

### Parameter Rename: `duration_hours` → `duration_minutes`

- All 6 log-querying tools renamed: `duration_hours` (float) → `duration_minutes` (int)
- `hours_ago` backward-compat alias removed entirely
- Integer arithmetic eliminates float→ParamValidationError bug class
- Adaptive window guidance in system prompt: LLM starts with default, narrows based on results
- `_athena_cap_hit` dead code removed from `waf_bypass.py`

### Report Improvements

- **Title**: "管理层周报" / "Executive Summary" (was "AWS WAF 安全周报")
- **Unified headers**: Both reports show WebACL name, scope, time range, gen time, timezone, delay note
- **Light theme chart fix**: `<html class="dark">` at top + Chart.js color update on toggle
- **Country map**: Includes Challenge + Captcha (not just Block) — DDoS-heavy WebACLs now show data
- **i18n**: DDoS section cards, delay note, "Generated" label all localized
- **IP Reputation check**: Validates `AmazonIpReputationList` (deployed) not `AnonymousIpList` (optional)

### CloudWatch MetricStat Migration (Phase 1)

- Fixed-dimension SEARCH queries converted to explicit MetricStat + FILL — extends queryable window from ~14 days (SEARCH index expiry) to 63 days (5-min rollup retention)
- Converted: Rule=ALL metrics, event-detected, ddos-request, total_m
- DDoS fallback: queries both `ddos-request` and `challengeable-request` labels

### Missing Data Indicators (Phase 2)

- When SEARCH returns empty (metric index expired), reports show user-friendly warning instead of blank space
- Tool return includes structured `PARTIAL_DATA` / `MISSING_SECTIONS` / `REASON` / `ACTION` for LLM

### WebACL Validation

- All tools validate WebACL name before querying metrics — returns available names + ACTION hint if not found

## 0.7.0 (2026-05-18)

### New Tool: `detect_bypass` — Bypass/Evasion Detection

- **3-step workflow**: `scan` (proactive anomaly detection), `investigate_ip` (single IP behavioral profile), `volume_anomaly` (WoW metrics comparison)
- **Anomaly-based filtering**: Crawlers (>50 unique URIs), repeaters (>200 req, <10 URIs), data-center IPs without bot labels, automation UAs (curl/python-requests/wget)
- **Coverage gap detection**: Auto-checks if Bot Control, rate-based rules, Anti-DDoS AMR are deployed
- **Volume anomaly classification**: Distinguishes classic DDoS vs cache-bypass DDoS vs scraper based on IP distribution + URI patterns
- **Confidence levels**: HIGH / LIKELY / CANNOT DETERMINE embedded in every output
- **Step flow guidance**: volume_anomaly → scan → investigate_ip, with reverse flow hints

### New Tool: `evaluate_count_rules` — COUNT-to-Block Workflow

- **Metrics-based init**: Uses CloudWatch Metrics (accurate, free) instead of CWL parse for hit counts
- **Rule classification**: Permanent-count / zero-hit / low-FP / needs-analysis
- **Peak hour detection**: Finds optimal analysis window
- **Client distribution analysis**: Top/bottom IPs, unique IP count

### New Tool: `investigate_block_fp` — False Positive Investigation

- **Two modes**: `investigate` (specific IP) and `scan` (proactive FP audit)
- **8-dimension analysis**: Block rule, sub-rule extraction, allow ratio, frequency, multi-rule check, URI distribution, match detail, text transformations
- **Batch ALLOW query**: Single query for all candidate IPs (not N queries)

### New Tool: `check_challenge_compatibility` — Challenge/CAPTCHA Analysis

- **URI/method distribution**: Shows which endpoints are being challenged
- **Anti-DDoS event detection**: Flags ChallengeAllDuringEvent activity
- **Incompatibility warnings**: API endpoints, native apps

### Unified Query Layer (`waf_query.py`)

- **Dual backend**: All log-querying tools now support both CWL and Athena (S3)
- **Auto-routing**: Detects log destination, routes to correct backend
- **Partition pruning**: Auto-injects `log_time` partition filter for Athena queries
- **`run_logs_query` upgraded**: All 20 templates now have Athena SQL versions
- **`analyze_ip` upgraded**: Migrated from CWL-only to unified query layer

### Athena Query Fixes (verified against live data)

- **`EXISTS(SELECT 1 FROM UNNEST(...))` → `any_match()`**: Athena doesn't support correlated subqueries with UNNEST in WHERE + GROUP BY. Replaced with `any_match(array, predicate)` (26 occurrences across 6 files)
- **`NOT EXISTS` → `none_match` + NULL guard**: `NOT any_match(NULL, ...)` returns NULL (filters out rows). Fixed to `(labels IS NULL OR none_match(labels, ...))` (8 occurrences)
- **`CROSS JOIN UNNEST` → `EXISTS` for single-rule queries**: 6 queries in waf_count_eval.py optimized (init query keeps CROSS JOIN for GROUP BY)

### CWL Query Fixes (verified against live data)

- **Removed `.*?` non-greedy regex**: CWL Insights doesn't support non-greedy quantifiers in `parse`. Removed redundant parse lines, rely on `filter @message like` (5 occurrences)

### CloudWatch Metrics Fixes (verified against live data)

- **REGIONAL scope dimension set**: `{Rule,WebACL}` → `{Rule,WebACL,Region}` for REGIONAL WebACLs. CLOUDFRONT keeps `{Rule,WebACL}`. Cannot use unified set (verified with live API).
- **All callers updated**: `_get_all_rules_metrics_search`, `_get_top_rules`, `_get_traffic_timeseries`, `_get_attack_timeseries`, patrol_scan attack chart

### Knowledge Base

- **`kb-docs/fraud-control-atp-acfp.md`**: ATP and ACFP managed rule groups — detection capabilities, JS SDK telemetry, pricing, cost control, limitations

### System Prompt

- **All trigger patterns in English**: Removed Chinese from system prompt (LLM auto-detects user language)
- **Bypass detection triggers**: "any bypass" / "traffic spike" / "suspected DDoS" → detect_bypass
- **Clean stop guidance**: Credential stuffing / API abuse / backend compromise → do NOT call detect_bypass
- **Volume-first priority**: If user mentions both traffic anomaly AND bypass → volume_anomaly first

### Performance

- **Partition pruning**: All Athena queries include `{PARTITION_FILTER}` — 14-day scans go from full-table to partition-pruned
- **Batch queries**: scan step uses single batch query instead of per-IP loops
- **Narrow window guidance**: Tool output guides LLM to use 1-2h windows for best signal-to-noise

### Breaking Changes

- **`run_athena_query` removed**: `run_logs_query` now auto-routes to CWL or Athena based on log destination. Same interface, same query_types — no user-facing change. LLM no longer needs to choose between the two tools.

## 0.6.0 (2026-05-15)

### Security Patrol Report v2 — Complete Redesign

- **Chart-first design**: Replaced tables with donut charts (traffic distribution, bot activity), horizontal stacked bar charts (per-rule Top 10, rate-limit, targeted signals), and stacked area timeline (attack types)
- **Single WebACL mode**: Requires `webacl_name` + `start_time` (max 24h window) — no more scanning all WebACLs
- **WoW anomaly detection**: 3x = moderate, 10x = critical, with cold-start fallback ("昨日无基线")
- **Deep Bot Analysis**: Self-declared bot donut + targeted bot signals chart (TGT_VolumetricIpTokenAbsent, SignalNonBrowserUserAgent, CSP) + bot names bar chart. All via SEARCH (dynamic discovery, no hardcoded rules)
- **Bot-derived action items**: Unverified bots allowed in Count mode, high CSP traffic, targeted rule triggers
- **i18n (zh/en)**: All labels, action items, detection tools detail strings, footer
- **Timezone support**: UTC+8 for zh, UTC for en (chart labels + header)
- **Dark/Light theme toggle**: ☀️/🌙 button, CSS variables switch
- **Deterministic**: Zero LLM involvement — pure metrics + config analysis
- **S3/Athena adaptive**: Auto-creates permanent Athena table with partition pruning

### New Tool: `get_waf_overview`

- **Fast metrics-based answers** (2-4s, no log queries, up to 14 days)
- **7 query types**: `top_rules`, `attack_types`, `bot_summary`, `bot_names`, `targeted_signals`, `rate_limits`, `challenge_solve_rate`
- **Next-step hints**: Each response guides LLM to deeper log analysis when needed
- **Bridges overview → investigation**: LLM uses this for triage, then logs for details

### Time Range Enforcement (Breaking Change)

- **All log-querying tools** now require `start_time` parameter:
  - `run_logs_query`: max 6h
  - `run_athena_query`: max 6h
  - `analyze_ip`: max 6h
  - `patrol_scan`: max 24h
  - `generate_weekly_report`: max 7 days
- **Prevents**: Expensive full-week scans, LLM defaulting to large ranges without user confirmation
- **Athena**: Always creates permanent tables (removed temporary table logic, atexit cleanup)

### Tool Chain Improvements

- **Next-step hints** added to all investigation tools (run_athena_query, lookup_ja4, analyze_ip, get_waf_metrics)
- **System prompt updated**: Reflects new tool signatures, guides LLM to use `get_waf_overview` for overview questions before querying logs
- **Removed**: `finalize_patrol_report` (patrol_scan is now self-contained)

### Code Quality

- **Dead code removal**: -333 lines from waf_patrol.py (old v1 functions)
- **Consistent i18n pattern**: `_PATROL_I18N` dict with `L[...]` references throughout

## 0.5.0 (2026-05-12)

### Deep WAF Review

- **Comprehensive rules audit**: Deterministic pipeline (10 Python scripts) analyzes WebACL for security issues, misconfigurations, and optimization opportunities
- **Label dependency analysis**: Maps label producers → consumers, detects broken chains and priority ordering issues
- **18+ automated checks**: Forgeable Allow rules, scope-down issues, missing baselines, Bot Control config, rate-limiting, and more
- **LLM-assisted analysis**: Agent performs cross-rule dependency analysis and Bot Control strategy assessment using domain-specific references
- **HTML report**: Downloadable styled report with Mermaid flow diagram, severity summary, and actionable recommendations
- **Two-tool pattern**: `review_waf_rules_deep` (pipeline) → Agent analysis → `finalize_review_report` (assemble + render)

### Knowledge Base

- **Bedrock KB + S3 Vectors**: Semantic search over AWS WAF best practices documents
- **`search_waf_knowledge` tool**: Agent retrieves domain-specific guidance during conversation
- **Separate CFN stack** (`deploy/kb.yaml`): Optional, recommended. Independent of backend.
- **`deploy/sync-kb.sh`**: One-command document upload + ingestion trigger
- **Graceful degradation**: KB not configured → tool returns "not configured", no errors

### Security Patrol Report

- **One-click weekly summary**: `patrol_scan()` scans all WebACLs, collects 7-day metrics, detects anomalies, queries logs for details
- **3 interactive charts**: Traffic Overview (15 min), Threats by Category (1h stacked area), Challenge Effectiveness (15 min)
- **Anomaly detection**: Concentration-based (single IP >30%) + absolute thresholds + spike detection (>3x daily average)
- **Zero-parameter tool**: Agent auto-discovers all WebACLs, no user input needed
- **CWL log details**: Parallel Logs Insights queries for top IPs/URIs on flagged rules
- **HTML report**: Downloadable dark-themed report with Chart.js zoom/pan

### Weekly Summary Improvements

- **Simplified Traffic chart**: 8 lines → 2 (Allowed + Blocked), cleaner for management
- **New Daily Protection chart**: Stacked bar (Blocked + Challenged + CAPTCHA per day) — ROI visual anchor
- **Unified 15-min period**: All charts now use 15-min granularity (consistent with patrol report)

## 0.4.0 (2026-05-12)

### Session History

- **DynamoDB backend**: Full message history persisted across sessions (split-item pattern, no 400KB limit)
- **Sessions API**: Separate CFN stack (`deploy/sessions-api.yaml`) — Lambda + API Gateway HTTP API with Cognito JWT authorizer. Optional but recommended.
- **Sidebar UI**: Session list with new chat button, click to restore, delete with ×. Auto-detects browser language. Limited to 10 most recent.
- **Restore mechanism**: Loads messages from DDB, uses new runtimeSessionId + AgentCore Memory LTM for context continuity
- **30-day TTL**: Automatic cleanup via DynamoDB TTL

### Security

- **IDOR fix**: User identity derived from JWT claims server-side (not client-supplied header). AgentCore does not validate custom headers against JWT.
- **Authorization header forwarded**: Added to `RequestHeaderAllowlist` so container can decode JWT
- **Agent user isolation**: Agent instance recreated if user_id changes (prevents cross-user memory leak)
- **Removed custom-user-id header**: No longer sent by frontend or trusted by backend (reduces attack surface)

### AWS WAF Features

- **Dynamic Label Interpolation**: `review_waf_rules` detects missing interpolation config, suggests forwarding Bot Control signals to origin
- **requestHeadersInserted parsing**: `_interpret_ip_labels` reads interpolated bot headers when available (fallback to labels array)

### Infrastructure

- **S3 hardening**: AES256 encryption, versioning, access logging, DenyInsecureTransport policy
- **DynamoDB table**: On-demand billing, TTL enabled, IAM scoped to table ARN only
- **CFN Memory auto-create**: Default behavior creates AgentCore Memory resource; set `MemoryId=none` to disable

### Compliance

- **Copyright headers**: SPDX MIT-0 on all source files (13 .py + 5 .jsx/.js/.css)
- **Service naming**: "AWS WAF" and "Amazon Bedrock" throughout all docs and code
- **Semgrep fixes**: tempfile flush, nosemgrep for polling sleep, route refactor

## 0.3.0 (2026-05-11)

### Architecture

- **Real-time streaming**: `callback_handler` + `asyncio.Queue` → SSE events. Users see tool calls and text tokens in real-time (previously waited 1-2 min for full response)
- **Refactored WebACL selection**: Removed all fuzzy match / interrupt / numeric parsing from `get_waf_config`. Now pure case-insensitive exact match. LLM handles natural language understanding via `list_webacls` → `ask_user` → `get_waf_config(exact name)` flow
- **Contextual hints**: All tools append `---\nHints:` sections to guide LLM follow-up questions (more effective than system prompt — appears at moment of maximum attention)

### Tools

- **Athena table consent**: Agent asks user to choose permanent vs temporary table before creating (no auto-create without consent). Permanent tables use stable names (`waf_logs_{webacl_name}`) for cross-session reuse
- **`_detect_capabilities`**: Fixed regression — now detects Bot Control and Anti-DDoS by `ManagedRuleGroupStatement.Name` (AWS fixed identifier), not user's custom rule name
- **`_find_existing_table`**: Fixed match direction — `s3_path.startswith(location)` ensures table covers our path (previously could match overly-specific partition tables)

### Frontend

- **Streaming UI**: Tool calls show ⏳/✅ status in real-time, text streams token-by-token
- **TOOL_CALL_END**: Match by `toolCallId` (not last index) — correct for future parallel tool calls
- **Share/Export**: Select multiple messages → export as styled HTML conversation
- **Copy/Export buttons**: Per-message copy markdown, export .md, export styled HTML
- **Sidebar guide**: Bilingual (zh/en) usage guide with example prompts
- **Dark/Light mode**: Theme toggle with CSS variables

### Docs

- Added: user-guide, iam-permissions, cost-estimation (English + Chinese)
- Sanitized: removed real WebACL names, ARNs, personal info from all docs
- Updated architecture diagram: streaming, 12 tools, PreQueryGuard hook

### Fixes

- `has_streamed_text` flag prevents duplicate text output on fallback path
- `callback_handler` set as Agent attribute (not deprecated `__call__` kwarg)
- System prompt: restored hard constraint "Do NOT query logs without confirmed time range"
- `bot_control` value: `"None"` → `"none"` (consistent with downstream consumers)

## 0.2.0 (2026-05-11)

- **ask_user interrupt**: Agent now proactively asks clarifying questions using Strands SDK interrupt mechanism (reliable, SDK-level pause)
- **Time range control**: `start_time` parameter on log queries — pass user's date directly, tool handles timezone conversion
- **Hard caps**: Bypass detection queries capped at 24h (prevents expensive full-week scans regardless of LLM behavior)
- **Multi-WebACL interrupt**: `get_waf_config` automatically asks user to choose when multiple WebACLs exist
- **Timezone support**: `WAF_AGENT_TIMEZONE_OFFSET` env var (default UTC+0) for date parsing fallback. LLM passes explicit offsets (e.g., +08:00) when user timezone is known.
- **Current date injection**: System prompt includes current date/time so agent can resolve relative dates

## 0.1.0 (2026-05-10)

Initial release.

- AWS WAF investigation engine: COUNT evaluation, bypass detection, attack source analysis
- Weekly business report generation (HTML + Chart.js)
- 13 deterministic rule review checks
- AG-UI streaming chat interface (React SPA)
- Athena support for S3-stored AWS WAF logs (auto table discovery/creation)
- CloudFormation deployment (Cognito + AgentCore + CloudFront)
- 12 tools: waf_config, waf_metrics, waf_logs, waf_athena, analyze_ip, waf_review, report, ja4, finding, ask_user
