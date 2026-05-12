# Changelog

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
- **Timezone support**: `WAF_AGENT_TIMEZONE_OFFSET` env var (default UTC+8) for correct date parsing
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
