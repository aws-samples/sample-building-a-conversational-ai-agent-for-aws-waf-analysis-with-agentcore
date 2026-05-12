# Changelog

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
