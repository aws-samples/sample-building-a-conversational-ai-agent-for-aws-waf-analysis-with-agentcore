# Changelog

## 0.2.0 (2026-05-11)

- **ask_user interrupt**: Agent now proactively asks clarifying questions using Strands SDK interrupt mechanism (reliable, SDK-level pause)
- **Time range control**: `start_time` parameter on log queries — pass user's date directly, tool handles timezone conversion
- **Hard caps**: Bypass detection queries capped at 24h (prevents expensive full-week scans regardless of LLM behavior)
- **Multi-WebACL interrupt**: `get_waf_config` automatically asks user to choose when multiple WebACLs exist
- **Timezone support**: `WAF_AGENT_TIMEZONE_OFFSET` env var (default UTC+8) for correct date parsing
- **Current date injection**: System prompt includes current date/time so agent can resolve relative dates

## 0.1.0 (2026-05-10)

Initial release.

- WAF investigation engine: COUNT evaluation, bypass detection, attack source analysis
- Weekly business report generation (HTML + Chart.js)
- 13 deterministic rule review checks
- AG-UI streaming chat interface (React SPA)
- Athena support for S3-stored WAF logs (auto table discovery/creation)
- CloudFormation deployment (Cognito + AgentCore + CloudFront)
- 12 tools: waf_config, waf_metrics, waf_logs, waf_athena, analyze_ip, waf_review, report, ja4, finding, ask_user
