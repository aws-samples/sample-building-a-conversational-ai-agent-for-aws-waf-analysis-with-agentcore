# Handoff Prompt — WAF Agent Development

## Project Context

You are continuing development of `~/Documents/gitlab/waf-agent/` — an AWS WAF Analysis Agent built on Amazon Bedrock AgentCore + Strands Agents SDK.

## What's Done

- **agent.py**: Entry point + system prompt with full investigation logic (~1200 tokens)
- **tools/waf_config.py**: `list_webacls`, `get_waf_config` (auto-discovers logging, populates session state)
- **tools/waf_metrics.py**: `get_waf_metrics` (GetMetricData + SEARCH, auto region from session state)
- **tools/waf_logs.py**: `run_logs_query` — **template-based** (12 query types, LLM only picks type + params)
- **tools/ja4.py**: `lookup_ja4` (TLS fingerprint → client identification, graceful offline fallback)
- **tools/report.py**: `generate_weekly_report` (HTML + Chart.js, verified end-to-end against real WebACL)
- **tools/session_state.py**: Cross-tool state (WebACL scope/region auto-detection)
- **tools/aws_session.py**: Shared boto3 session management
- **deploy/template.yaml**: CloudFormation (Cognito + API GW + Lambda bridge + IAM for AgentCore)
- **design/DESIGN.md**: Complete design document (gitignored)

## Key Decisions (confirmed with user)

| Decision | Value |
|----------|-------|
| Framework | Strands Agents SDK + AgentCore Runtime |
| Deployment model | Customer self-deploys (single-tenant), NOT SaaS |
| Agent deploy region | us-west-2 |
| Model (default) | Claude Sonnet 4.6 (`us.anthropic.claude-sonnet-4-6-20250514-v1:0`) |
| Model (strong reasoning) | Claude Opus 4.6 |
| Model (weekly report) | Claude Haiku 4.5 (executive summary only) |
| Output format | HTML with Chart.js charts (no PDF, no email/Slack) |
| Scheduled execution | Not doing — on-demand only |
| Report language | Same as user's prompt language |
| Auth (dev/test) | User's own AWS profile `primary` |
| Auth (production) | Cognito User Pool + API Gateway + Lambda → AgentCore |
| IAM trust principal | `bedrock-agentcore.amazonaws.com` (NOT bedrock.amazonaws.com) |
| WebACL discovery | Auto via ListWebACLs + GetLoggingConfiguration (same account) |
| Log queries | Template-based — LLM picks query_type, script builds CWL query |
| IP threat intel | Removed (no AbuseIPDB/ET). Use WAF labels + log behavior instead |
| JA4 fingerprint | Kept. DB bundled in image, graceful fallback if unavailable |
| Distribution | Open source: `github.com/aws-samples/`, image on ECR Public |
| Testing | User prepares EC2 + generates traffic when tools are ready |

## Architecture

```
Customer AWS Account
├── Cognito User Pool (employee auth)
├── API Gateway HTTP API (JWT authorizer)
│   └── POST /invoke → Lambda → AgentCore Runtime
├── AgentCore Runtime (microVM, session-isolated)
│   └── Strands Agent with tools:
│       ├── list_webacls()
│       ├── get_waf_config()       → also sets session_state
│       ├── get_waf_metrics()      → auto region from session_state
│       ├── run_logs_query()       → template-based, 12 query types
│       ├── lookup_ja4()           → offline-capable
│       └── generate_weekly_report()
└── IAM Execution Role (bedrock-agentcore.amazonaws.com)
```

## Design Principles

1. **Deterministic work → scripts, reasoning → LLM**: Query construction, API calls, formatting, validation are all in tool code. LLM only does scheduling and analysis.
2. **Session state over LLM memory**: Region, log destination, WebACL context stored in module-level state, not relying on LLM to remember.
3. **Metrics before Logs**: Always try CloudWatch Metrics first (free, fast). Only query logs when per-request detail is needed.
4. **Multi-dimensional cross-validation**: Never conclude attack/FP from a single signal. Check rule type prior + at least 3 dimensions.

## What's NOT Done Yet

| Item | Blocked on |
|------|-----------|
| `run_athena_query` tool | Need S3 log test environment |
| End-to-end investigation test | Need WAF logs (user will generate traffic on EC2) |
| AgentCore deployment | Need to build + push image, run `agentcore launch` |
| `record_finding` tool | Implement when testing investigation flow |
| `ask_user` tool | Depends on AgentCore session/interrupt mechanism |
| Weekly Report enrichment | Need more data (bot control, anti-ddos labels) |

## User's AWS Environment

- Profile: `primary`
- WAF WebACLs: 6 total (CloudFront scope, us-east-1), primary test target: `shield-sample-webacl`
- Bedrock: all models available (no access request needed)
- AgentCore: us-west-2

## Files to Reference (external repos)

- `~/Documents/github/aws-waf-rules-reviewer/references/` — WAF behavior docs
- `~/Documents/github/cloudwatch-log-insights-query-samples-for-waf/` — Verified CWL query syntax
- `~/Documents/gitlab/waf-analysis-report/scripts/waf-runner-athena.py` — Athena temp table logic to reuse

## Next Steps

1. Prepare test environment (EC2 + traffic generation → WAF logs)
2. End-to-end test investigation flow with real logs
3. Implement `run_athena_query` if customer uses S3 logs
4. Build + deploy to AgentCore, verify Lambda bridge works
5. Enrich Weekly Report (bot control, anti-ddos sections) once data exists
