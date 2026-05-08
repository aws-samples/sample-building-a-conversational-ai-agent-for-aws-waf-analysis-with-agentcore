# Handoff Prompt — WAF Agent Development

## Project Context

You are continuing development of `~/Documents/gitlab/waf-agent/` — an AWS WAF Analysis Agent built on Amazon Bedrock AgentCore + Strands Agents SDK.

## What's Done

- **DESIGN.md**: Complete design document (read it first — it's the source of truth)
- **README.md**: Project overview
- **.gitignore**: Standard Python gitignore

## Key Decisions (already confirmed with user)

| Decision | Value |
|----------|-------|
| Framework | Strands Agents SDK + AgentCore Runtime |
| Agent deploy region | us-west-2 |
| Model (default) | Claude Sonnet 4.6 (cross-region inference profile) |
| Model (strong reasoning) | Claude Opus 4.6 (Investigation pivot decisions) |
| Model (weekly report) | Claude Haiku 4.5 (only generates executive summary text, doesn't need strong reasoning) |
| Output format | HTML with Chart.js charts (no PDF, no email/Slack integration) |
| Scheduled execution | Not doing — on-demand only |
| Report language | Same as user's prompt language |
| Auth (dev/test) | User's own AWS profile `primary` |
| Auth (production) | Cognito User Pool + API Gateway Authorizer (customer self-deploys in their own account) |
| WebACL discovery | Agent auto-discovers via ListWebACLs + GetLoggingConfiguration (same account) |
| Log source | Auto-detect: CW Logs or S3/Athena (with temp table creation) |
| Code reuse from | `~/Documents/gitlab/waf-analysis-report/` (query logic, HTML template) and `~/Documents/github/aws-waf-rules-reviewer/` (WAF domain knowledge, rule review checklist) |
| Testing | User will prepare EC2 + generate traffic when tools are ready |
| New repo | `~/Documents/gitlab/waf-agent/` (this repo) |

## Implementation Priority

1. **Weekly Report (Scenario 4)** — customer leadership already requested this. Mostly CloudWatch Metrics (zero log cost). HTML output with charts.
2. **COUNT Rule Evaluation (Scenario 1)** — most common investigation scenario.
3. **Attack Source Investigation (Scenario 2)** — pivot chain with Anchor Discovery.

## Architecture Summary

```
Strands Agent (WAF Investigator)
├── @tool: list_webacls()              → wafv2:ListWebACLs (REGIONAL + CLOUDFRONT)
├── @tool: get_waf_config()            → wafv2:GetWebACL + GetLoggingConfiguration
├── @tool: get_waf_metrics()           → cloudwatch:GetMetricData / ListMetrics / SEARCH expressions
├── @tool: run_logs_query()            → logs:StartQuery + GetQueryResults (CW Logs Insights)
├── @tool: run_athena_query()          → athena:StartQueryExecution (S3 logs, with temp table support)
├── @tool: lookup_ja4()                → JA4 fingerprint → known client identification
├── @tool: record_finding()            → session state (evidence chain)
└── @tool: ask_user()                  → interactive clarification
```

## Critical WAF Domain Knowledge (Agent must understand)

- Rate-based rules have 20-30s kick-in delay — ALLOW requests before BLOCK is normal
- Anti-DDoS AMR: 5s snapshot, 5-10s kick-in, volumetric-index can miss highly distributed attacks
- Bot Control Common: only detects self-identifying bots (UA-based), browser-UA bots invisible
- Challenge/CAPTCHA: only works on browser GET text/html; POST/API/native = effectively Block
- Match detail: only SQLi_Body and XSS_Body provide terminatingRuleMatchDetails; all other rules don't
- WAF token is unforgeable (AWS cryptographic signature)
- CloudFront WAF metrics: no Region dimension, always us-east-1

## CloudWatch Metrics Discovery (verified via API)

WAF publishes rich metrics with 9 dimension patterns. Key insight: **Weekly Report can be generated entirely from Metrics without querying logs.** Use `SEARCH` expressions for dynamic label discovery. See DESIGN.md "Data Sources" section for full taxonomy.

## Files to Reference

- `~/Documents/github/aws-waf-rules-reviewer/references/` — WAF behavior docs (antiddos-amr.md, bot-control.md, rate-based.md, challenge-captcha.md, checklist.md, common-patterns.md, crawler-seo.md, ip-reputation.md)
- `~/Documents/github/cloudwatch-log-insights-query-samples-for-waf/cwt-query-samples-cloudformation-template.json` — Verified CWL query syntax
- `~/Documents/gitlab/waf-analysis-report/scripts/waf-runner.py` — CW Logs query execution logic to reuse
- `~/Documents/gitlab/waf-analysis-report/scripts/waf-runner-athena.py` — Athena query + temp table logic to reuse
- `~/Documents/gitlab/waf-analysis-report/scripts/waf-enrich.py` — HTML generation logic to reuse
- `~/Documents/gitlab/waf-analysis-report/assets/report-template.html` — HTML report template with Chart.js

## User's AWS Environment

- Profile: `primary`
- WAF WebACL: `shield-sample-webacl` (CloudFront, us-east-1)
- Bedrock: all models available (no access request needed)
- AgentCore: available in us-west-2

## Next Steps

1. Read DESIGN.md thoroughly
2. Set up project structure (src/, tools/, tests/, etc.)
3. Implement Weekly Report tools first (get_waf_metrics with SEARCH expressions)
4. Build HTML report generation (reuse template from waf-analysis-report)
5. Test against `shield-sample-webacl` using profile `primary`
