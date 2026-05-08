# waf-agent

AWS WAF Analysis Agent — powered by Amazon Bedrock AgentCore + Strands.

Automated WAF log investigation, weekly security reports, and rule recommendations.

## Features

- **Weekly Report**: Automated security posture report with attack/bot/DDoS metrics and week-over-week trends (HTML with charts)
- **Investigation Engine**: Interactive pivot-chain investigation for COUNT rule evaluation and attack source identification
- **Rule Recommendations**: Actionable WAF rule suggestions based on log analysis and configuration review

## Architecture

Strands Agent on AgentCore Runtime (us-west-2), querying customer WAF data via cross-account IAM role.

See [design/DESIGN.md](design/DESIGN.md) for full design document.

## Status

🚧 Under development
