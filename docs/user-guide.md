# WAF Agent User Guide

[中文版](user-guide_zh.md)

WAF Agent is an AI assistant that helps security engineers investigate AWS WAF incidents, detect bypasses, and generate ROI reports. It works best when you give it **specific, concrete questions**.

## Core Principle: Be Specific

The agent has access to your AWS WAF configuration, CloudWatch Metrics, CloudWatch Logs, and Athena. But it needs you to narrow the scope:

| Vague (slow, noisy) | Specific (fast, accurate) |
|---|---|
| "Check my AWS WAF" | "Check my-webacl for bypass traffic on May 9 afternoon" |
| "Any attacks?" | "IP 54.254.254.234 hit my site hard yesterday around 6am UTC" |
| "Generate a report" | "Generate ROI report for my-production-webacl" |

## Capabilities

### 1. Bypass / Evasion Detection

Find traffic that passes all AWS WAF rules (default ALLOW) but looks suspicious.

**Good prompts:**
- "Check if there are crawlers bypassing AWS WAF on my-webacl, May 9 afternoon"
- "Find high-volume IPs that weren't blocked in the last 6 hours"
- "Are there any bots getting through Bot Control?"

**What the agent does:** Queries metrics to find peak ALLOW windows → runs log queries for high-frequency/high-diversity IPs → analyzes top suspicious IPs (NAT detection, frequency, cross-validation).

### 2. Attack Source Investigation

Identify who is attacking, how, and whether AWS WAF stopped it.

**Good prompts:**
- "Analyze the DDoS attack on May 9 around 06:00 UTC"
- "Who is behind the blocked traffic spike at 2pm today?"
- "IP 3.249.182.182 looks suspicious — deep dive"

**What the agent does:** Checks metrics for anomaly windows → identifies top attackers → cross-validates with labels, JA4 fingerprints, URI patterns.

### 3. COUNT Rule Evaluation

Determine if a COUNT rule is catching real attacks or causing false positives.

**Good prompts:**
- "SizeRestrictions_BODY is triggering a lot — is it FP or real?"
- "Should I switch CrossSiteScripting_BODY from COUNT to BLOCK?"
- "Analyze who is triggering the GenericRFI rule"

**What the agent does:** Gets top IPs triggering the rule → cross-validates each IP (other rules triggered? URI patterns? time distribution?) → concludes attack/FP/mixed.

### 4. IP Deep Analysis

Full behavioral profile of a specific IP address.

**Good prompts:**
- "Analyze IP 54.254.254.234 on May 9"
- "Is 47.128.14.206 a bot or a real user?"
- "Check if 13.219.181.182 is behind a NAT"

**What the agent does:** Checks UA/JA4 diversity (NAT detection) → request frequency → URI breakdown → AWS WAF labels → cross-query with all rules.

### 5. AWS WAF Rule Review

Comprehensive security audit of your WebACL configuration with a downloadable HTML report.

**Good prompts:**
- "Review the rules on my-webacl"
- "Audit my AWS WAF configuration for security issues"
- "Generate a review report for production-webacl"

**What the agent does:** Runs a deterministic analysis pipeline (18+ checks: forgeable Allow rules, label dependency chains, scope-down issues, Bot Control config, priority ordering, etc.) → Agent adds cross-rule impact analysis → generates styled HTML report with Mermaid flow diagram → auto-downloads.

### 6. Security Patrol (Weekly Summary)

Comprehensive security event summary across all WebACLs — designed for operations teams.

**Good prompts:**
- "Security patrol" / "安全巡检"
- "Weekly security summary"
- "What happened this week?"

**What the agent does:** Scans all WebACLs → collects 7 days of metrics per rule → detects anomalies (concentration, spikes) → queries logs for top IPs/URIs on flagged rules → generates HTML report with 3 charts (Traffic, Threats by Category, Challenge Effectiveness).

### 7. ROI Report Generation

HTML report with charts showing AWS WAF protection value — designed for management.

**Good prompts:**
- "Generate ROI report for my-webacl"
- "Generate ROI report" (agent will ask which WebACL)

**What the agent does:** Collects 7 days of metrics → generates HTML with Chart.js charts (blocked vs allowed, daily breakdown, top rules, top countries) → asks LLM for executive summary.

> **Note:** ROI report uses CloudWatch Metrics + CloudWatch Logs Insights only (no Athena). Management reports only need aggregate numbers — not IP/URI-level details. If your WAF logs go to S3 via Firehose, the report still works (metrics for charts, CWL for bot/DDoS classification). If CWL is not configured, bot details are omitted but the report is still generated. For detailed attack source analysis, use Security Patrol or ask the agent directly.

### 8. Metrics Query

Quick, free overview of AWS WAF traffic patterns.

**Good prompts:**
- "Show me traffic trends for the last 7 days"
- "How many requests were blocked yesterday?"
- "Show AllowedRequests metric with 1-hour granularity"

### 9. Host Traffic Profiling

Classify domains behind a WebACL as Web/API/Mixed to guide protection strategy.

**Good prompts:**
- "What type of traffic does each host get?"
- "Is my domain mostly API or web traffic?"

## Tips for Best Results

1. **Always specify the WebACL** if you have multiple. The agent will ask if you don't, but specifying upfront saves a round-trip.

2. **Always specify a time range.** "May 9 afternoon", "yesterday 2-4pm", "last 6 hours" — anything concrete. The agent cannot effectively analyze 7 days of logs.

3. **Provide context about your environment:**
   - "This is a SPA with AWS WAF Client SDK"
   - "We have native mobile apps on the same domain"
   - "The /upload endpoint accepts large files (SizeRestrictions FP expected)"

4. **Ask follow-up questions.** After the agent presents findings, you can ask:
   - "Analyze the next 3 suspicious IPs"
   - "What about the other WebACL?"
   - "Show me the actual URIs this IP accessed"

5. **For bypass detection:** The most useful time window is ≤6 hours. Longer windows produce too much noise.

## Limitations

- **No write operations.** The agent cannot modify your AWS WAF rules, create/delete resources (except temporary Athena tables which are auto-cleaned).
- **Log availability.** If logging is not enabled on your WebACL, only CloudWatch Metrics are available (no IP-level analysis).
- **Session timeout.** Container idles out after 15 minutes. Download reports promptly.
- **Cold start.** First query in a new session takes ~30 seconds (container boot).
- **Match details.** AWS WAF only provides request body match details for SQLi and XSS rules. For other rules, the agent cannot tell you what specific content triggered the rule.
