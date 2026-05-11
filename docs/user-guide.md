# WAF Agent User Guide

[中文版](user-guide_zh.md)

WAF Agent is an AI assistant that helps security engineers investigate WAF incidents, detect bypasses, and generate ROI reports. It works best when you give it **specific, concrete questions**.

## Core Principle: Be Specific

The agent has access to your WAF configuration, CloudWatch Metrics, CloudWatch Logs, and Athena. But it needs you to narrow the scope:

| Vague (slow, noisy) | Specific (fast, accurate) |
|---|---|
| "Check my WAF" | "Check my-webacl for bypass traffic on May 9 afternoon" |
| "Any attacks?" | "IP 54.254.254.234 hit my site hard yesterday around 6am UTC" |
| "Generate a report" | "Generate ROI report for my-production-webacl" |

## Capabilities

### 1. Bypass / Evasion Detection

Find traffic that passes all WAF rules (default ALLOW) but looks suspicious.

**Good prompts:**
- "Check if there are crawlers bypassing WAF on my-webacl, May 9 afternoon"
- "Find high-volume IPs that weren't blocked in the last 6 hours"
- "Are there any bots getting through Bot Control?"

**What the agent does:** Queries metrics to find peak ALLOW windows → runs log queries for high-frequency/high-diversity IPs → analyzes top suspicious IPs (NAT detection, frequency, cross-validation).

### 2. Attack Source Investigation

Identify who is attacking, how, and whether WAF stopped it.

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

**What the agent does:** Checks UA/JA4 diversity (NAT detection) → request frequency → URI breakdown → WAF labels → cross-query with all rules.

### 5. WAF Rule Review

Automated security audit of your WebACL configuration.

**Good prompts:**
- "Review the rules on my-webacl"
- "Audit my WAF configuration for security issues"

**What the agent does:** Runs 13 deterministic checks (forgeable Allow rules, missing scope-down, Bot Control misconfiguration, priority order issues, etc.) → returns findings with severity and recommendations.

### 6. ROI Report Generation

HTML report with charts showing WAF protection value — designed for management.

**Good prompts:**
- "Generate ROI report for my-webacl"
- "Generate ROI report" (agent will ask which WebACL)

**What the agent does:** Collects 7 days of metrics → generates HTML with Chart.js charts (blocked vs allowed, daily breakdown, top rules, top countries) → asks LLM for executive summary.

### 7. Metrics Query

Quick, free overview of WAF traffic patterns.

**Good prompts:**
- "Show me traffic trends for the last 7 days"
- "How many requests were blocked yesterday?"
- "Show AllowedRequests metric with 1-hour granularity"

### 8. Host Traffic Profiling

Classify domains behind a WebACL as Web/API/Mixed to guide protection strategy.

**Good prompts:**
- "What type of traffic does each host get?"
- "Is my domain mostly API or web traffic?"

## Tips for Best Results

1. **Always specify the WebACL** if you have multiple. The agent will ask if you don't, but specifying upfront saves a round-trip.

2. **Always specify a time range.** "May 9 afternoon", "yesterday 2-4pm", "last 6 hours" — anything concrete. The agent cannot effectively analyze 7 days of logs.

3. **Provide context about your environment:**
   - "This is a SPA with WAF Client SDK"
   - "We have native mobile apps on the same domain"
   - "The /upload endpoint accepts large files (SizeRestrictions FP expected)"

4. **Ask follow-up questions.** After the agent presents findings, you can ask:
   - "Analyze the next 3 suspicious IPs"
   - "What about the other WebACL?"
   - "Show me the actual URIs this IP accessed"

5. **For bypass detection:** The most useful time window is ≤6 hours. Longer windows produce too much noise.

## Limitations

- **No write operations.** The agent cannot modify your WAF rules, create/delete resources (except temporary Athena tables which are auto-cleaned).
- **Log availability.** If logging is not enabled on your WebACL, only CloudWatch Metrics are available (no IP-level analysis).
- **Session timeout.** Container idles out after 15 minutes. Download reports promptly.
- **Cold start.** First query in a new session takes ~30 seconds (container boot).
- **Match details.** WAF only provides request body match details for SQLi and XSS rules. For other rules, the agent cannot tell you what specific content triggered the rule.
