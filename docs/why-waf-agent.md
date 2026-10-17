# Why WAF Analyst?

As of October 2026 there are three ways to put an AI agent on AWS WAF logs, and they sit at different depths. AWS DevOps Agent on its own can reach the data but has no WAF method. The open-source `aws-waf-log-investigation` skill ([aws/tools-for-devops-agent#142](https://github.com/aws/tools-for-devops-agent/pull/142)) teaches that method to DevOps Agent and covers the investigation cases. WAF Analyst goes deepest, with purpose-built tools and direct data access, and also covers the reporting cases the skill does not. The three-way comparison, measured against the same held-out questions, is in [Native vs skill vs WAF Analyst](#native-vs-skill-vs-waf-analyst) below.

## Gap Analysis

The DevOps Agent column is split: `native` is the agent with no skill, `+Skill` is the agent loaded with #142. The marks grade quality, not just whether it runs:

- **❌** not supported
- **△** pulls the data but the conclusion is unreliable (data without method)
- **✓** reliable method and conclusion
- **◎** deepest: purpose-built tools and validated methods, stays inside the evidence

| Customer Need | Security Agent | DevOps (native) | DevOps +Skill [#142] | Security IR | WAF Analyst |
|--------------|:---:|:---:|:---:|:---:|:---:|
| Determine if COUNT rule is causing false positives | ❌ | △ | ✓ | ❌ | ◎ |
| Confirm whether traffic is a real attack | ❌ | △ | ✓ | ❌ | ◎ |
| COUNT → BLOCK promotion decision support | ❌ | ❌ | ✓ | ❌ | ◎ |
| Attack source investigation (IP behavior) | ❌ | △ | ✓ | ❌ | ◎ |
| Distinguish bot vs legitimate user (post-hoc) | ❌ | ❌ | △ | ❌ | ◎ |
| False positive investigation ("my customer got blocked") | ❌ | △ | ✓ | ❌ | ◎ |
| Bypass/evasion detection | ❌ | ❌ | ✓ | ❌ | ◎ |
| DDoS event investigation | ❌ | △ | ✓ | ❌ | ◎ |
| REGIONAL WebACL (ALB, API Gateway) investigation | ❌ | △ | ✓ | ❌ | ❌ |
| Weekly security patrol report | ❌ | ❌ | ❌ | ❌ | ◎ |
| weekly summary for management | ❌ | ❌ | ❌ | ❌ | ◎ |
| WAF best practices knowledge base | ❌ | ❌ | ❌ | ❌ | ◎ |

The investigation rows read left to right as the whole point of this comparison: `native` has the data but draws the wrong conclusion (△), the skill adds the method so the conclusion is now reliable (✓), and WAF Analyst goes deeper still with purpose-built tools (◎). Where ✓ and ◎ differ in practice: on the same questions, WAF Analyst reads JA4 fingerprints across IPs, catches one token replayed from many IPs, checks challenge compatibility, and separates a custom rate rule from Anti-DDoS AMR event detection, which the skill can prompt a generic agent toward but not perform as deeply. The two places the skill wins are its own columns: REGIONAL WebACLs (WAF Analyst is CloudFront-only), and running inside an existing DevOps Agent with no separate deployment.

## How Other Services Differ

### AWS Security Agent

- **Focus**: Application security — penetration testing, SAST, code vulnerability scanning
- **Does NOT**: Read AWS WAF logs, analyze request patterns, or understand WAF rule logic
- **Gap**: Cannot answer "is this IP malicious?" or "should I promote this rule from COUNT to BLOCK?"

### AWS DevOps Agent

- **Focus**: Production incident response — deployment failures, infrastructure issues, operational metrics
- **Native**: Reads WebACL config, CloudWatch metrics and WAF logs, and its queries are usually correct. What it lacks is WAF method: it files a blocked legitimate user under the attack, misses allowed bypass traffic, and reads a COUNT-to-BLOCK call off the attack window alone.
- **With the skill (#142)**: the `aws-waf-log-investigation` skill supplies that method, and the agent then handles the investigation cases. See [Native vs skill vs WAF Analyst](#native-vs-skill-vs-waf-analyst).
- **Still missing even with the skill**: scheduled patrol and weekly reports, and the depth of WAF Analyst's purpose-built tools.

### AWS Security Incident Response

- **Focus**: IAM compromise, EC2 instance compromise, data exfiltration events
- **Does NOT**: Investigate WAF-layer events, analyze HTTP request patterns, or evaluate rule effectiveness
- **Gap**: Operates at the infrastructure/identity layer, not the application/WAF layer

## Native vs skill vs WAF Analyst

Measured on the same held-out WAF questions (false positives, injection, bypass, COUNT-to-BLOCK, DDoS, token replay, IP profiling), across CloudFront and REGIONAL (ALB) WebACLs.

**DevOps Agent, native.** It fetches the right data and its queries are usually correct, but without WAF method it draws the wrong conclusion: it files a blocked legitimate user under the attack, misses bypass traffic that WAF allowed, and bases a COUNT-to-BLOCK call on the attack window alone. There is also an IAM trap: DevOps Agent's session policy drops `s3:PutObject`, so Athena queries over WAF logs in S3 fail unless the agent is given a workgroup with managed query results.

**DevOps Agent + the skill (#142).** The skill carries the method onto the generic agent: which question to ask, how to read the answer, and where WAF evidence stops. It covers false positives, injection and bypass, COUNT-to-BLOCK, DDoS and IP profiling, on both Athena and CloudWatch Logs, and on both CloudFront and REGIONAL WebACLs. The customer runs it inside a DevOps Agent they already have, with no extra deployment, and it works in CDN/WAF accounts that have no AgentCore access. It does not produce the scheduled patrol or weekly reports.

**WAF Analyst.** Purpose-built tools (`analyze_ip`, `lookup_ja4`, `detect_bypass`, `check_challenge_compatibility`, `get_waf_overview`), direct data access and validated methods make it the deepest of the three where it runs. It reads JA4 fingerprints across IPs, detects one token replayed across many IPs, checks challenge compatibility, and separates a custom rate rule from Anti-DDoS AMR event detection. It also stays inside the evidence, saying when a log cannot prove intent instead of guessing. Its limits are about where it runs and how it is deployed, not about analysis quality: it supports CloudFront-scope WebACLs only, not REGIONAL, and it has to be deployed as its own agent in an account with AgentCore access.

**Choosing.** For the deepest analysis on a CloudFront WebACL, and for the patrol and weekly reports, use WAF Analyst. For WAF investigation inside an existing DevOps Agent, or on a REGIONAL WebACL, or in an account without AgentCore access, use the skill. The native agent alone is not enough for WAF work.

## Core Capabilities

### 1. Interactive Security Investigation

Conversational, iterative investigation of security events:

- **False positive investigation**: 5-step methodology — confirm rule → inspect match details → analyze IP behavior → detect NAT/proxy → recommend action
- **Bypass detection**: Identify anomalous patterns in high-volume ALLOW traffic (crawler disguise, repeaters, token reuse)
- **Attack source analysis**: IP behavior profiling (JA4 fingerprints, URI diversity, request rate, Bot Control labels)
- **DDoS event analysis**: Understand Anti-DDoS AMR behavior, distinguish normal Challenge from anomalies

### 2. Automated Reports

| Report Type | Audience | Content |
|------------|----------|---------|
| Security Patrol | Operations engineers | 7-day full scan, anomaly detection, 15-min charts, top attack sources |
| Weekly Summary | Management | Block counts, trend comparison, bot classification, country distribution, protection value |

### 3. Domain Knowledge

Built-in AWS WAF expertise, not reliant on generic LLM knowledge:

- Managed rule group behavior (Bot Control Common/Targeted, Anti-DDoS AMR, CRS, IP Reputation)
- Label semantics and rule interaction patterns
- Challenge/CAPTCHA applicability and limitations
- Rate-based rule delay characteristics
- Dynamic Label Interpolation
- Knowledge base retrieval (12 specialized documents)

### 4. Log Analysis

20+ pre-built query templates covering:

| Category | Capabilities |
|----------|-------------|
| COUNT rule evaluation | Top IPs, Top URIs, Top UAs (per rule) |
| IP deep analysis | Behavior profiling, JA4 fingerprints, URI distribution, request rate, NAT detection |
| Bypass detection | High-volume ALLOW crawlers, repeaters, token reuse |
| Attack overview | Top blocked IPs, top rules, top countries, timeline |
| Host profiling | Traffic distribution, method distribution, URI patterns (frontend vs API) |
| Label analysis | Top IPs per label (Bot Control, Anti-DDoS, etc.) |

### 5. No-Logging Degradation

When a WebACL has no logging configured, the agent explicitly states capability boundaries:
- ✅ Available: CloudWatch aggregate metrics (per-rule/label/country)
- ❌ Not available: IP-level analysis, bypass detection, URI pattern analysis, false positive investigation

Never fabricates data or provides unverifiable conclusions.

### 6. Single-WebACL Focus, Account-Wide Discovery

Lists the account's CLOUDFRONT-scope WebACLs in one call, since CloudFront WebACLs are global. Works on one WebACL per session; switching to another resets session state (log destination, capabilities, findings) so results are never mixed across WebACLs. REGIONAL-scope WebACLs (ALB, API Gateway, AppSync) are not supported.

## Architecture Advantages

- **Specialized tools over generic MCP**: Each tool has built-in analysis logic (anomaly detection, NAT detection, threshold evaluation) — not simple API wrappers
- **Deterministic + LLM hybrid**: Numerical computation and pattern matching in Python, natural language understanding and judgment by LLM
- **Session memory**: Maintains investigation context across turns, supports progressive deep-dives
- **Real-time streaming**: AG-UI protocol, users see tool call progress in real-time
