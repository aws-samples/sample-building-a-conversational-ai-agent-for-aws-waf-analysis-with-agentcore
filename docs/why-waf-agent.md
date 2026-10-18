# Why WAF Analyst?

AWS DevOps Agent can already investigate AWS WAF on its own: it reads the WebACL, the metrics and the logs, and its queries are usually correct. WAF Analyst is built for AWS WAF alone. When we put both on the same WAF questions, WAF Analyst reached the conclusion the evidence supports more often. The difference was in how each read and weighed the evidence, not in access to the data; see [DevOps Agent and WAF Analyst](#devops-agent-and-waf-analyst) below.

## Gap Analysis

The marks say whether a service does something at all. How well DevOps Agent and WAF Analyst investigate is covered in [DevOps Agent and WAF Analyst](#devops-agent-and-waf-analyst).

- **✓** supported
- **❌** not supported

| Customer Need | Security Agent | DevOps Agent | WAF Analyst |
|--------------|:---:|:---:|:---:|
| WAF log investigation: false positives, attack confirmation, bypass, COUNT → BLOCK, DDoS, IP profiling | ❌ | ✓ | ✓ |
| REGIONAL WebACL (ALB, API Gateway) investigation | ❌ | ✓ | ❌ |
| Weekly security patrol report | ❌ | ❌ | ✓ |
| Weekly summary for management | ❌ | ❌ | ✓ |

## How Other Services Differ

### AWS Security Agent

- **Focus**: Application security — penetration testing, SAST, code vulnerability scanning
- **Does NOT**: Read AWS WAF logs, analyze request patterns, or understand WAF rule logic
- **Gap**: Cannot answer "is this IP malicious?" or "should I promote this rule from COUNT to BLOCK?"

### AWS DevOps Agent

- **Focus**: Production incident response — deployment failures, infrastructure issues, operational metrics
- **WAF work**: Reads WebACL configuration, CloudWatch metrics and WAF logs, and carries a WAF investigation through on its own. How well it reads the evidence is covered in [DevOps Agent and WAF Analyst](#devops-agent-and-waf-analyst).
- **Not covered**: scheduled patrol and weekly reports.

## DevOps Agent and WAF Analyst

**DevOps Agent.** It fetches the right data. It is weaker at reading it. It tends to state conclusions more firmly than WAF logs allow, calling a likely false positive settled or a likely scraper certain. It sometimes misreads the traffic itself, such as how many hosts sent it. Now and then it offers to change the WebACL itself. To query WAF logs in S3 with Athena, it needs a workgroup with managed query results, because its session policy drops `s3:PutObject`.

**WAF Analyst.** Purpose-built tools (`analyze_ip`, `lookup_ja4`, `detect_bypass`, `check_challenge_compatibility`, `get_waf_overview`) do the counting and matching in code, and the model does the judging. On the same questions it reached the supported conclusion more often. It recognized a partner integration whose requests looked like SSRF and SQL injection. It questioned an explanation the logs contradicted. It explained why credential stuffing spread over several hosts slipped past per-IP limits, and treated those hosts as one campaign. It explained the requests a rate-based rule let through before it acted, and said when a false positive still needs the business to confirm it. On other questions the two did about as well, and on some DevOps Agent did better.

Its limits: it supports CloudFront-scope WebACLs only, and it runs as its own agent with AgentCore in your account. Over a long time range it asks you to narrow the window instead of scanning all of it, so a question about one IP across weeks needs a follow-up turn.

**Choosing.** If you already run DevOps Agent, it can take an ad-hoc WAF question; check its conclusions against what the logs actually prove, because that is where it overreaches. When the call matters, such as whether allowed traffic is an attack or whether a blocked customer is a false positive, use WAF Analyst. For a REGIONAL WebACL, use DevOps Agent; WAF Analyst does not support it.

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
