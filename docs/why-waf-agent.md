# Why AWS WAF Agent?

As of May 2026, no AWS-native service addresses WAF log investigation and operational analysis needs.

## Gap Analysis

| Customer Need | Security Agent | DevOps Agent | Security IR | Bot Control | WAF Agent |
|--------------|:---:|:---:|:---:|:---:|:---:|
| Determine if COUNT rule is causing false positives | ❌ | ❌ | ❌ | ❌ | ✅ |
| Confirm whether traffic is a real attack | ❌ | ❌ | ❌ | ❌ | ✅ |
| COUNT → BLOCK promotion decision support | ❌ | ❌ | ❌ | ❌ | ✅ |
| Attack source investigation (IP behavior) | ❌ | △ | ❌ | ❌ | ✅ |
| Distinguish bot vs legitimate user (post-hoc) | ❌ | ❌ | ❌ | △ | ✅ |
| False positive investigation ("my customer got blocked") | ❌ | ❌ | ❌ | ❌ | ✅ |
| Bypass/evasion detection | ❌ | ❌ | ❌ | ❌ | ✅ |
| DDoS event investigation | ❌ | △ | ❌ | ❌ | ✅ |
| Weekly security patrol report | ❌ | ❌ | ❌ | ❌ | ✅ |
| Deep WAF rule configuration review | ❌ | ❌ | ❌ | ❌ | ✅ |
| ROI report for management | ❌ | ❌ | ❌ | ❌ | ✅ |
| WAF best practices knowledge base | ❌ | ❌ | ❌ | ❌ | ✅ |

## How Other Services Differ

### AWS Security Agent

- **Focus**: Application security — penetration testing, SAST, code vulnerability scanning
- **Does NOT**: Read AWS WAF logs, analyze request patterns, or understand WAF rule logic
- **Gap**: Cannot answer "is this IP malicious?" or "should I promote this rule from COUNT to BLOCK?"

### AWS DevOps Agent

- **Focus**: Production incident response — deployment failures, infrastructure issues, operational metrics
- **Does NOT**: Have WAF domain knowledge, understand managed rule group behavior, or analyze security events
- **Gap**: Can surface that "5xx errors increased" but cannot determine if it's caused by WAF misconfiguration or an actual attack

### AWS Security Incident Response

- **Focus**: IAM compromise, EC2 instance compromise, data exfiltration events
- **Does NOT**: Investigate WAF-layer events, analyze HTTP request patterns, or evaluate rule effectiveness
- **Gap**: Operates at the infrastructure/identity layer, not the application/WAF layer

### Bot Control (AWS WAF Managed Rule)

- **Focus**: Real-time bot classification and labeling at request time
- **Does NOT**: Provide post-hoc analysis, historical investigation, or operational reporting
- **Gap**: Labels are applied in real-time but there is no built-in tool to analyze patterns across time, correlate with other rules, or generate reports

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
| ROI Report | Management | Block counts, trend comparison, bot classification, country distribution, protection value |
| Rule Review | Security architects | 10 deterministic checks + LLM deep analysis, rule interaction diagram, fix recommendations |

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

### 6. Multi-WebACL Support

Automatically discovers all WebACLs across CLOUDFRONT + REGIONAL scopes, supports cross-region analysis. Patrol reports cover all WebACLs.

## Architecture Advantages

- **Specialized tools over generic MCP**: Each tool has built-in analysis logic (anomaly detection, NAT detection, threshold evaluation) — not simple API wrappers
- **Deterministic + LLM hybrid**: Numerical computation and pattern matching in Python, natural language understanding and judgment by LLM
- **Session memory**: Maintains investigation context across turns, supports progressive deep-dives
- **Real-time streaming**: AG-UI protocol, users see tool call progress in real-time
