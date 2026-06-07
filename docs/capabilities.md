# Capabilities

## Proactive Checks (no specific problem needed)

> "What's the overall situation? Any anomalies?"

The agent checks traffic trends, rule effectiveness, bot activity, and attack patterns across the past 14 days using CloudWatch Metrics — fast and free.

> "Any false positives in the past hour? Scan for me."

The agent scans BLOCK logs for IPs that also have high ALLOW traffic — potential false positives that deserve investigation.

> "Are there any crawlers bypassing my WAF? Check yesterday 2pm-3pm."

The agent scans ALLOW traffic for anomalies: high-frequency IPs, unusual URI diversity, automation user-agents, and data-center IPs without bot labels. When investigating an IP it also shows the query strings it sent on ALLOW traffic — attack-like payloads that were let through are a direct bypass signal.

> "Evaluate my COUNT rules — can I switch them to Block?"

The agent inventories all COUNT rules, classifies them by risk level, finds the peak traffic hour, and analyzes client behavior to determine if switching is safe. For each rule it surfaces the triggering request content (redacted) so you can tell a real attack from a false positive by the actual payload.

> "Run a security patrol for today"

Generates a comprehensive HTML report covering rule effectiveness, anomaly detection, week-over-week trends, and bot activity — all in one click.

> "Do a deep review of my WAF rules"

Produces a full security audit: checks for overly broad Allow rules, missing protections, label dependency issues, and configuration anti-patterns.

## Incident Investigation (user has a specific problem)

> "My customer says they're being blocked, around 10am today"

The agent locates the blocking rule, computes the IP's Allow Ratio, and provides a confidence-level assessment of whether it's a true false positive. It shows the actual content that matched — the rule's match detail (SQLi/XSS) **and** the inspected request component (query string, URI, or cookie) — so you can see *why* the request was flagged. Secret values (cookies, auth/session tokens) are masked.

> "Traffic spiked 5x yesterday afternoon, is it DDoS?"

Compares this week vs last week metrics, checks if Anti-DDoS AMR triggered, and classifies the anomaly (distributed DDoS vs scraper vs cache-bypass attack).

> "Check IP 203.0.113.42, last 2 hours"

Profiles the IP across all dimensions: frequency, URI diversity, JA4 fingerprint, bot labels, action breakdown, NAT detection, and the top query strings it sent (secrets redacted).

> "Our API is returning 202 after enabling Challenge, check the past hour"

Lists all URIs/methods being challenged, flags incompatible requests (non-GET, API endpoints), and explains Challenge technical requirements.

> "We found malicious requests in our backend logs around May 15 14:00"

The agent searches WAF ALLOW logs for suspicious requests in that time window. It can find candidate IPs/URIs as forensic leads, but cannot confirm whether an exploit succeeded — that requires cross-referencing with backend logs.

## Reports

> "Generate a weekly report for management"

HTML report with traffic charts, top rules, attack types, bot breakdown, and an executive summary.

> "Daily ops report"

Deterministic HTML patrol report: rule metrics, anomaly flags, DDoS event detection, Challenge solve rates. For attention rules the summary also lists top IPs, top URIs, and the triggering request content (redacted).

## Best Practice Guidance

> "Is it safe to set Bot Control to Block mode?"

> "How should I configure scope-down for CrossSiteScripting rules?"

> "What's the difference between COUNT and EXCLUDED_AS_COUNT?"

The agent searches its knowledge base of AWS WAF documentation and provides specific, actionable guidance.

## Ad-hoc Queries

> "Which countries are being blocked the most, today 9am-10am?"

> "Top IPs blocked by rule XSS_BODY, yesterday 3pm-4pm"

> "Show me the request rate for IP 203.0.113.42 over the past 2 hours"

The agent supports 20+ predefined log query templates covering IPs, rules, URIs, labels, countries, host headers, and more.

## Limitations

- Cannot detect credential stuffing or brute-force attacks (request format is valid — recommend AWS WAF ATP)
- Cannot determine if a successful exploit occurred (WAF sees requests, not responses)
- Cannot analyze traffic without WAF logging enabled
- Cannot identify bots that perfectly mimic real browsers (legitimate UA + JA4 + moderate frequency)
- Log analysis works best with 1-2 hour windows around the incident. Maximum is 6 hours. Shorter windows = faster results + lower Athena cost.
- JA4 fingerprint analysis provides structural decoding (protocol, TLS version, cipher count) but cannot identify specific applications
- Secret values (cookies, Authorization/session tokens, API keys) are masked when showing inspected request content, and the agent does not judge attacks inside a value it cannot display. If a field is redacted via AWS WAF logging `RedactedFields`, that location cannot be inspected. See [Data Privacy](data-privacy.md)
