# AntiDDoS AMR (AWSManagedRulesAntiDDoSRuleSet)

## Why CloudFront Scope is Strongly Preferred

Anti-DDoS AMR should be deployed on a CLOUDFRONT-scope WebACL, not REGIONAL. Two reasons:

1. **IP aggregation**: Regional WAF (ALB/API Gateway) sees CDN/proxy IPs as source IP, not real client IPs. Anti-DDoS AMR does per-client-IP behavior analysis — if all traffic appears from a few CDN IPs, AMR either misidentifies them as attackers (false positive on all users) or cannot distinguish attackers from legitimate users. AMR does NOT support ForwardedIPConfig.

2. **DDoS hits the resource before WAF evaluates**: With Regional WAF, requests first reach ALB (TLS termination, connection handling), THEN get evaluated by WAF. A volumetric DDoS flood can overwhelm ALB before WAF can mitigate — causing 5xx errors, scaling delays, or resource exhaustion. With CloudFront-scope WAF, evaluation happens at the edge layer before traffic reaches the origin.

If CloudFront is not in the architecture, Regional WAF Anti-DDoS AMR provides limited value. Consider adding CloudFront in front of ALB specifically for DDoS protection.

### Detection mechanism
- Per-client-IP behavior analysis (NOT aggregate traffic volume)
- Requires a minimum of ~15 minutes after activation before it can start detecting anomalies; the full traffic baseline is built over a longer period
- Compares current traffic snapshots to baseline, assigns suspicion scores (low/medium/high)
- Distinguishes DDoS from flash crowds (legitimate traffic spikes)

### Performance
- Detection and mitigation: "single digit seconds" for standard DDoS attacks per official documentation
- Highly distributed low-rate attacks (many IPs, each sending minimal traffic) are harder to detect because per-IP anomaly may not be significant enough

### Key rules
- `ChallengeAllDuringEvent`: Challenge all challengeable requests during DDoS event (soft mitigation)
- `ChallengeDDoSRequests`: Challenge requests from suspicious sources
- `DDoSRequests`: Block requests from suspicious sources (hard mitigation)

### Sensitivity levels
- Block sensitivity (LOW/MEDIUM/HIGH): controls which suspicion levels trigger Block
  - LOW: only high-suspicion → Block
  - MEDIUM: medium + high → Block
  - HIGH: all suspicion levels → Block
- Challenge sensitivity: same logic for Challenge action

### Labels produced
- `awswaf:managed:aws:anti-ddos:challengeable-request` — GET + URI not matching exempt regex. Note: native apps sending GET requests also receive this label, even though they cannot complete Challenge.
- `awswaf:managed:aws:anti-ddos:event-detected` — DDoS event detected, applied to ALL requests
- `awswaf:managed:aws:anti-ddos:ddos-request` — request from suspicious source
- `awswaf:managed:aws:anti-ddos:high/medium/low-suspicion-ddos-request` — suspicion level

### Exempt URI regex
- Defines URIs that can't handle Challenge (API paths, static assets)
- Regex `|` branches are independent: `$` only anchors the last branch
- API paths without `^` are `contains` matches, not `starts-with` — an attacker can exploit this by targeting paths that incidentally contain the exempt keyword (e.g., `/admin/api/delete` or `/internal/messages/export` would be exempted by unanchored `\/api\/` or `\/messages` patterns), causing attack requests to bypass ChallengeAllDuringEvent
- Always anchor API path branches with `^`: `^\/api\/|^\/query|^\/messages|\.(css|js|png)$`

### Pricing
- $20/month per AMR instance + $0.15/million requests
- DDoS traffic detected and mitigated is NOT charged

### Recommended deployment patterns

When ChallengeAllDuringEvent is disabled (overridden to Count) — typically because the Web ACL serves both browser and non-browser traffic — the following patterns restore protection, listed from best to acceptable:

**Best: front/back separation (separate Web ACLs)**

If the architecture supports it (e.g., separate CloudFront distributions or ALBs for frontend and backend), use two Web ACLs:
- Frontend Web ACL: 100% browser traffic. AMR with default configuration — ChallengeAllDuringEvent enabled, no exempt URI regex needed.
- Backend Web ACL: 100% API/native app traffic. AMR with Challenge disabled, Block sensitivity raised to MEDIUM.

This eliminates the "which paths can Challenge" problem entirely. Security teams don't need to maintain exempt URI regex or custom rules. Zero custom configuration needed.

**Good: dual AMR instance in same Web ACL (frontend and API share the same domain)**

When front/back separation isn't possible (same-origin architecture), deploy two AMR instances in the same Web ACL with different scope-downs:

1. Add a Count+Label rule before both AMR instances: match `Accept: text/html` AND `GET` method → label `custom:browser-request` (or similar). Add a second Count+Label rule for crawler labeling (see crawler-seo.md).
2. Instance A (browser traffic): scope-down to `custom:browser-request` label, exclude crawler label. Default AMR configuration — ChallengeAllDuringEvent enabled.
3. Instance B (API/native app traffic): scope-down to NOT `custom:browser-request` label. Challenge disabled, Block sensitivity MEDIUM.

Trade-off: common DDoS requests (e.g., `Accept: */*`, no `Sec-Fetch-*` headers) fall into Instance B and are protected by Block only, not Challenge. But compared to disabling ChallengeAllDuringEvent entirely (zero soft mitigation), this is a significant improvement.

Note: the AWS console does not allow adding the same managed rule group twice. Use the JSON editor: copy the existing AMR rule JSON, paste as a new custom-JSON rule, change the Name and MetricName fields.



**Bad: single instance, all rules Count + custom label-based rules**

Override all AMR rules to Count and rebuild protection using custom rules that match AMR labels. This approach has three problems:
1. Requires understanding 6+ AMR labels and their interactions — too complex for most users to configure correctly.
2. Count overrides disable AMR's internal coordination logic (e.g., automatic Block of known offenders), which must be manually recreated using additional rules.
3. Still requires answering "which paths can Challenge" to build the custom Challenge rules.

Not recommended. The dual-instance pattern achieves near-complete native AMR capability with far less complexity.

### SEO: excluding search engine crawlers from AntiDDoS AMR
`ChallengeAllDuringEvent` will Challenge all challengeable requests during a DDoS event, including search engine crawlers. Although modern crawlers may support JavaScript execution, real-world cases have been observed where crawlers indexed the Challenge interstitial page (HTTP 202) instead of actual content during DDoS events, severely damaging SEO. The root cause is not fully understood — it may be that crawlers behave differently under high-load conditions, or that the Challenge interstitial is served in a context where the crawler does not retry after token acquisition.

The solution is to place the "ASN + UA Crawler Labeling Rule" (see crawler-seo.md) before AntiDDoS AMR, then add a scope-down to AntiDDoS AMR that excludes requests with the `crawler:verified` label.



## How Agent Should Use This

When analyzing logs:
1. `anti-ddos:event-detected` label present = DDoS event active. Legitimate users being challenged is EXPECTED.
2. `anti-ddos:high-suspicion-ddos-request` = confirmed attacker IP
3. Many IPs with `low-suspicion` but no `high-suspicion` = distributed low-rate attack (AMR blind spot)
4. `challengeable-request` label on API paths = exempt URI regex misconfigured

When reviewing rules:
1. ChallengeAllDuringEvent overridden to Count → check if dual-instance pattern is used instead
2. No exempt URI regex configured → API/SPA paths will get HTTP 202 during events
3. Exempt URI regex unanchored (no `^`) → attackers can bypass by embedding keyword in path
4. No crawler labeling rule before AMR → crawlers will be challenged during events (SEO risk)
