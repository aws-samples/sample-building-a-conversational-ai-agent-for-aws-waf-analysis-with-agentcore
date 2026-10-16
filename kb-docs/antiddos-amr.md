# AntiDDoS AMR (AWSManagedRulesAntiDDoSRuleSet)

## Why CloudFront Scope is Strongly Preferred

Anti-DDoS AMR should be deployed on a CLOUDFRONT-scope WebACL, not REGIONAL. Two reasons:

1. **IP aggregation**: Regional WAF (ALB/API Gateway) sees CDN/proxy IPs as source IP, not real client IPs. Anti-DDoS AMR labels the sources it suspects by the connecting client IP, and does NOT support ForwardedIPConfig. If all traffic appears from a few CDN IPs, AMR either misidentifies them as attackers (false positive on all users) or cannot distinguish attackers from legitimate users.

2. **DDoS hits the resource before WAF evaluates**: With Regional WAF, requests first reach ALB (TLS termination, connection handling), THEN get evaluated by WAF. A volumetric DDoS flood can overwhelm ALB before WAF can mitigate — causing 5xx errors, scaling delays, or resource exhaustion. With CloudFront-scope WAF, evaluation happens at the edge layer before traffic reaches the origin.

If CloudFront is not in the architecture, Regional WAF Anti-DDoS AMR provides limited value. Consider adding CloudFront in front of ALB specifically for DDoS protection.

### Detection mechanism
- One traffic baseline per protected resource ("establishes baselines for each protected resource"), not one per client IP
- The baseline is built within minutes of activation: the launch blog says within 15 minutes. Added during an attack, it takes two to three times longer, because the attack skews it
- Compares the resource's current traffic to its baseline to detect an event, and gives requests from sources suspected of taking part low, medium or high suspicion labels
- Distinguishes DDoS from flash crowds (legitimate traffic spikes)

### Performance
- Detection and mitigation: "single digit seconds" for standard DDoS attacks per official documentation
- Highly distributed low-rate attacks (many IPs, each sending minimal traffic) are harder to mitigate, because each source sends too little to stand out

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
- `awswaf:managed:aws:anti-ddos:challengeable-request` — a GET whose host and path do not match the exempt regex. It is applied while the challenge setting (`ClientSideActionConfig` → `Challenge` → `UsageOfAction`) is `ENABLED`, not only during an event, so ordinary logs show which requests an event would challenge. With it `DISABLED`, no request carries the label. Overriding `ChallengeAllDuringEvent` to Count does not remove it. Note: native apps sending GET requests also receive this label, even though they cannot complete Challenge.
- `awswaf:managed:aws:anti-ddos:event-detected` — DDoS event detected, applied to ALL requests
- `awswaf:managed:aws:anti-ddos:ddos-request` — request from suspicious source
- `awswaf:managed:aws:anti-ddos:high/medium/low-suspicion-ddos-request` — suspicion level

### Exempt URI regex
- Defines requests that can't handle Challenge (API paths, static assets)
- It is matched against the request's host followed by its normalized path, e.g. `www.example.com/api/orders`, with no scheme, query string or fragment (API Reference, `ClientSideAction`). So a branch anchored to the start of the path, `^/api/` or `^\/api\/`, never matches. Nothing reports it: the exemption silently does nothing and API GETs are challenged during an event. Measured on a test WebACL: under `^\/api\/`, `/api/orders` kept the `challengeable-request` label.
- The path is normalized first: empty and `.` segments are removed, `..` is resolved, and a trailing `/` is dropped, so `/api/` is evaluated as `/api` and `\/api\/` does not match `/api` itself
- A path branch without an anchor is a `contains` match: `\/api\/` also exempts `/admin/api/delete`, and an attacker can use such a path to avoid `ChallengeAllDuringEvent`
- Anchor a path branch after the host: `^[^/]+\/api(\/|$)` exempts `/api`, `/api/` and `/api/orders` on any host, and leaves `/x/api/orders` challengeable (measured). Suffix branches such as `\.(css|js|png)$` work as they are
- An API on its own host is exempted whole by the host: `^api\.example\.com\/`
- To check an exemption, look at ordinary traffic rather than waiting for an event: with `UsageOfAction` `ENABLED`, an API GET that carries `challengeable-request` is not exempt

### Pricing
- $20/month per AMR instance + $0.15/million requests
- DDoS traffic detected and mitigated is NOT charged

### Recommended deployment patterns

When ChallengeAllDuringEvent is disabled (overridden to Count) — typically because the Web ACL serves both browser and non-browser traffic — the following patterns restore protection, listed in the order to try them:

**Best: front/back separation (separate Web ACLs)**

If the architecture supports it (e.g., separate CloudFront distributions or ALBs for frontend and backend), use two Web ACLs:
- Frontend Web ACL: 100% browser traffic. AMR with default configuration — ChallengeAllDuringEvent enabled, no exempt URI regex needed.
- Backend Web ACL: 100% API/native app traffic. AMR with Challenge disabled, Block sensitivity raised to MEDIUM.

This eliminates the "which paths can Challenge" problem entirely. Security teams don't need to maintain exempt URI regex or custom rules. Zero custom configuration needed.

**Default for a shared Web ACL: one instance, the API exempted**

Keep ChallengeAllDuringEvent enabled and exempt what cannot complete a Challenge in the exempt URI regex: the API's host if it has its own (`^api\.example\.com\/`), otherwise its paths anchored after the host (`^[^/]+\/api(\/|$)`). One instance keeps one baseline over all the resource's traffic, which is what AWS's guidance assumes: it recommends against a scope-down statement on this rule group, because a scope-down limits the requests the group observes and can make the baseline inaccurate.

**Last resort: dual AMR instance in the same Web ACL**

Only when the frontend and the API share one host and the API paths cannot be listed or written as an exempt regex. Each instance's scope-down limits the requests it observes, which is what AWS says can make the baseline inaccurate; say so when recommending it. Deploy two AMR instances in the same Web ACL with different scope-downs:

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

Not recommended. Where an exemption is possible, one instance with it is simpler than either; where it is not, the dual-instance pattern keeps more native AMR capability than this.

### SEO: excluding search engine crawlers from AntiDDoS AMR
`ChallengeAllDuringEvent` will Challenge all challengeable requests during a DDoS event, including search engine crawlers. Although modern crawlers may support JavaScript execution, real-world cases have been observed where crawlers indexed the Challenge interstitial page (HTTP 202) instead of actual content during DDoS events, severely damaging SEO. The root cause is not fully understood — it may be that crawlers behave differently under high-load conditions, or that the Challenge interstitial is served in a context where the crawler does not retry after token acquisition.

The solution is to place the "ASN + UA Crawler Labeling Rule" (see crawler-seo.md) before AntiDDoS AMR, then add a scope-down to AntiDDoS AMR that excludes requests with the `crawler:verified` label.



## How Agent Should Use This

When analyzing logs:
1. `anti-ddos:event-detected` label present = DDoS event active. Legitimate users being challenged is EXPECTED.
2. `anti-ddos:high-suspicion-ddos-request` = confirmed attacker IP
3. Many IPs with `low-suspicion` but no `high-suspicion` = distributed low-rate attack (AMR blind spot)
4. `challengeable-request` label on API paths = exempt URI regex misconfigured. This holds in ordinary traffic too, while `UsageOfAction` is `ENABLED`: `aggregate_logs(group_by='uri', filter_by='{"label": "awswaf:managed:aws:anti-ddos:challengeable-request"}')` lists the paths an event would challenge

When reviewing rules:
1. ChallengeAllDuringEvent overridden to Count → check whether the API could be exempted instead, then whether the dual-instance pattern is in use
2. No exempt URI regex configured → API/SPA paths will get HTTP 202 during events
3. An exempt branch opening `^/` or `^\/` → it never matches, since the regex sees the host first; suggest anchoring after the host, `^[^/]+\/api(\/|$)`
4. An unanchored path branch → a `contains` match that attackers can use by embedding the keyword in another path; same suggestion
5. No crawler labeling rule before AMR → crawlers will be challenged during events (SEO risk)
