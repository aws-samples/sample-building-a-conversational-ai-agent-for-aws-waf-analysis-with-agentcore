## ASN Match Statement

- Match requests by source IP's Autonomous System Number
- Syntax: `"AsnMatchStatement": { "AsnList": [15169, 8075] }`
- Use case: identify legitimate search engine crawlers. Confirmed ASNs: Google ASN 15169, Bing ASN 8075, Yandex ASN 13238 and 208722. For other search engines (Baidu, Yahoo Japan, etc.), verify the current ASN list from their official documentation — these engines may use multiple ASNs.
- Combine with User-Agent for double verification (ASN is unforgeable, UA is forgeable)


## ASN + UA Crawler Labeling Rule

The recommended way to identify verified search engine crawlers is a dedicated Count+Label rule placed **before** any rule that needs to exclude crawlers. This rule uses ASN + User-Agent double verification:
- **ASN** is unforgeable — it identifies the actual network the request originates from
- **User-Agent** alone is forgeable, but combined with ASN it becomes reliable

Once labeled, downstream rules (AntiDDoS AMR, Always-on Challenge, etc.) can exclude crawlers via a simple `LabelMatchStatement` in their scope-down, without duplicating the ASN+UA logic.

### Why not use Bot Control's `bot:verified` label instead?
Bot Control Common level does identify verified search engine crawlers and adds the `bot:verified` label. However, Bot Control must be placed **last** in the Web ACL (it is the most expensive rule group at $1–$10/million requests; placing it last minimizes the number of requests it evaluates). This means `bot:verified` does not exist yet when AntiDDoS AMR and Always-on Challenge evaluate the request — both of which must be placed before Bot Control. The ASN+UA labeling rule is therefore always required when crawler exclusion is needed, regardless of whether Bot Control is present.

### Rule JSON

See **Appendix A** in the review report for the complete rule JSON.

### Confirmed ASNs
- Google: ASN 15169
- Bing (Microsoft): ASN 8075
- Yandex: ASN 13238 and ASN 208722

For other search engines (Baidu, Yahoo Japan, etc.), do NOT assume a single ASN covers all crawler IPs. Advise the user to verify the current ASN list from the search engine's official documentation before configuring.

### Extensibility
To add more search engines, add more `AndStatement` branches inside the `OrStatement`. No changes needed to downstream rules — they all consume the same `crawler:verified` label.


## Search Engine Crawler Exclusion Pattern

### Problem
Two rules in a typical DDoS-protection Web ACL will Challenge search engine crawlers:
1. **AntiDDoS AMR's `ChallengeAllDuringEvent`** — Challenges all challengeable requests during a DDoS event
2. **Always-on Challenge for landing pages** — Challenges requests to landing page URIs continuously, not just during attacks

Search engine crawlers (Googlebot, Bingbot, etc.) may not reliably complete JavaScript Challenge. Real-world cases have been observed where crawlers indexed the Challenge interstitial page (HTTP 202 with JS) instead of actual content during DDoS events, severely damaging SEO rankings and search result appearance.

### Why not use Bot Control for this?
Bot Control Common level does identify verified crawlers and adds the `bot:verified` label — but Bot Control must be placed **last** in the Web ACL to minimize per-request costs. This means `bot:verified` does not exist yet when AntiDDoS AMR and Always-on Challenge evaluate the request. Cost aside, the ordering constraint alone makes Bot Control unsuitable for this purpose. See "ASN + UA Crawler Labeling Rule" for the correct approach.

### Solution
Place the "ASN + UA Crawler Labeling Rule" (see above) at a higher priority (lower number) than both AntiDDoS AMR and Always-on Challenge. Then configure each of those rules to exclude requests carrying the `crawler:verified` label via their scope-down.

This single labeling rule serves both downstream consumers — no duplication of ASN+UA logic needed.


## Always-on Challenge for Landing Pages

### Why it is effective for DDoS protection
- Most DDoS attack tools are not real browsers — they cannot execute JavaScript and therefore cannot pass Challenge or obtain a AWS WAF token
- Always-on Challenge is preventive, not reactive: it filters non-browser traffic on landing page paths continuously, without waiting for AntiDDoS AMR to detect an attack
- **Covers the detection delay window of all other protections** — rate-based rules and AntiDDoS AMR both have an inherent delay between attack start and mitigation activation. Always-on Challenge takes effect immediately with zero detection delay, blocking attack traffic from the first request on landing page paths.
- Legitimate users with a valid AWS WAF token are not affected: Challenge acts like Count for requests with an unexpired token, so real users experience the JS verification only once, then browse uninterrupted for the token's lifetime
- **Severity when absent**: Medium — this is the most effective proactive DDoS defense for browser traffic; its absence means the Web ACL relies entirely on reactive protections with unavoidable delay windows

### Implementation: two-rule pattern (Count+Label → Challenge)

Always-on Challenge uses the same Count+Label → consume pattern as crawler labeling and native app identification:

1. **Label rule** (Count+Label): a custom rule that matches landing page URIs (e.g., `/`, `/login`, `/signup`, `/index.html`) and adds a label such as `custom:landing-page`. This rule uses Count action so the request continues to subsequent rules.
2. **Challenge rule**: a custom rule that matches the `custom:landing-page` label and applies Challenge action. Exclude verified crawlers by adding a `NotStatement` for the `crawler:verified` label (requires the ASN + UA crawler labeling rule to be placed before this rule).

This approach is URI-based, not Accept-header-based. DDoS scripts requesting landing page paths will be challenged regardless of what Accept header they send. API paths, native app endpoints, and static assets are not affected because they don't match the landing page URI list.

The user must define their own landing page URI list based on their application. Common examples: `/`, `/login`, `/signup`, `/register`, `/index.html`, `/index.php`, `/home`.

### Token immunity time
- Default immunity time is 300 seconds (5 minutes), which works but may concern some users about UX impact
- Recommend extending to at least 4 hours (14400 seconds) for always-on Challenge — real users complete the JS verification once and then browse uninterrupted for the entire immunity period
- Configurable at the rule level or Web ACL level

### Search engine crawler consideration
- Search engine crawlers request landing page URIs — they will match the label rule and be challenged on every request, not just during DDoS events
- Search engine crawlers may not reliably complete JavaScript Challenge — real-world cases show crawlers indexing the Challenge interstitial page instead of actual content, so always-on Challenge can continuously disrupt crawler indexing
- Solution: place the "ASN + UA Crawler Labeling Rule" (see "ASN + UA Crawler Labeling Rule" section) before the Challenge rule, then exclude requests with the `crawler:verified` label in the Challenge rule's statement

### Complementary to AntiDDoS AMR
- AntiDDoS AMR is reactive: it detects anomalies and then starts mitigating
- Always-on Challenge is proactive: it requires proof of browser capability before any landing page content is served
- Together they provide defense in depth: always-on Challenge handles the bulk of non-browser DDoS traffic on landing pages instantly, while AntiDDoS AMR handles sophisticated attacks that use real browsers or target non-landing-page paths

