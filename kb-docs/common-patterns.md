## Common Anti-patterns

### Count action as labeling mechanism
- Count is non-terminating: the request continues to subsequent rules
- Count rules often add custom labels used by downstream rules for scope-down or conditional logic
- This is a legitimate and common pattern ("label then act"), not an anti-pattern itself
- However, changing a Count rule to Block/Allow breaks this pattern — downstream rules lose the label and may behave unexpectedly
- When reviewing Count rules, always check if any later rule references labels produced by this rule
- **Count without labels**: A custom Count rule (not AWS managed) with no `RuleLabels` entry only contributes a CloudWatch metric — downstream rules have no way to act on its match result. This may be intentional (monitoring only) or a misconfiguration (user intended "label then act" but forgot to add labels).

### Allow based on forgeable conditions
- User-Agent prefix matching → attacker forges UA to bypass all rules
- Business cookie existence check → attacker adds cookie to bypass
- Any custom header value → attacker adds header to bypass

**Forgeable conditions** (attacker can set freely): User-Agent, cookies, custom headers, query parameters, request body content.

**Unforgeable conditions** (attacker cannot control): IP set, WAF token (`aws-waf-token` cookie — cryptographically signed by AWS), HMAC signature (if validated server-side), ASN match (based on source IP's network).

### HostingProviderIPList misconfiguration
- Default Block → frequent false positives for enterprise traffic routed through cloud platforms. Override to Count.
- Override to Allow → cloud-hosted attacks bypass all rules. Override to Count instead.
- See "IP Reputation Rule Groups" section for full details.

### Count rules with Challenge/Block intent (staging risk)
- Users often deploy rules in Count mode first to evaluate impact before switching to the intended action (Challenge, Block, etc.)
- The rule name often reveals the intended action (e.g., `challenge_all_traffic`, `block_suspicious_ips_staging`)
- Risk: the user may not realize that their statement, when combined with the intended action, would cause unintended collateral damage. For example, a rule that matches all traffic (or all traffic minus a few excluded paths) set to Challenge would effectively Block all POST requests, API calls, and native app traffic — because those requests cannot complete Challenge.
- This is especially dangerous for broad-match rules intended to become Challenge: the user sees Count metrics showing "X requests matched" and thinks "great, I'll flip it to Challenge" — not realizing that a large portion of those matched requests will be effectively Blocked, not Challenged.
- Always evaluate the statement as if the action were already the intended action, and flag any mismatch between the statement's scope and what the intended action can actually handle.

### Scope-down too narrow
- `URI EXACTLY "/"` on IP reputation rules → only homepage checked
- Effectively disables the rule group for all other paths

### Disabling core protections with weak fallbacks
- ChallengeAllDuringEvent → Count, relying on Bot Control as fallback
- Bot Control has different purpose, slower response, higher cost, narrower scope

### Override to Allow when default already handles the case
- CategorySearchEngine/CategorySeo Allow → category rules only match unverified bots; verified bots already pass without action; forged UAs never match category rules and are handled by SignalNonBrowserUserAgent. Allow override lets unverified search engine bots bypass all subsequent rules. See "Common level common misconfigurations" for details.

