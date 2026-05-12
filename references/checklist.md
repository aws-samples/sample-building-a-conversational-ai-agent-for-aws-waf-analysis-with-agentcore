# AWS WAF Rules Review Checklist

Evaluate each item. Skip items irrelevant to the Web ACL's purpose.

Phase 1 (sections 1–16): Independent checks.
Phase 2 (sections 17–18): Global cross-checks — require Phase 1 findings as input.

---

## Phase 1: Independent Checks

### 1. Allow Rules Audit

For every Allow rule:
- [ ] Is the matching condition forgeable? (UA, cookie, header = forgeable; IP set, AWS WAF token, ASN = unforgeable)
- [ ] Does bypassing all subsequent rules create a security gap?
- [ ] For managed rule group Allow overrides: does the default already handle the case?

If a UA-based Allow rule is found, note `UA_ALLOW_FOUND` — referenced by section 5.

### 2. Scope-down Statements

For every managed rule group with a scope-down:
- [ ] Does the scope-down make the rule group ineffective? (e.g., `URI EXACTLY "/"` = only homepage checked)
- [ ] Is the scope-down too broad?
- [ ] Regex anchoring: unanchored patterns are `contains` matches

### 3. AntiDDoS AMR Configuration

- [ ] Is `ChallengeAllDuringEvent` enabled (not overridden to Count)?
- [ ] If disabled for native app reasons → recommend dual AMR instance (read antiddos-amr.md for details)
- [ ] Exempt URI regex: are API path branches anchored with `^`? Unanchored = attackers can bypass via paths containing the keyword
- [ ] Regex `|` precedence: `$` only anchors the last branch unless grouped with `()`
- [ ] **SEO**: is there a crawler labeling rule before AMR? Without it, crawlers get challenged during DDoS events (read crawler-seo.md)

### 4. Challenge Action Applicability

For every Challenge or CAPTCHA rule:
- [ ] Does it target requests that can complete Challenge? (Only browser GET text/html)
- [ ] POST/API/native app = effectively Block. Intended?
- [ ] Challenge on rate-limit for API paths: low severity if users won't exceed threshold

**Count rules with Challenge/Block intent:**
- [ ] If a Count rule's name suggests Challenge/Block intent: evaluate statement as if action were already switched. Flag as Medium if broad match would Block POST/API/native app traffic.

### 5. Bot Control Configuration

- [ ] Common level only → Awareness finding (read bot-control.md for capability description)
- [ ] Allow override on category rules → lets unverified bots bypass all subsequent rules
- [ ] CategorySearchEngine/CategorySeo Allow → Low severity, limited blast radius. Correct approach: crawler labeling rule
- [ ] SignalNonBrowserUserAgent and CategoryHttpLibrary → best practice: override to Count

If `UA_ALLOW_FOUND`: native app traffic will enter Bot Control after fix.
- Short-term: scope-down Bot Control with unforgeable label (bypasses entire rule group)
- Medium-term: integrate AWS WAF Mobile SDK (read bot-control.md for details)
- **NEVER override TGT_TokenAbsent to Count**

### 6. Rate-based Rules

- [ ] Activation delay exists — not instantaneous
- [ ] Challenge on API paths = effectively Block (low severity)
- [ ] Thresholds reasonable? (payment APIs < static pages)
- [ ] Rate limiting coverage for native app traffic?
- [ ] Overlapping scope-downs: only lowest threshold triggers for overlapping traffic

### 7. IP Reputation and Anonymous IP Rules

- [ ] Are rule groups inspecting all traffic? (Check scope-down)
- [ ] AWSManagedIPDDoSList at default Count: only adds label. If no downstream rule uses it → no protection (read ip-reputation.md)
- [ ] HostingProviderIPList: default Block → override to Count. Override to Allow → dangerous.

### 8. Landing Page and Cookie-based Logic

- [ ] Business cookies used for security decisions? (forgeable)
- [ ] Better: Count+Label rule on landing page URIs → always-on Challenge on labeled requests
- [ ] AWS WAF token replaces cookie-based user detection (unforgeable)
- [ ] Exclude verified crawlers from Challenge (requires crawler labeling rule)

### 9. Missing Baseline Protections

- [ ] CRS present? If recommending: override SizeRestrictions_Body to Count
- [ ] KnownBadInputsRuleSet present? (Log4j, Java deserialization)
- [ ] Is absence intentional? (DDoS-only Web ACL)

### 10. WCU Awareness

Remind user to verify WCU ≤ 5000 after adding recommended rules.

### 11. Token Domain Configuration

- [ ] Apex domain covers all subdomains at any depth automatically (suffix-based matching)
- [ ] Wildcard (*) not needed

### 12. Managed Rule Group Versions

- [ ] SQLiRuleSet pinned below 2.0 → recommend upgrade
- [ ] BotControlRuleSet pinned below 5.0 → recommend upgrade
- Other rule groups: no action needed on version numbers

### 13. Logging and Monitoring

If no AWS WAF logging config visible → remind user logging is essential for diagnostics.

### 14. Hashed or Opaque search_string

For byte_match rules with hash/random-token search_string:
- [ ] Evaluate rule normally first (Allow audit, forgeability, etc.)
- [ ] Emit Awareness: value may be shared secret or redacted. Warn about leakage risk.
- [ ] Especially warn if action is Allow — leaked secret = full AWS WAF bypass

### 15. Default Action

- [ ] default_action Allow or Block? CustomRequestHandling is normal.
- [ ] Redundant trailing Allow-all rule: if default is Allow and last rule is Allow-all → recommend removing

### 16. Always-on Challenge for Landing Pages

- [ ] Is there an always-on Challenge targeting landing page URIs? (read crawler-seo.md for implementation)
- [ ] If absent + DDoS protection objectives → Medium severity. Recommend two-rule pattern: Count+Label on landing page URIs → Challenge on label (exclude crawlers)
- [ ] Token immunity time ≥ 4 hours (14400s)?
- [ ] Crawler labeling rule placed before Challenge rule?

---

## Phase 2: Global Cross-checks

### 17. Cross-rule and Label Dependency Analysis

**17a. Label source verification:**
- [ ] Token labels (`token:absent/accepted/rejected`) = shared, produced by Bot Control, ATP, ACFP, AND AntiDDoS AMR
- [ ] `challengeable-request` = produced by AntiDDoS AMR
- [ ] Custom Count rules without labels → Awareness (metric-only or missing labels?)

**17b. Fix impact analysis:**
- [ ] For each fix: trace affected traffic through full rule chain
- [ ] Does fix A break rule B? Remove a label? Prevent downstream rules from working?
- [ ] Document recommended fix order and simultaneous changes needed

### 18. Rule Priority Ordering

Compare against recommended order (read managed-overrides.md for full order):
- [ ] IP whitelist/blacklist before AntiDDoS AMR?
- [ ] Count+Label rules before label consumers?
- [ ] AntiDDoS AMR as early as possible?
- [ ] IP reputation/Anonymous IP after AMR?
- [ ] Rate-based before Always-on Challenge?
- [ ] Custom rules before application layer rule groups?
- [ ] Bot Control/ATP/ACFP last (per-request pricing)?
- [ ] Could a high-priority Allow skip critical protections?
