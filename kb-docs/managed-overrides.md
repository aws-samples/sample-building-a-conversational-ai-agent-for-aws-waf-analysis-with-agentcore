# AWSManagedRulesCommonRuleSet (CRS) Notes

- Covers cross-site scripting, local and remote file inclusion, SSRF to the EC2 metadata service, bad User-Agents and size limits. It has no SQL injection rules: those are in `AWSManagedRulesSQLiRuleSet`
- `SizeRestrictions_BODY` rule blocks request bodies larger than 8KB. This frequently causes false positives on file upload endpoints, API endpoints with large payloads, form submissions with rich content, etc. Most users don't know which of their endpoints need large bodies. When recommending CRS, always advise overriding `SizeRestrictions_BODY` to Count.


## AWSManagedRulesKnownBadInputsRuleSet Notes

- Protects against known malicious input patterns: Log4j/Log4Shell (CVE-2021-44228), Java deserialization exploits, and other well-known attack payloads
- Low WCU cost, low false positive rate — generally safe to enable with default actions
- Recommended as a baseline rule group alongside CRS


## Token Domain Configuration

- `token_domains` should include the apex domain (e.g., `example.com`), which automatically covers all subdomains at any depth (`www.example.com`, `api.example.com`, `sub.api.example.com`, etc.) via suffix-based matching
- No need to list each subdomain separately — the apex domain is sufficient
- Wildcard (`*`) is NOT needed and should not be used


## Web ACL Capacity Units (WCU)

- Each Web ACL has a maximum capacity of **5000 WCU**
- Each rule and rule group consumes WCU based on its complexity (statement types, number of conditions, etc.)
- WCU cannot be accurately calculated from JSON alone — the AWS console or API shows the actual WCU usage
- When recommending adding new rules or rule groups, always remind the user to verify remaining WCU capacity


## Recommended Rule Priority Order



Key principles:
- Label producers before label consumers
- AntiDDoS AMR as early as possible for accurate baseline
- Cost optimization: cheaper rules first to filter traffic before expensive rules
- Terminating rules (Allow/Block) placed early should be scrutinized


## Managed Rule Group Action Overrides

### Version recommendations
Only this managed rule group has a version upgrade worth flagging:
- **AWSManagedRulesBotControlRuleSet**: Version_7.0 (2026-10-15) is the latest static version; recommend pinning it. 5.0 "added 400+ new bots across multiple categories" (changelog, 2026-02-25), with the `CategoryPagePreview` and `CategoryWebhooks` rules. Version_6.1 lists 697 `bot:name:` labels and Version_7.0 lists 701 (`describe-managed-rule-group`, 2026-10-17). A group with no `Version` runs AWS's current default, which AWS moves without a changelog entry: the docs only say it pointed to Version_1.0 in May 2024, and `ListAvailableManagedRuleGroupVersions` still returned `CurrentDefaultVersion` Version_1.0 on 2026-10-17. Check it rather than assume.

**SQLi is not an upgrade path.** `AWSManagedRulesSQLiRuleSet` has two lineages. Version_2.0 (2022-01) added JSON inspection to `SQLi_BODY` and removed `SQLi_URIPATH`; 1.2 (2024) and 1.3 (2025) added transformations to the 1.x line; and the changelog says "Version_2.3 is the successor to Version_1.3, not Version_2.0". So a higher number is not a newer detection, and "upgrade to 2.0" is wrong advice. Flag the group only when it is unpinned.

For other managed rule groups, a pinned version needs no action.

### How overrides work
- Each rule inside a managed rule group has a default action (Block, Count, Challenge, etc.)
- You can override individual rules to a different action (e.g., Block → Count, Block → Allow)
- Overriding to Count: the request continues to the NEXT rule within the same rule group, then to subsequent rules in the Web ACL. Labels from the Count-overridden rule are still added.
- Overriding to Allow: the request is IMMEDIATELY allowed and skips ALL remaining rules (both within the group and in the Web ACL). This is the most dangerous override.
- Overriding to Block: the request is immediately blocked.

### Key implications
- Override to Count on one rule may expose traffic to a stricter rule later in the same group
- Override to Allow on one rule bypasses all subsequent protections — not just the current rule group
- When reviewing overrides, consider the rule's position within the group and what comes after it



## How Agent Should Use This

When reviewing rules:
1. CRS present but SizeRestrictions_Body not overridden to Count → recommend override (frequent FP)
2. No CRS and no KnownBadInputs → recommend both as baseline (unless DDoS-only WebACL)
3. SQLiRuleSet pinned at any version → no version advice; the lineages differ in trade-offs, not in age
4. BotControlRuleSet unpinned or pinned below the latest version → recommend pinning Version_7.0
5. Any rule overridden to Allow → check if it bypasses all subsequent rules (most dangerous override)
6. Token domain missing apex domain → subdomains not covered
7. WCU approaching 5000 → warn before recommending additional rules
