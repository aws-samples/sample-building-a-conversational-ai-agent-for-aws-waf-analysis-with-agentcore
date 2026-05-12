## AWSManagedRulesCommonRuleSet (CRS) Notes

- Provides OWASP Top 10 protection (SQLi, XSS, etc.)
- `SizeRestrictions_Body` rule blocks request bodies larger than 8KB. This frequently causes false positives on file upload endpoints, API endpoints with large payloads, form submissions with rich content, etc. Most users don't know which of their endpoints need large bodies. When recommending CRS, always advise overriding `SizeRestrictions_Body` to Count.


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

See **Appendix D** in the review report for the full recommended priority order table.

Key principles:
- Label producers before label consumers
- AntiDDoS AMR as early as possible for accurate baseline
- Cost optimization: cheaper rules first to filter traffic before expensive rules
- Terminating rules (Allow/Block) placed early should be scrutinized


## Managed Rule Group Action Overrides

### Version recommendations
Only these managed rule groups have significant version upgrades worth flagging:
- **AWSManagedRulesSQLiRuleSet**: version 2.0 has significantly higher SQLi detection coverage than the default 1.0. Recommend upgrading if pinned below 2.0.
- **AWSManagedRulesBotControlRuleSet**: version 5.0's Common level can identify close to 700 bot types (up from far fewer in 1.0) based on UA and IP, and Targeted level includes substantially more detection rules. The default version is still 1.0, which is outdated. Recommend upgrading if pinned below 5.0.

For all other managed rule groups, the version shown in JSON is just the current snapshot and requires no action.

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

