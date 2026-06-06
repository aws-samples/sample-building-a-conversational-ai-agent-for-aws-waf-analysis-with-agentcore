# AWS WAF Configuration for WordPress

## Recommended Managed Rule Groups

| Rule Group | WCU | Purpose |
|-----------|-----|---------|
| AWSManagedRulesAntiDDoSRuleSet | 50 | Volumetric request flood protection |
| AWSManagedRulesAmazonIpReputationList | 25 | Known bad IPs, botnets |
| AWSManagedRulesCommonRuleSet (CRS) | 700 | OWASP Top 10: XSS, LFI, size limits |
| AWSManagedRulesAdminProtectionRuleSet | 100 | Admin path access control |
| AWSManagedRulesKnownBadInputsRuleSet | 200 | Log4j, Java RCE, known exploits |
| AWSManagedRulesSQLiRuleSet | 200 | SQL injection |
| AWSManagedRulesPHPRuleSet | 100 | PHP-specific injections |
| AWSManagedRulesWordPressRuleSet | 100 | WordPress-specific exploits |
| AWSManagedRulesLinuxRuleSet | 200 | Linux LFI attacks |
| **Total** | **~1,675** | **of 5,000 WCU limit** |

---

## WordPress-Specific Rules

**AWSManagedRulesWordPressRuleSet** sub-rules:
- `WordPressExploitablePaths_URIPATH` — blocks xmlrpc.php and other exploitable files
- `WordPressExploitableCommands_QUERYSTRING` — blocks high-risk commands (e.g., do-reset-wordpress)

Deploy together with SQLi + PHP rule groups for comprehensive coverage.

---

## AdminProtectionRuleSet Configuration

**Problem**: `AdminProtection_URIPATH` blocks /wp-admin/ — locks out legitimate admins.

**Solution**: Count + Label + Custom Rule:
```json
{
  "ManagedRuleGroupStatement": {
    "VendorName": "AWS",
    "Name": "AWSManagedRulesAdminProtectionRuleSet",
    "RuleActionOverrides": [
      {"Name": "AdminProtection_URIPATH", "ActionToUse": {"Count": {}}}
    ]
  }
}
```

Custom rule below:
```json
{
  "Name": "block-admin-except-trusted-ips",
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:admin-protection:AdminProtection_URIPATH"
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "IPSetReferenceStatement": {"ARN": "<admin-ip-set-arn>"}
            }
          }
        }
      ]
    }
  },
  "Action": {"Block": {}}
}
```

**Important exception**: `/wp-admin/admin-ajax.php` is called by WordPress frontend (AJAX search, comment forms). Must NOT be blocked for public visitors. Add to scope-down or label match NOT condition.

---

## Essential Custom Rules

| Rule | Config | Purpose |
|------|--------|---------|
| Block wp-config.php | ByteMatch URI contains `wp-config.php` → Block | Protect database credentials |
| Block xmlrpc.php | ByteMatch URI contains `xmlrpc.php` → Block | Eliminate DDoS amplification + brute force surface |
| Rate limit global | RateBasedStatement 2000/5min per IP → Block | Baseline flood protection |
| Rate limit wp-login.php | RateBasedStatement 100/5min, scope-down to /wp-login.php → Block | Brute force protection |
| Geo-restrict wp-admin | GeoMatch NOT(allowed countries) + URI /wp-admin → Block | Admin access control |

---

## Rule Priority Order

| Priority | Rule |
|----------|------|
| 1 | Block wp-config.php (custom) |
| 2 | Anti-DDoS AMR |
| 3 | Rate limit global (custom) |
| 5 | Rate limit wp-login.php (custom) |
| 6 | Geo-block wp-admin (custom) |
| 10 | IP Reputation List AMR |
| 30 | CRS AMR (with CrossSiteScripting_BODY + SizeRestrictions_BODY overridden to Count) |
| 35 | Label match: block XSS body except /wp-admin (custom) |
| 40 | Admin Protection AMR (with Count + label pattern) |
| 50 | Known Bad Inputs AMR |
| 60 | SQLi AMR |
| 70 | PHP AMR |
| 80 | WordPress AMR |
| 90 | Linux AMR |

**Principles**:
- Custom blocks first (cheap WCU, high confidence)
- IP reputation before expensive inspection
- AMRs with Count overrides followed immediately by label match rules
- WordPress/PHP rules last (most targeted)
- Never use Allow rules — Count + Label + Block pattern is always safer

---

## WordPress FP Handling

**Problem**: Admin POST to /wp-admin triggers CrossSiteScripting_BODY and SizeRestrictions_BODY.

**Triggers in logs**:
- `CrossSiteScripting_BODY`, matchedData: `["<?", "xml"]` or `["<", "script"]` or `["<", "iframe"]`
- `SizeRestrictions_BODY` on large posts

**Solution**:
1. RuleActionOverride `CrossSiteScripting_BODY` → Count
2. RuleActionOverride `SizeRestrictions_BODY` → Count (permanent — WordPress posts always exceed limits)
3. Custom rule: `label=awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body AND URI NOT starts with /wp-admin → Block`

**Result**: XSS body protection on public paths. Admin editing unblocked.

---

## CloudFront Notes

- Web ACL scope: CLOUDFRONT (us-east-1 only)
- Body inspection limit: increase to 64 KB (WordPress posts are large)
- Rate-based rules: CloudFront forwards true client IP (use IP aggregation)
- Token domains: include all WordPress domains if using Challenge/CAPTCHA
