# False Positive Scope-Down Methods

## Method 1: RuleActionOverride + Label Match Rule

**When to use**: FP on a specific path but protection is still needed elsewhere.

**Problem**: Managed sub-rule blocks legitimate traffic on one path.

**Solution**:

Step 1 — Override the sub-rule to Count (it still labels but doesn't block):
```json
{
  "ManagedRuleGroupStatement": {
    "VendorName": "AWS",
    "Name": "AWSManagedRulesSQLiRuleSet",
    "RuleActionOverrides": [
      {"Name": "SQLi_QUERYARGUMENTS", "ActionToUse": {"Count": {}}}
    ]
  }
}
```

Step 2 — Add a label match rule below the managed group that blocks all EXCEPT the FP path:
```json
{
  "Name": "block-sqli-except-search",
  "Priority": 301,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:sql-database:SQLi_QueryArguments"
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "ByteMatchStatement": {
                "SearchString": "/search",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
                "PositionalConstraint": "STARTS_WITH"
              }
            }
          }
        }
      ]
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-sqli-except-search"
  }
}
```

**Result**: SQLi detection active everywhere. /search path gets labeled but not blocked. All other paths still blocked on SQLi match.

---

## Method 2: Scope-Down Statement

**When to use**: FP on a path where protection is not critical.

**Problem**: A path legitimately contains content that triggers rules (webhooks, callbacks, user content).

**Solution** — Exclude the path from managed rule evaluation entirely:
```json
{
  "ManagedRuleGroupStatement": {
    "VendorName": "AWS",
    "Name": "AWSManagedRulesSQLiRuleSet",
    "ScopeDownStatement": {
      "NotStatement": {
        "Statement": {
          "ByteMatchStatement": {
            "SearchString": "/search",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
            "PositionalConstraint": "STARTS_WITH"
          }
        }
      }
    }
  }
}
```

**Result**: /search requests are NOT inspected by SQLi rules at all. Less secure than Method 1 but simpler.

---

## Method 3: SQLi Sensitivity Level

**When to use**: Frequent FP across many paths from user-generated content.

**Problem**: A custom SQLi rule set to HIGH sensitivity catches too many legitimate patterns. (Note: LOW is the default for both custom `SqliMatchStatement` and the AWS managed SQLi rule group, which is fixed at LOW. HIGH only happens if you explicitly set it.)

**Solution** — Override managed rule to Count, add custom SQLi rule with LOW sensitivity:
```json
{
  "Name": "sqli-low-sensitivity-search",
  "Priority": 301,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "SearchString": "/search",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "LOWERCASE"}],
            "PositionalConstraint": "STARTS_WITH"
          }
        },
        {
          "SqliMatchStatement": {
            "FieldToMatch": {"QueryString": {}},
            "TextTransformations": [
              {"Priority": 0, "Type": "URL_DECODE"},
              {"Priority": 1, "Type": "HTML_ENTITY_DECODE"}
            ],
            "SensitivityLevel": "LOW"
          }
        }
      ]
    }
  },
  "Action": {"Block": {}},
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "sqli-low-sensitivity-search"
  }
}
```

**Result**: /search still has SQLi protection but only catches high-confidence injection patterns.

---

## Method Selection

| Condition | Method |
|-----------|--------|
| FP on one path, protection still needed elsewhere | Method 1 (label match) |
| FP on one path, protection not critical there | Method 2 (scope-down) |
| FP across many paths from user content | Method 3 (lower sensitivity) |
| FP from known partner/integration IP | Add IP set to scope-down NOT condition |
| FP from specific HTTP method (POST to API) | Add method condition to scope-down or label match |

---

## Anti-Patterns (Never Do)

| Anti-Pattern | Why It's Dangerous |
|-------------|-------------------|
| Disable entire managed rule group | Removes all protection, not just the FP path |
| Set entire group to permanent Count | No protection at all — Count doesn't block |
| Add Allow rule above managed group | Allow is terminating — skips ALL subsequent rules for matching traffic |
| IP-wide Allow for admin/partner | Bypasses every rule for that IP, including rate limits |

---

## Post-Change Monitoring

After any scope-down change:
1. Monitor BlockedRequests and CountedRequests metrics for 24-72 hours
2. Verify attack traffic on non-excluded paths is still blocked
3. Verify no new attack patterns exploit the excluded path
4. Set review date (30-90 days) to re-evaluate the exception
