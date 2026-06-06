# False Positive Scope-Down Best Practices

## Principle: Never Disable, Always Scope Down

When a managed rule causes false positives, do NOT:
- Disable the entire managed rule group
- Set the entire group to Count permanently
- Add a broad Allow rule above the managed rule group

Instead, create a narrow exception that preserves protection for all other traffic.

## Method 1: RuleActionOverride + Label Match Rule (Recommended)

Step 1: Override the specific sub-rule to Count.

```
ManagedRuleGroupStatement:
  VendorName: AWS
  Name: AWSManagedRulesSQLiRuleSet
  RuleActionOverrides:
    - Name: SQLi_QUERYARGUMENTS
      ActionToUse: { Count: {} }
```

Step 2: Add a label match rule BELOW the managed rule group that blocks everything except the FP path.

```
Rule: block-sqli-except-search
Priority: (below SQLiRuleSet)
Statement:
  AND:
    - LabelMatchStatement:
        Scope: LABEL
        Key: awswaf:managed:aws:sql-database:SQLi_QueryArguments
    - NOT:
        ByteMatchStatement:
          FieldToMatch: UriPath
          SearchString: /search
          PositionalConstraint: STARTS_WITH
Action: Block
```

This means: SQLi_QUERYARGUMENTS still evaluates all requests and adds labels, but only blocks requests NOT on /search. Requests to /search get the label but are allowed through.

## Method 2: Scope-Down Statement on the Managed Rule Group

Add a scope-down statement that excludes the problematic path from evaluation entirely.

```
ManagedRuleGroupStatement:
  VendorName: AWS
  Name: AWSManagedRulesSQLiRuleSet
  ScopeDownStatement:
    NOT:
      ByteMatchStatement:
        FieldToMatch: UriPath
        SearchString: /search
        PositionalConstraint: STARTS_WITH
```

Trade-off: Requests to /search are not inspected for SQLi at all. This is less secure than Method 1 but simpler to implement.

## Method 3: SQLi Sensitivity Level

AWS SQLi detection supports sensitivity levels: LOW and HIGH (default).

- HIGH: catches more injection patterns but produces more false positives
- LOW: only catches high-confidence injection, fewer false positives

For paths that accept user-generated content (search, comments, rich text):
```
ManagedRuleGroupStatement:
  VendorName: AWS
  Name: AWSManagedRulesSQLiRuleSet
  RuleActionOverrides:
    - Name: SQLi_QUERYARGUMENTS
      ActionToUse: { Count: {} }

# Then add custom rule with LOW sensitivity for that path:
Rule: sqli-low-sensitivity-search
Statement:
  AND:
    - ByteMatchStatement:
        FieldToMatch: UriPath
        SearchString: /search
        PositionalConstraint: STARTS_WITH
    - SqliMatchStatement:
        FieldToMatch: QueryString
        TextTransformations:
          - Priority: 0
            Type: URL_DECODE
          - Priority: 1
            Type: HTML_ENTITY_DECODE
        SensitivityLevel: LOW
Action: Block
```

## When to Use Each Method

| Scenario | Recommended Method |
|----------|-------------------|
| FP on one specific path, protection still needed | Method 1 (label match) |
| FP on one path, protection not critical there | Method 2 (scope-down) |
| Frequent FP across many paths from user content | Method 3 (lower sensitivity) |
| FP from known partner/integration IP | IP set exclusion in scope-down |
| FP from specific HTTP method (e.g., POST to API) | Method + method condition |

## Important: Always Monitor After Scope-Down

After creating any exception:
1. Monitor BlockedRequests and CountedRequests metrics for 24-72 hours
2. Check that attack traffic on other paths is still blocked
3. Verify no new attack patterns exploit the excluded path
4. Set a review date (30-90 days) to re-evaluate whether the exception is still needed
