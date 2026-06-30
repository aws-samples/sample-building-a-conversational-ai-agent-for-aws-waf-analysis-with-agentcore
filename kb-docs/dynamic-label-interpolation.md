# Dynamic Label Interpolation

## What It Is

Dynamic label interpolation lets you embed label values in custom request headers, custom response headers, and custom response bodies using `${namespace:}` syntax. AWS WAF resolves placeholders at evaluation time against labels attached to the request.

## Key Facts

- Syntax: `${namespace:}` — the trailing colon is required
- Single label match → resolves to terminal value (e.g., `${awswaf:managed:aws:bot-control:bot:category:}` → `scraping`)
- Multiple labels in namespace → comma-separated list (e.g., `scraping,advertising`)
- No match → empty string
- Limit: 10 placeholders per string value
- Custom labels require fully-qualified namespace: `awswaf:{ACCOUNT_ID}:webacl:{WEBACL_NAME}:{your_namespace:}`
- Label match statement uses short namespace, but interpolation requires fully-qualified namespace

## Supported Locations

- Custom request headers (InsertHeaders) — forwarded to origin
- Custom response headers — sent back to client
- Custom response bodies — block pages, challenge pages

## Synthetic Labels

| Placeholder | Resolves To |
|---|---|
| `${awswaf:request_id:}` | Unique AWS WAF request ID |
| `${awswaf:ip:}` | Client IP address |
| `${awswaf:ja3:}` | JA3 TLS fingerprint |
| `${awswaf:ja4:}` | JA4 TLS fingerprint |

## Impact on AWS WAF Logs

Dynamic label interpolation does NOT add new fields to AWS WAF logs. The `requestHeadersInserted` field in the log records the resolved header name-value pairs that were actually sent to the origin. This means:

- If a rule uses interpolation to insert `bot-category: scraping` into a request header, the log shows `{"name": "x-amzn-waf-bot-category", "value": "scraping"}` in `requestHeadersInserted`
- The log does NOT show the `${namespace:}` template — only the resolved values
- If the namespace matched no labels, the header value is empty string in the log
- `requestHeadersInserted` only appears for requests that reached a rule with CustomRequestHandling (Count or Allow actions)

## How WAF Analyst Should Use This

When analyzing AWS WAF logs:
1. Check `requestHeadersInserted` for resolved interpolation values — these reveal which Bot Control categories, signal types, or custom labels were active for each request
2. If a WebACL has interpolation rules configured, the `requestHeadersInserted` field is a richer signal source than the `labels` array (which only shows labels, not their resolved context)
3. Use interpolated headers to understand origin-side decisions: if origin uses `x-amzn-waf-bot-category` for routing/blocking, the WAF log shows exactly what value the origin received

When reviewing AWS WAF rules:
1. Check if the WebACL uses interpolation (look for `${` in InsertHeaders values)
2. If Bot Control or Anti-DDoS AMR is present but no interpolation rule exists, recommend adding one — it gives the origin visibility into AWS WAF's classification without requiring the origin to parse AWS WAF logs
3. Interpolation rules should use Count action (they're for signaling, not blocking)
4. Verify the namespace in `${...}` matches the actual label namespace produced by the managed rule group

## Common Pattern: Forward Bot Control Signals to Origin

```json
{
  "Name": "forward-waf-signals",
  "Statement": {
    "LabelMatchStatement": {
      "Scope": "NAMESPACE",
      "Key": "awswaf:managed:aws:bot-control:bot:category:"
    }
  },
  "Action": {
    "Count": {
      "CustomRequestHandling": {
        "InsertHeaders": [
          {"Name": "bot-category", "Value": "${awswaf:managed:aws:bot-control:bot:category:}"},
          {"Name": "bot-name", "Value": "${awswaf:managed:aws:bot-control:bot:name:}"},
          {"Name": "bot-signals", "Value": "${awswaf:managed:aws:bot-control:signal:}"},
          {"Name": "client-ip", "Value": "${awswaf:ip:}"}
        ]
      }
    }
  }
}
```

This single rule covers all bot categories without needing updates when new categories are added.

## Common Pattern: Cache Segmentation with CloudFront

Interpolation can drive CloudFront cache keys — different bot classifications get separate cache entries:

```json
{
  "Name": "cache-segmentation",
  "Statement": {
    "LabelMatchStatement": {
      "Scope": "NAMESPACE",
      "Key": "awswaf:managed:aws:bot-control:bot:category:"
    }
  },
  "Action": {
    "Count": {
      "CustomRequestHandling": {
        "InsertHeaders": [
          {"Name": "bot-category", "Value": "${awswaf:managed:aws:bot-control:bot:category:}"}
        ]
      }
    }
  }
}
```

CloudFront is configured to include `x-amzn-waf-bot-category` in the cache key policy. Result: verified crawlers, unverified bots, and normal users each get their own cache — origin can serve different content per classification without additional logic.

When reviewing rules: if you see an interpolation rule with Count action that inserts headers used in CloudFront cache key policy, this is a **performance optimization pattern**, not a security rule. Do not flag it as "Count rule without labels" or suggest changing its action.
