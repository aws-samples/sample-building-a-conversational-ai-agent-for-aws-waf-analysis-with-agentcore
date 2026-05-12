# Rate-based Rules

### Characteristics
- There is a delay from threshold breach to rule activation — rate-based rules do not take effect instantaneously
- Evaluation window options: 60s (1 min), 120s (2 min), 300s (5 min, default), 600s (10 min)
- Rate limit threshold: minimum 10 requests per evaluation window, no upper bound specified
- Action: any rule action except Allow

### Challenge action on rate-limit rules
- For API paths: Challenge = Block (clients can't complete)
- For browser paths: legitimate users rarely exceed thresholds
- Low severity issue in DDoS context

### Native app traffic coverage
- Native app traffic that bypasses Challenge-based protections (e.g., via scope-down exclusion or because native apps cannot complete Challenge) still needs rate limiting as a defense layer
- Ensure at least one rate-based rule covers native app traffic paths without relying on Challenge as the action

### Multiple rate-based rules with overlapping scope-downs
- If a Web ACL has multiple rate-based rules, and their scope-down conditions overlap or have a containing relationship (e.g., one targets `/api/` and another targets all traffic), only the rule with the lowest threshold will ever trigger for the overlapping traffic
- The other rules are effectively redundant for that traffic
- If the intent was different rate limits for different traffic types, scope-downs should be adjusted to be mutually exclusive



## How Agent Should Use This

When analyzing logs:
1. ALLOW entries before BLOCK from same IP on rate-based rule = normal (kick-in delay)
2. Rate-based rule blocking legitimate users → check if threshold is too low for the evaluation window

When reviewing rules:
1. Challenge action on rate-based rule for API paths → effectively Block (low severity if threshold is high)
2. Multiple rate-based rules with overlapping scope-downs → only lowest threshold triggers (redundancy)
3. No rate-based rule covering native app traffic → gap in protection
4. Very low threshold (e.g., 10) with short window (60s) → high FP risk for legitimate burst traffic
