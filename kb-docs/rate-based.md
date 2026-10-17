# Rate-based Rules

### Characteristics
- There is a delay from threshold breach to rule activation — rate-based rules do not take effect instantaneously. AWS gives no single figure: the caveats page says "usually, this delay is below 30 seconds", the rate-limiting options table says "usually 30-50 seconds", both say it can be several minutes, and AWS WAF checks the rate about every 10 seconds
- Evaluation window options: 60s (1 min), 120s (2 min), 300s (5 min, default), 600s (10 min)
- Rate limit threshold: 10 to 2,000,000,000 requests per evaluation window, for each aggregation instance (API reference, `RateBasedStatement.Limit`)
- Action: any rule action except Allow
- Changing any rate-limit setting of a rule in use resets its counts, which can pause its rate limiting for up to a minute

### What rate-based rules can't do
- With a scope-down, the rule only aggregates, counts and rate limits requests that match the scope-down, so its action applies to those requests only, not to everything from the IP. Only IP aggregation without a scope-down acts on everything from the IP
- A custom key of IP plus `UriPath` makes each IP and path pair its own aggregation instance; there is no key that counts distinct paths per IP, so path enumeration can't be rate limited directly. A request missing any component a key names is not evaluated by the rule
- AWS WAF inspects requests, not origin responses (ATP and ACFP excepted), so a count of 404 or 403 responses can't be a rule condition
- Log-driven 4xx blocking (Athena or Lambda writing an IP set) acts minutes later and costs money to run, so it does not stop burst scanning. Security Automations for AWS WAF, which offers it, "will retire in December 2026"

### Challenge action on rate-limit rules
- For API paths: Challenge = Block (clients can't complete)
- For browser paths: legitimate users rarely exceed thresholds
- Low severity issue in DDoS context

### Native app traffic coverage
- Native app traffic that bypasses Challenge-based protections (e.g., via scope-down exclusion or because native apps cannot complete Challenge) still needs rate limiting as a defense layer
- Ensure at least one rate-based rule covers native app traffic paths without relying on Challenge as the action

### Multiple rate-based rules with overlapping scope-downs
- If a Web ACL has multiple rate-based rules, and their scope-down conditions overlap or have a containing relationship (e.g., one targets `/api/` and another targets all traffic), each rule counts on its own, and rules are evaluated by priority, not by limit. The lower limit is crossed first, so it usually acts first on the overlapping traffic, and a request it blocks never reaches a later rule. A higher-limit rule still acts on that traffic if it runs earlier and its own count is over its limit
- So the higher limit adds little for the overlapping traffic unless it runs first
- If the intent was different rate limits for different traffic types, scope-downs should be adjusted to be mutually exclusive



## How Agent Should Use This

When analyzing logs:
1. ALLOW entries before BLOCK from same IP on rate-based rule = normal (kick-in delay)
2. Rate-based rule blocking legitimate users → check if threshold is too low for the evaluation window

When reviewing rules:
1. Challenge action on rate-based rule for API paths → effectively Block (low severity if threshold is high)
2. Multiple rate-based rules with overlapping scope-downs → the lower limit usually acts first on the overlap, so the higher one adds little there unless it runs earlier
3. No rate-based rule covering native app traffic → gap in protection
4. Very low threshold (e.g., 10) with short window (60s) → high FP risk for legitimate burst traffic
