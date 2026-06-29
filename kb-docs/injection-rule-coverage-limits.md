# When a SQLi/XSS managed rule is enabled but didn't block an attack

This covers the case where the rule IS configured and IS in Block mode, the request even reached
it, but a specific injection payload was still allowed. This is the opposite of a false positive
(see `sqli-xss-false-positives.md` for over-blocking). Here the question is "why did this attack
get through?"

First rule: confirm the rule actually works before assuming it's broken. The agent can do this
from logs and config — check that the rule is present and in Block mode, and that the payload's
request shows up as ALLOW'd having matched no injection rule. To confirm the rule itself still
fires, suggest the *user* send a classic, well-known payload of the **same attack type** the rule
covers, to the **same location** (query string, body, header, or path) where their payload landed
— e.g. a textbook SQLi string for a SQLi rule, a textbook tag-based XSS string for an XSS rule. It
should be blocked. Match the attack type and location to their case; don't suggest an XSS test for
a SQLi complaint, or a query-string test when the payload was in the body. The agent is read-only
and cannot send test traffic itself. If the classic payload blocks but the user's specific one
does not, the rule is fine — the payload is outside what the rule's detection covers. Don't tell
the user "your config is wrong" when it isn't.

## The XSS coverage gap: payloads with no HTML tags

AWS WAF's managed XSS detection is strongest on HTML-context injection — payloads that carry
HTML structure: `<script>`, other tags, event handlers like `onerror=`, or the `javascript:`
protocol. It is much weaker on **pure JavaScript-context** payloads that contain no HTML tags at
all — for example a quote-break into a function call:

```
';a=prompt,a('XSS')//
```

This has no `<`, `>`, or tags. It breaks out of a JavaScript string and calls a function. The
managed XSS rule generally will NOT catch this class, and adding more text transformations
(HTML entity decode, JS decode, etc.) will NOT help — the issue isn't encoding, the decoded
plaintext simply has no signal the XSS rule keys on. It is a coverage limit of the managed XSS
rule, not a misconfiguration on the user's side.

So when a user reports "XSS rule didn't block this": check whether the payload has HTML tags.
- Has tags (`<script>`, `<img onerror=>`, etc.) and still allowed → investigate config / scope-down / encoding.
- No tags, pure JS-context escape → this is the coverage gap above. Explain it honestly; the fix
  is a custom rule (below), not a managed-rule setting.

## SQLi has a sensitivity lever; XSS does not

This is the key difference in how you fix a coverage gap for each.

**SQLi** has a `SensitivityLevel` of `LOW` or `HIGH`. HIGH catches more injection patterns, at the
cost of more false positives and slightly higher WCUs. But there are two constraints that make
"just turn it up" wrong:

- The **AWS managed SQLi rule group is fixed at LOW and cannot be changed** — you can override its
  actions or exclude rules, but not its sensitivity. So raising sensitivity is not a setting on
  the managed rule.
- `SensitivityLevel` only exists on a **custom `SqliMatchStatement`** that you write yourself, and
  it **defaults to LOW** (in the console, CLI, SDK, and CloudFormation alike — omitting it gives
  LOW). To get HIGH you must write a custom rule and set `"SensitivityLevel": "HIGH"` explicitly.
- A `SqliMatchStatement` inspects **one `FieldToMatch` location** (query string, body, a specific
  header, or URI path). One statement covers one location, so covering several locations means
  several rules (or several statements). You cannot set HIGH "globally" in one place.

So the real SQLi fix is: add a custom rule with `SqliMatchStatement`, `SensitivityLevel: HIGH`,
pointed at the specific location where attacks are getting through; repeat per location if needed.

**XSS** has **no sensitivity setting at all** — there is no dial to turn up, on managed or custom
rules. The only WAF-side option for an XSS coverage gap is a custom rule (regex or
`XssMatchStatement`), also one `FieldToMatch` location per statement.

Either way, deploy the new custom rule in Count first (next section) before switching to Block.

## Adding a custom rule to cover the gap

For an uncovered pattern (e.g. quote-escape into a dangerous function call), add a custom
`RegexMatchStatement` against the relevant field (e.g. `AllQueryArguments`) with the usual text
transformations (URL decode, HTML entity decode, lowercase). Place it before the managed rule
group.

**Always deploy a new injection rule in Count mode first.** Both a HIGH-sensitivity SQLi rule and
an XSS/regex rule over-match easily — a search box that accepts quotes, parentheses, or code-like
queries will trip them. Watch it for a few days using the rule's **CloudWatch `CountedRequests`
metric** (the reliable count of matches) and **sampled requests** (to see the actual matched
requests and weed out legitimate ones), tune out false positives, then switch to Block. Going
straight to Block risks blocking real users.

## The bigger point: scanners are stopped by behavior layers, not injection signatures

Many "why didn't WAF block this scan?" reports come from automated scanners (tell-tale signs:
scanner-style parameter names, fixed user-agents, high-frequency probing, parameter fuzzing).
Other WAFs that "catch everything" usually aren't catching it with a smarter XSS signature — they
catch it at the behavior layer: bot detection, IP reputation, rate limiting, and request scoring.
The scanner gets blocked for *being a scanner*, often before its payload is even inspected.

AWS WAF has behavior layers available too: Bot Control, the Anti-DDoS managed rule group,
rate-based rules, and the Amazon IP reputation list. These are usually a better answer for "stop
the scanner" than fighting it with injection signatures. Two caveats to set the right
expectation:

- Bot Control's stronger detection depends on a WAF token, which the client only gets by solving
  a Challenge or CAPTCHA (the token carries the signals that identify a session). Without that
  token flow in place, Bot Control falls back to weaker request-shape signals and catches much
  less. So "turn Bot Control to Block" is not a one-switch fix — it works well once Challenge/
  CAPTCHA is issuing tokens, less so without.
- Rate-based rules and IP reputation don't need a token and can blunt high-frequency scanners on
  their own, independent of Bot Control.

## Honesty boundary

- A managed injection rule allowing a specific payload is a **coverage limit**, not proof the WAF
  is broken or misconfigured. Confirm with a known-good payload first.
- Whether an allowed payload is actually exploitable depends on the application: if the backend
  escapes its output, a reflected payload may be a non-exploitable scanner finding. WAF rules are
  defense-in-depth; the root fix for XSS/SQLi is application-layer input validation and output
  encoding.
- Don't promise that a custom rule will catch "all" variants. No signature-based layer does. Pair
  it with the behavior layers above.
