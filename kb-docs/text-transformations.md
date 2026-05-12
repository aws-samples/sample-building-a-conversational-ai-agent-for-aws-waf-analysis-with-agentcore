# Text Transformations (Encoding Bypass Prevention)

## What It Is

Text transformations normalize web request content BEFORE the match condition is evaluated. They counter encoding-based WAF evasion by decoding obfuscated payloads into their canonical form for inspection. Transformations operate on an inspection copy only — the actual forwarded request is never modified.

## Key Facts

- Applied BEFORE match condition evaluation
- Operate on inspection copy only (request not modified)
- Max 10 transformations per rule statement (hard limit, not adjustable)
- Each transformation adds WCUs (for regex pattern set rules: 10 WCU per transformation; for other rule types the impact varies)
- Priority field = execution order (lowest number runs first)
- Transformations never cause a rule to be skipped — on "failure" (e.g., BASE64_DECODE on non-base64), produces best-effort output and evaluation continues
- For JSON body: transformations apply AFTER JSON parsing (on extracted element values)

## Complete Transformation List (21 types)

| API Name | Purpose |
|---|---|
| `NONE` | No transformation; inspect as-is |
| `URL_DECODE` | Standard percent-decoding (%xx) |
| `URL_DECODE_UNI` | Percent-decode + Microsoft %u encoding |
| `HTML_ENTITY_DECODE` | Decode &amp; &#60; &#x3C; etc. |
| `BASE64_DECODE` | Strict Base64 decode |
| `BASE64_DECODE_EXT` | Forgiving Base64 (ignores invalid chars) |
| `LOWERCASE` | Convert A-Z to a-z |
| `CMD_LINE` | OS command injection normalization |
| `COMPRESS_WHITE_SPACE` | Collapse multiple spaces/control chars |
| `CSS_DECODE` | Decode CSS 2.x escape sequences |
| `ESCAPE_SEQ_DECODE` | Decode ANSI C escapes (\n, \xHH, \0OOO) |
| `HEX_DECODE` | Decode hex-encoded string |
| `JS_DECODE` | Decode JavaScript \uHHHH sequences |
| `MD5` | Compute MD5 hash |
| `NORMALIZE_PATH` | Remove ./ ../ and multiple slashes |
| `NORMALIZE_PATH_WIN` | Convert \ to / then normalize path |
| `REMOVE_NULLS` | Strip all NULL bytes (0x00) |
| `REPLACE_NULLS` | Replace NULL bytes with space |
| `REPLACE_COMMENTS` | Replace C-style /* */ comments with space |
| `SQL_HEX_DECODE` | Decode SQL hex literals (0x414243 → ABC) |
| `UTF8_TO_UNICODE` | Convert UTF-8 sequences to Unicode code points |

## Bypass Techniques and Countermeasures

| Bypass Technique | Transformation |
|---|---|
| URL encoding | `URL_DECODE` |
| Double URL encoding | `URL_DECODE` × 2 (priority 0 + 1) |
| Microsoft %u encoding | `URL_DECODE_UNI` |
| HTML entity encoding | `HTML_ENTITY_DECODE` |
| Mixed case | `LOWERCASE` |
| Null byte injection | `REMOVE_NULLS` |
| Base64 payload | `BASE64_DECODE_EXT` |
| CSS escape | `CSS_DECODE` |
| JS unicode escape | `JS_DECODE` |
| SQL comment bypass | `REPLACE_COMMENTS` |
| Path traversal | `NORMALIZE_PATH` |
| Windows path traversal | `NORMALIZE_PATH_WIN` |
| SQL hex literal | `SQL_HEX_DECODE` |
| Full-width Unicode | `UTF8_TO_UNICODE` |
| ANSI C escape | `ESCAPE_SEQ_DECODE` |

## Recommended Transformation Chains

### Baseline for custom SQLi/XSS rules
```
Priority 0: URL_DECODE
Priority 1: HTML_ENTITY_DECODE
Priority 2: LOWERCASE
```

### Double-encoding prevention
```
Priority 0: URL_DECODE       (first pass: %2527 → %27)
Priority 1: URL_DECODE       (second pass: %27 → ')
Priority 2: LOWERCASE
```

### Base64 payload inspection
```
Priority 0: BASE64_DECODE_EXT  (forgiving decode)
Priority 1: URL_DECODE
Priority 2: LOWERCASE
```

### Path traversal prevention
```
Priority 0: URL_DECODE
Priority 1: NORMALIZE_PATH_WIN  (handles both / and \)
```

### Command injection prevention
```
Priority 0: URL_DECODE
Priority 1: CMD_LINE
Priority 2: LOWERCASE
```

## Managed Rules and Transformations

- AWS Managed Rules (CRS, KnownBadInputs) apply their own internal transformations — not publicly documented
- You CANNOT add transformations to a managed rule group reference statement
- Managed rules' internal transformations do NOT apply to your custom rules
- If you write custom rules to complement managed rules, you MUST add your own transformations

## How Agent Should Use This

When reviewing rules:
1. Custom string-match or regex rule with `NONE` transformation → potential bypass vulnerability (recommend adding URL_DECODE + HTML_ENTITY_DECODE + LOWERCASE at minimum)
2. Custom rule with only single URL_DECODE → vulnerable to double-encoding bypass (recommend URL_DECODE × 2)
3. Rule inspecting body of API that accepts Base64 input without BASE64_DECODE_EXT → payloads hidden in Base64 won't be detected
4. Path-based rules without NORMALIZE_PATH → traversal bypass possible
5. High WCU usage from many transformations → each adds 10 WCU, consider if all are necessary

When analyzing bypass incidents:
1. If attacker bypassed a custom rule → check what transformations are configured
2. Compare attacker's encoding technique against the transformation list above
3. Recommend adding the missing transformation to close the gap
4. Note: managed rules may already handle the encoding internally — check if the bypass was against a custom rule or managed rule
