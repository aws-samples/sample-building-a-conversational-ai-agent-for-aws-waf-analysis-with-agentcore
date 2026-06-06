# Common SQLi and XSS False Positive Scenarios

## SQLi False Positives

### Financial Services — UNION + SELECT in Natural Language

**Trigger**: Users search for financial products containing SQL keywords.

**Examples that trigger AWS SQLi rules**:
- `credit UNION members SELECT best savings plan`
- `federal UNION SELECT retirement benefits`
- `trade UNION SELECT worker compensation`

**Why it triggers**: `UNION` + `SELECT` is a SQL keyword pair. The SQLi engine detects this pattern regardless of surrounding natural language text.

**Fix**: Scope-down SQLi for /search path (Method 1: label match, or Method 3: LOW sensitivity). Do NOT disable SQLi site-wide.

---

### E-commerce / Content — HTML in User Input

**Trigger**: Rich text, product descriptions, comments contain HTML-like syntax.

**Examples**:
- `<b>great product</b>` → CrossSiteScripting_QUERYARGUMENTS
- `price <100` → angle bracket detection
- `<script>` in code block discussions → CrossSiteScripting

**Fix**: Scope-down XSS rules for user-content paths (/comments, /reviews, /posts). Keep XSS protection on /login, /checkout, /admin.

---

### SaaS / API — URLs in Query Parameters

**Trigger**: Webhook callbacks, OAuth redirects, share URLs in query params.

**Examples**:
- `?callback=http://partner.com/handler` → GenericRFI_QUERYARGUMENTS
- `?redirect_uri=https://oauth.provider.com/callback` → GenericRFI_QUERYARGUMENTS

**Fix**: Scope-down RFI for webhook/callback endpoints. Use IP-based scope-down for trusted partner sources.

---

## XSS False Positives

### XML Processing Instructions

**Trigger**: `<?xml version="1.0"?>` in request body.

**What WAF logs show**: `CrossSiteScripting_BODY`, matchedData: `["<?", "xml"]`

**Why**: AWS WAF XSS engine interprets `<?` followed by tag name as potential processing instruction injection.

**Common in**: SOAP APIs, XML document upload, RSS feed submissions, WordPress post editing with embedded XML.

---

### WordPress / CMS Post Editing (Most Common Enterprise FP)

**Trigger**: Admin saves post via /wp-admin, POST body contains HTML/JS/XML.

**Content that triggers**:
- Gutenberg block markup: `<!-- wp:paragraph -->`, `<!-- wp:image -->`
- Embedded media: `<iframe>`, `<script>`, `<svg>`, `<object>`
- XML declarations: `<?xml version="1.0" encoding="UTF-8"?>`
- oEmbed markup from video/social media embeds
- Event handlers in content: `onerror`, `onload`, `onclick`

**Rules triggered**:
- `CrossSiteScripting_BODY` — HTML/script/XML in POST body
- `SizeRestrictions_BODY` — Large posts exceeding 8KB default limit

**Fix**:
1. Override `CrossSiteScripting_BODY` to Count
2. Override `SizeRestrictions_BODY` to Count (keep permanently — WordPress posts routinely exceed limits)
3. Add label match rule: `label=awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body AND URI NOT /wp-admin → Block`

**Result**: XSS body protection active on public paths; admin content editing allowed.

---

### Base64 Data with Event Handler Patterns

**Trigger**: Base64-encoded strings containing `+on` or `/on` substrings.

**Example**: `"dBV6+ON23vgWCNw=="` blocked because `+ON` matches XSS event handler pattern.

**Fix**: Scope-down XSS for API endpoints that transmit base64 data, or use a custom rule with specific field targeting.

---

## Path-Based Risk Assessment

| Path | SQLi Risk | XSS Risk | Action |
|------|-----------|----------|--------|
| /login, /auth | HIGH | LOW | Keep full Block |
| /admin, /wp-admin | HIGH | HIGH (FP on body) | Block on query; Count + label match on body for admin paths |
| /search | LOW | LOW | Scope-down SQLi; keep or lower XSS |
| /api/webhook | LOW | LOW | Scope-down both for verified sources |
| /comments, /reviews | LOW | MEDIUM | Scope-down XSS; keep SQLi |
| /upload | LOW | LOW | Focus on SizeRestrictions instead |
| /checkout, /payment | HIGH | HIGH | Keep full Block, never scope-down |

---

## Key Principle

A false positive does NOT mean the rule is wrong. It means the path accepts content that legitimately resembles an attack pattern. The correct response is to narrow the protection scope for that path, not to disable the rule globally.
