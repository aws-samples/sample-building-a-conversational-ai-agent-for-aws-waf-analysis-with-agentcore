# Common SQLi/XSS False Positive Scenarios

## SQLi False Positives by Industry

### Financial Services

The most common SQLi FP pattern. Users searching for financial products trigger UNION + SELECT keyword detection.

Examples that trigger AWS SQLi rules:
- "credit UNION members SELECT best savings plan"
- "federal UNION SELECT retirement benefits"
- "trade UNION SELECT worker compensation"

The word "union" (labor/credit union) combined with "select" (choose) forms a SQL keyword pair that the SQLi engine detects as injection syntax.

**Recommended fix**: Scope-down the SQLi rule for the /search path using Method 1 (label match) or Method 3 (LOW sensitivity). Do NOT disable SQLi for the entire site.

### E-commerce / Content Sites

Rich text editors, product descriptions, and user comments commonly trigger XSS rules.

Examples:
- HTML in comments: `<b>great product</b>` triggers CrossSiteScripting
- Price comparisons: `price <100` triggers angle bracket detection
- Code snippets in tech forums: `<script>` in code blocks

**Recommended fix**: For user-generated content paths (/comments, /reviews, /posts), use Method 1 with label match or Method 2 scope-down. Keep XSS protection active on admin/login/checkout paths.

### SaaS / API Platforms

Webhook payloads, JSONP callbacks, and OAuth redirect URIs trigger RFI rules.

Examples:
- `?callback=http://partner.com/handler` triggers GenericRFI
- `?redirect_uri=https://oauth.provider.com/callback` triggers GenericRFI
- JSON body containing URLs triggers GenericRFI_BODY

**Recommended fix**: Scope-down RFI rules for known webhook/callback endpoints. Use IP-based or signature-based allow for trusted partner integrations.

## XSS False Positives

### Common Triggers

- HTML formatting in user content (`<b>`, `<i>`, `<em>`)
- Template syntax (`{{variable}}`, `<%= code %>`)
- Mathematical expressions (`x<10`, `a>b`)
- SVG/image markup in rich editors
- Email content with HTML signatures

### Less Common but Valid

- Search queries containing HTML examples (tech documentation sites)
- API endpoints accepting HTML email templates
- CMS endpoints saving page templates
- Chat/messaging with HTML preview

## Path-Based Risk Assessment

| Path Type | SQLi Risk | XSS Risk | Recommended Action |
|-----------|-----------|----------|-------------------|
| /login, /auth | HIGH | LOW | Keep full Block |
| /admin, /dashboard | HIGH | HIGH | Keep full Block |
| /search | LOW (user queries) | LOW | Scope-down SQLi, keep or lower XSS |
| /api/webhook | LOW | LOW | Scope-down both for verified sources |
| /comments, /reviews | LOW | MEDIUM | Scope-down XSS, keep SQLi |
| /upload | LOW | LOW | Focus on size restrictions instead |
| /checkout, /payment | HIGH | HIGH | Keep full Block, never scope-down |

## Key Principle

A false positive on /search does NOT mean SQLi protection is wrong — it means the path accepts content that legitimately contains SQL-like keywords. The correct response is to narrow the protection scope, not to question the rule's validity.
