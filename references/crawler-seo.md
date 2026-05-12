# Crawler and Cookie Logic Analysis Guide (for LLM Section 8)

## Your Task
Evaluate cookie-based security decisions and landing page protection patterns.

## Judgment Rules

### Cookie-based Security Logic
- Business cookie used as Allow/Block condition → forgeable, Awareness finding
- Cookie existence check for "returning user" detection → recommend AWS WAF token instead
- Cookie value matching for access control → recommend unforgeable alternative (IP set, ASN, WAF token)

### Landing Page Protection
- Always-on Challenge present with crawler exclusion → good configuration, no finding
- Always-on Challenge WITHOUT crawler exclusion → Medium (SEO risk)
- No always-on Challenge + DDoS protection objectives → Medium (recommend two-rule pattern: Count+Label on landing URIs → Challenge on label, exclude crawlers)
- Token immunity time < 4 hours (14400s) for always-on Challenge → Low (recommend extending)

### Crawler Labeling
- ASN + UA crawler labeling rule present before AMR/Challenge → good
- No crawler labeling rule + AMR or Challenge present → Medium (crawlers will be challenged)
- Bot Control CategorySearchEngine Allow used "for SEO" → unnecessary, recommend labeling rule instead

### Two-Rule Pattern (Count+Label → Challenge)
The correct always-on Challenge implementation:
1. Count+Label rule: matches landing page URIs, adds label (e.g., `custom:landing-page`)
2. Challenge rule: matches the label, applies Challenge. Excludes `crawler:verified` label via NotStatement.

This is URI-based, not Accept-header-based. API paths and static assets are unaffected.

## Severity Guide
- Cookie-based security decision (forgeable) → Awareness
- Missing always-on Challenge (DDoS protection gap) → Medium
- Always-on Challenge without crawler exclusion → Medium
- Token immunity too short → Low
