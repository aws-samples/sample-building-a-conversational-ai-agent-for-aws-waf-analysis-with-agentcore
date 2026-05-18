# Fraud Control: ATP and ACFP

## Overview

AWS WAF Fraud Control provides two specialized managed rule groups for protecting login and registration endpoints against attacks that standard WAF rules cannot detect:
- **ATP** (`AWSManagedRulesATPRuleSet`, WCU: 50) — Account Takeover Prevention
- **ACFP** (`AWSManagedRulesACFPRuleSet`, WCU: 50) — Account Creation Fraud Prevention

Both require endpoint-specific configuration, carry steep per-request fees, and work best with the JavaScript SDK for full session-level detection.

## What They Detect That Standard WAF Rules Cannot

| Attack Type | Why Standard Rules Miss It | How ATP/ACFP Detects It |
|---|---|---|
| Credential stuffing with valid-format credentials | Request format is perfectly valid (correct POST, correct JSON structure) | ATP checks actual leaked credential pairs from dark web database |
| Distributed credential attacks (slow/rotating IPs) | Each IP stays below rate-limit threshold | ATP aggregates over 10-min/30-min windows across IPs and sessions |
| Automated account creation that passes CAPTCHA | CAPTCHA solved by solving service; request looks human | ACFP's `SignalClientHumanInteractivityAbsentLow` detects absence of genuine mouse/keyboard interaction |
| Headless browser automation | UA and TLS fingerprint look like real browser | `AutomatedBrowser` and `BrowserInconsistency` rules detect Selenium/Puppeteer via browser interrogation |
| Token reuse across IPs (botnet) | Each request individually looks normal | Detects single session token used from >5 distinct IPs |
| Bulk account creation with same phone/address | Each request individually has valid PII | `VolumetricPhoneNumberHigh` and `VolumetricAddressHigh` detect reuse patterns |

## JavaScript SDK Telemetry

The SDK (`challenge.js`) runs a silent browser challenge and stores results in encrypted cookie `aws-waf-token`. Telemetry signals collected:

- **Browser fingerprint** — computed from browser settings/inconsistencies; stable across token acquisitions
- **Mouse movements** — passively captured page interactivity patterns
- **Key presses** — keystroke dynamics on forms (timing, rhythm)
- **HTML form interactions** — which fields were interacted with, in what order
- **Browser interrogation** — automation indicators, headless browser detection, setting inconsistencies
- **Challenge/CAPTCHA timestamps** — when client last passed silent challenge

Without the SDK, many ATP/ACFP rules cannot function (they rely on token presence and telemetry data). Rules like `TGT_TokenAbsent` will fire on every request without SDK integration.

## ATP — Account Takeover Prevention

### What it inspects
- HTTP POST requests to the configured login endpoint only
- Request body: extracts username + password fields (JSON or form-encoded)
- Response (CloudFront only, async — no latency impact): tracks success/failure rates

### Key rules and labels

| Rule | Label | Default Action | What it detects |
|---|---|---|---|
| `AttributeCompromisedCredentials` | `signal:credential_compromised` | Block | Username+password pair found in stolen credentials database |
| `VolumetricIpHigh` | `aggregate:volumetric:ip:high` | Block | >20 login attempts from same IP in 10 min |
| `VolumetricSession` | `aggregate:volumetric:session` | Block | >20 login attempts from same session in 30 min |
| `AttributeUsernameTraversal` | `aggregate:attribute:username_traversal` | Block | Systematic username enumeration from same session |
| `AttributePasswordTraversal` | `aggregate:attribute:password_traversal` | Block | Same username with many different passwords |
| `AttributeLongSession` | `aggregate:attribute:long_session` | Block | Abnormally long session duration (bot behavior) |
| `VolumetricIpFailedLoginResponseHigh` | `aggregate:volumetric:ip:failed_login_response:high` | Block | >10 failed logins per IP in 10 min (requires response inspection) |
| `VolumetricSessionFailedLoginResponseHigh` | `aggregate:volumetric:session:failed_login_response:high` | Block | >10 failed logins per session in 30 min (requires response inspection) |
| `SignalMissingCredential` | `signal:missing_credential` | Block | Login request missing username or password field |

### Requirements
- Must configure `LoginPath` (e.g., `/api/login`)
- Must specify `PayloadType` (JSON or FORM_ENCODED) and field identifiers
- Response inspection: CloudFront only, requires defining success/failure status codes
- Stolen credentials DB only works with **email-format usernames**
- Not compatible with Amazon Cognito user pools

## ACFP — Account Creation Fraud Prevention

### What it inspects
- HTTP GET to registration page path (issues Challenge on every page load)
- HTTP POST to account creation path
- Request body: extracts username, password, email, phone, address fields

### Key rules and labels

| Rule | Label | Default Action | What it detects |
|---|---|---|---|
| `RiskScoreHigh` | `risk_score:high` | Block | ML-based risk score combining IP reputation + stolen credentials + behavioral signals |
| `SignalCredentialCompromised` | `signal:credential_compromised` | Block | Email+password found in stolen credentials DB |
| `SignalClientHumanInteractivityAbsentLow` | `signal:client:human_interactivity:low` | CAPTCHA | No genuine mouse/keyboard interaction detected (bot filling form) |
| `AutomatedBrowser` | `signal:automated_browser` | Block | Selenium/Puppeteer/Playwright detected via browser interrogation |
| `BrowserInconsistency` | `signal:browser_inconsistency` | CAPTCHA | Browser settings inconsistent with claimed UA |
| `VolumetricIpHigh` | `aggregate:volumetric:ip:creation:high` | CAPTCHA | >10 account creation attempts from same IP in 10 min |
| `VolumetricSessionHigh` | `aggregate:volumetric:session:creation:high` | Block | >10 creation attempts from same session in 30 min |
| `VolumetricPhoneNumberHigh` | `aggregate:volumetric:phone_number:high` | Block | Same phone number used in >5 creation attempts in 30 min |
| `VolumetricAddressHigh` | `aggregate:volumetric:address:high` | Block | Same address used in >5 creation attempts in 30 min |
| `VolumetricSessionTokenReuseIp` | `aggregate:volumetric:session:creation:token_reuse:ip` | Block | Same token used from >5 IPs |

### Requirements
- Must configure `RegistrationPagePath` (GET, text/html) and `CreationPath` (POST)
- Users must load the registration page BEFORE submitting account creation (ACFP validates this flow)
- `AllRequests` rule issues Challenge on every registration page load — frontend must handle challenge flow
- Response inspection: CloudFront only
- Not compatible with Amazon Cognito user pools

## Pricing

### Fee structure (per-request, on top of standard WAF charges)

| Tier | Requests/month | Price per million |
|---|---|---|
| Free | First 10,000 | $0 |
| Tier 1 | First 2M | $1,000/million |
| Tier 2 | Next 3M (2M–5M) | $700/million |
| Tier 3 | Next 10M (5M–15M) | $400/million |
| Tier 4 | Next 15M (15M–30M) | $200/million |
| Tier 5 | Over 30M | $50/million |

Plus $10/month subscription per WebACL per rule group.

### Real cost examples
- ATP only, 15M login requests/month: **~$8,110/month** in Fraud Control fees alone
- ACFP only, 5M registration requests/month: **~$4,110/month**
- Both, 40M combined requests/month: **~$11,620/month**

### Critical cost implication
The per-request fee applies to ALL requests evaluated by the rule group — not just blocked ones. A misconfigured scope-down that lets all traffic hit ATP/ACFP will generate massive bills.

## Cost Control (mandatory)

1. **Scope-down to exact endpoint paths** — ATP should ONLY evaluate `POST /login` (or equivalent). ACFP should ONLY evaluate `GET /register` + `POST /api/accounts`. All other requests must be excluded.
2. **Place cheaper rules first** — IP reputation, rate-based, Bot Control (Common) should block obvious bots BEFORE they reach ATP/ACFP. Blocked requests don't reach paid rule groups.
3. **Recommended evaluation order**: IP Reputation → Rate-based → Bot Control Common → Bot Control Targeted → ATP → ACFP
4. **Monitor CountedRequests metric** — Track how many requests actually hit the rule group. Alert if unexpected traffic patterns emerge.

## When to Recommend ATP/ACFP

### Recommend ATP when:
- User reports credential stuffing attacks (many failed logins from distributed IPs)
- User's login endpoint receives >1000 login attempts/day from non-human sources
- User has already deployed Bot Control but still sees automated login attempts (bots using real browser fingerprints)

### Recommend ACFP when:
- User reports mass fake account creation
- User sees same phone/email/address reused across many accounts
- User's registration flow is being automated despite CAPTCHA (CAPTCHA-solving services)

### Do NOT recommend when:
- User's concern is general web scraping (use Bot Control Targeted instead)
- User's concern is DDoS (use Anti-DDoS AMR instead)
- User cannot afford the per-request cost (suggest application-layer alternatives: fail2ban, custom rate limiting on login endpoint, account lockout policies)
- User uses Cognito (not compatible)

## Limitations

- **Extremely expensive at low-to-moderate volumes** — $1/request for first 2M makes it impractical for many organizations, especially in price-sensitive markets
- Response inspection (failed login tracking) only works on CloudFront — ALB/API Gateway users lose this capability
- Stolen credentials DB only matches email-format usernames — phone number or custom username formats not supported
- JavaScript SDK requires HTTPS and browser environment — native apps need custom integration
- ACFP's `AllRequests` Challenge on registration page can break SPAs that don't handle challenge flow
- No protection against attacks using completely unique, never-leaked credentials (novel passwords)
- Cannot detect "low and slow" attacks that stay below all volumetric thresholds AND use unique credentials each time
