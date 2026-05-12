## Challenge Action

### How it works
- Returns HTTP 202 with JavaScript interstitial page
- Client browser silently executes the script for environment detection
- On success, client gets/updates `aws-waf-token` cookie, then auto-resubmits original request
- If client already has valid unexpired token, Challenge acts like Count (no interstitial)

### What can be challenged
- Browser `GET` requests with `Accept: text/html` over HTTPS

### What cannot be challenged
- `POST` requests
- CORS preflight `OPTIONS` requests
- Any non-`GET` request
- Non-HTTPS requests
- Non-browser clients (API calls, native apps, CLI tools)
- Requests not accepting HTML (CSS, images, JSON API)
- Small iFrames that accept HTML but can't process interstitial

### Token immunity time
- Default: 300 seconds
- Configurable at Web ACL or rule level
- After successful Challenge, client is not re-challenged until token expires

### AWS WAF token properties
- The `aws-waf-token` cookie is cryptographically signed by AWS — it is **unforgeable**. Attackers cannot craft a valid token without completing the Challenge.
- A valid token serves as proof that the client previously completed a Challenge (or CAPTCHA) successfully.
- This makes AWS WAF token a reliable replacement for business cookies in security decisions. For example, always-on Challenge on landing pages + extended token immunity time (e.g., 4 hours) can replace cookie-based "new vs returning user" detection — the token proves the user has been verified, without relying on forgeable cookies.


## CAPTCHA Action

### How it works
- Returns HTTP 405 with a visible image puzzle interstitial
- User must solve the puzzle; on success, client gets/updates `aws-waf-token` cookie
- If client already has valid unexpired AWS WAF token with a valid CAPTCHA timestamp, CAPTCHA acts like Count (no puzzle shown) — same token-validation logic as Challenge

### What can complete CAPTCHA
- Same constraints as Challenge: browser `GET` requests with `Accept: text/html` over HTTPS

### What cannot complete CAPTCHA
- Same as Challenge: `POST` requests, API calls, native apps, non-`GET` requests, non-browser clients
- **For POST/API paths, CAPTCHA is effectively equivalent to Block** — the interstitial cannot be completed, so the original request is never resubmitted

### Key difference from Challenge
- Challenge: silent JS puzzle, returns HTTP 202. Checks challenge solve timestamp in token.
- CAPTCHA: visible image puzzle, returns HTTP 405. Checks CAPTCHA solve timestamp in token.
- Both are token-aware: if client has valid unexpired token (with the relevant timestamp), both act like Count (no interstitial). Each checks its own timestamp with its own immunity time.
- Both require browser JS execution; neither works for non-browser or non-GET requests

