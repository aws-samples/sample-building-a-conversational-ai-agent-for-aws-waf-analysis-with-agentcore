# Advanced Bot Detection and Targeted Bot Control Escalation

## When to Recommend Upgrading to Targeted Bot Control

Bot Control Common level detects bots that self-identify via User-Agent. It cannot detect:
- Automated tools using standard browser User-Agents
- Headless browsers with engine-level stealth modifications
- Coordinated bot farms using real browser instances with human-like behavior

Bot Control Targeted adds ML-based behavioral analysis and browser interrogation. Recommend upgrading when:
1. Common level is deployed AND
2. Evidence of sophisticated automation exists (see "Evidence Framework" below)

Do NOT recommend Targeted solely because `signal:known_bot_data_center` traffic exists — data center traffic may be legitimate (CDN, enterprise proxies, SaaS tools).

## TGT_ML_ CoordinatedActivity: When to Recommend Block

Default actions:
- `TGT_ML_CoordinatedActivityLow` → Count
- `TGT_ML_CoordinatedActivityMedium` → CAPTCHA
- `TGT_ML_CoordinatedActivityHigh` → CAPTCHA

Recommending Block on High requires sufficient evidence that CAPTCHA is ineffective (being solved by automation).

### Evidence Framework for Block Recommendation

**Step 1: Confirm the traffic is automated**

Check IPs marked with `coordinated_activity:high`:
- Are they from data center/cloud ASNs? (`signal:known_bot_data_center` or `signal:cloud_service_provider:*`)
- Is request frequency superhuman? (>200 unique URIs/hour or >200 req/min from single IP)
- Are URIs concentrated on high-value pages? (login, checkout, search, pricing)
- Is the time distribution unnatural? (24/7 uniform, no diurnal pattern)

If ≥3 of these are true → traffic is automated.

**Step 2: Assess CAPTCHA effectiveness (critical step)**

Compare behavior before and after CAPTCHA is applied:
- If request volume from marked IPs drops significantly after CAPTCHA → CAPTCHA is working, keep CAPTCHA (no need for Block)
- If request volume remains unchanged → CAPTCHA is being solved by automation, Block is justified

Token-based validation:
- Query logs for IPs marked `coordinated_activity:high`: do they subsequently appear with `token:accepted`?
- If yes (high rate of token:accepted after CAPTCHA) → automation is solving CAPTCHA → Block justified
- If no (IPs never get token:accepted, just disappear) → CAPTCHA is working as deterrent → keep CAPTCHA

**Step 3: Assess false positive risk**

Before recommending Block:
- Check if any `coordinated_activity:high` IPs also carry `bot:verified` → if yes, DO NOT recommend Block (ML may be misclassifying verified bots)
- Check if IPs are residential (no `signal:known_bot_data_center`, no `signal:cloud_service_provider:*`) → higher FP risk, recommend Count+monitor first
- Check the volume: if only 5-10 IPs are marked high → low confidence, wait for more data

**Step 4: Recommend with conditions**

If evidence supports Block:
- Recommend Block on `TGT_ML_CoordinatedActivityHigh` only
- Keep Medium at CAPTCHA (lower confidence, higher FP risk)
- Keep Low at Count (monitoring only)
- Always recommend monitoring for 24-48 hours after change
- Always ask user: "Do you have a rollback plan if legitimate users are affected?"

## Why Common Level Misses Advanced Bots

Modern automation tools modify browser behavior at the engine level (not via JavaScript injection). This means:
- `navigator.webdriver` detection is ineffective (the flag is removed at source level)
- Canvas/WebGL/Audio fingerprinting returns consistent, realistic values
- CDP (Chrome DevTools Protocol) automation signals are suppressed

Bot Control Targeted counters this through:
- `targeted:signal:browser_inconsistency` — detects subtle inconsistencies that engine-level patches miss
- `targeted:signal:browser_automation_extension` — detects automation extensions
- `TGT_ML_CoordinatedActivity` — detects coordinated patterns across multiple sessions (does NOT require WAF token)

The ML-based detection (`TGT_ML_`) is the strongest defense against sophisticated automation because it analyzes aggregate traffic patterns (timestamps, navigation sequences, browser characteristics) rather than individual request properties that can be spoofed.

## IP Reputation as Last Defense Layer

Even with perfect browser stealth, attackers need IP addresses. Detection hierarchy:
1. Data center IPs → detected by `signal:known_bot_data_center` (Common level)
2. Residential proxy IPs → harder to detect, but coordinated behavior from many residential IPs triggers `TGT_ML_CoordinatedActivity`
3. Single residential IP with human-like behavior → nearly undetectable by WAF alone (requires application-layer signals)

When Agent finds high-volume traffic with no bot labels and no ML signals → recommend application-layer defenses (rate limiting per account, business logic validation) rather than WAF-only solutions.

## How Agent Should Use This

When analyzing bypass incidents:
1. Check if Bot Control is Common or Targeted level
2. If Common → check for `signal:known_bot_data_center` or `signal:non_browser_user_agent` on suspicious IPs. If absent → bot is using browser UA from non-data-center IP → Common cannot detect, recommend Targeted
3. If Targeted → check for `coordinated_activity` labels. If present but traffic continues → CAPTCHA being solved → recommend Block escalation (with evidence framework above)
4. If Targeted with no ML labels on suspicious traffic → truly sophisticated single-IP bot → recommend application-layer defenses

When reviewing rules:
1. `TGT_ML_CoordinatedActivityHigh` at default CAPTCHA → not a misconfiguration (default is correct)
2. `TGT_ML_CoordinatedActivityHigh` overridden to Count → Awareness finding (reduces protection)
3. `TGT_ML_CoordinatedActivityHigh` overridden to Block → verify user has monitoring in place
