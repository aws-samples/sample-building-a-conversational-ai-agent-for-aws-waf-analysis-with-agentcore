# Bot Control Labels (through Version_7.0)

Checked against `describe-managed-rule-group` for every Bot Control version on 2026-10-17. Its
`AvailableLabels` lists what each version can add, so read it there for the version a WebACL pins.
The default version is still Version_1.0, which has no `cloud_service_provider` labels at all; they
start in Version_2.0.

## Label Namespace Structure

Bot Control labels follow a hierarchical namespace. Understanding the structure lets you interpret any label without memorizing them all.

```
awswaf:managed:aws:bot-control:{category}
  bot:category:{type}          — what kind of bot
  bot:name:{specific_bot}      — which specific bot
  bot:organization:{org}       — who operates the bot
  bot:verified                 — reverse-DNS verified
  bot:unverified               — claims identity but unverified
  bot:user_triggered:verified  — verified but triggered by individual user
  bot:vendor:agentcore         — vendor-specific
  bot:intent:{purpose}         — bot's declared purpose
  bot:developer_platform:verified — verified developer platform bot
  bot:web_bot_auth:{status}    — web bot authentication result
  signal:{signal_type}         — behavioral signals (Common level)
  targeted:signal:{type}       — behavioral signals (Targeted level)
  targeted:aggregate:{type}    — aggregate behavioral patterns (Targeted level)
```

Token and CAPTCHA labels (shared across Bot Control, ATP, ACFP, Anti-DDoS AMR):
```
awswaf:managed:token:{status}          — challenge token state
awswaf:managed:captcha:{status}        — CAPTCHA token state
```

## Verification Status Labels

| Label | Meaning | Agent Action |
|---|---|---|
| `bot:verified` | Bot identity confirmed via reverse DNS | Legitimate — do not block |
| `bot:unverified` | Claims to be a known bot but cannot verify | Suspicious — default Block in Bot Control |
| `bot:user_triggered:verified` | Verified org but individual-triggered (e.g., Google SaaS tool on personal device) | Usually legitimate but not crawling |
| `bot:web_bot_auth:verified` | Passed web bot authentication | Legitimate |
| `bot:web_bot_auth:failed` | Failed web bot authentication | Likely spoofing identity |
| `bot:web_bot_auth:expired` | Auth token expired | May need re-verification |
| `bot:web_bot_auth:unknown_bot` | Bot not in known list | Unknown — evaluate by behavior |

## Category Labels

| Label | Meaning | Typical Action |
|---|---|---|
| `bot:category:search_engine` | Search engine crawlers (Google, Bing, Baidu) | Allow if verified |
| `bot:category:seo` | SEO tools (Ahrefs, SEMrush, Moz) | Usually Allow |
| `bot:category:social_media` | Social media previews (Facebook, Twitter, LinkedIn) | Allow |
| `bot:category:advertising` | Ad verification bots | Allow |
| `bot:category:monitoring` | Uptime/performance monitors | Allow if expected |
| `bot:category:ai` | AI crawlers (GPTBot, ClaudeBot, Anthropic) | Policy decision — block or allow |
| `bot:category:scraping_framework` | Known scraping tools (Scrapy, crawler4j) | Usually Block |
| `bot:category:http_library` | Generic HTTP clients (curl, python-requests, okhttp) | Evaluate — may be legitimate API client |
| `bot:category:security` | Security scanners (Qualys, Detectify) | Allow if authorized |
| `bot:category:content_fetcher` | Content aggregators | Evaluate by volume |
| `bot:category:archiver` | Web archivers (Internet Archive) | Usually Allow |
| `bot:category:miscellaneous` | Doesn't fit other categories | Evaluate individually |
| `bot:category:page_preview` | Link preview generators (Slack, Discord) | Allow |
| `bot:category:link_checker` | Broken link checkers | Allow |
| `bot:category:email_client` | Email preview fetchers | Allow |
| `bot:category:webhooks` | Webhook delivery (Stripe, PayPal) | Allow — blocking breaks integrations |

## Intent Labels

| Label | Meaning |
|---|---|
| `bot:intent:search` | Indexing for search results |
| `bot:intent:train_ai` | Training AI models on web content |
| `bot:intent:ai_assistant` | Fetching content for AI assistant responses |
| `bot:intent:content_optimization` | SEO/content optimization |

## Signal Labels (Common Level)

These are behavioral signals — they don't identify specific bots but flag suspicious characteristics. Available at Common level (no extra cost beyond Bot Control Common).

| Label | Meaning | Investigation Value |
|---|---|---|
| `signal:non_browser_user_agent` | UA string is not a known browser | High — automation indicator |
| `signal:non_browser_header` | HTTP headers inconsistent with browsers | High — automation indicator |
| `signal:automated_browser` | Detected browser automation (headless, Selenium) | High — sophisticated bot |
| `signal:known_bot_data_center` | IP belongs to known bot hosting infrastructure | High — equivalent to HostingProviderIPList but more precise |
| `signal:cloud_service_provider:<provider>` | The IP belongs to that cloud provider | Depends on the provider, see below |

Version_7.0's `AvailableLabels` lists nine providers: akamai, alibaba, aws, azure, cloudflare,
digital_ocean, gcp, ibm and oracle. The 7.0 changelog adds fastly, which that list does not show
yet, and later versions can add more, so read the provider off the label rather than from a list.
What it means depends on what the provider sells. A host of rented instances is where automation
often runs, and partners, SaaS tools and office egresses run there too, so the label is a reason
to ask rather than a verdict. A CDN or proxy service in front of the site makes the IP its egress
for many clients, and nothing about that IP describes one client.

## Targeted Rule Name Prefixes

| Prefix | Meaning | Detection Method | Token Required? |
|---|---|---|---|
| `TGT_` | Targeted protection rules | Browser interrogation, fingerprinting, behavior heuristics | Mostly. Five rules "only apply when the web request has a token" and the `TGT_TokenReuse*` rules inspect a token's use, but `TGT_TokenAbsent` and `TGT_VolumetricIpTokenAbsent` match its absence |
| `TGT_ML_` | Targeted ML rules | Machine learning on traffic statistics (timestamps, browser characteristics, previous URL). Enabled by default, can be disabled in rule group config. When disabled, these rules are not evaluated. | **No** — does not require AWS WAF token or Challenge/CAPTCHA as prerequisite. Works on raw traffic patterns without client-side instrumentation. |

## Targeted Signal Labels (Targeted Level Only)

Require Bot Control Targeted level (additional per-request cost). These detect sophisticated bots that pass Common-level checks.

| Label | Meaning | Investigation Value |
|---|---|---|
| `targeted:signal:automated_browser` | Advanced browser automation detection (beyond Common) | Very High — confirms sophisticated bot |
| `targeted:signal:browser_inconsistency` | Browser fingerprint doesn't match claimed identity | Very High — spoofing attempt |
| `targeted:signal:browser_automation_extension` | Browser automation extension detected | Very High — Selenium/Puppeteer |

## Targeted Aggregate Labels (Targeted Level Only)

Behavioral patterns detected across multiple requests from the same session/token.

| Label Pattern | Meaning |
|---|---|
| `targeted:aggregate:coordinated_activity:{low/medium/high}` | Multiple clients exhibiting coordinated behavior (bot farm) |
| `targeted:aggregate:volumetric:ip:token_absent` | High volume from IP without AWS WAF token |
| `targeted:aggregate:volumetric:session:{low/medium/high}` | Abnormal request volume per session |
| `targeted:aggregate:volumetric:session:maximum` | Session exceeded maximum volume threshold |
| `targeted:aggregate:volumetric:session:token_reuse:ip:{low/medium/high}` | Same token used from multiple IPs |
| `targeted:aggregate:volumetric:session:token_reuse:asn:{low/medium/high}` | Same token used across multiple ASNs |
| `targeted:aggregate:volumetric:session:token_reuse:country:{low/medium/high}` | Same token used from multiple countries |

## Token Provenance Labels (Targeted Level, Version_7.0 and Later)

`token_provenance:ip_category_mismatch:<level>` flags a change in the category of IP address between
the request that acquired the AWS WAF token and the request that presents it, such as a token
acquired from a data center and presented from a residential address.

| Level | Meaning |
|---|---|
| `high` | A change legitimate clients rarely make, such as a token acquired from a data center, proxy or VPN address and presented from a residential or mobile one |
| `medium`, `low` | Changes with common legitimate causes, such as a residential client turning on a VPN |

Added only for requests that present a token, and never for `bot:verified` requests. No rule in the
group acts on them: blocking or challenging needs a label match rule placed after Bot Control.

## Device ID Label (Targeted Level)

`device_id:<device_id>` carries the device ID the AWS WAF Android SDK collected when it acquired the
token. Only tokens from Android SDK 2.1.0 or later carry one, and that SDK version is not released
yet, so the label does not appear today. Reserved values: `device_id:Unavailable` (the SDK could not
collect an ID) and `device_id:invalid` (the ID was malformed and replaced). The value identifies a
device, so treat it like any other identifier taken from a log.

## Token and CAPTCHA Status Labels

Shared across Bot Control, ATP, ACFP, and Anti-DDoS AMR.

| Label | Meaning |
|---|---|
| `awswaf:managed:token:accepted` | Valid, unexpired challenge token present |
| `awswaf:managed:token:absent` | No challenge token in request |
| `awswaf:managed:token:rejected` | Token present but invalid |
| `awswaf:managed:token:rejected:expired` | Token expired |
| `awswaf:managed:token:rejected:domain_mismatch` | Token issued for different domain |
| `awswaf:managed:token:rejected:not_solved` | Challenge not completed |
| `awswaf:managed:token:rejected:invalid` | Token cryptographically invalid |
| `awswaf:managed:captcha:accepted` | Valid CAPTCHA solution |
| `awswaf:managed:captcha:absent` | No CAPTCHA token |
| `awswaf:managed:captcha:rejected` | CAPTCHA failed |
| `awswaf:managed:captcha:rejected:expired` | CAPTCHA solution expired |
| `awswaf:managed:captcha:rejected:domain_mismatch` | CAPTCHA for wrong domain |
| `awswaf:managed:captcha:rejected:not_solved` | CAPTCHA not solved |
| `awswaf:managed:captcha:rejected:invalid` | CAPTCHA cryptographically invalid |

## How WAF Analyst Should Use These Labels

When analyzing logs:
1. `bot:verified` + `bot:category:search_engine` = legitimate crawler, not a threat
2. `bot:unverified` + `signal:known_bot_data_center` = likely malicious, spoofing bot identity
3. `signal:cloud_service_provider:*` without `bot:verified` = traffic from a cloud provider's addresses: worth asking about when the provider hosts rented instances, and an egress for many clients when it is a CDN or proxy
4. `targeted:aggregate:coordinated_activity:high` = coordinated bot activity, CAPTCHA by default from Version_3.0 and Count before it. Recommend Block only on the evidence in advanced-bot-detection.md
5. `token:absent` on high-volume IP = likely bot that cannot execute JavaScript
6. `token_reuse:ip:high` = token sharing/theft, recommend TGT_TokenReuseIp to Block
7. `token_provenance:ip_category_mismatch:high` = a token carried from a data center, proxy or VPN to a residential address, which is what a token acquired by one client and handed to another looks like
8. No bot labels on high-frequency IP = undetected bot (Common level insufficient, recommend Targeted)
9. Token-id cross-IP check: a single issued token (`awswaf:managed:token:id:<id>`) normally maps to 1–2 client IPs. If one token-id appears across **>5 distinct IPs**, that token is being reused/shared across a botnet — a strong fraud/abuse signal, stronger than UA or even JA4 (the token is cryptographically issued by WAF). Investigate those IPs together.

When reviewing rules:
1. If Bot Control is Common level and `signal:known_bot_data_center` traffic is high → recommend Targeted
2. If `CategoryHttpLibrary` is overridden to Block → warn about native app false positives (okhttp, java)
3. If `CategorySearchEngine` is overridden to Allow → low risk (only affects unverified, see bot-control.md)
4. If no rule consumes `token:absent` label → missed protection opportunity

## Notable Bot Names (Representative Examples)

AI crawlers: `gptbot`, `chatgpt`, `chatgpt_user`, `claudebot`, `claude_web`, `claude_user`, `anthropic`, `perplexitybot`, `perplexity-user`, `bytespider`, `ccbot`, `cohere`, `mistralai_user`, `google_cloud_vertex_bot`, `bedrockbot`, `gemini_deep_research`, `nova_act`, `devin`

Search engines: `googlebot`, `bingbot`, `baidu`, `yandexbot`, `duckduckbot`, `naver`, `seznam`

Social/preview: `facebook`, `facebot`, `twitter`, `linkedin`, `slack_images`, `slackbot`, `discordbot`, `telegram`, `whatsapp`, `pinterest`

Monitoring: `pingdom`, `uptimerobot`, `datadog_synthetic_monitor`, `newrelic_synthetic_monitor`, `site24x7`, `catchpoint`

Security: `qualys`, `detectify`, `acunetix`, `censys`, `netcraft`, `sucuri`

Scraping: `scrapy`, `curl`, `wget`, `python_requests`, `go_http`, `fasthttp`, `okhttp`
