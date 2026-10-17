# Bot Control (AWSManagedRulesBotControlRuleSet)

### Common level
- Identifies bots with what AWS calls "static request data analysis". Its rules read the User-Agent (the category rules and `SignalNonBrowserUserAgent`), the source IP (bot verification and `SignalKnownBotDataCenter`) and indicators that the browser is automated (`SignalAutomatedBrowser`)
- Bots fall into three categories based on how Common level handles them:
  1. **Verified bots** — UA claims to belong to a specific organization (e.g., Googlebot, Bingbot, Route53 Health Check) AND reverse DNS lookup confirms the source IP belongs to that organization. The matching category rule adds labels (`bot:verified` + category + name) but takes **no action**. Bot Control evaluation ends here; the request continues to subsequent Web ACL rules.
  2. **Unverified bots** — UA identifies the bot as belonging to a known category, but the bot cannot be verified via reverse DNS. This includes: bots not belonging to any specific organization (e.g., okhttp, WhatsApp), bots triggered by individual users on personal devices, bots whose business model doesn't involve visiting websites (e.g., scanners, curl), and bots from organizations where individual-triggered requests can't be reverse-DNS-verified (e.g., some Google SaaS developer tools). The matching category rule adds labels (`bot:unverified` + category + name) and applies the **default action (Block)**.
  3. **Unknown non-browser UA** — UA is neither a browser UA nor any recognized bot UA, OR it claims to be an organization bot but reverse DNS verification fails (forged UA). These requests do NOT match any category rule. If the User-Agent doesn't look like a browser, `SignalNonBrowserUserAgent` is the rule AWS documents for "user agent strings that don't seem to be from a web browser"; it adds `signal:non_browser_user_agent` and applies the **default action (Block)**. AWS says no more about which rule takes a forged one.
- How many bots it names depends on the version: 5.0 "added 400+ new bots" (changelog), Version_6.1 lists 697 `bot:name:` labels and Version_7.0, the latest static version, lists 701 (`describe-managed-rule-group`, 2026-10-17). A group with no `Version` runs AWS's default, which was still Version_1.0 on 2026-10-17 (see managed-overrides.md)
- A scope-down on the rule group means a request that doesn't match it is not evaluated, so it gets no Bot Control labels, and per-request Bot Control charges apply only to evaluated requests
- In Count mode, matches don't appear in `terminatingRuleId` or `BlockedRequests`. Look at `ruleGroupList[].nonTerminatingMatchingRules` in the logs, each rule's Count metric and the `awswaf:managed:aws:bot-control:*` label metrics

### Common level limitations
- **Mostly detects bots that identify themselves.** A client that sends a standard browser User-Agent (Chrome or Firefox) from an address that isn't a known bot data center, with no automated-browser indicator, looks like a normal browser request and passes through.
- No behavioral analysis, no browser fingerprinting, no ML-based detection
- Cannot detect: credential stuffing bots, scraping bots using real browser UAs, automated browsers that hide their indicators, automated tools that mimic human behavior
- Common level classifies from static request data; it is not a bot defense for advanced threats

### Common level common misconfigurations

**Overriding CategorySearchEngine/CategorySeo to Allow to "protect SEO":**
This is unnecessary and potentially harmful, but the actual risk is more nuanced than it appears. Category rules only match **unverified** bots in that category — bots that self-identify as search engine crawlers but cannot be verified via reverse DNS (e.g., individual-triggered Google SaaS tools, personal-device bots). Verified crawlers (e.g., real Googlebot with confirmed reverse DNS) are already handled without any action by the category rule — they pass through with `bot:verified` label regardless of the override. Forged Googlebot UAs (reverse DNS fails) do NOT match `CategorySearchEngine` at all; a non-browser UA is then for `SignalNonBrowserUserAgent` (Block). Therefore, overriding `CategorySearchEngine` to Allow only affects unverified search engine bots (which would otherwise be Blocked), allowing them to bypass all subsequent AWS WAF rules. Severity: **Low** — the blast radius is limited to unverified bots in that category; it does not enable full AWS WAF bypass for arbitrary attackers. The correct approach: keep default actions. If AntiDDoS AMR's ChallengeAllDuringEvent is a concern for crawlers, use the Count+Label crawler labeling rule to label verified crawlers, then scope-down both AntiDDoS AMR and Always-on Challenge to exclude that label (see "ASN + UA Crawler Labeling Rule" and "Search Engine Crawler Exclusion Pattern"), not Bot Control Allow overrides.

**SignalNonBrowserUserAgent and CategoryHttpLibrary: depends on who calls the site.**
Both block requests with non-browser User-Agents by default.
- If native apps, API clients, partners or monitoring reach this Web ACL, override both to **Count**. The labels stay for downstream rules, and those clients aren't blocked.
- For a site only browsers use, keep both at the default Block. Real visitors don't send HTTP library User-Agents, and verified crawlers are handled before these rules.
- The configuration can't prove which case applies. An `app.*` host exclusion, a native framework User-Agent or an API path rule shows such clients exist; their absence shows nothing. Ask the user, and if you can't, describe both cases rather than pick one.

### Common level key labels
- `bot:verified` — UA verified via reverse DNS as belonging to a specific organization. The matching category rule takes no action; Bot Control evaluation ends here and the request continues to subsequent Web ACL rules.
- `bot:unverified` — Bot identified as a known category but cannot be verified (no specific organization, personal device, or individual-triggered). The matching category rule applies default action (Block).
- `signal:non_browser_user_agent` — Either: (1) UA claims to be an organization bot but reverse DNS verification failed (forged UA), or (2) UA is neither a browser nor any recognized bot UA. These requests do NOT match any category rule; they fall through to `SignalNonBrowserUserAgent`. Default action: Block.

### Verified vs unverified bots
- For verified bots: the matching category rule adds labels only (`bot:verified` + category + name), takes no action. Bot Control evaluation ends here.
- For unverified bots: the matching category rule adds labels (`bot:unverified` + category + name) and applies default action (Block).
- For a forged or unknown UA: no category rule names it. If it doesn't look like a browser, `SignalNonBrowserUserAgent` (Block) is the documented rule for it.
- Override to Allow on a category rule only affects unverified bots in that category — verified bots already pass without action, and forged UAs never match the category rule.

### Targeted level
- Includes all Common level protections
- Adds behavioral analysis, browser fingerprinting, and ML-based detection for advanced bots
- Has a built-in scope-down that automatically skips requests with `bot:verified` label — verified bots are never challenged by Targeted rules
- Rules prefixed with `TGT_` (e.g., TGT_TokenAbsent, TGT_VolumetricIpTokenAbsent)
- Per-request pricing: $10/million requests (10x more expensive than Common level at $1/million)
- Designed for advanced bot detection (credential stuffing, inventory hoarding), NOT for volumetric DDoS

### Targeted level without the SDKs
- **Documented as needing a token**, "This inspection only applies when the web request has a token": `TGT_VolumetricSession`, `TGT_VolumetricSessionMaximum`, `TGT_SignalAutomatedBrowser`, `TGT_SignalBrowserAutomationExtension` and `TGT_SignalBrowserInconsistency`
- **Needing a token by what they inspect**: `TGT_TokenReuseIp*`, `TGT_TokenReuseCountry*` and `TGT_TokenReuseAsn*` look at "the use of a single token" across IPs, countries or ASNs. That is an inference from the description
- **Not needing a token**: the Common level rules and `TGT_ML_CoordinatedActivityLow/Medium/High`, which analyze traffic statistics, need machine learning enabled, and "can take up to 24 hours to go into effect"
- **Matching a missing token**: `TGT_TokenAbsent` (Count) matches requests not from verified bots "that don't include a valid challenge token", and `TGT_VolumetricIpTokenAbsent` (Challenge) matches a client IP with "5 or more requests from a single client in the last 5 minutes" that have none. Neither carries the token-only sentence
- Tokens come from the application integration SDKs, or from a Challenge or CAPTCHA action. Without the SDKs, only sessions that went through an interstitial carry one, and only a browser `GET` with `Accept: text/html` gets the interstitial; anything else gets the bare status, 202 for Challenge and 405 for CAPTCHA. The default immunity time is 300 seconds
- So a TARGETED Web ACL without the SDK runs the Common rules, the ML rules and the two token-absent rules. Most of its requests carry no token, so `TGT_VolumetricIpTokenAbsent` challenges any client that sends five of them in five minutes, API and native-app clients included, while the token-only rules' metrics stay near empty and say little about false positives. AWS says evaluating targeted protection without the SDKs "does not give you an accurate picture of its detection capabilities". Check for the SDK before recommending TARGETED

### Token labels
- `awswaf:managed:token:absent/accepted/rejected` — shared token labels produced by all intelligent threat mitigation rule groups: Bot Control, ATP, ACFP, **and AntiDDoS AMR**
- These are shared labels with namespace `awswaf:managed:token:*`, not specific to any single rule group
- `token:absent` means request has no AWS WAF token

### Key rules for native app considerations

**Short-term: scope-down Bot Control to exclude native app traffic**
- Apply a scope-down to the entire Bot Control managed rule group using an unforgeable label (e.g., a label applied by an earlier Count rule). This bypasses the entire rule group — both Common and Targeted levels — for native app traffic. `SignalNonBrowserUserAgent` and `TGT_TokenAbsent` are irrelevant in this scenario since the rule group is not evaluated at all.

**Medium-term: integrate AWS WAF Mobile SDK**
- The SDK generates valid AWS WAF tokens for native app requests. Remove the scope-down once SDK is integrated.
- Targeted level: works correctly. `TGT_TokenAbsent` will not fire for SDK-enabled requests.
- Common level: `SignalNonBrowserUserAgent` (default Block) will Block native app requests. Must be overridden to **Count** when the scope-down is removed.
- **Do not switch `TGT_TokenAbsent` to Block** for this traffic. Its default action is already Count, and a request without a token matches it, so before the SDK is integrated every native app request would be blocked.

**Key rules**:
- `SignalNonBrowserUserAgent` (default Block): blocks non-browser User-Agents. Override to **Count** when native apps are present and not excluded via scope-down.
- `TGT_TokenAbsent` (default Count): flags requests without an AWS WAF token. An override to Count changes nothing. Block or Challenge applies to every request that has no token, which is every first visit unless the SDK or an earlier Challenge/CAPTCHA issued one.
- `TGT_VolumetricIpTokenAbsent` (default Challenge): 5+ requests from same IP without token in 5 min



## How Agent Should Use This

When analyzing logs:
1. `bot:verified` on an IP = legitimate, do not flag as threat
2. `signal:non_browser_user_agent` without `bot:verified` = likely automation
3. High-volume IP with no bot labels at all = undetected bot (Common level insufficient)
4. `bot:unverified` + high frequency = malicious bot spoofing identity

When reviewing rules:
1. CategorySearchEngine/CategorySeo overridden to Allow → Low severity (only affects unverified)
2. SignalNonBrowserUserAgent at default Block + native app traffic → recommend Count override
3. No Bot Control at all + bot traffic detected → recommend Common level first
4. Common level present but sophisticated bots detected → recommend Targeted (only if active malicious behavior confirmed)
