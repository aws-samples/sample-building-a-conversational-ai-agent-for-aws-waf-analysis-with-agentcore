# Bot Control (AWSManagedRulesBotControlRuleSet)

### Common level
- Identifies self-declared bots by analyzing the User-Agent header
- Bots fall into three categories based on how Common level handles them:
  1. **Verified bots** — UA claims to belong to a specific organization (e.g., Googlebot, Bingbot, Route53 Health Check) AND reverse DNS lookup confirms the source IP belongs to that organization. The matching category rule adds labels (`bot:verified` + category + name) but takes **no action**. Bot Control evaluation ends here; the request continues to subsequent Web ACL rules.
  2. **Unverified bots** — UA identifies the bot as belonging to a known category, but the bot cannot be verified via reverse DNS. This includes: bots not belonging to any specific organization (e.g., okhttp, WhatsApp), bots triggered by individual users on personal devices, bots whose business model doesn't involve visiting websites (e.g., scanners, curl), and bots from organizations where individual-triggered requests can't be reverse-DNS-verified (e.g., some Google SaaS developer tools). The matching category rule adds labels (`bot:unverified` + category + name) and applies the **default action (Block)**.
  3. **Unknown non-browser UA** — UA is neither a browser UA nor any recognized bot UA, OR it claims to be an organization bot but reverse DNS verification fails (forged UA). These requests do NOT match any category rule. They fall through to `SignalNonBrowserUserAgent`, which adds `signal:non_browser_user_agent` and applies the **default action (Block)**.
- Can identify close to 700 bot types based on UA and IP (version 5.0+)

### Common level limitations
- **Only detects bots that self-identify via User-Agent.** If a bot uses a standard browser User-Agent (e.g., Chrome or Firefox UA), Common level will not detect it at all — the request passes through Bot Control as if it were a normal browser request.
- No behavioral analysis, no browser fingerprinting, no ML-based detection
- Cannot detect: credential stuffing bots, scraping bots using real browser UAs, headless browsers, automated tools that mimic human behavior
- Common level is a UA-based classifier, not a bot defense solution for advanced threats

### Common level common misconfigurations

**Overriding CategorySearchEngine/CategorySeo to Allow to "protect SEO":**
This is unnecessary and potentially harmful, but the actual risk is more nuanced than it appears. Category rules only match **unverified** bots in that category — bots that self-identify as search engine crawlers but cannot be verified via reverse DNS (e.g., individual-triggered Google SaaS tools, personal-device bots). Verified crawlers (e.g., real Googlebot with confirmed reverse DNS) are already handled without any action by the category rule — they pass through with `bot:verified` label regardless of the override. Forged Googlebot UAs (reverse DNS fails) do NOT match `CategorySearchEngine` at all — they fall through to `SignalNonBrowserUserAgent` and are Blocked. Therefore, overriding `CategorySearchEngine` to Allow only affects unverified search engine bots (which would otherwise be Blocked), allowing them to bypass all subsequent AWS WAF rules. Severity: **Low** — the blast radius is limited to unverified bots in that category; it does not enable full AWS WAF bypass for arbitrary attackers. The correct approach: keep default actions. If AntiDDoS AMR's ChallengeAllDuringEvent is a concern for crawlers, use the Count+Label crawler labeling rule to label verified crawlers, then scope-down both AntiDDoS AMR and Always-on Challenge to exclude that label (see "ASN + UA Crawler Labeling Rule" and "Search Engine Crawler Exclusion Pattern"), not Bot Control Allow overrides.

**Keeping SignalNonBrowserUserAgent and CategoryHttpLibrary at default Block:**
These two rules block requests with non-browser User-Agents. Default Block frequently causes false positives on legitimate non-browser clients (native apps, API clients, monitoring tools, legitimate HTTP libraries). Best practice is to override both to **Count**. This preserves the labeling (for downstream rules to use) while avoiding false positives.

### Common level key labels
- `bot:verified` — UA verified via reverse DNS as belonging to a specific organization. The matching category rule takes no action; Bot Control evaluation ends here and the request continues to subsequent Web ACL rules.
- `bot:unverified` — Bot identified as a known category but cannot be verified (no specific organization, personal device, or individual-triggered). The matching category rule applies default action (Block).
- `signal:non_browser_user_agent` — Either: (1) UA claims to be an organization bot but reverse DNS verification failed (forged UA), or (2) UA is neither a browser nor any recognized bot UA. These requests do NOT match any category rule; they fall through to `SignalNonBrowserUserAgent`. Default action: Block.

### Verified vs unverified bots
- For verified bots: the matching category rule adds labels only (`bot:verified` + category + name), takes no action. Bot Control evaluation ends here.
- For unverified bots: the matching category rule adds labels (`bot:unverified` + category + name) and applies default action (Block).
- For forged/unknown UA: no category rule matches; falls through to `SignalNonBrowserUserAgent` (Block).
- Override to Allow on a category rule only affects unverified bots in that category — verified bots already pass without action, and forged UAs never match the category rule.

### Targeted level
- Includes all Common level protections
- Adds behavioral analysis, browser fingerprinting, and ML-based detection for advanced bots
- Has a built-in scope-down that automatically skips requests with `bot:verified` label — verified bots are never challenged by Targeted rules
- Rules prefixed with `TGT_` (e.g., TGT_TokenAbsent, TGT_VolumetricIpTokenAbsent)
- Per-request pricing: $10/million requests (10x more expensive than Common level at $1/million)
- Designed for advanced bot detection (credential stuffing, inventory hoarding), NOT for volumetric DDoS

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
- **NEVER override `TGT_TokenAbsent` to Count** — it is the foundation of all Targeted Bot Control detection. Overriding it disables the entire session-tracking mechanism for token-absent requests.

**Key rules**:
- `SignalNonBrowserUserAgent` (default Block): blocks non-browser User-Agents. Override to **Count** when native apps are present and not excluded via scope-down.
- `TGT_TokenAbsent` (default Count, often overridden to Challenge): flags requests without AWS WAF token. **Do not override to Count.**
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
