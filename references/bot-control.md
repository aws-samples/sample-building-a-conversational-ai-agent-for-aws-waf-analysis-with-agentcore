# Bot Control Analysis Guide (for LLM Section 5)

## Your Task
Evaluate the overall Bot Control strategy and assess native app implications if a forgeable UA-based Allow rule was found.

## Judgment Rules

### Bot Control Level Assessment
- Common level only → Awareness finding (not a misconfiguration, but limited protection)
- Common level + active sophisticated bot traffic in logs → recommend Targeted
- Targeted level present → no finding needed unless misconfigured

### Native App Impact (only if UA-based Allow rule exists)
If a forgeable Allow rule was removed (fix from scripted findings), native app traffic will enter Bot Control:
- SignalNonBrowserUserAgent (default Block) will block native apps
- Short-term fix: scope-down entire Bot Control rule group with unforgeable label
- Medium-term fix: integrate AWS WAF Mobile SDK
- NEVER recommend overriding TGT_TokenAbsent to Count (breaks all Targeted detection)

### CategorySearchEngine/CategorySeo Allow Override
Already handled by scripted findings. Do NOT duplicate. Severity: Low.

### SignalNonBrowserUserAgent + CategoryHttpLibrary
- If at default Block AND native app traffic exists → recommend Count override
- If already Count → no finding

### Common Override Recommendations
- SignalNonBrowserUserAgent → Count (preserves label, avoids native app FP)
- CategoryHttpLibrary → Count (same reason)
- TGT_TokenAbsent → NEVER override to Count
- TGT_VolumetricIpTokenAbsent → Challenge is correct default

## Severity Guide
- Missing Targeted when sophisticated bots confirmed → Medium
- Native app will be blocked after Allow rule fix → Awareness (inform user of impact)
- Common level only, no evidence of advanced bots → Awareness
- TGT_TokenAbsent overridden to Count → Critical
