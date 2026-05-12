# Cross-Rule Dependency Analysis Guide (for LLM Section 17)

## Your Task
For each fix recommended in the report (both scripted and your own), trace the affected traffic through the full rule chain. Identify if fixing one issue breaks another rule or removes a label that downstream rules depend on.

## Judgment Rules

### Label Dependency Tracing
- For each label mentioned in any finding, verify the producer rule exists at a LOWER priority number (higher priority) than the consumer rule
- If a fix removes a rule that produces labels → check all downstream rules that consume those labels
- If a fix changes an Allow rule to Block/Count → traffic that was previously allowed now enters subsequent rules (may trigger unexpected blocks)

### Token Labels Are Shared
- `awswaf:managed:token:absent/accepted/rejected` are produced by Bot Control, ATP, ACFP, AND AntiDDoS AMR
- Removing any ONE of these rule groups does NOT remove token labels (other groups still produce them)
- Only if ALL intelligent threat mitigation groups are removed do token labels disappear

### Count Rules Without Labels (17a — already scripted, skip)
This is handled by scripted findings. Do NOT duplicate.

### Fix Impact Patterns

| Fix Type | Potential Impact |
|----------|-----------------|
| Remove Allow rule | Traffic enters subsequent rules → may get blocked by rules it previously skipped |
| Change Allow → Count | Same as above, plus the rule now adds labels (if configured) |
| Add scope-down to rule | Traffic outside scope-down is no longer inspected by that rule |
| Remove scope-down | Rule now inspects ALL traffic (may cause FP on previously excluded paths) |
| Override Block → Count | Request continues to next rule in group, then subsequent rules |
| Add new Block rule | May block traffic that was previously allowed through |

### Recommended Fix Order
- If fix A depends on fix B being applied first → document the dependency
- If two fixes must be applied simultaneously (one without the other causes issues) → state explicitly
- Group related fixes and recommend applying them together in a single change window

## Output Format
For each cross-rule dependency found:
- State which fixes interact
- Explain the dependency (which label/traffic flow is affected)
- Recommend order or simultaneous application

## Severity Guide
- Fix that breaks another rule's label dependency → Medium
- Fix that causes unexpected blocks on legitimate traffic → Medium
- Fix order dependency (must apply together) → Awareness
- No cross-rule dependencies found → state "No cross-rule dependencies identified"
