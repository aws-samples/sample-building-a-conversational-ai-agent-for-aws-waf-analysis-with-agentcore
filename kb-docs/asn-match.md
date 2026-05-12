# ASN Match Statement

## What It Is

ASN (Autonomous System Number) match is a rule statement type that inspects traffic based on the network organization (ISP, enterprise, cloud provider) that owns the IP address. ASNs are more stable than IP ranges — they change less frequently.

## Key Facts

- WCU cost: 1 (extremely cheap)
- Nestable: yes (can be used in AND/OR/NOT, scope-down statements)
- Max ASNs per rule: 100
- ASN 0 = unmapped IP (AWS WAF couldn't determine ASN)
- Supports forwarded IP configuration (X-Forwarded-For)
- Fallback behavior for invalid IPs: Match or No Match (configurable)

## Why It Matters for AWS WAF Configuration

### As a Scope-Down Statement (Primary Use Case)

ASN match is unforgeable — attackers cannot spoof their ASN. This makes it ideal for scope-down statements:

- Scope-down Bot Control to exclude known partner ASNs (reduces per-request cost)
- Scope-down rate-based rules to only apply to hosting provider ASNs
- Scope-down Anti-DDoS AMR to exclude internal traffic from specific networks

### Comparison with Other Unforgeable Conditions

| Condition | Forgeable? | Granularity | Use Case |
|---|---|---|---|
| IP Set | No | Individual IPs/CIDRs | Known good/bad IPs |
| ASN Match | No | Entire network org | Partner networks, hosting providers |
| Geo Match | No | Country level | Geographic blocking |
| JA3/JA4 | No | TLS fingerprint | Bot detection |
| AWS WAF Token | No | Per-client token | Verified browsers |

### ASN Match vs IP Set for Allow Rules

When creating Allow rules (which bypass all subsequent rules):
- IP Set Allow: safe if IPs are controlled (e.g., office IPs)
- ASN Allow: DANGEROUS — an entire ASN may contain millions of IPs including attacker infrastructure
- Never use ASN match alone as the condition for an Allow rule without additional conditions

### Recommended Patterns

1. **Hosting provider detection**: ASN match on known hosting/cloud ASNs → Count + Label → downstream rules use label for enhanced scrutiny
2. **Partner traffic bypass**: ASN match + additional condition (e.g., specific header) → Allow (ASN alone is not sufficient)
3. **Rate limiting scope**: Scope-down rate-based rule to specific ASNs (e.g., only rate-limit requests from residential ISP ASNs, not CDN ASNs)

## JSON Example

```json
{
  "Name": "detect-hosting-providers",
  "Priority": 50,
  "Statement": {
    "AsnMatchStatement": {
      "AsnList": [16509, 14618, 8075, 15169],
      "ForwardedIPConfig": {
        "HeaderName": "X-Forwarded-For",
        "FallbackBehavior": "NO_MATCH"
      }
    }
  },
  "Action": {
    "Count": {}
  },
  "RuleLabels": [{"Name": "hosting-provider"}]
}
```

Common hosting/cloud ASNs:
- 16509, 14618: Amazon (AWS)
- 8075: Microsoft (Azure)
- 15169: Google (GCP)
- 13335: Cloudflare
- 20940: Akamai
- 63949: Linode
- 14061: DigitalOcean
- 24940: Hetzner

## Impact on Review Findings

When reviewing AWS WAF rules:
1. If an Allow rule uses only forgeable conditions (UA, header, cookie), recommend adding ASN match as an additional unforgeable condition
2. If scope-down uses URI path only, suggest adding ASN match to narrow the scope further
3. ASN-based Count+Label rules placed early in priority order provide useful signals for downstream rules
4. Check if rate-based rules could benefit from ASN-based scope-down (e.g., only rate-limit residential traffic)
