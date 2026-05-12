# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""Generate fixed appendix content for WAF review reports.

All appendix sections are always written. The LLM decides which to reference.
Only dynamic value: WCU capacity from waf-summary.json.
"""

import json
import os
import sys
from pathlib import Path
from waf_utils import fatal

APPENDIX_SECTIONS = r"""
---

# 附录 / Appendix

## Appendix A: ASN + UA Crawler Labeling Rule

Place this rule **before** AntiDDoS AMR and Always-on Challenge. It labels verified search engine crawlers so downstream rules can exclude them via scope-down.

```json
{{
  "Name": "label-verified-crawlers",
  "Priority": "<place before AntiDDoS AMR>",
  "Action": {{
    "Count": {{}}
  }},
  "RuleLabels": [
    {{ "Name": "crawler:verified" }}
  ],
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "label-verified-crawlers"
  }},
  "Statement": {{
    "OrStatement": {{
      "Statements": [
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "googlebot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [15169] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "bingbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [8075] }} }}
            ]
          }}
        }},
        {{
          "AndStatement": {{
            "Statements": [
              {{
                "ByteMatchStatement": {{
                  "SearchString": "yandexbot",
                  "FieldToMatch": {{ "SingleHeader": {{ "Name": "user-agent" }} }},
                  "TextTransformations": [{{ "Priority": 0, "Type": "LOWERCASE" }}],
                  "PositionalConstraint": "CONTAINS"
                }}
              }},
              {{ "AsnMatchStatement": {{ "AsnList": [13238, 208722] }} }}
            ]
          }}
        }}
      ]
    }}
  }}
}}
```

Confirmed ASNs: Google 15169, Bing 8075, Yandex 13238 + 208722. For other search engines (Baidu, Yahoo Japan, etc.), verify current ASNs from their official documentation before adding.

---

## Appendix B: Dual AntiDDoS AMR Instance Pattern

When browser and native app traffic need different AntiDDoS strategies:

1. **Add a Count+Label rule before both AMR instances** to label native app traffic (e.g., label `native-app:identified`). This rule must have a higher priority (lower number) than both AMR instances.
2. **AMR instance 1 (browser traffic)**: scope-down excludes the native app label. `ChallengeAllDuringEvent` enabled. Block sensitivity: LOW (default).
3. **AMR instance 2 (native app traffic)**: scope-down matches the native app label only. `ChallengeAllDuringEvent` disabled. Block sensitivity: MEDIUM (since Challenge is unavailable, raise Block sensitivity for adequate protection).
4. **Implementation**: The AWS console does not allow adding the same managed rule group twice. First copy the existing AMR rule's JSON. Then create a new **custom rule** in the Web ACL, open its **JSON editor**, paste the copied AMR JSON, change `Name` and `MetricName` to unique values (e.g., `AntiDDoS-NativeApp`), then save.

Crawler exclusion scope-down (add to AMR scope-down via `AndStatement` if AMR already has one):

```json
{{
  "NotStatement": {{
    "Statement": {{
      "LabelMatchStatement": {{
        "Scope": "LABEL",
        "Key": "crawler:verified"
      }}
    }}
  }}
}}
```

---

## Appendix C: Always-on Challenge for Landing Pages

Two-rule pattern for proactive DDoS defense on landing page URIs:

1. **Label rule** (Count+Label): matches landing page URIs (e.g., `/`, `/login`, `/signup`) and adds label `custom:landing-page`. Action: Count (request continues).
2. **Challenge rule**: matches `custom:landing-page` label and applies Challenge action. Exclude verified crawlers by adding a `NotStatement` for `crawler:verified` label.

The user must define their own landing page URI list based on their application.

Recommended token immunity time: ≥ 4 hours (14400 seconds). Real users complete JS verification once and browse uninterrupted for the entire immunity period.

---

## Appendix D: Recommended Rule Priority Order

| Position | Rule Type | Rationale |
|----------|-----------|-----------|
| 1 | IP whitelist (Allow) | Trusted IPs bypass all rules |
| 2 | IP blacklist (Block) | Known malicious IPs blocked immediately |
| 3 | Count+Label rules | Tag traffic types for downstream scope-down |
| 4 | AntiDDoS AMR | Needs full traffic for accurate baseline |
| 5 | IP reputation rule group | Low WCU, filters known malicious IPs |
| 6 | Anonymous IP rule group | Filters anonymous/hosting provider IPs |
| 7 | Rate-based rules | Rate limiting before Challenge |
| 8 | Always-on Challenge | Proactive DDoS defense for landing pages |
| 9 | Custom rules | Business-specific logic |
| 10 | Application layer rule groups (CRS, KnownBadInputs) | OWASP Top 10 protections |
| 11 | Bot Control / ATP / ACFP | Per-request pricing — place last |

Key principles: label producers before consumers, AntiDDoS AMR as early as possible, cheaper rules before expensive ones.

---

## Appendix E: WCU Capacity Reminder

{wcu_text}

After implementing any recommended changes, verify the new WCU total does not exceed 5000. Check in the AWS Console: WAF → Web ACLs → select your Web ACL → the capacity is shown in the overview.

---

## Appendix F: Common Override Recommendations

When adding or reviewing managed rule groups, consider these common overrides:

**AWSManagedRulesCommonRuleSet (CRS):**
- Override `SizeRestrictions_Body` to **Count**. This rule blocks request bodies larger than 8KB, which frequently causes false positives on file upload endpoints, API endpoints with large payloads, and form submissions with rich content.

**AWSManagedRulesBotControlRuleSet (Bot Control Common level):**
- Override `SignalNonBrowserUserAgent` to **Count**. Default Block will block legitimate non-browser clients (native apps using okhttp/gohttp, API clients, monitoring tools).
- Override `CategoryHttpLibrary` to **Count**. Same reason — legitimate HTTP libraries used by native apps and API clients will be blocked.

**AWSManagedRulesAnonymousIpList:**
- Review `HostingProviderIPList` carefully. Default Block will block requests from cloud platforms and hosting providers. If your clients may originate from cloud-hosted environments (e.g., enterprise users behind cloud proxies, SaaS integrations), override to **Count**. Never override to Allow — that lets cloud-hosted attack traffic bypass all subsequent rules.
"""




def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-generate-appendix.py <output_dir>")

    output_dir = sys.argv[1]
    summary_path = os.path.join(output_dir, "waf-summary.json")

    # Read WCU from summary
    wcu_text = "WCU capacity unknown (not in export JSON). Verify in AWS Console before adding rules."
    if os.path.isfile(summary_path):
        try:
            summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
            capacity = summary.get("web_acl", {}).get("capacity")
            if capacity is not None:
                wcu_text = f"Current WCU: **{capacity}** / 5000."
        except (json.JSONDecodeError, OSError):
            pass  # Fall back to unknown

    content = APPENDIX_SECTIONS.replace("{wcu_text}", wcu_text)

    output_file = os.path.join(output_dir, "appendix.md")
    try:
        Path(output_file).write_text(content, encoding="utf-8")
    except OSError as e:
        fatal(f"Failed to write {output_file}: {e}")

    print("Generated appendix with 6 sections", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {output_file}")
    print("SECTIONS: 6")


if __name__ == "__main__":
    main()
