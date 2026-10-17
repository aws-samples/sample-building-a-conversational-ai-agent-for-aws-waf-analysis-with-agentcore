# Roadmap

English | [中文](roadmap_zh.md)

What we plan to support or fix from here. For what the agent already does, and where it stops, see
[Capabilities](capabilities.md) and [Known Limitations](limitations.md).

Items are listed roughly in the order we intend to work on them, and that can change.

## Scope: which WebACLs, and which account

The three shapes the agent does not fully support. The agent declines a regional WebACL at selection and
says why; a cross-account log bucket, and a Parquet table kept in a prefix beside your JSON logs, both fail
less clearly, which is why [Known Limitations](limitations.md#not-supported-yet) states each and the README
warns before you deploy.

- Analyse a REGIONAL WebACL (ALB, API Gateway, AppSync) as completely as a CloudFront one; today it is declined at selection, because its label-, attack-, bot-, country- and anti-DDoS-derived sections would read as zero
- Read WAF logs from an S3 bucket in a different AWS account from the one the agent runs in, rather than requiring the WebACL, the metrics and the logs to share an account
- Read a Parquet copy you keep in a prefix beside your JSON logs; today only Parquet delivered to the log destination itself is read, because the agent matches a table by the log path and a side copy sits below it, with no way to point it at a table by name or path

## Long-running queries

- A stop button that actually cancels the Athena query, not just the browser request

## Analysis

- Network (ASN) concentration as an analysis dimension, alongside the country and referer breakdowns that already ship
- A cross-WebACL summary in the patrol report
- Sensitive-file probing as its own investigation: requests for `.env`, `.git/config` or backup files by name, which the injection investigation now leaves out, and which several common files reach with no managed rule matching at all
- Treat an IP that Bot Control labels as a CDN (`signal:cloud_service_provider:fastly`, added in version 7.0) as a proxy in front of many clients; today the bypass investigation judges it as one client, and a CDN edge's URI count passes the bar for automation easily
- Read Bot Control's token provenance labels (`token_provenance:ip_category_mismatch:<level>`, targeted level, version 7.0 and later) in the bypass and token-reuse investigations: a token acquired from a data center and presented from a residential address is what they look for
- Group by Bot Control's device ID label (`device_id:<id>`) once the Android SDK that sets it ships, and decide whether the ID is redacted before it reaches the model or a report
- Check the Bot Control labels the bypass verdicts read against each version's `describe-managed-rule-group`, as the injection investigation's sub-rule list is checked. A renamed label would read as "Bot Control did not classify this IP" and push the verdict toward a bypass. The knowledge base's Bot Control label reference also stops at version 5

## Security and privacy

- Escape all report fields on render
- Automated tests for prompt-injection resistance
