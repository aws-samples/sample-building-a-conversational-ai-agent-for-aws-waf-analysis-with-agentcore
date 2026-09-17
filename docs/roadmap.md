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

## Security and privacy

- Escape all report fields on render
- Automated tests for prompt-injection resistance
