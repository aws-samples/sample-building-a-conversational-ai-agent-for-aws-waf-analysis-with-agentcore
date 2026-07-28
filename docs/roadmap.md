# Roadmap

English | [中文](roadmap_zh.md)

What we plan to support or fix.

**A date on the right means it has shipped.** No date means it has not, and no date is being
promised. Within each group, undated items are listed roughly in the order we intend to work on
them, and that order can change.

## Log querying and partitioning

| | |
|---|---|
| Detect minute-level partitioning correctly on a bucket whose prefix layout changed partway through | |
| Tell you the date from which minute-level log querying is available, when a bucket holds both layouts | |
| Work with an existing Athena table whose partition column is not named `log_time` | |
| Read a Parquet WAF log table you converted yourself | |
| Explain the hourly-partition limit and the one-time Firehose fix in the conversation | 2026-06-24 |
| Reuse an existing Athena table instead of creating one, and self-heal when a table's location goes stale | 2026-06-06 |
| Keep one WebACL's results out of another's when several share an S3 prefix | 2026-06-06 |

## Long-running queries

| | |
|---|---|
| Keep the connection alive and show scan progress while a large query runs | |
| Say plainly when a question needs a wider scan than one turn allows, and what to ask instead | |
| A stop button that actually cancels the Athena query, not just the browser request | |
| Say when a report section was skipped, instead of leaving it blank | |

## Analysis

| | |
|---|---|
| One general log-aggregation query that combines any supported filter with any supported grouping | |
| Rule and endpoint hit rate, including false-positive rate after a Count to Block switch | |
| A guided SQL injection investigation, the way false-positive and bypass investigations already work | |
| Detect one WAF token replayed across many IPs | |
| Country, referer, and network (ASN) concentration as additional dimensions | |
| Find the WebACL for a domain name without asking you which one it is | |
| A cross-WebACL summary in the patrol report | |
| Detect User-Agent rotation behind a single TLS fingerprint | 2026-06-24 |
| Break down why real users fail a Challenge or CAPTCHA, by token failure reason | 2026-06-24 |
| Guidance for CloudWatch alarms that watch a rule's block and false-positive rate | 2026-06-24 |
| Weekly security patrol report, with charts and per-rule inspected content | 2026-06-07 |

## Security and privacy

| | |
|---|---|
| Keep log content as data and never as instructions, even when a log field contains one | |
| Escape all report fields on render | |
| Automated tests for prompt-injection resistance, and for attack payloads still displaying as text | |
| Sanitize agent output before rendering it in the browser | 2026-07-20 |
| Mask secret values in inspected request content | 2026-06-07 |

## Documentation

| | |
|---|---|
| A published list of known limitations | |
| Athena table detection guide | 2026-06-05 |
| Firehose minute-level partitioning guide | 2026-05-25 |
| User, IAM permissions, and cost estimation guides | 2026-05-11 |
