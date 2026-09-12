# Roadmap

English | [中文](roadmap_zh.md)

What we plan to support or fix from here. Already-shipped work is in the
[CHANGELOG](../CHANGELOG.md), not here.

A date on the right means the item has shipped and been verified against a real environment. An empty
cell means it has not, and carries no promise about when it will. Within a group, items are listed
roughly in the order we intend to work on them, and that order can change.

## Log querying and partitioning

| | |
|---|---|
| Run log-detail analysis on hourly-partitioned logs (with an up-front note that scans cost more), instead of declining them | 2026-09-10 |
| Detect minute-level partitioning correctly on a bucket whose prefix layout changed partway through | 2026-09-09 |
| Tell you the date from which minute-level log querying is available, when a bucket holds both layouts | 2026-09-09 |
| Work with an existing Athena table whose partition column is not named `log_time`, at minute or hourly granularity | 2026-09-09 |
| Stop dropping rows at the edges of a query window, where a log record's timestamp and the partition directory it landed in disagree | 2026-09-09 |
| Detect a non-UTC timezone on Firehose S3 log paths automatically, so queries don't silently miss rows | |
| Show query result times consistently in your session timezone across all data sources | 2026-09-09 |
| Read a Parquet WAF log table you converted yourself | |

See [Hourly vs Minute Partitioning](hourly-vs-minute-partitioning.md) for the trade-off and the measurements behind accepting hourly.

## Long-running queries

| | |
|---|---|
| Keep the connection alive and show scan progress while a large query runs | |
| Say plainly when a question needs a wider scan than one turn allows, and what to ask instead | 2026-09-09 |
| Enforce the query time-window limit in code, not only as guidance | |
| Offer the deepest bypass-scan drill-down as candidates you pick from, instead of running the whole chain automatically | |
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

## Security and privacy

| | |
|---|---|
| Keep log content as data and never as instructions, even when a log field contains one | |
| Escape all report fields on render | |
| Automated tests for prompt-injection resistance, and for attack payloads still displaying as text | |

## Deployment

| | |
|---|---|
| Build the container image on AWS, so no container tool is needed on your own machine ([#8](https://github.com/aws-samples/sample-building-a-conversational-ai-agent-for-aws-waf-analysis-with-agentcore/issues/8)) | 2026-09-12 |
| Move a deployment to a newer release by updating one stack parameter | 2026-09-12 |

## Documentation

| | |
|---|---|
| A published list of known limitations | |
