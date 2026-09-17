# Regional (ALB) WAF is not supported; Parquet log tables are

WAF Analyst analyses CloudFront-scope WebACLs, with logs delivered to S3 and read through Athena or
sent to CloudWatch Logs.

This article answers two questions that have opposite answers. A regional-scope WebACL is not
supported, and the agent declines it on purpose. A Parquet log table, on the other hand, works when
you maintain it. Each is explained below.

## Why regional-scope WebACLs are not supported

A REGIONAL-scope WebACL protects a regional resource: an Application Load Balancer, an API Gateway
stage, an AppSync API, an App Runner service, a Cognito user pool, or a Verified Access instance.
WAF Analyst does not analyse these. It declines them at the point you select the WebACL, and the
decision is deliberate.

The reason is in the metrics. A regional WebACL publishes its CloudWatch metrics with an extra
`Region` dimension that a CloudFront WebACL does not have. CloudWatch matches a metric by its exact
set of dimensions, so queries that leave the `Region` dimension out match nothing and come back
empty. The result would be a report where the plain request counts, allowed and blocked and
per-rule totals, still came back correct, while the bot analysis, the DDoS detection, the
attack-type breakdown, and the label views all read as zero. A report that looks whole while whole
sections are silently empty is worse than a clear answer of no, so the tool declines the regional
WebACL rather than hand back a half-right one.

CloudWatch metrics and CloudWatch Logs are per-region services as well, and a regional WebACL keeps
its metrics and its logs in its own region, which the tool's other region assumptions do not fully
account for. The metric dimension is the main reason; this compounds it.

## Parquet log tables work at the log destination, not beside it

The agent reads Parquet WAF logs with no special handling: its SQL is written against the WAF schema
(the nested `httpRequest` struct, the `labels` array) independent of storage format, its table
resolution never inspects the storage format, and Athena's Parquet reader matches column names
case-insensitively. Verified 2026-09-17 against a Parquet table whose nested field names kept AWS
WAF's original camelCase, such as `httpRequest.clientIp`: the agent's lowercase queries read them and
every query shape returned real values.

The constraint is where the Parquet lives. The agent adopts an existing table only when that table's
`LOCATION` is the log path your WebACL resolves to, or an ancestor of it. So Parquet works when your
logs are delivered as Parquet to that destination. It does not work if you keep JSON at the
destination and convert a separate copy to a side prefix: that table sits below the log path, the
agent never matches it, and there is no way to point the agent at a table by name or path. Over a
bucket with no table at all the agent looks for `.gz`, so it does not auto-build a table over Parquet
either.

## What to do instead

If the resource you protect is a CloudFront distribution, point WAF Analyst at its CloudFront-scope
WebACL. If your WAF only protects regional resources, WAF Analyst cannot analyse it. If your WAF logs
are delivered as Parquet to the log destination, the agent reads them. A Parquet copy kept in a
separate prefix, with JSON still at the destination, is not picked up.
