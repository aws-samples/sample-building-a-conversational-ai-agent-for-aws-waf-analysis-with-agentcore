# IAM Permissions Reference

This document lists every IAM permission WAF Agent requires, what it's used for, and whether it can modify your production environment.

## Summary

**WAF Agent is read-only for your production resources.** It cannot modify WAF rules, delete log groups, change CloudFront distributions, or alter any production configuration. The only write operations are:

1. Creating/deleting **temporary Athena tables** in a dedicated database (auto-cleaned on session end)
2. Writing its own **container logs** to CloudWatch

## Permission Details

### WAF (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `wafv2:ListWebACLs` | List available WebACLs | None (read) |
| `wafv2:GetWebACL` | Read WebACL rules and configuration | None (read) |
| `wafv2:GetLoggingConfiguration` | Discover where WAF logs are sent | None (read) |
| `wafv2:ListResourcesForWebACL` | Find which CloudFront/ALB resources use a WebACL | None (read) |

### CloudWatch Metrics (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `cloudwatch:GetMetricData` | Query WAF metrics (AllowedRequests, BlockedRequests, etc.) | None (read) |
| `cloudwatch:ListMetrics` | Discover available metric names | None (read) |

### CloudWatch Logs (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `logs:StartQuery` | Run Logs Insights queries on WAF logs | None (read). Queries are read-only and cannot modify log data. |
| `logs:GetQueryResults` | Retrieve query results | None (read) |
| `logs:StopQuery` | Cancel a running query (cleanup) | None (stops a read operation) |
| `logs:DescribeLogGroups` | Find WAF log groups | None (read) |

### Athena (Limited Write)

| Permission | Purpose | Production Impact |
|---|---|---|
| `athena:StartQueryExecution` | Run SQL queries on S3-based WAF logs | **See note below** |
| `athena:GetQueryExecution` | Check query status | None (read) |
| `athena:GetQueryResults` | Retrieve query results | None (read) |

**Athena write impact:** Athena queries themselves are read-only (SELECT). The agent also creates temporary tables (CREATE TABLE) for partition projection — see Glue section below.

### S3 (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `s3:GetObject` | Read WAF log files from S3 | None (read) |
| `s3:ListBucket` | Discover log file paths and partition structure | None (read) |

### Firehose (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `firehose:DescribeDeliveryStream` | Discover S3 delivery path for Firehose-based WAF logs | None (read) |

### Glue Data Catalog (Limited Write)

| Permission | Purpose | Production Impact |
|---|---|---|
| `glue:GetTable` | Find existing Athena tables for WAF logs | None (read) |
| `glue:GetDatabase` | Check if database exists | None (read) |
| `glue:CreateDatabase` | Create `waf_agent_temp` database if not exists | **Creates a new empty database.** Does not touch existing databases. |
| `glue:CreateTable` | Create temporary table with partition projection | **Creates a table in `waf_agent_temp` database only.** Does not modify existing tables. |
| `glue:DeleteTable` | Clean up temporary table on session end | **Deletes only tables created by the agent** (in `waf_agent_temp` database). |

**Safety guarantees for Glue:**
- The agent only creates tables in a dedicated `waf_agent_temp` database
- Tables are automatically deleted when the session ends (SIGTERM handler)
- If cleanup fails (e.g., container killed), orphaned tables in `waf_agent_temp` can be safely deleted manually
- The agent never modifies tables in other databases

### Bedrock (Model Invocation)

| Permission | Purpose | Production Impact |
|---|---|---|
| `bedrock:InvokeModel` | Call the LLM (Claude) for reasoning | None (API call to Bedrock service) |
| `bedrock:InvokeModelWithResponseStream` | Stream LLM responses | None (API call to Bedrock service) |

### ECR (Container Pull)

| Permission | Purpose | Production Impact |
|---|---|---|
| `ecr:BatchGetImage` | Pull agent container image | None (read) |
| `ecr:GetDownloadUrlForLayer` | Download container layers | None (read) |
| `ecr:GetAuthorizationToken` | Authenticate to ECR | None (auth token) |

### CloudWatch Logs (Agent's Own Logs)

| Permission | Purpose | Production Impact |
|---|---|---|
| `logs:CreateLogGroup` | Create log group for agent container logs | Creates `/aws/bedrock-agentcore/runtimes/*` log group only |
| `logs:CreateLogStream` | Create log stream within agent's log group | Within agent's own log group only |
| `logs:PutLogEvents` | Write agent container logs | Within agent's own log group only |

**Note:** These permissions are scoped to `arn:aws:logs:${Region}:${Account}:log-group:/aws/bedrock-agentcore/runtimes/*` — the agent cannot write to any other log group.

## What the Agent CANNOT Do

- ❌ Modify WAF rules (no `wafv2:UpdateWebACL`, `wafv2:CreateRule`, etc.)
- ❌ Delete or modify log groups (no `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`)
- ❌ Modify S3 objects (no `s3:PutObject`, `s3:DeleteObject`)
- ❌ Modify CloudFront distributions
- ❌ Create or modify Firehose delivery streams
- ❌ Modify existing Glue tables or databases (only creates in `waf_agent_temp`)
- ❌ Access any service not listed above
