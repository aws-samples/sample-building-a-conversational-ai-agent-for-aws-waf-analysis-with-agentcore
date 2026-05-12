# IAM Permissions Reference

[中文版](iam-permissions_zh.md)

This document lists every IAM permission WAF Agent requires, what it's used for, and whether it can modify your production environment.

## Summary

**WAF Agent is read-only for your production resources.** It cannot modify AWS WAF rules, delete log groups, change CloudFront distributions, or alter any production configuration. The only write operations are:

1. Creating/deleting **temporary Athena tables** in a dedicated database (auto-cleaned on session end)
2. Writing its own **container logs** to CloudWatch
3. Writing **session history** to a dedicated DynamoDB table (auto-expires after 30 days)
4. Writing **memory events** to AgentCore Memory (managed service, auto-expires)

## Permission Details

### AWS WAF (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `wafv2:ListWebACLs` | List available WebACLs | None (read) |
| `wafv2:GetWebACL` | Read WebACL rules and configuration | None (read) |
| `wafv2:GetLoggingConfiguration` | Discover where AWS WAF logs are sent | None (read) |
| `wafv2:ListResourcesForWebACL` | Find which CloudFront/ALB resources use a WebACL | None (read) |

### CloudWatch Metrics (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `cloudwatch:GetMetricData` | Query AWS WAF metrics (AllowedRequests, BlockedRequests, etc.) | None (read) |
| `cloudwatch:ListMetrics` | Discover available metric names | None (read) |

### CloudWatch Logs (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `logs:StartQuery` | Run Logs Insights queries on AWS WAF logs | None (read). Queries are read-only and cannot modify log data. |
| `logs:GetQueryResults` | Retrieve query results | None (read) |
| `logs:StopQuery` | Cancel a running query (cleanup) | None (stops a read operation) |
| `logs:DescribeLogGroups` | Find AWS WAF log groups | None (read) |

### Athena (Limited Write)

| Permission | Purpose | Production Impact |
|---|---|---|
| `athena:StartQueryExecution` | Run SQL queries on S3-based AWS WAF logs | **See note below** |
| `athena:GetQueryExecution` | Check query status | None (read) |
| `athena:GetQueryResults` | Retrieve query results | None (read) |

**Athena write impact:** Athena queries themselves are read-only (SELECT). The agent also creates temporary tables (CREATE TABLE) for partition projection — see Glue section below.

### S3 (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `s3:GetObject` | Read AWS WAF log files from S3 | None (read) |
| `s3:ListBucket` | Discover log file paths and partition structure | None (read) |

### Firehose (Read-Only)

| Permission | Purpose | Production Impact |
|---|---|---|
| `firehose:DescribeDeliveryStream` | Discover S3 delivery path for Firehose-based AWS WAF logs | None (read) |

### Glue Data Catalog (Limited Write)

| Permission | Purpose | Production Impact |
|---|---|---|
| `glue:GetTable` | Find existing Athena tables for AWS WAF logs | None (read) |
| `glue:GetDatabase` | Check if database exists | None (read) |
| `glue:CreateDatabase` | Create `waf_agent_temp` database if not exists | **Creates a new empty database.** Does not touch existing databases. |
| `glue:CreateTable` | Create temporary table with partition projection | **Creates a table in `waf_agent_temp` database only.** Does not modify existing tables. |
| `glue:DeleteTable` | Clean up temporary table on session end | **Deletes only tables created by the agent** (in `waf_agent_temp` database). |

**Safety guarantees for Glue:**
- The agent only creates tables in a dedicated `waf_agent_temp` database
- Tables are automatically deleted when the session ends (SIGTERM handler)
- If cleanup fails (e.g., container killed), orphaned tables in `waf_agent_temp` can be safely deleted manually
- The agent never modifies tables in other databases

### Amazon Bedrock (Model Invocation)

| Permission | Purpose | Production Impact |
|---|---|---|
| `bedrock:InvokeModel` | Call the LLM (Claude) for reasoning | None (API call to Amazon Bedrock service) |
| `bedrock:InvokeModelWithResponseStream` | Stream LLM responses | None (API call to Amazon Bedrock service) |

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

**Note:** These permissions are scoped to `/aws/bedrock-agentcore/runtimes/*` (scoped by CloudFormation) — the agent cannot write to any other log group.

### DynamoDB (Session History)

**AgentCore Runtime role** (saves messages during conversations):

| Permission | Purpose | Production Impact |
|---|---|---|
| `dynamodb:PutItem` | Save conversation messages | Writes to dedicated sessions table only |
| `dynamodb:GetItem` | Retrieve session metadata | None (read) |
| `dynamodb:Query` | List sessions / get messages | None (read) |
| `dynamodb:DeleteItem` | Delete individual items | Deletes from sessions table only |
| `dynamodb:UpdateItem` | Upsert session metadata (title, lastUsed) | Updates sessions table only |
| `dynamodb:BatchWriteItem` | Bulk delete session messages | Deletes from sessions table only |

**Sessions API Lambda role** (handles sidebar list/get/delete):

| Permission | Purpose | Production Impact |
|---|---|---|
| `dynamodb:Query` | List sessions / get messages | None (read) |
| `dynamodb:GetItem` | Retrieve session metadata | None (read) |
| `dynamodb:DeleteItem` | Delete individual items | Deletes from sessions table only |
| `dynamodb:BatchWriteItem` | Bulk delete session messages | Deletes from sessions table only |

**Note:** Both roles are scoped to the `${StackName}-sessions` table ARN only.

### AgentCore Memory

| Permission | Purpose | Production Impact |
|---|---|---|
| `bedrock-agentcore:CreateEvent` | Store conversation turns (STM) | Writes to managed Memory service |
| `bedrock-agentcore:ListEvents` | Retrieve recent turns | None (read) |
| `bedrock-agentcore:RetrieveMemoryRecords` | Semantic search of LTM | None (read) |
| `bedrock-agentcore:ListMemoryRecords` | List LTM records | None (read) |

### Bedrock Knowledge Base (optional)

| Permission | Purpose | Production Impact |
|---|---|---|
| `bedrock:Retrieve` | Search AWS WAF best practices KB | None (read) |

**Note:** Only granted when `KnowledgeBaseId` parameter is set. Scoped to the specific KB ARN — the agent cannot query any other knowledge base.

## What the Agent CANNOT Do

- ❌ Modify AWS WAF rules (no `wafv2:UpdateWebACL`, `wafv2:CreateRule`, etc.)
- ❌ Delete or modify log groups (no `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`)
- ❌ Modify S3 objects (no `s3:PutObject`, `s3:DeleteObject`)
- ❌ Modify CloudFront distributions
- ❌ Create or modify Firehose delivery streams
- ❌ Modify existing Glue tables or databases (only creates in `waf_agent_temp`)
- ❌ Access DynamoDB tables other than its own sessions table
- ❌ Access any service not listed above
