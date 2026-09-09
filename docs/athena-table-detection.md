# Athena Table Auto-Detection

English | [中文](athena-table-detection_zh.md)

## How It Works

When the agent needs to query WAF logs stored in S3, it follows this sequence:

1. **Resolve S3 path** from the WAF logging configuration ARN
2. **Search Glue Data Catalog** for an existing table whose `LOCATION` covers that path, which has the WAF log columns (`action`, `httprequest`), and which is partitioned on **one** time column using partition projection of type `date`. The column can be called anything: `log_time`, `datehour`, `dt`
3. **If found** — cross-check the table's declared partitioning against the actual S3 directory structure, then reuse it
4. **If not found** — auto-create a table in the `waf_analysis_tmp` database

Every log query reports which table it used, and if a table was passed over, why. So "the agent created its own table" always comes with the reason it did not use yours.

### Automatic Self-Healing

The agent's own scratch table (`waf_analysis_tmp.waf_logs_{webacl}`) self-heals when its location becomes stale — for example when you switch a WebACL's log delivery from **Vended Logs** (`AWSLogs/.../WAFLogs/{scope}/{webacl}/`) to **Firehose** (a custom bucket-root prefix). The old table still points at the now-empty original path, so queries would return 0 rows while CloudWatch metrics still show traffic.

On the next query the agent compares the existing table's `LOCATION` against the freshly-resolved S3 path:

- **Location matches** → reuse as-is (no recreation, no downtime)
- **Location differs** → drop and recreate the scratch table at the correct path

This happens automatically; no manual `DROP TABLE` is needed. (Dropping an external table never touches the underlying S3 data.)

### Multi-WebACL Buckets

If several WebACLs deliver logs to the **same** Firehose bucket prefix, the resolved table location is shared and would otherwise mix every WebACL's records. When the agent detects that the table location is not specific to the current WebACL, it automatically adds a `webaclid` filter to every log query so results only reflect the WebACL under investigation. Metrics-based numbers are already scoped by CloudWatch dimensions and are unaffected.

## Partition Projection (Not Hive Partitions)

The agent uses **Athena partition projection** — the same mechanism described in [Athena docs: Partition Projection](https://docs.aws.amazon.com/athena/latest/ug/partition-projection.html). It does **not** use Hive-style partitions (`ALTER TABLE ADD PARTITION`).

Tables created by the agent have these TBLPROPERTIES:

```
'projection.enabled'                = 'true'
'projection.log_time.type'          = 'date'
'projection.log_time.format'        = 'yyyy/MM/dd/HH/mm'   (or yyyy/MM/dd/HH)
'projection.log_time.interval'      = '1'
'projection.log_time.interval.unit' = 'minutes'             (or hours)
'storage.location.template'         = 's3://bucket/path/${log_time}'
```

The interval is always `1`. Firehose names an object after whatever minute its buffer flushed at, so
the minute directories are arbitrary values and nothing useful can be inferred from the gaps between
them. Earlier versions inferred an interval and could land on a value that projected only every Nth
minute, leaving the objects in between unread.

This means:
- No partition management needed — new time slots are automatically included
- `SHOW PARTITIONS` returns empty (this is normal for projection tables)
- No Glue Crawler required
- Query performance is identical to hand-built partition projection tables

## Existing Table Detection

The agent searches **all Glue databases**, paginated, for a table whose `LOCATION` covers the resolved S3 log path.

### When Detection Succeeds

- The S3 path resolved from WAF logging config is your table's `LOCATION` or sits underneath it. The comparison is on a path boundary, so a table at `s3://b/waf-logs` does not claim `s3://b/waf-logs-prod`
- Your table has both `action` and `httprequest` columns, by those exact names
- Your table has **exactly one** partition column, using partition projection of type `date`. Its name is free
- Its `projection.<col>.format` is `yyyy/MM/dd`, `yyyy/MM/dd/HH` or `yyyy/MM/dd/HH/mm`, with any separator you like
- Its `projection.<col>.range` upper bound is `NOW` or a future date

### Which Table Wins

More than one table can qualify. The agent prefers **any table you maintain over its own scratch table**, then the most specific location within that group. Specificity alone would not work: the agent's own table sits at exactly the resolved path, making it the most specific match every time, so yours would never be chosen.

Ties between two equally specific tables in different databases resolve alphabetically, and the chosen table is always named in the query output so an ambiguity is visible rather than silent.

### When Detection May Fail

| Scenario | Why it fails | Workaround |
|----------|-------------|------------|
| Firehose prefix is entirely dynamic expressions | Resolved path is just the bucket root, doesn't match a more-specific user table LOCATION | The agent's own scratch table self-heals (drops + recreates at the resolved path); a *user-provided* table at a deeper path still won't match |
| Custom column names | `httprequest` named differently (e.g., `http_request`) | Rename column to `httprequest` (the agent's SQL references it by that exact name) |
| Integer or enum partition projection | Pruning compares the partition value against a rendered timestamp, which only works for a `date` projection | Recreate the column as `projection.<col>.type=date` |
| Non-projected Hive partitions | The agent never runs `ALTER TABLE ADD PARTITION`, so it cannot see them | Switch the table to partition projection |
| More than one partition key | Queries prune on a single time column | Use one projected time column |
| Declared partitions finer than the S3 layout | A table declaring `yyyy/MM/dd/HH/mm` over hourly directories projects paths that do not exist, and Athena reports that as zero rows | Fix the declared format to match the data. Declaring *coarser* than the data is fine: Athena scans recursively below the directory |

## S3 Path Resolution by Delivery Method

### S3 Direct Delivery (Vended Logs)

- WAF config ARN: `arn:aws:s3:::aws-waf-logs-{bucket}`
- Resolved path: `s3://{bucket}/AWSLogs/{account}/WAFLogs/{region}/{webacl}/`
- Partition format: always `yyyy/MM/dd/HH/mm` with 5-minute interval (AWS-managed)

### Firehose Delivery

- WAF config ARN: `arn:aws:firehose:{region}:{account}:deliverystream/aws-waf-logs-{name}`
- Resolved path: calls `DescribeDeliveryStream` → extracts S3 bucket + static prefix (dynamic expressions like `!{timestamp:...}` are stripped)
- Partition format: detected from S3 directory structure — hourly (`yyyy/MM/dd/HH`) or minute-level (`yyyy/MM/dd/HH/mm`)

**Important:** If your Firehose uses hourly partitions (default), the agent blocks log-detail queries because they time out on production traffic. When this happens the agent retrieves the fix from its knowledge base and explains the cause and the one-time Firehose change to you inline. See the [Firehose Optimization Guide](firehose-minute-partitioning.md) for the same steps.

## Partition-Path Timezone

The partition **directory names** encode a wall-clock time (e.g. `.../2026/07/27/12/16`), and the agent has to know which timezone that clock is in to prune the right directories. The record's own `timestamp` field is always UTC epoch and is filtered exactly regardless — this only affects *which directories Athena scans*.

- **AWS vended logs (S3 direct delivery)** always partition in **UTC**. No action needed — this is the default assumption.
- **Firehose** evaluates the `!{timestamp:...}` prefix in its **`CustomTimeZone`** setting (default UTC). The agent reads `CustomTimeZone` from `DescribeDeliveryStream` and prunes in that zone automatically.
- **A custom ETL** that writes local-time directories is not detectable, because there is no Firehose config to read. Set the `WAF_AGENT_PARTITION_TZ` environment variable on the agent runtime to an IANA name (`America/New_York`, DST-aware) or a fixed offset (`-04:00`).
- **Operator override:** `WAF_AGENT_PARTITION_TZ` also wins over Firehose detection, so it doubles as an escape hatch when the detected zone is wrong.

Resolution precedence: `WAF_AGENT_PARTITION_TZ` env → detected Firehose `CustomTimeZone` → UTC.

**Symptom of a wrong partition timezone:** log queries return **0 rows while CloudWatch metrics show traffic**. If your paths are in local time but the agent assumes UTC, the query looks in the wrong hour's directory. Set `WAF_AGENT_PARTITION_TZ` and redeploy.

## Tables Created by the Agent

- Database: `waf_analysis_tmp` (auto-created if not exists)
- Table name: `waf_logs_{webacl_name}` (special characters replaced with underscores)
- Partition column: `log_time` (string type, partition projection)
- These tables are **permanent** and reused across sessions — no recreation overhead (they are only recreated if their location becomes stale; see "Automatic Self-Healing" above)
- They are read-only external tables pointing to your existing S3 log data (no data copying)
- Safe to delete: `DROP TABLE waf_analysis_tmp.waf_logs_xxx` or `DROP DATABASE waf_analysis_tmp CASCADE`

> **Note:** The agent builds its own table only when no table of yours qualifies. When that happens the query output says which check yours failed. Both tables point to the same S3 data, so there is no duplication and no conflict; keep both or drop the agent's after the investigation.

## Known Limitations

1. **No way to name a table in chat.** You cannot tell the agent "use my table X in database Y." It resolves the table from your logging configuration, so the way to steer it is to make your table qualify.

2. **Hourly and coarser tables are still refused for log-detail queries.** Detection accepts them, then the query is blocked on scan cost. Only minute-level tables can run log details today.

3. **Custom S3 prefix on Vended Logs is invisible.** If you configured a custom key prefix via the API (not console), the agent may not resolve the correct path because `GetLoggingConfiguration` doesn't return the prefix.
