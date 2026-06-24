# Athena Table Auto-Detection

English | [中文](athena-table-detection_zh.md)

## How It Works

When the agent needs to query WAF logs stored in S3, it follows this sequence:

1. **Resolve S3 path** from the WAF logging configuration ARN
2. **Search Glue Data Catalog** for an existing table that matches the S3 path, has WAF log columns (`action`, `httprequest`), **and is partitioned by `log_time`** (required for the agent's partition pruning)
3. **If found** — validate that the table's partition format and interval match the actual S3 directory structure, then reuse it
4. **If not found** — auto-create a table in the `waf_analysis_tmp` database

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
'projection.log_time.interval'      = '5'                   (or 1)
'projection.log_time.interval.unit' = 'minutes'             (or hours)
'storage.location.template'         = 's3://bucket/path/${log_time}'
```

This means:
- No partition management needed — new time slots are automatically included
- `SHOW PARTITIONS` returns empty (this is normal for projection tables)
- No Glue Crawler required
- Query performance is identical to hand-built partition projection tables

## Existing Table Detection

The agent searches **all Glue databases** (not just `waf_analysis_tmp`) for a table whose `LOCATION` is a prefix of the resolved S3 log path. To qualify, the table must have both `action` and `httprequest` columns.

### When Detection Succeeds

- The S3 path resolved from WAF logging config **starts with** your table's `LOCATION` (i.e., your table's LOCATION is equal to or a parent prefix of the resolved path)
- Your table has both `action` and `httprequest` columns
- Your table is partitioned by `log_time` (partition projection)
- The partition interval matches the actual S3 directory structure

### When Detection May Fail

| Scenario | Why it fails | Workaround |
|----------|-------------|------------|
| Firehose prefix is entirely dynamic expressions | Resolved path is just the bucket root, doesn't match a more-specific user table LOCATION | The agent's own scratch table self-heals (drops + recreates at the resolved path); a *user-provided* table at a deeper path still won't match |
| Database has >100 tables | Pagination not yet implemented | Place WAF table in a smaller database, or in `waf_analysis_tmp` |
| Custom column names | `httprequest` named differently (e.g., `http_request`) | Rename column to `httprequest`, or wait for future "bring your own table" support |
| Different partition column name | Your table uses `datehour` instead of `log_time` | The agent skips it and creates its own `log_time`-partitioned table alongside yours (both point to the same S3 data) |

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

## Tables Created by the Agent

- Database: `waf_analysis_tmp` (auto-created if not exists)
- Table name: `waf_logs_{webacl_name}` (special characters replaced with underscores)
- Partition column: `log_time` (string type, partition projection)
- These tables are **permanent** and reused across sessions — no recreation overhead (they are only recreated if their location becomes stale; see "Automatic Self-Healing" above)
- They are read-only external tables pointing to your existing S3 log data (no data copying)
- Safe to delete: `DROP TABLE waf_analysis_tmp.waf_logs_xxx` or `DROP DATABASE waf_analysis_tmp CASCADE`

> **Note:** If you already have your own partition projection table but it uses a different partition column name, the agent will create its own table alongside yours. Both tables point to the same S3 data — no duplication, no conflict. You can keep both or drop the agent's table after investigation.

## Known Limitations

1. **Partition column name is hardcoded to `log_time`.** If you have an existing table with a different partition column (e.g., `datehour`, `dt`), the agent cannot reuse it — it will create its own table alongside yours.

2. **No "bring your own table" config yet.** You cannot currently tell the agent "use my table X in database Y." It always auto-detects or creates.

3. **Glue pagination not implemented.** If a database has >100 tables, some tables may not be found during detection.

4. **Custom S3 prefix on Vended Logs is invisible.** If you configured a custom key prefix via the API (not console), the agent may not resolve the correct path because `GetLoggingConfiguration` doesn't return the prefix.
