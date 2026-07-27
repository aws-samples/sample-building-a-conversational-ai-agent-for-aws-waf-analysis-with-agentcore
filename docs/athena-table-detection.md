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
| Custom column names | `httprequest` named differently (e.g., `http_request`) | Rename column to `httprequest` (the agent's SQL references it by that exact name) |
| Different partition column name | Your table uses `datehour` instead of `log_time` | Auto-detection skips it and creates its own `log_time`-partitioned table alongside yours. To use your table directly, run `set_log_table` — it accepts any single `date`-projected partition column (see [Bring Your Own Table](#bring-your-own-table)) |

## Bring Your Own Table

If auto-detection picks the wrong table, can't resolve your S3 path, or you simply want the agent to query a table you already maintain, tell the agent in chat — e.g. *"use my table `my_db.my_waf_logs`"*. The agent calls the `set_log_table` tool, which pins log-detail queries for the current WebACL to that table (overriding auto-detection). Say *"go back to auto-detection"* to clear it.

The tool validates the table before using it and reports the reason if it can't:

- The table must exist in the Glue Data Catalog in the WAF logs region.
- It must expose the WAF log columns `action` and `httprequest` (exact names).
- It must have **exactly one** time-based partition column using Athena partition projection of type `date`. The column name is free — `log_time`, `datehour`, `dt`, whatever — and the agent adapts its pruning to it.

Behavior notes:

- The tool reads the partition column's own `projection.<col>.format` (e.g. `yyyy/MM/dd/HH/mm`, `yyyy-MM-dd-HH`) and translates it to build the pruning predicate. The column name and format are recorded and used verbatim in every subsequent query.
- A user-provided table **opts out of the coarse-partition guard**. Hourly (`yyyy/MM/dd/HH`) and daily tables are allowed to run log-detail queries, since you explicitly chose the table. The tool's confirmation warns that such queries scan more data and can hit the Athena timeout on busy traffic — narrow the window if a query is slow. (Auto-detected/Firehose hourly tables are still blocked; the guard only relaxes for the explicit `set_log_table` opt-in.)
- If the table's `LOCATION` does not contain the WebACL name, the agent treats it as potentially shared and adds a `webaclid` filter to every log query automatically.
- The override is scoped to the current WebACL and is cleared when you switch WebACLs — re-set it if your table spans multiple WebACLs.
- The agent never drops or recreates a user-provided table (self-healing applies only to its own `waf_analysis_tmp` scratch tables).

> **Not supported by `set_log_table`:** integer/enum partition projections (e.g. `dt` as `2024010100`), non-projected Hive partitions, and tables with more than one partition key. The tool rejects these with an explanation. Auto-detection (below) still requires the column to be named `log_time`.

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
- **Custom / bring-your-own tables** whose directories are written in local time: declare it with `set_log_table(partition_timezone='America/New_York')` (IANA name, DST-aware, or a fixed offset like `-04:00`).
- **Operator override:** set the `WAF_AGENT_PARTITION_TZ` environment variable on the runtime to force a zone for all queries.

Resolution precedence: `WAF_AGENT_PARTITION_TZ` env → `set_log_table(partition_timezone=...)` → detected Firehose `CustomTimeZone` → UTC.

**Symptom of a wrong partition timezone:** log queries return **0 rows while CloudWatch metrics show traffic**. If your paths are in local time but the agent assumes UTC, the query looks in the wrong hour's directory. Re-run `set_log_table` with the correct `partition_timezone`.

## Tables Created by the Agent

- Database: `waf_analysis_tmp` (auto-created if not exists)
- Table name: `waf_logs_{webacl_name}` (special characters replaced with underscores)
- Partition column: `log_time` (string type, partition projection)
- These tables are **permanent** and reused across sessions — no recreation overhead (they are only recreated if their location becomes stale; see "Automatic Self-Healing" above)
- They are read-only external tables pointing to your existing S3 log data (no data copying)
- Safe to delete: `DROP TABLE waf_analysis_tmp.waf_logs_xxx` or `DROP DATABASE waf_analysis_tmp CASCADE`

> **Note:** If you already have your own partition projection table but it uses a different partition column name, the agent will create its own table alongside yours. Both tables point to the same S3 data — no duplication, no conflict. You can keep both or drop the agent's table after investigation.

## Known Limitations

1. **Auto-detection still requires the partition column to be named `log_time`.** During automatic detection a table with a differently-named partition column (e.g., `datehour`, `dt`) is skipped and the agent creates its own `log_time` table alongside yours. To use such a table directly, point the agent at it with `set_log_table` — the "bring your own table" path accepts any single `date`-projected partition column regardless of name.

2. **Glue pagination not implemented.** If a database has >100 tables, some tables may not be found during detection. Use `set_log_table` to point the agent straight at the right table.

3. **Custom S3 prefix on Vended Logs is invisible.** If you configured a custom key prefix via the API (not console), the agent may not resolve the correct path because `GetLoggingConfiguration` doesn't return the prefix. `set_log_table` sidesteps this by using your table's own `LOCATION`.




