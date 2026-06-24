# Why Athena log queries need minute-level partitioning, and how to enable it

This explains why the agent stops and asks you to re-partition when your WAF logs use
hourly partitioning, and gives the exact steps to fix it. Use this whenever a log query is
blocked with a "hourly partition detected" message.

## Why the agent stops (and why it's not a bug)

When AWS WAF logs are delivered to S3 through Amazon Data Firehose with the **default prefix**
(`YYYY/MM/dd/HH/`), each partition holds a whole hour of data. Athena then has to scan the
**entire hour** even when you only asked about a 5-minute window.

For any real traffic volume (>10K requests/hour) this means:

- Queries take 30–60 seconds or time out entirely (>5 minutes)
- Drill-down investigation becomes too slow to be usable in a conversation
- Athena scan costs go up (you pay per byte scanned)

Important: this is **not** a correctness problem. Every query already filters on the exact
`timestamp` (epoch milliseconds), so results would still be accurate — just slow. The agent
is an interactive assistant: a user asks "any false positives between 14:30 and 15:00?" and
waits in the chat. A 30–60 second answer breaks that. So the agent deliberately **does not run
slow log queries** on hourly-partitioned tables. Instead it stops, explains why, and points
you here. (Aggregate CloudWatch metrics still work — they don't depend on partitioning — so
the agent can still give you trends and volume while log-level detail is blocked.)

The fix is a **one-time, in-place** Firehose configuration change: switch the S3 prefix from
hourly to minute-level. No stream recreation, no data loss, no downtime. After that, Athena
scans only the relevant minutes — **10–60× faster** — and the agent picks up the new structure
automatically on the next query.

## What changes

**Before (default, hourly):**
```
s3://bucket/2026/05/25/14/      ← every file for the whole hour in one directory
```

**After (minute-level):**
```
s3://bucket/2026/05/25/14/00/   ← only minutes 00–04
s3://bucket/2026/05/25/14/05/   ← only minutes 05–09
...
```

## How to enable it

### Option A — AWS Console

1. Open the Amazon Data Firehose console: https://console.aws.amazon.com/firehose/
2. Select your `aws-waf-logs-*` delivery stream
3. Click **Edit** on the S3 destination configuration
4. Set **S3 bucket prefix** to:
   ```
   !{timestamp:yyyy/MM/dd/HH/mm/}
   ```
5. Set **S3 bucket error output prefix** to:
   ```
   errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}
   ```
6. **S3 bucket prefix time zone**: keep as **UTC** (default). Do NOT change this — Athena
   partition pruning assumes UTC paths; a non-UTC time zone makes queries return 0 results.
7. Save.

### Option B — AWS CLI

```bash
STREAM_NAME="aws-waf-logs-your-stream-name"

VERSION=$(aws firehose describe-delivery-stream \
  --delivery-stream-name $STREAM_NAME \
  --query 'DeliveryStreamDescription.VersionId' --output text)

DEST_ID=$(aws firehose describe-delivery-stream \
  --delivery-stream-name $STREAM_NAME \
  --query 'DeliveryStreamDescription.Destinations[0].DestinationId' --output text)

aws firehose update-destination \
  --delivery-stream-name $STREAM_NAME \
  --current-delivery-stream-version-id $VERSION \
  --destination-id $DEST_ID \
  --extended-s3-destination-update '{
    "Prefix": "!{timestamp:yyyy/MM/dd/HH/mm/}",
    "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}"
  }'
```

### Option C — keep account/WebACL in the path (recommended for multi-WebACL streams)

If several WebACLs share one Firehose stream, hardcode the identifiers so each WebACL's data
stays separable (this mirrors WAF's native S3 / Vended Logs layout):

```bash
aws firehose update-destination \
  --delivery-stream-name $STREAM_NAME \
  --current-delivery-stream-version-id $VERSION \
  --destination-id $DEST_ID \
  --extended-s3-destination-update '{
    "Prefix": "AWSLogs/YOUR_ACCOUNT_ID/WAFLogs/YOUR_REGION/YOUR_WEBACL_NAME/!{timestamp:yyyy/MM/dd/HH/mm/}",
    "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}"
  }'
```

Replace `YOUR_ACCOUNT_ID`, `YOUR_REGION`, `YOUR_WEBACL_NAME` with actual values.

## What to expect after the change

- **No downtime** — the stream stays active; new prefix takes effect within a few minutes.
- **Old data is not moved** — existing files stay at their original hourly paths; only new
  data uses the minute-level prefix. (So the speed-up applies to data written after the change.)
- **The agent auto-detects** — on the next query it sees the new minute structure and recreates
  its Athena table automatically. No manual table work needed.
- **No extra cost** — timestamp-based prefixes are a standard Firehose feature, no per-GB
  charge (unlike Dynamic Partitioning).
- **`ErrorOutputPrefix` is required** — when `Prefix` uses `!{timestamp:...}`, the API requires
  `ErrorOutputPrefix` with `!{firehose:error-output-type}`, or it returns a validation error.
- Optional: lower the buffer interval to 60s (from the default 300s) for fresher logs (slightly
  more S3 PUTs).

## Common mistakes

- **`MM` vs `mm`**: `MM` = month, `mm` = minute. Using `mm` for the month produces wrong paths.
  The correct minute-level prefix is `yyyy/MM/dd/HH/mm` (capital MM for month, lowercase mm for minute).
- **Changing the time zone away from UTC** → Athena partition pruning expects UTC; queries
  return 0 results.

## Verify

After a few minutes, check that new data lands in minute-level directories:

```bash
aws s3 ls s3://your-bucket/ --recursive | tail -5
```

You should see paths like `.../14/30/...` (an extra minute directory under the hour).
