# What hourly partitioning costs you, and how to switch to minute-level

Hourly partitioning is the Firehose default and log queries work on it. What it costs you is
bytes scanned, and therefore money. This explains the size of that cost and gives the exact
steps to switch, which is a one-time in-place Firehose change.

Read this if the agent told you your table is partitioned by hour, or if you want to lower
what log queries cost.

## What hourly partitioning costs

When AWS WAF logs are delivered to S3 through Amazon Data Firehose with the **default prefix**
(`YYYY/MM/dd/HH/`), each partition holds a whole hour of data. Athena then has to scan the
**entire hour** even when you only asked about a 5-minute window.

**It costs bytes, not time, and that surprises people.** Measured at 4000 requests per second
against two real tables over the same traffic: an unaligned 30-minute query scanned 2108 MB on
the hourly table against 545 MB on the minute-level one, about 3.9x the bytes, and both
finished in about 13 seconds. A full 6-query analysis chain scanned 5x the bytes for roughly
25% more wall time. Athena reads a scan in parallel across many splits, and for gzipped WAF
logs one object is roughly one split, so parallelism follows object count rather than partition
count and absorbs most of the extra volume.

So the honest summary is:

- **You pay for the extra bytes.** Athena bills per byte scanned, so an hourly query costs
  several times what the same question costs on minute-level data.
- **Wall time is close.** Expect the same order of seconds for one query, and a modest increase
  across a long chain.
- **Narrowing a window below one hour saves nothing.** There is no sub-hour directory to skip,
  so asking for 5 minutes and asking for 60 minutes scan exactly the same bytes. Zoom in by
  asking for fewer hours instead.
- **Nothing is wrong with your results.** Every query filters on the exact `timestamp` in epoch
  milliseconds, so the rows are correct either way.

**Only day-level and coarser partitioning is refused**, because one day of production logs is a
multiple of what an hourly scan reads with none of hourly's excuse that it is the delivery
default. If the agent refused a log query outright, your prefix is coarser than hourly.

Switching to minute-level is a **one-time, in-place** Firehose configuration change: no stream
recreation, no data loss, no downtime. The agent picks up the new structure automatically on
the next query.

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
6. **S3 bucket prefix time zone**: leave it as **UTC**, the default. A non-UTC zone works
   too: the agent reads the delivery stream's `CustomTimeZone` and prunes partitions in
   that zone. UTC is just one less moving part. If log queries return 0 rows while
   metrics show traffic, tell us which zone your prefix uses.
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
  data uses the minute-level prefix, so the saving applies to data written after the change.
  The agent reads one table per WebACL, for whichever layout your newest data uses, so if you
  need the older hourly era as well you create a second table over the same bucket yourself.
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
