# Optimizing Firehose Log Delivery for WAF Analyst

English | [中文](firehose-minute-partitioning_zh.md)

## Problem

If your AWS WAF logs are delivered to S3 via Amazon Data Firehose with the **default prefix** (`YYYY/MM/dd/HH/`), Athena queries scan an entire hour of data per query — even if you only need 5 minutes. For high-traffic WebACLs (>10K requests/hour), this causes:

- Query timeouts (>5 minutes)
- Slow investigation workflows
- Higher Athena scan costs

## Solution: Add Minute-Level Partitioning

Change the Firehose S3 prefix from hourly to minute-level. This is a **one-time, in-place configuration change** — no stream recreation, no data loss, no downtime.

### Before (default)
```
s3://bucket/2026/05/25/14/  ← all files for the entire hour in one directory
```

### After (minute-level)
```
s3://bucket/2026/05/25/14/00/  ← only files for minute 00-04
s3://bucket/2026/05/25/14/05/  ← only files for minute 05-09
...
```

Athena can now scan just the relevant minutes instead of the full hour — **10-60× faster queries**.

## How to Update

### Option A: AWS Console

1. Open the [Amazon Data Firehose console](https://console.aws.amazon.com/firehose/)
2. Select your `aws-waf-logs-*` delivery stream
3. Click **Edit** on the S3 destination configuration
4. Change **S3 bucket prefix** to:
   ```
   !{timestamp:yyyy/MM/dd/HH/mm/}
   ```
5. Set **S3 bucket error output prefix** to:
   ```
   errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}
   ```
6. **S3 bucket prefix time zone**: Keep as **UTC** (default). Do NOT change this — Athena partition pruning assumes UTC paths. Using a non-UTC time zone will cause queries to return 0 results.
7. Save changes

### Option B: AWS CLI

```bash
# Step 1: Get current stream version and destination ID
STREAM_NAME="aws-waf-logs-your-stream-name"

VERSION=$(aws firehose describe-delivery-stream \
  --delivery-stream-name $STREAM_NAME \
  --query 'DeliveryStreamDescription.VersionId' --output text)

DEST_ID=$(aws firehose describe-delivery-stream \
  --delivery-stream-name $STREAM_NAME \
  --query 'DeliveryStreamDescription.Destinations[0].DestinationId' --output text)

# Step 2: Update the prefix
aws firehose update-destination \
  --delivery-stream-name $STREAM_NAME \
  --current-delivery-stream-version-id $VERSION \
  --destination-id $DEST_ID \
  --extended-s3-destination-update '{
    "Prefix": "!{timestamp:yyyy/MM/dd/HH/mm/}",
    "ErrorOutputPrefix": "errors/!{firehose:error-output-type}/!{timestamp:yyyy/MM/dd/HH/}"
  }'
```

### Option C: Keep Account/WebACL in Path (Recommended for Multi-WebACL)

If you have multiple WebACLs logging to the same Firehose stream, hardcode the identifiers:

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

Replace `YOUR_ACCOUNT_ID`, `YOUR_REGION`, and `YOUR_WEBACL_NAME` with actual values. This produces the same path structure as WAF's native S3 delivery (Vended Logs).

## Important Notes

- **No downtime**: The stream stays active during the update. Changes take effect within a few minutes.
- **Old data is not moved**: Existing files stay at their original paths. Only new data uses the new prefix.
- **WAF Analyst auto-detects**: After the prefix change, WAF Analyst will detect the new partition structure on the next query and recreate its Athena table automatically.
- **No extra cost**: Timestamp-based prefixes are a standard Firehose feature — no additional charges (unlike Dynamic Partitioning which charges per GB).
- **ErrorOutputPrefix is required**: When `Prefix` contains `!{timestamp:...}` expressions, you must also set `ErrorOutputPrefix` with `!{firehose:error-output-type}`. Otherwise the API returns a validation error.
- **Buffer interval**: Consider reducing buffer interval to 60s (from default 300s) for better real-time visibility. This increases S3 PUT costs slightly but improves log freshness.

## Syntax Reference

| Expression | Meaning | Example Output |
|---|---|---|
| `!{timestamp:yyyy}` | Year (4 digits) | 2026 |
| `!{timestamp:MM}` | Month (2 digits, uppercase) | 05 |
| `!{timestamp:dd}` | Day (2 digits) | 25 |
| `!{timestamp:HH}` | Hour 24h (2 digits) | 14 |
| `!{timestamp:mm}` | Minute (2 digits, lowercase) | 30 |

⚠️ Case matters: `MM` = month, `mm` = minute. Using `mm` for month will produce wrong paths.

## Verification

After updating, wait a few minutes for new data to arrive, then check S3:

```bash
aws s3 ls s3://your-bucket/ --recursive | tail -5
```

You should see paths with minute-level directories (e.g., `.../14/30/...`).
