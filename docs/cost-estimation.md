# Cost Estimation

[中文版](cost-estimation_zh.md)

Estimated monthly costs for WAF Agent deployment. All prices in USD.

## Cost Components

### 1. Infrastructure (Fixed Monthly)

| Component | Cost | Notes |
|---|---|---|
| CloudFront (frontend) | **$0** | Free tier: 1 TB data out + 10M requests/month. A small internal tool won't exceed this. |
| AWS WAF (frontend protection) | **~$8/month** | 1 WebACL ($5) + 3 rules ($3). Request charges negligible for internal use. |
| Cognito User Pool | **$0** | Free tier: 10,000 MAU. Internal team won't exceed this. |
| S3 (frontend hosting) | **<$0.10/month** | ~1 MB static files. |
| **Subtotal** | **~$8/month** | |

### 2. AgentCore Compute (Per-Session)

AgentCore bills for active CPU time only. I/O wait (waiting for LLM, API calls) is free.

| Metric | Typical Value |
|---|---|
| Session duration | 30–120 seconds |
| Active CPU time | ~30% of session (rest is I/O wait) |
| Peak memory | ~500 MB |

**Cost per session:**
- CPU: 30s active × 1 vCPU × ($0.0895/3600) = $0.00075
- Memory: 120s × 0.5 GB × ($0.00945/3600) = $0.00016
- **Total: ~$0.001 per session**

| Monthly usage | Sessions | AgentCore cost |
|---|---|---|
| Light (1 engineer, 5 sessions/day) | ~150 | **$0.15** |
| Medium (5 engineers, 10 sessions/day) | ~1,500 | **$1.50** |
| Heavy (20 engineers, 20 sessions/day) | ~12,000 | **$12.00** |

### 3. LLM Token Cost (Largest Component)

Claude Sonnet 4 on Amazon Bedrock (approximate pricing):
- Input: ~$3.00 per 1M tokens
- Output: ~$15.00 per 1M tokens

**Typical session token usage:**

| Scenario | Input tokens | Output tokens | Cost |
|---|---|---|---|
| Simple query (list WebACLs, metrics) | ~5K | ~2K | **$0.045** |
| Investigation (bypass detection, 10 tool calls) | ~30K | ~5K | **$0.165** |
| Deep analysis (13 tool calls + report) | ~50K | ~8K | **$0.270** |
| ROI report generation | ~40K | ~10K | **$0.270** |

**Monthly estimates:**

| Usage level | Sessions × avg cost | Monthly token cost |
|---|---|---|
| Light (150 sessions, mostly simple) | 150 × $0.10 | **$15** |
| Medium (1,500 sessions, mixed) | 1,500 × $0.15 | **$225** |
| Heavy (12,000 sessions, mixed) | 12,000 × $0.15 | **$1,800** |

### 4. CloudWatch Costs

**Metrics (GetMetricData):** $0.01 per 1,000 metrics requested
- Typical session: 5–20 metric queries → $0.0001–$0.0002 per session
- **Monthly: <$1** even at heavy usage

**Logs Insights:** $0.005 per GB scanned
- Typical query scans 50–500 MB of logs
- Investigation session (10 queries): ~2 GB scanned → $0.01
- **Monthly (medium usage):** 1,500 sessions × $0.01 = **$15**

### 5. Athena (S3 Logs Only)

$5.00 per TB scanned. Only used when AWS WAF logs go to S3 (not CloudWatch Logs).

- Typical query: 10–100 MB scanned → $0.0001–$0.0005
- DDL queries (CREATE/DROP TABLE): **free**
- **Monthly (if used):** <$5

### 6. AgentCore Memory (Optional)

Only incurred if Memory is enabled (`MEMORY_ID` parameter set).

| Dimension | Price |
|---|---|
| Short-term memory (CreateEvent) | $0.25 per 1,000 requests |
| Long-term memory storage | $0.75 per 1,000 records/month |
| Long-term memory retrieval | $0.50 per 1,000 requests |

**Typical usage per session:** 5–15 CreateEvent calls (one per turn) + 1 RetrieveMemoryRecords call (on session start).

| Usage level | Monthly events | Monthly cost |
|---|---|---|
| Light (150 sessions) | ~1,500 events + 150 retrievals | **<$1** |
| Medium (1,500 sessions) | ~15,000 events + 1,500 retrievals | **~$5** |
| Heavy (12,000 sessions) | ~120,000 events + 12,000 retrievals | **~$36** |

## Total Monthly Cost Estimates

| Usage Level | Infrastructure | AgentCore | Tokens | CloudWatch | Memory | Total |
|---|---|---|---|---|---|---|
| **Light** (1 engineer) | $8 | $0.15 | $15 | $1 | $1 | **~$25/month** |
| **Medium** (5 engineers) | $8 | $1.50 | $225 | $15 | $5 | **~$255/month** |
| **Heavy** (20 engineers) | $8 | $12 | $1,800 | $50 | $36 | **~$1,900/month** |

## Key Takeaways

1. **Token cost dominates.** Infrastructure and compute are negligible. The main cost driver is LLM usage.
2. **AgentCore is extremely cheap.** ~$0.001 per session because you only pay for active CPU (not I/O wait).
3. **CloudWatch Logs Insights is cheap.** $0.005/GB scanned. Even heavy usage stays under $50/month.
4. **Free tier covers infrastructure.** CloudFront, Cognito, and basic S3 are effectively free for internal tools.
5. **Cost scales linearly with usage.** No minimum commitments or reserved capacity needed.

## Cost Optimization Tips

- Use **Metrics before Logs** — metrics queries are 100x cheaper than log queries
- Keep investigation **time windows narrow** (≤6 hours) — reduces GB scanned
- Use **Athena for historical analysis** (S3 logs) — cheaper than keeping months of logs in CloudWatch
- Consider **Amazon Bedrock Batch inference** for scheduled reports (50% token discount)
- The agent's system prompt uses ~1,200 tokens — this is a fixed cost per session that cannot be reduced further

## Pricing References

- [AgentCore Pricing](https://aws.amazon.com/bedrock/agentcore/pricing/)
- [Amazon Bedrock Model Pricing](https://aws.amazon.com/bedrock/pricing/)
- [CloudWatch Pricing](https://aws.amazon.com/cloudwatch/pricing/)
- [Athena Pricing](https://aws.amazon.com/athena/pricing/)
- [CloudFront Pricing](https://aws.amazon.com/cloudfront/pricing/)
- [AWS WAF Pricing](https://aws.amazon.com/waf/pricing/)
- [Cognito Pricing](https://aws.amazon.com/cognito/pricing/)
