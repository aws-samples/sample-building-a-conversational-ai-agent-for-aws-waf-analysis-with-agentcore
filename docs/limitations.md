# Known Limitations

English | [中文](limitations_zh.md)

What this agent cannot do, or cannot do without a cost you should know about. Read it before you conclude something is broken.

**Two rules govern this file, and they are here because a limitations list rots in the dangerous direction.** A limitation that has since been fixed is worse than no list at all: you read "it cannot do X", stop trying X, and never find out. So every entry below either points at the code that makes it true, or carries the date it was measured, and an entry that stops being true gets deleted rather than softened. Entries describe the design. What a particular deployment happens to be running is not here.

## Not supported yet

These three are support boundaries rather than trade-offs. Each one is on the [roadmap](roadmap.md).

**CloudFront WebACLs only. A REGIONAL WebACL, on an ALB, API Gateway or AppSync, is not supported.** The
agent declines one at the point you select it: every tool that takes a scope refuses `scope="REGIONAL"`
and returns a fixed message saying so, and it cites [`kb-docs/regional-alb-and-parquet.md`](../kb-docs/regional-alb-and-parquet.md)
for the reason. It refuses rather than analysing because the report it would return looks populated: the
allowed, blocked and per-rule totals come back correct, while everything derived from labels, attacks,
bots, countries and the anti-DDoS rule group reads as zero. That is, in the weekly report, the anti-DDoS
section, the bot analytics and the country breakdown; in the patrol, the attack chart, the targeted signals
and the bot names; in the overview, the attack-type breakdown, the bot names, the targeted signals and the
top labels. The cause is a dimension. A REGIONAL WAF metric carries `Region` and a CloudFront one does not,
`GetMetricData` matches a metric by its complete dimension set, and 22 of the 22 literal `SEARCH` schemas in
[`tools/report.py`](../tools/report.py), [`tools/waf_patrol.py`](../tools/waf_patrol.py) and
[`tools/waf_overview.py`](../tools/waf_overview.py) omit it. Measured 2026-09-17 on a real REGIONAL WebACL:
the same label metric returns eight datapoints with `Region` present and zero with it absent. A report that
looks whole while those sections are silently empty is worse than declining, so the agent declines.

**The agent has to run in the account that owns the WebACL, and that account has to be able to read the
log bucket.** WAF will deliver logs to an S3 bucket in a different account, and that arrangement is not
supported here, in either placement. Run the agent in the WAF account and the log bucket is remote, so
reads need a bucket policy and, under SSE-KMS, a key grant that nothing in
[`deploy/backend.yaml`](../deploy/backend.yaml) creates; the resulting `AccessDenied` surfaces as "the log
path was not detected" rather than as a permissions error. Run it in the log account instead and there is
no WebACL there at all, so [`tools/waf_config.py`](../tools/waf_config.py) cannot resolve one and nothing
downstream starts, while the CloudWatch metrics stay behind in the WAF account. The agent assumes no role
in any other account, anywhere in its code. This applies to a CloudFront WebACL exactly as it does to a
REGIONAL one: logs delivered outside the deployment account are out of scope for now.

**Parquet WAF logs work only when the log destination itself holds Parquet; a Parquet copy you keep in a
separate prefix is not read.** The SQL is written against the WAF schema (the nested `httprequest` struct,
the `labels` array) independent of storage format, and Athena's Parquet reader case-folds field names, so a
Parquet table is queried like a JSON one, camelCase nested fields (`httpRequest.clientIp`) included, verified
2026-09-17 with every query shape returning real values. The constraint is where the table points. The agent
adopts an existing table only when its `LOCATION` is the log path the WebACL resolves to, or an ancestor of
it (`_path_covers` in `tools/waf_athena.py`). So Parquet works when your logs are delivered as Parquet to
that destination **and you already have a Glue table over it**: the agent adopts an existing table, it does
not create one over Parquet the way it does over JSON, so a Parquet destination with no table yet finds no
`.gz` objects either and raises rather than reading your logs. It does not work if you keep JSON there and
convert a second copy to a side prefix: that
table's `LOCATION` is a child of the log path, so the agent never matches it and answers from a JSON table it
builds instead, and there is no tool to point the agent at a table by name or path. Over a bucket with no
table it looks for `.gz`, so it will not auto-build over Parquet either.

## What WAF logs can and cannot tell you

**A log proves a request arrived and which rule matched it. It does not show what your application did with it.** The agent will not tell you an exploit succeeded, because the data cannot support that. Settling it needs your origin logs, response codes or application errors ([`tools/waf_injection.py`](../tools/waf_injection.py) states this in the finding it produces).

**Match details exist for SQLi and XSS only.** WAF records the `matchedData` field for those inspections and no others, so for a rate-based rule, an IP-set match, a size constraint or most managed-rule hits there is no field saying which part of the request matched. The agent says so rather than guessing, and it lowers its confidence accordingly ([`tools/waf_block_fp.py`](../tools/waf_block_fp.py)).

**CloudWatch metrics carry three dimensions: `WebACL`, `Rule` and `Region`** ([`tools/waf_metrics.py`](../tools/waf_metrics.py)). Rule-level questions are therefore free and fast. Anything per-URI, per-IP, per-country or per-fingerprint has to come from a log query, which costs money and time.

**A WAF log filter drops records before they reach your destination, and the agent cannot correct for it.** When one is active it says so on every affected result, but any count or rate computed from logs is low by an amount only your filter configuration knows. Cross-check against metrics, which the filter does not touch ([`tools/session_state.py`](../tools/session_state.py)).

**JA4 TLS fingerprints are absent on API Gateway and AppSync upstreams.** So on those upstreams "one client behind many IPs" cannot be distinguished from "many separate clients", and the agent says the distinction cannot be made rather than picking one ([`tools/waf_injection.py`](../tools/waf_injection.py)).

## Query cost and partitioning

**Hourly-partitioned logs scan more data per query than minute-partitioned ones.** The agent accepts hourly logs deliberately, and warns before an expensive scan; the extra cost is the standing trade rather than a defect. [Hourly vs minute partitioning](hourly-vs-minute-partitioning.md) has the measurements.

**A bucket whose layout changed partway can be addressed by one table at a time.** A minute-format table returns zero rows for the period before the cutover. Reaching that history means keeping an hourly-format table over the same bucket; the agent tells you the cutover date and which era the table it used can address.

**Athena bills by bytes scanned, and the agent caps the time window rather than the spend.** A wide window on a busy WebACL is expensive whether or not it returns anything.

## Sessions and timeouts

**One session is one microVM: 15 minutes idle, 8 hours maximum.** An investigation that pauses for longer than the idle timeout resumes in a fresh session. Continuity across sessions comes from stored history and memory, not from the container, so anything the agent worked out but never wrote down is gone.

**You can stop a runtime session but you cannot list them.** `StopRuntimeSession` takes a `runtimeSessionId` and an `agentRuntimeArn`, and no operation in either AgentCore API returns the ids of a runtime's live sessions. `ListSessions` exists but is memory-scoped: its required inputs are `memoryId` and `actorId`. Verified 2026-09-12 across all 218 operations in the two AgentCore APIs, read from the service models botocore ships, and [`tests/test_limitations_hold.py`](../tests/test_limitations_hold.py) re-checks it every time the suite runs, so this is the one entry here that goes red on its own if AWS adds the operation. So a stuck session has to be waited out rather than found and stopped.

**A corporate proxy with a short read timeout will cut a streaming answer mid-flight.** Sixty seconds is a common default. Nothing in this product can extend it; the answer is usually still being produced on the server side.

## Scope of what it touches

**Read-only on your WAF, CloudWatch and Athena data.** The only things it writes are its own Athena temporary tables and its own session and memory records ([`AGENTS.md`](../AGENTS.md) lists the exact grants; [IAM permissions](iam-permissions.md) has the policy).

**One WebACL per session, and switching resets the session context.** Logging configuration, capabilities and accumulated findings all belong to the WebACL that was selected. Every log result names the WebACL it answered from, so you can tell when the context is not the one you meant.

**Secret-looking values are masked before display and the agent will not judge an attack inside one.** A cookie, `Authorization` header, session token or API key is replaced with its length. The WAF rule inspected the real value; the agent will not show it to you and will not tell you whether a payload was hiding in it. See [Data privacy](data-privacy.md).

## Model behaviour

**GPT-family models on Amazon Bedrock can stall silently on this workload.** Every prompt here is full of SQLi, XSS, bypass and payload, and upstream cyber-safety checks can stop a response with no error, which looks like the agent hanging. Use Claude Sonnet 5. This is not a limitation we can fix from inside the agent.
