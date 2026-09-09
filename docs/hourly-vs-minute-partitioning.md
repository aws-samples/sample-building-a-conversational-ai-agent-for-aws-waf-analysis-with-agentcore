# Hourly vs Minute Log Partitioning in WAF Analyst

English | [中文](hourly-vs-minute-partitioning_zh.md)

If your AWS WAF logs reach S3 through Amazon Data Firehose, the delivery stream's S3 prefix
decides how Athena can read them later. The default prefix is **hourly** (`YYYY/MM/dd/HH/`);
you can also configure a **minute-level** prefix (`YYYY/MM/dd/HH/mm/`). WAF Analyst works with
both. This document explains the difference, what it costs you on hourly, and how to decide.

The short version: **hourly logs work.** They cost more to scan and are somewhat slower per
query, and you should know that going in, but the difference is far smaller than it looks,
because of how Athena reads data. If per-query cost matters to you, switch to a minute-level
prefix; if you'd rather not touch your Firehose config, hourly is a supported choice.

## How Athena reads partitioned logs

Athena prunes by partition **directory**. With a minute-level layout, a query for 14:30–14:35
reads only those five minute-directories. With an hourly layout there is no sub-hour
directory, so the same query has to read the entire `14/` hour, and a query that straddles two
hours (say 13:58–14:03) reads both hours in full. This is the core difference: **on an hourly
table you cannot ask for less than an hour of data.** Asking for 5 minutes and asking for 60
minutes scan exactly the same bytes.

That has a real cost, and it is honest to name it:

- **You scan more bytes, so you pay more.** Athena bills by bytes scanned. An hourly query
  reads a whole hour even when you wanted five minutes, so it costs more per query than the
  same investigation on a minute-level table.
- **Queries are somewhat slower.** More data per query is more work. It is slower. How much
  slower is the part most people get wrong, which is the next section.

## Why hourly is much less slow than it looks: Athena parallelism

This is the point that is easy to miss, and missing it makes hourly sound far worse than it
is. **Athena does not read a scan serially.** It splits the data into pieces and reads many of
them in parallel across a large fleet. For gzip-compressed WAF logs, roughly one S3 object is
one split, so the work is spread across however many objects your window covers. The number of
partition directories does not drive this parallelism; the number of objects does.

The consequence is that **scanning several times more data does not take several times
longer.** In our testing (details below), an hourly query that scanned about 4× the bytes of
the equivalent minute-level query finished in essentially the same wall-clock time, and a full
6-query analysis chain that scanned 5× the bytes on hourly ran only about 25% slower than on
minute-level. The extra bytes are real (you pay for them), but Athena absorbs most of the time
cost by reading them in parallel.

So the trade is mostly **cost**, not **speed**. That is the opposite of the intuition that
"12× the data means 12× the wait," and it is why hourly is a supported configuration rather
than a blocked one.

## What we measured

A clean-room test: two CloudFront distributions, each behind its own WAFv2 WebACL (11 free AWS
Managed Rule groups + Bot Control COMMON), logging through Firehose to S3 with GZIP, one on the
default hourly prefix and one on a minute prefix. We drove ~4000 requests/second of
browser-User-Agent traffic at each and replayed WAF Analyst's own analysis SQL against both
tables.

At 4000 RPS, one full hour of logs was **~14.4 million rows ≈ 1.1 GB scanned** (gzipped).

**Single aggregation, unaligned 30-minute window** (crosses an hour boundary, so hourly must
read two whole hours):

| Table | Bytes scanned | Wall time |
|---|---|---|
| Hourly | 2108 MB | ~13 s |
| Minute | 545 MB | ~13 s |

Hourly scanned **3.9× the bytes** and took **the same wall time** — parallelism at work. This
is the case where minute-level saves the most bytes, and even here it saves no time on a single
query.

These are a fair fight: both tables used a narrow partition-projection range, so query-*planning*
time was ~0.2–0.3 s on each and is not skewing the comparison. (A minute table left on an
over-wide projection range pays several seconds of extra planning per query, which would make
minute-level look artificially slow. We measured that separately and kept it out of these numbers,
so the wall times above reflect scan-and-compute, not planning overhead.)

**Full analysis chain** (the longest one, a bypass scan: 6 independent aggregation queries run
back to back):

| | Queries | Bytes scanned | Wall time |
|---|---|---|---|
| Hourly, 2-hour window | 6 | 16.0 GB | ~166 s |
| Minute, 30-minute window | 6 | 3.2 GB | ~133 s |

Hourly scanned **5× the bytes** for only **~25% more wall time**. Note also that even the
minute-level chain took over two minutes: the dominant cost here is the *number of queries run
back to back*, not the partition layout. That is a separate matter WAF Analyst handles on its
own side, independent of your partition choice.

**A note on scale.** 4000 RPS is about 10 billion requests/month, which is a normal production
figure but not a peak. Real traffic has daily peaks and attack spikes several times higher, and
large customers run well above this. At a true production peak, one hour is many times 14.4M
rows, so per-query cost and time both rise — the numbers above are a floor, not a worst case.
The relative picture (hourly costs more bytes, parallelism keeps the time close) holds; the
absolute seconds grow with your volume.

## How to decide

- **Staying on hourly is fine.** WAF Analyst will run log-detail analysis on hourly logs. It
  will note that scans are larger and cost more, so you know what you're paying for. If your
  traffic is modest, you may never notice.
- **Switch to minute-level if per-query scan cost matters**, or if your volume is high enough
  that reading a whole hour per query is wasteful. It is a one-time, in-place Firehose prefix
  change with no stream recreation, no data loss, and no downtime. See
  [firehose-minute-partitioning.md](firehose-minute-partitioning.md) for the exact steps.
- **CloudWatch-metrics analysis is unaffected** either way — traffic trends, top rules,
  blocked vs allowed, spike detection all work the same on hourly, because they read
  pre-aggregated metrics, not raw logs.

One asymmetry to know if you switch: after moving to a minute prefix, logs written from that
point on are queryable at minute granularity, but logs written *before* the switch stay in
their hourly directories and remain queryable only through CloudWatch metrics, not through
minute-level log queries. Your raw objects are never lost; only the detail-query path changes.

**Since 2026-09-09 that asymmetry is something you can hit, not just something to plan around.**
Detection used to misread a bucket holding both layouts as hourly, which refused every log-detail
query outright. It now reads such a bucket as minute-level, so recent windows work and a window
from before the cutover comes back with zero rows and no error. To read that history, build a second table
over the old range with an hourly `projection.<col>.format`, because an hourly table can read
minute-nested objects while a minute-level one cannot read hourly ones.

Two things about that table, and both matter more than they look:

- **End its `projection.<col>.range` at the cutover, not at `NOW`.** A closed end in the past is
  deliberate here. WAF Analyst refuses to resolve a table whose projected range has already stopped,
  and that refusal is what keeps the history table from shadowing your minute-level one. A history
  table ending at `NOW` sits at the same S3 location as the minute-level table, wins discovery because
  a table you maintain outranks the agent's own, and then every log-detail query is declined on
  hourly scan cost, including the recent windows that worked before you added it.
- **Query the history table in the Athena console**, not through WAF Analyst. Following from the
  above, the agent will not resolve it, and it will say so: the query output lists the table with
  `projection range ends at ..., already in the past` as the reason it was passed over. That note is
  expected, not a misconfiguration.

Telling you the cutover date, so you know where one table's coverage ends and the other's begins, is
on the [roadmap](roadmap.md).

## External factor

Some corporate proxies close idle connections early (for example a 60-second
`proxy_read_timeout`). That is a network setting outside this product's control, mentioned only
so a slow response through such a proxy isn't mistaken for a product limit.

---

*Appendix — test setup: us-east-1; CLOUDFRONT-scope WebACLs with Bot Control COMMON
`Version_6.1` (2025 WCU); private S3 origin via OAC; Firehose GZIP, 64 MB / 60 s buffer;
`vegeta` load on c7g.2xlarge; Athena partition-projection tables using WAF Analyst's own DDL
schema, both built with a narrow projection range (start date at the data's actual beginning,
not the DDL's historical default) so planning time is negligible and equal on both — the wall
times compare scan-and-compute, not projection overhead. Full-hour partitions measured at
14,369,773 and 14,386,572 rows. SQL replayed verbatim from the bypass-scan methodology.*
