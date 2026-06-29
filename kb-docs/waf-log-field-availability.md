# Which WAF log fields are available, and when

Not every field exists in every WAF log record. Some are always there, some only appear when
the WebACL has a specific rule type, and some depend on the log backend (CloudWatch Logs vs
Athena/S3). When a field is missing, say so and explain the precondition — never treat a
missing field as "no data" or as a tool failure.

## Always present (no rule or config needed)

These appear on every record, on both backends:

- `action` (ALLOW / BLOCK / COUNT / CHALLENGE / CAPTCHA)
- `httpRequest.clientIp`, `httpRequest.uri`, `httpRequest.args`, `httpRequest.httpMethod`,
  `httpRequest.headers` (the full header array — this is where **Referer**, **User-Agent**,
  **Host**, **Cookie** live)
- **`httpRequest.country`** — the geo country (ISO code). Populated by WAF's own GeoIP for every
  request. It does NOT need a GeoMatchStatement rule. There is **no top-level `country` field** —
  country is only under `httpRequest`. (Value is `-` when WAF can't resolve the IP.)
- `terminatingRuleId`, `terminatingRuleType`, `webaclId`, `timestamp`, `formatVersion`, `labels`

## Conditional — only present when the WebACL has a matching rule

- **`clientAsn`** (the client's network/ASN) — **only logged when the WebACL contains an
  `AsnMatchStatement` rule.** Without an ASN rule the field is absent entirely (not null —
  absent). A Count-action ASN rule is enough to make it appear (it blocks nothing). `forwardedAsn`
  behaves the same way (ASN rule with `ForwardedIPConfig`).
  - **ASN value `0` means "unknown ASN"**, not a real network — treat it as undetermined.
- `captchaResponse` / `challengeResponse` — only when a CAPTCHA / Challenge action fired on the
  request (these carry `failureReason`: TOKEN_MISSING / INVALID / EXPIRED / DOMAIN_MISMATCH /
  NOT_SOLVED).

## Backend-dependent (CWL vs Athena differ — this is the subtle one)

**`clientAsn` availability is NOT the same on the two backends**, even with an ASN rule in place:

- **CloudWatch Logs**: logs are raw JSON. The moment the WebACL has an ASN rule, `clientAsn`
  appears as a top-level JSON key and the agent can query it immediately. No other setup.
- **Athena / S3**: the table only exposes the columns its `CREATE TABLE` DDL declares. The
  agent's self-created table (`DDL_TEMPLATE`) currently does **not** declare a `clientasn`
  column, so even if the S3 JSON files contain `clientAsn`, a query like `SELECT clientasn ...`
  fails with **`COLUMN_NOT_FOUND`**. To use ASN on Athena you must ALSO add the column to the
  table DDL and recreate the table — having the ASN rule is necessary but not sufficient.

`country` and the header fields (incl. Referer) are the same on both backends — `country` is in
the `httprequest` struct, Referer is extracted from the `httprequest.headers` array
(`element_at(filter(headers, h -> lower(h.name)='referer'),1).value`).

`ja3Fingerprint` / `ja4Fingerprint`: present on **CloudFront and ALB** WebACLs (WAF computes
them from the TLS Client Hello; no rule needed). Absent on API Gateway / AppSync / Cognito
regardless.

## Adding a column to an Athena table does NOT backfill history

The agent's Athena tables use a JSON SerDe (schema-on-read). Adding a new column like
`clientasn` and recreating the table is **safe** — for any log record whose JSON lacks that key,
the column simply reads **NULL** (it does not error, and it does not break existing queries).
But it also does **not** make old data appear: history written before the ASN rule existed has
no `clientAsn` in the JSON, so it stays NULL forever. Only records written *after* the rule was
added carry a real value.

So two independent conditions must BOTH hold for ASN data to be queryable on Athena:
1. the WebACL had an `AsnMatchStatement` rule **when the log was written**, AND
2. the Athena table DDL declares a `clientasn` column.
Neither can be applied retroactively to old logs.

## When a "bring-your-own-table" lacks the ASN column

If the user pointed the agent at their own Athena table (BYOT) and it has no `clientasn`
column, the agent must not modify or recreate the user's table — that's the user's schema. But
it can offer to build a **separate, parallel table** in its own working database that points at
the same S3 log data and includes the ASN column. The user's table is left untouched; the
parallel table is just a different read-only view over the same files.

Explain to the user, when this comes up:
- **Why a new table is needed:** their table's definition doesn't include the ASN field, and an
  Athena table can only return columns its definition declares. Their table stays as-is; the
  agent builds an additional one alongside it.
- **The prerequisite:** ASN only lands in the logs at all if the WebACL has an ASN match rule
  (a Count rule is enough, it blocks nothing). Without that rule, even the new table shows ASN
  as empty.
- **What it will and won't show:** only traffic logged *after* both the rule and the new table
  exist will have ASN values; older logs stay empty (no backfill).

This is a description for the agent to explain the situation to the user. The actual table
creation is done by the agent's table-building tool, not by hand-writing SQL — so this doc
deliberately contains no `CREATE TABLE` statement.

## How the agent should behave

- If a query needs `clientAsn` and the field/column is missing, tell the user **why**: "ASN
  isn't in your logs because the WebACL has no ASN match rule" (CWL) or "…and the Athena table
  needs a `clientasn` column" (Athena). Offer the fix (add a Count-action `AsnMatchStatement`,
  ~1 WCU, blocks nothing; for Athena also recreate the table). Do not silently return empty.
- Treat missing `country` value `-` and `clientAsn` `0` as "undetermined", not as real data.
- Don't infer "no malicious traffic" from a missing conditional field — the field may just be
  unconfigured.
