# Changelog

## Unreleased

### Added: Athena queries are cancelled too, and the message stops overclaiming

- **Both engines now cancel a query the agent has given up on.** Athena bills for data scanned
  up to the cancellation, so an abandoned query was billed for its whole scan. Measured on a
  real query: cancelling at the poll budget costs about 0.8 seconds of continued scanning
  against up to 28 minutes avoided, because Athena's own DML timeout is 30 minutes.
- **Needs one new permission, `athena:StopQueryExecution`.** Redeploy to pick it up. Until you
  do, the cancel is denied and the message says the cancel did not go through, which is true,
  so nothing breaks and the redeploy can wait for a convenient moment.
- **The timeout message now says only what the engine confirmed.** CloudWatch reports whether
  it stopped a running query, so that case still reads "was cancelled, so it has stopped
  scanning". Athena's cancel returns an empty response and succeeds just as quietly against a
  query that had already finished, so it reads "a cancel was requested" and does not promise
  the scan ended. The old wording for a failed cancel claimed the query was definitely still
  scanning, which it could not know either.

### Fixed: a CloudWatch query the agent stops waiting for is now cancelled

- **It used to keep running and keep billing.** Logs Insights charges for data scanned up to
  the moment of cancellation, so an abandoned query was billed for its whole scan. All five
  give-up paths now cancel, through one helper rather than five copies.
- **The message says which of the two happened**, rather than one shared sentence that would
  have understated one engine and overstated the other. The wording it ended up with is
  described in the Athena entry above.
- No permission change was needed: `logs:StopQuery` was already granted, for a call that did
  not exist until now.

### Fixed: a deleted log bucket is reported instead of quietly accepted

- **Setup used to succeed over an S3 bucket that no longer exists.** If a WebACL's logging
  destination pointed at a deleted bucket and an Athena table was still declared over it, the
  table was accepted as valid and every query afterwards failed with a raw engine error
  naming the bucket. Setup now fails once, saying the path cannot be read, what S3 said, and
  that the bucket may have been deleted or the role may not be allowed to list it.
- **A bucket that is merely empty still works as before.** A table over a prefix that has not
  received data yet is trusted as declared, which is the whole point of that behaviour. The
  two cases used to be indistinguishable; only the unreadable one changed.

## 0.15.0 (2026-09-09)

### Added: a long query shows progress instead of going silent

- **The connection no longer goes quiet while a query runs.** The stream emitted only on
  text and tool events, so a four-minute Athena query was four minutes of zero bytes with
  the input box disabled and no stop control, which is indistinguishable from a crash. The
  stream now sends something at least every 10 seconds.
- **While an Athena query is running, that something says what it has scanned**, for example
  `Athena query running, scanned 2.10 GB, 45s of 120s`. Those numbers were already being
  fetched on every poll and discarded: `GetQueryExecution` reports bytes scanned while the
  query is still in flight.
- This fixes visibility, not duration. A visible slow query is still a slow query.
- **Known limitation**: during a patrol scan, which runs several queries at once, the
  progress line can blink off for a couple of seconds when one of them finishes before the
  others. It is a best-effort line, not a loss of the connection.


### Fixed: the poll budget was two of six, and shorter than it claimed

- **Two more per-query wait budgets existed under a different name.**
  `report._poll_log_query` carried `max_wait=120` and `waf_patrol._poll_log_query` carried
  `max_wait: int = 60`, spending it through `range(max_wait // 2)`. Neither was findable by
  looking for `MAX_POLL`, including by the test written to guard against exactly this, which
  matched a string rather than the idea and now walks the syntax tree instead. **Patrol's
  per-query budget goes from 60 s to 120 s** as a result; no reason for 60 was ever
  recorded, and patrol's queries are small aggregates that rarely approach either number.
- **The budget is wall-clock now, not a count of sleeps.** Each poll also pays an API round
  trip, which the old arithmetic ignored, so a budget described as 120 seconds ran 131 when
  measured against real Athena, and it stretched on a slow connection and shrank on a fast
  one.
- **An Athena query the engine fails now says so like the CloudWatch one already did**, with
  the engine's own reason kept and the "this is not an absence of traffic, do not re-run it
  unchanged" guidance added. Found by running a wide query for real: it came back
  `HIVE_S3_THROTTLING`, which is exactly the failure where retrying immediately makes things
  worse, and nothing said not to.
- **A timeout no longer tells you the window was too large.** It could not know that: on the
  bucket this was tested against the window was fine and the object count was the problem.
  Narrowing is still what it suggests, because that is the only lever available, but it now
  names both possible causes and says it cannot tell which.

### Fixed: one slow query could cost a whole patrol report, on both backends

- **A fan-out timeout now costs the per-rule detail section, not everything.** `patrol_scan`
  submits three queries per rule to a thread pool, and the timeout `as_completed` raises
  comes from the iterator rather than from inside the loop, so the handler in the loop body
  never saw it. On the CloudWatch path it propagated out and killed the report; on the Athena
  path an outer handler swallowed it and silently discarded both the details already
  collected and the resolved-table message. Whatever finished is kept now, on both.
- **Patrol returns when it stops collecting, instead of waiting for work it discards.** The
  thread pool was a `with` block, and exiting one waits for every submitted query even after
  the collection loop has given up on the results. Fifteen queries over five workers is three
  waves, so a patrol could return after roughly six minutes while throwing away two thirds of
  what it waited for. It now cancels what has not started and returns at the batch budget.
- The batch budget has a name, `MAX_FANOUT_WAIT`, beside `MAX_POLL`, and both fan-out sites
  use it; one of them had the number as a bare literal.

### Known gaps, unchanged by this release

- Nothing cancels a query the agent stops waiting for, so it keeps running and keeps
  billing. `logs:StopQuery` is granted for a call that does not exist.
- `report._poll_log_query` and `waf_patrol._poll_log_query` still return partial or empty
  results on a timeout with no way for the caller to tell, and the weekly report attributes
  any missing section to an idle WebACL.

## 0.14.0 (2026-09-09)

### Fixed: repeated log queries paid AWS control-plane calls they did not need

- **A warm session no longer re-resolves the log destination on every query.** Each
  Athena query re-ran the destination-to-S3-path translation first, which on a Firehose
  destination is a `DescribeDeliveryStream` per query. That call is capped at 5 requests
  per second per account per Region and the quota is not adjustable, so a busy
  investigation could hit `ThrottlingException` and surface as a hard failure rather than
  as slowness. The path translation and the Athena output location are both memoized now,
  each behind its own lock.
- **Patrol scans share the resolved-table cache** instead of paying a full Glue
  enumeration and S3 walk on every scan. There was one cache for the query path and none
  for patrol, plus a second copy of the same table value in the query layer that nothing
  reset. One resolver, one cache, one lock.

### Fixed: a slow CloudWatch query was reported as "no traffic"

- **A query that ran past its poll budget returned zero rows**, and zero rows was
  reported as `Query returned 0 results` with three suggested reasons, none of which was
  "the query never finished". A stopped query now says it was stopped. So does one
  CloudWatch reports as `Failed` or `Cancelled`, which used to print `Query Running.
  QueryId: ...`, and that is internal state rather than an answer.
- **A timeout no longer starts an unbounded retry loop.** The old message told the model
  to narrow the window and retry, the prompt separately promised it was "always able to
  reduce until query succeeds", and nothing counted attempts. Three tries was fifteen
  minutes with nothing on screen. The first timeout now invites exactly one narrower
  retry and the second withdraws the invitation; any successful query resets that.
- **The poll budget is 2 minutes everywhere.** It was five separate constants reading
  120, 120, 120, 300 and 600 seconds for the same "wait for one query" job, two of them
  in files that never used them. **This is a real change for slow queries**: on
  high-volume logs, some that previously returned after several minutes will now be
  stopped instead. That is deliberate, and it is only reasonable because a stopped query
  now explains itself rather than failing silently. Raising the number is almost always
  the wrong response to a timeout; the query that needs it has usually failed to prune.

### Fixed: every Athena query paid a few seconds of planning it did not need

- **The projected partition range now starts where your data starts**, floored to the
  first of that month, instead of a fixed `2020/01/01`. Athena expands the whole
  declared range before it applies the `WHERE` clause, so planning time followed the
  table properties rather than the window you asked about. On a small test bucket,
  five tables differing in nothing but this value, the same 5-minute query spent 4.4
  to 5.0 s planning with the old start and 0.19 to 0.25 s with a start two months
  back, scanning identical bytes. It also brings the table under Athena's limit of
  1,000,000 partitions per scan, which the old range exceeded on its own and which
  only a `log_time` predicate on every query was keeping survivable.
- **A table the agent built earlier is rebuilt to pick this up.** Without that, the
  change would have reached new installations only: a scratch table declaring the old
  `2020/01/01` range still matches its bucket on format, interval and unit, so it
  passed every check, was reused, and kept paying the planning cost with nothing left
  to trigger a rebuild. A table *you* maintain is not touched. A range wider than your
  data is your choice there, it costs only planning time, and a window falling outside
  it is already reported.

### Added: a bucket that changed partition layout says so, and says from when

- **The `TABLE:` block now names the day minute-level querying begins and the date of
  the oldest data in the bucket**, on any bucket holding both an hourly era and a
  minute-level one. `projection.<col>.format` holds one value, so no single table
  describes both, and everything between those two dates sits in hourly directories
  that no minute-level table can address. Athena answers those paths with zero rows
  and no error, which is the reason to say it up front.
- **The out-of-range message no longer tells you to widen the projection range** when
  the bucket is one of those. Widening cannot work there: the older directories are
  hourly, so a wider minute-level projection generates paths that do not exist, and
  following the advice looks like confirmation that the data is gone.
- **Zero-result output names the table it queried.** It returned before the `TABLE:`
  block, so the three suggested reasons stood alone, and on a window that straddles a
  layout change all three are wrong.
- The projection start is exact at month granularity and never later than your
  minute-level data. The cutover *day* comes from a search inside that month and
  assumes the layout changed once, so it is reported as best-effort.

### Fixed: the first log query of a session listed the same S3 prefixes repeatedly

- **Resolving a table walked the bucket once but listed 15 prefixes twice**, because
  finding where the layout begins descends the newest year, then descends it again
  looking for the cutover, then descends candidate months. Measured against real S3
  on a two-era tree: 34 `ListObjectsV2` calls covering 19 distinct prefixes, now 19
  calls with identical results. The cache is scoped to one walk on purpose. A bucket
  gains directories while the agent is running, and a cache that outlived the walk
  would hand back a stale newest directory and pin the projected range behind the
  data.

### Development

- 102 tests, up from 60. The new ones cover where the partition layout begins, a
  bucket that alternates between the two layouts, the zero-result message, the
  no-prefix-listed-twice invariant, the retry bound, and a stopped query not reading as
  zero rows. Run them with `uv run --extra dev python -m pytest tests/ -q`.
- Each fix in this release was checked by removing it and requiring its test to fail.
  Several tests passed on first writing while the defect they targeted was present, so
  the perturbation is the check that matters rather than the green run.

## 0.13.0 (2026-09-09)

Thanks to @vishallakhotia (#12), whose refactor made the partition column and its
projection format first-class instead of hardcoded. Everything under "reuse a WAF
log table you already maintain" below rests on that, and so does the partition-bound
widening, which has to be expressed in projection-interval units and could not have
been written before those units existed anywhere.

### Fixed: log queries were silently returning fewer rows than they should

Three separate bugs, all in partition pruning, all with the same shape. No error,
no warning, a plausible answer built on a fraction of the data.

- **Partition bounds are now widened by one projection interval on each side.**
  Pruning used the same bounds as the `"timestamp" BETWEEN` filter, which assumes a
  record timestamped inside minute *M* lives in directory *M*. It does not. Firehose
  names an object after the arrival time of the record that opened the buffer, and one
  object holds a whole buffer window, so the minute in the path bounds the timestamps
  inside it in neither direction. Measured on a minute-level bucket, one directory
  spanned 76 seconds and reached 28 seconds before its own label; the partition clause
  dropped 5.70% and 8.12% of rows on two 5-minute windows and 0.23% on an hour. Worst
  on the narrow windows the timeout guidance recommends. `"timestamp" BETWEEN` is
  unchanged and still exact, so this only stops excluding rows inside the window.
- **A bucket that switched from hourly to minute-level Firehose prefixes is now
  detected as minute-level.** Detection walked into the *earliest* directory at every
  level below the year, which on such a bucket is pre-cutover hourly data. The table
  was pinned to `yyyy/MM/dd/HH` permanently, because no amount of new
  minute-partitioned data changes a walk that never looks at it. Anyone who followed
  [the minute-partitioning guide](docs/firehose-minute-partitioning.md) still has
  those old paths, so this affected all of them.
- **Minute-level tables always declare projection interval 1.** The interval used to
  be inferred by subtracting two minute directory names. Firehose's
  `!{timestamp:mm}` emits whatever minute the buffer flushed at, so those names are
  arbitrary values like `03`, `07`, `41`, and the difference was meaningless. A guess
  of 5 makes partition projection generate paths only at `00, 05, 10, ...` and never
  read the objects under any other minute.

**Known limitation this introduces.** A mixed-layout bucket now resolves as
minute-level, and a minute-format table cannot read the pre-cutover hourly-era
objects, because the projected minute paths do not exist under them. Those queries
return zero rows with no error. To read that history, keep a separate
hourly-format table over the old range. The intended behaviour is to detect the
mixed layout and let you choose, which is still ahead: see
[the roadmap](docs/roadmap.md). Minute-level is the right default in the meantime,
since before this release the same bucket was misdetected as hourly and every
log-detail query was refused outright.

### Added: the agent can reuse a WAF log table you already maintain

- **The partition column no longer has to be called `log_time`.** Discovery accepts
  any single time column using partition projection of type `date`, so `datehour` or
  `dt` work, and pruning uses the table's own declared `projection.<col>.format`,
  which is the only correct thing to compare partition values against.
- **Log-detail queries still need a minute-level table**, meaning a format equivalent
  to `yyyy/MM/dd/HH/mm` with any separator you like. Hourly and daily formats are now
  understood and pruned correctly rather than misread, but the coarse-partition guard
  still refuses to run log queries against them, so being understood is not the same
  as being queryable. Accepting hourly is a separate change still ahead of this one.
- **Every log query names the table it ran against, and names any table it passed
  over with the reason.** Rejections are specific: integer or enum projections,
  non-projected Hive partitions, more than one partition key, an unusable format, an
  interval unit with no fixed length, and a projection range that has already
  stopped. "The agent built its own table" is not something you can act on by itself.
- **A table you maintain is preferred over the agent's own scratch table**, then the
  most specific location. Preferring specificity alone could not work: the scratch
  table sits at exactly the resolved path, so it always won.
- **Glue discovery is paginated.** A database past its first page of tables used to be
  invisible, and the agent would build its own table next to a perfectly good one.
- **Location matching respects path boundaries**, so a table at `s3://b/waf-logs` no
  longer claims `s3://b/waf-logs-prod`.
- **A query window outside the table's projected range is reported** instead of
  returning zero rows that read as an absence of traffic.
- WebACL scoping is now decided from the resolved table's own location rather than
  the requested S3 path. The two genuinely differ when a table sits on an ancestor
  prefix, and the resolved location is the only one that describes the data a query
  will actually read. Stated narrowly on purpose: no delivery method AWS offers
  produces a layout where the old comparison caused real cross-WebACL contamination,
  because vended logs put the WebACL name above the date so an ancestor table cannot
  span two of them, and a Firehose bucket root carries no WebACL name at all so the
  old comparison already reached the right answer. A custom pipeline that puts
  several WebACLs under one date-shaped tree could reach it, which is reason enough
  to score the correct input.

### Fixed: timezones

- **Partition pruning honors the partition-path timezone.** Partition bounds were
  always derived in UTC, so a table whose S3 directories are written in local time
  had its data silently pruned away: a 12:16 local event lives under `.../12/16`
  while the query looked under `.../16/16`, returning zero rows while metrics showed
  traffic. Bounds are now derived in the actual partition timezone, resolved as env
  `WAF_AGENT_PARTITION_TZ` > auto-detected Firehose `CustomTimeZone` > UTC (the
  vended-log default). A custom local-time ETL is not detectable, so the env var is
  the way to declare one. IANA names (DST-aware) and fixed offsets are both accepted;
  added the `tzdata` dependency so IANA zones resolve inside the slim container.
- **Log-query timestamps respect the session timezone.** `get_waf_overview` already
  returned session-local times but `run_logs_query` and `analyze_ip` returned UTC,
  because Athena's `from_unixtime()` renders in UTC and CloudWatch Logs Insights
  `bin()` / `@timestamp` are UTC. The mismatch made the agent misreport the hour of an
  event, showing a 14:00 EDT incident as 18:00. Time-based Athena templates now offset
  the epoch by the session timezone inside `from_unixtime()`, and CWL results are
  shifted in Python. Grouping-only rate subqueries (peak and average rpm) are
  unchanged, since their per-minute bucket is never displayed. The system prompt
  states that these timestamps are already session-local so the agent does not
  re-label them as UTC.

### Security / Dependencies

- Dependency maintenance (Dependabot).
  - Frontend: `dompurify` `3.4.12` → `3.4.13`, `postcss` `8.5.15` → `8.5.24`
  - Backend: `cryptography` `48.0.1` → `50.0.0`, `bedrock-agentcore` `1.11.0` → `1.18.1`,
    `mcp` `1.27.1` → `1.28.1`
- **`bedrock-agentcore` moved seven minor versions**, and it is the runtime SDK the agent
  is deployed onto rather than an ordinary library, so it is worth naming separately.
- Neither security advisory in this batch is reachable in this code, stated so that a
  reader does not go looking. The `dompurify` release fixes two `IN_PLACE` sanitization
  issues and a hook bypass, while `frontend/src/App.jsx` calls
  `DOMPurify.sanitize(marked.parse(...))` with no hooks and no `IN_PLACE`. The
  `cryptography` release fixes a Bleichenbacher timing oracle in `pkcs7_decrypt_der`
  (CVE-2026-69247); `cryptography` is a transitive dependency here, nothing in the
  Python source imports it, and the agent decrypts no PKCS#7 messages. Both were taken
  anyway: staying behind on a sanitizer or a crypto library needs a better reason than
  "the current code does not reach it".

### Development

- First tests in the repo, 60 of them, covering table resolution and partition
  detection against a fake Glue catalog and a fake S3 tree. Run with
  `uv run --extra dev python -m pytest tests/ -q`. Glue, S3 and Athena are all faked,
  so these cover resolution logic and not AWS behaviour.

## 0.12.1 (2026-07-20)

### Security

- **Frontend: sanitize agent markdown before render (DOM XSS fix).** The chat window rendered
  `marked` output straight into `dangerouslySetInnerHTML`, and `marked` v18 does not sanitize.
  Agent answers routinely quote attacker-controlled log content (User-Agents, URIs, payloads),
  so a crafted `<script>` / `<img onerror>` in a WAF log field could execute in the main origin,
  where Cognito tokens live. Added `dompurify` and wrapped both `marked.parse` sinks
  (`App.jsx` chat render + the multi-message HTML export) in `DOMPurify.sanitize`. Zero analysis
  impact — malicious payloads still display verbatim as text/code, they just no longer execute.

## 0.12.0 (2026-06-24)

New detection/diagnostic signals, knowledge-base monitoring guidance, a friendlier
hourly-partition flow, a brand rename, and the dependency maintenance below.

### Bypass detection

- `detect_bypass` scan adds a **UA-rotation** filter: flags a single JA4 TLS fingerprint
  used behind many different User-Agents from few IPs (UA spoofing). Complements the
  existing single-JA4-many-IPs (distributed) filter; excludes `bot:verified`.

### Challenge/CAPTCHA investigation

- `check_challenge_compatibility` now reports a **Token Failure Reasons** breakdown
  (`TOKEN_MISSING` / `TOKEN_INVALID` / `TOKEN_EXPIRED` / `TOKEN_DOMAIN_MISMATCH` /
  `TOKEN_NOT_SOLVED`) alongside the existing URI/method compatibility table, so "why can't
  real users pass the challenge" covers both client-type and token-side causes.

### Hourly-partition handling

- When an Athena/Firehose table uses hourly partitioning, the agent still stops log-detail
  queries (scan-time/UX), but now retrieves the fix from the knowledge base and explains the
  cause + one-time Firehose change to the user inline, instead of dropping a repo link.

### Knowledge base

- New KB doc: **WAF hit-rate monitoring** — how to set up CloudWatch metric-math ratio
  alarms (and per-URI metric filters) to watch a rule's block/false-positive rate after a
  Count→Block switch. Agent advises; it does not create alarms (stays read-only).
- New KB doc: **Firehose minute-level partitioning** — why it's required and the exact
  one-time fix, retrieved when the agent blocks hourly-partition queries.
- Added a token-id cross-IP abuse note (one issued token across >5 IPs = reuse/botnet signal).

### Frontend

- Default UI brand renamed **"Amazon WAF Agent" → "WAF Analyst"** to avoid implying an
  official AWS product. Override via `VITE_BRAND_NAME` is unchanged.
- Fixed a white-screen bug introduced by the Vite 8 bump: `amazon-cognito-identity-js`
  references Node's `global`, which Vite 8 no longer shims — mapped `global` → `globalThis`
  in the build so the production bundle runs in the browser.

### Security / Dependencies

- Dependency maintenance (Dependabot).
  - Frontend: `vite` `^6` → `^8`, `@vitejs/plugin-react` `^4` → `^6` (clears the esbuild dev-server advisory; `npm audit` now reports 0 vulnerabilities), `@babel/core` `7.29.0` → `7.29.7`
  - Backend: `starlette` `1.0.1` → `1.3.1`, `cryptography` `48.0.0` → `48.0.1`, `python-multipart` `0.0.29` → `0.0.31`, `pydantic-settings` `2.14.1` → `2.14.2`

## 0.11.0 (2026-06-07)

Internal refactor + CloudWatch Logs query precision. No user-facing behavior change.

### CloudWatch Logs COUNT precision (#8)

- `evaluate_count_rules` CWL queries used two independent substring filters (`like '"ruleId":"X"'` AND `like '"action":"COUNT"'`), which over-matched when rule X co-occurred with a different rule's COUNT action. Replaced all three with a single contiguous match `'"ruleId":"X","action":"COUNT"'`, matching the precision the Athena path already had
- `patrol_scan` CWL content query now also matches COUNT rules (not only terminating ones), aligning the two backends

### Refactor (#7)

- Split the ~330-line `_step_investigate` into `_investigate_gather` (queries → dict), `_gather_match_detail`, and `_render_investigation` (pure formatting). Output is byte-for-byte identical; verified end-to-end

## 0.10.4 (2026-06-07)

Review follow-ups to 0.10.3 — redaction precision and the patrol content gap.

### Redaction precision (keep attacks visible, fix over-masking)

- Sensitive-name matching now tokenizes the name (camelCase + non-alphanumeric split) and matches whole tokens, instead of a substring regex. Fixes false positives (`author`→auth, `design`/`signal`/`assignee`→sig, `user_agent`) while still catching `accessToken`, `x-api-key`, `session_id`
- Query-string values: password-family params are always masked; other sensitive-named params are masked only when the value looks like an opaque credential. Attack payloads (e.g. `token=<script>alert(1)</script>`) now stay visible — an attacker can no longer hide an attack by naming the param `token`. Real JWTs / API keys / `Bearer …` tokens are still masked
- `redact_row_fields` gains a value-level fallback: masks a cell whose value contains an embedded credential assignment (`sessionid=…`, `Bearer …`) even when the column name is innocuous

### Patrol: per-rule detail + inspected content

- `patrol_scan` fetched per-rule top IPs/URIs but never rendered them (dead data) and never fetched the request payload. It now surfaces top IPs, top URIs, and the inspected content (redacted) for attention rules in the returned summary, so weekly reports judge attack vs. false positive from real payloads. Both CloudWatch Logs and Athena backends
- Content is redacted on both backends (the Athena content path originally returned raw args/cookie/headers under a "redacted" label — fixed so the label is truthful)
- `inspection_location` now returns `None` for `_BODY` rules (body is never logged) and defaults injection/web-exploit rule-group names (SQLi/XSS/RFI/LFI/Log4J/…) to the query string, so group-level findings still show payloads

## 0.10.3 (2026-06-07)

Investigation depth + privacy, found while demo-testing false-positive and COUNT analysis.

### Inspected Request Content by Rule Location

AWS WAF only records matchedData for SQLi/XSS statements. For every other managed rule the rule name encodes which request component it inspected, but the tools never pulled that component from the log — so the agent could not see WHY a request matched and resorted to guessing (e.g. it leaned toward "false positive" on COUNT hits that were actually XSS payloads in the query string).

- `investigate_block_fp` and `evaluate_count_rules` now surface the inspected component for the analysed rows, derived from the rule-name suffix: query string (`_QUERYARGUMENTS`/`_QUERYSTRING`), URI path (`_URIPATH`/`_URI`/`_PATH`), cookie (`_COOKIE`), and HTTP headers (`_HEADER`)
- `analyze_ip` now shows the IP's top query strings; `detect_bypass` (investigate_ip) shows query strings on ALLOW traffic — attack-like payloads that were allowed through are a direct bypass signal
- Works on both backends (CloudWatch Logs and Athena/S3); verified against real logs

### Privacy: Sensitive-Value Masking

- Secret values are masked as `<redacted len=N>` before display: all cookie values, sensitive headers (Authorization/Cookie/token/API-key/CSRF/…), and sensitive-named query params (token/secret/password/…). Attack payloads in non-secret params (e.g. `q=<script>…`) stay visible, and the WAF rule still inspected the full value
- `run_logs_query` masks sensitive columns (e.g. the raw Cookie value in `token_reuse_ips`) centrally in its result formatter, so every query type — current and future — is covered
- When content is masked, the tool instructs the agent to tell the user the masking is a deliberate privacy safeguard — not the agent being unable to see the data
- When a location yields no content, the tool flags that it may be empty OR redacted via AWS WAF logging `RedactedFields`, so "no data" is never reported as "no attack"
- System prompt and `docs/data-privacy.md` updated to state the agent does not display or judge attacks inside secret values

## 0.10.2 (2026-06-07)

Bug fixes found during demo testing of the false-positive investigation flow.

### Block FP Investigation: Match-Detail Extraction

- **Athena TYPE_MISMATCH fix**: `investigate_block_fp(step="investigate")` crashed on the Athena backend with `Cannot cast array(row(...)) to varchar` — the match-detail query did `CAST(terminatingrulematchdetails AS VARCHAR)` on an `array<struct<...>>`. The whole investigation aborted. Now flattened with `transform` + `array_join` into a readable line (e.g. `SQL_INJECTION location=ALL_QUERY_ARGS matched=credit,UNION,SELECT`)
- **Custom rules now covered**: match-detail extraction was gated on the managed-rule-group sub-rule name, so blocks by custom/REGULAR SQLi/XSS rules never showed why they matched. Removed the name gate — extraction runs for every block and is scoped by the match-details cardinality
- **CWL truncation fix**: the CWL path used a regex that truncated the nested match-details array at the first `]`. Replaced with a raw-message fetch + JSON parse
- **Consistent output**: CWL and Athena now emit the identical one-line match-detail format
- **Graceful degradation + observability**: a match-detail query failure no longer aborts the investigation; when details cannot be retrieved or parsed, the output says so explicitly so the agent reports it instead of guessing

### Agent Honesty Guidance

- System prompt now requires reporting tool errors verbatim: do not invent explanations ("query limitation"), do not silently fall back to another method and present it as success, and never fabricate or guess matched content when match details are unavailable

## 0.10.1 (2026-06-06)

Bug fixes and hardening found during end-to-end demo testing. No new features.

### Critical Fix: Tool Calls Before get_waf_config

- Tools that depend on session state (`investigate_block_fp`, `detect_bypass`, `evaluate_count_rules`, `check_challenge_compatibility`) could be called before `get_waf_config`, producing a misleading "no logging configured" error even when logging was active
- Added an explicit `get_webacl_name()` guard returning an actionable error ("call get_waf_config first") instead of the misleading one
- System prompt now requires `get_waf_config` immediately after WebACL selection
- Declared the `get_waf_config` prerequisite in the affected tools' docstrings (the layer the LLM consumes)

### Athena Table Detection Hardening

- **Delivery-method switch**: when a WebACL's log delivery changes (e.g. Vended Logs → Firehose), the scratch table kept pointing at the old S3 sub-path and every query scanned an empty location (0 rows while metrics showed traffic). `_create_named_table` now drops the stale same-named table before recreating, so any delivery/partition change self-heals on the next query
- **WebACL-switch stale cache**: the process-lifetime table cache is now reset on every WebACL switch, so querying a new WebACL never reuses the previous one's table
- **Concurrency**: serialized table setup with a lock + double-checked caching, and the table DROP is now conditional on a location mismatch (same-location creates skip the DROP), so concurrent queries on different paths (`query_logs` vs `patrol_scan`) can never drop a table mid-query
- **Multi-WebACL shared bucket**: when a table location is shared by multiple WebACLs (Firehose bucket-root), both Athena paths (`query_logs` and the independent `patrol_scan` detail path) now filter by `webaclid` to avoid cross-WebACL contamination
- **Incompatible table reuse**: only reuse Glue tables that have a `log_time` partition compatible with our partition pruning

### Knowledge Base

- Marked `AMAZON_BEDROCK_TEXT` / `AMAZON_BEDROCK_METADATA` as non-filterable in the S3 Vectors index to stay under the 2 KB filterable-metadata limit

### Internal Refactors

- Unified scope→region resolution on a single fail-loud `resolve_region(scope)` helper; retired the redundant `get_metrics_region` and the duplicated `"us-east-1" if CLOUDFRONT else ...` pattern across 6 call sites
- Removed 15 dead imports across `tools/` and `agent.py`

## 0.10.0 (2026-06-05)

### Detection Methodology Refinements

Reviewed and improved the core analysis methodology for false positive, bypass, COUNT→Block, and injection attack workflows.

### Bypass Detection: JA4 Cross-IP Aggregation (new filter)

- `detect_bypass(step="scan")` now includes a 5th anomaly filter: JA4 cross-IP aggregation
- Detects distributed scraping where a single tool (same JA4 fingerprint) spreads across many IPs, each below per-IP thresholds
- Requires `unique_ips > 10 AND total > 500 AND unique_uris > 50` to avoid false-positiving normal browser traffic
- Outputs representative IPs for drill-down into `investigate_ip`

### CWL Query Precision Fix

- `count_rule_top_ips`, `count_rule_top_uris`, `count_rule_top_uas` templates: CWL filter changed from `@message like '{rule_name}'` to `@message like '"ruleId":"{rule_name}"'` — prevents substring false matches
- `rule_uri_prefix` CWL: changed from `@message like '{rule_name}'` to `(terminatingRuleId = '{rule_name}' or @message like '"ruleId":"{rule_name}"')`
- `waf_count_eval.py` `_step_check_clients`: same fix applied
- Athena queries were already using structured fields — no change needed

### Managed Rule Group Sub-Rule Matching

- New query template `rule_block_top_ips`: fetches top IPs blocked by a rule, supporting both top-level `terminatingRuleId` and managed sub-rules in `ruleGroupList[].terminatingRule.ruleId`
- `rule_uri_prefix` Athena: added `rulegrouplist` sub-rule condition for managed rule groups (SQLi/XSS/LFI)
- This fixes the main injection investigation case where blocks come from managed sub-rules

### Athena COUNT Query: ruleGroupList Support

- All COUNT-related Athena queries (`count_rule_top_ips/uris/uas`, `waf_count_eval check_clients`) now check **both** top-level `nonterminatingmatchingrules` AND `rulegrouplist[].nonterminatingmatchingrules`
- RuleActionOverride COUNT entries live in ruleGroupList, not the top-level array — previous queries missed them entirely

### System Prompt Updates

- **Injection attack investigation**: 6-step deterministic sequence (overview → rule_uri_prefix → top_ua → rule_block_top_ips → analyze_ip → classify)
- **Confidence boundaries**: explicit statement that WAF logs cannot prove backend exploit success; FP requires business confirmation; bypass is "probable abuse" not "confirmed exploit"
- **Reactive investigation**: agent now asks for missing context (IP, time, business action) before running broad scans
- **COUNT workflow**: removed contradictory "do NOT manually query logs" instruction; tool output may direct follow-up `ip_cross_query` calls

### False Positive Output Wording

- Changed from "LIKELY FALSE POSITIVE" to "WAF-side likely FP candidate (needs business confirmation)"
- Added `missing_confirmation` note listing what evidence is needed to upgrade to confirmed FP

### Legacy Cleanup

- Removed `run_athena_query` decorated tool + `_build_query()` + `_time_filter()` from `waf_athena.py` (~310 lines of dead code)
- This tool was not registered in agent `_TOOLS` and had no callers. Helpers used by `waf_query.py` routing layer retained.

### Documentation

- Added model choice warning (Claude recommended, GPT-family may silently fail) to README, README_zh, deployment, deployment_zh, user-guide, user-guide_zh

### Knowledge Base

- New KB doc: `false-positive-scope-down.md` — 3 methods (label match, scope-down, sensitivity level) with complete JSON configs
- New KB doc: `sqli-xss-false-positives.md` — common FP scenarios by industry (financial/UNION+SELECT, WordPress/XML, SaaS/webhooks, base64 event handlers)
- New KB doc: `wordpress-waf-config.md` — full WordPress WAF configuration (recommended AMRs, priority order, custom rules, admin protection, FP handling)
- KB chunking: increased from 300 to 1000 tokens for better retrieval coherence
- New doc: `docs/athena-table-detection.md` — explains partition projection usage, existing table detection logic, match conditions, and known limitations
- New doc: `docs/athena-table-detection_zh.md` — Chinese version
- Fixed user-guide misleading "temporary Athena tables" wording → clarified tables are permanent and reused across sessions
- Added Athena query performance limitation to user-guide_zh (was missing compared to English version)
- Added doc links to README and README_zh

## 0.9.0 (2026-05-25)

### Breaking Change: `duration_hours` → `duration_minutes`

- All 6 log-querying tools renamed: `duration_hours` (float) → `duration_minutes` (int)
- `hours_ago` backward-compat alias removed entirely
- Integer arithmetic eliminates float→ParamValidationError bug class
- CWL: default 180 min, max 360 min. Athena: default 60 min, max 60 min (hard cap)

### New Query Types (6 added, total 36)

- `ip_uri_prefix` — URI path prefix clustering for an IP (crawl/scrape pattern detection)
- `rule_uri_prefix` — URI prefix clustering for a rule (FP vs attack signal for COUNT-to-BLOCK)
- `top_ua_by_action` — Global User-Agent distribution by action (bot/bypass detection)
- `ip_request_timeline` — Per-minute action timeline for an IP (rate-limit/DDoS analysis)
- `ip_label_breakdown` — All WAF labels on an IP (bot signals, Anti-DDoS, token status)
- `host_top_ips` — Top IPs per host/domain (multi-domain WebACL attack attribution)

### IP Attribution & Route 53 Misidentification Fix

- `ip_cross_query` now returns User-Agent in both CWL and Athena
- System prompt: mandatory IP identity verification before concluding malicious
- DDoS methodology step 6b: exclude benign services (Route 53 health checks, monitoring) using `bot:verified` label
- Query Type Selection Guide added to system prompt

### MetricStat for `top_rules` Totals

- `_top_rules` now gets `Rule=ALL` totals via MetricStat (immune to 14-day SEARCH index expiry)
- Previously, if Anti-DDoS rules hadn't fired in 14 days, weekly overview showed "0 mitigated" — now always accurate
- Gap warning fires correctly when per-rule SEARCH attribution is missing

### SEARCH Index Expiry Detection

- `attack_types`, `bot_names`, `targeted_signals`, `top_labels` now detect when SEARCH returns empty but MetricStat shows traffic exists
- Explicit ACTION hints guide LLM to inform user and use alternative queries (top_rules, bot_summary, logs)
- No false warnings when data genuinely doesn't exist

### Athena Reliability

- Auto-resolve Athena output location from WAF log bucket (fallback when workgroup not configured)
- Validate table path on reuse — detect log delivery method changes (Firehose ↔ Vended Logs)
- Validate partition format + interval on reuse — detect S3 structure changes
- Block queries on hourly partitions — guide user to configure minute-level partitioning
- `s3:PutObject` permission added (scoped to `athena-results/*` prefix only)
- Silent `return None` replaced with `RuntimeError` — errors now surface to LLM instead of showing "0 results"
- Strip Firehose dynamic expressions (`!{timestamp:...}`) from S3 prefix before path resolution
- Fix path validation: bucket root no longer incorrectly matches sub-path tables (Vended Logs → Firehose switch)
- Firehose S3 prefix time zone must be UTC — documented + LLM hint added

### Protection Coverage Assessment

- `get_waf_config` now reports protection status for Anti-DDoS, Bot Control, Rate-based, and Injection rule groups
- Detects action mode (Block vs Count), scope-down presence, rate-limit thresholds
- Flags protection gaps with ACTION hints — LLM informs user about unprotected areas

### Build & Deployment

- Build-time version injection (`version.json` with commit hash + timestamp)
- System prompt shows `Agent version: <commit> (<time>)` — users can verify container is current
- Deployment guide updated: always use unique commit hash tags (not `:latest`)
- `--build-arg BUILD_COMMIT` and `BUILD_TIME` documented for both Docker and finch

### `_step_analyze_rule` Refactor

- No longer auto-queries logs — returns peak hour + hit count + suggested `duration_minutes`
- LLM decides window size based on volume, then calls `check_low_volume_clients`

### Documentation

- User guide: metric discovery 14-day limitation, Athena output location, version check
- IAM permissions: `s3:PutObject` for Athena results, `glue:DeleteTable` restored
- Firehose minute-level partitioning guide (new doc)
- No-data caution rewritten to be user-friendly with actionable next steps

### Bug Fixes

- `_athena_cap_hit` dead code removed from `waf_bypass.py`
- Athena partition format mismatch — validate existing table before reuse
- Athena partition interval detection — use actual S3 interval (5min) not hardcoded 1
- Chinese IAM doc stale references fixed (`waf_agent_temp` → `waf_analysis_tmp`)

## 0.8.0 (2026-05-24)

### Breaking Change: `get_waf_overview` parameter renamed

- `hours` parameter renamed to `minutes` for finer granularity control
- Existing callers must update: `hours=24` → `minutes=1440`

### Time-Series Output & Zoom-In Capability

- **All metric functions now output full time-series data** — LLM can see spike shapes, duration, and timing
- **5-tier granularity**: 1-min (≤60min), 5-min (≤6h), 15-min (≤3d), 1-hour (≤1w), 4-hour (>1w)
- **Zoom-in methodology**: LLM guided to progressively narrow windows (1440→240→60 minutes) to locate exact spike timing before querying logs
- Functions with time-series: `top_rules`, `attack_types`, `bot_summary`, `rate_limits`, `challenge_solve_rate`

### DDoS Investigation Methodology

- **Explicit AMR rule identification**: LLM must verify rule names (ChallengeAllDuringEvent, ChallengeDDoSRequests, DDoSRequests) — prevents misattribution of custom rules to AMR
- **`top_labels` query type**: Lists all managed rule group labels with hit counts — confirms AMR/Bot Control involvement without guessing
- **`top_ips_by_volume` / `top_countries_by_volume`**: Action-agnostic DDoS source queries (works regardless of Challenge/Block/Count config)
- **Result validation step**: Flags when top IPs have low counts vs metrics (wrong time window)

### Timezone Handling

- **Timezone confirmation overlay**: User must select timezone before chatting, locked for session duration
- **Session timezone injected into system prompt**: LLM always sees "Session timezone: UTC+8" — eliminates double-conversion bugs
- **localStorage persistence**: Remembers last timezone choice, pre-selects browser TZ for first-time users

### Bug Fixes

- **fix: TypeError in `run_logs_query`** — results were double-parsed as CWL raw format
- **fix: `top_ips_by_volume` missing IP column** — CWL null group-by field caused column loss; added `filter ispresent()`
- **fix: KeyError TABLE when routing CWL queries** — `.format()` replaced with `.replace()` for user params only
- **fix: metric granularity** — was using entire window as one data point (`period=hours*3600`)
- **fix: checkbox double-toggle** — `stopPropagation` moved from `onChange` to `onClick`
- **fix: `ScanBy=TimestampAscending`** — time-series output now chronological in all functions
- **fix: query injection** — IP validation added to `waf_bypass`, `waf_block_fp`; rule_name sanitized in `waf_count_eval`
- **fix: timezone `.replace(tzinfo=utc)` discarding explicit offset** — now uses `.astimezone()` for tz-aware strings
- **fix: half-hour timezone support** — offset stored as float (India +5.5, Nepal +5.75)
- **fix: guard all `query_logs` callers** — RuntimeError from Athena no longer crashes tools

### New Query Types

- `top_challenged_ips` / `top_challenged_countries` — Challenge action sources
- `top_captcha_ips` / `top_captcha_countries` — CAPTCHA action sources
- `top_counted_ips` / `top_counted_countries` — COUNT action sources
- `top_ips_by_volume` / `top_countries_by_volume` — All actions combined
- `top_labels` — All managed rule group labels with hit counts
- `ip_uri_prefix` — URI path prefix clustering for an IP (crawl/scrape pattern detection)
- `rule_uri_prefix` — URI prefix clustering for a rule (FP vs attack signal for COUNT-to-BLOCK)
- `top_ua_by_action` — Global User-Agent distribution by action (bot/bypass detection)
- `ip_request_timeline` — Per-minute action timeline for an IP (rate-limit/DDoS analysis)
- `ip_label_breakdown` — All WAF labels on an IP (bot signals, Anti-DDoS, token status)
- `host_top_ips` — Top IPs per host/domain (multi-domain WebACL attack attribution)

### Other

- Removed unused `strands-agents-tools` dependency (42% smaller lock file)
- Added stderr logging to `waf_logs`, `waf_overview`, `waf_bypass` for debugging
- Frontend: connection status indicator with auto-retry
- Frontend: sidebar tooltips for quick-start items
- `js-cookie` override to 3.0.7 (CVE fix)

### Athena Performance & Robustness

- **Unified query window caps**: Athena hard-capped at 60 min, CWL defaults to 180 min (max 360 min). Enforced at tool level — no separate cap in `waf_query.py`.
- **Partition pruning fix**: `_ensure_athena_table` now detects partition format for existing tables (was only set during table creation, causing full scans on pre-existing tables).
- **Error surfacing**: Query errors bubble up to LLM (previously `detect_bypass` and `evaluate_count_rules` silently returned empty results).
- **Metrics-based peak detection**: `evaluate_count_rules(step='analyze_rule')` returns peak hour + hit count only — does NOT auto-query logs. LLM decides window based on volume.
- **Improved timeout message**: Suggests `duration_minutes=30` or `duration_minutes=15` instead of generic "timed out".
- **User expectation management**: LLM proactively informs user about Athena latency after `get_waf_config`.

### Parameter Rename: `duration_hours` → `duration_minutes`

- All 6 log-querying tools renamed: `duration_hours` (float) → `duration_minutes` (int)
- `hours_ago` backward-compat alias removed entirely
- Integer arithmetic eliminates float→ParamValidationError bug class
- Adaptive window guidance in system prompt: LLM starts with default, narrows based on results
- `_athena_cap_hit` dead code removed from `waf_bypass.py`

### Report Improvements

- **Title**: "管理层周报" / "Executive Summary" (was "AWS WAF 安全周报")
- **Unified headers**: Both reports show WebACL name, scope, time range, gen time, timezone, delay note
- **Light theme chart fix**: `<html class="dark">` at top + Chart.js color update on toggle
- **Country map**: Includes Challenge + Captcha (not just Block) — DDoS-heavy WebACLs now show data
- **i18n**: DDoS section cards, delay note, "Generated" label all localized
- **IP Reputation check**: Validates `AmazonIpReputationList` (deployed) not `AnonymousIpList` (optional)

### CloudWatch MetricStat Migration (Phase 1)

- Fixed-dimension SEARCH queries converted to explicit MetricStat + FILL — extends queryable window from ~14 days (SEARCH index expiry) to 63 days (5-min rollup retention)
- Converted: Rule=ALL metrics, event-detected, ddos-request, total_m
- DDoS fallback: queries both `ddos-request` and `challengeable-request` labels

### Missing Data Indicators (Phase 2)

- When SEARCH returns empty (metric index expired), reports show user-friendly warning instead of blank space
- Tool return includes structured `PARTIAL_DATA` / `MISSING_SECTIONS` / `REASON` / `ACTION` for LLM

### WebACL Validation

- All tools validate WebACL name before querying metrics — returns available names + ACTION hint if not found

## 0.7.0 (2026-05-18)

### New Tool: `detect_bypass` — Bypass/Evasion Detection

- **3-step workflow**: `scan` (proactive anomaly detection), `investigate_ip` (single IP behavioral profile), `volume_anomaly` (WoW metrics comparison)
- **Anomaly-based filtering**: Crawlers (>50 unique URIs), repeaters (>200 req, <10 URIs), data-center IPs without bot labels, automation UAs (curl/python-requests/wget)
- **Coverage gap detection**: Auto-checks if Bot Control, rate-based rules, Anti-DDoS AMR are deployed
- **Volume anomaly classification**: Distinguishes classic DDoS vs cache-bypass DDoS vs scraper based on IP distribution + URI patterns
- **Confidence levels**: HIGH / LIKELY / CANNOT DETERMINE embedded in every output
- **Step flow guidance**: volume_anomaly → scan → investigate_ip, with reverse flow hints

### New Tool: `evaluate_count_rules` — COUNT-to-Block Workflow

- **Metrics-based init**: Uses CloudWatch Metrics (accurate, free) instead of CWL parse for hit counts
- **Rule classification**: Permanent-count / zero-hit / low-FP / needs-analysis
- **Peak hour detection**: Finds optimal analysis window
- **Client distribution analysis**: Top/bottom IPs, unique IP count

### New Tool: `investigate_block_fp` — False Positive Investigation

- **Two modes**: `investigate` (specific IP) and `scan` (proactive FP audit)
- **8-dimension analysis**: Block rule, sub-rule extraction, allow ratio, frequency, multi-rule check, URI distribution, match detail, text transformations
- **Batch ALLOW query**: Single query for all candidate IPs (not N queries)

### New Tool: `check_challenge_compatibility` — Challenge/CAPTCHA Analysis

- **URI/method distribution**: Shows which endpoints are being challenged
- **Anti-DDoS event detection**: Flags ChallengeAllDuringEvent activity
- **Incompatibility warnings**: API endpoints, native apps

### Unified Query Layer (`waf_query.py`)

- **Dual backend**: All log-querying tools now support both CWL and Athena (S3)
- **Auto-routing**: Detects log destination, routes to correct backend
- **Partition pruning**: Auto-injects `log_time` partition filter for Athena queries
- **`run_logs_query` upgraded**: All 20 templates now have Athena SQL versions
- **`analyze_ip` upgraded**: Migrated from CWL-only to unified query layer

### Athena Query Fixes (verified against live data)

- **`EXISTS(SELECT 1 FROM UNNEST(...))` → `any_match()`**: Athena doesn't support correlated subqueries with UNNEST in WHERE + GROUP BY. Replaced with `any_match(array, predicate)` (26 occurrences across 6 files)
- **`NOT EXISTS` → `none_match` + NULL guard**: `NOT any_match(NULL, ...)` returns NULL (filters out rows). Fixed to `(labels IS NULL OR none_match(labels, ...))` (8 occurrences)
- **`CROSS JOIN UNNEST` → `EXISTS` for single-rule queries**: 6 queries in waf_count_eval.py optimized (init query keeps CROSS JOIN for GROUP BY)

### CWL Query Fixes (verified against live data)

- **Removed `.*?` non-greedy regex**: CWL Insights doesn't support non-greedy quantifiers in `parse`. Removed redundant parse lines, rely on `filter @message like` (5 occurrences)

### CloudWatch Metrics Fixes (verified against live data)

- **REGIONAL scope dimension set**: `{Rule,WebACL}` → `{Rule,WebACL,Region}` for REGIONAL WebACLs. CLOUDFRONT keeps `{Rule,WebACL}`. Cannot use unified set (verified with live API).
- **All callers updated**: `_get_all_rules_metrics_search`, `_get_top_rules`, `_get_traffic_timeseries`, `_get_attack_timeseries`, patrol_scan attack chart

### Knowledge Base

- **`kb-docs/fraud-control-atp-acfp.md`**: ATP and ACFP managed rule groups — detection capabilities, JS SDK telemetry, pricing, cost control, limitations

### System Prompt

- **All trigger patterns in English**: Removed Chinese from system prompt (LLM auto-detects user language)
- **Bypass detection triggers**: "any bypass" / "traffic spike" / "suspected DDoS" → detect_bypass
- **Clean stop guidance**: Credential stuffing / API abuse / backend compromise → do NOT call detect_bypass
- **Volume-first priority**: If user mentions both traffic anomaly AND bypass → volume_anomaly first

### Performance

- **Partition pruning**: All Athena queries include `{PARTITION_FILTER}` — 14-day scans go from full-table to partition-pruned
- **Batch queries**: scan step uses single batch query instead of per-IP loops
- **Narrow window guidance**: Tool output guides LLM to use 1-2h windows for best signal-to-noise

### Breaking Changes

- **`run_athena_query` removed**: `run_logs_query` now auto-routes to CWL or Athena based on log destination. Same interface, same query_types — no user-facing change. LLM no longer needs to choose between the two tools.

## 0.6.0 (2026-05-15)

### Security Patrol Report v2 — Complete Redesign

- **Chart-first design**: Replaced tables with donut charts (traffic distribution, bot activity), horizontal stacked bar charts (per-rule Top 10, rate-limit, targeted signals), and stacked area timeline (attack types)
- **Single WebACL mode**: Requires `webacl_name` + `start_time` (max 24h window) — no more scanning all WebACLs
- **WoW anomaly detection**: 3x = moderate, 10x = critical, with cold-start fallback ("昨日无基线")
- **Deep Bot Analysis**: Self-declared bot donut + targeted bot signals chart (TGT_VolumetricIpTokenAbsent, SignalNonBrowserUserAgent, CSP) + bot names bar chart. All via SEARCH (dynamic discovery, no hardcoded rules)
- **Bot-derived action items**: Unverified bots allowed in Count mode, high CSP traffic, targeted rule triggers
- **i18n (zh/en)**: All labels, action items, detection tools detail strings, footer
- **Timezone support**: UTC+8 for zh, UTC for en (chart labels + header)
- **Dark/Light theme toggle**: ☀️/🌙 button, CSS variables switch
- **Deterministic**: Zero LLM involvement — pure metrics + config analysis
- **S3/Athena adaptive**: Auto-creates permanent Athena table with partition pruning

### New Tool: `get_waf_overview`

- **Fast metrics-based answers** (2-4s, no log queries, up to 14 days)
- **7 query types**: `top_rules`, `attack_types`, `bot_summary`, `bot_names`, `targeted_signals`, `rate_limits`, `challenge_solve_rate`
- **Next-step hints**: Each response guides LLM to deeper log analysis when needed
- **Bridges overview → investigation**: LLM uses this for triage, then logs for details

### Time Range Enforcement (Breaking Change)

- **All log-querying tools** now require `start_time` parameter:
  - `run_logs_query`: max 6h
  - `run_athena_query`: max 6h
  - `analyze_ip`: max 6h
  - `patrol_scan`: max 24h
  - `generate_weekly_report`: max 7 days
- **Prevents**: Expensive full-week scans, LLM defaulting to large ranges without user confirmation
- **Athena**: Always creates permanent tables (removed temporary table logic, atexit cleanup)

### Tool Chain Improvements

- **Next-step hints** added to all investigation tools (run_athena_query, lookup_ja4, analyze_ip, get_waf_metrics)
- **System prompt updated**: Reflects new tool signatures, guides LLM to use `get_waf_overview` for overview questions before querying logs
- **Removed**: `finalize_patrol_report` (patrol_scan is now self-contained)

### Code Quality

- **Dead code removal**: -333 lines from waf_patrol.py (old v1 functions)
- **Consistent i18n pattern**: `_PATROL_I18N` dict with `L[...]` references throughout

## 0.5.0 (2026-05-12)

### Deep WAF Review

- **Comprehensive rules audit**: Deterministic pipeline (10 Python scripts) analyzes WebACL for security issues, misconfigurations, and optimization opportunities
- **Label dependency analysis**: Maps label producers → consumers, detects broken chains and priority ordering issues
- **18+ automated checks**: Forgeable Allow rules, scope-down issues, missing baselines, Bot Control config, rate-limiting, and more
- **LLM-assisted analysis**: Agent performs cross-rule dependency analysis and Bot Control strategy assessment using domain-specific references
- **HTML report**: Downloadable styled report with Mermaid flow diagram, severity summary, and actionable recommendations
- **Two-tool pattern**: `review_waf_rules_deep` (pipeline) → Agent analysis → `finalize_review_report` (assemble + render)

### Knowledge Base

- **Bedrock KB + S3 Vectors**: Semantic search over AWS WAF best practices documents
- **`search_waf_knowledge` tool**: Agent retrieves domain-specific guidance during conversation
- **Separate CFN stack** (`deploy/kb.yaml`): Optional, recommended. Independent of backend.
- **`deploy/sync-kb.sh`**: One-command document upload + ingestion trigger
- **Graceful degradation**: KB not configured → tool returns "not configured", no errors

### Security Patrol Report

- **One-click weekly summary**: `patrol_scan()` scans all WebACLs, collects 7-day metrics, detects anomalies, queries logs for details
- **3 interactive charts**: Traffic Overview (15 min), Threats by Category (1h stacked area), Challenge Effectiveness (15 min)
- **Anomaly detection**: Concentration-based (single IP >30%) + absolute thresholds + spike detection (>3x daily average)
- **Zero-parameter tool**: Agent auto-discovers all WebACLs, no user input needed
- **CWL log details**: Parallel Logs Insights queries for top IPs/URIs on flagged rules
- **HTML report**: Downloadable dark-themed report with Chart.js zoom/pan

### Weekly Summary Improvements

- **Simplified Traffic chart**: 8 lines → 2 (Allowed + Blocked), cleaner for management
- **New Daily Protection chart**: Stacked bar (Blocked + Challenged + CAPTCHA per day) — ROI visual anchor
- **Unified 15-min period**: All charts now use 15-min granularity (consistent with patrol report)

## 0.4.0 (2026-05-12)

### Session History

- **DynamoDB backend**: Full message history persisted across sessions (split-item pattern, no 400KB limit)
- **Sessions API**: Separate CFN stack (`deploy/sessions-api.yaml`) — Lambda + API Gateway HTTP API with Cognito JWT authorizer. Optional but recommended.
- **Sidebar UI**: Session list with new chat button, click to restore, delete with ×. Auto-detects browser language. Limited to 10 most recent.
- **Restore mechanism**: Loads messages from DDB, uses new runtimeSessionId + AgentCore Memory LTM for context continuity
- **30-day TTL**: Automatic cleanup via DynamoDB TTL

### Security

- **IDOR fix**: User identity derived from JWT claims server-side (not client-supplied header). AgentCore does not validate custom headers against JWT.
- **Authorization header forwarded**: Added to `RequestHeaderAllowlist` so container can decode JWT
- **Agent user isolation**: Agent instance recreated if user_id changes (prevents cross-user memory leak)
- **Removed custom-user-id header**: No longer sent by frontend or trusted by backend (reduces attack surface)

### AWS WAF Features

- **Dynamic Label Interpolation**: `review_waf_rules` detects missing interpolation config, suggests forwarding Bot Control signals to origin
- **requestHeadersInserted parsing**: `_interpret_ip_labels` reads interpolated bot headers when available (fallback to labels array)

### Infrastructure

- **S3 hardening**: AES256 encryption, versioning, access logging, DenyInsecureTransport policy
- **DynamoDB table**: On-demand billing, TTL enabled, IAM scoped to table ARN only
- **CFN Memory auto-create**: Default behavior creates AgentCore Memory resource; set `MemoryId=none` to disable

### Compliance

- **Copyright headers**: SPDX MIT-0 on all source files (13 .py + 5 .jsx/.js/.css)
- **Service naming**: "AWS WAF" and "Amazon Bedrock" throughout all docs and code
- **Semgrep fixes**: tempfile flush, nosemgrep for polling sleep, route refactor

## 0.3.0 (2026-05-11)

### Architecture

- **Real-time streaming**: `callback_handler` + `asyncio.Queue` → SSE events. Users see tool calls and text tokens in real-time (previously waited 1-2 min for full response)
- **Refactored WebACL selection**: Removed all fuzzy match / interrupt / numeric parsing from `get_waf_config`. Now pure case-insensitive exact match. LLM handles natural language understanding via `list_webacls` → `ask_user` → `get_waf_config(exact name)` flow
- **Contextual hints**: All tools append `---\nHints:` sections to guide LLM follow-up questions (more effective than system prompt — appears at moment of maximum attention)

### Tools

- **Athena table consent**: Agent asks user to choose permanent vs temporary table before creating (no auto-create without consent). Permanent tables use stable names (`waf_logs_{webacl_name}`) for cross-session reuse
- **`_detect_capabilities`**: Fixed regression — now detects Bot Control and Anti-DDoS by `ManagedRuleGroupStatement.Name` (AWS fixed identifier), not user's custom rule name
- **`_find_existing_table`**: Fixed match direction — `s3_path.startswith(location)` ensures table covers our path (previously could match overly-specific partition tables)

### Frontend

- **Streaming UI**: Tool calls show ⏳/✅ status in real-time, text streams token-by-token
- **TOOL_CALL_END**: Match by `toolCallId` (not last index) — correct for future parallel tool calls
- **Share/Export**: Select multiple messages → export as styled HTML conversation
- **Copy/Export buttons**: Per-message copy markdown, export .md, export styled HTML
- **Sidebar guide**: Bilingual (zh/en) usage guide with example prompts
- **Dark/Light mode**: Theme toggle with CSS variables

### Docs

- Added: user-guide, iam-permissions, cost-estimation (English + Chinese)
- Sanitized: removed real WebACL names, ARNs, personal info from all docs
- Updated architecture diagram: streaming, 12 tools, PreQueryGuard hook

### Fixes

- `has_streamed_text` flag prevents duplicate text output on fallback path
- `callback_handler` set as Agent attribute (not deprecated `__call__` kwarg)
- System prompt: restored hard constraint "Do NOT query logs without confirmed time range"
- `bot_control` value: `"None"` → `"none"` (consistent with downstream consumers)

## 0.2.0 (2026-05-11)

- **ask_user interrupt**: Agent now proactively asks clarifying questions using Strands SDK interrupt mechanism (reliable, SDK-level pause)
- **Time range control**: `start_time` parameter on log queries — pass user's date directly, tool handles timezone conversion
- **Hard caps**: Bypass detection queries capped at 24h (prevents expensive full-week scans regardless of LLM behavior)
- **Multi-WebACL interrupt**: `get_waf_config` automatically asks user to choose when multiple WebACLs exist
- **Timezone support**: `WAF_AGENT_TIMEZONE_OFFSET` env var (default UTC+0) for date parsing fallback. LLM passes explicit offsets (e.g., +08:00) when user timezone is known.
- **Current date injection**: System prompt includes current date/time so agent can resolve relative dates

## 0.1.0 (2026-05-10)

Initial release.

- AWS WAF investigation engine: COUNT evaluation, bypass detection, attack source analysis
- Weekly business report generation (HTML + Chart.js)
- 13 deterministic rule review checks
- AG-UI streaming chat interface (React SPA)
- Athena support for S3-stored AWS WAF logs (auto table discovery/creation)
- CloudFormation deployment (Cognito + AgentCore + CloudFront)
- 12 tools: waf_config, waf_metrics, waf_logs, waf_athena, analyze_ip, waf_review, report, ja4, finding, ask_user
