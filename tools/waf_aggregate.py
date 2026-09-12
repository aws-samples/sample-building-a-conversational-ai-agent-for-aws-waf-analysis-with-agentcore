# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.1: one composable aggregation, instead of a template per (filter x group) cell.

`run_logs_query` is already a primitive layer, but a fixed-combination one. `top_blocked_ips`,
`top_allowed_ips`, `top_challenged_ips`, `top_captcha_ips` and `top_counted_ips` are ONE query
with the action welded into the template name, and the `top_*_countries` family is the same
query with the group dimension welded in too. Every new combination needed a new template times
two dialects, so the cells nobody hand-wrote were simply unavailable: "requests per URI, as a
share of that URI's traffic" is the hit-rate question and no template covers it.

This frees the welded dimensions into parameters and keeps every safety property, because the
SQL is still assembled here and never by the model.

**The allow-list is the mechanism, not a guard in front of one.** ROADMAP 4.1 decision 3, and
the two halves are deliberately different because keys and values are different problems:

- **Keys are dispatched through a table and never interpolated.** `group_by` and each
  `filter_by` key select a pre-written expression out of `_GROUP_BY` / `_FILTERS`. The model's
  string is compared against the table's keys and then dropped; only the expression this file
  wrote reaches a query. Stronger than validating the key, because there is nothing to escape.
- **Values do reach a predicate, so each is `fullmatch`-or-refused per dimension**, in the
  `(value, error)` shape `waf_query.checked_rule_name` sets, and with `ipaddress.ip_address`
  where a real parser exists. Refuse, do not substitute.

**Tier-2 fallback, not a replacement for the scenario tools.** `evaluate_count_rules`,
`investigate_block_fp` and `detect_bypass` carry embedded judgment about what to look at and in
what order. This carries none: it answers exactly the question asked. The system prompt says so,
because a model that defaults here erodes the packaged methods.

## What was measured, 2026-09-11, and why each dialect line reads the way it does

Two subagents disagreed on the construct `metric="ratio"` depends on, so it was measured on the
live account. All six CloudWatch spellings of a conditional count work, positive and negative
controls both correct: bare `sum(action = 'X')` in either quoting, `sum(if(...))` in either,
`sum(case(...))` and `sum(strcontains(...))`. `sum(if(cond, 1, 0))` ships because it is the one
the published function reference documents, `if()` being usable as an argument to another
function; the bare boolean is shorter and measured identical but is a documented type mismatch,
`sum` taking a numeric field while a comparison is typed Boolean.

Chained `stats` works and is what `metric="percentile"` needs. `pct(c, N)` takes **0-100** and
is a real percentile, not a dressed-up maximum: over 11 buckets holding ten values of 1-2 and
one of 289549, it returned p10=1, p50=2, p95=289549. `bin()` in a second `stats` is rejected
outright, which is why `bin()` here only ever appears in the first.

**The percentile scale diverges between the engines and only one direction fails loudly.**
Athena's `approx_percentile` takes a **0-1 fraction** and rejects 95 with
`INVALID_FUNCTION_ARGUMENT: Percentile must be between 0 and 1`. CloudWatch accepts
`pct(c, 0.95)` and silently returns the near-minimum, 1 where the 95th percentile was 289549.
So the two spellings are derived from one `_PERCENTILES` tuple rather than written twice.
"""

import json
import re
import time

from strands import tool

from tools.query_limits import MAX_MINUTES
from tools.session_state import is_log_filter_active

MAX_RESULTS = 25
# One tuple, two scales. Writing 95 twice is what makes a silent CloudWatch wrong answer
# available; see the module docstring for the measurement.
_PERCENTILES = (95, 99)


class _Dim:
    """A group-by dimension in both dialects.

    `cwl_pre` is the pipeline stages that must run before any `filter` referring to the field,
    which is how CloudWatch reaches a request header at all: there is no array accessor, so the
    value is pulled out of the raw JSON by regex. `unnest` marks the one dimension whose Athena
    form multiplies rows, so it can never be used as a filter.

    **`cwl_pre` is a SEQUENCE, not one string, so a stage shared by a dimension and a filter is
    emitted once.** `group_by="label"` and `filter_by={"label": ...}` both need the same
    `"labels":[...]` capture; as single strings the two preludes differed, so nothing deduplicated
    them and `lbls` was defined twice in one query, the second time after it had already been
    read."""

    def __init__(self, athena: str, cwl: str, cwl_pre: tuple = (), unnest: str = ""):
        self.athena = athena
        self.cwl = cwl
        self.cwl_pre = tuple(cwl_pre)
        self.unnest = unnest


def _header(name: str) -> str:
    return f"element_at(filter(httprequest.headers, h -> lower(h.name) = '{name}'), 1).value"


# The `labels` array as one raw string, shared by the label group dimension and the label filter.
# `[^\]]*` reaches the closing bracket because a WAF label name cannot contain one, and the whole
# array is captured, so a filter over it sees EVERY label rather than the first.
_LABELS_ARRAY = r'parse @message /"labels":\[(?<lbls>[^\]]*)\]/'


def _parse(name: str, into: str) -> str:
    """The CloudWatch `parse` for one header. `(?i)` because the log keeps the client's casing.

    Measured: this is how the `referer` dimension was confirmed to work on CloudWatch, finding
    5 records carrying one and 293367 without."""
    return rf'parse @message /(?i)\{{"name":"{name}","value":"(?<{into}>[^"]*)"\}}/'


# group_by key -> the pre-written expression pair. The model names a KEY; nothing it sends is
# ever interpolated into a query.
_GROUP_BY = {
    "clientIp": _Dim("httprequest.clientip", "httpRequest.clientIp"),
    "uri": _Dim("httprequest.uri", "httpRequest.uri"),
    "country": _Dim("httprequest.country", "httpRequest.country"),
    "method": _Dim("httprequest.httpmethod", "httpRequest.httpMethod"),
    "action": _Dim("action", "action"),
    "rule": _Dim("terminatingruleid", "terminatingRuleId"),
    "ruletype": _Dim("terminatingruletype", "terminatingRuleType"),
    "ja4": _Dim("ja4fingerprint", "ja4Fingerprint"),
    "host": _Dim(_header("host"), "host", (_parse("host", "host"),)),
    "ua": _Dim(_header("user-agent"), "ua", (_parse("user-agent", "ua"),)),
    "referer": _Dim(_header("referer"), "referer", (_parse("referer", "referer"),)),
    # The only dimension that changes the FROM clause. On CloudWatch this reads the FIRST label
    # per request and no more, the same limitation `ip_label_breakdown` documents, because the
    # raw JSON has to be parsed rather than unnested.
    "label": _Dim("l.name", "label",
                  (_LABELS_ARRAY, "filter ispresent(lbls)",
                   r'parse lbls /"name":"(?<label>[^"]*)"/'),
                  unnest="CROSS JOIN UNNEST(labels) AS t(l)"),
    # Rendered from `bucket_minutes`, so it is built in `_group_expr` rather than sitting here.
    "time_bucket": None,
}

_METRICS = ("count", "ratio", "percentile")


def _checked(pattern: str, what: str):
    """A `fullmatch`-or-refuse validator in the `(value, error)` shape.

    Returning the value as well as the verdict is ROADMAP 4.1 decision 3's precedent, and it is
    that shape because the alternative shipped a bug: a validator that decided on a stripped
    copy and returned only a verdict left every caller to re-derive the normalised value, and two
    of three did not, so a trailing space reached a literal and matched nothing."""
    rx = re.compile(pattern)

    def check(raw) -> tuple[str, str | None]:
        value = (raw or "").strip() if isinstance(raw, str) else ""
        if not rx.fullmatch(value):
            return "", f"Error: {raw!r} is not {what}."
        return value, None

    return check


def _checked_ip(raw) -> tuple[str, str | None]:
    """The strongest form available, and the reason there is no regex here.

    `ipaddress.ip_address` is a real parser, so a pattern in front of it would be a weaker
    duplicate of a check already being done, which is the dead `re.sub` `analyze_ip` carried for
    eight releases."""
    import ipaddress
    value = (raw or "").strip() if isinstance(raw, str) else ""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "", f"Error: {raw!r} is not an IP address."
    return value, None


def _checked_rule(raw) -> tuple[str, str | None]:
    from tools.waf_query import checked_rule_name
    return checked_rule_name(raw if isinstance(raw, str) else "")


class _Filter:
    def __init__(self, check, athena: str, cwl: str, cwl_pre: tuple = (),
                 redactable_filter: tuple = ()):
        self.check = check
        self.athena = athena
        self.cwl = cwl
        self.cwl_pre = tuple(cwl_pre)
        # ROADMAP 6.13's filter half: the `RedactedFields` entries that would strip what this
        # PREDICATE reads. Named for the role, not the field, because the display half is covered
        # data-side by the `REDACTED` sentinel scan at `query_logs` and does not belong here. #62
        # declared "reads this field" and mixed both roles inside one entry, which is why it was
        # closed rather than trimmed.
        #
        # A filter is the case that leaves no trace: the predicate cannot match a redacted value, so
        # those records are absent and no sentinel appears anywhere in the result.
        self.redactable_filter = tuple(redactable_filter)


# **The rule filter names all four places a match can be recorded**, which is the nested-COUNT
# trap ROADMAP 2.6 owns. A `RuleActionOverrides` Count lands in
# `rulegrouplist[].nonterminatingmatchingrules[]`, a group-level `OverrideAction: Count` writes
# the sub-rule to `rulegrouplist[].terminatingrule` paired with its native action, a top-level
# Count lands in `nonterminatingmatchingrules`, and a rate-based rule is a fourth shape. The
# existing `rule_uri_prefix` template covers three of the four, so a filter copied from it would
# silently miss exactly the case a COUNT investigation is looking for.
#
# No NULL guard on the `any_match` calls, and that is reasoned rather than overlooked. Trino
# gives NULL for `any_match(NULL, ...)`; in this OR chain `TRUE OR NULL` keeps the row and
# `FALSE OR NULL` drops it, which is right both times for a POSITIVE filter. The static-asset
# exclusion needed its guard because it was a negation, where NULL drops a row that should have
# been kept.
#
# **The `excludedrules` branch is a string search, and that is measured rather than a shortcut.**
# `DDL_TEMPLATE` types this column `excludedrules:string` (see `waf_athena.py`), not as an array of
# structs, so there is nothing to `any_match` over. The obvious conclusion is that closing this gap
# needs a DDL change plus the table-recreate path, i.e. the same blocker that deferred ASN. It does
# not: measured 2026-09-11 against a record written for the purpose, a string-typed column over a
# JSON array yields **the array's raw JSON text**, so `strpos` reaches it today.
#
# **The key is lowercased and that is the whole trap.** The openx SerDe normalises JSON keys, so the
# column reads
# `[{"exclusiontype":"EXCLUDED_AS_COUNT","ruleid":"SizeRestrictions_BODY"}]`.
# Searching for `"ruleId"`, the spelling the raw WAF log actually uses and the one every other
# branch here is written in, matches NOTHING. Five controls: the lowercase key hits both excluded
# rules, misses a rule that is not excluded, the camelCase key misses, and a lowercased rule NAME
# misses, so values keep their case while keys do not.
#
# Why this branch is worth having at all: `excludedRules` is the LEGACY `ExcludedRules` mechanism,
# and an entry there means the rule genuinely matched and was counted instead of blocked. So without
# this, CloudWatch counts those matches (its raw-JSON search reaches them) and Athena silently does
# not, with Athena under-reporting a real match. Modern `RuleActionOverrides` never populates it;
# that match lands in `nonterminatingmatchingrules` with `action: COUNT`, which branch 2 already
# catches.
#
# **Exercised against a written record, not against production traffic.** `excludedrules` is NULL on
# every row this account has, so no real WAF record here can reach this branch. What IS verified on
# real data is that adding it changes no existing count: `strpos(NULL, ...)` is NULL and `NULL > 0`
# is NULL, so the OR chain is unaffected where the column is empty.
_RULE_ATHENA = (
    "(terminatingruleid = '{v}'"
    " OR any_match(nonterminatingmatchingrules, r -> r.ruleid = '{v}')"
    " OR any_match(rulegrouplist, rg -> rg.terminatingrule.ruleid = '{v}')"
    " OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules,"
    " r -> r.ruleid = '{v}'))"
    " OR any_match(rulegrouplist, rg -> strpos(rg.excludedrules, '\"ruleid\":\"{v}\"') > 0)"
    " OR any_match(ratebasedrulelist, rb -> rb.ratebasedrulename = '{v}'))"
)
# CloudWatch has no array accessor, so a raw-JSON substring reaches every nested path at once.
#
# **`"ruleId":` cannot be produced by anything but a key named exactly that**, because JSON puts the
# opening quote immediately before a key's first character, so `ruleGroupId`, `terminatingRuleId`
# and `rateBasedRuleId` cannot satisfy it. There are four such keys in a WAF record:
# `nonTerminatingMatchingRules[]`, `ruleGroupList[].terminatingRule`,
# `ruleGroupList[].nonTerminatingMatchingRules[]` and `ruleGroupList[].excludedRules[]`, all four of
# which the Athena side now names. `rateBasedRuleList` uses `rateBasedRuleId`/`rateBasedRuleName`
# and never `ruleId`, which is why the second clause here is a separate key rather than a duplicate.
#
# **Nor can a client produce it, measured 2026-09-11 rather than argued.** The worry is that this
# pattern also matches client-controlled text, so a header or query string carrying
# `"ruleId":"Log4JRCE"` would inflate that rule's apparent hits. A request was sent through the live
# WAF with exactly that in both an `X-Probe` header and the query string. Both arrive
# backslash-escaped in the log line, `\"ruleId\":\"...\"`, so the bare-quote pattern cannot reach
# them: the anchored filter returned 0 while an unanchored control on the same records returned 3.
# A JSON serializer has no choice here, since a literal quote inside a string value must be escaped
# or the line stops being JSON.
#
# One belief this measurement corrected: `args` is NOT percent-encoded by WAF. The probe's
# `raw="ruleId":"..."` parameter was logged with its literal quotes, escaped, while only the part
# already percent-encoded by the client stayed encoded. So the escaping alone carries this, not any
# encoding of the field.
_RULE_CWL = ("(terminatingRuleId = '{v}' or @message like '\"ruleId\":\"{v}\"'"
             " or @message like '\"rateBasedRuleName\":\"{v}\"')")

# filter_by key -> validator plus the pre-written predicate pair.
_FILTERS = {
    "action": _Filter(
        _checked(r"ALLOW|BLOCK|COUNT|CAPTCHA|CHALLENGE|EXCLUDED_AS_COUNT",
                 "a WAF action (ALLOW, BLOCK, COUNT, CAPTCHA, CHALLENGE, EXCLUDED_AS_COUNT)"),
        "action = '{v}'", "action = '{v}'"),
    "rule": _Filter(_checked_rule, _RULE_ATHENA, _RULE_CWL),
    "ip": _Filter(_checked_ip,
                  "httprequest.clientip = '{v}'", "httpRequest.clientIp = '{v}'"),
    "country": _Filter(_checked(r"[A-Za-z]{2}", "a two-letter country code"),
                       "httprequest.country = '{v}'", "httpRequest.country = '{v}'"),
    "method": _Filter(
        _checked(r"GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS", "an HTTP method"),
        "httprequest.httpmethod = '{v}'", "httpRequest.httpMethod = '{v}'",
        redactable_filter=("Method",)),
    "ruletype": _Filter(
        _checked(r"REGULAR|RATE_BASED|GROUP|MANAGED_RULE_GROUP",
                 "a rule type (REGULAR, RATE_BASED, GROUP, MANAGED_RULE_GROUP)"),
        "terminatingruletype = '{v}'", "terminatingRuleType = '{v}'"),
    "ja4": _Filter(_checked(r"[0-9a-zA-Z_]+", "a JA4 fingerprint"),
                   "ja4fingerprint = '{v}'", "ja4Fingerprint = '{v}'"),
    # `strpos` rather than `LIKE '%v%'`, because `_` is in the validated charset AND is a LIKE
    # wildcard matching any single character: `bot_verified` would also match `botXverified`. A
    # filter matching more than it says it matches is the defect class this whole item keeps
    # running into, so the wildcard-free spelling wins.
    #
    # **The CloudWatch side is scoped to the labels array, and shipping it as `@message like` was
    # a real defect.** That spelling matches the value anywhere in the record, so
    # `filter_by={"label": "bot"}` also matched a `User-Agent: Googlebot`, a `/robots.txt` URI and
    # a referer containing "bot", none of them carrying any label. Same filter, same question, two
    # different answers per backend. It came from copying `label_top_ips`, and the `host` entry two
    # lines down already stated the principle it broke. Measured on the live account: `k6test`, a
    # URI, matched 293371 records as `@message like` and 0 once scoped, while a real label
    # (`token:absent`) returns the same 293371 either way.
    #
    # The array capture holds EVERY label, so this does not inherit the group dimension's
    # first-label-only limit: one record's capture carried all 8 of its labels.
    #
    # Residual divergence, stated rather than implied: the capture includes the JSON scaffolding,
    # so a value that is a substring of `name` or is a bare `:` can match the wrapper on
    # CloudWatch while Athena matches only label names. Closing that needs a regex, which would
    # reintroduce `.` as a metacharacter, and no label filter anyone would write is a substring of
    # `name`. This trades an over-match spanning every field in the record for one spanning four
    # letters of scaffolding.
    "label": _Filter(_checked(r"[0-9a-zA-Z_:.\-]+", "a WAF label"),
                     "any_match(labels, l -> strpos(l.name, '{v}') > 0)",
                     "lbls like '{v}'", (_LABELS_ARRAY,)),
    # Matched through the parse rather than a raw-message substring, so `example.com` cannot be
    # satisfied by the string turning up in a URI or a referer.
    "host": _Filter(_checked(r"[0-9a-zA-Z.\-]+(:[0-9]+)?", "a hostname"),
                    f"{_header('host')} = '{{v}}'", "host = '{v}'",
                    (_parse("host", "host"),),
                    redactable_filter=("SingleHeader:host",)),
}


def _group_expr(group_by: str, bucket_minutes: int, tz_token: str = "{TZ_OFFSET_SECONDS}"):
    """`(athena_select, athena_group, cwl_by, cwl_parse, unnest, alias)` for a group dimension.

    `time_bucket` is the one dimension rendered from a parameter. Its Athena form floors the
    epoch to the bucket and adds the session offset only in the SELECT, exactly as
    `ip_request_timeline` does, so the GROUP BY stays on the raw arithmetic. The column is named
    `time_bucket` on purpose: `waf_query._shift_time_fields` shifts that name on the CloudWatch
    side, which is what keeps one engine's hours from being an offset copy of the other's."""
    if group_by == "time_bucket":
        secs = bucket_minutes * 60
        floor = f'("timestamp" / {secs * 1000}) * {secs}'
        return (f"from_unixtime({floor} + {tz_token})", floor,
                f"bin({bucket_minutes}m) as time_bucket", (), "", "time_bucket")
    dim = _GROUP_BY[group_by]
    # The alias is `dim.cwl`, NOT the dimension key: CloudWatch has no `as` on a plain field, so
    # its column header is the field path itself, and Athena aliasing to anything else would make
    # the same request return `ruletype` on one backend and `terminatingRuleType` on the other.
    # Every existing template resolves it this direction too.
    return dim.athena, dim.athena, dim.cwl, dim.cwl_pre, dim.unnest, dim.cwl


def _parse_filters(filter_by: str) -> tuple[dict, str | None]:
    """`filter_by` as a validated `{key: value}`, or a refusal.

    A JSON STRING rather than a dict, which is ROADMAP 4.1 decision 2 and follows
    `get_waf_metrics(dimension_filters='{"Country": "CN"}')`. Seven flat `filter_*` parameters
    would bloat the signature the model reads on every turn."""
    raw = (filter_by or "").strip()
    if not raw:
        return {}, None
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        return {}, (f"Error: filter_by is not valid JSON ({exc}). Pass it as a JSON string, "
                    f"for example filter_by='{{\"action\": \"BLOCK\"}}'.")
    if not isinstance(parsed, dict):
        return {}, f"Error: filter_by must be a JSON object, got {type(parsed).__name__}."

    checked = {}
    for key, value in parsed.items():
        if key not in _FILTERS:
            return {}, (f"Error: '{key}' is not a filter dimension. Available: "
                        f"{', '.join(sorted(_FILTERS))}.")
        clean, bad = _FILTERS[key].check(value)
        if bad:
            return {}, f"{bad} (filter_by['{key}'])"
        checked[key] = clean
    return checked, None


def _build(group_by: str, metric: str, filters: dict, bucket_minutes: int,
           limit: int) -> tuple[str, str]:
    """The CloudWatch query and the Athena SQL for one request.

    Both dialects are assembled from the same three decisions, which is the point: a dimension
    added to `_GROUP_BY` reaches both engines or neither."""
    a_select, a_group, cwl_by, cwl_pre, unnest, alias = _group_expr(group_by, bucket_minutes)

    stages = list(cwl_pre)
    a_preds, cwl_preds = [], []
    for key, value in sorted(filters.items()):
        spec = _FILTERS[key]
        from tools.waf_query import note_redacted_filter  # lazy: circular at module level
        # ROADMAP 6.13's filter half. Recorded here, where the predicate is actually built, rather
        # than at the render sites: the zero-row branch returns before either of them, and a filter
        # on a redacted field is a fourth cause of zero rows that the message there does not offer.
        note_redacted_filter(spec.redactable_filter)
        a_preds.append(spec.athena.replace("{v}", value))
        cwl_preds.append(spec.cwl.replace("{v}", value))
        # Deduplicated per STAGE, which is what makes `_LABELS_ARRAY` shareable between the label
        # dimension and the label filter without defining `lbls` twice.
        stages.extend(stage for stage in spec.cwl_pre if stage not in stages)

    prelude = "".join(f"{stage} | " for stage in stages)
    a_where = (f'"timestamp" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}')
    a_from = f"FROM {{TABLE}} {unnest}".strip()

    if metric == "percentile":
        # Two levels: per-entity per-bucket counts, then the spread over those counts. This is
        # what sizes a rate-based rule threshold, and it returns ONE row rather than a top-N.
        secs = bucket_minutes * 60
        a_scope = f" AND {' AND '.join(a_preds)}" if a_preds else ""
        athena = (
            f'WITH per AS (SELECT {a_select} AS k, "timestamp" / {secs * 1000} AS b,'
            f" count(*) AS c {a_from} WHERE {a_where}{a_scope} GROUP BY 1, 2)"
            f" SELECT count(*) AS buckets, min(c) AS min_per_bucket,"
            f" round(avg(c), 2) AS avg_per_bucket,"
            + "".join(f" approx_percentile(c, {p / 100}) AS p{p}," for p in _PERCENTILES)
            + f" max(c) AS max_per_bucket FROM per")
        cwl_filter = f"filter {' and '.join(cwl_preds)} | " if cwl_preds else ""
        cwl = (f"{prelude}{cwl_filter}stats count(*) as c by {cwl_by},"
               f" bin({bucket_minutes}m) as t"
               f" | stats count(*) as buckets, min(c) as min_per_bucket,"
               f" avg(c) as avg_per_bucket,"
               + "".join(f" pct(c, {p}) as p{p}," for p in _PERCENTILES)
               + " max(c) as max_per_bucket")
        return cwl, athena

    if metric == "ratio":
        # `filter_by` is the NUMERATOR here, not a scope: it moves out of WHERE and into the
        # conditional count, so the denominator is every request in the group. That is the
        # hit-rate definition WI-2 needs, matched over total, and it is why an empty `filter_by`
        # is refused upstream rather than defaulted: matched/total would be 1 everywhere.
        a_pred = " AND ".join(a_preds)
        cwl_pred = " and ".join(cwl_preds)
        athena = (f"SELECT {a_select} AS \"{alias}\", count(*) AS total,"
                  f" count_if({a_pred}) AS matched,"
                  f" round(100.0 * count_if({a_pred}) / count(*), 2) AS hit_rate_pct"
                  f" {a_from} WHERE {a_where} GROUP BY {a_group}"
                  f" ORDER BY matched DESC LIMIT {{LIMIT}}")
        cwl = (f"{prelude}stats count(*) as total, sum(if({cwl_pred}, 1, 0)) as matched,"
               f" sum(if({cwl_pred}, 1, 0)) * 100 / count(*) as hit_rate_pct"
               f" by {cwl_by} | sort matched desc | limit {limit}")
        return cwl, athena

    a_scope = f" AND {' AND '.join(a_preds)}" if a_preds else ""
    a_order = f"{a_group} ASC" if group_by == "time_bucket" else "hits DESC"
    athena = (f"SELECT {a_select} AS \"{alias}\", count(*) AS hits {a_from}"
              f" WHERE {a_where}{a_scope} GROUP BY {a_group}"
              f" ORDER BY {a_order} LIMIT {{LIMIT}}")
    cwl_filter = f"filter {' and '.join(cwl_preds)} | " if cwl_preds else ""
    cwl_order = f"sort {alias} asc" if group_by == "time_bucket" else "sort hits desc"
    cwl = (f"{prelude}{cwl_filter}stats count(*) as hits by {cwl_by}"
           f" | {cwl_order} | limit {limit}")
    return cwl, athena


def _reject(group_by: str, metric: str, filters: dict) -> str | None:
    """Combinations with no answer, refused with the reason rather than run.

    **Two candidates were dropped from this list after being measured, and both would have been
    guards against a mistake nobody was making.**

    A compound ratio numerator was going to be refused as "ambiguous". It is not: `count_if(a
    AND b)` and `sum(if(a and b, 1, 0))` both run, verified on both engines, and "the share of
    this URI's requests that were ALLOW and from the US" is a perfectly well-defined number. The
    real content of that worry was that `filter_by` cannot scope the denominator as well, which
    is a documentation job, not a refusal.

    `metric='percentile'` with `group_by='label'` was going to be refused because "a request
    carries several labels, so the counts would be label hits rather than requests". That reason
    is false. The `UNNEST` groups by label NAME, so within one group each request appears exactly
    once and the per-bucket count is requests carrying that label. Niche, since no WAF rate-based
    rule keys on a label, but correct, and being useless is not grounds for refusing."""
    if metric == "ratio" and not filters:
        return ("Error: metric='ratio' needs filter_by to say what the numerator is, for "
                "example filter_by='{\"rule\": \"MyRule\"}' with group_by='uri' for that "
                "rule's hit rate per URI. Without it every group would read 100%.")
    if metric == "percentile" and group_by == "time_bucket":
        return ("Error: metric='percentile' already groups by time bucket internally, so "
                "group_by='time_bucket' would bucket twice. Name the entity you want the "
                "distribution for, e.g. group_by='clientIp' to size a rate-based rule.")
    return None


@tool
def aggregate_logs(
    start_time: str,
    duration_minutes: int = 180,
    group_by: str = "clientIp",
    metric: str = "count",
    filter_by: str = "",
    bucket_minutes: int = 5,
    limit: int = 25,
) -> str:
    """Aggregate AWS WAF logs over any (filter x group) combination. Tier-2 fallback: prefer a
    scenario tool when one fits, and use this for the long tail no template covers.

    Routes to CloudWatch Logs Insights or Athena automatically, same as run_logs_query.

    Args:
        start_time: Start of the window, e.g. "2026-05-09T14:00". REQUIRED — ask the user.
        duration_minutes: Window length from start_time (default 180, max 360, both engines).
        group_by: What to group by. One of: clientIp, uri, country, method, action, rule,
            ruletype, ja4, host, ua, referer, label, time_bucket.
        metric: "count" for request counts, "ratio" for hit rate (matched/total per group),
            "percentile" for the min/avg/p95/p99/max of per-bucket request counts — use that
            one to size a rate-based rule threshold.
        filter_by: JSON string of filters, e.g. '{"action": "BLOCK", "country": "CN"}'. Keys:
            action, rule, ip, country, method, ruletype, ja4, label, host. A label value is
            matched as a substring of the full namespaced name, so
            filter_by='{"label": "bot-control:bot:verified"}' works and so does the whole
            "awswaf:managed:aws:bot-control:bot:verified"; a bare word like "bot" matches every
            bot-control label at once, which is usually not the question. For metric="count"
            and "percentile" these narrow which requests are counted. For metric="ratio" they
            are the NUMERATOR instead, and the denominator is every request in the group: so
            filter_by='{"rule": "X"}' with group_by="uri" gives rule X's hit rate per URI. Give
            several and the numerator is their AND, which means you cannot narrow the
            denominator of a ratio — narrow the window instead.
        bucket_minutes: Bucket size for group_by="time_bucket" and for metric="percentile"
            (default 5).
        limit: Max rows (default 25, max 25).

    Returns:
        A results table, or the reason there is none.
    """
    from tools.waf_query import (check_coarse_partition_block, log_query_error, query_logs,
                                redact_row_fields, PRIVACY_MASK_HINT)
    from tools.waf_logs import _parse_start_time, _table_block

    if group_by not in _GROUP_BY:
        return (f"Error: '{group_by}' is not a group_by dimension. Available: "
                f"{', '.join(sorted(_GROUP_BY))}.")
    if metric not in _METRICS:
        return f"Error: '{metric}' is not a metric. Available: {', '.join(_METRICS)}."
    if not start_time:
        return ("Error: start_time is required. Ask the user which time period to investigate.\n"
                "Example: aggregate_logs(start_time=\"2026-05-09T14:00\", duration_minutes=60, "
                "group_by=\"uri\", filter_by='{\"action\": \"BLOCK\"}')")
    if not 1 <= bucket_minutes <= MAX_MINUTES:
        return f"Error: bucket_minutes must be between 1 and {MAX_MINUTES}."

    filters, bad = _parse_filters(filter_by)
    if bad:
        return bad
    bad = _reject(group_by, metric, filters)
    if bad:
        return bad

    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return (f"Error: cannot parse start_time '{start_time}'. Use format: YYYY-MM-DD or "
                f"YYYY-MM-DDTHH:MM")
    duration = min(duration_minutes, MAX_MINUTES)
    end_epoch = min(start_epoch + duration * 60, int(time.time()))
    if bucket_minutes > duration:
        return (f"Error: bucket_minutes ({bucket_minutes}) is larger than the window "
                f"({duration} min), so every request lands in one bucket.")

    coarse = check_coarse_partition_block()
    if coarse:
        return coarse

    row_limit = min(limit, MAX_RESULTS)
    cwl, athena = _build(group_by, metric, filters, bucket_minutes, row_limit)

    # The module's one and only `query_logs` call, guarded in this same scope. That pairing is
    # what `tests/test_window_cap.py` asserts, and it is why "is the result checked" is a
    # question about one place here rather than a dataflow problem.
    try:
        rows = query_logs(cwl, athena, start_epoch, end_epoch, row_limit)
    except Exception as exc:
        return f"Error: the aggregation query did not run. {type(exc).__name__}: {exc}"
    reason = log_query_error(rows)
    if reason:
        return reason

    described = _describe(group_by, metric, filters, bucket_minutes, duration)
    if not rows:
        msg = f"{described} returned 0 results."
        if is_log_filter_active():
            msg += ("\n⚠️  A Log Filter is active on this WebACL, so some actions never reach "
                    "the log destination. 0 results may be filtering rather than absence of "
                    "traffic. Cross-check with get_waf_overview.")
        else:
            msg += ("\nPossible reasons: (1) no traffic matched these filters in this window; "
                    "(2) the window or timezone is wrong; (3) the dimension is not populated on "
                    "this upstream — referer and ja4 are absent on some, see "
                    "search_waf_knowledge for field availability.")
        return msg + _table_block()

    masked = redact_row_fields(rows)
    columns = [k for k in max(rows[:MAX_RESULTS], key=lambda r: len(r)).keys()
               if not k.startswith("@ptr")]
    lines = [f"{described} — {len(rows)} rows\n",
             "| " + " | ".join(columns) + " |",
             "| " + " | ".join(["---"] * len(columns)) + " |"]
    for row in rows[:MAX_RESULTS]:
        lines.append("| " + " | ".join(str(row.get(c, "")) for c in columns) + " |")
    if masked:
        lines.append(f"\nHINT: {PRIVACY_MASK_HINT}")
    if metric == "percentile":
        lines.append(
            f"\nHINT: these are per-{bucket_minutes}-minute request counts per {group_by}. A "
            f"rate-based rule counts over a fixed 5-minute window, so read p99 as the level "
            f"normal traffic stays under and set the threshold above it, not at it.")
    block = _table_block()
    if block:
        lines.append(block)
    return "\n".join(lines)


def _describe(group_by: str, metric: str, filters: dict, bucket_minutes: int,
              duration: int) -> str:
    """What was actually asked, echoed back.

    Not decoration: the model chose four parameters and the window was silently clamped to
    `MAX_MINUTES`, so a header naming the request is how a caller notices it got the aggregation
    it asked for over the window it did not."""
    scope = ", ".join(f"{k}={v}" for k, v in sorted(filters.items())) or "all requests"
    if metric == "ratio":
        return f"Hit rate of [{scope}] by {group_by}, {duration} min"
    if metric == "percentile":
        return (f"Requests per {bucket_minutes} min per {group_by} for [{scope}], "
                f"distribution over {duration} min")
    if group_by == "time_bucket":
        return f"[{scope}] per {bucket_minutes} min, {duration} min"
    return f"[{scope}] by {group_by}, {duration} min"
