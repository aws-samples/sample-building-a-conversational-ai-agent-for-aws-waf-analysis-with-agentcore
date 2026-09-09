# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Unified WAF log query layer — routes to CWL or Athena based on log destination."""

import re
import json
import time
import threading
from collections import Counter
from tools.aws_session import get_client
from tools.session_state import get_log_destination, get_logs_region, get_webacl_name, get_scope, get_user_timezone, note_query_success

_cwl_semaphore = threading.Semaphore(8)
from tools.query_limits import MAX_POLL, POLL_INTERVAL, poll_timeout_message, query_failed_message


def reset_table_cache():
    """Reset the resolved-table cache. Called on WebACL switch so a stale table from
    the previous WebACL is not reused.

    Kept as a thin delegate rather than removed: `session_state.set_webacl_context`
    imports it from here, and pointing that at `waf_athena` instead would make
    session_state depend on the module that imports session_state."""
    from tools.waf_athena import reset_table_cache as _reset_state
    _reset_state()


def inspection_location(rule_name: str):
    """Map an AWS Managed Rule name to the request component it inspects.

    AWS WAF only records matchedData (terminatingRuleMatchDetails) for SQLi/XSS
    statements. For every other managed rule the rule name encodes the inspected
    component (e.g. ..._QUERYARGUMENTS, ..._COOKIE, ..._HEADER), so to show WHY a
    request matched we must pull that component out of the log ourselves.

    Returns (label, kind) where kind is one of "args" | "uri" | "cookie" |
    "header", or None when the component is not determinable or not present in
    WAF logs (BODY is never logged).
    """
    rn = (rule_name or "").upper()
    if "QUERYARGUMENT" in rn or rn.endswith("QUERYSTRING") or rn.endswith("_QS"):
        return ("query string", "args")
    if rn.endswith("URIPATH") or rn.endswith("_URI") or rn.endswith("_PATH") or rn.endswith("URIFRAGMENT"):
        return ("URI path", "uri")
    if "COOKIE" in rn:
        return ("Cookie header", "cookie")
    if rn.endswith("_HEADER") or rn.endswith("HEADERS") or "NOUSERAGENT" in rn or "USERAGENT" in rn:
        return ("HTTP headers", "header")
    if rn.endswith("_BODY") or rn.endswith("BODY"):
        return None  # request body is never present in WAF logs
    # No explicit location suffix (e.g. a managed rule-GROUP name like
    # AWS-AWSManagedRulesSQLiRuleSet). For injection / web-exploit families the
    # query string is the most common and the only reliably-logged attack
    # location, so default to it — lets group-level findings still show payloads.
    if any(k in rn for k in ("SQLI", "XSS", "CROSSSITESCRIPTING", "RFI", "LFI",
                             "LOG4J", "GENERICRFI", "JAVADESERIALIZATION", "INJECTION")):
        return ("query string", "args")
    return None  # rate-based / bot / size / unknown — no single content location


# Header/param names whose VALUES are secrets and must never be shown to the
# user. We display the name (and length) but mask the value. Matching is on a
# Sensitive name tokens, matched against the TOKENS of a field/param/header
# name (split on camelCase and non-alphanumeric). Tokenizing avoids substring
# false positives like author->auth, design/signal->sig, assignee->sig.
_SENSITIVE_TOKENS = {
    "authorization", "auth", "cookie", "cookies", "token", "tokens",
    "accesstoken", "idtoken", "refreshtoken", "session", "sessionid", "sid",
    "secret", "secrets", "apisecret", "apikey", "key", "csrf", "xsrf",
    "signature", "sig", "bearer", "credential", "credentials", "jwt",
    "password", "passwd", "pwd", "pass", "proxyauthorization",
}
# Concatenated forms (no separator) to catch e.g. apikey/accesstoken/sessionid.
_SENSITIVE_COMPOUNDS = (
    "apikey", "accesstoken", "idtoken", "refreshtoken", "sessionid",
    "csrftoken", "authtoken", "xapikey", "securitytoken", "clientsecret",
)
# Names whose value must ALWAYS be masked regardless of its shape — a password
# is never an attack payload an analyst needs to read.
_ALWAYS_MASK_TOKENS = {"password", "passwd", "pwd", "pass", "secret", "secrets",
                       "apisecret", "credential", "credentials"}
# An opaque credential (JWT, API key, session id): only token charset, length
# >= 8. An attack payload contains <,>,',",(,),;,%,space etc. and fails this,
# so it stays visible even when carried in a sensitive-named parameter.
_OPAQUE_TOKEN = re.compile(r"[A-Za-z0-9._~/=+-]{8,}")
# Value-level fallback: an embedded credential assignment in any column.
_VALUE_SENSITIVE = re.compile(
    r"(?i)((session|sess|auth|token|secret|csrf|xsrf|password|passwd|sid|apikey|"
    r"api[-_]?key|access[-_]?token|bearer)\w*\s*[=:]\s*\S)|^(bearer|basic)\s+\S")


def _name_tokens(name: str) -> set:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name or "")
    return {t for t in re.split(r"[^A-Za-z0-9]+", s.lower()) if t}


def _name_is_sensitive(name: str) -> bool:
    toks = _name_tokens(name)
    if toks & _SENSITIVE_TOKENS:
        return True
    flat = "".join(re.split(r"[^a-z0-9]+", (name or "").lower()))
    return any(c in flat for c in _SENSITIVE_COMPOUNDS)


def _name_always_mask(name: str) -> bool:
    return bool(_name_tokens(name) & _ALWAYS_MASK_TOKENS)


def _looks_like_credential(value: str) -> bool:
    return bool(_OPAQUE_TOKEN.fullmatch(value or ""))


def _mask_value(value: str) -> str:
    return f"<redacted len={len(value)}>"


def _redact_pairs(raw: str, sep: str, mask_all: bool):
    """Redact a delimited 'name=value' string (query string or cookie).
    Cookies (mask_all=True): every value masked. Query string: password-family
    always masked; other sensitive-named params masked only when the value
    looks like an opaque credential — so attack payloads (q=<script>, even in a
    param named 'token') stay visible. Returns (redacted_str, masked_bool)."""
    out, masked = [], False
    for pair in raw.split(sep):
        pair = pair.strip()
        if not pair:
            continue
        if "=" in pair:
            name, _, value = pair.partition("=")
            nm = name.strip()
            do_mask = False
            if value:
                if mask_all or _name_always_mask(nm):
                    do_mask = True
                elif _name_is_sensitive(nm) and _looks_like_credential(value):
                    do_mask = True
            if do_mask:
                out.append(f"{nm}={_mask_value(value)}")
                masked = True
            else:
                out.append(f"{nm}={value}")
        else:
            out.append(pair)
    return (sep.join(out), masked)


def _redact_headers(headers: list):
    """headers: list of {'name','value'}. Mask values of sensitive-named headers
    wholesale (e.g. 'Authorization: Bearer ...' contains a space and cannot be
    opaque-token-checked), keep names. Returns (formatted_str, masked_bool)."""
    out, masked = [], False
    for h in headers or []:
        if not isinstance(h, dict):
            continue
        name = h.get("name", "") or ""
        value = h.get("value", "") or ""
        if name and value and _name_is_sensitive(name):
            out.append(f"{name}: {_mask_value(value)}")
            masked = True
        else:
            out.append(f"{name}: {value}")
    return (" | ".join(out), masked)


def _redact(kind: str, raw: str):
    """Redact one raw sample for display. Returns (redacted, masked_bool)."""
    if not raw:
        return ("", False)
    if kind == "uri":
        return (raw, False)  # path — no secrets
    if kind == "args":
        return _redact_pairs(raw, "&", mask_all=False)
    if kind == "cookie":
        return _redact_pairs(raw, ";", mask_all=True)  # cookie values are always secret
    if kind == "header":
        try:
            headers = json.loads(raw)
        except Exception:
            return ("", False)
        return _redact_headers(headers)
    return (raw, False)


def athena_content_expr(kind: str) -> str | None:
    """Athena SELECT expression for the request component of a given location
    kind. Shared so direct-Athena callers (e.g. patrol) build the same query as
    sample_inspection_content. Returns None for kinds with no useful content."""
    if kind == "args":
        return "httprequest.args"
    if kind == "uri":
        return "httprequest.uri"
    if kind == "cookie":
        return ("array_join(transform(filter(httprequest.headers,"
                " h -> lower(h.name) = 'cookie'), h -> h.value), '; ')")
    if kind == "header":
        return "cast(httprequest.headers as json)"
    return None


def _headers_from_message(message: str) -> list:
    try:
        rec = json.loads(message)
        return rec.get("httpRequest", {}).get("headers", []) or []
    except Exception:
        return []


def redact_row_fields(rows: list) -> bool:
    """Mask sensitive VALUES in query-result rows in place. Masks a cell when
    its column NAME is sensitive (cookie/authorization/token/...), OR — as a
    column-name-agnostic fallback (#3) — when the VALUE itself contains an
    embedded credential assignment (e.g. 'sessionid=...', 'Bearer ...'), so a
    future template that selects a secret into an innocuously-named column is
    still covered. Returns True if anything was masked."""
    masked = False
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        for key, val in list(row.items()):
            if not isinstance(val, str) or not val:
                continue
            if _name_is_sensitive(key) or _VALUE_SENSITIVE.search(val):
                row[key] = _mask_value(val)
                masked = True
    return masked


def sample_inspection_content(rule_name: str, cwl_filter: str, athena_where: str,
                              start_epoch: int, end_epoch: int, limit: int = 5):
    """Sample the request component a rule inspects, for the rows the caller is
    analysing, with sensitive values redacted.

    Returns (label, samples, masked):
      - label: human location label, or None if not determinable
      - samples: list of {"content": str, "hits": int}; [] if none found;
        None if the component could not be retrieved on this backend
      - masked: True if any value was redacted (caller must tell the user the
        masking is an intentional privacy safeguard, not a tool limitation)

    cwl_filter / athena_where are the caller's row-selection predicates.
    """
    loc = inspection_location(rule_name)
    if not loc:
        return (None, None, False)
    label, kind = loc
    backend = get_log_type()

    raw_samples = []  # list of (raw_content, hits)
    try:
        if kind in ("args", "uri"):
            fa = "httprequest.args" if kind == "args" else "httprequest.uri"
            fc = "httpRequest.args" if kind == "args" else "httpRequest.uri"
            if backend == "cwl":
                cwl = f"{cwl_filter} | stats count(*) as hits by {fc} | sort hits desc | limit {limit}"
                rows = query_logs(cwl, "", start_epoch, end_epoch, limit=limit) or []
                raw_samples = [(r.get(fc, ""), int(r.get("hits", 0) or 0)) for r in rows]
            else:
                athena = (
                    f"SELECT {fa} as content, count(*) as hits FROM {{TABLE}}"
                    f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
                    f" AND {athena_where} GROUP BY {fa} ORDER BY hits DESC LIMIT {limit}"
                )
                rows = query_logs("", athena, start_epoch, end_epoch, limit=limit) or []
                raw_samples = [(r.get("content", ""), int(r.get("hits", 0) or 0)) for r in rows]
        elif kind == "cookie":
            if backend == "cwl":
                # Aggregate over a sample of messages so hits are real frequencies
                # (consistent with the args/uri stats and the Athena GROUP BY).
                cwl = f"{cwl_filter} | fields @message | limit 25"
                rows = query_logs(cwl, "", start_epoch, end_epoch, limit=25) or []
                counter = Counter()
                for r in rows:
                    hdrs = _headers_from_message(r.get("@message", ""))
                    val = "; ".join(h.get("value", "") for h in hdrs if h.get("name", "").lower() == "cookie")
                    if val:
                        counter[val] += 1
                raw_samples = counter.most_common(limit)
            else:
                expr = ("array_join(transform(filter(httprequest.headers,"
                        " h -> lower(h.name) = 'cookie'), h -> h.value), '; ')")
                athena = (
                    f"SELECT {expr} as content, count(*) as hits FROM {{TABLE}}"
                    f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
                    f" AND {athena_where} AND {expr} <> '' GROUP BY {expr} ORDER BY hits DESC LIMIT {limit}"
                )
                rows = query_logs("", athena, start_epoch, end_epoch, limit=limit) or []
                raw_samples = [(r.get("content", ""), int(r.get("hits", 0) or 0)) for r in rows]
        elif kind == "header":
            if backend == "cwl":
                cwl = f"{cwl_filter} | fields @message | limit 25"
                rows = query_logs(cwl, "", start_epoch, end_epoch, limit=25) or []
                counter = Counter()
                for r in rows:
                    hdrs = _headers_from_message(r.get("@message", ""))
                    if hdrs:
                        counter[json.dumps(hdrs)] += 1
                raw_samples = counter.most_common(limit)
            else:
                expr = "cast(httprequest.headers as json)"
                athena = (
                    f"SELECT {expr} as content, count(*) as hits FROM {{TABLE}}"
                    f" WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
                    f" AND {athena_where} GROUP BY {expr} ORDER BY hits DESC LIMIT {limit}"
                )
                rows = query_logs("", athena, start_epoch, end_epoch, limit=limit) or []
                raw_samples = [(r.get("content", ""), int(r.get("hits", 0) or 0)) for r in rows]
    except Exception:
        return (label, None, False)

    samples, masked = [], False
    for raw, hits in raw_samples:
        red, m = _redact(kind, raw)
        masked = masked or m
        if red:
            samples.append({"content": red, "hits": hits})
    return (label, samples, masked)


# Hint the agent MUST relay to the user whenever inspected content was masked,
# so masking reads as a deliberate privacy safeguard rather than the agent
# being unable to see the data.
PRIVACY_MASK_HINT = (
    "Sensitive values (cookies, auth/session tokens, API keys) were masked as "
    "<redacted len=N>. Tell the user EXPLICITLY that you intentionally do not "
    "display these secret values to protect their privacy — the WAF rule still "
    "inspected the full value, and any attack match is shown in Match Detail. "
    "This is a deliberate safeguard, not a limitation."
)

# Hint when a location yielded no content. Absence is ambiguous: the field may
# genuinely be empty, OR the user configured AWS WAF logging RedactedFields to
# strip it (shows as REDACTED / drops from the log). The agent must surface this
# so a "no data" result is never mistaken for "no attack / no false positive".
REDACTION_POSSIBLE_HINT = (
    "No content was found at this location. This may be because the field was "
    "empty, OR because you configured AWS WAF logging RedactedFields to redact "
    "it (e.g. the Cookie/Authorization header or query string). Tell the user we "
    "could not inspect this location and that, if it is redacted in their WAF "
    "logging config, we cannot assess false positives or injection there."
)


_HOURLY_PARTITION_ERROR = (
    "BLOCKED: This table uses hourly partitioning (the Firehose default). Log-detail queries "
    "are intentionally stopped here — on production traffic they would scan a whole hour per "
    "query and take 30-60s or time out, which breaks interactive analysis. This is a deliberate "
    "stop for query speed, NOT a data error and NOT a tool failure.\n"
    "ACTION: Call search_waf_knowledge(query='Firehose minute-level partitioning for Athena WAF "
    "log queries') to retrieve the guide, then explain to the user IN YOUR OWN WORDS: (1) why "
    "the agent stopped (scan-time/UX, not correctness), (2) that aggregate CloudWatch metrics "
    "still work meanwhile, and (3) the concrete one-time Firehose prefix change to fix it "
    "(Console or CLI steps from the knowledge base). Do NOT just paste a link — walk them "
    "through the cause and the fix."
)


def check_hourly_partition_block() -> str | None:
    """Return the coarse-partition error if the Athena table is coarser than
    minute-level, else None.

    Best-effort pre-flight only, and deliberately so. It reads
    `_athena_state["partition_format"]`, which is written by table resolution, so
    on a cold session where nothing has resolved a table yet it returns None and
    the caller proceeds. That is fine because the real block is enforced inside
    `query_logs` after resolution; this only exists to fail early with written
    guidance instead of a bare exception. Do not add a resolve call here: callers
    use it as a cheap guard and resolution walks S3 and the Glue catalog."""
    if get_log_type() != "s3":
        return None
    from tools.waf_athena import _athena_state, _partition_has_minutes
    part_fmt = _athena_state.get("partition_format")
    if part_fmt and not _partition_has_minutes(part_fmt):
        return _HOURLY_PARTITION_ERROR
    return None


# Result columns that carry a wall-clock timestamp (produced by the time-based
# query templates). Used to convert CWL Insights' UTC output to session-local.
_TIME_FIELD_NAMES = {"first_seen", "last_seen", "minute", "time_bucket"}
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?$")


def _shift_time_fields(rows: list[dict] | None, tz_seconds: int) -> list[dict] | None:
    """Shift UTC wall-clock strings in known time columns to the session tz.

    CWL Insights renders bin()/@timestamp in UTC. We add the session offset so
    these match Athena output (offset in-SQL) and get_waf_overview (local). A
    field qualifies only if its NAME is a known time column (or a `bin(...)`
    alias) AND its VALUE parses as a plain datetime — so non-time fields are
    never touched. No-op when tz_seconds == 0."""
    if not rows or not tz_seconds:
        return rows
    from datetime import datetime, timedelta
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key, val in list(row.items()):
            if not isinstance(val, str) or not val:
                continue
            if key not in _TIME_FIELD_NAMES and not key.startswith("bin("):
                continue
            if not _TS_RE.match(val.strip()):
                continue
            try:
                dt = datetime.fromisoformat(val.strip()) + timedelta(seconds=tz_seconds)
                row[key] = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                continue
    return rows


def query_logs(query_cwl: str, query_athena: str, start_epoch: int, end_epoch: int, limit: int = 25) -> list[dict] | None:
    """Execute a log query, routing to CWL or Athena based on log destination.

    Args:
        query_cwl: CloudWatch Logs Insights query string.
        query_athena: Athena SQL query string (use {TABLE} placeholder for table name,
                      {START_MS} and {END_MS} for timestamp range in milliseconds).
        start_epoch: Start time (epoch seconds).
        end_epoch: End time (epoch seconds).
        limit: Max results.

    Returns:
        List of dicts (field→value), or None if no logging configured.
    """
    dest = get_log_destination()
    if not dest:
        raise RuntimeError("No log destination configured. Call get_waf_config first.")

    if ":log-group:" in dest:
        log_group = dest.split(":log-group:")[-1].rstrip(":*")
        rows = _run_cwl(log_group, query_cwl, start_epoch, end_epoch, limit)
        # CWL Insights returns bin()/@timestamp fields in UTC. Shift the known
        # time-valued columns to the session timezone so CWL output matches the
        # Athena output (which is offset in-SQL) and the metrics overview.
        _tz_off = get_user_timezone()
        return _shift_time_fields(rows, int(round((_tz_off or 0) * 3600)))
    elif ":s3:::" in dest or ":firehose:" in dest:
        table = _ensure_athena_table(dest)
        # Block queries on coarse (hourly or coarser) partitions — they make
        # Athena scan too much data per query and time out on production traffic.
        # Safe as a bare granularity test because discovery rejects any declared
        # format it could not classify, so nothing unclassifiable reaches here.
        from tools.waf_athena import _athena_state, _partition_has_minutes
        if _athena_state.get("partition_format") and not _partition_has_minutes(_athena_state["partition_format"]):
            raise RuntimeError(_HOURLY_PARTITION_ERROR)
        sql = query_athena.replace("{TABLE}", table)
        sql = sql.replace("{START_MS}", str(start_epoch * 1000))
        sql = sql.replace("{END_MS}", str(end_epoch * 1000))
        sql = sql.replace("{LIMIT}", str(limit))
        # Timezone: WAF log `timestamp` is epoch millis (UTC). Templates that
        # DISPLAY a wall-clock time add {TZ_OFFSET_SECONDS} inside from_unixtime()
        # so the returned string is in the user's session timezone — consistent
        # with get_waf_overview (metrics), which already returns local times.
        # Without this the agent gets UTC strings while everything else is local
        # and misreports the hour of an event.
        _tz_off = get_user_timezone()
        _tz_seconds = int(round((_tz_off or 0) * 3600))
        sql = sql.replace("{TZ_OFFSET_SECONDS}", str(_tz_seconds))
        # Inject partition pruning. Rendering the bounds, choosing the timezone
        # and checking the projected range all live in partition_predicate so
        # patrol's Athena path cannot drift from this one.
        from tools.waf_athena import partition_predicate
        from datetime import datetime, timezone as _tz
        partition_clause, range_problem = partition_predicate(
            datetime.fromtimestamp(start_epoch, tz=_tz.utc),
            datetime.fromtimestamp(end_epoch, tz=_tz.utc),
        )
        if range_problem:
            # Fatal here: the query would come back empty and the agent would
            # report "no traffic", which is a wrong answer rather than a slow one.
            raise RuntimeError(range_problem)
        # If the table is not WebACL-specific (e.g. a Firehose bucket-root table
        # shared by multiple WebACLs), filter by webaclid so we never count
        # another WebACL's traffic. webaclid in the logs is the full ARN, which
        # contains the WebACL name as a path segment. WebACL names are limited to
        # [A-Za-z0-9-_] by AWS, so no SQL-escaping is needed.
        if not _athena_state.get("webacl_scoped", True):
            wn = get_webacl_name()
            if wn and re.fullmatch(r"[A-Za-z0-9_-]+", wn):
                partition_clause += f" AND webaclid LIKE '%/{wn}/%'"
        sql = sql.replace("{PARTITION_FILTER}", partition_clause)
        return _run_athena(sql)
    raise RuntimeError(f"Unsupported log destination format: {dest}")


def get_log_type() -> str:
    """Return 'cwl', 's3', or 'none'."""
    dest = get_log_destination()
    if not dest:
        return "none"
    if ":log-group:" in dest:
        return "cwl"
    if ":s3:::" in dest or ":firehose:" in dest:
        return "s3"
    return "none"


def _run_cwl(log_group: str, query: str, start_epoch: int, end_epoch: int, limit: int) -> list[dict]:
    """Execute CWL Insights query."""
    region = get_logs_region()
    client = get_client("logs", region_name=region)
    with _cwl_semaphore:
        resp = client.start_query(
            logGroupName=log_group, startTime=start_epoch, endTime=end_epoch,
            queryString=query, limit=limit,
        )
        query_id = resp["queryId"]
        deadline = time.monotonic() + MAX_POLL
        while time.monotonic() < deadline:
            time.sleep(POLL_INTERVAL)
            result = client.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
    # A non-Complete status used to return [], which `run_logs_query` then reported as
    # "0 results" with three suggested reasons, none of which is "the query never
    # finished". Returning the `_error` row the caller already knows how to surface keeps
    # a stopped query from reading as an absence of traffic.
    if result["status"] in ("Failed", "Cancelled"):
        return [{"_error": query_failed_message("CloudWatch Logs Insights", result["status"])}]
    if result["status"] != "Complete":
        return [{"_error": poll_timeout_message("CloudWatch Logs Insights")}]
    note_query_success()
    return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]


def _run_athena(sql: str) -> list[dict]:
    """Execute Athena SQL query."""
    from tools.waf_athena import _run_athena_select
    region = get_logs_region()
    return _run_athena_select(sql, region)


def _ensure_athena_table(dest: str) -> str | None:
    """Return the Athena table for this log destination, resolving one if needed.

    Holds no cache of its own; it reads the single cache in `_athena_state` and
    otherwise delegates. Both the destination-to-S3-path translation and the table
    resolution now live in `waf_athena` and are shared with patrol, so the two query
    paths have no remaining opportunity to disagree.
    """
    from tools.waf_athena import _athena_state, resolve_s3_log_path, resolve_log_table

    # Read the one cache before any AWS call. This is not a second cache: it is the
    # same key resolve_log_table checks, read early so a warm session makes no
    # control-plane call at all. Losing this line cost one or two describes per query.
    if _athena_state.get("table"):
        return _athena_state["table"]

    try:
        region = get_logs_region()
        s3_path = resolve_s3_log_path(dest, get_scope(), get_webacl_name() or "unknown", region)
        return resolve_log_table(s3_path, region, get_webacl_name() or "unknown")
    except Exception as e:
        raise RuntimeError(f"Athena table setup failed: {type(e).__name__}: {e}") from e
