# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Unified WAF log query layer — routes to CWL or Athena based on log destination."""

import re
import json
import time
import threading
from tools.aws_session import get_client
from tools.session_state import get_log_destination, get_logs_region, get_webacl_name, get_scope

_cwl_semaphore = threading.Semaphore(8)
MAX_POLL = 120
POLL_INTERVAL = 2

# Athena state (reuse existing table if already created)
_athena_table: str | None = None
_table_setup_lock = threading.Lock()


def reset_table_cache():
    """Reset the cached Athena table name. Called on WebACL switch so a stale
    table from the previous WebACL is not reused."""
    global _athena_table
    _athena_table = None
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
    return None  # BODY (not logged) or unknown


# Header/param names whose VALUES are secrets and must never be shown to the
# user. We display the name (and length) but mask the value. Matching is on a
# substring of the (lower-cased) name.
_SENSITIVE_KEY = re.compile(
    r"(authorization|auth|cookie|token|session|sess[-_]?id|secret|password|passwd|"
    r"pwd|api[-_]?key|apikey|x-api|csrf|xsrf|signature|sig|bearer|"
    r"access[-_]?token|id[-_]?token|refresh[-_]?token|x-amz-security-token|credential)",
    re.I,
)


def _mask_value(value: str) -> str:
    return f"<redacted len={len(value)}>"


def _redact_pairs(raw: str, sep: str, mask_all: bool):
    """Redact a delimited 'name=value' string (query string or cookie).
    mask_all=True masks every value (cookies); else only sensitive-named ones.
    Returns (redacted_str, masked_bool)."""
    out, masked = [], False
    for pair in raw.split(sep):
        pair = pair.strip()
        if not pair:
            continue
        if "=" in pair:
            name, _, value = pair.partition("=")
            if value and (mask_all or _SENSITIVE_KEY.search(name)):
                out.append(f"{name.strip()}={_mask_value(value)}")
                masked = True
            else:
                out.append(f"{name.strip()}={value}")
        else:
            out.append(pair)
    return (sep.join(out), masked)


def _redact_headers(headers: list):
    """headers: list of {'name','value'}. Mask values of sensitive headers,
    keep names. Returns (formatted_str, masked_bool)."""
    out, masked = [], False
    for h in headers or []:
        if not isinstance(h, dict):
            continue
        name = h.get("name", "") or ""
        value = h.get("value", "") or ""
        if name and _SENSITIVE_KEY.search(name):
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


def _headers_from_message(message: str) -> list:
    try:
        rec = json.loads(message)
        return rec.get("httpRequest", {}).get("headers", []) or []
    except Exception:
        return []


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
                cwl = f"{cwl_filter} | fields @message | limit {limit}"
                rows = query_logs(cwl, "", start_epoch, end_epoch, limit=limit) or []
                for r in rows:
                    hdrs = _headers_from_message(r.get("@message", ""))
                    val = "; ".join(h.get("value", "") for h in hdrs if h.get("name", "").lower() == "cookie")
                    if val:
                        raw_samples.append((val, 1))
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
                cwl = f"{cwl_filter} | fields @message | limit {limit}"
                rows = query_logs(cwl, "", start_epoch, end_epoch, limit=limit) or []
                for r in rows:
                    hdrs = _headers_from_message(r.get("@message", ""))
                    if hdrs:
                        raw_samples.append((json.dumps(hdrs), 1))
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
    "Error: Firehose hourly partition detected. Queries will timeout on production traffic.\n"
    "Please configure minute-level partitioning on your Firehose stream.\n"
    "Guide: https://github.com/aws-samples/sample-building-a-conversational-ai-agent-for-aws-waf-analysis-with-agentcore/blob/main/docs/firehose-minute-partitioning.md\n"
    "ACTION: Inform user about this limitation and share the guide link."
)


def check_hourly_partition_block() -> str | None:
    """Return error message if Athena backend has hourly partitions, else None."""
    if get_log_type() != "s3":
        return None
    from tools.waf_athena import _athena_state
    if _athena_state.get("partition_format") == "yyyy/MM/dd/HH":
        return _HOURLY_PARTITION_ERROR
    return None

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
        return _run_cwl(log_group, query_cwl, start_epoch, end_epoch, limit)
    elif ":s3:::" in dest or ":firehose:" in dest:
        table = _ensure_athena_table(dest)
        # Block queries on hourly partitions (Firehose without minute-level prefix)
        from tools.waf_athena import _athena_state
        if _athena_state.get("partition_format") == "yyyy/MM/dd/HH":
            raise RuntimeError(_HOURLY_PARTITION_ERROR)
        sql = query_athena.replace("{TABLE}", table)
        sql = sql.replace("{START_MS}", str(start_epoch * 1000))
        sql = sql.replace("{END_MS}", str(end_epoch * 1000))
        sql = sql.replace("{LIMIT}", str(limit))
        # Inject partition pruning
        from tools.waf_athena import _athena_state
        from datetime import datetime, timezone as tz
        part_fmt = _athena_state.get("partition_format")
        if part_fmt:
            start_dt = datetime.fromtimestamp(start_epoch, tz=tz.utc)
            end_dt = datetime.fromtimestamp(end_epoch, tz=tz.utc)
            if "mm" in part_fmt:
                sp = start_dt.strftime("%Y/%m/%d/%H/%M")
                ep = end_dt.strftime("%Y/%m/%d/%H/%M")
            else:
                sp = start_dt.strftime("%Y/%m/%d/%H")
                ep = end_dt.strftime("%Y/%m/%d/%H")
            partition_clause = f"AND log_time >= '{sp}' AND log_time <= '{ep}'"
        else:
            partition_clause = ""
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
        elapsed = 0
        while elapsed < MAX_POLL:
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            result = client.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
    if result["status"] != "Complete":
        return []
    return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]


def _run_athena(sql: str) -> list[dict]:
    """Execute Athena SQL query."""
    from tools.waf_athena import _run_athena_select
    region = get_logs_region()
    return _run_athena_select(sql, region)


def _ensure_athena_table(dest: str) -> str | None:
    """Ensure Athena table exists for the log destination. Returns table name or None."""
    global _athena_table
    if _athena_table:
        return _athena_table

    # Serialize table setup. The agent fires Athena queries in parallel; without
    # this lock two threads could both run the DROP/CREATE in _create_named_table,
    # and one could drop the table while the other queries it.
    with _table_setup_lock:
        # Double-checked: another thread may have built it while we waited.
        if _athena_table:
            return _athena_table

        try:
            from tools.waf_athena import (
                _resolve_s3_path, _try_standard_path, _get_account_id,
                _find_existing_table, _validate_waf_log, _detect_partitions,
                _create_named_table, _athena_state,
            )

            s3_base = _resolve_s3_path(dest)
            bucket = s3_base.replace("s3://", "").split("/")[0]
            scope = get_scope()
            webacl_name = get_webacl_name() or "unknown"
            region = get_logs_region()

            # Try standard path for S3 direct delivery
            s3_path = None
            if ":s3:::" in dest:
                account_id = _get_account_id()
                s3_path = _try_standard_path(bucket, account_id, scope, webacl_name, region)
            if not s3_path:
                s3_path = s3_base

            # A table whose location does NOT include the WebACL name (e.g. a
            # Firehose bucket-root prefix) may hold logs from multiple WebACLs.
            # Record this so query_logs can add a webaclid filter to avoid
            # cross-WebACL contamination.
            webacl_scoped = webacl_name.lower() in s3_path.lower()
            _athena_state["webacl_scoped"] = webacl_scoped

            # Check for existing table
            existing = _find_existing_table(s3_path, region)
            if existing:
                # Validate partition config and path match S3 structure
                try:
                    from tools.aws_session import get_client as _gc
                    glue = _gc("glue", region_name=region)
                    db, tbl_name = existing.split(".", 1)
                    tbl_resp = glue.get_table(DatabaseName=db, Name=tbl_name)
                    tbl_params = tbl_resp["Table"].get("Parameters", {})
                    existing_interval = tbl_params.get("projection.log_time.interval", "1")
                    table_location = tbl_resp["Table"]["StorageDescriptor"]["Location"].rstrip("/")
                    resolved = s3_path.rstrip("/")
                    _, part_fmt, _, actual_interval = _detect_partitions(s3_path)
                    interval_mismatch = str(actual_interval) != str(existing_interval)
                    # Path mismatch: resolved must be equal to or more specific than table location.
                    # If resolved is just bucket root but table points to a sub-path, it's a mismatch
                    # (log delivery method changed — e.g., Vended Logs → Firehose).
                    path_mismatch = not resolved.startswith(table_location)
                    if interval_mismatch or path_mismatch:
                        if db == "waf_analysis_tmp":
                            glue.delete_table(DatabaseName=db, Name=tbl_name)
                            # Fall through to create new table
                        else:
                            pass  # External table — create our own below
                    else:
                        _athena_table = existing
                        _athena_state["table"] = existing
                        _athena_state["partition_format"] = part_fmt
                        return existing
                except Exception:
                    _athena_table = existing
                    _athena_state["table"] = existing
                    # Best-effort partition_format so query_logs can prune and
                    # apply the hourly-partition guard.
                    try:
                        _, pf, _, _ = _detect_partitions(s3_path)
                        _athena_state["partition_format"] = pf
                    except Exception:
                        pass
                    return existing

            # Create permanent table
            if not _validate_waf_log(s3_path):
                raise RuntimeError(f"S3 path does not contain valid AWS WAF logs: {s3_path}. Verify the log destination is correct.")
            storage_template, part_fmt, part_unit, part_interval = _detect_partitions(s3_path)
            safe_name = re.sub(r"[^a-zA-Z0-9]", "_", webacl_name).lower()
            full_table = _create_named_table(
                s3_path, storage_template, part_fmt, part_unit, part_interval,
                region, "primary", f"waf_logs_{safe_name}"
            )
            _athena_table = full_table
            _athena_state["table"] = full_table
            _athena_state["partition_format"] = part_fmt
            return full_table
        except Exception as e:
            raise RuntimeError(f"Athena table setup failed: {type(e).__name__}: {e}") from e
