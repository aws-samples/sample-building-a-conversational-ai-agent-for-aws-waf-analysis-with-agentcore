# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Unified WAF log query layer — routes to CWL or Athena based on log destination."""

import re
import time
import threading
from tools.aws_session import get_client
from tools.session_state import get_log_destination, get_logs_region, get_webacl_name, get_scope

_cwl_semaphore = threading.Semaphore(8)
MAX_POLL = 120
POLL_INTERVAL = 2

# Athena state (reuse existing table if already created)
_athena_table: str | None = None



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
