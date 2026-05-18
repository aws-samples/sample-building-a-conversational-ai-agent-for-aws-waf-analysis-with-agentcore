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
        return None

    if ":log-group:" in dest:
        log_group = dest.split(":log-group:")[-1].rstrip(":*")
        return _run_cwl(log_group, query_cwl, start_epoch, end_epoch, limit)
    elif ":s3:::" in dest or ":firehose:" in dest:
        table = _ensure_athena_table(dest)
        if not table:
            return None
        sql = query_athena.replace("{TABLE}", table)
        sql = sql.replace("{START_MS}", str(start_epoch * 1000))
        sql = sql.replace("{END_MS}", str(end_epoch * 1000))
        sql = sql.replace("{LIMIT}", str(limit))
        return _run_athena(sql)
    return None


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
            _create_named_table, _ensure_database, _athena_state,
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
            _athena_table = existing
            _athena_state["table"] = existing
            return existing

        # Create permanent table
        if not _validate_waf_log(s3_path):
            return None
        storage_template, part_fmt, part_unit = _detect_partitions(s3_path)
        safe_name = re.sub(r"[^a-zA-Z0-9]", "_", webacl_name).lower()
        full_table = _create_named_table(
            s3_path, storage_template, part_fmt, part_unit,
            region, "primary", f"waf_logs_{safe_name}"
        )
        _athena_table = full_table
        _athena_state["table"] = full_table
        _athena_state["partition_format"] = part_fmt
        return full_table
    except Exception:
        return None
