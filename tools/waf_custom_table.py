# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""set_log_table — let the user point the agent at their own Athena/Glue WAF log table."""

from strands import tool

from tools.session_state import (
    set_custom_table,
    get_custom_table,
    get_logs_region,
    get_webacl_name,
)


@tool
def set_log_table(database: str = "", table: str = "") -> str:
    """Use a specific user-provided Athena/Glue table for WAF log queries instead of auto-detection.

    Call this when the user asks to "use my table", "query my existing WAF table",
    or when auto-detection picked the wrong table (or failed to find one). All
    subsequent log-detail queries for the current WebACL (run_logs_query,
    analyze_ip, detect_bypass, patrol_scan, etc.) will run against this table.

    To restore automatic detection, call with empty database and table:
    set_log_table(database='', table='').

    Requirements for the table (validated here — the call fails with a clear
    reason if unmet):
      - It exists in the Glue Data Catalog in the WAF logs region.
      - It exposes the WAF log columns `action` and `httprequest` (exact names).
      - It has exactly one time-based partition column using Athena partition
        projection of type `date`. The column name can be anything (`log_time`,
        `datehour`, `dt`, ...); its projection `format` drives query pruning.
        Integer/enum partitions, non-projected Hive partitions, and multi-key
        partitioning are not supported.

    Notes:
      - Select a WebACL and run get_waf_config first so the region is resolved.
      - The override applies to the current WebACL only; switching WebACL clears
        it, so re-set it if your table spans multiple WebACLs.

    Args:
        database: Glue database containing the table (e.g. "waf_logs_db"). Empty clears the override.
        table: Table name (e.g. "my_waf_logs"). Empty clears the override.

    Returns:
        A confirmation describing the active table, its S3 location, and detected
        partition format — or an error explaining why the table can't be used.
    """
    # Clear override → resume auto-detection.
    if not database or not table:
        set_custom_table("", "")
        return (
            "Cleared the custom log table. The agent will auto-detect or create a "
            "table from the WebACL's logging configuration on the next log query."
        )

    # Store first, then validate by resolving it (raises RuntimeError with an
    # actionable message on any problem). Resolution also populates the shared
    # table cache so the very next log query reuses it without re-detecting.
    set_custom_table(database, table)
    region = get_logs_region()
    try:
        from tools.waf_athena import _apply_custom_table
        full = _apply_custom_table(region)
    except Exception as e:
        # Roll back the bad override so we don't leave the session pinned to an
        # unusable table.
        set_custom_table("", "")
        return f"Could not use `{database}.{table}`: {e}"

    from tools.waf_athena import _athena_state, _partition_has_minutes
    part_fmt = _athena_state.get("partition_format")
    part_col = _athena_state.get("partition_col", "log_time")
    webacl_scoped = _athena_state.get("webacl_scoped", False)
    wn = get_webacl_name() or "the current WebACL"

    coarse_note = ""
    if not _partition_has_minutes(part_fmt):
        coarse_note = (
            "\n- NOTE: this table partitions coarser than minute-level "
            f"({part_fmt}). Log-detail queries are allowed but may scan a lot of "
            "data and can hit the Athena timeout on busy traffic — narrow the time "
            "window if a query is slow."
        )

    scope_note = (
        "Its location includes the WebACL name, so results reflect only "
        f"{wn}."
        if webacl_scoped
        else "Its location is not specific to this WebACL. Automatic single-WebACL "
        "scoping is disabled, so queries will include every WebACL present in this "
        "table (no `webaclid` filter is added)."
    )

    return (
        f"Now using `{full}` for WAF log queries in region {region}.\n"
        f"- Partition column: {part_col} (format {part_fmt})\n"
        f"- {scope_note}"
        f"{coarse_note}\n"
        "This applies to the current WebACL. Call set_log_table(database='', table='') "
        "to return to automatic detection."
    )
