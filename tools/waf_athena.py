# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Athena query tool — for S3-stored AWS WAF logs."""

import re
import time
import gzip
import json
import tempfile
import os
from datetime import datetime, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_log_destination, get_webacl_name, get_scope

MAX_POLL = 300
TMP_DATABASE = "waf_analysis_tmp"

# Module-level state (lazy init on first query)
_athena_state = {
    "table": None,           # "database.table_name"
    "partition_format": None, # "yyyy/MM/dd/HH" or "yyyy/MM/dd/HH/mm"
    "temp_created": False,
}


# ---------------------------------------------------------------------------
# S3 path resolution
# ---------------------------------------------------------------------------


def _resolve_s3_path(log_dest_arn: str) -> str:
    """Resolve log destination ARN to an S3 path prefix.
    Handles both S3 direct delivery and Firehose delivery."""
    if ":s3:::" in log_dest_arn:
        bucket = log_dest_arn.split(":::")[1].rstrip("*").rstrip("/")
        return f"s3://{bucket}"
    elif ":firehose:" in log_dest_arn:
        # Extract stream name from ARN
        stream_name = log_dest_arn.split("/")[-1]
        region = log_dest_arn.split(":")[3]
        fh = get_client("firehose", region_name=region)
        resp = fh.describe_delivery_stream(DeliveryStreamName=stream_name)
        dest = resp["DeliveryStreamDescription"]["Destinations"][0]
        # Try ExtendedS3 first, fallback to S3
        s3_dest = dest.get("ExtendedS3DestinationDescription") or dest.get("S3DestinationDescription", {})
        bucket_arn = s3_dest.get("BucketARN", "")
        prefix = s3_dest.get("Prefix", "").rstrip("/")
        bucket = bucket_arn.split(":::")[1] if ":::" in bucket_arn else ""
        # Strip Firehose dynamic expressions (!{timestamp:...}, !{firehose:...})
        import re
        prefix = re.sub(r'!{[^}]*}', '', prefix).strip("/")
        if prefix:
            return f"s3://{bucket}/{prefix}"
        return f"s3://{bucket}"
    else:
        raise RuntimeError(f"Unsupported log destination: {log_dest_arn}")


def _try_standard_path(bucket: str, account_id: str, scope: str, webacl_name: str, region: str) -> str | None:
    """Try the standard AWS WAF direct delivery path. Returns full S3 path or None."""
    s3 = get_client("s3", region_name="us-east-1")
    scope_dir = "cloudfront" if scope == "CLOUDFRONT" else region
    prefix = f"AWSLogs/{account_id}/WAFLogs/{scope_dir}/{webacl_name}/"
    try:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter="/", MaxKeys=1)
        if resp.get("CommonPrefixes") or resp.get("Contents"):
            return f"s3://{bucket}/{prefix}"
    except Exception:
        pass
    return None


def _get_account_id() -> str:
    sts = get_client("sts")
    return sts.get_caller_identity()["Account"]


# ---------------------------------------------------------------------------
# Partition detection (ported from waf-runner-athena.py)
# ---------------------------------------------------------------------------


def _s3_list_dirs(bucket: str, prefix: str) -> list[str]:
    """List directory-like prefixes under an S3 path."""
    s3 = get_client("s3", region_name="us-east-1")
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter="/", MaxKeys=100)
    dirs = []
    for cp in resp.get("CommonPrefixes", []):
        p = cp["Prefix"]
        name = p[len(prefix):].rstrip("/")
        if name:
            dirs.append(name)
    return dirs


def _detect_partitions(s3_path: str) -> tuple[str, str, str, int]:
    """Walk S3 to find partition structure.
    Returns (storage_template, partition_format, partition_unit, partition_interval)."""
    parts = s3_path.replace("s3://", "").split("/", 1)
    bucket = parts[0]
    base_prefix = parts[1] if len(parts) > 1 else ""
    if base_prefix and not base_prefix.endswith("/"):
        base_prefix += "/"

    current_prefix = base_prefix
    for _ in range(10):
        dirs = _s3_list_dirs(bucket, current_prefix)
        if not dirs:
            break
        year_dirs = [d for d in dirs if re.match(r"^20[2-3]\d$", d)]
        if year_dirs:
            year = sorted(year_dirs)[-1]
            # Walk down to determine depth
            test_prefix = current_prefix + year + "/"
            levels = [year]
            for _ in range(5):
                sub_dirs = _s3_list_dirs(bucket, test_prefix)
                if sub_dirs:
                    levels.append(sub_dirs[0])
                    test_prefix = test_prefix + sub_dirs[0] + "/"
                else:
                    break
            if len(levels) >= 5:
                fmt, unit = "yyyy/MM/dd/HH/mm", "minutes"
                # Detect interval from minute-level directories (e.g., 00,05,10 → interval=5)
                minute_dirs = sorted(_s3_list_dirs(bucket, test_prefix.rsplit("/", 2)[0] + "/"))
                if len(minute_dirs) >= 2:
                    try:
                        interval = int(minute_dirs[1]) - int(minute_dirs[0])
                    except (ValueError, IndexError):
                        interval = 5
                else:
                    interval = 5
            else:
                fmt, unit = "yyyy/MM/dd/HH", "hours"
                interval = 1
            storage_template = f"s3://{bucket}/{current_prefix}${{log_time}}"
            return storage_template, fmt, unit, interval

        # Pick best subdir to descend
        chosen = None
        if "AWSLogs" in dirs:
            chosen = "AWSLogs"
        else:
            for d in dirs:
                sub = _s3_list_dirs(bucket, current_prefix + d + "/")
                if any(re.match(r"^20[2-3]\d$", s) for s in sub):
                    chosen = d
                    break
        if not chosen:
            chosen = dirs[0]
        current_prefix = current_prefix + chosen + "/"

    raise RuntimeError(f"Cannot detect partition structure under {s3_path}")


def _validate_waf_log(s3_path: str) -> bool:
    """Download one .gz file and verify it's an AWS WAF log."""
    parts = s3_path.replace("s3://", "").split("/", 1)
    bucket = parts[0]
    prefix = parts[1] if len(parts) > 1 else ""
    if prefix and not prefix.endswith("/"):
        prefix += "/"

    s3 = get_client("s3", region_name="us-east-1")
    # Walk to find a .gz file
    current = prefix
    for _ in range(15):
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=current, Delimiter="/", MaxKeys=50)
        files = [c["Key"] for c in resp.get("Contents", []) if c["Key"].endswith(".gz")]
        if files:
            key = files[0]
            break
        sub_prefixes = resp.get("CommonPrefixes", [])
        if sub_prefixes:
            current = sub_prefixes[0]["Prefix"]
        else:
            return False
    else:
        return False

    # Download and validate
    tmp = tempfile.NamedTemporaryFile(suffix=".gz", delete=False)
    tmp.close()
    try:
        s3.download_file(bucket, key, tmp.name)
        with gzip.open(tmp.name, "rt") as f:
            first_line = f.readline()
        record = json.loads(first_line)
        return {"webaclId", "action", "httpRequest"}.issubset(record.keys())
    except Exception:
        return False
    finally:
        os.unlink(tmp.name)


# ---------------------------------------------------------------------------
# Table discovery and creation
# ---------------------------------------------------------------------------

DDL_TEMPLATE = """
CREATE EXTERNAL TABLE IF NOT EXISTS `{database}`.`{table}` (
  `timestamp` bigint,
  `formatversion` int,
  `webaclid` string,
  `terminatingruleid` string,
  `terminatingruletype` string,
  `action` string,
  `terminatingrulematchdetails` array<struct<conditiontype:string,sensitivitylevel:string,location:string,matcheddata:array<string>>>,
  `httpsourcename` string,
  `httpsourceid` string,
  `rulegrouplist` array<struct<rulegroupid:string,terminatingrule:struct<ruleid:string,action:string,rulematchdetails:array<struct<conditiontype:string,sensitivitylevel:string,location:string,matcheddata:array<string>>>>,nonterminatingmatchingrules:array<struct<ruleid:string,action:string,overriddenaction:string,rulematchdetails:array<struct<conditiontype:string,sensitivitylevel:string,location:string,matcheddata:array<string>>>,challengeresponse:struct<responsecode:string,solvetimestamp:string>,captcharesponse:struct<responsecode:string,solvetimestamp:string>>>,excludedrules:string>>,
  `ratebasedrulelist` array<struct<ratebasedruleid:string,ratebasedrulename:string,limitkey:string,maxrateallowed:int>>,
  `nonterminatingmatchingrules` array<struct<ruleid:string,action:string,rulematchdetails:array<struct<conditiontype:string,sensitivitylevel:string,location:string,matcheddata:array<string>>>,challengeresponse:struct<responsecode:string,solvetimestamp:string>,captcharesponse:struct<responsecode:string,solvetimestamp:string>>>,
  `requestheadersinserted` array<struct<name:string,value:string>>,
  `responsecodesent` string,
  `httprequest` struct<clientip:string,country:string,headers:array<struct<name:string,value:string>>,uri:string,args:string,httpversion:string,httpmethod:string,requestid:string,fragment:string,scheme:string,host:string>,
  `labels` array<struct<name:string>>,
  `captcharesponse` struct<responsecode:string,solvetimestamp:string,failurereason:string>,
  `challengeresponse` struct<responsecode:string,solvetimestamp:string,failurereason:string>,
  `ja3fingerprint` string,
  `ja4fingerprint` string,
  `oversizefields` string,
  `requestbodysize` int,
  `requestbodysizeinspectedbywaf` int
)
PARTITIONED BY (`log_time` string)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
WITH SERDEPROPERTIES ('ignore.malformed.json' = 'true')
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION '{s3_location}'
TBLPROPERTIES (
  'projection.enabled' = 'true',
  'projection.log_time.format' = '{partition_format}',
  'projection.log_time.interval' = '{partition_interval}',
  'projection.log_time.interval.unit' = '{partition_unit}',
  'projection.log_time.range' = '{range_start},NOW',
  'projection.log_time.type' = 'date',
  'storage.location.template' = '{storage_template}'
)
""".strip()


def _find_existing_table(s3_path: str, region: str) -> str | None:
    """Search Glue catalog for a table matching this S3 location."""
    glue = get_client("glue", region_name=region)
    s3_normalized = s3_path.rstrip("/")

    # Search all databases
    try:
        dbs = glue.get_databases().get("DatabaseList", [])
        db_names = [d["Name"] for d in dbs]
    except Exception:
        db_names = [TMP_DATABASE, "default"]

    for db_name in db_names:
        try:
            resp = glue.get_tables(DatabaseName=db_name, MaxResults=100)
            for tbl in resp.get("TableList", []):
                location = tbl.get("StorageDescriptor", {}).get("Location", "").rstrip("/")
                # Match: our s3_path is within the table's location scope (table covers our path)
                if s3_normalized == location or s3_normalized.startswith(location):
                    # Verify it has AWS WAF log columns
                    cols = [c["Name"] for c in tbl["StorageDescriptor"].get("Columns", [])]
                    if "action" in cols and "httprequest" in cols:
                        return f"{db_name}.{tbl['Name']}"
        except Exception:
            continue
    return None


def _ensure_database(region: str, workgroup: str):
    """Create tmp database if not exists."""
    sql = f"CREATE DATABASE IF NOT EXISTS `{TMP_DATABASE}`"
    _run_athena_ddl(sql, region, workgroup)


def _create_named_table(s3_path: str, storage_template: str, partition_format: str,
                        partition_unit: str, partition_interval: int, region: str, workgroup: str, table_name: str) -> str:
    """Create a permanent Athena table with the given name."""
    _ensure_database(region, workgroup)
    range_start = "2020/01/01/00/00" if "mm" in partition_format else "2020/01/01/00"

    ddl = DDL_TEMPLATE.format(
        database=TMP_DATABASE, table=table_name,
        s3_location=s3_path.rstrip("/") + "/",
        partition_format=partition_format, partition_unit=partition_unit,
        partition_interval=partition_interval,
        storage_template=storage_template, range_start=range_start,
    )
    _run_athena_ddl(ddl, region, workgroup)
    return f"{TMP_DATABASE}.{table_name}"


# ---------------------------------------------------------------------------
# Athena query execution
# ---------------------------------------------------------------------------


def _get_output_location(region: str, workgroup: str = "primary") -> str:
    """Get Athena output location from workgroup config or fallback."""
    athena = get_client("athena", region_name=region)
    try:
        resp = athena.get_work_group(WorkGroup=workgroup)
        loc = resp.get("WorkGroup", {}).get("Configuration", {}).get(
            "ResultConfiguration", {}).get("OutputLocation", "")
        if loc:
            return loc
    except Exception:
        pass
    # Fallback 1: use the WAF log bucket with athena-results prefix
    from tools.session_state import get_log_destination
    import sys as _sys
    dest = get_log_destination()
    if dest:
        if ":s3:::" in dest:
            bucket = dest.split(":s3:::")[-1].rstrip(":*").split("/")[0]
            print(f"[waf_athena] Workgroup has no output location. Using fallback: s3://{bucket}/athena-results/", file=_sys.stderr, flush=True)
            return f"s3://{bucket}/athena-results/"
        elif ":firehose:" in dest:
            try:
                firehose = get_client("firehose", region_name=region)
                stream_name = dest.split("/")[-1]
                resp = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
                s3_dest = resp["DeliveryStreamDescription"]["Destinations"][0].get("ExtendedS3DestinationDescription", {})
                bucket = s3_dest.get("BucketARN", "").split(":::")[-1]
                if bucket:
                    print(f"[waf_athena] Workgroup has no output location. Using fallback: s3://{bucket}/athena-results/", file=_sys.stderr, flush=True)
                    return f"s3://{bucket}/athena-results/"
            except Exception:
                pass
    # Fallback 2: find any athena results bucket
    s3 = get_client("s3", region_name=region)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            if "athena" in name and "result" in name:
                return f"s3://{name}/"
    except Exception:
        pass
    raise RuntimeError(
        "No Athena output location found. Either:\n"
        "1. Configure an output location in the Athena 'primary' workgroup, or\n"
        "2. Ensure the agent's IAM role has s3:PutObject on the WAF log bucket.\n"
        "ACTION: Guide user to set Athena workgroup output location in the AWS Console → Athena → Workgroups → primary → Edit → Query result location."
    )


def _run_athena_ddl(sql: str, region: str, workgroup: str = "primary"):
    """Run DDL (CREATE/DROP) and wait."""
    athena = get_client("athena", region_name=region)
    output_loc = _get_output_location(region, workgroup)
    resp = athena.start_query_execution(
        QueryString=sql, WorkGroup=workgroup,
        QueryExecutionContext={"Database": TMP_DATABASE},
        ResultConfiguration={"OutputLocation": output_loc},
    )
    _wait_query(athena, resp["QueryExecutionId"])


def _run_athena_select(sql: str, region: str, workgroup: str = "primary", limit: int = 25) -> list[dict]:
    """Run SELECT query, wait, return rows as list of dicts."""
    athena = get_client("athena", region_name=region)
    output_loc = _get_output_location(region, workgroup)
    resp = athena.start_query_execution(
        QueryString=sql, WorkGroup=workgroup,
        ResultConfiguration={"OutputLocation": output_loc},
        ResultReuseConfiguration={"ResultReuseByAgeConfiguration": {"Enabled": True, "MaxAgeInMinutes": 60}},
    )
    qid = resp["QueryExecutionId"]
    _wait_query(athena, qid)

    # Fetch results
    columns = []
    rows = []
    paginator = athena.get_paginator("get_query_results")
    first_page = True
    for page in paginator.paginate(QueryExecutionId=qid, MaxResults=limit + 1):
        rs = page.get("ResultSet", {})
        if not columns:
            columns = [c["Name"] for c in rs.get("ResultSetMetadata", {}).get("ColumnInfo", [])]
        page_rows = rs.get("Rows", [])
        start = 1 if first_page else 0
        first_page = False
        for row in page_rows[start:]:
            record = {}
            for i, cell in enumerate(row.get("Data", [])):
                if i < len(columns):
                    record[columns[i]] = cell.get("VarCharValue", "")
            rows.append(record)
            if len(rows) >= limit:
                return rows
    return rows


def _wait_query(athena, qid: str):
    """Poll until query completes."""
    elapsed = 0
    while elapsed < MAX_POLL:
        time.sleep(2)  # nosemgrep: arbitrary-sleep — polling for Athena query completion
        elapsed += 2
        resp = athena.get_query_execution(QueryExecutionId=qid)
        state = resp["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            return
        if state in ("FAILED", "CANCELLED"):
            reason = resp["QueryExecution"]["Status"].get("StateChangeReason", "")
            raise RuntimeError(f"Athena query {state}: {reason}")
    raise RuntimeError("Athena query timed out (>5min). Narrow the time window — try duration_minutes=30 or duration_minutes=15. Use get_waf_overview to identify the exact spike period first.")


# ---------------------------------------------------------------------------
# Lazy initialization
# ---------------------------------------------------------------------------



def _ensure_table(region: str) -> str:
    """Ensure Athena table is ready. Returns full table name.

    Auto-creates a permanent table if none exists.
    """
    if _athena_state["table"]:
        return _athena_state["table"]

    log_dest = get_log_destination()
    if not log_dest:
        raise RuntimeError("No log destination configured. Run get_waf_config first.")

    webacl_name = get_webacl_name()
    scope = get_scope()

    # Resolve S3 path
    s3_base = _resolve_s3_path(log_dest)
    bucket = s3_base.replace("s3://", "").split("/")[0]

    # For S3 direct delivery, try standard path first
    s3_path = None
    if ":s3:::" in log_dest:
        account_id = _get_account_id()
        s3_path = _try_standard_path(bucket, account_id, scope, webacl_name, region)
    if not s3_path:
        s3_path = s3_base

    # Check for existing table
    existing = _find_existing_table(s3_path, region)
    if existing:
        # Validate partition format matches actual S3 structure
        try:
            db, tbl_name = existing.split(".", 1)
            glue = get_client("glue", region_name=region)
            tbl_resp = glue.get_table(DatabaseName=db, Name=tbl_name)
            tbl_params = tbl_resp["Table"].get("Parameters", {})
            existing_fmt = tbl_params.get("projection.log_time.format", "")
            existing_interval = tbl_params.get("projection.log_time.interval", "1")
            table_location = tbl_resp["Table"]["StorageDescriptor"]["Location"].rstrip("/")
            resolved = s3_path.rstrip("/")
            _, actual_fmt, _, actual_interval = _detect_partitions(s3_path)
            fmt_mismatch = existing_fmt and actual_fmt and existing_fmt != actual_fmt
            interval_mismatch = str(actual_interval) != str(existing_interval)
            path_mismatch = not resolved.startswith(table_location)
            if fmt_mismatch or interval_mismatch or path_mismatch:
                if db == TMP_DATABASE:
                    reason = "path" if path_mismatch else ("interval" if interval_mismatch else "format")
                    print(f"[waf_athena] Table {reason} mismatch. Recreating.", file=__import__('sys').stderr, flush=True)
                    glue.delete_table(DatabaseName=db, Name=tbl_name)
                else:
                    print(f"[waf_athena] Table mismatch in external table {existing}. Creating correct table in {TMP_DATABASE}.", file=__import__('sys').stderr, flush=True)
            else:
                _athena_state["table"] = existing
                _athena_state["partition_format"] = existing_fmt or None
                return existing
        except Exception:
            _athena_state["table"] = existing
            return existing

    # Detect partitions and create permanent table
    if not _validate_waf_log(s3_path):
        raise RuntimeError(f"S3 path does not contain valid AWS WAF logs: {s3_path}")

    storage_template, part_fmt, part_unit, part_interval = _detect_partitions(s3_path)
    _athena_state["partition_format"] = part_fmt

    workgroup = "primary"
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", webacl_name).lower()
    full_table = _create_named_table(s3_path, storage_template, part_fmt, part_unit, part_interval, region, workgroup, f"waf_logs_{safe_name}")
    _athena_state["table"] = full_table
    _athena_state["temp_created"] = False
    return full_table


# ---------------------------------------------------------------------------
# Query templates (Athena SQL equivalents of CWL templates)
# ---------------------------------------------------------------------------

_UA_EXPR = "element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value"
_HOST_EXPR = "element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value"


def _time_filter(table: str, duration_minutes: int, partition_format: str | None, start_epoch: int | None = None) -> str:
    """Build WHERE clause with timestamp + partition pruning."""
    if start_epoch:
        start_ms = start_epoch * 1000
        end_ms = start_ms + duration_minutes * 60 * 1000
    else:
        end_ms = int(time.time()) * 1000
        start_ms = end_ms - duration_minutes * 60 * 1000
    clause = f'"timestamp" BETWEEN {start_ms} AND {end_ms}'
    if partition_format:
        start_dt = datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc)
        end_dt = datetime.fromtimestamp(end_ms / 1000, tz=timezone.utc)
        if "mm" in partition_format:
            sp = start_dt.strftime("%Y/%m/%d/%H/%M")
            ep = end_dt.strftime("%Y/%m/%d/%H/%M")
        else:
            sp = start_dt.strftime("%Y/%m/%d/%H")
            ep = end_dt.strftime("%Y/%m/%d/%H")
        clause += f" AND log_time >= '{sp}' AND log_time <= '{ep}'"
    return clause


def _build_query(query_type: str, table: str, duration_minutes: int, partition_format: str | None,
                 limit: int, start_epoch: int | None = None, **params) -> str:
    """Build Athena SQL for a given query_type."""
    tf = _time_filter(table, duration_minutes, partition_format, start_epoch)
    ip = params.get("ip", "")
    rule_name = params.get("rule_name", "")
    label = params.get("label", "")
    action = params.get("action", "")
    host = params.get("host", "")

    templates = {
        "count_rule_top_ips": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf}
            AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}')
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "count_rule_top_uris": f"""SELECT httprequest.uri as uri, count(*) as cnt
            FROM {table} WHERE {tf}
            AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}')
            GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT {limit}""",

        "count_rule_top_uas": f"""SELECT {_UA_EXPR} as ua, count(*) as cnt
            FROM {table} WHERE {tf}
            AND any_match(nonterminatingmatchingrules, r -> r.ruleid = '{rule_name}')
            GROUP BY {_UA_EXPR} ORDER BY cnt DESC LIMIT {limit}""",

        "ip_cross_query": f"""SELECT action, terminatingruleid, count(*) as cnt
            FROM {table} WHERE {tf} AND httprequest.clientip = '{ip}'
            GROUP BY action, terminatingruleid ORDER BY cnt DESC LIMIT {limit}""",

        "ip_uri_breakdown": f"""SELECT httprequest.uri as uri, count(*) as cnt
            FROM {table} WHERE {tf} AND httprequest.clientip = '{ip}'
            GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT {limit}""",

        "ip_ja4_fingerprints": f"""SELECT ja4fingerprint, count(*) as cnt
            FROM {table} WHERE {tf} AND httprequest.clientip = '{ip}'
            GROUP BY ja4fingerprint ORDER BY cnt DESC LIMIT {limit}""",

        "ip_request_rate": f"""SELECT date_format(from_unixtime("timestamp"/1000), '%Y-%m-%d %H:%i:00') as minute, count(*) as cnt
            FROM {table} WHERE {tf} AND httprequest.clientip = '{ip}'
            GROUP BY date_format(from_unixtime("timestamp"/1000), '%Y-%m-%d %H:%i:00')
            ORDER BY minute ASC LIMIT {limit}""",

        "ip_unique_uris": f"""SELECT count(DISTINCT httprequest.uri) as unique_uris, count(*) as total_requests,
            min(from_unixtime("timestamp"/1000)) as first_seen, max(from_unixtime("timestamp"/1000)) as last_seen
            FROM {table} WHERE {tf} AND httprequest.clientip = '{ip}'
            AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$')""",

        "ip_diversity": f"""SELECT count(DISTINCT {_UA_EXPR}) as unique_uas,
            count(DISTINCT ja4fingerprint) as unique_ja4s, count(*) as total_requests
            FROM {table} WHERE {tf} AND httprequest.clientip = '{ip}'""",

        "ip_labels": f"""SELECT json_format(cast(labels as json)) as Labels, count(*) as cnt
            FROM {table} WHERE {tf} AND httprequest.clientip = '{ip}'
            AND labels IS NOT NULL AND cardinality(labels) > 0
            GROUP BY json_format(cast(labels as json)) ORDER BY cnt DESC LIMIT {limit}""",

        "top_blocked_ips": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'BLOCK'
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "top_blocked_rules": f"""SELECT terminatingruleid, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'BLOCK'
            GROUP BY terminatingruleid ORDER BY cnt DESC LIMIT {limit}""",

        "top_allowed_ips": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'ALLOW'
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "top_allowed_crawlers": f"""SELECT httprequest.clientip as clientip, count(*) as total,
            count(DISTINCT httprequest.uri) as unique_uris,
            min(from_unixtime("timestamp"/1000)) as first_seen, max(from_unixtime("timestamp"/1000)) as last_seen
            FROM {table} WHERE {tf} AND action = 'ALLOW'
            AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$')
            AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )
            GROUP BY httprequest.clientip
            HAVING count(DISTINCT httprequest.uri) > 50
            ORDER BY unique_uris DESC LIMIT {limit}""",

        "top_allowed_repeaters": f"""SELECT httprequest.clientip as clientip, count(*) as total,
            count(DISTINCT httprequest.uri) as unique_uris,
            min(from_unixtime("timestamp"/1000)) as first_seen, max(from_unixtime("timestamp"/1000)) as last_seen
            FROM {table} WHERE {tf} AND action = 'ALLOW'
            AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$')
            AND ( labels IS NULL OR none_match(labels, l -> l.name LIKE '%bot:verified%') )
            GROUP BY httprequest.clientip
            HAVING count(*) > 200 AND count(DISTINCT httprequest.uri) < 10
            ORDER BY total DESC LIMIT {limit}""",

        "top_countries_blocked": f"""SELECT httprequest.country as country, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'BLOCK'
            GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {limit}""",

        "top_challenged_ips": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'CHALLENGE'
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "top_challenged_countries": f"""SELECT httprequest.country as country, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'CHALLENGE'
            GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {limit}""",

        "top_captcha_ips": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'CAPTCHA'
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "top_captcha_countries": f"""SELECT httprequest.country as country, count(*) as cnt
            FROM {table} WHERE {tf} AND action = 'CAPTCHA'
            GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {limit}""",

        "top_counted_ips": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf}
            AND any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT')
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "top_counted_countries": f"""SELECT httprequest.country as country, count(*) as cnt
            FROM {table} WHERE {tf}
            AND any_match(nonterminatingmatchingrules, r -> r.action = 'COUNT')
            GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {limit}""",

        "top_ips_by_volume": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf}
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "top_countries_by_volume": f"""SELECT httprequest.country as country, count(*) as cnt
            FROM {table} WHERE {tf}
            GROUP BY httprequest.country ORDER BY cnt DESC LIMIT {limit}""",

        "label_top_ips": f"""SELECT httprequest.clientip as clientip, count(*) as cnt
            FROM {table} WHERE {tf}
            AND any_match(labels, l -> l.name LIKE '%{label}%')
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "action_timeline": f"""SELECT date_format(from_unixtime("timestamp"/1000), '%Y-%m-%d %H:%i:00') as bin, count(*) as cnt
            FROM {table} WHERE {tf} AND action = '{action}'
            GROUP BY date_format(from_unixtime("timestamp"/1000), '%Y-%m-%d %H:%i:00')
            ORDER BY bin ASC LIMIT {limit}""",

        "host_traffic_profile": f"""SELECT {_HOST_EXPR} as host, count(*) as total,
            count(DISTINCT httprequest.uri) as unique_uris,
            sum(CASE WHEN httprequest.httpmethod IN ('POST','PUT','DELETE') THEN 1 ELSE 0 END) as write_requests
            FROM {table} WHERE {tf}
            GROUP BY {_HOST_EXPR} ORDER BY total DESC LIMIT {limit}""",

        "host_uri_pattern": f"""SELECT httprequest.uri as uri, count(*) as cnt
            FROM {table} WHERE {tf} AND {_HOST_EXPR} = '{host}'
            GROUP BY httprequest.uri ORDER BY cnt DESC LIMIT {limit}""",

        "host_method_distribution": f"""SELECT httprequest.httpmethod as httpmethod, count(*) as cnt
            FROM {table} WHERE {tf} AND {_HOST_EXPR} = '{host}'
            GROUP BY httprequest.httpmethod ORDER BY cnt DESC LIMIT {limit}""",

        "top_allowed_by_volume": f"""SELECT httprequest.clientip as clientip, count(*) as cnt,
            count(DISTINCT httprequest.uri) as unique_uris
            FROM {table} WHERE {tf} AND action = 'ALLOW'
            AND NOT regexp_like(httprequest.uri, '\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)$')
            GROUP BY httprequest.clientip ORDER BY cnt DESC LIMIT {limit}""",

        "token_reuse_ips": f"""SELECT httprequest.clientip as clientip, count(*) as total,
            count(DISTINCT {_UA_EXPR}) as unique_uas, count(DISTINCT ja4fingerprint) as unique_ja4s
            FROM {table} WHERE {tf}
            AND any_match(labels, l -> l.name LIKE '%token:accepted%')
            GROUP BY httprequest.clientip ORDER BY total DESC LIMIT {limit}""",
    }

    if query_type not in templates:
        raise ValueError(f"Unknown query_type '{query_type}'")
    return templates[query_type]


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@tool
def run_athena_query(
    query_type: str,
    start_time: str,
    duration_minutes: int = 60,
    rule_name: str = "",
    ip: str = "",
    label: str = "",
    action: str = "",
    host: str = "",
    limit: int = 25,
) -> str:
    """Run an AWS WAF log query via Athena (for S3-stored logs).

    Same interface as run_logs_query — same query_types, same output format.
    Automatically discovers S3 path and creates a permanent Athena table if needed.

    IMPORTANT: You MUST provide start_time. Ask the user for the time period to investigate.
    Max query window is 60 minutes. For broader trends, use CloudWatch Metrics instead.

    Args:
        query_type: Same types as run_logs_query (count_rule_top_ips, ip_cross_query, etc.)
        start_time: Start date/time for the query (e.g., "2026-05-09" or "2026-05-09T14:00"). REQUIRED — ask user if not provided.
        duration_minutes: Duration in minutes from start_time (default 60, max 60). The query covers [start_time, start_time + duration_minutes].
        rule_name: Rule name (for count_rule_* queries).
        ip: Client IP address (for ip_* queries).
        label: AWS WAF label name (for label_top_ips).
        action: Action value (for action_timeline).
        host: Hostname (for host_* queries).
        limit: Max results (default 25).

    Returns:
        Query results as a table, or error message.
    """
    from tools.session_state import get_metrics_region
    region = get_metrics_region()
    limit = min(limit, 25)

    # Validate start_time
    if not start_time:
        return "Error: start_time is required. Ask the user which time period to investigate.\nExample: run_athena_query(query_type=\"...\", start_time=\"2026-05-09T14:00\", duration_minutes=60)"

    # Cap at 60 minutes
    _duration = min(duration_minutes, 60)

    # Parse start_time (reuse same logic as run_logs_query)
    from tools.waf_logs import _parse_start_time
    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: invalid start_time format '{start_time}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM (with optional +HH:MM offset)."

    # Sanitize params
    ip = re.sub(r"[^0-9a-fA-F.:]", "", ip)
    rule_name = re.sub(r"['\"|;`\\]", "", rule_name)
    label = re.sub(r"['\"|;`\\]", "", label)
    action = re.sub(r"[^A-Z]", "", action)
    host = re.sub(r"['\"|;`\\]", "", host)

    try:
        table = _ensure_table(region)
    except RuntimeError as e:
        return f"Error: {e}"

    # Block queries on hourly partitions
    if _athena_state.get("partition_format") == "yyyy/MM/dd/HH":
        from tools.waf_query import _HOURLY_PARTITION_ERROR
        return _HOURLY_PARTITION_ERROR

    try:
        sql = _build_query(query_type, table, _duration, _athena_state.get("partition_format"),
                           limit, start_epoch=start_epoch, ip=ip, rule_name=rule_name, label=label, action=action, host=host)
    except ValueError as e:
        return str(e)

    try:
        rows = _run_athena_select(sql, region, limit=limit)
    except RuntimeError as e:
        return f"Query failed: {e}"

    if not rows:
        return f"Query '{query_type}' returned 0 results."

    # Format as table (same format as run_logs_query)
    columns = list(rows[0].keys())
    lines = [
        f"Query '{query_type}' returned {len(rows)} results (Athena)\n",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in rows:
        values = [row.get(col, "") for col in columns]
        lines.append("| " + " | ".join(values) + " |")

    # Hints for next steps
    lines.append("")
    if "ip" in query_type or "top_ips" in query_type:
        top_ip = rows[0].get("clientIp", rows[0].get("httpRequest.clientIp", ""))
        if top_ip:
            lines.append(f"→ To investigate top IP: analyze_ip(ip='{top_ip}', start_time='{start_time}')")
    elif "uri" in query_type:
        lines.append("→ To check which IPs hit these URIs: run_athena_query(query_type='top_blocked_ips', start_time='...')")
    elif "ja4" in query_type or "fingerprint" in query_type:
        lines.append("→ To analyze fingerprints: lookup_ja4(fingerprints=[...])")
    return "\n".join(lines)



