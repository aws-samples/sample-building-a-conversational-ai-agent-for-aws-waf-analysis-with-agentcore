# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Athena query tool — for S3-stored AWS WAF logs."""

import re
import time
import gzip
import json
import tempfile
import os
import threading
from datetime import datetime, timedelta
from tools.aws_session import get_client
from tools.session_state import get_webacl_name

MAX_POLL = 300
TMP_DATABASE = "waf_analysis_tmp"

# Serializes DROP+CREATE of a scratch table. _create_named_table is reachable
# from two independent paths (query_logs via _ensure_athena_table, and
# patrol_scan via _get_log_details_athena); without this lock a concurrent
# call could drop a table another thread is creating/querying.
_create_lock = threading.Lock()

# Module-level state (lazy init on first query).
#
# Every value here describes the ONE table resolved for the current WebACL, and
# it is the table's own DECLARED projection config, not what a walk of S3
# suggested. The pruning predicate compares partition-column string values, and
# those values come from the projection, so rendering bounds with anything else
# silently matches no partition and returns zero rows. The S3 walk survives only
# as a cross-check.
_ATHENA_STATE_DEFAULTS = {
    "table": None,           # "database.table_name"
    "table_location": None,  # resolved table's own LOCATION, no trailing slash
    "partition_format": None, # declared Java date format, e.g. "yyyy/MM/dd/HH/mm"
    "partition_col": "log_time",  # partition column the SQL builders prune on
    "partition_interval": 1,      # declared projection interval
    "partition_interval_unit": "minutes",  # its unit: minutes / hours / days
    "partition_range_start": None,  # naive datetime, in partition-path local time
    "partition_range_end": None,    # naive datetime, or None for an open (NOW) range
    "partition_tz": None,    # IANA name / fixed offset the PARTITION PATHS are
                             # written in (e.g. Firehose CustomTimeZone). None → UTC.
                             # Independent of the user's display timezone.
    "temp_created": False,
    "webacl_scoped": True,   # True if table location is specific to one WebACL
    "table_choice": None,    # one line naming the resolved table, for tool output
    "discovery_notes": [],   # why candidate tables were rejected, for tool output
}

_athena_state = dict(_ATHENA_STATE_DEFAULTS)


def reset_table_cache():
    """Reset the cached Athena table metadata.

    Must be called whenever the active WebACL changes — the cached table is
    keyed to the previous WebACL's resolved S3 path, and reusing it would
    query the wrong logs (stale-table bug). Restores every key from one
    defaults dict so a newly added key cannot be forgotten here and survive a
    WebACL switch."""
    _athena_state.clear()
    _athena_state.update(_ATHENA_STATE_DEFAULTS)
    _athena_state["discovery_notes"] = []


# Java SimpleDateFormat tokens (used by Athena partition projection 'date' type)
# mapped to Python strftime directives. Order matters: longer/unambiguous tokens
# first. Case-sensitive — Java uses `MM` for month and `mm` for minute.
_JAVA_TO_STRFTIME = (
    ("yyyy", "%Y"), ("MM", "%m"), ("dd", "%d"),
    ("HH", "%H"), ("mm", "%M"), ("ss", "%S"),
)


def _java_date_format_to_strftime(java_fmt: str) -> str:
    """Translate an Athena partition-projection date format (Java SimpleDateFormat,
    e.g. 'yyyy/MM/dd/HH') to a Python strftime pattern ('%Y/%m/%d/%H'), preserving
    separators. Substituted directives never contain the raw tokens, so repeated
    passes don't collide."""
    out = java_fmt
    for token, directive in _JAVA_TO_STRFTIME:
        out = out.replace(token, directive)
    return out


def _partition_has_minutes(java_fmt: str | None) -> bool:
    """True if the partition format resolves to minute-level granularity.

    Case-sensitive `mm` (minute) check — `MM` (month) must not count. Anything
    coarser than minute-level (hourly, daily) returns False and is subject to
    the coarse-partition query guard. Only call this on a format that
    _partition_granularity has already accepted; on an unclassifiable format the
    bare `mm` test can be wrong in either direction."""
    return bool(java_fmt) and "mm" in java_fmt


# The only partition layouts the pruning predicate is valid for. Pruning is a
# lexicographic string comparison against a rendered date, which requires the
# fields to appear most-significant-first and zero-padded, so `dd/MM/yyyy` is
# not merely unusual, it silently compares wrong. Separators are free.
_GRANULARITY_BY_TOKENS = {
    ("yyyy", "MM", "dd", "HH", "mm"): "minutes",
    ("yyyy", "MM", "dd", "HH"): "hours",
    ("yyyy", "MM", "dd"): "days",
}

_JAVA_TOKEN_RE = re.compile(r"y+|M+|d+|H+|m+|s+|[^yMdHms]+")

# Coarsest last. Used to compare a table's declared partitioning against the
# layout actually in S3, and to turn a projection interval into a wall-clock
# offset. The keys double as the set of `interval.unit` values that are accepted:
# Athena also allows weeks, months and years, and a unit with no fixed length
# cannot be widened by, so those are refused at discovery. The names match
# `timedelta`'s keyword arguments on purpose.
_GRANULARITY_ORDER = {"minutes": 0, "hours": 1, "days": 2}
_MINUTES_PER_UNIT = {"minutes": 1, "hours": 60, "days": 1440}


def _partition_granularity(java_fmt: str | None) -> str | None:
    """Classify a declared projection format as 'minutes', 'hours' or 'days'.

    None means the format is one this agent cannot serve, and callers must treat
    that as a rejection rather than falling back to a default. Two reasons. The
    pruning comparison is only valid for the layouts above. And the
    coarse-partition guard is a granularity test, so a format nobody classified
    would run at unknown scan cost while the product believes it refuses coarse
    tables."""
    if not java_fmt:
        return None
    tokens = tuple(t for t in _JAVA_TOKEN_RE.findall(java_fmt) if t[0] in "yMdHms")
    return _GRANULARITY_BY_TOKENS.get(tokens)


def _zone_from_str(name: str | None):
    """Resolve a timezone string to a tzinfo. Accepts an IANA name
    ('America/New_York') or a fixed offset ('-04:00', '+05:30', '-4', 'UTC').
    Returns None if the string is empty or unparseable (caller falls back)."""
    from datetime import timezone, timedelta
    if not name:
        return None
    name = name.strip()
    if name.upper() in ("UTC", "Z", "GMT"):
        return timezone.utc
    # Fixed offset forms: ±HH:MM, ±HHMM, ±HH, or a bare number of hours.
    import re as _re
    m = _re.fullmatch(r"(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?", name)
    if m:
        sign = -1 if m.group(1) == "-" else 1
        hours = int(m.group(2))
        mins = int(m.group(3) or 0)
        return timezone(sign * timedelta(hours=hours, minutes=mins))
    try:
        num = float(name)
        return timezone(timedelta(hours=num))
    except ValueError:
        pass
    # IANA name (needs the `tzdata` package in the slim container).
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        return None


def _partition_zone():
    """The timezone the S3 partition PATHS are written in, used to derive the
    partition-pruning bounds. Precedence:

      1. env WAF_AGENT_PARTITION_TZ (operator override)
      2. auto-detected Firehose CustomTimeZone (_athena_state['partition_tz'])
      3. UTC (AWS vended logs and the default assumption)

    Returns a tzinfo, never None. WAF vended logs partition in UTC, so the
    common case stays UTC; only Firehose CustomTimeZone / custom local-time
    pipelines need a non-UTC value. A custom pipeline that Firehose detection
    cannot see is reachable only through the env var, which is why step 1 exists."""
    from datetime import timezone
    z = _zone_from_str(os.environ.get("WAF_AGENT_PARTITION_TZ"))
    if z is None:
        z = _zone_from_str(_athena_state.get("partition_tz"))
    return z if z is not None else timezone.utc


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
        # Firehose evaluates the !{timestamp:...} prefix in its CustomTimeZone
        # (default UTC). If set to a non-UTC zone, the partition PATHS are in
        # local time and pruning must derive bounds in that zone — record it.
        _ctz = s3_dest.get("CustomTimeZone")
        if _ctz and _ctz.upper() != "UTC":
            _athena_state["partition_tz"] = _ctz
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
            # Descend into the NEWEST child at every level, not the earliest.
            #
            # Anyone who has switched a Firehose prefix from hourly to
            # minute-level still has the old hourly paths in their bucket, under
            # earlier months of the same year. Taking the earliest child walked
            # straight into that pre-cutover data, counted four levels, and pinned
            # the table to yyyy/MM/dd/HH — permanently, because no amount of new
            # minute-partitioned data changes a walk that never looks at it.
            #
            # Levels below the year are always two zero-padded digits, so a
            # lexicographic max is the numeric max. Filtering to that shape also
            # keeps a stray non-numeric directory from being chosen; letters sort
            # after digits, so "newest" would otherwise pick it.
            test_prefix = current_prefix + year + "/"
            levels = [year]
            for _ in range(5):
                sub_dirs = [d for d in _s3_list_dirs(bucket, test_prefix) if re.fullmatch(r"\d{2}", d)]
                if not sub_dirs:
                    break
                newest = max(sub_dirs)
                levels.append(newest)
                test_prefix = test_prefix + newest + "/"
            if len(levels) >= 5:
                # Minute-level means interval 1, and it is never inferred from the
                # directory names. Firehose's !{timestamp:mm} emits whatever minute
                # the buffer happened to flush at, so the minute directories are
                # arbitrary values like 03, 07, 08, 41. The old code subtracted two
                # of them and fed the difference to partition projection, which then
                # generated paths only at that stride and never read the objects in
                # between: a fraction of the rows, with no error to show for it.
                fmt, unit, interval = "yyyy/MM/dd/HH/mm", "minutes", 1
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


def _path_covers(location: str, resolved: str) -> bool:
    """True when `location` is `resolved` itself or one of its ancestor prefixes.

    The trailing slash is the whole point: a bare `startswith` lets a table at
    s3://b/waf-logs claim to cover s3://b/waf-logs-prod."""
    return bool(location) and (resolved == location or resolved.startswith(location + "/"))


def _table_metadata(db_name: str, tbl: dict) -> dict | str:
    """Validate one Glue table as a WAF log source for the pruning path.

    Returns its metadata on success, or a one-line string saying why it was
    rejected. The string is shown to the user: "the agent built its own table"
    is a confusing outcome unless it also says what was wrong with theirs."""
    name = f"{db_name}.{tbl['Name']}"
    sd = tbl.get("StorageDescriptor", {})
    cols = [c["Name"].lower() for c in sd.get("Columns", [])]
    missing = [c for c in ("action", "httprequest") if c not in cols]
    if missing:
        return (f"{name}: missing WAF log column(s) {', '.join(missing)}. Queries "
                f"reference `action` and `httprequest` by those exact names.")

    part_keys = [p["Name"] for p in tbl.get("PartitionKeys", [])]
    if not part_keys:
        return (f"{name}: not partitioned. Every log query is pruned on one "
                f"projected time column, so an unpartitioned table would scan whole.")
    if len(part_keys) > 1:
        return (f"{name}: partitioned on {len(part_keys)} keys "
                f"({', '.join(part_keys)}); exactly one time column is supported.")

    col = part_keys[0]
    params = tbl.get("Parameters", {})
    if params.get("projection.enabled", "").lower() != "true":
        return (f"{name}: partition projection is not enabled. Hive-style partitions "
                f"registered with ALTER TABLE ADD PARTITION are not supported.")
    proj_type = params.get(f"projection.{col}.type", "").lower()
    if proj_type != "date":
        return (f"{name}: partition column `{col}` has projection type "
                f"'{proj_type or 'none'}'; only 'date' is supported. Integer and enum "
                f"projections cannot be compared against a rendered timestamp.")

    fmt = params.get(f"projection.{col}.format", "")
    granularity = _partition_granularity(fmt)
    if granularity is None:
        return (f"{name}: partition format '{fmt or 'none'}' is not supported. Use "
                f"yyyy/MM/dd, yyyy/MM/dd/HH or yyyy/MM/dd/HH/mm, any separator, "
                f"most significant field first.")

    proj_range = params.get(f"projection.{col}.range", "").strip()
    if not proj_range:
        return (f"{name}: partition column `{col}` declares no projection range, "
                f"which Athena requires for a date projection.")
    bounds = [b.strip() for b in proj_range.split(",")]
    if len(bounds) != 2:
        return f"{name}: projection range '{proj_range}' is not a start,end pair."
    strftime_fmt = _java_date_format_to_strftime(fmt)
    try:
        range_start = datetime.strptime(bounds[0], strftime_fmt)
    except ValueError:
        return (f"{name}: projection range start '{bounds[0]}' does not parse as "
                f"'{fmt}'.")
    range_end = None
    if bounds[1].upper() not in ("NOW", "NOW()"):
        try:
            range_end = datetime.strptime(bounds[1], strftime_fmt)
        except ValueError:
            return (f"{name}: projection range end '{bounds[1]}' is neither NOW nor a "
                    f"date in format '{fmt}'.")
        # A fixed bound in the past projects no partition for recent data, and
        # Athena reports that as zero rows rather than as an error.
        if range_end < datetime.now(_partition_zone()).replace(tzinfo=None):
            return (f"{name}: projection range ends at {bounds[1]}, already in the past, "
                    f"so recent log data is outside the projected partitions.")

    try:
        interval = int(params.get(f"projection.{col}.interval", "1"))
    except ValueError:
        return (f"{name}: projection interval "
                f"'{params.get(f'projection.{col}.interval')}' is not a number.")
    unit = params.get(f"projection.{col}.interval.unit", "").strip().lower() or granularity
    if unit not in _MINUTES_PER_UNIT:
        # Athena also allows weeks, months and years. Refusing them is not
        # laziness: pruning widens the window by one interval on each side, and a
        # unit with no fixed length cannot be turned into a wall-clock offset.
        # Nothing that partitions WAF logs by month is usable here anyway.
        return (f"{name}: projection interval unit '{unit}' is not supported. Use "
                f"minutes, hours or days.")

    return {
        "table": name,
        "location": sd.get("Location", "").rstrip("/"),
        "partition_col": col,
        "partition_format": fmt,
        "partition_granularity": granularity,
        "partition_interval": interval,
        "partition_interval_unit": unit,
        "partition_range_start": range_start,
        "partition_range_end": range_end,
    }


def _find_existing_table(s3_path: str, region: str) -> dict | None:
    """Find a usable WAF log table in the Glue catalog covering this S3 path.

    Returns the matched table's declared metadata (see _table_metadata) rather
    than a "db.table" string: every caller needs the projection config to build a
    correct pruning predicate, and GetTables already returns full Table objects,
    so reading it here costs no extra API call.

    Preference order, and it is not "most specific wins". _create_named_table
    puts the agent's own scratch table at exactly the resolved path, making it
    always the longest possible match, so specificity alone would pick the
    scratch table every time and a user's own table would never be used. So:
    every database except waf_analysis_tmp first, longest location within that
    group, and the scratch table only if nothing else qualifies.

    Rejections are recorded in _athena_state["discovery_notes"] so the agent can
    say why it built its own table instead of leaving the user to guess."""
    glue = get_client("glue", region_name=region)
    resolved = s3_path.rstrip("/")
    notes: list[str] = []

    # Never pass AttributesToGet to either paginator. It reads as an obvious
    # optimisation and it is a trap: GetTables accepts ['NAME', 'TABLE_TYPE'] and
    # GetDatabases accepts ['NAME', 'TARGET_DATABASE'], and either one strips
    # StorageDescriptor and Parameters, so every projection.* read above comes
    # back empty. The result is wrong pruning with no error.
    try:
        db_names = [d["Name"] for page in glue.get_paginator("get_databases").paginate()
                    for d in page.get("DatabaseList", [])]
    except Exception as e:
        notes.append(f"Could not list Glue databases ({type(e).__name__}); searched only "
                     f"{TMP_DATABASE} and default.")
        db_names = [TMP_DATABASE, "default"]

    for group in (sorted(d for d in db_names if d != TMP_DATABASE),
                  [d for d in db_names if d == TMP_DATABASE]):
        best = None
        for db_name in group:
            try:
                tables = [t for page in glue.get_paginator("get_tables").paginate(DatabaseName=db_name)
                          for t in page.get("TableList", [])]
            except Exception:
                continue
            for tbl in sorted(tables, key=lambda t: t["Name"]):
                location = tbl.get("StorageDescriptor", {}).get("Location", "").rstrip("/")
                if not _path_covers(location, resolved):
                    continue
                meta = _table_metadata(db_name, tbl)
                if isinstance(meta, str):
                    notes.append(meta)
                    continue
                # An exact-location match inside this group cannot be beaten:
                # matches are ancestor-or-equal, so equality is the most specific
                # possible. Databases and tables are walked in sorted order, so
                # this is also the lexicographically first such table, which makes
                # returning here deterministic rather than dependent on whatever
                # order Glue enumerated. Without this the ranking rule would force
                # a full walk of every table in every database on every cold
                # resolve, which on a real warehouse is hundreds of Glue calls.
                if meta["location"] == resolved:
                    _athena_state["discovery_notes"] = notes
                    return meta
                if best is None or len(meta["location"]) > len(best["location"]):
                    best = meta
        if best is not None:
            _athena_state["discovery_notes"] = notes
            return best

    _athena_state["discovery_notes"] = notes
    return None


def _ensure_database(region: str, workgroup: str):
    """Create tmp database if not exists."""
    sql = f"CREATE DATABASE IF NOT EXISTS `{TMP_DATABASE}`"
    _run_athena_ddl(sql, region, workgroup)


def _create_named_table(s3_path: str, storage_template: str, partition_format: str,
                        partition_unit: str, partition_interval: int, region: str, workgroup: str, table_name: str) -> dict:
    """Create a permanent Athena table with the given name. Returns its metadata."""
    _ensure_database(region, workgroup)
    range_start = "2020/01/01/00/00" if "mm" in partition_format else "2020/01/01/00"
    target_location = s3_path.rstrip("/")

    # A same-named table can linger with an outdated LOCATION after the WAF log
    # delivery method changes (e.g. Vended Logs -> Firehose moves data from
    # AWSLogs/.../{webacl}/ to a custom bucket-root prefix). _find_existing_table
    # only matches tables whose location is an ancestor of the resolved path, so
    # a stale child-location table is invisible to it. We must replace it.
    #
    # But DROP unconditionally would open a window where a concurrent query on
    # the other code path (query_logs vs patrol_scan) sees the table missing
    # between DROP and CREATE. So we DROP only when an existing table actually
    # points at a DIFFERENT location; when the location already matches (the
    # common/steady case, and the case where another thread just created it),
    # we skip the DROP entirely and let CREATE ... IF NOT EXISTS be a no-op.
    # The whole check-then-act is held under _create_lock so the two paths
    # cannot interleave. Dropping an EXTERNAL table never touches S3 data.
    with _create_lock:
        needs_drop = False
        try:
            glue = get_client("glue", region_name=region)
            existing = glue.get_table(DatabaseName=TMP_DATABASE, Name=table_name)
            existing_loc = existing["Table"]["StorageDescriptor"].get("Location", "").rstrip("/")
            if existing_loc and existing_loc != target_location:
                needs_drop = True
        except Exception:
            # Table absent (EntityNotFoundException) or Glue error → nothing to drop.
            needs_drop = False

        if needs_drop:
            _run_athena_ddl(f"DROP TABLE IF EXISTS `{TMP_DATABASE}`.`{table_name}`", region, workgroup)

        ddl = DDL_TEMPLATE.format(
            database=TMP_DATABASE, table=table_name,
            s3_location=target_location + "/",
            partition_format=partition_format, partition_unit=partition_unit,
            partition_interval=partition_interval,
            storage_template=storage_template, range_start=range_start,
        )
        _run_athena_ddl(ddl, region, workgroup)
    # Same metadata shape _find_existing_table returns, so both resolution paths
    # feed _record_table identically. For a table this function wrote, the
    # declared values ARE the ones passed in, so there is nothing to read back.
    return {
        "table": f"{TMP_DATABASE}.{table_name}",
        "location": target_location,
        "partition_col": "log_time",
        "partition_format": partition_format,
        "partition_granularity": _partition_granularity(partition_format),
        "partition_interval": partition_interval,
        "partition_interval_unit": partition_unit,
        "partition_range_start": datetime.strptime(
            range_start, _java_date_format_to_strftime(partition_format)),
        "partition_range_end": None,
    }


def _cross_check_declared(meta: dict, s3_path: str, strict: bool) -> str | None:
    """Compare a table's declared projection against the real S3 layout.

    Returns None when the table can address the data, else one line naming the
    problem. Free to run: the S3 walk happens on this path anyway.

    Asymmetric on purpose, because the two directions of disagreement are not
    equally bad. A table declaring COARSER partitions than the data has is fine:
    its storage.location.template resolves to the hour directory and Athena scans
    recursively beneath it, so minute-nested objects are still found, just pruned
    less tightly. A table declaring FINER partitions is broken: it projects
    `.../12/16` under a bucket that only has `.../12`, that path does not exist,
    and Athena reports the miss as zero rows rather than as an error. Same shape
    for the interval. A declared step finer than reality only costs planning time,
    while a declared step coarser than reality skips directories that exist and
    silently drops their rows.

    `strict` is for the agent's own scratch table, where any difference at all
    means the table is stale and should be rebuilt rather than tolerated.

    Note the interval comparison converts to minutes first. Comparing the bare
    numbers makes "1 minute" equal "1 hour", which is precisely the pair of
    layouts this check exists to tell apart."""
    try:
        _, actual_fmt, actual_unit, actual_interval = _detect_partitions(s3_path)
    except Exception:
        # Nothing readable under the path yet: an empty bucket, or a prefix that
        # has received no data. Trust the declaration; there is nothing to compare.
        return None

    declared_fmt = meta["partition_format"]
    if strict and (declared_fmt, meta["partition_interval"], meta["partition_interval_unit"]) \
            != (actual_fmt, actual_interval, actual_unit):
        return (f"declares {declared_fmt} / interval {meta['partition_interval']} "
                f"{meta['partition_interval_unit']} but the S3 layout is {actual_fmt} / "
                f"interval {actual_interval} {actual_unit}")

    actual_granularity = _partition_granularity(actual_fmt)
    if actual_granularity is None:
        return None
    if _GRANULARITY_ORDER[meta["partition_granularity"]] < _GRANULARITY_ORDER[actual_granularity]:
        return (f"declares partition format {declared_fmt}, finer than the {actual_fmt} "
                f"directories that actually exist in S3, so the partitions it projects "
                f"point at paths that are not there")

    declared_step = meta["partition_interval"] * _MINUTES_PER_UNIT.get(
        meta["partition_interval_unit"], 1)
    actual_step = actual_interval * _MINUTES_PER_UNIT.get(actual_unit, 1)
    if meta["partition_granularity"] == actual_granularity and declared_step > actual_step:
        return (f"declares interval {meta['partition_interval']} "
                f"{meta['partition_interval_unit']} but the S3 directories step by "
                f"{actual_interval} {actual_unit}, so it skips directories that exist")
    return None


def resolve_log_table(s3_path: str, region: str, webacl_name: str) -> str:
    """Resolve the Athena table for this WebACL's S3 logs, creating one if needed.

    Returns the "db.table" name, and publishes the resolved table's declared
    metadata to `_athena_state` through `_record_table`. That state is where the
    SQL builders read the partition column, format, interval and projected range,
    so nothing downstream has to re-derive any of it from the S3 path.

    Shared by `query_logs`' setup path and `patrol_scan`'s because every step in
    here is identical between them. What genuinely differs stays at the call
    sites: `query_logs` holds a setup lock and keeps its own name cache, patrol
    reports table creation in its own output.

    The cache lives here so patrol gets it too. Patrol previously held none, so it
    paid a full Glue enumeration and S3 walk on every scan, and it is the tool most
    likely to be run repeatedly against the same WebACL. `reset_table_cache()`
    already fires on every WebACL switch, so there is no stale-table window."""
    if _athena_state.get("table"):
        return _athena_state["table"]

    meta = _find_existing_table(s3_path, region)
    if meta is not None:
        db, tbl = meta["table"].split(".", 1)
        problem = _cross_check_declared(meta, s3_path, strict=(db == TMP_DATABASE))
        if problem is None:
            return _record_table(meta)
        if db == TMP_DATABASE:
            # The agent's own scratch table, now inconsistent with the data under
            # it. Drop and rebuild; dropping an EXTERNAL table never touches S3.
            _athena_state["discovery_notes"].append(
                f"{meta['table']} {problem}. Recreating it.")
            try:
                get_client("glue", region_name=region).delete_table(DatabaseName=db, Name=tbl)
            except Exception:
                pass
        else:
            _athena_state["discovery_notes"].append(
                f"{meta['table']} {problem}. Building a separate table in "
                f"{TMP_DATABASE} instead and leaving yours untouched.")

    if not _validate_waf_log(s3_path):
        raise RuntimeError(
            f"S3 path does not contain valid AWS WAF logs: {s3_path}. Verify the log "
            f"destination is correct.")
    storage_template, part_fmt, part_unit, part_interval = _detect_partitions(s3_path)
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", webacl_name or "unknown").lower()
    created = _create_named_table(s3_path, storage_template, part_fmt, part_unit,
                                 part_interval, region, "primary", f"waf_logs_{safe_name}")
    return _record_table(created, created=True)


def partition_predicate(start_dt, end_dt) -> tuple[str, str | None]:
    """Render the partition-pruning predicate for a time window.

    Returns (sql_fragment, problem). Both datetimes must be timezone-aware.

    Two things this centralises, and both were previously duplicated per caller
    and got them subtly different.

    The bounds are converted into the PARTITION-PATH timezone, not UTC. Directory
    names encode a wall clock in whatever zone wrote them, so for a Firehose
    stream with a CustomTimeZone, UTC bounds look in the wrong hour's directory
    and the rows are pruned away with no error. The `"timestamp" BETWEEN` epoch
    filter still enforces exactness; this only decides what Athena scans.

    And they are rendered with the table's DECLARED projection format, not with
    whatever a walk of S3 suggested. The predicate compares partition-column
    values, and those values come from the projection config, so rendering with
    anything else can produce a string matching no partition at all. For a table
    the agent built itself the two always agree, which is why using the wrong one
    stays invisible until somebody reuses an external table.

    The bounds are widened by one projection interval on each side, and that is a
    correctness fix rather than a safety margin. A partition directory's name is
    the arrival time of the record that opened the Firehose buffer, and one object
    holds a whole buffer window, so the minute in the path bounds the timestamps
    inside it in neither direction: it lags event time by the delivery delay and
    leads the records that arrived later in the same buffer. Measured on a
    minute-level bucket, one directory spanned 76 seconds and reached 28 seconds
    before its own label, and using the window's own bounds lost 5.70% and 8.12%
    of rows on two 5-minute windows. The loss is a couple of partitions at each
    edge, so it is worst on exactly the narrow windows the timeout guidance steers
    people toward. `"timestamp" BETWEEN` stays exact, so widening cannot pull in
    rows from outside the window; it only stops excluding rows inside it.

    `problem` is set when the window falls outside the table's projected range.
    Athena reports that as zero rows, so saying so is the difference between "your
    table only covers from X" and the user concluding they had no traffic."""
    part_fmt = _athena_state.get("partition_format")
    part_col = _athena_state.get("partition_col") or "log_time"
    if not part_fmt:
        return "", None

    zone = _partition_zone()
    start_local = start_dt.astimezone(zone)
    end_local = end_dt.astimezone(zone)

    problem = None
    naive_start, naive_end = start_local.replace(tzinfo=None), end_local.replace(tzinfo=None)
    range_start = _athena_state.get("partition_range_start")
    range_end = _athena_state.get("partition_range_end")
    table = _athena_state.get("table") or "the log table"

    # Widen by one interval, expressed in the projection's own unit rather than in
    # hardcoded minutes, because a user's table may declare any interval. Then
    # clamp back inside the projected range: a bound outside it matches no
    # projected partition, and there is nothing out there to find anyway. Range
    # checking below uses the UNWIDENED window, so a query starting exactly at the
    # projection's first partition is not reported as out of range.
    widened_start, widened_end = naive_start, naive_end
    step = timedelta(**{_athena_state.get("partition_interval_unit") or "minutes":
                        _athena_state.get("partition_interval") or 1})
    widened_start -= step
    widened_end += step
    if range_start is not None:
        widened_start = max(widened_start, range_start)
    if range_end is not None:
        widened_end = min(widened_end, range_end)

    strftime_fmt = _java_date_format_to_strftime(part_fmt)
    clause = (f"AND {part_col} >= '{widened_start.strftime(strftime_fmt)}' "
              f"AND {part_col} <= '{widened_end.strftime(strftime_fmt)}'")

    if range_start is not None and naive_start < range_start:
        problem = (f"The requested window starts {naive_start:%Y-%m-%d %H:%M}, before "
                   f"`{table}`'s partition projection begins "
                   f"({range_start:%Y-%m-%d %H:%M}). Athena projects no partition that "
                   f"far back, so rows before that point cannot be returned no matter "
                   f"what the data contains. Widen the table's "
                   f"projection.{part_col}.range or query a later window.")
    elif range_end is not None and naive_end > range_end:
        problem = (f"The requested window ends {naive_end:%Y-%m-%d %H:%M}, after "
                   f"`{table}`'s partition projection stops "
                   f"({range_end:%Y-%m-%d %H:%M}). Rows after that point are outside "
                   f"the projected partitions and cannot be returned.")
    return clause, problem


def describe_table_resolution() -> str:
    """One block naming the resolved table and why any candidate was rejected.

    Surfaced in tool output so the choice is auditable. "The agent built its own
    table" is a confusing outcome on its own; with the rejection reasons attached
    the user can fix their table instead of guessing."""
    lines = []
    if _athena_state.get("table_choice"):
        lines.append(_athena_state["table_choice"])
    for note in _athena_state.get("discovery_notes") or []:
        lines.append(f"Skipped {note}")
    return "\n".join(lines)


def _record_table(meta: dict, created: bool = False) -> str:
    """Publish a resolved table's metadata to the shared state and return its name.

    One writer for both resolution paths. Every consumer of _athena_state reads
    what this puts there, so a key that is set on one path and not the other is
    how the copies drifted in the first place."""
    _athena_state["table"] = meta["table"]
    _athena_state["table_location"] = meta["location"]
    _athena_state["partition_col"] = meta["partition_col"]
    _athena_state["partition_format"] = meta["partition_format"]
    _athena_state["partition_interval"] = meta["partition_interval"]
    _athena_state["partition_interval_unit"] = meta["partition_interval_unit"]
    _athena_state["partition_range_start"] = meta["partition_range_start"]
    _athena_state["partition_range_end"] = meta["partition_range_end"]
    _athena_state["temp_created"] = created
    # A table whose location does not contain the WebACL name may hold several
    # WebACLs' logs. Score the RESOLVED table's own location, never the requested
    # s3_path: matches are ancestor-or-equal, so the requested path can contain
    # the WebACL name while the table sitting above it does not, and that error
    # runs one way only, claiming single-WebACL scoping a table does not have.
    wn = get_webacl_name() or ""
    _athena_state["webacl_scoped"] = bool(wn) and wn.lower() in meta["location"].lower()
    _athena_state["table_choice"] = (
        f"{'Created' if created else 'Using'} Athena table `{meta['table']}` at "
        f"{meta['location']}, partitioned on `{meta['partition_col']}` "
        f"({meta['partition_format']}, interval {meta['partition_interval']} "
        f"{meta['partition_interval_unit']})"
        + ("" if _athena_state["webacl_scoped"] else
           "; its location is shared, so queries are filtered by webaclid")
    )
    return meta["table"]


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
