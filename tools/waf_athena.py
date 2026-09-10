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

from tools.query_limits import (MAX_POLL, POLL_INTERVAL, poll_timeout_message,
                                 query_failed_message, stop_athena_query)
TMP_DATABASE = "waf_analysis_tmp"


class PartitionsNotFound(RuntimeError):
    """The S3 walk completed and found no date-shaped directories under the path.

    A named type because resolution branches on this condition and on nothing else:
    finding nothing under an empty prefix is a reason to trust a table's declaration,
    while *failing to read* the path is not. That distinction was carried by
    `except RuntimeError` for one commit, which inferred the signal from a generic type
    rather than stating it. Any `raise RuntimeError` later added anywhere in the walk, for
    a depth limit or a malformed template, would have been silently reclassified as
    "walked it, found nothing" and restored trust-the-declaration over a path that is not
    empty. Subclasses `RuntimeError` so existing callers catching the base type, and the
    tests asserting it, keep working.
    """

# Serializes DROP+CREATE of a scratch table. Held inside _create_named_table.
# Kept separate from _resolve_lock below because it guards a narrower critical
# section, and because dropping it would leave the DROP/CREATE unprotected if
# _create_named_table ever gains a caller outside resolve_log_table.
_create_lock = threading.Lock()

# Serializes table resolution. The agent fires Athena queries in parallel, and the
# cache check at the top of resolve_log_table is not atomic, so without this two
# threads both miss it and both pay a full Glue enumeration plus S3 walk. This lives
# here rather than at a call site because BOTH callers need it: query_logs used to
# hold an equivalent lock of its own and patrol_scan held none at all, which is the
# asymmetry that made patrol the expensive path.
_resolve_lock = threading.Lock()

# Serializes the destination-to-S3-path translation. Its memo is a read-modify-write
# and is not atomic, so without this every thread on a cold cache passes the memo
# check before any of them writes. Measured with a 100 ms stand-in for the AWS call:
# ten threads produced ten DescribeDeliveryStream calls unlocked and one locked. That
# is the case the 5-per-second non-adjustable ceiling is about, so this lock is
# correctness rather than efficiency.
_translate_lock = threading.Lock()

# Serializes the Athena output-location lookup. Same non-atomic read-modify-write as
# the translate memo, and the hotter of the two: both Athena executors call it once per
# STATEMENT rather than once per query, and on a workgroup with no output location its
# fallback reaches the same DescribeDeliveryStream under the same ceiling. Measured with
# a 100 ms stand-in, ten threads: ten lookups unlocked, one locked.
#
# Deliberately its own lock and not _translate_lock. `_run_athena_ddl` calls
# `_get_output_location` from inside `with _create_lock`, so this runs while a lock two
# levels out is held. Reusing _translate_lock would not deadlock today, since the
# translate path takes nothing else, but it would falsify the invariant below, and that
# invariant is the sentence a future edit will rely on.
_output_location_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Lock order, outermost to innermost: translate, resolve, create, output. Never
# the reverse, and no function takes an outer lock while holding an inner one, so
# they cannot deadlock against each other.
#
# They are plain non-reentrant Locks, so the sharper hazard is one deadlocking
# against ITSELF, and that is a property of the current shape rather than of the
# locks. `_resolve_log_table_locked` handles a stale scratch table by dropping it
# and rebuilding INLINE. If that were ever rewritten as a recursive call back into
# `resolve_log_table`, which would read as a tidy-up, the second acquisition of
# `_resolve_lock` would block forever and the session would hang with no error and
# no log line. Keep the self-heal inline.
#
# The same applies to `_output_location_lock`: it is taken inside `_create_lock` via
# `_run_athena_ddl`, so it must stay innermost and must never reach back outward.
# ---------------------------------------------------------------------------

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
    "layout_mixed": False,   # bucket holds both hourly and minute-level eras
    "layout_cutover": None,  # 'yyyy/MM/dd' the minute era begins, best-effort
    "layout_data_start": None,  # 'yyyy/MM/dd' of the OLDEST data in the bucket,
                             # whichever era it is in. Only interesting when the
                             # layout is mixed, where it is the far edge of the
                             # history the resolved table cannot reach.
    "table_choice": None,    # one line naming the resolved table, for tool output
    "discovery_notes": (),   # why candidate tables were rejected, for tool output
    "schema_note": None,     # optional columns the resolved table lacks, and the
                             # features that will therefore fail. None when nothing
                             # is missing, which is every table the agent builds.
    # Memo of the log-destination ARN -> S3 path translation. Not a second table
    # cache: it caches the AWS calls that happen BEFORE resolution, which are the
    # ones with a hard rate ceiling. firehose:DescribeDeliveryStream is capped at
    # 5 requests per second per account per Region and is NOT adjustable, so the
    # only lever is not making the call. Stable for the life of a WebACL
    # selection, and cleared by reset_table_cache with everything else.
    "s3_path_memo": (),      # (((dest_arn, scope, webacl_name, region), s3_path), ...)
    "output_location_memo": (),  # (((region, workgroup), location), ...)
    #
    # **A memo here can now be written after the tool call that started it has returned.**
    # Patrol's fan-out shuts its pool down with `wait=False, cancel_futures=True`, so the
    # queries already in flight finish in the background, and `_run_athena_select` calls
    # `_get_output_location` on the way. One of those stragglers can repopulate this memo
    # after a `reset_table_cache()` has cleared it.
    #
    # Harmless for *this* key, and the reasons are specific rather than general: the write is
    # lock-guarded, the memo is keyed on `(region, workgroup)`, and the value does not vary by
    # WebACL, so restoring it after a reset restores the same string. Do not read that as a
    # property of the state dict. Any key whose value depends on the *WebACL* would be a
    # stale-state bug of exactly the kind `reset_table_cache` exists to prevent, reintroduced
    # by a thread nobody is waiting for. Check that before adding one.
}

# Every default is immutable, so this shallow copy shares nothing with the live
# dict. That is what makes reset_table_cache's promise true: restoring from one
# defaults dict cannot forget a key, and cannot alias a mutable value either.
# A future key holding a list or dict would break that, so keep them tuples here
# and convert at the use site.
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

def _partition_too_coarse(java_fmt: str | None) -> bool:
    """True when the layout is too coarse to serve log-detail queries, i.e. coarser
    than hourly.

    **This replaces `_partition_has_minutes`, and the threshold moved with it (ROADMAP
    3.2).** Hourly used to be refused, which refused most Firehose users, since hourly is
    the Firehose default. The load test in `docs/hourly-vs-minute-partitioning.md` settled
    it: hourly scans about 4x the bytes of minute-level at the *same* wall time, because
    Athena's split parallelism follows object count rather than partition count. So hourly
    is a cost difference and not a speed wall, and the right response is to run it and say
    what it costs. Daily and coarser stay refused: nobody configures daily, its per-query
    scan is a multiple of hourly's, and it has none of hourly's "it is just the default"
    excuse.

    An unclassifiable format is refused. Reading it as fine-grained would run at unknown
    scan cost while the product believes it refuses coarse layouts, which is the one
    direction of this decision that cannot be walked back after the bill arrives."""
    granularity = _partition_granularity(java_fmt)
    if granularity is None:
        return True
    return _GRANULARITY_ORDER[granularity] > _GRANULARITY_ORDER["hours"]


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


def _memo_lister():
    """A `_s3_list_dirs` that answers a repeated prefix from memory.

    Scoped to one detection and passed down, rather than kept module-level. A bucket
    gains directories while the agent runs, so a cache that outlived the walk would
    hand back a stale newest-directory and pin the projection behind the data. Within a
    single walk the tree is effectively frozen, and the walk revisits prefixes heavily:
    measured against real S3 on a two-era tree, 34 listings covering 19 distinct
    prefixes, so 15 were repeats. `_layout_from_years` descends the newest year to
    decide the format, then descends it again looking for the cutover year, then again
    per candidate month.
    """
    memo: dict[tuple[str, str], list[str]] = {}

    def ls(bucket: str, prefix: str) -> list[str]:
        key = (bucket, prefix)
        if key not in memo:
            memo[key] = _s3_list_dirs(bucket, prefix)
        return memo[key]

    return ls


def _date_levels(bucket: str, root: str, parts: list[str], newest: bool, ls=None) -> list[str]:
    """Descend one date subtree, taking the newest or the earliest child each level.

    Returns the level names, starting from `parts`. Length is what identifies the
    layout: 4 levels is `yyyy/MM/dd/HH`, 5 is `yyyy/MM/dd/HH/mm`. Levels below the
    year are always two zero-padded digits, so a lexicographic min/max is the numeric
    one, and filtering to that shape keeps a stray non-numeric directory out.

    `ls` is the listing function, so a caller running several descents over one tree can
    pass a memoizing one. It defaults to listing S3 directly.
    """
    ls = ls or _s3_list_dirs
    prefix = root + "/".join(parts) + "/"
    levels = list(parts)
    while len(levels) < 5:
        kids = sorted(d for d in ls(bucket, prefix) if re.fullmatch(r"\d{2}", d))
        if not kids:
            break
        pick = kids[-1] if newest else kids[0]
        levels.append(pick)
        prefix += pick + "/"
    return levels


def _era_of(levels: list[str]) -> str | None:
    """'minutes', 'hours', 'days', or None when the subtree is too shallow to read.

    Three-way as of ROADMAP 3.2, and it had to become three-way in the same change that
    opened the gate to hourly. While hourly was refused outright, folding daily in with it
    was harmless: both were rejected and the message was right either way. Open the gate and
    a daily bucket declared as `yyyy/MM/dd/HH` projects `.../27/00` through `/23` while the
    objects sit directly under `.../27/`, so no projected partition covers them and Athena
    reports that as **zero rows with no error**. A loud refusal would have become a silent
    wrong answer.

    `days` and None stay distinct on purpose. `mixed` is only reported when both ends read as
    a real era, so folding an unreadable subtree into `days` would make an unreadable bucket
    claim a layout change it knows nothing about."""
    if len(levels) >= 5:
        return "minutes"
    if len(levels) == 4:
        return "hours"
    if len(levels) == 3:
        return "days"
    return None


def _detect_partitions(s3_path: str) -> dict:
    """Walk S3 to find the partition layout, and where the current layout begins.

    Returns a dict rather than a tuple. Three consumers now need different subsets of
    it, and a positional tuple churns every call site each time the set grows, which
    is the same lesson `_find_existing_table`'s return value taught.

    Keys: `storage_template`, `format`, `unit`, `interval`, `range_start`, `mixed`,
    `cutover`, `data_start`.

    **Why `range_start` is computed here at all.** It used to be hardcoded to 2020,
    giving about 3.46 million projected minutes, and Athena expands the whole declared
    range before applying `WHERE`, so that cost 4 to 5 seconds of planning on every
    query with scanned bytes unchanged. Deriving it needs to know where the data
    starts, which is the same walk that finds a mixed layout, so the two are one piece
    of work.

    **The two halves have deliberately different guarantees.** `range_start` is
    correctness-critical: too early only projects extra partitions, while too late
    makes real data unqueryable with no error. So it is computed by a *linear* scan
    over years and then months, which is exact, and floored to the first of the month.
    `cutover` is user-facing reporting, found by binary search within that month, and
    is best-effort: it assumes the layout changed once rather than alternating. A
    non-monotone bucket can therefore report a slightly late cutover date while
    `range_start` stays safe, which is the right way round.
    """
    parts = s3_path.replace("s3://", "").split("/", 1)
    bucket = parts[0]
    base_prefix = parts[1] if len(parts) > 1 else ""
    if base_prefix and not base_prefix.endswith("/"):
        base_prefix += "/"

    ls = _memo_lister()
    current_prefix = base_prefix
    for _ in range(10):
        dirs = ls(bucket, current_prefix)
        if not dirs:
            break
        years = sorted(d for d in dirs if re.match(r"^20[2-3]\d$", d))
        if years:
            return _layout_from_years(bucket, current_prefix, years, ls)

        # Pick best subdir to descend
        chosen = None
        if "AWSLogs" in dirs:
            chosen = "AWSLogs"
        else:
            for d in dirs:
                sub = ls(bucket, current_prefix + d + "/")
                if any(re.match(r"^20[2-3]\d$", x) for x in sub):
                    chosen = d
                    break
        if not chosen:
            chosen = dirs[0]
        current_prefix = current_prefix + chosen + "/"

    raise PartitionsNotFound(f"Cannot detect partition structure under {s3_path}")


# Padding for a range start, one entry per declared unit. `range_start_parts` is always
# [year, month, day], so each unit needs the fields its format adds beyond the day.
_RANGE_START_SUFFIX = {"days": "", "hours": "/00", "minutes": "/00/00"}

_FORMAT_BY_ERA = {
    "minutes": ("yyyy/MM/dd/HH/mm", "minutes"),
    "hours": ("yyyy/MM/dd/HH", "hours"),
    "days": ("yyyy/MM/dd", "days"),
}


def _layout_from_years(bucket: str, root: str, years: list[str], ls=None) -> dict:
    """Decide the layout and its start date, given the years present under `root`.

    `ls` should be the memoizing lister from `_memo_lister`: this function descends the
    same subtrees several times over, so listing S3 directly costs about 40% more calls
    than it needs to."""
    ls = ls or _s3_list_dirs
    newest = _date_levels(bucket, root, [years[-1]], newest=True, ls=ls)
    oldest = _date_levels(bucket, root, [years[0]], newest=False, ls=ls)
    era_new, era_old = _era_of(newest), _era_of(oldest)

    # The layout to declare is whatever the newest data uses: that is what the user
    # switched to, and it is what new objects will keep arriving as.
    #
    # A table rather than an if/else, because the old `else` collected two different cases
    # and declared hourly for both. Daily data got a format one level too fine, which
    # projects partitions that do not exist. An unreadable subtree got a guess.
    #
    # An unreadable subtree now falls back to the COARSEST layout, not the middle one.
    # Declaring coarser than reality is safe, since `storage.location.template` resolves to
    # the day directory and Athena scans recursively beneath it; declaring finer is the
    # zero-rows failure above. So when we cannot tell, guess in the direction that still
    # reads the data. It is then refused for log detail, which is the honest outcome for a
    # layout nobody could classify.
    fmt, unit = _FORMAT_BY_ERA[era_new or "days"]

    # Minute-level means interval 1, never inferred from the directory names.
    # Firehose's !{timestamp:mm} emits whatever minute the buffer happened to flush
    # at, so those names are arbitrary values like 03, 07, 41. Subtracting two of them
    # and feeding the difference to partition projection generated paths at that
    # stride only and never read the objects in between: a fraction of the rows, with
    # no error to show for it.
    interval = 1

    # One expression for "the oldest date in the bucket", used twice: reported to the
    # user as the far edge of the history a mixed bucket's table cannot reach, and used
    # as range_start whenever the table can address the whole timeline. It used to be
    # two expressions and they padded differently. The reporting copy appended
    # ["01", "00", "00"], so a year whose only children are non-date directories
    # produced day 00, and 2022/01/00 is not a date. Deriving both from one list makes
    # that divergence unrepresentable rather than merely fixed.
    data_start_parts = (oldest + ["01", "01"])[:3]
    data_start = "/".join(data_start_parts)

    # `era_new is not None` is load-bearing. Without it, a newest year whose subtree is
    # too shallow to read reports mixed=True with no cutover date, which tells the user
    # the bucket holds both eras when what actually happened is that the newest year is
    # unreadable and the format quietly fell back to hourly. Saying nothing is the
    # honest answer to an unreadable tree.
    mixed = era_new is not None and era_old is not None and era_new != era_old
    cutover = None

    if mixed and era_new == "minutes":
        # Exact at year and month granularity: a year or month whose newest child is
        # minute-level is the one the change falls in, and scanning them linearly
        # cannot be fooled by a layout that alternates.
        cy = next((y for y in years
                   if _era_of(_date_levels(bucket, root, [y], True, ls)) == "minutes"),
                  years[-1])
        months = sorted(d for d in ls(bucket, root + cy + "/") if re.fullmatch(r"\d{2}", d))
        cm = next((m for m in months
                   if _era_of(_date_levels(bucket, root, [cy, m], True, ls)) == "minutes"),
                  months[-1] if months else "01")
        range_start_parts = [cy, cm, "01"]
        cutover = _first_minute_day(bucket, root, cy, cm, ls)
    else:
        # Not mixed, or newest is hourly and an hourly table reads the whole timeline
        # anyway, so the earliest data is the safe start in both cases.
        range_start_parts = data_start_parts

    # The suffix has to match the DECLARED format field for field: `_create_named_table`
    # parses this string with `strptime` against `_java_date_format_to_strftime(fmt)`, so a
    # daily table given `yyyy/MM/dd/00` raises. The old two-way test read "minutes or not",
    # which was true while `not minutes` could only mean hourly.
    range_start = "/".join(range_start_parts) + _RANGE_START_SUFFIX[unit]

    return {
        "storage_template": f"s3://{bucket}/{root}${{log_time}}",
        "format": fmt,
        "unit": unit,
        "interval": interval,
        "range_start": range_start,
        "mixed": mixed,
        "cutover": cutover,
        "data_start": data_start,
    }


def _first_minute_day(bucket: str, root: str, year: str, month: str, ls=None) -> str | None:
    """Best-effort cutover day, by binary search inside one month.

    Reporting only. `range_start` is floored to the first of this month by the caller,
    so a wrong answer here costs a wrong date in a message rather than unreadable data.
    Binary search assumes the layout changed once inside the month; a bucket that
    alternates gets a late date and nothing worse.

    Binary search rather than a linear day scan because this issues a listing per probe,
    and each probe is itself a descent. Measured on a real 3-day month: 7 listings.
    """
    ls = ls or _s3_list_dirs
    days = sorted(d for d in ls(bucket, f"{root}{year}/{month}/") if re.fullmatch(r"\d{2}", d))
    if not days:
        return None
    lo, hi = 0, len(days) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if _era_of(_date_levels(bucket, root, [year, month, days[mid]], True, ls)) == "minutes":
            hi = mid
        else:
            lo = mid + 1
    if _era_of(_date_levels(bucket, root, [year, month, days[lo]], True, ls)) != "minutes":
        return None
    return f"{year}/{month}/{days[lo]}"


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


_TYPE_KINDS = {
    "int": lambda t: t in ("bigint", "int", "integer", "smallint", "tinyint"),
    "string": lambda t: t in ("string", "varchar") or t.startswith(("varchar(", "char(")),
    "struct": lambda t: t.startswith("struct<"),
    "array_struct": lambda t: t.startswith("array<struct<"),
}

# The tier is NOT decided by "does the generated SQL read this column". The SQL reads
# every column below, so that test puts all of them in one tier and explains nothing.
# What decides it is **what the user loses without it**:
#
#   REQUIRED     nothing worth running runs, so refuse the table and name the column.
#   SHARED_ONLY  required only when the table's location covers more than one WebACL.
#                Every query on such a table carries the `webaclid` filter and would
#                fail without the column; on a WebACL-scoped table no query mentions
#                it, so asking for it there would refuse a table for a column nothing
#                reads.
#   OPTIONAL     a named set of features fails, loudly, and the rest still works.
#
# The split earns its keep on a table nobody has updated. AWS WAF has added log columns
# over the years, and a Glue table declared before `labels` or `ja4fingerprint` existed
# still reads today's logs, because JsonSerDe ignores fields the table does not declare.
# Refusing that table is the outcome bring-your-own-table exists to avoid, so only the
# three columns that carry every query can be fatal.
#
# `ja3fingerprint` is deliberately absent: DDL_TEMPLATE declares it and no query reads
# it, so listing it would warn about losing a feature that does not exist.
REQUIRED, SHARED_ONLY, OPTIONAL = "required", "shared only", "optional"

# column -> (tier, type kind, struct fields the SQL dereferences, what reads it)
_COLUMN_SPEC = {
    "timestamp": (REQUIRED, "int", (),
                  'every window bound, as `"timestamp" BETWEEN` epoch milliseconds'),
    "action": (REQUIRED, "string", (),
               "the ALLOW/BLOCK/COUNT filter that almost every query carries"),
    "httprequest": (REQUIRED, "struct", ("clientip", "uri"),
                    "every query that reports a client IP or a URI"),
    "webaclid": (SHARED_ONLY, "string", (),
                 "the filter that keeps another WebACL's rows out of a shared table"),
    "terminatingruleid": (OPTIONAL, "string", (),
                          "per-rule breakdowns in patrol, COUNT evaluation and bypass"),
    "labels": (OPTIONAL, "array_struct", ("name",),
               "label queries on bot, managed-rule and anti-DDoS labels"),
    "nonterminatingmatchingrules": (OPTIONAL, "array_struct", ("ruleid",),
                                    "the query that finds COUNT-mode rule hits, which is how COUNT evaluation works"),
    "rulegrouplist": (OPTIONAL, "array_struct", ("nonterminatingmatchingrules",),
                      "the queries that attribute a hit to a managed rule group, including COUNT-mode hits on its nested rules"),
    "ja4fingerprint": (OPTIONAL, "string", (),
                       "JA4 client-fingerprint aggregation in the bypass scan"),
    "challengeresponse": (OPTIONAL, "struct", ("failurereason",),
                          "the token failure-reason breakdown for CHALLENGE"),
    "captcharesponse": (OPTIONAL, "struct", ("failurereason",),
                        "the token failure-reason breakdown for CAPTCHA"),
}


def _is_webacl_scoped(location: str) -> bool:
    """True when the table's own location names the active WebACL.

    One implementation for two readers. `_record_table` publishes it so the SQL builders
    know whether to add the `webaclid` filter, and `_check_schema` needs the same answer
    to decide whether `webaclid` has to be declared at all. Two copies would drift, and
    the drift would show up as a table refused for a column no query would have read.

    Always score the RESOLVED table's own location, never the requested s3_path: matches
    are ancestor-or-equal, so the requested path can contain the WebACL name while the
    table sitting above it does not, and that error runs one way only, claiming
    single-WebACL scoping a table does not have."""
    wn = get_webacl_name() or ""
    return bool(wn) and wn.lower() in (location or "").lower()


def _struct_fields(glue_type: str) -> list[str]:
    """Top-level field names of a Glue `struct<...>` or `array<struct<...>>` type.

    Depth-aware rather than a substring test, and that is the whole reason it exists:
    `httprequest` nests `headers:array<struct<name:string,value:string>>`, so
    `"name:" in type_string` reports a top-level `name` field that is not there, and
    `labels` would validate against any table whose httprequest has headers."""
    t = glue_type.strip().lower()
    if t.startswith("array<"):
        t = t[len("array<"):-1].strip() if t.endswith(">") else t
    if not (t.startswith("struct<") and t.endswith(">")):
        return []
    depth, field, out = 0, "", []
    for ch in t[len("struct<"):-1]:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(field)
            field = ""
        else:
            field += ch
    out.append(field)
    return [f.split(":", 1)[0].strip() for f in out if ":" in f]


def _column_readable(types: dict[str, str], col: str, kind: str, fields) -> bool:
    """True when the column is declared and shaped so the generated SQL can read it.

    Absent, wrongly typed and missing a dereferenced field give one answer on purpose:
    all three lose exactly the same queries, so one sentence covers them and the caller
    does not have to explain a distinction the user cannot act on differently."""
    if col not in types or not _TYPE_KINDS[kind](types[col]):
        return False
    have = _struct_fields(types[col])
    return all(f in have for f in fields)


def _check_schema(name: str, types: dict[str, str],
                  shared_location: bool) -> tuple[str | None, str | None]:
    """Validate a candidate table against what the generated SQL reads.

    Returns (rejection, note). The rejection is fatal and worded like the other
    `_table_metadata` refusals; the note names the features that will fail on a table
    that is otherwise fine. `shared_location` is False when the table's own location
    names the active WebACL, which is what makes the `webaclid` column unnecessary.

    Name-only checking was the gap: an `httprequest` of the wrong shape, or a
    `timestamp` declared `string`, bound successfully and then failed once per query
    with a raw Athena error naming a column but not what the agent wanted it for."""
    for col, (tier, kind, fields, why) in _COLUMN_SPEC.items():
        if tier == OPTIONAL or (tier == SHARED_ONLY and not shared_location):
            continue
        if col not in types:
            return f"{name}: missing WAF log column `{col}`. It is read by {why}.", None
        if not _TYPE_KINDS[kind](types[col]):
            return (f"{name}: column `{col}` is declared `{types[col]}`, but it is read "
                    f"by {why}, so it has to be declared "
                    f"{kind.replace('array_struct', 'array<struct<…>>')}.", None)
        absent = [f for f in fields if f not in _struct_fields(types[col])]
        if absent:
            return (f"{name}: `{col}` has no {', '.join(absent)} field"
                    f"{'s' if len(absent) > 1 else ''}. Its fields are "
                    f"{', '.join(_struct_fields(types[col])) or '(none readable)'}, and "
                    f"it is read by {why}.", None)

    # Each column travels next to its own reason. Two independently sorted lists, one of
    # columns and one of reasons, invite the reader to pair them positionally, and the
    # pairing is wrong for every entry.
    lost = sorted((col, why) for col, (tier, kind, fields, why) in _COLUMN_SPEC.items()
                  if tier == OPTIONAL and not _column_readable(types, col, kind, fields))
    if not lost:
        return None, None
    return None, (f"{name} is missing or mis-declaring "
                  + "; ".join(f"`{col}`, needed by {why}" for col, why in lost)
                  + ". Those will fail; the table is usable for everything else.")


def _table_metadata(db_name: str, tbl: dict) -> dict | str:
    """Validate one Glue table as a WAF log source for the pruning path.

    Returns its metadata on success, or a one-line string saying why it was
    rejected. The string is shown to the user: "the agent built its own table"
    is a confusing outcome unless it also says what was wrong with theirs."""
    name = f"{db_name}.{tbl['Name']}"
    sd = tbl.get("StorageDescriptor", {})
    location = sd.get("Location", "").rstrip("/")
    types = {c["Name"].lower(): (c.get("Type") or "").strip().lower()
             for c in sd.get("Columns", [])}
    rejection, schema_note = _check_schema(
        name, types, shared_location=not _is_webacl_scoped(location))
    if rejection:
        return rejection

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
        "location": location,
        "schema_note": schema_note,
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
    notes: list[str] = []  # built as a list, published as a tuple

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
                    _athena_state["discovery_notes"] = tuple(notes)
                    return meta
                if best is None or len(meta["location"]) > len(best["location"]):
                    best = meta
        if best is not None:
            _athena_state["discovery_notes"] = tuple(notes)
            return best

    _athena_state["discovery_notes"] = tuple(notes)
    return None


def _ensure_database(region: str, workgroup: str):
    """Create tmp database if not exists."""
    sql = f"CREATE DATABASE IF NOT EXISTS `{TMP_DATABASE}`"
    _run_athena_ddl(sql, region, workgroup)


def _create_named_table(s3_path: str, storage_template: str, partition_format: str,
                        partition_unit: str, partition_interval: int, region: str, workgroup: str,
                        table_name: str, range_start: str | None = None) -> dict:
    """Create a permanent Athena table with the given name. Returns its metadata.

    `range_start` comes from `_detect_partitions`, derived from where the data actually
    begins. The old hardcoded 2020 meant about 3.46 million projected minutes, and
    Athena expands the declared range before applying `WHERE`, so it cost 4 to 5
    seconds of planning per query with scanned bytes unchanged. It also sat above
    Athena's documented 1,000,000-partition ceiling for a single scan, survivable only
    because every query carries a partition predicate. The fallback is kept for a
    caller that has no layout in hand, but every live caller passes one.
    """
    _ensure_database(region, workgroup)
    if range_start is None:
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
        # DDL_TEMPLATE is where the required schema is defined, so a table this
        # function wrote cannot be missing any of it.
        "schema_note": None,
        "partition_col": "log_time",
        "partition_format": partition_format,
        "partition_granularity": _partition_granularity(partition_format),
        "partition_interval": partition_interval,
        "partition_interval_unit": partition_unit,
        "partition_range_start": datetime.strptime(
            range_start, _java_date_format_to_strftime(partition_format)),
        "partition_range_end": None,
    }


def _cross_check_declared(meta: dict, layout: dict | None, strict: bool) -> str | None:
    """Compare a table's declared projection against the real S3 layout.

    Returns None when the table can address the data, else one line naming the
    problem. Takes the layout rather than walking S3 for it: the caller has already
    walked, and it needs the same dict for two other things.

    `layout` is None when nothing readable sits under the path: an empty bucket, or a
    prefix that has received no data. There is nothing to compare against, so the
    declaration is trusted.

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
    if layout is None:
        return None
    actual_fmt = layout["format"]
    actual_unit = layout["unit"]
    actual_interval = layout["interval"]

    declared_fmt = meta["partition_format"]
    if strict and (declared_fmt, meta["partition_interval"], meta["partition_interval_unit"]) \
            != (actual_fmt, actual_interval, actual_unit):
        return (f"declares {declared_fmt} / interval {meta['partition_interval']} "
                f"{meta['partition_interval_unit']} but the S3 layout is {actual_fmt} / "
                f"interval {actual_interval} {actual_unit}")

    # The projected range start, strict only, and this is what carries the range fix to
    # an installation that already has a scratch table. Every table the agent built
    # before that change declares 2020/01/01, about 3.46 million projected minutes, and
    # nothing else here would ever notice: the format, interval and unit all still match
    # the bucket, so the table passes, gets reused, and keeps paying seconds of planning
    # per query forever. There is no other trigger to rebuild it.
    #
    # Strict only, on purpose. On a table the user maintains, a range wider than the
    # data is their choice and costs them planning time they can measure; rewriting it
    # is not this code's business, and `partition_predicate` already reports a window
    # that falls outside it. On the agent's own table the whole meaning of strict is
    # that any disagreement makes it stale.
    if strict and meta["partition_range_start"] is not None:
        try:
            wanted = datetime.strptime(
                layout["range_start"], _java_date_format_to_strftime(actual_fmt))
        except (ValueError, KeyError):
            wanted = None
        if wanted is not None and wanted != meta["partition_range_start"]:
            # Both directions are stale, and they are stale for opposite reasons, so
            # say which. Too early is wasted planning; too late means real data the
            # table cannot address, reported by Athena as zero rows.
            why = ("wasting planning time on partitions that cannot exist"
                   if meta["partition_range_start"] < wanted
                   else "so data before that point cannot be returned at all")
            return (f"projects from {meta['partition_range_start']:%Y-%m-%d %H:%M} but the "
                    f"data starts {wanted:%Y-%m-%d %H:%M}, {why}")

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


def resolve_s3_log_path(log_dest: str, scope: str, webacl_name: str, region: str) -> str:
    """Translate a WAF log destination into the S3 path to resolve a table against.

    Memoized on all four inputs (see below), because the calls behind it are the ones with a
    rate ceiling rather than the ones with a cost. `firehose:DescribeDeliveryStream`
    is capped at **5 requests per second, per account per Region, and is not
    adjustable**, so the only lever is not making the call; on throttle it returns
    ThrottlingException with HTTP 400, botocore retries with backoff, and the visible
    result is added latency then a hard failure once the retry budget runs out. The
    S3-direct branch has no ceiling but still pays `sts:GetCallerIdentity` and an
    `s3:ListObjectsV2` probe, which is latency worth not repeating.

    The memo is not a second table cache: it caches the step *before* resolution.

    **Keyed on all four inputs, not on the destination alone.** On the S3-direct branch
    the answer depends on the WebACL, because `_try_standard_path` builds
    `AWSLogs/{account}/WAFLogs/{scope}/{webacl_name}/`, and several WebACLs sharing one
    bucket is an ordinary setup. Keying on the destination alone would be safe only
    because `set_webacl_context` resets this state on every switch, which makes
    correctness depend on a caller doing something rather than on the key. With the
    full key the reset is redundancy instead of a requirement, and moving the memo to
    module scope, an obvious-looking tidy-up, could no longer start returning the
    previous WebACL's path.

    Shared by both query paths on purpose. Each used to do this translation itself,
    which is the seam that made the two copies drift, and on a Firehose destination it
    meant one describe per query on one side and one per scan on the other.
    """
    key = (log_dest, scope, webacl_name, region)
    memo = dict(_athena_state.get("s3_path_memo") or ())
    if key in memo:
        return memo[key]

    with _translate_lock:
        # Double-checked: another thread may have translated it while we waited.
        memo = dict(_athena_state.get("s3_path_memo") or ())
        if key in memo:
            return memo[key]

        s3_base = _resolve_s3_path(log_dest)
        s3_path = None
        if ":s3:::" in log_dest:
            bucket = s3_base.replace("s3://", "").split("/")[0]
            s3_path = _try_standard_path(bucket, _get_account_id(), scope, webacl_name, region)
        s3_path = s3_path or s3_base

        memo[key] = s3_path
        _athena_state["s3_path_memo"] = tuple(memo.items())
        return s3_path


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

    with _resolve_lock:
        # Double-checked: another thread may have resolved it while we waited.
        if _athena_state.get("table"):
            return _athena_state["table"]
        return _resolve_log_table_locked(s3_path, region, webacl_name)


def _resolve_log_table_locked(s3_path: str, region: str, webacl_name: str) -> str:
    """The body of resolve_log_table. Call only with _resolve_lock held.

    One walk of S3, at the top, shared by every path out of here. Three things need
    the same dict: the cross-check of a table we found, the CREATE of one we did not,
    and the mixed-layout state the user-facing warning reads. Deriving it per consumer
    walked the same tree twice on the self-heal path, and worse, published the layout
    only inside the create branch, so a returning session and anyone querying their
    own table saw `layout_mixed` False no matter what the bucket held, which is
    precisely the population the mixed-bucket warning exists for."""
    layout, layout_error = None, None
    try:
        layout = _detect_partitions(s3_path)
    except PartitionsNotFound as exc:
        # Walked the path and found nothing recognisable under it: an empty bucket, or a
        # prefix that has not received data yet. Not fatal: an existing table is still
        # trusted as declared, and the create path re-raises this below rather than
        # writing a second copy of the same message.
        layout_error = exc
    except Exception as exc:
        # Could not walk the path at all, which `except Exception` used to flatten into
        # the case above. Trusting a declaration because the bucket is *empty* is sound;
        # trusting one because the bucket is *gone* is not. Measured on a real account
        # with a deleted bucket: resolution succeeded, published `layout_data_start` as
        # None, and every query then failed with a raw `HIVE_FILESYSTEM_ERROR` naming a
        # bucket, once per query, where resolution had already held the information to
        # say so once and say it usefully.
        raise RuntimeError(
            f"Cannot read the S3 log path for this WebACL: {s3_path}. S3 said "
            f"{type(exc).__name__}: {exc}. The bucket may have been deleted, or this "
            f"role may not be allowed to list it. This is NOT an absence of traffic. Any "
            f"Athena table still declared over this path will fail every query rather "
            f"than return rows, so check the WebACL's logging destination.") from exc
    if layout is not None:
        _athena_state["layout_mixed"] = layout["mixed"]
        _athena_state["layout_cutover"] = layout["cutover"]
        _athena_state["layout_data_start"] = layout["data_start"]

    meta = _find_existing_table(s3_path, region)
    if meta is not None:
        db, tbl = meta["table"].split(".", 1)
        problem = _cross_check_declared(meta, layout, strict=(db == TMP_DATABASE))
        if problem is None:
            return _record_table(meta)
        if db == TMP_DATABASE:
            # The agent's own scratch table, now inconsistent with the data under
            # it. Drop and rebuild; dropping an EXTERNAL table never touches S3.
            _athena_state["discovery_notes"] += (
                f"{meta['table']} {problem}. Recreating it.",)
            try:
                get_client("glue", region_name=region).delete_table(DatabaseName=db, Name=tbl)
            except Exception:
                pass
        else:
            _athena_state["discovery_notes"] += (
                f"{meta['table']} {problem}. Building a separate table in "
                f"{TMP_DATABASE} instead and leaving yours untouched.",)

    if not _validate_waf_log(s3_path):
        raise RuntimeError(
            f"S3 path does not contain valid AWS WAF logs: {s3_path}. Verify the log "
            f"destination is correct.")
    if layout is None:
        raise layout_error
    safe_name = re.sub(r"[^a-zA-Z0-9]", "_", webacl_name or "unknown").lower()
    created = _create_named_table(
        s3_path, layout["storage_template"], layout["format"], layout["unit"],
        layout["interval"], region, "primary", f"waf_logs_{safe_name}",
        range_start=layout["range_start"])
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
                   f"what the data contains. ")
        mixed = _mixed_layout_sentence()
        if mixed:
            # "Widen the range" is the obvious advice and on a mixed bucket it is
            # actively wrong: the pre-cutover directories are hourly, so a wider
            # minute-level projection generates paths that do not exist and returns
            # nothing, which looks like the advice was followed and the data is gone.
            # Second copy of the sentence 3.2 falsified, and the sweep that corrected the one
            # in `describe_table_resolution` missed it. Hourly tables ARE queryable now; what
            # stays true is that the agent builds one table per WebACL, for the newest layout,
            # so the older era needs a second one the user creates.
            problem += (f"{mixed} Widening the range would not help, because the paths a "
                        f"minute-level projection generates are not there before the "
                        f"cutover. Query a window after it, or read the older era with a "
                        f"second, hourly table you create yourself over the same bucket.")
        else:
            problem += (f"Widen the table's projection.{part_col}.range or query a "
                        f"later window.")
    elif range_end is not None and naive_end > range_end:
        problem = (f"The requested window ends {naive_end:%Y-%m-%d %H:%M}, after "
                   f"`{table}`'s partition projection stops "
                   f"({range_end:%Y-%m-%d %H:%M}). Rows after that point are outside "
                   f"the projected partitions and cannot be returned.")
    return clause, problem


def _mixed_layout_sentence() -> str | None:
    """One sentence naming the layout switch, or None if the bucket has a single layout.

    Two messages need this fact and neither owns it: the table-resolution block, which
    explains what the table can reach, and `partition_predicate`'s out-of-range
    problem, which explains why widening the range would not help. One function so the
    cutover date cannot be described two ways.

    Returns None when the newest era is hourly, which is `layout_cutover is None`. That
    table reads the whole timeline, so there is no unreachable history to warn about,
    and every query against it is already refused by the coarse-partition gate with its
    own explanation."""
    if not (_athena_state.get("layout_mixed") and _athena_state.get("layout_cutover")):
        return None
    return (f"This bucket holds two partition layouts: hourly directories up to about "
            f"{_athena_state['layout_cutover']}, minute-level ones after.")


def describe_table_resolution() -> str:
    """One block naming the resolved table and why any candidate was rejected.

    Surfaced in tool output so the choice is auditable. "The agent built its own
    table" is a confusing outcome on its own; with the rejection reasons attached
    the user can fix their table instead of guessing."""
    lines = []
    if _athena_state.get("table_choice"):
        lines.append(_athena_state["table_choice"])
    mixed = _mixed_layout_sentence()
    if mixed:
        # `projection.<col>.format` holds one value, so one table cannot describe two
        # granularities, and the pre-cutover era is unreachable rather than merely
        # coarse. Say so here rather than only when a query happens to ask for it: a
        # user who switched prefixes months ago has no reason to suspect the older
        # objects are invisible, and Athena's answer for them is zero rows.
        # The last sentence used to read "an hourly table, which this agent does not build
        # yet", and 3.2 made that false: the agent now declares hourly when the newest data
        # is hourly, and hourly log queries run. What is still true is narrower, so say the
        # narrower thing. The agent builds ONE table, for the layout the newest data uses,
        # and reading the older era needs a SECOND table over the same bucket that it does
        # not build. That is also why the manual second-table recipe in
        # docs/hourly-vs-minute-partitioning.md stays: it is still the only way to read a
        # pre-cutover era, which 3.2 was expected to change and did not.
        lines.append(
            f"{mixed} This table covers the minute-level era only. Logs from "
            f"{_athena_state.get('layout_data_start')} up to the cutover are in the "
            f"bucket, but no minute-level table can address them, and Athena reports "
            f"that as zero rows rather than as an error. Hourly tables are queryable "
            f"now, but the agent builds one table per WebACL, for the newest layout, so "
            f"reading the older era needs a second, hourly table you create yourself over "
            f"the same bucket. The cutover date is best-effort.")
    # 3.3's cost notice. Here rather than per query because it is a property of the table:
    # once per resolved table is information, once per query is noise the model learns to
    # skip. Fires for hourly only; daily and coarser are refused outright and say so at the
    # query, and minute-level has nothing to report.
    if _partition_granularity(_athena_state.get("partition_format")) == "hours":
        from tools.waf_query import HOURLY_COST_NOTICE
        lines.append(HOURLY_COST_NOTICE)
    if _athena_state.get("schema_note"):
        lines.append(_athena_state["schema_note"])
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
    # Subscript, not `.get`: both producers set this key, so a third one that forgets
    # should raise here rather than have its table silently report a clean schema.
    _athena_state["schema_note"] = meta["schema_note"]
    # A table whose location does not contain the WebACL name may hold several
    # WebACLs' logs, and then every query has to carry the webaclid filter.
    _athena_state["webacl_scoped"] = _is_webacl_scoped(meta["location"])
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
    """Get Athena output location from workgroup config or fallback.

    Memoized on (region, workgroup), which is stable for a session. Both Athena
    executors call this once per statement, and on a workgroup with no output location
    configured the fallback path below reaches for
    `firehose:DescribeDeliveryStream`, whose 5-per-second per-account ceiling is not
    adjustable. Unmemoized that is one describe per statement, and a patrol scan runs
    several. Configuring an output location on the workgroup removes the call
    entirely, which is the real fix; this keeps an unconfigured account off the
    ceiling in the meantime.
    """
    key = (region, workgroup)
    memo = dict(_athena_state.get("output_location_memo") or ())
    if key in memo:
        return memo[key]

    with _output_location_lock:
        # Re-read the state rather than reusing the dict captured above; reusing it is
        # how this pattern is usually written wrong.
        memo = dict(_athena_state.get("output_location_memo") or ())
        if key in memo:
            return memo[key]

        loc = _resolve_output_location(region, workgroup)
        memo[key] = loc
        _athena_state["output_location_memo"] = tuple(memo.items())
        return loc


def _resolve_output_location(region: str, workgroup: str) -> str:
    """The uncached body of _get_output_location."""
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


# What a running query has done so far, for the SSE heartbeat to report. Written by the
# agent's worker thread and read by the event loop, so the contract is: replace the whole
# dict in one assignment, never mutate it in place. A reader then sees either the previous
# snapshot or the next one, never half of one, without needing a lock for what is a
# best-effort progress line.
#
# Deliberately not in `_athena_state`: that dict is reset per WebACL and describes a
# resolved table, while this describes one in-flight query and is cleared when it ends.
_query_progress: dict | None = None


# A snapshot older than this is treated as no snapshot. A running query republishes every
# POLL_INTERVAL, so its own reading is never this old; anything that is has been abandoned.
_PROGRESS_STALE_AFTER = POLL_INTERVAL * 3


def query_progress() -> dict | None:
    """The in-flight query's progress, or None when nothing is running.

    Read by `agent.py`'s SSE heartbeat so a long query shows movement instead of a bare
    keepalive.

    **Takes one reference and answers from it**, so a caller cannot observe two different
    snapshots inside one heartbeat. That, plus writers replacing the whole dict rather than
    mutating it, is the entire lock-free contract.

    **Age is checked here rather than trusted from the writer**, and it is the backstop for
    every way a snapshot can outlive its query: a thread killed at shutdown, or a `qid`-guarded
    clear that loses a race. Without it a stale reading means the heartbeat announces "Athena
    query running, scanned 2.10 GB" for a query that is gone, which is worse than saying
    nothing, because silence is honest and a stale claim is not.
    """
    snap = _query_progress
    if snap is None:
        return None
    if time.monotonic() - snap.get("at", 0) > _PROGRESS_STALE_AFTER:
        return None
    return snap


def _wait_query(athena, qid: str):
    """Poll until query completes.

    On success this clears the consecutive-timeout count, which is what keeps the retry
    bound in `poll_timeout_message` scoped to a run of failures rather than to the session.

    Publishes progress on every poll. `get_query_execution` already returns
    `Statistics.DataScannedInBytes` *while the query is still running*, so the bytes are
    free: this loop was making the call anyway and throwing that field away.
    """
    global _query_progress
    from tools.session_state import note_query_success
    started = time.monotonic()
    deadline = started + MAX_POLL
    try:
        while time.monotonic() < deadline:
            time.sleep(POLL_INTERVAL)  # nosemgrep: arbitrary-sleep — polling for Athena query completion
            resp = athena.get_query_execution(QueryExecutionId=qid)
            state = resp["QueryExecution"]["Status"]["State"]
            _query_progress = {
                "engine": "Athena",
                "state": state,
                "scanned_bytes": resp["QueryExecution"].get("Statistics", {}).get(
                    "DataScannedInBytes", 0),
                "elapsed": time.monotonic() - started,
                "budget": MAX_POLL,
                "qid": qid,
                "at": time.monotonic(),
            }
            if state == "SUCCEEDED":
                note_query_success()
                return
            if state in ("FAILED", "CANCELLED"):
                # Carries the engine's own reason, and the same "not an absence of traffic"
                # framing the CloudWatch path got. Observed on a real bucket: a wide query
                # returned HIVE_S3_THROTTLING, which is exactly the failure where an
                # unprompted retry makes things worse.
                reason = resp["QueryExecution"]["Status"].get("StateChangeReason", "")
                raise RuntimeError(query_failed_message("Athena", state, reason))
        # The only stop site for Athena, and it is here rather than inside the loop because
        # every in-loop exit is already terminal: SUCCEEDED returns, FAILED and CANCELLED
        # raise. So reaching this line means the last poll saw a non-terminal state, which is
        # what makes a terminal-state guard unnecessary. Nothing may re-read the execution
        # between the stop and the raise: our own cancel lands as CANCELLED with reason
        # "Query cancelled by user", and the branch above would report that to the user as an
        # engine failure while also not spending the retry allowance a timeout does.
        raise RuntimeError(poll_timeout_message("Athena", stop_athena_query(athena, qid)))
    finally:
        # `finally` rather than a clear on each exit, because the three enumerated exits are
        # not all of them: `get_query_execution` can raise on throttling, expired credentials
        # or a dropped socket, and callers wrap Athena work in broad excepts in several
        # places, so that raise is survivable and the stale snapshot therefore persistent
        # rather than fatal.
        #
        # **Only clear a snapshot that is still ours**, which is what `qid` is for. Patrol
        # runs up to fifteen of these across five workers, all writing this one global. A
        # clear that ignored ownership would blank the progress line every time any one of
        # the fifteen finished, so the display would flicker off and back through the whole
        # scan, and patrol is the longest tool call in the product and the reason the
        # heartbeat exists.
        #
        # **The guard bounds that flicker, it does not remove it, and a test proved the
        # stronger claim false.** Publishing takes ownership, so ownership churns to whoever
        # polled most recently. The line therefore survives any *non-owning* query finishing,
        # and still goes blank for up to one POLL_INTERVAL when the owner finishes while
        # others run, until the next worker republishes. `query_progress`'s age check is the
        # backstop for a clear that loses a race or a thread killed at shutdown.
        snap = _query_progress
        if snap is not None and snap.get("qid") == qid:
            _query_progress = None
