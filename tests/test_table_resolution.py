# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Athena table resolution, against a fake Glue catalog.

Covers the parts of `waf_athena` that decide WHICH table a log query runs
against. Worth having as tests rather than as a manual check because the failure
mode is silence: the wrong table, or the wrong pruning format, returns zero rows
or another WebACL's rows, with no error anywhere. A real-environment check can
confirm one table resolves; it cannot cheaply cover eight rejection reasons, the
preference order between two candidates, Glue pagination, or a path-boundary
collision.

Glue, S3 and Athena are all faked. So this says nothing about real Glue response
shapes, real projection semantics, or IAM. Run `AGENTS.md`'s deploy checks for
those.
"""

import datetime as dt

import pytest

from tools import waf_athena as A

WAF_COLS = [{"Name": "action"}, {"Name": "httprequest"},
            {"Name": "webaclid"}, {"Name": "timestamp"}]

# A vended-log path, i.e. one specific to a single WebACL.
SCOPED_PATH = "s3://bkt/AWSLogs/1/WAFLogs/us-east-1/myacl"
# Its ancestor, i.e. what a shared Firehose bucket-root table would sit on.
SHARED_PATH = "s3://bkt/AWSLogs"
def _layout(fmt, unit, interval=1, **extra):
    """The shape `_detect_partitions` returns. A dict, not a tuple, because three
    consumers need different subsets and a tuple churns them all when it grows."""
    return {"storage_template": "tmpl", "format": fmt, "unit": unit,
            "interval": interval, "range_start": "2020/01/01/00/00",
            "mixed": False, "cutover": None, "data_start": "2020/01/01",
            **extra}


MINUTE_LAYOUT = _layout("yyyy/MM/dd/HH/mm", "minutes")
HOURLY_LAYOUT = _layout("yyyy/MM/dd/HH", "hours")
# Hourly before a cutover, minute-level after. What every bucket looks like once its
# owner has followed the minute-partitioning guide.
MIXED_LAYOUT = _layout("yyyy/MM/dd/HH/mm", "minutes", mixed=True,
                       cutover="2026/01/05", data_start="2022/03/07",
                       range_start="2026/01/01/00/00")


def table(name, location, col="log_time", fmt="yyyy/MM/dd/HH/mm", interval="1",
          unit="minutes", rng=None, ptype="date", enabled="true", keys=None,
          cols=WAF_COLS):
    """Build a Glue Table dict. Defaults describe a healthy minute-level table."""
    if rng is None:
        # A real table declares its range in its own format, and resolution
        # checks that, so the default has to follow `fmt` rather than be literal.
        rng = (dt.datetime(2020, 1, 1).strftime(A._java_date_format_to_strftime(fmt))
               + ",NOW") if fmt else ""
    params = {"projection.enabled": enabled}
    for key, value in ((f"projection.{col}.type", ptype),
                       (f"projection.{col}.format", fmt),
                       (f"projection.{col}.interval", interval),
                       (f"projection.{col}.interval.unit", unit),
                       (f"projection.{col}.range", rng)):
        if value:
            params[key] = value
    return {
        "Name": name,
        "StorageDescriptor": {"Location": location, "Columns": cols},
        "PartitionKeys": [{"Name": k} for k in (keys if keys is not None else [col])],
        "Parameters": params,
    }


class FakeGlue:
    """Only the three Glue operations resolution uses, paginated two per page.

    Small pages on purpose: a single-page fake would pass even if the pagination
    were removed, which is one of the things being tested.
    """

    PAGE = 2

    def __init__(self, catalog):
        self.catalog = catalog
        self.deleted = []
        self.get_tables_calls = 0

    def _pages(self, key, rows):
        for i in range(0, max(len(rows), 1), self.PAGE):
            yield {key: rows[i:i + self.PAGE]}

    def get_paginator(self, operation):
        outer = self

        class _Paginator:
            def paginate(self, DatabaseName=None, **_):
                if operation == "get_databases":
                    yield from outer._pages("DatabaseList",
                                            [{"Name": d} for d in outer.catalog])
                else:
                    outer.get_tables_calls += 1
                    yield from outer._pages("TableList",
                                            outer.catalog.get(DatabaseName, []))

        return _Paginator()

    def delete_table(self, DatabaseName, Name):
        self.deleted.append(f"{DatabaseName}.{Name}")


@pytest.fixture
def catalog(monkeypatch):
    """Install a fake Glue catalog and stub out the S3 walk.

    Returns a callable: pass {database: [table, ...]} and get the FakeGlue back.
    """
    def install(entries, layout=MINUTE_LAYOUT):
        glue = FakeGlue(entries)
        monkeypatch.setattr(A, "get_client", lambda *a, **k: glue)
        monkeypatch.setattr(A, "_detect_partitions", lambda path: dict(layout))
        monkeypatch.setattr(A, "_validate_waf_log", lambda path: True)
        monkeypatch.setattr(A, "get_webacl_name", lambda: "myacl")
        A.reset_table_cache()
        return glue

    yield install
    A.reset_table_cache()


# --- which table wins -------------------------------------------------------


def test_user_table_on_ancestor_beats_scratch_table_at_exact_path(catalog):
    """The scratch table is always the most specific match, so it must not win.

    _create_named_table puts it at exactly the resolved path. Ranking purely by
    specificity would therefore pick it every time and a user's own table would
    never be used, which is the whole point of the feature.
    """
    catalog({"userdb": [table("waf", SHARED_PATH)],
             A.TMP_DATABASE: [table("waf_logs_myacl", SCOPED_PATH)]})
    assert A._find_existing_table(SCOPED_PATH, "us-east-1")["table"] == "userdb.waf"


def test_scratch_table_is_used_when_nothing_else_qualifies(catalog):
    catalog({A.TMP_DATABASE: [table("waf_logs_myacl", SCOPED_PATH)]})
    chosen = A._find_existing_table(SCOPED_PATH, "us-east-1")
    assert chosen["table"] == f"{A.TMP_DATABASE}.waf_logs_myacl"


def test_longest_location_wins_within_the_preferred_group(catalog):
    catalog({"adb": [table("shallow", "s3://bkt/AWSLogs")],
             "bdb": [table("deep", "s3://bkt/AWSLogs/1/WAFLogs")]})
    assert A._find_existing_table(SCOPED_PATH, "us-east-1")["table"] == "bdb.deep"


def test_exact_match_short_circuits_the_catalog_walk(catalog):
    """An exact-location match cannot be beaten, so resolution stops there.

    Without this a cold resolve walks every table in every database, which on a
    real warehouse is hundreds of Glue calls. `aaa` sorts before `zzz`, so
    stopping at the first exact match is also the deterministic choice rather
    than whichever one Glue happened to return first.
    """
    glue = catalog({"aaa": [table("exact", SCOPED_PATH)],
                    "zzz": [table("other", SHARED_PATH)]})
    assert A._find_existing_table(SCOPED_PATH, "us-east-1")["table"] == "aaa.exact"
    assert glue.get_tables_calls == 1


def test_a_match_beyond_the_first_page_is_still_found(catalog):
    """Glue pagination. Before this, a database past its first page of tables
    was invisible and the agent built its own table next to a perfectly good one."""
    entries = [table(f"t{i:03}", "s3://elsewhere") for i in range(5)]
    entries.append(table("zwin", SHARED_PATH))
    catalog({"userdb": entries})
    assert A._find_existing_table(SCOPED_PATH, "us-east-1")["table"] == "userdb.zwin"


def test_location_match_respects_the_path_boundary(catalog):
    """s3://bkt/waf-logs must not claim s3://bkt/waf-logs-prod."""
    catalog({"userdb": [table("a", "s3://bkt/waf-logs")]})
    assert A._find_existing_table("s3://bkt/waf-logs-prod", "us-east-1") is None


# --- what a table has to look like -----------------------------------------


def test_partition_column_may_be_named_anything(catalog):
    """The point of ROADMAP 0.2: discovery used to require the name `log_time`."""
    catalog({"userdb": [table("dh", SHARED_PATH, col="datehour")]})
    chosen = A._find_existing_table(SCOPED_PATH, "us-east-1")
    assert (chosen["partition_col"], chosen["partition_format"]) == \
        ("datehour", "yyyy/MM/dd/HH/mm")


@pytest.mark.parametrize("kwargs,expected_reason", [
    ({"keys": ["log_time", "region"]}, "partitioned on 2 keys"),
    ({"keys": []}, "not partitioned"),
    ({"ptype": "integer"}, "projection type 'integer'"),
    ({"enabled": "false"}, "projection is not enabled"),
    ({"fmt": "dd/MM/yyyy"}, "not supported"),
    ({"cols": [{"Name": "action"}]}, "missing WAF log column"),
    ({"rng": ""}, "no projection range"),
    ({"rng": "2020/01/01/00/00,2021/01/01/00/00"}, "already in the past"),
    ({"rng": "2020/01/01/00/00"}, "is not a start,end pair"),
])
def test_unusable_table_is_rejected_with_a_reason(catalog, kwargs, expected_reason):
    """Every rejection has to say why, because "the agent built its own table"
    is not something a user can act on by itself."""
    catalog({"userdb": [table("m", SHARED_PATH, **kwargs)]})
    assert A._find_existing_table(SCOPED_PATH, "us-east-1") is None
    assert expected_reason in " ".join(A._athena_state["discovery_notes"])


@pytest.mark.parametrize("fmt,granularity", [
    ("yyyy/MM/dd/HH/mm", "minutes"),
    ("yyyy/MM/dd/HH", "hours"),
    ("yyyy/MM/dd", "days"),
    ("yyyy-MM-dd-HH", "hours"),      # legal Athena, and not the hardcoded string
    ("yyyyMMddHH", "hours"),         # no separator at all
    ("dd/MM/yyyy", None),            # lexicographic pruning would compare wrong
    ("yyyy/MM/dd/HH/mm/ss", None),   # sub-minute is not rendered
    ("yy/MM/dd", None),              # two-digit year
    ("yyyy/MM/dd/mm", None),         # minute without hour
    ("", None),
    (None, None),
])
def test_granularity_classification(fmt, granularity):
    assert A._partition_granularity(fmt) == granularity


# --- declared config versus what is actually in S3 -------------------------
#
# These take the layout as an argument rather than through the fixture, because the
# function does. It used to walk S3 itself; the walk moved up to the one caller, which
# needs the same dict for two other things.


def test_declaring_coarser_than_the_data_is_accepted():
    """An hourly table over minute-nested S3 works: the location template
    resolves to the hour directory and Athena scans recursively beneath it."""
    meta = A._table_metadata("d", table("h", SCOPED_PATH, fmt="yyyy/MM/dd/HH", unit="hours"))
    assert A._cross_check_declared(meta, MINUTE_LAYOUT, strict=False) is None


def test_declaring_finer_than_the_data_is_rejected():
    """A minute-level table over hourly directories projects `.../12/16` under a
    bucket that only has `.../12`. Athena reports the miss as zero rows."""
    meta = A._table_metadata("d", table("m", SCOPED_PATH))
    assert "finer than" in A._cross_check_declared(meta, HOURLY_LAYOUT, strict=False)


def test_interval_coarser_than_the_data_is_rejected():
    """Interval 5 over every-minute directories skips four minutes in five, and
    the skipped rows are simply absent from results."""
    meta = A._table_metadata("d", table("i", SCOPED_PATH, interval="5"))
    assert "skips directories" in A._cross_check_declared(meta, MINUTE_LAYOUT, strict=False)


def test_interval_finer_than_the_data_is_accepted():
    """The opposite direction only costs planning time, so it is not refused."""
    meta = A._table_metadata("d", table("i", SCOPED_PATH, interval="1"))
    assert A._cross_check_declared(
        meta, _layout("yyyy/MM/dd/HH/mm", "minutes", 5), strict=False) is None


def test_interval_compares_value_and_unit_together():
    """Comparing the bare numbers makes 1 minute equal 1 hour, which is exactly
    the pair of layouts this check exists to tell apart."""
    meta = A._table_metadata("d", table("h", SCOPED_PATH, fmt="yyyy/MM/dd/HH",
                                       interval="1", unit="hours"))
    assert A._cross_check_declared(meta, MINUTE_LAYOUT, strict=True) is not None


def test_a_scratch_table_with_the_old_wide_range_is_rebuilt():
    """How the narrowed projection range reaches an install that already has a table.

    Every scratch table the agent built before that change declares
    `2020/01/01/00/00,NOW`. Format, interval and unit all still match the bucket, so
    without this the table passes the cross-check, gets reused, and keeps paying seconds
    of planning per query forever. Nothing else would ever rebuild it.
    """
    meta = A._table_metadata(A.TMP_DATABASE,
                            table("waf_logs_x", SCOPED_PATH, rng="2020/01/01/00/00,NOW"))
    layout = _layout("yyyy/MM/dd/HH/mm", "minutes", range_start="2026/03/01/00/00")
    problem = A._cross_check_declared(meta, layout, strict=True)
    assert problem is not None
    assert "2020-01-01" in problem and "2026-03-01" in problem
    assert "planning" in problem, "too-early is a cost, and the message should say so"


def test_a_scratch_table_projecting_later_than_the_data_says_so_differently():
    """The other direction is not a cost, it is unreachable data, so it reads
    differently even though both rebuild."""
    meta = A._table_metadata(A.TMP_DATABASE,
                             table("waf_logs_x", SCOPED_PATH, rng="2026/06/01/00/00,NOW"))
    problem = A._cross_check_declared(
        meta, _layout("yyyy/MM/dd/HH/mm", "minutes", range_start="2026/03/01/00/00"),
        strict=True)
    assert problem is not None and "cannot be returned at all" in problem


def test_a_user_table_with_a_wide_range_is_left_alone():
    """The asymmetry that keeps the check above safe. A range wider than the data is the
    user's choice on their own table, it costs only planning time, and rewriting someone
    else's table is not this code's business. `partition_predicate` already reports a
    window that falls outside a range."""
    meta = A._table_metadata("userdb", table("waf", SCOPED_PATH, rng="2020/01/01/00/00,NOW"))
    layout = _layout("yyyy/MM/dd/HH/mm", "minutes", range_start="2026/03/01/00/00")
    assert A._cross_check_declared(meta, layout, strict=False) is None


def test_a_matching_range_does_not_rebuild_on_every_resolve():
    """The value round-trips exactly, so a rebuilt table agrees with the next walk and
    the check settles. Without that this would drop and recreate the table forever."""
    meta = A._table_metadata(A.TMP_DATABASE,
                             table("waf_logs_x", SCOPED_PATH, rng="2026/03/01/00/00,NOW"))
    layout = _layout("yyyy/MM/dd/HH/mm", "minutes", range_start="2026/03/01/00/00")
    assert A._cross_check_declared(meta, layout, strict=True) is None


def test_unreadable_s3_layout_trusts_the_declaration():
    """No layout means an empty bucket or a prefix with no data yet, which is not
    evidence of a problem. The declaration is all there is, so it is trusted."""
    meta = A._table_metadata("d", table("m", SCOPED_PATH))
    assert A._cross_check_declared(meta, None, strict=False) is None


def test_mixed_layout_is_published_when_a_table_already_exists(catalog):
    """The state the user-facing warning reads has to be set on BOTH resolution paths.

    It was written only inside the table-creation branch, and every resolve that finds a
    table returns before reaching it. So `layout_mixed` stayed False for a returning
    session and for anyone querying a table they maintain themselves, which is exactly
    the population a mixed-bucket warning is for.
    """
    glue = catalog({"userdb": [table("waf", SCOPED_PATH)]}, layout=MIXED_LAYOUT)
    # The precondition: this must take the found-a-table path, not the create path,
    # or the assertions below pass for the wrong reason.
    assert A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl") == "userdb.waf"
    assert glue.deleted == []
    assert A._athena_state["layout_mixed"] is True
    assert A._athena_state["layout_cutover"] == "2026/01/05"
    assert A._athena_state["layout_data_start"] == "2022/03/07"


def test_the_resolution_block_names_the_history_a_mixed_bucket_hides(catalog):
    """`projection.<col>.format` holds one value, so the pre-cutover era is unreachable
    rather than merely coarse, and nothing else tells the user that.

    The single-layout control runs first: the line has to appear because the bucket is
    mixed, not because the block always says it.
    """
    catalog({"userdb": [table("waf", SCOPED_PATH)]}, layout=MINUTE_LAYOUT)
    A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    assert "minute-level era only" not in A.describe_table_resolution()

    catalog({"userdb": [table("waf", SCOPED_PATH)]}, layout=MIXED_LAYOUT)
    A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    block = A.describe_table_resolution()
    assert "minute-level era only" in block
    assert "2026/01/05" in block, "the cutover, so the user knows where the table starts"
    assert "2022/03/07" in block, "the oldest data, so they know how much is out of reach"


def test_the_self_heal_path_walks_s3_once(catalog, monkeypatch):
    """The scratch table is stale, so it is dropped and rebuilt. That used to walk the
    whole S3 tree twice: once for the cross-check that condemned it, once to build its
    replacement. One walk at the top of resolution serves both."""
    glue = catalog({A.TMP_DATABASE: [table("waf_logs_myacl", SCOPED_PATH,
                                           fmt="yyyy/MM/dd/HH", unit="hours")]},
                   layout=MIXED_LAYOUT)
    walks = []

    def counted(path):
        walks.append(path)
        return dict(MIXED_LAYOUT)

    monkeypatch.setattr(A, "_detect_partitions", counted)
    monkeypatch.setattr(A, "_create_named_table", lambda *a, **k: A._table_metadata(
        A.TMP_DATABASE, table("waf_logs_myacl", SCOPED_PATH)))

    A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    # The precondition: the stale table really was dropped, so this is the two-walk
    # path and not the ordinary create path.
    assert glue.deleted == [f"{A.TMP_DATABASE}.waf_logs_myacl"]
    assert len(walks) == 1


def test_an_empty_bucket_still_resolves_an_existing_table(catalog, monkeypatch):
    """The other half of the None contract, and the one that used to live inside
    `_cross_check_declared`'s try block.

    The walk now happens once at the top of resolution, so a path it finds nothing under
    has to fail soft there rather than abort the resolve. A user with a declared table
    over a prefix that has not received data yet must still get their table.

    Named for the empty case rather than "unreadable", which is what it said before and
    is now the *other* branch: an empty listing and a missing bucket are no longer the
    same outcome, and this is the one that stays soft.

    The stub raises `PartitionsNotFound` and not a bare `RuntimeError`, which is the whole
    point of the named type: the base class no longer buys the soft path, and this test
    failed when the type was introduced until the stub was made specific.
    """
    glue = catalog({"userdb": [table("waf", SCOPED_PATH)]})

    def boom(_):
        raise A.PartitionsNotFound("Cannot detect partition structure")

    monkeypatch.setattr(A, "_detect_partitions", boom)
    assert A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl") == "userdb.waf"
    assert glue.deleted == []


def test_a_deleted_bucket_does_not_resolve_a_table_over_it(catalog, monkeypatch):
    """A silent-success path, found by enumerating the account's own catalog rather than
    by reading code: `waf_log_db.waf_logs` points at a bucket that no longer exists.

    `_find_existing_table` reads Glue only, so it finds the table with S3 gone.
    `_cross_check_declared` is handed `layout=None` and trusts the declaration by design.
    The trust is right for an empty prefix and wrong here, and `except Exception` was what
    made the two indistinguishable. Reproduced on the real account before this test
    existed: resolution returned `waf_log_db.waf_logs` with no error and published
    `layout_data_start=None`, then every query failed with `HIVE_FILESYSTEM_ERROR`.

    So the user-visible symptom was a loud failure per query rather than the silent zero
    rows first supposed, which lowers the severity and does not change the fix: the error
    arrives once per query at the engine layer, naming a bucket, when resolution could
    raise once and name the logging destination.
    """
    glue = catalog({"userdb": [table("waf", SCOPED_PATH)]})

    class NoSuchBucket(Exception):
        """Stands in for botocore's; the point is only that it is not a RuntimeError."""

    def gone(_):
        raise NoSuchBucket("The specified bucket does not exist")

    monkeypatch.setattr(A, "_detect_partitions", gone)
    with pytest.raises(RuntimeError) as e:
        A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    msg = str(e.value)
    assert SCOPED_PATH in msg, "the path is the actionable part"
    assert "NoSuchBucket" in msg, "the S3 error has to survive, not be paraphrased"
    assert "NOT an absence of traffic" in msg
    assert glue.deleted == [], "a user's table is never dropped over an S3 failure"


def test_a_listing_failure_is_not_converted_into_an_empty_listing(monkeypatch):
    """What the fix rests on, asserted so it cannot quietly stop being true.

    The resolver discriminates on `PartitionsNotFound`, raised only once the walk has
    completed and found nothing. Anything else means the walk itself failed. Both halves
    measured on the real account, where a deleted bucket raised `NoSuchBucket` from
    `list_objects_v2` and an existing-but-empty prefix returned `[]`.

    Two assertions, because the first alone claimed more than it proved. Stubbing the lister
    shows `_detect_partitions` propagates rather than swallows, which is what the resolver
    needs. It says nothing about the real lister, and the way this regresses is someone
    adding a `try` there that returns `[]` on error: the two outcomes collapse back
    together, resolution resumes trusting a dead declaration, and a test that stubbed the
    lister out would not notice.

    **The source check reads the file, not the attribute.** `inspect.getsource` resolves
    whatever is bound to `A._s3_list_dirs` at the time, so with a monkeypatch in scope it
    read the stub, found no `try`, and passed while the real lister swallowed everything.
    Ordering it before the patch fixed that instance and left the test order-dependent by
    construction. Parsing the file cannot be fooled by a patch at all, which is how the
    three structural tests in `test_query_timeout.py` are written, and this is the second
    time this exact ordering error has shipped here.
    """
    import ast
    import pathlib
    src = pathlib.Path(A.__file__).read_text()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "_s3_list_dirs")
    assert not [n for n in ast.walk(fn) if isinstance(n, (ast.Try, ast.ExceptHandler))], \
        "_s3_list_dirs must let S3 errors out; catching one makes a dead bucket look empty"

    def raises(bucket, prefix):
        raise LookupError("NoSuchBucket")

    monkeypatch.setattr(A, "_s3_list_dirs", raises)
    # Not PartitionsNotFound: that is the value reserved for "walked it, found nothing".
    with pytest.raises(LookupError):
        A._detect_partitions("s3://bkt")


def test_a_plain_runtimeerror_from_the_walk_is_not_read_as_an_empty_bucket(catalog, monkeypatch):
    """Why the condition is a named type rather than `except RuntimeError`.

    `except RuntimeError` was correct on the day it was written, because the only deliberate
    raise in the walk was the not-found one. It inferred the signal from a generic type
    instead of stating it, so the next `raise RuntimeError` added anywhere in that call
    graph, for a depth limit or a malformed storage template, would be reclassified as
    "walked it, found nothing" and quietly restore trust-the-declaration over a path that is
    not empty. Same collision as a heartbeat sentinel sharing `None` with end-of-stream.

    Without this test the named type is a rename that nothing depends on.
    """
    glue = catalog({"userdb": [table("waf", SCOPED_PATH)]})

    def some_other_bug(_):
        raise RuntimeError("walk exceeded its depth limit")

    monkeypatch.setattr(A, "_detect_partitions", some_other_bug)
    with pytest.raises(RuntimeError) as e:
        A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    assert "Cannot read the S3 log path" in str(e.value), \
        "a RuntimeError that is not PartitionsNotFound must not buy the soft path"
    assert glue.deleted == []


# --- WebACL scoping ---------------------------------------------------------


def test_shared_location_disables_webacl_scoping(catalog):
    """Scored on the RESOLVED table's location, never the requested path. The
    requested path contains the WebACL name here while the table above it does
    not, and that is the case where the old code claimed scoping it lacked."""
    catalog({"userdb": [table("shared", SHARED_PATH)]})
    A._record_table(A._find_existing_table(SCOPED_PATH, "us-east-1"))
    assert A._athena_state["webacl_scoped"] is False


def test_webacl_specific_location_keeps_scoping(catalog):
    catalog({"userdb": [table("own", SCOPED_PATH)]})
    A._record_table(A._find_existing_table(SCOPED_PATH, "us-east-1"))
    assert A._athena_state["webacl_scoped"] is True


# --- pruning predicate ------------------------------------------------------


def _resolve(catalog, tbl):
    catalog({"userdb": [tbl]})
    A._record_table(A._find_existing_table(SCOPED_PATH, "us-east-1"))


def test_predicate_renders_with_the_declared_format(catalog):
    """The predicate compares partition-column values, and those come from the
    projection, so the DECLARED format is the only correct thing to render with.
    Bounds are one hour out on each side because this table's interval is 1 hour."""
    _resolve(catalog, table("dh", SCOPED_PATH, col="datehour", fmt="yyyy-MM-dd-HH",
                            unit="hours", rng="2026-01-01-00,NOW"))
    clause, problem = A.partition_predicate(
        dt.datetime(2026, 9, 7, 3, tzinfo=dt.timezone.utc),
        dt.datetime(2026, 9, 7, 5, tzinfo=dt.timezone.utc))
    assert clause == "AND datehour >= '2026-09-07-02' AND datehour <= '2026-09-07-06'"
    assert problem is None


def test_predicate_uses_the_partition_path_timezone_not_utc(catalog):
    """Firehose evaluates its prefix in CustomTimeZone, so UTC bounds would look
    in the wrong hour's directory and prune real rows away."""
    _resolve(catalog, table("t", SCOPED_PATH))
    window = (dt.datetime(2026, 9, 7, 3, 5, tzinfo=dt.timezone.utc),
              dt.datetime(2026, 9, 7, 3, 40, tzinfo=dt.timezone.utc))
    assert "2026/09/07/03/04" in A.partition_predicate(*window)[0]
    A._athena_state["partition_tz"] = "America/New_York"
    assert "2026/09/06/23/04" in A.partition_predicate(*window)[0]


def test_env_var_overrides_the_detected_partition_timezone(catalog, monkeypatch):
    _resolve(catalog, table("t", SCOPED_PATH))
    A._athena_state["partition_tz"] = "America/New_York"
    monkeypatch.setenv("WAF_AGENT_PARTITION_TZ", "Asia/Tokyo")
    assert "2026/09/07/12/04" in A.partition_predicate(
        dt.datetime(2026, 9, 7, 3, 5, tzinfo=dt.timezone.utc),
        dt.datetime(2026, 9, 7, 3, 40, tzinfo=dt.timezone.utc))[0]


# --- widening the bounds by one interval ------------------------------------


def test_bounds_are_widened_by_one_interval_on_each_side(catalog):
    """A partition directory's name is the arrival time of the record that opened
    the Firehose buffer, and one object holds a whole buffer window, so the minute
    in the path bounds the timestamps inside it in neither direction. Using the
    window's own bounds lost 5.70% and 8.12% of rows on two measured 5-minute
    windows. `"timestamp" BETWEEN` stays exact, so this cannot pull in rows from
    outside the window; it only stops excluding rows inside it."""
    _resolve(catalog, table("t", SCOPED_PATH))
    clause, _ = A.partition_predicate(
        dt.datetime(2026, 9, 7, 14, 10, tzinfo=dt.timezone.utc),
        dt.datetime(2026, 9, 7, 14, 15, tzinfo=dt.timezone.utc))
    assert clause == ("AND log_time >= '2026/09/07/14/09' "
                      "AND log_time <= '2026/09/07/14/16'")


def test_widening_uses_the_declared_interval_not_a_fixed_minute(catalog):
    """Expressed in the projection's own units, because a user's table may declare
    any interval. Five minutes each side here, not one."""
    _resolve(catalog, table("t", SCOPED_PATH, interval="5"))
    clause, _ = A.partition_predicate(
        dt.datetime(2026, 9, 7, 14, 10, tzinfo=dt.timezone.utc),
        dt.datetime(2026, 9, 7, 14, 15, tzinfo=dt.timezone.utc))
    assert clause == ("AND log_time >= '2026/09/07/14/05' "
                      "AND log_time <= '2026/09/07/14/20'")


def test_widening_crosses_hour_and_day_boundaries(catalog):
    """The arithmetic is on a datetime, not on the rendered string, so midnight is
    not a special case."""
    _resolve(catalog, table("t", SCOPED_PATH))
    clause, _ = A.partition_predicate(
        dt.datetime(2026, 9, 7, 0, 0, tzinfo=dt.timezone.utc),
        dt.datetime(2026, 9, 7, 23, 59, tzinfo=dt.timezone.utc))
    assert clause == ("AND log_time >= '2026/09/06/23/59' "
                      "AND log_time <= '2026/09/08/00/00'")


def test_widening_is_clamped_to_the_projected_range(catalog):
    """Widening past the projection's first partition would render a bound that
    matches nothing, and there is no data out there to reach anyway."""
    _resolve(catalog, table("t", SCOPED_PATH, rng="2026/09/07/00/00,NOW"))
    clause, problem = A.partition_predicate(
        dt.datetime(2026, 9, 7, 0, 0, tzinfo=dt.timezone.utc),
        dt.datetime(2026, 9, 7, 1, 0, tzinfo=dt.timezone.utc))
    assert clause.startswith("AND log_time >= '2026/09/07/00/00'")
    assert problem is None


def test_range_check_uses_the_unwidened_window(catalog):
    """A query starting exactly at the projection's first partition is legitimate.
    Checking the widened bound instead would report it as out of range."""
    _resolve(catalog, table("t", SCOPED_PATH, rng="2026/09/07/00/00,NOW"))
    _, problem = A.partition_predicate(
        dt.datetime(2026, 9, 7, 0, 0, tzinfo=dt.timezone.utc),
        dt.datetime(2026, 9, 7, 1, 0, tzinfo=dt.timezone.utc))
    assert problem is None


def test_window_before_the_projected_range_is_reported(catalog):
    """Athena returns zero rows for a window outside the projection, which
    otherwise reads as "no traffic" rather than as a table limitation.

    On a single-layout bucket widening the range is the correct advice, which is what
    makes it the control for the mixed-bucket case below."""
    _resolve(catalog, table("t", SCOPED_PATH, rng="2026/01/01/00/00,NOW"))
    _, problem = A.partition_predicate(
        dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc),
        dt.datetime(2025, 6, 2, tzinfo=dt.timezone.utc))
    assert problem is not None and "before" in problem
    assert "Widen the table's projection" in problem


def test_mixed_bucket_is_not_told_to_widen_the_range(catalog):
    """Widening is the obvious advice and on a mixed bucket it cannot work.

    The pre-cutover directories are hourly, so a minute-level projection stretched back
    over them generates paths that do not exist and still returns nothing. Following
    the advice therefore looks like confirmation that the data is gone.
    """
    _resolve(catalog, table("t", SCOPED_PATH, rng="2026/01/01/00/00,NOW"))
    A._athena_state.update({"layout_mixed": True, "layout_cutover": "2026/01/05",
                            "layout_data_start": "2022/03/07"})
    _, problem = A.partition_predicate(
        dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc),
        dt.datetime(2025, 6, 2, tzinfo=dt.timezone.utc))
    # The precondition: this window IS out of range, so the branch under test ran.
    assert problem is not None
    assert "2026/01/05" in problem
    assert "Widen the table's projection" not in problem


def test_unsupported_interval_unit_is_rejected(catalog):
    """Athena also allows weeks, months and years. Widening needs a unit with a
    fixed wall-clock length, and nothing that partitions WAF logs by month is
    usable here regardless."""
    catalog({"userdb": [table("m", SHARED_PATH, fmt="yyyy/MM/dd", unit="months")]})
    assert A._find_existing_table(SCOPED_PATH, "us-east-1") is None
    assert "interval unit 'months'" in " ".join(A._athena_state["discovery_notes"])


def test_no_resolved_table_yields_no_predicate(catalog):
    catalog({})
    now = dt.datetime.now(dt.timezone.utc)
    assert A.partition_predicate(now, now) == ("", None)


# --- caching and state ------------------------------------------------------


def test_resolution_is_cached_so_patrol_stops_re_walking_glue(catalog):
    """Patrol held no cache and re-resolved on every scan. reset_table_cache()
    fires on every WebACL switch, so there is no stale-table window."""
    glue = catalog({"userdb": [table("c", SCOPED_PATH)]})
    first = A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    after_first = glue.get_tables_calls
    second = A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    assert first == second
    assert after_first > 0 and glue.get_tables_calls == after_first


def test_reset_restores_every_state_key(catalog):
    """A key added to the state dict but forgotten in the reset would survive a
    WebACL switch and query the previous WebACL's table."""
    _resolve(catalog, table("t", SCOPED_PATH))
    A.reset_table_cache()
    assert A._athena_state == A._ATHENA_STATE_DEFAULTS
    assert A._athena_state["table"] is None


def test_resolution_is_reported_for_tool_output(catalog):
    """The chosen table and any rejection both have to reach the user."""
    catalog({"userdb": [table("good", SHARED_PATH), table("bad", SHARED_PATH, keys=[])]})
    A._record_table(A._find_existing_table(SCOPED_PATH, "us-east-1"))
    report = A.describe_table_resolution()
    assert "userdb.good" in report
    assert "userdb.bad" in report and "not partitioned" in report


# --- one cache, one lock ---------------------------------------------------


def test_query_layer_keeps_no_table_cache_of_its_own(catalog):
    """`waf_query` used to hold `_athena_table`, a second copy of the same value.

    Two caches meant the two query paths could disagree about which table was
    current, and only one of them was reset by anything. The check is structural
    because a behavioural one cannot see a duplicate that happens to agree.
    """
    from tools import waf_query

    assert not hasattr(waf_query, "_athena_table")
    assert not hasattr(waf_query, "_table_setup_lock")


def test_reset_clears_the_cache_through_the_query_layer_delegate(catalog):
    """`session_state.set_webacl_context` resets through `waf_query`, so that entry
    point has to reach the one real cache in `waf_athena`."""
    from tools import waf_query

    catalog({"userdb": [table("t", SCOPED_PATH)]})
    A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl")
    assert A._athena_state["table"] is not None

    waf_query.reset_table_cache()
    assert A._athena_state["table"] is None


def test_concurrent_resolves_enumerate_glue_once(catalog):
    """Both query paths now share the resolver's lock. `query_logs` used to hold an
    equivalent lock of its own while `patrol_scan` held none, so patrol paid a full
    Glue enumeration per concurrent scan. Ten threads must produce one enumeration.
    """
    import threading

    glue = catalog({"userdb": [table("c", SCOPED_PATH)]})
    results, errors = [], []

    def resolve():
        try:
            results.append(A.resolve_log_table(SCOPED_PATH, "us-east-1", "myacl"))
        except Exception as exc:  # pragma: no cover - a failure here is the finding
            errors.append(exc)

    threads = [threading.Thread(target=resolve) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(set(results)) == 1
    assert glue.get_tables_calls == 1


# --- control-plane calls before resolution ---------------------------------
#
# firehose:DescribeDeliveryStream is capped at 5 requests per second, per account
# per Region, and is not adjustable. So the number of times these paths call it is
# a correctness property, not a performance nicety, and it needs a test that counts.


class CallCounter:
    """Counts the pre-resolution AWS calls, so a lost cache read is visible."""

    def __init__(self, monkeypatch, dest="arn:aws:firehose:us-east-1:1:deliverystream/aws-waf-logs-x",
                 call_delay=0.0, s3_direct_path=None):
        self.dest = dest
        self.describe = 0
        self.sts = 0
        self.list_objects = 0
        self.s3_direct_path = s3_direct_path

        def resolve(log_dest):
            if ":firehose:" in log_dest:
                self.describe += 1
            if call_delay:
                import time
                time.sleep(call_delay)
            return "s3://bkt"

        def account():
            self.sts += 1
            return "1"

        def standard(bucket, account, scope, webacl_name, region):
            self.list_objects += 1
            if self.s3_direct_path:
                # Mirror the real shape: the answer embeds the WebACL name, which is
                # why the memo cannot be keyed on the destination alone.
                return f"s3://{bucket}/AWSLogs/{account}/WAFLogs/cloudfront/{webacl_name}/"
            return None

        monkeypatch.setattr(A, "_resolve_s3_path", resolve)
        monkeypatch.setattr(A, "_get_account_id", account)
        monkeypatch.setattr(A, "_try_standard_path", standard)

    @property
    def total(self):
        return self.describe + self.sts + self.list_objects


def test_warm_session_makes_no_call_before_resolution(catalog, monkeypatch):
    """A resolved session must not touch the control plane again.

    This regressed once: the early cache read was dropped from the query path, so
    every query re-ran the destination translation and paid a describe before the
    resolver's own cache check was reached.
    """
    from tools import waf_query

    catalog({"userdb": [table("t", "s3://bkt")]})
    counter = CallCounter(monkeypatch)
    waf_query._ensure_athena_table(counter.dest)
    assert counter.total >= 1, "cold resolve should have called something"

    # Count entries into the translation, not AWS calls. The translation is itself
    # memoized, so counting calls would pass even with the early return removed and
    # the test would prove nothing. What this asserts is that a warm query does not
    # reach the translation at all.
    entries = []
    real = A.resolve_s3_log_path
    monkeypatch.setattr(A, "resolve_s3_log_path",
                        lambda *a, **k: entries.append(a[0]) or real(*a, **k))
    for _ in range(5):
        waf_query._ensure_athena_table(counter.dest)
    assert entries == [], "a warm session must return from the cache before translating"
    assert counter.total >= 1


def test_translation_is_memoized_across_both_query_paths(catalog, monkeypatch):
    """query_logs and patrol_scan share one translation, so the second caller pays
    nothing. Each used to do it inline, which on Firehose was a describe per scan."""
    catalog({})
    counter = CallCounter(monkeypatch)
    first = A.resolve_s3_log_path(counter.dest, "CLOUDFRONT", "myacl", "us-east-1")
    assert counter.describe == 1
    second = A.resolve_s3_log_path(counter.dest, "CLOUDFRONT", "myacl", "us-east-1")
    assert second == first
    assert counter.describe == 1


def test_same_destination_two_webacls_get_different_paths(catalog, monkeypatch):
    """The hazard is a switch that keeps the destination and changes the answer.

    On the S3-direct branch the resolved path embeds the WebACL name, and several
    WebACLs sharing one log bucket is ordinary. A memo keyed on the destination alone
    would hand the second WebACL the first one's path. An earlier version of this test
    asserted the *safe* case instead, that a different destination re-translates, which
    is true by construction because a different destination is a different key.
    """
    catalog({})
    dest = "arn:aws:s3:::aws-waf-logs-shared"
    counter = CallCounter(monkeypatch, dest=dest, s3_direct_path=True)

    first = A.resolve_s3_log_path(dest, "CLOUDFRONT", "acl-one", "us-east-1")
    second = A.resolve_s3_log_path(dest, "CLOUDFRONT", "acl-two", "us-east-1")

    assert first.endswith("/acl-one/")
    assert second.endswith("/acl-two/")
    assert first != second


def test_translation_memo_is_cleared_on_reset(catalog, monkeypatch):
    """Reset is redundancy rather than a requirement once the key is complete, but it
    still has to drop the memo, because it is the only thing that clears stale AWS
    answers if a destination is reconfigured under the same name."""
    catalog({})
    counter = CallCounter(monkeypatch)
    A.resolve_s3_log_path(counter.dest, "CLOUDFRONT", "myacl", "us-east-1")
    A.reset_table_cache()
    A.resolve_s3_log_path(counter.dest, "CLOUDFRONT", "myacl", "us-east-1")
    assert counter.describe == 2


def test_concurrent_cold_start_translates_once(catalog, monkeypatch):
    """Ten threads on a cold cache must produce exactly one describe.

    **The stand-in has to be slow.** An instant fake closes the race window on its
    own, so an unsynchronised memo passes and the test proves nothing; a first version
    of this test did exactly that, and paired it with a `<= 2` tolerance that made a
    timing-dependent pass look deliberate. Measured against the real function with a
    100 ms stand-in: ten describes without the lock, one with it. A control-plane call
    is slower than 100 ms in practice, so this is the conservative direction.
    """
    import threading
    import time

    catalog({"userdb": [table("t", "s3://bkt")]})
    counter = CallCounter(monkeypatch, call_delay=0.1)
    errors = []

    def go():
        try:
            A.resolve_s3_log_path(counter.dest, "CLOUDFRONT", "myacl", "us-east-1")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=go) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert counter.describe == 1, f"expected one describe, got {counter.describe}"


def test_output_location_is_resolved_once_per_session(catalog, monkeypatch):
    """Both Athena executors call this per statement, and on a workgroup with no
    output location the fallback reaches DescribeDeliveryStream."""
    catalog({})
    calls = []
    monkeypatch.setattr(A, "_resolve_output_location",
                        lambda region, workgroup: calls.append((region, workgroup)) or "s3://out/")
    for _ in range(6):
        assert A._get_output_location("us-east-1") == "s3://out/"
    assert len(calls) == 1
    A.reset_table_cache()
    A._get_output_location("us-east-1")
    assert len(calls) == 2


def test_concurrent_output_location_resolves_once(catalog, monkeypatch):
    """The hotter of the two memos, and it had the same unsynchronised race.

    Both Athena executors call this once per *statement*, not once per query, and on a
    workgroup with no output location the fallback reaches the same
    DescribeDeliveryStream under the same 5-per-second non-adjustable ceiling. A patrol
    scan runs several statements, so an unlocked memo multiplies. The single-threaded
    test above cannot see this; only a slow stand-in can.
    """
    import threading
    import time

    catalog({})
    calls = []

    def slow(region, workgroup):
        calls.append((region, workgroup))
        time.sleep(0.1)
        return "s3://out/"

    monkeypatch.setattr(A, "_resolve_output_location", slow)
    threads = [threading.Thread(target=lambda: A._get_output_location("us-east-1")) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 1, f"expected one lookup, got {len(calls)}"
