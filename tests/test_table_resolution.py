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
MINUTE_LAYOUT = ("tmpl", "yyyy/MM/dd/HH/mm", "minutes", 1)
HOURLY_LAYOUT = ("tmpl", "yyyy/MM/dd/HH", "hours", 1)


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
        monkeypatch.setattr(A, "_detect_partitions", lambda path: layout)
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


def test_declaring_coarser_than_the_data_is_accepted(catalog):
    """An hourly table over minute-nested S3 works: the location template
    resolves to the hour directory and Athena scans recursively beneath it."""
    catalog({}, layout=MINUTE_LAYOUT)
    meta = A._table_metadata("d", table("h", SCOPED_PATH, fmt="yyyy/MM/dd/HH", unit="hours"))
    assert A._cross_check_declared(meta, SCOPED_PATH, strict=False) is None


def test_declaring_finer_than_the_data_is_rejected(catalog):
    """A minute-level table over hourly directories projects `.../12/16` under a
    bucket that only has `.../12`. Athena reports the miss as zero rows."""
    catalog({}, layout=HOURLY_LAYOUT)
    meta = A._table_metadata("d", table("m", SCOPED_PATH))
    assert "finer than" in A._cross_check_declared(meta, SCOPED_PATH, strict=False)


def test_interval_coarser_than_the_data_is_rejected(catalog):
    """Interval 5 over every-minute directories skips four minutes in five, and
    the skipped rows are simply absent from results."""
    catalog({}, layout=MINUTE_LAYOUT)
    meta = A._table_metadata("d", table("i", SCOPED_PATH, interval="5"))
    assert "skips directories" in A._cross_check_declared(meta, SCOPED_PATH, strict=False)


def test_interval_finer_than_the_data_is_accepted(catalog):
    """The opposite direction only costs planning time, so it is not refused."""
    catalog({}, layout=("tmpl", "yyyy/MM/dd/HH/mm", "minutes", 5))
    meta = A._table_metadata("d", table("i", SCOPED_PATH, interval="1"))
    assert A._cross_check_declared(meta, SCOPED_PATH, strict=False) is None


def test_interval_compares_value_and_unit_together(catalog):
    """Comparing the bare numbers makes 1 minute equal 1 hour, which is exactly
    the pair of layouts this check exists to tell apart."""
    catalog({}, layout=MINUTE_LAYOUT)
    meta = A._table_metadata("d", table("h", SCOPED_PATH, fmt="yyyy/MM/dd/HH",
                                       interval="1", unit="hours"))
    assert A._cross_check_declared(meta, SCOPED_PATH, strict=True) is not None


def test_unreadable_s3_layout_trusts_the_declaration(catalog):
    """An empty bucket or a prefix with no data yet is not evidence of a problem."""
    catalog({}, layout=MINUTE_LAYOUT)
    meta = A._table_metadata("d", table("m", SCOPED_PATH))

    def boom(_):
        raise RuntimeError("Cannot detect partition structure")

    A._detect_partitions = boom
    assert A._cross_check_declared(meta, SCOPED_PATH, strict=False) is None


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
    otherwise reads as "no traffic" rather than as a table limitation."""
    _resolve(catalog, table("t", SCOPED_PATH, rng="2026/01/01/00/00,NOW"))
    _, problem = A.partition_predicate(
        dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc),
        dt.datetime(2025, 6, 2, tzinfo=dt.timezone.utc))
    assert problem is not None and "before" in problem


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
