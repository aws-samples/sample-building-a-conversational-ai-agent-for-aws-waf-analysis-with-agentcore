# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`_detect_partitions`, against a fake S3 directory tree.

This is the function that decides whether a log bucket is hourly or minute-level,
and everything downstream trusts it: the coarse-partition gate, the DDL the agent
generates, and the declared-vs-actual cross-check in table resolution. It gets
its answer by walking a few directory levels, so a fake tree covers it honestly.

The case that matters most is a bucket that changed prefix layout partway
through, because every user who follows the minute-partitioning guide has one:
old hourly paths under earlier months, minute paths under recent ones.
"""

import pytest

from tools import waf_athena as A


@pytest.fixture
def s3_tree(monkeypatch):
    """Install a fake S3 listing built from directory paths under the bucket root."""
    def install(*paths):
        def list_dirs(bucket, prefix):
            children = set()
            for path in paths:
                if not path.startswith(prefix):
                    continue
                rest = path[len(prefix):].strip("/")
                if rest:
                    children.add(rest.split("/")[0])
            return sorted(children)

        monkeypatch.setattr(A, "_s3_list_dirs", list_dirs)

    return install


HOURLY_ERA = "2026/06/15/10"
MINUTE_ERA = "2026/09/07/14/03"


def test_mixed_layout_bucket_detects_as_minute_level(s3_tree):
    """The headline bug. Walking into the EARLIEST child landed in pre-cutover
    hourly data, counted four levels, and pinned the table to hourly forever, no
    matter how much minute-partitioned data arrived afterwards."""
    s3_tree(HOURLY_ERA, MINUTE_ERA)
    L = A._detect_partitions("s3://bkt")
    fmt, unit, interval = L["format"], L["unit"], L["interval"]
    assert (fmt, unit, interval) == ("yyyy/MM/dd/HH/mm", "minutes", 1)


def test_pure_hourly_bucket_still_detects_as_hourly(s3_tree):
    s3_tree("2026/06/15/10", "2026/09/07/14")
    L = A._detect_partitions("s3://bkt")
    fmt, unit, interval = L["format"], L["unit"], L["interval"]
    assert (fmt, unit, interval) == ("yyyy/MM/dd/HH", "hours", 1)


def test_pure_minute_bucket_detects_as_minute_level(s3_tree):
    s3_tree("2026/09/07/14/03")
    L = A._detect_partitions("s3://bkt")
    fmt, unit, interval = L["format"], L["unit"], L["interval"]
    assert (fmt, unit, interval) == ("yyyy/MM/dd/HH/mm", "minutes", 1)


def test_interval_is_always_one_never_inferred_from_directory_names(s3_tree):
    """Firehose's !{timestamp:mm} emits whatever minute the buffer flushed at, so
    these names are arbitrary. Subtracting two of them used to give interval 4
    here, and partition projection would then generate 03, 07, 11 ... and never
    read the objects under any other minute. Missing rows, no error."""
    s3_tree("2026/09/07/14/03", "2026/09/07/14/07", "2026/09/07/14/41")
    assert A._detect_partitions("s3://bkt")["interval"] == 1


def test_newest_child_is_taken_at_every_level(s3_tree):
    """Not just the newest year. A cutover mid-month or mid-day has to be found
    too, so the choice repeats at month, day and hour."""
    s3_tree("2026/09/01/10", "2026/09/28/23/59", "2025/12/31/23/59")
    assert A._detect_partitions("s3://bkt")["format"] == "yyyy/MM/dd/HH/mm"


def test_two_digit_levels_sort_numerically(s3_tree):
    """Zero padding is what makes a lexicographic max the numeric max. If it were
    not padded, "9" would beat "28" and the walk would pick the wrong month."""
    s3_tree("2026/02/03/04", "2026/10/09/08/07")
    assert A._detect_partitions("s3://bkt")["format"] == "yyyy/MM/dd/HH/mm"


def test_stray_non_numeric_directory_is_ignored(s3_tree):
    """Letters sort after digits, so taking the newest child would otherwise pick
    a stray directory like this and abandon the walk one level in."""
    s3_tree("2026/09/07/14/03", "2026/backfill")
    fmt = A._detect_partitions("s3://bkt")["format"]
    assert fmt == "yyyy/MM/dd/HH/mm"


def test_storage_template_points_at_the_partition_root(s3_tree):
    s3_tree("logs/2026/09/07/14/03")
    template = A._detect_partitions("s3://bkt/logs")["storage_template"]
    assert template == "s3://bkt/logs/${log_time}"


def test_vended_log_prefix_is_walked_through(s3_tree):
    """AWS vended logs bury the dates under AWSLogs/<account>/WAFLogs/..., and the
    walk has to descend to wherever the years actually start."""
    s3_tree("AWSLogs/1234/WAFLogs/us-east-1/myacl/2026/09/07/14/03")
    L = A._detect_partitions("s3://bkt")
    template, fmt, interval = L["storage_template"], L["format"], L["interval"]
    assert fmt == "yyyy/MM/dd/HH/mm" and interval == 1
    assert template.endswith("/myacl/${log_time}")


def test_no_dates_anywhere_raises(s3_tree):
    """Better loud than a made-up layout: a wrong format here silently prunes
    every query down to nothing."""
    s3_tree("notalogbucket/whatever")
    with pytest.raises(RuntimeError, match="Cannot detect partition structure"):
        A._detect_partitions("s3://bkt")


def test_detection_now_agrees_with_a_correctly_declared_minute_table(s3_tree):
    """Why 1.1 had to ship inside this merge rather than after it. Table
    resolution cross-checks a table's declared partitioning against the real S3
    layout, and while the detector reported a mixed bucket as hourly, a correctly
    declared minute-level table read as finer than reality and was refused."""
    s3_tree(HOURLY_ERA, MINUTE_ERA)
    declared = {
        "table": "userdb.waf", "location": "s3://bkt", "partition_col": "log_time",
        "partition_format": "yyyy/MM/dd/HH/mm", "partition_granularity": "minutes",
        "partition_interval": 1, "partition_interval_unit": "minutes",
        "partition_range_start": None, "partition_range_end": None,
    }
    assert A._cross_check_declared(declared, "s3://bkt", strict=False) is None


# --- where the current layout begins ----------------------------------------
#
# One value feeds three consumers: the projection `range_start`, the mixed-layout
# report, and the cutover date shown to the user. Its two halves have different
# guarantees on purpose, and the tests below hold them to different standards.


def test_range_start_follows_the_data_not_a_hardcoded_year(s3_tree):
    """It used to be `2020/01/01/00/00` regardless, which is about 3.46 million
    projected minutes. Athena expands the declared range before applying `WHERE`, so
    that cost seconds of planning per query while scanning identical bytes."""
    s3_tree("2026/09/07/14/03")
    layout = A._detect_partitions("s3://bkt")
    assert layout["range_start"] == "2026/09/07/00/00"
    assert "2020" not in layout["range_start"]


def test_range_start_on_an_hourly_bucket_uses_the_hourly_shape(s3_tree):
    s3_tree("2026/06/15/10", "2026/09/07/14")
    layout = A._detect_partitions("s3://bkt")
    assert layout["range_start"] == "2026/06/15/00"
    assert layout["format"] == "yyyy/MM/dd/HH"


def test_mixed_bucket_is_reported_as_mixed_with_a_cutover_day(s3_tree):
    """Both eras present. The layout to declare is the newest one, and the cutover is
    reported so the user learns where the minute era starts rather than discovering it
    as an unexplained empty result."""
    s3_tree("2026/03/10/08", "2026/03/11/09", "2026/03/20/14/03", "2026/03/28/09/41")
    layout = A._detect_partitions("s3://bkt")
    assert layout["mixed"] is True
    assert layout["format"] == "yyyy/MM/dd/HH/mm"
    assert layout["cutover"] == "2026/03/20"


def test_pure_layouts_are_not_reported_as_mixed(s3_tree):
    s3_tree("2026/09/07/14/03")
    assert A._detect_partitions("s3://bkt")["mixed"] is False
    s3_tree("2026/09/07/14")
    assert A._detect_partitions("s3://bkt")["mixed"] is False


def test_range_start_is_floored_to_the_month_the_change_falls_in(s3_tree):
    """The correctness-critical half. Too early only projects extra partitions; too
    late makes real data unqueryable with no error. So it floors to the first of the
    month found by a linear scan, rather than trusting the binary-searched day."""
    s3_tree("2026/01/05/03", "2026/02/10/08", "2026/05/20/14/03", "2026/09/01/00/00")
    layout = A._detect_partitions("s3://bkt")
    assert layout["range_start"] == "2026/05/01/00/00"
    assert layout["cutover"] == "2026/05/20"


def test_cutover_across_a_year_boundary(s3_tree):
    """The year scan is linear too, so a change at a year boundary is found exactly.
    This is the shape the account's own bucket has, which is why that bucket could
    never fail the earlier detection test."""
    s3_tree("2024/05/25/08", "2026/05/31/00/00", "2026/09/08/14/03")
    layout = A._detect_partitions("s3://bkt")
    assert layout["mixed"] is True
    assert layout["range_start"] == "2026/05/01/00/00"


def test_non_monotone_layout_keeps_range_start_safe(s3_tree):
    """A bucket that alternates breaks a binary search's assumption, which is why the
    month scan is linear and only the reported day is binary-searched.

    **Three fixtures failed to discriminate before this one, and each failed
    differently.** Alternating inside a single month proves nothing, because a binary
    month scan and a linear one then pick the same month. Alternating across months with
    eras minute, hourly, minute is not enough either, because a binary search happens to
    land on the right answer. And a fixture whose *earliest* date is already minute-level
    never reaches this branch at all: the oldest and newest descents agree, `mixed` is
    False, and the month scan does not run, so swapping linear for binary changes
    nothing.

    What is needed is all three at once: the earliest month hourly so the layout reads
    as mixed, the earliest *minute* month before the midpoint, and the midpoint hourly.
    Then the midpoint probe reads hourly, the search moves rightward past the month it
    needed, and answers 07 instead of 02. That is five months of minute-level data made
    unqueryable with no error.
    """
    s3_tree("2026/01/05/03",       # hourly, and the earliest, so the layout is mixed
            "2026/02/11/08/17",    # minute: the answer a linear scan finds
            "2026/03/09/11",       # hourly
            "2026/04/09/11",       # hourly
            "2026/05/09/11",       # hourly: the month a binary search probes first
            "2026/06/09/11",       # hourly
            "2026/07/25/13/22")    # minute: the answer a binary search would give
    layout = A._detect_partitions("s3://bkt")
    assert layout["mixed"] is True
    assert layout["range_start"] == "2026/02/01/00/00", (
        "must floor to the earliest minute-level month; a binary month scan answers 07")
    assert layout["cutover"] == "2026/02/11"


def test_range_start_is_never_later_than_the_earliest_minute_data(s3_tree):
    """The invariant behind all of the above, stated on its own.

    Too early only projects extra partitions, which costs planning time. Too late makes
    real data unqueryable and reports it as zero rows. So the only thing that must never
    happen is a `range_start` after the first minute-level object, whatever the layout.
    """
    for tree, earliest_minute in (
        (("2026/09/07/14/03",), "2026/09/07"),
        (("2026/01/05/03", "2026/02/11/08/17", "2026/07/25/13/22"), "2026/02/11"),
        (("2026/01/05/03/09", "2026/03/09/11", "2026/07/25/13/22"), "2026/01/05"),
    ):
        s3_tree(*tree)
        layout = A._detect_partitions("s3://bkt")
        assert layout["range_start"][:10] <= earliest_minute, (
            f"{layout['range_start']} is after {earliest_minute} for {tree}")
