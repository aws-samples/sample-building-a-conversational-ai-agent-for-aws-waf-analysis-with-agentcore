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
    _, fmt, unit, interval = A._detect_partitions("s3://bkt")
    assert (fmt, unit, interval) == ("yyyy/MM/dd/HH/mm", "minutes", 1)


def test_pure_hourly_bucket_still_detects_as_hourly(s3_tree):
    s3_tree("2026/06/15/10", "2026/09/07/14")
    _, fmt, unit, interval = A._detect_partitions("s3://bkt")
    assert (fmt, unit, interval) == ("yyyy/MM/dd/HH", "hours", 1)


def test_pure_minute_bucket_detects_as_minute_level(s3_tree):
    s3_tree("2026/09/07/14/03")
    _, fmt, unit, interval = A._detect_partitions("s3://bkt")
    assert (fmt, unit, interval) == ("yyyy/MM/dd/HH/mm", "minutes", 1)


def test_interval_is_always_one_never_inferred_from_directory_names(s3_tree):
    """Firehose's !{timestamp:mm} emits whatever minute the buffer flushed at, so
    these names are arbitrary. Subtracting two of them used to give interval 4
    here, and partition projection would then generate 03, 07, 11 ... and never
    read the objects under any other minute. Missing rows, no error."""
    s3_tree("2026/09/07/14/03", "2026/09/07/14/07", "2026/09/07/14/41")
    assert A._detect_partitions("s3://bkt")[3] == 1


def test_newest_child_is_taken_at_every_level(s3_tree):
    """Not just the newest year. A cutover mid-month or mid-day has to be found
    too, so the choice repeats at month, day and hour."""
    s3_tree("2026/09/01/10", "2026/09/28/23/59", "2025/12/31/23/59")
    assert A._detect_partitions("s3://bkt")[1] == "yyyy/MM/dd/HH/mm"


def test_two_digit_levels_sort_numerically(s3_tree):
    """Zero padding is what makes a lexicographic max the numeric max. If it were
    not padded, "9" would beat "28" and the walk would pick the wrong month."""
    s3_tree("2026/02/03/04", "2026/10/09/08/07")
    assert A._detect_partitions("s3://bkt")[1] == "yyyy/MM/dd/HH/mm"


def test_stray_non_numeric_directory_is_ignored(s3_tree):
    """Letters sort after digits, so taking the newest child would otherwise pick
    a stray directory like this and abandon the walk one level in."""
    s3_tree("2026/09/07/14/03", "2026/backfill")
    _, fmt, _, _ = A._detect_partitions("s3://bkt")
    assert fmt == "yyyy/MM/dd/HH/mm"


def test_storage_template_points_at_the_partition_root(s3_tree):
    s3_tree("logs/2026/09/07/14/03")
    template, _, _, _ = A._detect_partitions("s3://bkt/logs")
    assert template == "s3://bkt/logs/${log_time}"


def test_vended_log_prefix_is_walked_through(s3_tree):
    """AWS vended logs bury the dates under AWSLogs/<account>/WAFLogs/..., and the
    walk has to descend to wherever the years actually start."""
    s3_tree("AWSLogs/1234/WAFLogs/us-east-1/myacl/2026/09/07/14/03")
    template, fmt, _, interval = A._detect_partitions("s3://bkt")
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
