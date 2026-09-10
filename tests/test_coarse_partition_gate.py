# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Which partition layouts may run a log-detail query, and what a daily bucket detects as.

ROADMAP 3.2 and 3.3. The gate used to block anything not minute-level, which blocked most
Firehose users, since hourly is the Firehose default. It now blocks only daily and coarser.
Moving that threshold with all 262 existing tests still green is what says the threshold was
never covered.

**The two halves had to land together and this file is where that is asserted.** While
hourly was refused, `_era_of` folding a daily tree in with hourly was harmless: both were
rejected. Open the gate alone and a daily bucket is declared `yyyy/MM/dd/HH`, which projects
`.../27/00` through `/23` while the objects sit directly under `.../27/`, so no projected
partition covers them and Athena answers zero rows with no error. A loud refusal would have
become a silent wrong answer.
"""

import pytest

from tools import waf_athena as A
from tools import waf_query as Q

# depth of the date tree -> (era, declared format, whether a log query may run)
LAYOUTS = [
    (5, "minutes", "yyyy/MM/dd/HH/mm", True),
    (4, "hours", "yyyy/MM/dd/HH", True),
    (3, "days", "yyyy/MM/dd", False),
]


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


@pytest.mark.parametrize("depth,era,fmt,_runs", LAYOUTS)
def test_the_detected_era_matches_the_declared_format(depth, era, fmt, _runs):
    """`_era_of` and `_FORMAT_BY_ERA` are the pair that stops a daily bucket being declared
    hourly. Asserted together because either alone is satisfiable while the other is wrong."""
    assert A._era_of(["x"] * depth) == era
    assert A._FORMAT_BY_ERA[era][0] == fmt
    assert A._partition_granularity(fmt) == era, "the two classifiers must agree"


def test_a_daily_tree_is_no_longer_declared_hourly():
    """The silent-zero-rows case, stated as the one thing that must not happen. A three-level
    tree declared `yyyy/MM/dd/HH` projects one level below where the objects are."""
    fmt, _unit = A._FORMAT_BY_ERA[A._era_of(["2026", "09", "10"])]
    assert fmt == "yyyy/MM/dd"
    assert fmt != "yyyy/MM/dd/HH"


def test_an_unreadable_tree_falls_back_to_the_coarsest_layout(s3_tree):
    """Declaring coarser than reality is safe, because the partition location resolves to the
    day directory and Athena scans recursively beneath it. Declaring finer is the zero-rows
    failure. So an unclassifiable tree has to guess coarse, and it is then refused for log
    detail, which is the honest outcome for a layout nobody could read.

    Driven through `_detect_partitions` rather than by re-deriving `_FORMAT_BY_ERA[era or
    "days"]` in the test. The first version did re-derive it, and flipping production's
    fallback to "hours" left the test green: it was asserting its own copy of the expression
    it was meant to cover. Found by the perturbation reporting HOLLOW."""
    s3_tree("2026/09")
    assert A._era_of(["2026", "09"]) is None, "fixture does not reach the branch"
    layout = A._detect_partitions("s3://bkt")
    assert (layout["format"], layout["unit"]) == ("yyyy/MM/dd", "days")
    assert A._partition_too_coarse(layout["format"]) is True


@pytest.mark.parametrize("tree,fmt", [
    ("2026/09/10/14/03", "yyyy/MM/dd/HH/mm"),
    ("2026/09/10/14", "yyyy/MM/dd/HH"),
    ("2026/09/10", "yyyy/MM/dd"),
])
def test_the_detected_range_start_parses_against_the_declared_format(s3_tree, tree, fmt):
    """`_create_named_table` parses `range_start` with `strptime` against the declared
    format, so a mismatch raises at CREATE. The old suffix was a two-way "minutes or not",
    correct only while "not minutes" could only mean hourly: it gives a daily table
    `2026/09/10/00`, which does not parse as `yyyy/MM/dd`.

    Asserted on what `_detect_partitions` returns, not on the suffix table. The first version
    checked `_RANGE_START_SUFFIX` and did its own join, so restoring the two-way expression in
    production left it green."""
    from datetime import datetime
    s3_tree(tree)
    layout = A._detect_partitions("s3://bkt")
    assert layout["format"] == fmt, "fixture does not reach the branch"
    assert datetime.strptime(layout["range_start"],
                             A._java_date_format_to_strftime(layout["format"]))


# --- the gate ---------------------------------------------------------------


@pytest.mark.parametrize("depth,era,fmt,runs", LAYOUTS)
def test_the_gate_admits_hourly_and_refuses_daily(monkeypatch, depth, era, fmt, runs):
    """Both directions in one sweep. A one-sided test here is satisfied by a constant, and
    this predicate was inverted from `not _partition_has_minutes` in exactly the place where
    that matters."""
    assert A._partition_too_coarse(fmt) is (not runs)
    monkeypatch.setattr(Q, "get_log_type", lambda: "s3")
    A._athena_state["partition_format"] = fmt
    blocked = Q.check_coarse_partition_block()
    assert (blocked is None) is runs, blocked
    if blocked:
        assert "day or coarser" in blocked


@pytest.mark.parametrize("fmt", ["dd/MM/yyyy", "yy/MM/dd", "", None])
def test_an_unclassifiable_format_is_refused(fmt):
    """The direction that cannot be walked back after the bill arrives: reading an
    unclassifiable format as fine-grained would run at unknown scan cost while the product
    believes it refuses coarse layouts."""
    assert A._partition_too_coarse(fmt) is True


def test_a_cold_session_does_not_block(monkeypatch):
    """The gate is a pre-flight over state that resolution writes, so before any table is
    resolved it must let the caller through to the real check inside `query_logs`."""
    monkeypatch.setattr(Q, "get_log_type", lambda: "s3")
    assert A._athena_state.get("partition_format") is None
    assert Q.check_coarse_partition_block() is None


def test_the_old_minute_level_predicate_is_gone():
    """It had exactly three callers, all of them this gate, so moving the threshold made it
    dead. Leaving both would let a later caller pick the retired threshold."""
    assert not hasattr(A, "_partition_has_minutes")
    assert not hasattr(Q, "_HOURLY_PARTITION_ERROR")


# --- 3.3, the cost notice that replaced the refusal ------------------------


@pytest.mark.parametrize("depth,era,fmt,_runs", LAYOUTS)
def test_only_hourly_gets_the_cost_notice(depth, era, fmt, _runs):
    """Hourly runs and is told what it costs. Minute-level has nothing to report, and daily
    is refused at the query, so a notice there would describe a query that never runs."""
    A._athena_state["partition_format"] = fmt
    out = A.describe_table_resolution()
    assert ("partitioned by hour" in out) is (era == "hours"), out


def test_the_notice_says_narrowing_below_an_hour_saves_nothing():
    """The measured fact, and the one a user acts on: on an hourly table a 5-minute request
    and a 60-minute request scan identical bytes, so zooming in means fewer hours."""
    assert "narrowing a window below one hour saves" in Q.HOURLY_COST_NOTICE
    assert "fewer hours rather than fewer minutes" in Q.HOURLY_COST_NOTICE


def test_the_mixed_bucket_message_no_longer_claims_hourly_is_unbuildable():
    """3.2 falsified the old sentence "an hourly table, which this agent does not build
    yet". What stayed true is narrower: the agent builds one table for the newest layout, so
    the older era needs a second table the user creates."""
    A._athena_state.update({"layout_mixed": True, "layout_cutover": "2026/05/25",
                           "layout_data_start": "2022/05/26",
                           "partition_format": "yyyy/MM/dd/HH/mm"})
    out = A.describe_table_resolution()
    assert "does not build yet" not in out
    assert "second, hourly table you create yourself" in out
    # And it must still say the old era is unreachable, which is the point of the message.
    assert "zero rows" in out and "2022/05/26" in out


def test_no_user_facing_string_still_says_hourly_is_unbuildable():
    """A sweep, because correcting the sentence twice was not enough.

    3.2 made "an hourly table, which this agent does not build yet" false, and the first fix
    corrected the copy in `describe_table_resolution` while missing a second in
    `partition_predicate`'s out-of-range message, which kept shipping. Asserting the phrase's
    ABSENCE across `tools/` costs a line and catches a third copy, where a test per call site
    only covers the sites someone remembered."""
    import pathlib
    offenders = []
    for path in sorted(pathlib.Path("tools").glob("*.py")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if "does not build yet" in line and "used to read" not in line:
                offenders.append(f"{path}:{n}")
    assert not offenders, offenders
