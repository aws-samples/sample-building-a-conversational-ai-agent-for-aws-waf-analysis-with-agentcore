# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The weekly report's title named a day the report does not cover, in two independent ways.

ROADMAP 7.2's other half. The date-offset defect that opened section 7 was invisible because nothing in
`get_waf_metrics`' output said which window it had read; this is the same shape in the weekly report,
except the window is stated and stated wrongly.

`generate_weekly_report` parses `start_time` in the session timezone and converts to UTC, then the
subtitle formatted those UTC datetimes raw. Two errors, and they push in opposite directions, so a
reader could not spot either by arithmetic on the other.
"""

from datetime import datetime, timedelta, timezone

from tools.report import _date_range_label, _window_labels, last_day_covered

UTC8 = timezone(timedelta(hours=8))
UTC_MINUS_5 = timezone(timedelta(hours=-5))


def _asked(day: str, tz) -> datetime:
    """What `generate_weekly_report` does with `start_time="YYYY-MM-DD"`: session-local midnight, in UTC."""
    return datetime.fromisoformat(day + "T00:00:00").replace(tzinfo=tz).astimezone(timezone.utc)


def test_the_start_date_is_the_day_the_caller_asked_for():
    """**The defect: at UTC+8, `2026-05-08` became `2026-05-07` in the title.** Session-local midnight is
    16:00 the previous day in UTC, and the subtitle formatted the UTC value. The report covered the day
    that was asked for; only its own title disagreed, which is why nothing downstream noticed."""
    start = _asked("2026-05-08", UTC8)
    assert start.strftime("%Y-%m-%d") == "2026-05-07", (
        "this test's premise is gone: the UTC value no longer falls on the previous day")
    label = _date_range_label(start, start + timedelta(days=7), UTC8, "UTC+8")
    assert label.startswith("2026-05-08 "), label


def test_a_negative_offset_moves_the_day_the_other_way():
    """The mirror, because a fix that shifted by a fixed number of hours passes the test above and is
    wrong for every user west of UTC.

    **The start has to be an evening one for this to discriminate, and a midnight one does not**,
    measured: at UTC-5 session midnight is 05:00 the same UTC day, so the correct conversion and a
    plausible `+8h` shift both land on 05-08 and the perturbation reported HOLLOW. 20:00 at UTC-5 is
    01:00 the next UTC day, where raw UTC says 05-09 and `+8h` says 05-09 while the answer is 05-08.
    `start_time` accepts `YYYY-MM-DDTHH:MM`, so this is a real input rather than a contrived one."""
    start = datetime.fromisoformat("2026-05-08T20:00").replace(
        tzinfo=UTC_MINUS_5).astimezone(timezone.utc)
    assert start.strftime("%Y-%m-%d") == "2026-05-09", "premise: 20:00 at UTC-5 is the next UTC day"
    label = _date_range_label(start, start + timedelta(days=7), UTC_MINUS_5, "UTC-5")
    assert label.startswith("2026-05-08 "), label


def test_the_end_date_is_the_last_day_covered_not_the_first_day_after():
    """`end` is exclusive, so seven days beginning on the 8th run to midnight on the 15th and the last
    day covered is the 14th.

    **The old code printed the 14th here too, and for the wrong reason**, which is worth stating because
    the fixture is UTC+8. Formatting the exclusive UTC boundary raw happens to land on the same day as
    the last local instant at any positive offset, so the two errors cancelled on this date and only the
    start was wrong. At zero and negative offsets the cancellation does not happen and the old title said
    `to 2026-05-15`. What makes this test discriminating is not the old behaviour but the perturbation
    that drops the one-second step, which prints the 15th at every offset."""
    start = _asked("2026-05-08", UTC8)
    label = _date_range_label(start, start + timedelta(days=7), UTC8, "UTC+8")
    assert label == "2026-05-08 to 2026-05-14 UTC+8", label


def test_an_end_capped_at_now_names_the_day_it_was_capped_on():
    """`end` is `min(start + days, now)`, so a report requested for a window that has not finished ends
    at a mid-day timestamp rather than a boundary. Stepping back one second must not move that date."""
    start = _asked("2026-05-08", UTC8)
    capped = datetime(2026, 5, 12, 10, 30, tzinfo=UTC8).astimezone(timezone.utc)
    label = _date_range_label(start, capped, UTC8, "UTC+8")
    assert label == "2026-05-08 to 2026-05-12 UTC+8", label


def test_the_zone_is_named_in_the_label():
    """A date with no zone is not a claim anyone can check, and this report is read by someone comparing
    it against a graph in their own console. The label is passed in rather than derived here, so there is
    one rule for spelling it."""
    start = _asked("2026-05-08", UTC8)
    assert _date_range_label(start, start + timedelta(days=7), UTC8, "UTC+8").endswith(" UTC+8")
    utc = _asked("2026-05-08", timezone.utc)
    assert _date_range_label(utc, utc + timedelta(days=7), timezone.utc, "UTC") == (
        "2026-05-08 to 2026-05-14 UTC")


def test_the_subtitle_names_the_baseline_window_it_also_read():
    """**The report reads fourteen days and reports on seven**, because every week-over-week figure comes
    from `start_last_week` to `start_this_week`. The provenance record on the tool chip is the union of
    everything read, so a title naming only the reported week put fourteen days on the chip beside a
    title claiming seven, with nothing to explain it.

    Naming the baseline is the cheaper half of resolving that. The other half would be a record that
    leaves a real read out, which is what the record exists to prevent. A week-over-week percentage whose
    baseline dates are unstated is also a number nobody can check."""
    start = _asked("2026-05-08", UTC8)
    label = _window_labels(start, start + timedelta(days=7), start - timedelta(days=7), UTC8, "UTC+8")
    assert label == "2026-05-08 to 2026-05-14 UTC+8 · baseline 2026-05-01 to 2026-05-07", label


def test_the_baseline_ends_where_the_reported_window_begins():
    """Not seven days back from the end, which is the plausible wrong bound and overlaps the window being
    reported on. `_get_weekly_totals` is called with `(start_last_week, start_this_week)`, so the two
    windows meet and do not overlap."""
    start = _asked("2026-05-08", UTC8)
    label = _window_labels(start, start + timedelta(days=3), start - timedelta(days=7), UTC8, "UTC+8")
    assert label.endswith("baseline 2026-05-01 to 2026-05-07"), label
    assert label.startswith("2026-05-08 to 2026-05-10 "), label


def test_the_zone_is_named_once_rather_than_on_both_halves():
    """Two identical zone labels in one subtitle read as two different zones being compared."""
    start = _asked("2026-05-08", UTC8)
    label = _window_labels(start, start + timedelta(days=7), start - timedelta(days=7), UTC8, "UTC+8")
    assert label.count("UTC+8") == 1, label


def test_the_filename_names_the_last_day_the_report_covers():
    """**The title was fixed in 0.26.0 and the filename was not**, because each derived the last day for
    itself. Measured against the deployed endpoint 2026-09-15: a report covering 2026-09-08 to 09-14 was
    written to `waf-weekly-summary-shield-sample-webacl-20260915.html`.

    Driven at UTC, where the old code was wrong, and at UTC+8, where `end`'s exclusive boundary lands on
    the same local day as the last instant so the old code happened to be right. One offset alone cannot
    tell the two derivations apart, which is the same reason the title's own tests sweep five offsets."""
    for tz, label in ((timezone.utc, "UTC"), (UTC8, "UTC+8")):
        start = _asked("2026-09-08", tz)
        end = start + timedelta(days=7)
        assert last_day_covered(end, tz, "%Y%m%d") == "20260914", (
            f"at {label} the filename names {last_day_covered(end, tz, '%Y%m%d')}, and the report covers "
            f"through 2026-09-14")


def test_the_filename_and_the_title_cannot_disagree():
    """The pairing, and it is the property rather than the instance. Two copies of one derivation is what
    produced the defect, so the assertion is that they are one: the day the filename carries is the day
    the title's range ends on, for a window `now` capped mid-day as well as one on a boundary."""
    start = _asked("2026-09-08", UTC8)
    for end in (start + timedelta(days=7), start + timedelta(days=6, hours=13, minutes=27)):
        title = _date_range_label(start, end, UTC8, "UTC+8")
        title_end = title.split(" to ")[1].split(" ")[0]
        assert last_day_covered(end, UTC8, "%Y%m%d") == title_end.replace("-", ""), (
            f"the file is named for {last_day_covered(end, UTC8, '%Y%m%d')} and its own title says the "
            f"window ends {title_end}")


def test_the_name_comes_from_the_shared_derivation():
    """Structural, and it guards the state rather than the symptom. The test above would pass again after
    someone re-derived the last day at the filename with a correct expression, and the next fix to one of
    the two would leave the other behind, which is exactly what happened between 0.26.0 and 0.26.1."""
    import pathlib

    from tools import report

    line = next(ln for ln in pathlib.Path(report.__file__).read_text().splitlines()
                if "output_path = " in ln)
    assert "last_day_covered(" in line, (
        f"the filename derives its own last day again rather than sharing the title's: {line.strip()}")
