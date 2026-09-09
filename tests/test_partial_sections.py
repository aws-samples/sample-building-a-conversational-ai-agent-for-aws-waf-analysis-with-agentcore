# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The block that reports missing report sections used to crash when one was missing.

`patrol_scan` builds a result dict whose `bot_data` key is initialised to None and stays None
for any WebACL whose five Bot Control label metrics sum to zero. That is not an edge case: it
is every WebACL without AWS Managed Bot Control enabled. The detection then did
`wr.get("bot_data", {}).get("bot_names")`, and `.get`'s default applies only when the key is
*absent*, so it handed back the stored None and raised.

Found by running a patrol scan against the deployed agent while measuring something else, not
by reading the code, and reproduced on `main` before being fixed.
"""

from tools import waf_patrol as P


def test_a_none_bot_data_does_not_crash_the_missing_section_check():
    """The defect, stated directly. `bot_data` present and None is the ordinary case."""
    missing = P._missing_sections({"bot_data": None}, chart_data=None)
    assert missing == ["attack_chart", "bot_names", "targeted_signals"]


def test_an_absent_bot_data_key_behaves_the_same_as_a_none_one():
    """The two spellings of absence have to agree, since the crash came from a helper that
    handled only one of them. A dict built by a different code path may omit the key
    entirely."""
    assert P._missing_sections({}, chart_data=None) == \
        P._missing_sections({"bot_data": None}, chart_data=None)


def test_populated_bot_data_reports_nothing_missing():
    """The control. The fix must not report every section missing regardless of input, which
    is the way a `return []`-shaped mistake would still pass the tests above."""
    wr = {"bot_data": {"bot_names": {"cat": 3}, "targeted_signals": {"sig": 1}}}
    assert P._missing_sections(wr, chart_data={"labels": [1], "series": []}) == []


def test_each_section_is_reported_independently():
    """Three separate signals, not one flag. A report with a chart but no bot names has to say
    which of the two it lacks, or the PARTIAL_DATA note tells the user nothing actionable."""
    full_bot = {"bot_names": {"cat": 3}, "targeted_signals": {"sig": 1}}
    chart = {"labels": [1], "series": []}
    assert P._missing_sections({"bot_data": full_bot}, chart_data=None) == ["attack_chart"]
    assert P._missing_sections(
        {"bot_data": {"targeted_signals": {"sig": 1}}}, chart_data=chart) == ["bot_names"]
    assert P._missing_sections(
        {"bot_data": {"bot_names": {"cat": 3}}}, chart_data=chart) == ["targeted_signals"]


def test_an_empty_bot_names_counts_as_missing_not_as_present():
    """`{}` is what an empty CloudWatch result looks like, and reporting it as present would
    put an empty section in the report with nothing saying why."""
    wr = {"bot_data": {"bot_names": {}, "targeted_signals": {}}}
    assert P._missing_sections(wr, chart_data={"labels": [1]}) == \
        ["bot_names", "targeted_signals"]
