# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The block that reports missing report sections used to crash when one was missing.

`patrol_scan` builds a result dict whose `bot_data` key is initialised to None and stays None
whenever the five Bot Control label metrics sum to zero. The detection then did
`wr.get("bot_data", {}).get("bot_names")`, and `.get`'s default applies only when the key is
*absent*, so it handed back the stored None and raised.

**Not an edge case, and wider than first documented.** The WebACL that hit this in a real
account *has* Bot Control enabled; the metric call succeeded and returned five empty series,
because no bot labels were emitted in the window. So a quiet hour on a fully configured WebACL
is enough, and "WebACL without Bot Control", which is what this file said first, was a subset
described as the trigger.

**What was actually missing was an input shape, not a test layer.** These tests need no AWS at
all, and the crash reproduces from a two-key dict, so nothing about containers or endpoints was
required to find it. What no run had done was point patrol at a WebACL whose bot metrics were
empty. Two WebACLs are not a configuration matrix.
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


def test_the_producer_never_puts_a_falsy_bot_data_under_the_key():
    """The root-cause half. The reader fix above makes `_missing_sections` safe; this keeps the
    trap from being re-set for the next reader.

    A key that is always present and sometimes None makes `.get(key, default)` wrong for
    everyone, since the default applies only when the key is ABSENT. Omitting it when empty
    makes the idiom correct everywhere, including in code nobody has written yet. Asserted over
    the syntax tree rather than by running `patrol_scan`, which needs live CloudWatch: the
    property is about how the dict is built, so the dict literal is the honest place to check
    it. A string search would pass on the comment that explains the rule.
    """
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(P.patrol_scan._tool_func))
    literals = [n for n in ast.walk(tree) if isinstance(n, ast.Dict)
                and any(isinstance(k, ast.Constant) and k.value == "bot_data" for k in n.keys)]
    assert literals, "no dict literal mentions bot_data; did the builder move?"
    for lit in literals:
        for key, value in zip(lit.keys, lit.values):
            if isinstance(key, ast.Constant) and key.value == "bot_data":
                # Inside a `**({...} if bot_data else {})` spread the mapping is fine, because
                # the whole dict is conditional. What must not exist is the key sitting
                # directly in `wr` beside "name" and "scope".
                siblings = {k.value for k in lit.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                assert "name" not in siblings, (
                    "bot_data is mapped unconditionally in the result dict; a present-but-None "
                    "key is what made .get(key, {}) crash")


def test_an_empty_bot_names_counts_as_missing_not_as_present():
    """`{}` is what an empty CloudWatch result looks like, and reporting it as present would
    put an empty section in the report with nothing saying why."""
    wr = {"bot_data": {"bot_names": {}, "targeted_signals": {}}}
    assert P._missing_sections(wr, chart_data={"labels": [1]}) == \
        ["bot_names", "targeted_signals"]
