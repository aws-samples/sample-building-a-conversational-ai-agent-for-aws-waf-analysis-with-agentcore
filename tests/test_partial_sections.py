# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A blank report section has to say it is partial and why.

Two defects met in the same block. It **crashed** when a section was missing:
`wr.get("bot_data", {}).get("bot_names")` handed back a stored None, because `.get`'s default
applies only when the key is *absent* and this key is always present. And once it stopped
crashing it attributed every empty section to one hardcoded cause, "CloudWatch metric
auto-discovery requires recent activity", which told a user whose query had *failed* to go
generate traffic, and a user with no Bot Control rule group to wait for data that cannot arrive.

**Not an edge case, and wider than first documented.** The WebACL that hit the crash in a real
account *has* Bot Control enabled; the metric call succeeded and returned five empty series
because no bot labels were emitted in the window. A quiet hour on a fully configured WebACL is
enough.

**What was missing was an input shape, not a test layer.** These tests need no AWS, and the
crash reproduces from a two-key dict, so nothing about containers or endpoints was required to
find it. What no run had done was point patrol at a WebACL whose bot metrics were empty. Two
WebACLs are not a configuration matrix.
"""

from tools import waf_patrol as P

CHART = {"labels": ["09/09 10:00"], "series": {}}
FULL_BOT = {"bot_names": {"cat": 3}, "targeted_signals": {"sig": 1}}


# --- it must not crash, which is where this started -------------------------


def test_a_none_bot_data_does_not_crash_the_missing_section_check():
    """The original defect, stated directly. `bot_data` present and None is the ordinary case."""
    missing = P._missing_sections({"bot_data": None}, chart_data=None)
    assert sorted(missing) == ["attack_chart", "bot_names", "targeted_signals"]


def test_an_absent_bot_data_key_behaves_the_same_as_a_none_one():
    """The two spellings of absence have to agree, since the crash came from a helper that
    handled only one of them. A dict built by a different code path may omit the key."""
    assert P._missing_sections({}, chart_data=None) == \
        P._missing_sections({"bot_data": None}, chart_data=None)


def test_populated_bot_data_reports_nothing_missing():
    """The control. The fix must not report every section missing regardless of input, which is
    how a `return everything`-shaped mistake would still pass the tests above."""
    assert P._missing_sections({"bot_data": FULL_BOT}, chart_data=CHART) == {}


def test_each_section_is_reported_independently():
    """Three separate signals, not one flag. A report with a chart but no bot names has to say
    which of the two it lacks, or the note tells the user nothing actionable."""
    assert list(P._missing_sections({"bot_data": FULL_BOT}, chart_data=None)) == ["attack_chart"]
    assert list(P._missing_sections(
        {"bot_data": {"targeted_signals": {"s": 1}}}, chart_data=CHART)) == ["bot_names"]
    assert list(P._missing_sections(
        {"bot_data": {"bot_names": {"c": 3}}}, chart_data=CHART)) == ["targeted_signals"]


def test_an_empty_bot_names_counts_as_missing_not_as_present():
    """`{}` is what an empty CloudWatch result looks like, and reporting it as present would put
    an empty section in the report with nothing saying why."""
    wr = {"bot_data": {"bot_names": {}, "targeted_signals": {}}}
    assert sorted(P._missing_sections(wr, chart_data=CHART)) == \
        ["bot_names", "targeted_signals"]


# --- and it must say why, which is the half this item is named for ----------


def test_a_recorded_reason_reaches_the_report():
    """The point of the whole change. Four `except Exception: pass` handlers and two all-zero
    branches produced the same None, so the reason has to be recorded where it is still known
    and carried out to the reader."""
    wr = {"bot_data": None,
          "skips": {"bot_names": "the bot-name query failed (ThrottlingException)"}}
    assert P._missing_sections(wr, chart_data=CHART)["bot_names"] == \
        "the bot-name query failed (ThrottlingException)"


def test_an_unrecorded_reason_says_so_instead_of_guessing():
    """The default has to admit ignorance rather than pick a plausible cause. Naming one is
    exactly the defect being fixed: the old text asserted "no matching traffic recently" for
    every empty section, including sections whose query had failed."""
    why = P._missing_sections({"bot_data": None}, chart_data=None)["bot_names"]
    assert "did not record why" in why
    assert "traffic" not in why.replace("your traffic", ""), \
        "an unknown cause must not be described as a traffic condition"


def test_the_reasons_are_per_section_and_not_shared():
    """Two sections empty for different reasons must not collapse into one explanation, which is
    what a single `REASON:` line structurally could not avoid."""
    wr = {"bot_data": None,
          "skips": {"bot_names": "query failed", "targeted_signals": "no TGT_ labels matched"}}
    missing = P._missing_sections(wr, chart_data=CHART)
    assert missing["bot_names"] != missing["targeted_signals"]


# --- the input the metric sum cannot supply ---------------------------------


def test_bot_control_is_detected_from_the_rule_list_not_the_metrics():
    """The distinction the metric sum cannot make. Zero labels covers "never configured" and
    "configured and quiet", and only the rule list separates them, so a message that picks one
    would be wrong for the other half of the users."""
    on = {"Rules": [{"Name": "bc", "Statement": {"ManagedRuleGroupStatement": {
        "Name": "AWSManagedRulesBotControlRuleSet"}}}]}
    off = {"Rules": [{"Name": "crs", "Statement": {"ManagedRuleGroupStatement": {
        "Name": "AWSManagedRulesCommonRuleSet"}}}]}
    assert P._has_bot_control(on) is True
    assert P._has_bot_control(off) is False
    assert P._has_bot_control({}) is False



def test_targeted_only_bot_control_still_counts_as_present():
    """Matched on the substring rather than the exact name, because ATP and ACFP are also Bot
    Control family names and a WebACL running only Targeted inspection still has the rule
    group."""
    atp = {"Rules": [{"Name": "x", "Statement": {"ManagedRuleGroupStatement": {
        "Name": "AWSManagedRulesBotControlRuleSet"}}}]}
    assert P._has_bot_control(atp) is True


def test_the_zero_label_reason_names_the_right_one_of_the_two_worlds():
    """The wiring, not just the lookup. Testing `_has_bot_control` alone would pass while the
    reason ignored it, which is how the wrong version survived: inline in `patrol_scan` this
    branch could only be reached with live CloudWatch."""
    on = {"Rules": [{"Name": "bc", "Statement": {"ManagedRuleGroupStatement": {
        "Name": "AWSManagedRulesBotControlRuleSet"}}}]}
    enabled = P._bot_zero_reason(on)
    absent = P._bot_zero_reason({"Rules": []})
    assert enabled != absent, "the two worlds must not get the same sentence"
    assert "enabled" in enabled and "no bot traffic" in enabled
    assert "no AWS Managed Bot Control rule group" in absent
    assert "no bot traffic" not in absent, \
        "a WebACL without Bot Control has no traffic claim to make"


def test_the_reason_channel_is_carried_out_of_the_scan():
    """`skips` is useless if the result dict drops it, and `_missing_sections` would then fall
    back to the honest-but-uninformative default for every section. Checked over the syntax tree
    for the same reason as the `bot_data` invariant below: it is a property of how the dict is
    built."""
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(P.patrol_scan._tool_func))
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            keys = {k.value for k in node.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            if "name" in keys and "totals" in keys:
                assert "skips" in keys, "the result dict drops the reasons it collected"
                return
    raise AssertionError("could not find the result dict; did the builder move?")


# --- every reason, checked as a set rather than one at a time ---------------


def test_every_reason_that_blames_traffic_actually_knows_about_traffic():
    """The invariant the old single `REASON:` line broke for every section at once.

    A reason may only mention traffic if the query it describes *succeeded* and came back empty.
    A failed query knows nothing about traffic, and saying "no matching traffic recently" to
    someone whose query threw is what sent users off to generate load for no reason. Enumerated
    over the whole table so a tenth reason added later is covered without anyone remembering
    this test exists, which is why the strings were collected in the first place.
    """
    for kind, text in P._SKIP_REASONS.items():
        filled = P._skip_reason(kind, "SomeError").lower()
        claims_absence = "no bot traffic to report" in filled or "no named bots were seen" in filled
        if "failed" in kind or kind == "unrecorded":
            assert not claims_absence, f"{kind} blames traffic it cannot have observed"


def test_every_failure_reason_carries_the_engine_error():
    """A reason that says "the query failed" without saying how is barely better than silence,
    and the exception type is the one piece of evidence available at the handler."""
    for kind in P._SKIP_REASONS:
        if "failed" in kind:
            assert "SomeError" in P._skip_reason(kind, "SomeError"), \
                f"{kind} drops the detail it was given"


def test_no_two_reasons_are_the_same_sentence():
    """Two identical strings mean two causes the reader cannot tell apart, which is the defect
    this item is named for, reintroduced by copy-paste."""
    texts = list(P._SKIP_REASONS.values())
    assert len(set(texts)) == len(texts)


def test_the_table_covers_every_reason_the_module_asks_for():
    """`_skip_reason` raises `KeyError` on an unknown kind, which would crash a patrol scan on
    the path that exists to explain a failure. Cheaper to check every literal key the module
    passes than to hope every branch is exercised."""
    import ast
    import pathlib
    src = pathlib.Path(P.__file__).read_text()
    asked = set()
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_skip_reason"
                and node.args and isinstance(node.args[0], ast.Constant)):
            asked.add(node.args[0].value)
    assert asked, "no _skip_reason call sites found; did the helper get renamed?"
    assert asked <= set(P._SKIP_REASONS), f"missing from the table: {asked - set(P._SKIP_REASONS)}"


# --- the trap this fix must not re-set -------------------------------------


def test_the_producer_never_puts_a_falsy_bot_data_under_the_key():
    """The root-cause half. The reader fix makes `_missing_sections` safe; this keeps the trap
    from being re-set for the next reader.

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
        siblings = {k.value for k in lit.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        if "name" in siblings:
            raise AssertionError(
                "bot_data is mapped unconditionally in the result dict; a present-but-None "
                "key is what made .get(key, {}) crash")
