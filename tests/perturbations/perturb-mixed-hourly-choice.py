#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the ROADMAP 3.2 mixed-bucket hourly build and require the tests to notice.

On a bucket that holds both hourly (pre-cutover) and minute-level (post-cutover) partition
eras, the default reads the recent minute era; on an explicit hourly choice the agent builds
its own hourly table over the whole timeline so the pre-cutover history is reachable.

Every mixed-bucket decision keys on ONE property, `_is_minute_newest_mixed` (mixed with a
minute-level newest era, read from the layout published to state): the build gate, the
`set_log_granularity` tool, and the two user-facing messages (`_mixed_layout_sentence`, the
minute-choice reply). The first three cases break that shared predicate's three parts and a
different site's test must notice: drop the newest-unit conjunct (a reverse minute->hourly
switch reads as minute-newest), drop the mixed conjunct (a single layout does), or revert it
to the best-effort cutover DATE (a genuine mixed bucket with a non-monotone cutover month,
whose date is None, drops out). The per-site cases then check that each site consults the
property rather than the date or the resolved table's unit, that the build declares an HOURLY
table from the oldest data, that the tool's decline/recall/minute wording is accurate, and
that `_create_named_table` raises on a transient Glue error rather than silently keeping a
range-stale table.

Two build cases and the DDL case land on a continuation line or an f-string fragment that no
statement fits above, so they pass probe=False. The staleness cases used to as well, when the
folded self-heal's `except` swallowed any error; now that it re-raises anything but
EntityNotFoundException, an inserted probe propagates, so they probe like the rest.
"""

import sys

from _harness import sweep

A = "tools/waf_athena.py"
L = "tools/waf_logs.py"
T = "tests/test_table_resolution.py"
T2 = "tests/test_partition_detection.py"

# The shared predicate's body, inside `return bool(...)`. Named once so the three cases that
# break a different part of the conjunction share one anchor.
HELPER = '_athena_state.get("layout_mixed") and _athena_state.get("layout_newest_unit") == "minutes"'

CASES = [
    # --- the one owner: _is_minute_newest_mixed, broken three ways ---

    # Drop the newest-unit conjunct: a reverse minute->hourly switch (mixed, hourly-newest) now
    # reads as minute-newest, so the gate builds a redundant `_hourly` table beside a default one
    # that already reads the whole timeline.
    ("the property drops its newest-unit conjunct, rebuilding a reverse-switch bucket",
     [(A, HELPER, '_athena_state.get("layout_mixed")')],
     [f"{T}::test_hourly_choice_does_not_rebuild_a_reverse_switch_bucket"],
     True),

    # Drop the mixed conjunct: a single minute-level layout now reads as minute-newest, so the
    # gate coarsens a bucket that has no older era to a redundant hourly table.
    ("the property drops its mixed conjunct, rebuilding a single-layout bucket",
     [(A, HELPER, '_athena_state.get("layout_newest_unit") == "minutes"')],
     [f"{T}::test_hourly_choice_is_ignored_on_a_single_layout_bucket"],
     True),

    # Revert the property to the best-effort cutover DATE: an undated minute-newest mixed bucket
    # (non-monotone cutover month) then reads as not-mixed, so `_mixed_layout_sentence` falls
    # silent and the resolution block stops warning and offering the hourly build.
    ("the property reverts to the cutover date, silencing the mixed warning on an undated bucket",
     [(A, HELPER, '_athena_state.get("layout_mixed") and _athena_state.get("layout_cutover")')],
     [f"{T}::test_undated_mixed_bucket_still_warns_and_offers_hourly"],
     True),

    # --- the build gate keys on the property, not the date ---

    # Key the gate on the cutover DATE instead of the property, so an undated minute-newest mixed
    # bucket's build is refused and the pre-cutover history stays unreachable.
    ("the build gate keys on the cutover date, not building an undated minute-newest bucket",
     [(A, "layout is not None and _is_minute_newest_mixed()",
       'layout is not None and _athena_state.get("layout_cutover")')],
     [f"{T}::test_hourly_choice_builds_on_a_minute_newest_mixed_bucket_without_a_cutover_date"],
     True),

    # --- what the build declares (continuation lines inside the _create_named_table call) ---

    # The agent builds a MINUTE table under the hourly choice, which cannot reach the hourly
    # pre-cutover era it was chosen to read.
    ("the hourly build declares a minute-level format instead",
     [(A, '"yyyy/MM/dd/HH", "hours", 1,', '"yyyy/MM/dd/HH/mm", "minutes", 1,')],
     [f"{T}::test_hourly_choice_on_a_mixed_bucket_builds_the_whole_timeline_table"],
     False),   # continuation line inside the _create_named_table call; no statement fits above it

    # The range starts at the minute era's own start rather than the oldest data, so the hourly
    # table stops exactly where the minute one did and the history is still unreachable.
    ("the hourly range starts at the minute era, not the oldest data",
     [(A, 'range_start=layout["data_start"] + _RANGE_START_SUFFIX["hours"]',
       'range_start=layout["range_start"] + _RANGE_START_SUFFIX["hours"]')],
     [f"{T}::test_hourly_choice_on_a_mixed_bucket_builds_the_whole_timeline_table"],
     False),   # continuation line inside the _create_named_table call; no statement fits above it

    # The default-choice block goes back to telling the user to build the table themselves, the
    # recipe 3.2 retired.
    ("the resolution block sends the user back to hand-written DDL",
     [(A, "agent will build it over the same bucket",
       "user builds a second hourly table you create yourself")],
     [f"{T}::test_resolution_block_by_default_offers_the_agent_built_hourly_table"],
     False),   # f-string fragment inside a lines.append call; no statement fits above it

    # --- the tool consults the property, not the date or the resolved table's unit ---

    # The tool's decline drops to bare `layout_mixed`, so a reverse minute->hourly switch is
    # coarsened and told history "becomes queryable" instead of being declined.
    ("the tool decline keys on bare mixed, coarsening a reverse-switch bucket",
     [(L, "    if not minute_newest_mixed:", '    if not _athena_state.get("layout_mixed"):')],
     [f"{T}::test_tool_declines_hourly_when_the_table_already_reads_the_whole_timeline"],
     True),

    # The tool's decline keys on the cutover DATE, so an undated minute-newest mixed bucket is
    # declined and told it is single-layer, the finding this fix closed on the tool side.
    ("the tool decline keys on the cutover date, declining an undated minute-newest bucket",
     [(L, "    if not minute_newest_mixed:", '    if not _athena_state.get("layout_cutover"):')],
     [f"{T}::test_tool_offers_hourly_on_a_minute_newest_mixed_bucket_even_without_a_cutover_date"],
     True),

    # The tool decline re-adds the resolved table's unit (the regression this round fixed), so a
    # user-maintained hourly table over a minute-newest mixed bucket is declined as already-whole
    # rather than triggering the agent's build.
    ("the tool decline re-adds the resolved-table unit, declining over a user hourly table",
     [(L, "    if not minute_newest_mixed:",
       '    if not (minute_newest_mixed and _athena_state.get("partition_interval_unit") == "minutes"):')],
     [f"{T}::test_tool_offers_hourly_even_when_a_user_hourly_table_is_resolved_over_a_mixed_bucket"],
     True),

    # The already-chosen branch loses its property guard, so a stale hourly choice on a bucket
    # that is no longer minute-newest (its hourly era aged out) still claims "already reading as
    # hourly" when the active table is single-layout minute-level.
    ("the recall branch drops its property guard, claiming hourly after the bucket changed",
     [(L, '    if minute_newest_mixed and _athena_state.get("layout_choice") == "hourly":',
       '    if _athena_state.get("layout_choice") == "hourly":')],
     [f"{T}::test_tool_hourly_recall_does_not_claim_hourly_after_the_bucket_stopped_being_mixed"],
     True),

    # The already-chosen branch never fires, so a re-call after the build falls to the first-time
    # reply and implies a fresh build ("the agent builds") the idempotent set_layout_choice will
    # not do.
    ("a re-call after the hourly build implies a fresh build it will not do",
     [(L, '    if minute_newest_mixed and _athena_state.get("layout_choice") == "hourly":',
       "    if False:")],
     [f"{T}::test_tool_hourly_recall_after_the_build_does_not_imply_a_fresh_build"],
     True),

    # The minute-choice reply keys its "recent minute-level era, ask for hourly" pointer on bare
    # `layout_mixed`, so a reverse minute->hourly switch is told its data is minute-level.
    ("the minute reply keys on bare mixed, claiming minute-level on a hourly-newest bucket",
     [(L, "        if minute_newest_mixed:", '        if _athena_state.get("layout_mixed"):')],
     [f"{T}::test_tool_minute_message_keys_on_the_minute_newest_property_not_bare_mixed"],
     True),

    # The decline's precision-loss reason fires regardless of the current granularity, so an
    # already-hourly bucket is told it has "precision to lose" when hourly is the finest it has.
    ("the decline claims precision loss even on an already-hourly bucket",
     [(L, '        if _athena_state.get("partition_interval_unit") == "minutes":', "        if True:")],
     [f"{T}::test_tool_declines_hourly_when_the_table_already_reads_the_whole_timeline"],
     True),

    # The decline's precision-loss reason never fires, so a pure minute-level bucket is told the
    # neutral "already whole timeline" message instead of that it would lose precision.
    ("the decline drops the precision-loss reason on a pure minute-level bucket",
     [(L, '        if _athena_state.get("partition_interval_unit") == "minutes":', "        if False:")],
     [f"{T}::test_tool_refuses_hourly_on_a_single_minute_layout_bucket"],
     True),

    # --- detection: the cutover date and the newest-unit both come from _layout_from_years ---

    # The cutover gate never fires, so a genuine minute-newest mixed bucket reports no cutover
    # date, which the display path (which reports the date) reads.
    ("the cutover gate never fires, so a minute-newest mixed bucket reports no cutover",
     [(A, '    if mixed and era_new == "minutes":', "    if False:")],
     [f"{T2}::test_cutover_is_set_exactly_for_a_minute_newest_mixed_bucket"],
     True),

    # --- choice bookkeeping and the tool's other branches ---

    # set_layout_choice loses its idempotence, so setting the choice to what it already is
    # still resets and drops the cached table, firing the rate-limited describe the memo avoids.
    ("set_layout_choice is no longer idempotent, so an unchanged choice still rebuilds",
     [(A, 'if _athena_state.get("layout_choice") == choice:', "if False:")],
     [f"{T}::test_set_layout_choice_is_idempotent"],
     True),

    # The hourly branch drops its "resolve first" precondition, so calling it before any query
    # sets the choice and relays a whole-timeline promise the resolver may silently ignore.
    ("the tool promises the whole timeline before the layout is even known",
     [(L, "    if not resolved:", "    if False:")],
     [f"{T}::test_tool_hourly_before_resolution_asks_for_a_query_first"],
     True),

    # The "already recorded" sub-branch is dropped, so a re-call before a query implies the
    # hourly choice was not recorded when it was.
    ("a pending hourly choice is not acknowledged on a re-call before a query",
     [(L, '        if _athena_state.get("layout_choice") == "hourly":', "        if False:")],
     [f"{T}::test_tool_hourly_recall_before_resolution_says_the_choice_is_recorded"],
     True),

    # --- the projection self-heal folded into _create_named_table ---

    # _create_named_table stops dropping a range/format-stale scratch table, so CREATE IF NOT
    # EXISTS keeps a range-too-late table and a window before its start returns zero rows read
    # as "no traffic" (the finding-1 silent-wrong-answer).
    ("a range-stale scratch table is not dropped before CREATE",
     [(A, "                    if problem is not None:", "                    if False:")],
     [f"{T}::test_create_named_table_rebuilds_a_range_stale_scratch_table"],
     True),

    # The staleness rebuild is no longer disclosed, so a moved range and a slow first query
    # after a gap go unexplained.
    ("the scratch-table rebuild is dropped silently, without a note",
     [(A, "            if stale_note:", "            if False:")],
     [f"{T}::test_create_named_table_rebuilds_a_range_stale_scratch_table"],
     True),

    # The staleness gate inverts, so a table already matching the data is dropped and rebuilt on
    # every cold resolve: drop/rebuild thrash.
    ("a matching scratch table is dropped anyway, thrashing",
     [(A, "                    if problem is not None:", "                    if True:")],
     [f"{T}::test_create_named_table_does_not_drop_a_matching_scratch_table"],
     True),

    # A transient Glue error at get_table is swallowed as "table absent" again, so CREATE IF NOT
    # EXISTS keeps a possibly range-stale table on a throttle rather than failing loudly.
    ("a transient get_table error is swallowed, keeping a possibly stale table",
     [(A, 'if type(e).__name__ != "EntityNotFoundException":', "if False:")],
     [f"{T}::test_create_named_table_raises_on_a_transient_glue_error_not_keeps_a_stale_table"],
     True),
]

sys.exit(sweep(CASES))
