#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the ROADMAP 3.2 mixed-bucket hourly build and require the tests to notice.

On a bucket that holds both hourly (pre-cutover) and minute-level (post-cutover) partition
eras, the default reads the recent minute era; on an explicit hourly choice the agent builds
its own hourly table over the whole timeline so the pre-cutover history is reachable. The
properties a passing suite must fail on when removed: the build fires for a minute-newest mixed
bucket (`mixed` and a minute-level newest era), keyed on that PROPERTY and not on the
best-effort cutover DATE, so it still fires when the date could not be pinned, and it does not
fire on a reverse minute->hourly switch or a single layout; it builds an HOURLY table (not
minute); its range starts at the oldest data (the whole timeline, not the minute era's start);
the tool declines when the table already reads the whole timeline and does not claim "precision
to lose" on an already-hourly bucket; the tool acknowledges an already-recorded hourly choice
rather than implying a fresh build the idempotent path will not do; and the resolution block
offers the agent's build rather than telling the user to write DDL. One case in
test_partition_detection.py holds the invariant those sites lean on: a cutover date is set
exactly for a minute-newest mixed bucket.

Most cases probe. Those that land on a continuation line inside a multi-line call or f-string
cannot take an inserted statement, and the two that land inside `_create_named_table`'s broad
`except` (which swallows the inserted raise) cannot be probed either, so all of those pass
probe=False and say so, per the same rule as the rest of the suite.
"""

import sys

from _harness import sweep

A = "tools/waf_athena.py"
L = "tools/waf_logs.py"
T = "tests/test_table_resolution.py"
T2 = "tests/test_partition_detection.py"

# The build-gate predicate and the tool's decline predicate, each named once so the three
# cases that break a different part of the same conjunction share one anchor string.
GATE = 'layout["mixed"] and layout["unit"] == "minutes"'
DECLINE = 'not (mixed and _athena_state.get("partition_interval_unit") == "minutes")'

CASES = [
    # --- the build gate: fire for minute-newest mixed, keyed on the property not the date ---

    # Revert the gate to the cutover DATE. `_first_minute_day` returns None for a non-monotone
    # cutover month, so a genuine minute-newest mixed bucket then has cutover=None and the build
    # is refused, losing the whole feature on that bucket. This is the finding.
    ("the build gate keys on the cutover date, so an undated minute-newest bucket is not built",
     [(A, GATE, 'layout["cutover"]')],
     [f"{T}::test_hourly_choice_builds_on_a_minute_newest_mixed_bucket_without_a_cutover_date"],
     True),

    # Drop the minute-newest conjunct, so a reverse minute->hourly switch (mixed, hourly-newest)
    # gets a redundant `_hourly` build beside a default table that already reads the whole timeline.
    ("the build gate drops the minute-newest conjunct, rebuilding a reverse-switch bucket",
     [(A, GATE, 'layout["mixed"]')],
     [f"{T}::test_hourly_choice_does_not_rebuild_a_reverse_switch_bucket"],
     True),

    # Drop the `mixed` conjunct, so a pure minute-level bucket (already whole-timeline) is coarsened
    # to a redundant hourly table for no history to gain.
    ("the build gate drops the mixed conjunct, rebuilding a pure minute-level bucket",
     [(A, GATE, 'layout["unit"] == "minutes"')],
     [f"{T}::test_hourly_choice_is_ignored_on_a_single_layout_bucket"],
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

    # --- the tool's decline predicate: same property, mirrored from the gate ---

    # Revert the tool's guard to the cutover DATE, so an undated minute-newest bucket is declined
    # and told it is "a single minute-level layout" with no older era, which is false.
    ("the tool guard keys on the cutover date, declining an undated minute-newest bucket",
     [(L, DECLINE, "not cutover")],
     [f"{T}::test_tool_offers_hourly_on_a_minute_newest_mixed_bucket_even_without_a_cutover_date"],
     True),

    # Drop the minute-newest conjunct, so a reverse minute->hourly switch is coarsened and told
    # history "becomes queryable" instead of being declined.
    ("the tool guard drops the minute-newest conjunct, coarsening a reverse-switch bucket",
     [(L, DECLINE, "not mixed")],
     [f"{T}::test_tool_declines_hourly_when_the_table_already_reads_the_whole_timeline"],
     True),

    # Drop the `mixed` conjunct, so a pure minute-level bucket proceeds to set the choice and
    # rebuild as hourly rather than being refused.
    ("the tool guard drops the mixed conjunct, coarsening a pure minute-level bucket",
     [(L, DECLINE, 'not (_athena_state.get("partition_interval_unit") == "minutes")')],
     [f"{T}::test_tool_refuses_hourly_on_a_single_minute_layout_bucket"],
     True),

    # The decline no longer keys its precision-loss reason on the current granularity, so an
    # already-hourly bucket is told it has "precision to lose" when hourly is the finest it has.
    ("the decline claims precision loss even on an already-hourly bucket",
     [(L, '        if _athena_state.get("partition_interval_unit") == "minutes":', "        if True:")],
     [f"{T}::test_tool_declines_hourly_when_the_table_already_reads_the_whole_timeline"],
     True),

    # The already-chosen acknowledgement is dropped, so a re-call after the build falls to the
    # first-time reply and implies a fresh build ("the agent builds") the idempotent
    # set_layout_choice will not do. Anchored with a leading newline: the 4-space line is a
    # substring of the 8-space "already recorded" line otherwise.
    ("a re-call after the hourly build implies a fresh build it will not do",
     [(L, '\n    if _athena_state.get("layout_choice") == "hourly":', '\n    if False:')],
     [f"{T}::test_tool_hourly_recall_after_the_build_does_not_imply_a_fresh_build"],
     True),

    # --- the invariant the two sites lean on ---

    # The cutover gate in `_layout_from_years` never fires, so a genuine minute-newest mixed bucket
    # reports no cutover date, which the display path (which reports the date) reads.
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

    # The minute-choice reply keys its "minute-level era" claim on `mixed` instead of the
    # cutover, so a mixed-but-hourly-newest bucket is told its data is minute-level.
    ("the minute reply claims minute-level on a bucket keyed only by mixed",
     [(L, "        if cutover:", "        if mixed:")],
     [f"{T}::test_tool_minute_message_keys_on_cutover_not_mixed"],
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
     False),   # anchor is inside _create_named_table's try/except Exception, which swallows an
               # inserted raise, so reachability cannot be probed here; the edit still changes
               # the drop decision the target asserts on

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
     False),   # same try/except as above swallows an inserted raise; the edit still forces the
               # drop the target asserts against
]

sys.exit(sweep(CASES))
