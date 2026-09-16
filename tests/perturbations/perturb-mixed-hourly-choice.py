#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the ROADMAP 3.2 mixed-bucket hourly build and require the tests to notice.

On a bucket that holds both hourly (pre-cutover) and minute-level (post-cutover) partition
eras, the default reads the recent minute era; on an explicit hourly choice the agent builds
its own hourly table over the whole timeline so the pre-cutover history is reachable. Four
properties carry that, and a passing test suite has to fail when each is removed: the build
only fires on a mixed bucket (else it coarsens a bucket for nothing), it builds an HOURLY
table (not minute), its range starts at the oldest data (the whole timeline, not the minute
era's start), and the tool refuses to coarsen a single-layout bucket. A fifth guards the
prose: the resolution block offers the agent's build and no longer tells the user to write
DDL, which is what "retire the manual recipe" means.

The two `if`-header cases probe; the three that land on a continuation line inside a
multi-line call or f-string cannot take an inserted statement, so they pass probe=False and
say so, per the same rule as the rest of the suite.
"""

import sys

from _harness import sweep

A = "tools/waf_athena.py"
L = "tools/waf_logs.py"
T = "tests/test_table_resolution.py"

CASES = [
    # The build fires for any hourly choice, mixed bucket or not: drop the `mixed` gate and a
    # pure minute-level bucket gets coarsened to hourly for no history to gain.
    ("the mixed gate dropped, so the hourly build fires on a single-layout bucket too",
     [(A, '    if _athena_state.get("layout_choice") == "hourly" and layout is not None and layout["mixed"]:',
       '    if _athena_state.get("layout_choice") == "hourly" and layout is not None:')],
     [f"{T}::test_hourly_choice_is_ignored_on_a_single_layout_bucket"],
     True),

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

    # The tool's guard for a single-layout bucket is dropped, so an hourly choice coarsens it
    # rather than being refused. (Guard is `if not mixed`, after the resolved check.)
    ("the tool no longer refuses hourly on a single-layout bucket",
     [(L, "    if not mixed:", "    if False:")],
     [f"{T}::test_tool_refuses_hourly_on_a_single_layout_bucket"],
     True),

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
]

sys.exit(sweep(CASES))
