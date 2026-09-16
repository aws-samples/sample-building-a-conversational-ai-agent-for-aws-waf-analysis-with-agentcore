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
     [(A, 'format="yyyy/MM/dd/HH", unit="hours"', 'format="yyyy/MM/dd/HH/mm", unit="minutes"')],
     [f"{T}::test_hourly_choice_on_a_mixed_bucket_builds_the_whole_timeline_table"],
     False),   # continuation line inside the dict() literal; no statement fits above it

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

    # The self-heal condemns a stale hourly table but stops disclosing the rebuild, so a moved
    # range and a slow first query after a gap go unexplained.
    ("the hourly self-heal rebuilds silently, without a note",
     [(A, "Recreating it for the hourly choice", "done")],
     [f"{T}::test_hourly_self_heal_discloses_the_rebuild"],
     False),   # f-string fragment inside the discovery_notes append; no statement fits above it

    # The drop-failed branch stops disclosing, so CREATE keeps the stale table and a zero-row
    # pre-cutover answer reads as "no traffic" with nothing to explain it.
    ("a failed drop of the stale hourly table is swallowed silently",
     [(A, "Could not drop the stale", "Removed the stale")],
     [f"{T}::test_hourly_self_heal_discloses_a_failed_drop"],
     False),   # f-string fragment inside the discovery_notes append; no statement fits above it
]

sys.exit(sweep(CASES))
