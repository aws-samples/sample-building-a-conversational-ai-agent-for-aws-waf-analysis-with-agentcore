#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each way a patrol detail cell can lose its reason and require `test_partial_details.py`
to notice.

That file had no script here, and the gap it left was not theoretical. Its two groups of tests sit
one layer apart: the poller tests call `_poll_log_query` directly, and the fan-out tests replace all
three detail functions with fakes, so the real ones never run. `_query_content_by_rule` lost the
`_error` row in the space between, because it is the one detail query that parses its rows and the
parse sat inside `except Exception: continue`. The first three cases below are that defect and the
two wrong fixes for it.

The `_poll_log_query` cases follow because the sweep test's precondition is that the poller emits
the sentinel at all: with those branches returning `[]` again, a guard that forwards it correctly
would still have nothing to forward.
"""

import sys

from _harness import sweep

T = "tests/test_partial_details.py"
P = "tools/waf_patrol.py"

GUARD = "    if log_query_error(rows):\n        return rows"
SWEEP = f"{T}::test_every_detail_query_hands_the_failure_on_instead_of_an_empty_cell"
CONTROL = f"{T}::test_a_detail_query_that_answered_still_returns_its_content"

CASES = [
    # The shipped defect, restored. Measured 2026-09-13: `ips` and `uris` came back as `_error`
    # rows and `content` came back `[]`, so the renderer printed two failures and one idle rule.
    ("the content cell swallowing the reason again, i.e. a failed query read as an idle rule",
     [(P, GUARD + "\n", "")],
     [SWEEP], True),

    # The first wrong fix: notice the failure, then drop it. Loud enough to look handled.
    ("the guard noticing the failure and returning an empty cell anyway",
     [(P, GUARD, "    if log_query_error(rows):\n        return []")],
     [SWEEP], True),

    # The second wrong fix, and the one the control exists for: forward every result unparsed.
    # It satisfies every assertion in the sweep case and hands the renderer raw `@message` rows.
    ("the guard made unconditional, so the parse never runs",
     [(P, "    if log_query_error(rows):", "    if True:")],
     [CONTROL], True),

    # The sweep test's precondition, one branch at a time. Without the sentinel there is nothing
    # for the guard above to forward, and a green sweep would say nothing about either.
    ("the poller returning [] on an engine failure, i.e. the silence 2.3 removed",
     [(P, '            return [{"_error": _skip_reason("detail_engine_failed", result["status"])}]',
       "            return []")],
     [SWEEP, f"{T}::test_an_engine_failure_is_distinguished_from_a_budget_timeout"], True),

    ("the poller returning [] when its budget ran out",
     [(P, '            return [{"_error": _skip_reason("detail_budget_exhausted")}]',
       "            return []")],
     [f"{T}::test_a_budget_exhausted_detail_query_says_so_instead_of_no_rows"], True),

    ("a raised call swallowed, which is how the whole class starts",
     [(P, '        return [{"_error": _skip_reason("detail_query_error", type(exc).__name__)}]\n\n\n'
       "def _query_top_ips_by_rule",
       "        return []\n\n\ndef _query_top_ips_by_rule")],
     [f"{T}::test_a_raised_call_says_which_error"], True),
]

sys.exit(sweep(CASES))
