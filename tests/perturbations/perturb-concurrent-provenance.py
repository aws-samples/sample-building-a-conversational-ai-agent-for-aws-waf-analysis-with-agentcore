#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Collapse the per-tool-call provenance slot again and require `test_concurrent_tool_provenance.py` to notice.

The first case is the state the deployed v0.27.0 was in: one slot for the whole session, so two concurrent
tool calls wrote into it and one chip named the other tool's WebACL. The second is the fix that looks right
and separates nothing, a thread-local, which both asyncio tasks read as the last writer. The third is the
other boundary, where a `ContextVar` is the one that fails.
"""

import sys

from _harness import sweep

T = "tests/test_concurrent_tool_provenance.py"
S = "tools/session_state.py"
Q = "tools/waf_query.py"
A = "agent.py"

CASES = [
    # The shipped state: one slot for the session.
    ("the record back in one slot for the whole session",
     [(S, '        slot = current_tool_call()\n'
          '        p = _state.setdefault("provenance", {}).setdefault(slot, {})',
       '        slot = ""\n        p = _state.setdefault("provenance", {}).setdefault(slot, {})')],
     [f"{T}::test_two_concurrent_tool_calls_keep_their_own_subject"], True),

    ("the declared subject back in one slot, which is what named the wrong WebACL",
     [(S, '        _state.setdefault("provenance_subject", {})[current_tool_call()] = name',
       '        _state.setdefault("provenance_subject", {})[""] = name')],
     [f"{T}::test_two_concurrent_tool_calls_keep_their_own_subject"], True),

    # The fan-out boundary, where the ContextVar is the half that fails.
    ("the fan-out submitting bare, so a worker's record lands in no tool call's slot",
     [(Q, "    futures = {executor.submit(copy_call_context().run, job): key for key, job in jobs.items()}",
       "    futures = {executor.submit(job): key for key, job in jobs.items()}")],
     [f"{T}::test_the_fan_out_hands_each_job_its_own_context"], False),

    ("one context shared by every job, which raises rather than mislabels",
     [(Q, "    futures = {executor.submit(copy_call_context().run, job): key for key, job in jobs.items()}",
       "    _ctx = copy_call_context()\n"
       "    futures = {executor.submit(_ctx.run, job): key for key, job in jobs.items()}")],
     [f"{T}::test_the_fan_out_hands_each_job_its_own_context"], False),

    # The binding site.
    ("the slot bound after the guard's early return, so unguarded tools lose theirs",
     [(A, "        from tools.session_state import begin_tool_call\n"
          '        begin_tool_call((event.tool_use or {}).get("toolUseId") or "")\n\n'
          '        if event.tool_use["name"] not in self.GUARDED_TOOLS:\n            return',
       '        if event.tool_use["name"] not in self.GUARDED_TOOLS:\n            return\n\n'
       "        from tools.session_state import begin_tool_call\n"
       '        begin_tool_call((event.tool_use or {}).get("toolUseId") or "")')],
     [f"{T}::test_the_slot_is_bound_for_every_tool_and_before_the_guard_returns"], False),

    ("the binding removed, so every tool records into the slot nobody owns",
     [(A, "        from tools.session_state import begin_tool_call\n"
          '        begin_tool_call((event.tool_use or {}).get("toolUseId") or "")\n', "")],
     [f"{T}::test_the_slot_is_bound_for_every_tool_and_before_the_guard_returns"], False),
]

sys.exit(sweep(CASES))
