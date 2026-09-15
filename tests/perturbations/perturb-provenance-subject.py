#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the declared subject and require `test_provenance_subject.py` to notice.

Every case here is a state that shipped or nearly shipped. The first is the measured defect itself: the
funnel recorded `get_webacl_name()` while five tools took their own `webacl_name`, so a metric answer about
one WebACL carried another's name. The pin's lifetime cases are the same shape as the accumulation the
hook's drain fixed in #100, one scope smaller: a subject that survives its tool call labels the next one's
numbers.

The ordering case is the one no output would show. A declaration moved below the first read leaves that
read recorded against the session's WebACL, and `webacl` keeps its first value, so the late declaration
never appears at all.
"""

import sys

from _harness import sweep

T = "tests/test_provenance_subject.py"
S = "tools/session_state.py"
M = "tools/waf_metrics.py"
O = "tools/waf_overview.py"

CASES = [
    # The measured defect. The record read session state while the tool used its argument.
    ("the declared subject ignored, so a metric answer carries another WebACL's name",
     [(S, '        p["webacl"] = subject or declared or get_webacl_name()',
       '        p["webacl"] = subject or get_webacl_name()')],
     [f"{T}::test_a_metric_read_names_the_declared_webacl_not_the_session_one"], True),

    # The wording half, which is what told the model to discard a correct answer.
    ("the declaration not counted as explicit, so the line orders a context reload that changes nothing",
     [(S, '        p["subject_explicit"] = bool(subject or declared)',
       '        p["subject_explicit"] = bool(subject)')],
     [f"{T}::test_the_line_does_not_tell_the_model_to_reload_a_context_the_tool_never_read"], True),

    # **Lifetime, and what these three guard changed on 2026-09-15.** Before the record was keyed by tool
    # call they prevented the next call inheriting this one's subject; keying makes that structural, and the
    # sweep reported all three HOLLOW, which was right. What removing the drain still changes is that two
    # dict entries per tool call are never reclaimed, and this runs as a server. So they target the growth
    # bound now, in the file that owns the keying.
    ("the pin never cleared, so a finished tool call's slot is never reclaimed",
     [(S, '        (_state.get("provenance_subject") or {}).pop(tool_use_id, None)\n'
          "        if record and tool_use_id:", "        if record and tool_use_id:")],
     ["tests/test_concurrent_tool_provenance.py::test_a_finished_tool_call_leaves_nothing_in_either_slot_dict"], True),

    ("the pin cleared only when a query ran, so a refused tool call's slot is never reclaimed",
     [(S, '        (_state.get("provenance_subject") or {}).pop(tool_use_id, None)\n'
          "        if record and tool_use_id:",
       "        if record and tool_use_id:\n"
       '            (_state.get("provenance_subject") or {}).pop(tool_use_id, None)')],
     ["tests/test_concurrent_tool_provenance.py::test_a_finished_tool_call_leaves_nothing_in_either_slot_dict"], True),

    ("the fallback drain leaving the pin, so the leak moves to the path that keeps the chip working",
     [(S, '        (_state.get("provenance_subject") or {}).pop(tool_use_id or "", None)\n'
          "        if tool_use_id is not None:", "        if tool_use_id is not None:")],
     ["tests/test_concurrent_tool_provenance.py::test_the_fallback_reader_reclaims_the_slot_too"], True),

    # Declaring must not invent a record, or every config-only tool claims a query.
    ("the declaration creating the record, so a tool that queried nothing claims a source",
     [(S, '        _state.setdefault("provenance_subject", {})[current_tool_call()] = name',
       '        _state.setdefault("provenance_subject", {})[current_tool_call()] = name\n'
       '        _state.setdefault("provenance", {}).setdefault(current_tool_call(), {})')],
     [f"{T}::test_declaring_creates_no_record_so_a_tool_that_queries_nothing_stays_silent"], True),

    # The invariant that catches the seventh tool. Both remaining cases target tests that read source
    # rather than run it, so no probe: any insertion at that position turns them red.
    ("one tool left without a declaration, which is the state all five were in",
     [(O, "    declare_query_subject(webacl_name)\n", "")],
     [f"{T}::test_every_tool_taking_a_webacl_name_says_which_one_it_queried"], False),

    # Moved rather than deleted, so the tool still declares and the case is about order alone. The
    # membership test above stays green under this one, which is why order needs its own assertion.
    ("a declaration below the first read, where it can never reach the record",
     [(M, '    declare_query_subject(webacl_name)\n    if region == "auto":', '    if region == "auto":'),
      (M, '    client = get_client("cloudwatch", region_name=region)',
       '    client = get_client("cloudwatch", region_name=region)\n'
       "    declare_query_subject(webacl_name)")],
     [f"{T}::test_the_declaration_comes_before_the_first_query"], False),
]

sys.exit(sweep(CASES))
