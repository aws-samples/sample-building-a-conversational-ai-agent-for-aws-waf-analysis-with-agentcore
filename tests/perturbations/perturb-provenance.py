#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each link in the provenance channel and require `test_provenance_channel.py` to notice.

The channel has four links and the whole point is that none of them is the model: the query layer records,
the streaming loop emits, the frontend attaches, the chip renders. Breaking any one of them puts the
disclosure back where it was, which is present in a tool result and absent from what the user reads.

The `{}`-means-silence case matters as much as the rest. A tool that ran no log query has no window, and
emitting one anyway would be the defect this replaces rather than a smaller version of it.
"""

import sys

from _harness import sweep

T = "tests/test_provenance_channel.py"
S = "tools/session_state.py"
Q = "tools/waf_query.py"
A = "agent.py"

CASES = [
    # Link one: the query layer records nothing.
    ("the CloudWatch path recording no provenance",
     [(Q, '        note_query_provenance("CloudWatch Logs Insights", start_epoch, end_epoch)\n', "")],
     [f"{T}::test_a_log_query_records_the_engine_and_the_window"], True),

    # The union. Keeping the last query's window hides the widest thing that was read.
    ("the window overwritten per query instead of widened",
     [(S, '        p["start"] = min(start_epoch, p["start"]) if "start" in p else start_epoch\n'
          '        p["end"] = max(end_epoch, p["end"]) if "end" in p else end_epoch',
       '        p["start"] = start_epoch\n        p["end"] = end_epoch')],
     [f"{T}::test_many_queries_in_one_tool_call_widen_the_window_and_count"], True),

    ("the query count never incremented, so fifteen queries read as one",
     [(S, '        p["queries"] = p.get("queries", 0) + 1', '        p["queries"] = 1')],
     [f"{T}::test_many_queries_in_one_tool_call_widen_the_window_and_count"], True),

    # The clear on read. Without it the next tool call inherits a window it never queried, which is the
    # 0.24.0 defect in another shape.
    ("the record left behind, so the next tool call inherits this window",
     [(S, '        return _state.pop("provenance", {})', '        return _state.get("provenance", {})')],
     [f"{T}::test_the_record_is_cleared_on_read_so_the_next_tool_cannot_inherit_it"], True),

    # The offset read by a guessed key, which is how it first shipped: silently None.
    # One field instead of a list. Reachable today rather than after the metric funnel: three tools pair
    # a log query with a metric read in the same call, and in `waf_count_eval` the metric read is 435
    # lines below the log query, so the last writer would name the engine that did not produce the answer.
    ("the engine kept as one value again, so a log answer is labelled with the metric read",
     [(S, "        if engine not in engines:\n            engines.append(engine)",
       "        engines[:] = [engine]")],
     [f"{T}::test_one_tool_call_reading_two_engines_names_both"], True),

    ("the chip naming only the first engine, which is the same loss one layer out",
     [("frontend/src/App.jsx", "const engines = (p.engines || []).join(' + ');",
       "const engines = (p.engines || [])[0];")],
     [f"{T}::test_the_frontend_attaches_it_to_the_chip_and_renders_both_window_renderings"], False),

    ("the timezone read by a guessed state key instead of the accessor",
     [(S, '        p["tz_offset"] = get_user_timezone()', '        p["tz_offset"] = _state.get("user_timezone")')],
     [f"{T}::test_a_log_query_records_the_engine_and_the_window"], True),

    # Link two: the event is never emitted, or is emitted without saying which tool call it belongs to.
    #
    # No probe for these three: the emit sits inside an async generator whose other branches need a
    # live Strands agent, so the target reads the source instead and no line of it runs. They were
    # written `"textual"`, which is truthy, so each asked for the probe it was declining.
    ("the event never emitted, so the record reaches nobody",
     [(A, "                if _prov:\n", "                if False:\n")],
     [f"{T}::test_the_event_carries_the_record_and_names_the_tool_call"], False),

    ("an empty record emitted anyway, inventing a window for a config-only tool",
     [(A, "                if _prov:\n", "                if True:\n")],
     [f"{T}::test_the_event_carries_the_record_and_names_the_tool_call"], False),

    ("the event omitting the tool call id, so the frontend cannot place it",
     [(A, '"value": {"toolCallId": payload, **_prov}', '"value": {**_prov}')],
     [f"{T}::test_the_event_carries_the_record_and_names_the_tool_call"], False),

    # The lock. All three merges are read-modify-write and `run_concurrently` reaches them by default.
    ("the lock removed, so concurrent queries lose a count and narrow the window",
     [(S, "    with _provenance_lock:\n        p = _state.setdefault(\"provenance\", {})",
       "    if True:\n        p = _state.setdefault(\"provenance\", {})")],
     [f"{T}::test_concurrent_queries_do_not_lose_a_count_or_narrow_the_window"], True),

    # The position of the Athena record. Moved back below `_ensure_athena_table`, a fan-out job stuck in
    # table resolution when the batch times out writes into the NEXT tool call's record.
    ("the Athena record moved back below table resolution",
     [(Q, '        note_query_provenance("Athena over S3", start_epoch, end_epoch)\n        table = _ensure_athena_table(dest)',
       '        table = _ensure_athena_table(dest)\n        note_query_provenance("Athena over S3", start_epoch, end_epoch)')],
     [f"{T}::test_the_athena_record_lands_before_table_resolution_can_block"], True),
]

sys.exit(sweep(CASES))
