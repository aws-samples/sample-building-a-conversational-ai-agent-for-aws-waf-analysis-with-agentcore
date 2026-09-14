#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the `SOURCE:` line and require `test_query_provenance.py` to notice.

The line existed for two releases with six tests and no perturbation script, so nothing had shown those
tests can fail. It moved on 2026-09-14 from two call sites inside `waf_logs` to one hook at
`AfterToolCallEvent`, which is what made most of these cases expressible: a property spread across two
renderers is broken two ways, and one held in a hook is broken once.

The last case is the pairing. A disclosure the model is never told to read is a string in a log, and an
instruction naming a marker nothing emits is worse than neither.
"""

import sys

from _harness import sweep

A = "agent.py"
S = "tools/session_state.py"
L = "tools/waf_logs.py"
T = "tests/test_query_provenance.py"

CASES = [
    ("the line never appended, so a wrong-WebACL answer reads like a right one",
     [(A, '        content.append({"text": f"\\n{provenance_source_line(record)}"})\n', "")],
     [f"{T}::test_every_tool_result_that_queried_carries_the_line"], True),

    ("appended on every tool call, so a config read claims a query it never ran",
     [(A, "        if not record:\n            return", "        if False:\n            return")],
     [f"{T}::test_every_tool_result_that_queried_carries_the_line"], True),

    ("the line merged into the tool's last block, where it can land inside a table",
     [(A, '        content.append({"text": f"\\n{provenance_source_line(record)}"})',
       '        content[-1] = {"text": content[-1].get("text", "") + f"\\n{provenance_source_line(record)}"}')],
     [f"{T}::test_every_tool_result_that_queried_carries_the_line"], True),

    # Two readers, one record, and only the streaming loop may clear it.
    ("the hook draining the record, leaving the user's chip empty",
     [(A, "        record = peek_query_provenance()", "        record = take_query_provenance()"),
      (A, "from tools.session_state import peek_query_provenance, provenance_source_line",
       "from tools.session_state import take_query_provenance, provenance_source_line")],
     [f"{T}::test_the_hook_leaves_the_record_for_the_chip_to_read"], False),

    # The old emitter's shape: derive the engine from session state when the line is rendered, which
    # answers "what would a query use now" rather than "what did this one use".
    ("the engine re-derived from state at render time instead of read from the record",
     [(S, '    engines = " + ".join(p.get("engines") or []) or "no engine"',
       '    from tools.waf_query import get_log_type\n'
       '    engines = {"cwl": "CloudWatch Logs", "s3": "Athena over S3"}.get(get_log_type(), "no engine")')],
     [f"{T}::test_the_engine_named_is_the_one_the_query_used"], True),

    ("the subject ignored, so an explicit log group is reported as the session's WebACL",
     [(S, '        p["webacl"] = subject or get_webacl_name()', '        p["webacl"] = get_webacl_name()')],
     [f"{T}::test_an_explicit_log_group_is_named_instead_of_the_session_webacl"], True),

    # The one query in the repository outside the funnel. Nothing else would notice.
    ("the explicit-log-group path no longer recording what it queried",
     [(L, '        note_query_provenance("CloudWatch Logs Insights", start_epoch, end_epoch,\n'
          '                              subject=f"log group {log_group}")\n', "")],
     [f"{T}::test_an_explicit_log_group_is_named_instead_of_the_session_webacl"], False),

    ("an unset context rendered as a sentence that looks like it names something",
     [(S, """    return (f"SOURCE: {p.get('webacl') or '(none set)'} via {engines}. That is the WebACL from the last \"""",
       """    return (f"SOURCE: {p.get('webacl')} via {engines}. That is the WebACL from the last \"""")],
     [f"{T}::test_an_unset_context_says_so_rather_than_looking_confident"], True),

    # The pairing. Either half alone is worthless, so the marker is perturbed on the emitter's side and
    # the prompt's side is what goes red.
    ("the marker renamed on the emitter while the prompt still names SOURCE",
     [(S, '    return (f"SOURCE: ', '    return (f"ORIGIN: ')],
     [f"{T}::test_the_prompt_tells_the_model_to_read_the_source_line"], True),
]

sys.exit(sweep(CASES))
