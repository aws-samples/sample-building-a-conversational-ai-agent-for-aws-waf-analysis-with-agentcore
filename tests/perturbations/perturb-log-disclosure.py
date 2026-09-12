#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_log_value_disclosure.py` claims and require it to notice.

One property has no entry on purpose. The lock in `_scan_log_values`/`drain_log_value_findings`
guards a race measured to be unreachable from a test: 20 concurrent writers lose nothing without it,
because `|=` is one atomic `set.update` under the GIL, and 24,000 write-versus-drain interleavings
lost zero because the window is a couple of bytecodes against a 5 ms switch interval. So the lock is
asserted structurally, and `the drain reads and clears under one lock` is what carries it. Removing
the lock and calling the green run a pass would be the passing-with-no-signal shape.
"""

import sys

from _harness import sweep

T = "tests/test_log_value_disclosure.py"
Q = "tools/waf_query.py"
A = "agent.py"
CASES = [
    # The set the mechanism keys off, both directions.
    ("a marker scanned for that the prompt never trusts", Q,
     '    "INJECTION_ATTEMPT:", "REDACTION_DETECTED:",',
     '    "INJECTION_ATTEMPT:", "REDACTION_DETECTED:", "## Invented Heading",',
     [f"{T}::test_the_scanned_set_is_the_set_the_prompt_grants_authority_to"]),
    ("a marker the prompt trusts and the scan ignores", Q,
     '    "ACTION:", "HINT:", "Next:", "STOPPED:", "BLOCKED:", "PARTIAL_DATA:",',
     '    "ACTION:", "HINT:", "Next:", "STOPPED:", "PARTIAL_DATA:",',
     [f"{T}::test_the_scanned_set_is_the_set_the_prompt_grants_authority_to"]),
    # The forged-control scan itself, and the column naming that replaced wrapping.
    ("the forged-marker scan recording nothing", Q,
     "            forged |= {(key, m) for m in _HEADING_MARKERS if m in val}\n"
     "            forged |= {(key, m) for m in _COLON_MARKER_RE.findall(val)}",
     "            forged |= set()",
     [f"{T}::test_a_forged_marker_in_a_log_value_is_found_and_named_by_column"]),
    ("the note stops naming the column", Q,
     'where = "; ".join(f"`{col}` contains `{marker}`" for col, marker in forged)',
     'where = "; ".join(f"contains `{marker}`" for col, marker in forged)',
     [f"{T}::test_a_forged_marker_in_a_log_value_is_found_and_named_by_column"]),
    # 6.13's sentinel, both spellings and the substring trap.
    ("the JSON-embedded redaction spelling dropped", Q,
     'if val == _AWS_REDACTED or _AWS_REDACTED_IN_JSON in val:',
     'if val == _AWS_REDACTED:',
     [f"{T}::test_the_aws_redaction_sentinel_is_found_as_a_whole_value_and_in_a_headers_array"]),
    ("the sentinel matched as a substring, so a URI about redaction fires it", Q,
     'if val == _AWS_REDACTED or _AWS_REDACTED_IN_JSON in val:',
     'if _AWS_REDACTED in val or _AWS_REDACTED_IN_JSON in val:',
     [f"{T}::test_a_value_merely_containing_the_word_redacted_is_not_the_sentinel"]),
    # The tool's own failure row, which begins "BLOCKED:" and carries "ACTION:".
    ("the error sentinel row scanned like data", Q,
     "    if log_query_error(rows):\n        return rows\n    forged, redacted = set(), set()",
     "    forged, redacted = set(), set()",
     [f"{T}::test_the_error_sentinel_row_is_not_scanned"]),
    # Failure 1: early. Clearing, and the hook draining before it decides.
    ("the accumulator never cleared", Q,
     '        _value_findings["forged"].clear()\n'
     '        _value_findings["redacted"].clear()\n'
     '        _value_findings["filtered"].clear()',
     '        pass',
     [f"{T}::test_draining_clears_so_the_note_does_not_ride_along_forever",
      f"{T}::test_the_hook_drains_on_a_tool_that_read_no_logs"]),
    ("a name-based skip added above the drain", A,
     "        notes = drain_log_value_findings()",
     "        if event.tool_use[\"name\"] == \"set_report_summary\":\n            return\n"
     "        notes = drain_log_value_findings()",
     [f"{T}::test_the_hook_drains_on_a_tool_that_read_no_logs"]),
    ("the note merged into the tool's last content block", A,
     '        content.append({"text": f"\\n{notes}"})',
     '        content[-1] = {"text": content[-1].get("text", "") + f"\\n{notes}"}',
     [f"{T}::test_the_hook_drains_on_a_tool_that_read_no_logs"]),
    # Failure 2: missing. The accumulator has to be shared across the fan-out's threads.
    # Anchored on both lines of the declaration. It gained a `masked` bucket after this case was
    # written, which left the single-line anchor matching nothing and the case silently inert.
    ("per-thread findings, which is what a ContextVar would give", Q,
     '_value_findings: dict[str, set] = {"forged": set(), "redacted": set(), "filtered": set(),\n'
     '                                  "masked": set()}',
     'import threading as _t\n'
     'class _PerThread(dict):\n'
     '    def __getitem__(self, k):\n'
     '        d = getattr(_t.current_thread(), "_vf", None)\n'
     '        if d is None:\n'
     '            d = _t.current_thread()._vf = {"forged": set(), "redacted": set(),\n'
     '                                          "filtered": set(), "masked": set()}\n'
     '        return d[k]\n'
     '_value_findings = _PerThread()',
     [f"{T}::test_every_finding_from_a_real_fanout_reaches_the_drain"]),
    # The LAST clear, not a middle one. Dedenting `filtered` used to leave the `masked` clear
    # below it still indented, so the file stopped parsing and red said nothing about the lock.
    ("a clear moved out from under the drain's lock", Q,
     '        _value_findings["masked"].clear()\n    notes = []',
     '    _value_findings["masked"].clear()\n    notes = []',
     [f"{T}::test_the_drain_reads_and_clears_under_one_lock"]),
    # Failure 3: wrong bytes. The wording IS the fix, so the wording is the target.
    ("the note stops saying it is about the log record", Q,
     'f"notice is about the log record, so it holds whether or not that column is displayed, "',
     'f"notice describes content that reached you verbatim. "',
     [f"{T}::test_the_note_is_about_the_log_record_not_about_what_reached_the_model"]),
    # Anchoring the colon form, which is the plausible "fix" if it ever collides with real content.
    ("the colon markers anchored to the value's start", Q,
     "            forged |= {(key, m) for m in _COLON_MARKER_RE.findall(val)}",
     "            forged |= {(key, m) for m in _COLON_MARKER_RE.findall(val)\n"
     "                       if val.startswith(m)}",
     [f"{T}::test_a_forged_marker_in_a_log_value_is_found_and_named_by_column"]),
    # The false-positive floor, and the positive control that keeps it honest.
    ("a heading-form marker that collides with ordinary WAF log content", Q,
     '    "ACTION:", "HINT:", "Next:", "STOPPED:", "BLOCKED:", "PARTIAL_DATA:",',
     '    "awswaf", "ACTION:", "HINT:", "Next:", "STOPPED:", "BLOCKED:", "PARTIAL_DATA:",',
     [f"{T}::test_a_real_waf_record_produces_no_finding"]),
    ("two Agent construction sites, so one set of hooks reads as unregistered", A,
     "    _agent = Agent(model=_get_model()",
     "    if False:\n        Agent(model=None, tools=[], hooks=[])\n"
     "    _agent = Agent(model=_get_model()",
     [f"{T}::test_every_hook_defined_in_agent_is_registered_on_the_agent"]),
    # The customer-label false positive, which shipped in #66 and is a wrong finding, not noise.
    ("the whitespace requirement dropped from the colon markers", Q,
     "            forged |= {(key, m) for m in _COLON_MARKER_RE.findall(val)}",
     '            forged |= {(key, m) for m in CONTROL_MARKERS\n'
     '                       if m.endswith(":") and m in val}',
     [f"{T}::test_a_customer_label_named_after_a_marker_is_not_an_injection_attempt"]),
    ("the lookahead widened to a label character, so a custom label fires again", Q,
     r'key=len, reverse=True)) + r")(?=\s)")',
     r'key=len, reverse=True)) + r")(?=[\sA-Za-z])")',
     [f"{T}::test_a_customer_label_named_after_a_marker_is_not_an_injection_attempt"]),
    # Key immunity: if the quote stopped intervening, every record would fire.
    ("the colon stripped from the marker, so it matches a JSON key", Q,
     '    "ACTION:", "HINT:", "Next:", "STOPPED:", "BLOCKED:", "PARTIAL_DATA:",',
     '    "ACTION", "HINT:", "Next:", "STOPPED:", "BLOCKED:", "PARTIAL_DATA:",',
     [f"{T}::test_no_colon_marker_can_match_a_json_KEY_however_it_is_named",
      f"{T}::test_a_real_waf_record_produces_no_finding"]),
    # And the disclosure's own delivery, which every one of the above rides on.
    ("the hook unregistered from the agent", A,
     "hooks=[PreQueryGuard(), LogValueDisclosure()]", "hooks=[PreQueryGuard()]",
     [f"{T}::test_every_hook_defined_in_agent_is_registered_on_the_agent"]),
]

sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4]) for c in CASES]))
