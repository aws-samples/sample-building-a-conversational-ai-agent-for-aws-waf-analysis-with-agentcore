#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each half of the truncation rule and require `test_truncation_disclosure.py` to notice.

The rule is one line in two places: ask the engine for `limit + 1`, return at most `limit`, and record
that the extra row existed. Each case below removes one of those three and the tool goes back to
rendering a top-N table that reads as the whole set.

The boundary cases matter as much as the removals. Off by one in the cautious direction reports every
full page as truncated, which is the always-on failure that makes a warning worth nothing; off by one
the other way never reports anything.
"""

import sys

from _harness import sweep

T = "tests/test_truncation_disclosure.py"
Q = "tools/waf_query.py"
B = "tools/waf_bypass.py"
L = "tools/waf_logs.py"

CASES = [
    # The shipped behaviour: ask for exactly what the caller wanted and never know there was more.
    ("the CloudWatch path asking for exactly the limit again",
     [(Q, "        rows = _trim(_run_cwl(log_group, cwl, start_epoch, end_epoch, limit + 1),",
       "        rows = _trim(_run_cwl(log_group, cwl, start_epoch, end_epoch, limit),")],
     [f"{T}::test_the_cloudwatch_path_asks_the_engine_for_one_more_than_the_caller_wanted"], True),

    ("the Athena placeholder substituting the plain limit",
     [(Q, '        sql = sql.replace("{LIMIT}", str(limit + 1))',
       '        sql = sql.replace("{LIMIT}", str(limit))')],
     [f"{T}::test_the_athena_path_substitutes_one_more_into_the_limit_placeholder"], True),

    # The record. Without it the extra row is fetched, trimmed, and forgotten.
    ("the note never written, so the extra row is fetched and forgotten",
     [(Q, "    if notes is not None:\n        notes[label] = limit\n", "")],
     [f"{T}::test_the_extra_row_is_cut_back_off_and_recorded",
      f"{T}::test_the_cloudwatch_path_asks_the_engine_for_one_more_than_the_caller_wanted"], True),

    # The trim. Returning the extra row hands the caller one more than it asked for, which a renderer
    # prints, so the table silently grows past its own stated limit.
    ("the extra row returned to the caller instead of trimmed",
     [(Q, "    return rows[:limit]", "    return rows")],
     [f"{T}::test_the_extra_row_is_cut_back_off_and_recorded"], True),

    # Both boundary directions.
    ("the comparison off by one toward crying wolf, so a full page reports truncated",
     [(Q, "    if not rows or len(rows) <= limit:", "    if not rows or len(rows) < limit:")],
     [f"{T}::test_an_exactly_full_answer_records_nothing"], True),

    ("the comparison off by one the other way, so nothing is ever reported",
     [(Q, "    if not rows or len(rows) <= limit:", "    if not rows or len(rows) <= limit + 1:")],
     [f"{T}::test_the_extra_row_is_cut_back_off_and_recorded"], True),

    # The `_error` row. Trimming or flagging it turns a failed query into a partial answer.
    ("a failure read as truncation, which reports a broken query as a partial table",
     [(Q, "    if not rows or len(rows) <= limit:", "    if not rows:")],
     [f"{T}::test_an_error_row_is_neither_trimmed_nor_read_as_truncation",
      f"{T}::test_an_exactly_full_answer_records_nothing"], True),

    # The invariant the maintainer asked for: a failed section must not report only truncation.
    #
    # **This case reported HOLLOW on its first run, and the finding was real.** It anchored to the same
    # filter inside a `truncation_note` helper that nothing called once the design moved to one summary
    # per output. Perturbing a dead function proves nothing, and the dead function itself was the second
    # copy of this filter. It is deleted; the anchor is now the filter that runs.
    ("a failed section reported as merely truncated",
     [(Q, "                 if not (failures and label in failures))",
       "                 if True)")],
     [f"{T}::test_a_section_that_failed_is_never_reported_as_merely_truncated"], True),

    ("the summary emptied, so every cut table reads as the whole set",
     [(Q, '    if not cut:\n        return ""', '    if True:\n        return ""')],
     [f"{T}::test_the_summary_names_every_cut_section_and_its_limit"], True),

    ("the summary emitted unconditionally, which is the always-on failure",
     [(Q, '    if not cut:\n        return ""', '    if False:\n        return ""')],
     [f"{T}::test_the_summary_is_empty_when_nothing_was_cut"], True),

    # The carriage. The record can be perfect and reach nobody.
    #
    # No probe for these three or for the Athena template below: each target reads source across every
    # tool rather than running one, so there is no line for a raise to be reached on. They were written
    # `"textual"`, which is truthy, so each asked for the probe it was declining.
    ("the bypass scan no longer surfacing the record",
     [(B, "    _cut = truncation_summary(notes, failures)\n    if _cut:\n        lines.append(_cut)\n",
       "", 3)],
     [f"{T}::test_every_tool_that_builds_a_table_appends_the_summary"], False),

    ("analyze_ip no longer surfacing the record",
     [(L, "    _cut = truncation_summary(notes, failures)\n    if _cut:\n        lines.append(_cut)\n",
       "")],
     [f"{T}::test_every_tool_that_builds_a_table_appends_the_summary"], False),

    ("a notes dict dropped where a failures dict exists, so that tool cannot report at all",
     [(B, "    notes: dict[str, int] = {}\n", "", 3)],
     [f"{T}::test_the_notes_dict_is_created_wherever_a_failures_dict_is"], False),

    # --- one limit-writing form, added with ROADMAP 7.7 item 3 ---

    # A hardcoded Athena LIMIT caps the SQL at n however many the caller asked for, so the extra row
    # never comes back and that section can never report truncation on the Athena backend.
    ("an Athena template hardcoding its row limit again",
     [(B, "ORDER BY hits DESC LIMIT {{LIMIT}}", "ORDER BY hits DESC LIMIT 3", 5)],
     [f"{T}::test_no_athena_template_hardcodes_its_row_limit"], False),

    ("the CloudWatch query-string limit left at the caller's number",
     [(Q, 'cwl = re.sub(r"\\|\\s*limit\\s+\\d+\\s*$", f"| limit {limit + 1}", query_cwl.strip())',
       'cwl = query_cwl.strip()')],
     [f"{T}::test_the_cloudwatch_query_string_limit_is_rewritten_to_agree"], True),

    ("the limit clause appended to every query, including single-row aggregations",
     [(Q, 'cwl = re.sub(r"\\|\\s*limit\\s+\\d+\\s*$", f"| limit {limit + 1}", query_cwl.strip())',
       'cwl = query_cwl.strip() + f" | limit {limit + 1}"')],
     [f"{T}::test_a_query_with_no_limit_clause_is_left_alone"], True),

    # **The nesting, which is how this feature was half-off from the day it shipped.** The disclosure sat
    # inside `if interpretation:` in `run_logs_query`, and `_interpret_results` answers for 6 of the 37
    # templates, so 31 of them rendered a cut-off table as a complete answer. Both halves arrived in
    # ee73d80 and `analyze_ip` got the unconditional one. No probe: the target reads the source.
    ("the disclosure nested back inside the interpretation branch",
     [(L, "    from tools.waf_query import truncation_summary\n"
          "    _cut = truncation_summary(_notes, _failures)\n"
          "    if _cut:\n        lines.append(_cut)",
       "    if interpretation:\n"
       "        from tools.waf_query import truncation_summary\n"
       "        _cut = truncation_summary(_notes, _failures)\n"
       "        if _cut:\n            lines.append(_cut)")],
     [f"{T}::test_every_tool_that_builds_a_table_appends_the_summary"], False),
]

sys.exit(sweep(CASES))
