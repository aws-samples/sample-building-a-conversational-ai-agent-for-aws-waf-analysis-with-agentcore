#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_redacted_filter.py` claims and require it to notice."""

import sys

from _harness import sweep

T = "tests/test_redacted_filter.py"
Q = "tools/waf_query.py"
C = "tools/waf_config.py"
G = "tools/waf_aggregate.py"
L = "tools/waf_logs.py"
CASES = [
    # The config read. Each accepted FieldToMatch type, and the lowercasing whose failure is silent.
    ("Method dropped from the normaliser", C,
     'for kind in ("UriPath", "QueryString", "Method"):',
     'for kind in ("UriPath", "QueryString"):',
     [f"{T}::test_every_accepted_field_type_is_normalised_and_nothing_else_is"]),
    ("the normaliser inventing a type it should skip", C,
     '        for kind in ("UriPath", "QueryString", "Method"):',
     '        for kind in ("UriPath", "QueryString", "Method", "Body"):',
     [f"{T}::test_every_accepted_field_type_is_normalised_and_nothing_else_is"]),
    ("header names no longer lowercased, so a config spelling Host misses silently", C,
     'name = (header.get("Name") or "").strip().lower()',
     'name = (header.get("Name") or "").strip()',
     [f"{T}::test_a_header_name_is_lowercased_because_http_header_names_are_case_insensitive"]),
    ("duplicates no longer collapsed", C,
     "    return tuple(dict.fromkeys(out))", "    return tuple(out)",
     [f"{T}::test_duplicate_entries_collapse"]),
    ("`redacted` initialised inside the try, so logging-off raises", C,
     "    redacted = ()\n    try:", "    try:",
     [f"{T}::test_the_config_read_survives_logging_being_disabled"]),
    # The declarations, both directions.
    ("a filter that reads a redactable field loses its declaration", G,
     '        redactable_filter=("Method",)),', '        ),',
     [f"{T}::test_every_filter_that_reads_a_redactable_field_declares_it"]),
    ("a template that filters on the Host header loses its declaration", L,
     '        "redactable_filter": ["SingleHeader:host"],\n'
     '        "description": "HTTP method distribution for a host",',
     '        "description": "HTTP method distribution for a host",',
     [f"{T}::test_every_filter_that_reads_a_redactable_field_declares_it"]),
    ("a declaration on a field the predicate never reads, which is #62's shape", G,
     '        redactable_filter=("Method",)),', '        redactable_filter=("UriPath",)),',
     [f"{T}::test_no_declaration_names_a_field_the_predicate_does_not_read",
      f"{T}::test_every_filter_that_reads_a_redactable_field_declares_it"]),
    # The notice itself.
    ("the notice fires regardless of what the config redacts", Q,
     "    hit = {d for d in (declared or []) if d in get_redacted_fields()}",
     "    hit = {d for d in (declared or [])}",
     [f"{T}::test_the_notice_fires_only_when_the_config_actually_redacts_that_field"]),
    ("the zero-row sentence dropped from the notice", Q,
     '            f"the row count is simply lower. **A zero-row result here does NOT mean no such traffic.** "',
     '            f"the row count is simply lower. "',
     [f"{T}::test_the_notice_says_a_zero_row_result_does_not_mean_no_traffic"]),
    ("the notice offers no way forward", Q,
     '            f"counts, and offer to group BY that field instead of filtering on it, which keeps the "',
     '            f"counts. Also worth noting that "',
     [f"{T}::test_the_notice_says_a_zero_row_result_does_not_mean_no_traffic"]),
    ("the notice merged into the zero-row message instead of appended", "agent.py",
     '        content.append({"text": f"\\n{notes}"})',
     '        content[-1] = {"text": content[-1].get("text", "") + f"\\n{notes}"}',
     [f"{T}::test_the_notice_reaches_the_model_through_the_hook_not_a_render_branch"]),
    # The wiring, which is what a helper-only test would miss.
    ("the call dropped from the aggregate filter loop", G,
     "        note_redacted_filter(spec.redactable_filter)",
     "        pass",
     [f"{T}::test_running_a_declared_filter_records_it_without_reaching_aws"]),
    ("the except widened, which makes the () default fail-open", C,
     "    except client.exceptions.WAFNonexistentItemException:",
     "    except Exception:",
     [f"{T}::test_the_default_is_safe_only_because_the_except_is_narrow"]),
    ("the reset fixture naming its buckets again", "tests/test_log_value_disclosure.py",
     "    for bucket in q._value_findings.values():\n        bucket.clear()",
     '    q._value_findings["forged"].clear()\n    q._value_findings["redacted"].clear()',
     ["tests/test_log_value_disclosure.py::test_the_reset_fixture_clears_every_bucket"]),
    ("the accumulator bucket not cleared under the lock", Q,
     '        _value_findings["filtered"].clear()', '        pass',
     ["tests/test_log_value_disclosure.py::test_the_drain_reads_and_clears_under_one_lock"]),
]

sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4]) for c in CASES]))
