#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Remove each fix and require the tests that cover it to fail.

`ast.parse` runs before pytest on every perturbation: a perturbation that breaks the
build fails at collection instead of at the assertion, and the red output looks like
proof. Reports INVALID rather than PASS in that case.
"""

import sys

from _harness import sweep

CASES = [
    (
        "name-only validation, i.e. what the code did before step 3",
        "tools/waf_athena.py",
        "    for col, (tier, kind, fields, why) in _COLUMN_SPEC.items():",
        "    for col in ('action', 'httprequest'):\n"
        "        if col not in types:\n"
        "            return (f'{name}: missing WAF log column `{col}`.', None)\n"
        "    return None, None\n"
        "    for col, (tier, kind, fields, why) in _COLUMN_SPEC.items():",
        ["tests/test_schema_validation.py"],
    ),
    (
        "the type check dropped, names still checked",
        "tools/waf_athena.py",
        "        if not _TYPE_KINDS[kind](types[col]):",
        "        if False:",
        ["tests/test_schema_validation.py::test_a_required_column_is_refused_when_wrongly_typed"],
    ),
    (
        "_struct_fields as a substring test instead of a depth-aware parse",
        "tools/waf_athena.py",
        "    depth, field, out = 0, \"\", []",
        "    return [p.split(':')[0].strip() for p in t.split(',') if ':' in p]\n"
        "    depth, field, out = 0, \"\", []",
        ["tests/test_schema_validation.py::test_struct_fields_reads_only_the_top_level",
         "tests/test_schema_validation.py::test_a_nested_name_field_does_not_satisfy_labels"],
    ),
    (
        "labels back in the required tier, i.e. refusing a pre-labels table",
        "tools/waf_athena.py",
        '    "labels": (OPTIONAL, "array_struct", ("name",),',
        '    "labels": (REQUIRED, "array_struct", ("name",),',
        ["tests/test_schema_validation.py::test_a_table_predating_labels_is_accepted"],
    ),
    (
        "webaclid required unconditionally, i.e. refusing a scoped table over it",
        "tools/waf_athena.py",
        '    "webaclid": (SHARED_ONLY, "string", (),',
        '    "webaclid": (REQUIRED, "string", (),',
        # Emptying SHARED_ONLY makes its own sweeps SKIP rather than fail, which is why
        # the partition guard is the target that has to go red here.
        ["tests/test_schema_validation.py::test_every_tier_is_non_empty_and_they_partition_the_spec",
         "tests/test_schema_validation.py::test_a_shared_only_column_is_not_asked_for_on_a_scoped_table"],
    ),
    (
        "the wiring inverted: shared_location=_is_webacl_scoped, i.e. drop the `not`",
        "tools/waf_athena.py",
        "        name, types, shared_location=not _is_webacl_scoped(location))",
        "        name, types, shared_location=_is_webacl_scoped(location))",
        ["tests/test_table_resolution.py::test_a_shared_location_table_must_declare_webaclid",
         "tests/test_table_resolution.py::test_a_webacl_scoped_table_does_not_need_webaclid"],
    ),
    (
        "the wiring pinned true, i.e. the constant a single-direction test allows",
        "tools/waf_athena.py",
        "        name, types, shared_location=not _is_webacl_scoped(location))",
        "        name, types, shared_location=True)",
        ["tests/test_table_resolution.py::test_a_webacl_scoped_table_does_not_need_webaclid"],
    ),
    (
        "the note as two independently sorted lists instead of pairs",
        "tools/waf_athena.py",
        '                  + "; ".join(f"`{col}`, needed by {why}" for col, why in lost)',
        '                  + ", ".join(f"`{col}`" for col, _ in lost) + ", so these will fail: "\n'
        '                  + "; ".join(sorted({why for _, why in lost}))',
        ["tests/test_schema_validation.py::test_the_note_keeps_each_column_beside_its_own_reason"],
    ),
    (
        "a why written as a full clause, i.e. the ungrammatical message",
        "tools/waf_athena.py",
        '                  \'every window bound, as `"timestamp" BETWEEN` epoch milliseconds\'),',
        '                  \'every window bound is `"timestamp" BETWEEN` epoch milliseconds\'),',
        ["tests/test_schema_validation.py::test_every_why_splices_into_both_sentence_frames"],
    ),
    (
        "the hand-listed four-column fixture, i.e. the trap the derivation avoids",
        "tests/test_table_resolution.py",
        "WAF_COLS = _cols_from_ddl()",
        "WAF_COLS = [{\"Name\": \"action\", \"Type\": \"string\"},\n"
        "            {\"Name\": \"httprequest\", \"Type\": \"struct<clientip:string>\"},\n"
        "            {\"Name\": \"webaclid\", \"Type\": \"string\"},\n"
        "            {\"Name\": \"timestamp\", \"Type\": \"bigint\"}]",
        ["tests/test_schema_validation.py::test_the_agents_own_schema_is_clean"],
    ),
]

sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4]) for c in CASES]))
