#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A Parquet WAF log table you maintain works because table resolution ignores storage format.

Add the first move of a storage-format branch, a read of the SerDe metadata, and the source-level
guard must go red. That guard is what stops a future "reject anything but JSON" from silently
removing the Parquet path verified on 2026-09-17.
"""

import sys

from _harness import sweep

T = "tests/test_parquet_byot.py"
TEXTUAL = "textual"
CASES = [
    (
        "a storage-format branch reading SerdeInfo creeps into table resolution",
        "tools/waf_athena.py",
        "    if _athena_state.get(\"table\"):\n"
        "        return _athena_state[\"table\"]\n"
        "\n"
        "    with _resolve_lock:",
        "    _sd = _athena_state.get(\"SerdeInfo\")  # a format branch would begin by reading this\n"
        "    if _athena_state.get(\"table\"):\n"
        "        return _athena_state[\"table\"]\n"
        "\n"
        "    with _resolve_lock:",
        [f"{T}::test_table_resolution_does_not_branch_on_storage_format"],
        TEXTUAL,  # the target reads the resolution path's source, not its runtime behaviour
    ),
]

# 6-tuple, so probe is False: the target asserts over source text rather than running the line, and
# there is nothing to reach with a bare raise. The 5-tuple cases elsewhere take the reachability probe.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
