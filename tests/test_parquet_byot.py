# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A Parquet WAF log table you maintain is queried like a JSON one, and this pins why it can be.

Verified end to end on 2026-09-17 against a Parquet table whose nested fields kept AWS WAF's original
camelCase (`httpRequest.clientIp`): Athena's Parquet reader matches column names case-insensitively, so
the agent's lowercase SQL read them and every query shape returned real values. That validation needs a
Parquet object in S3 and cannot run in CI, so what CI holds is its structural precondition: table
resolution never inspects the storage format, so a future "reject anything but JSON" check goes red here
rather than silently removing a path that works today."""

import inspect

from tools import waf_athena


def test_table_resolution_does_not_branch_on_storage_format():
    """A storage-format branch would have to read one of the Glue StorageDescriptor keys that name the
    SerDe or the input and output formats. None of the resolution path reads any of them: it accepts a
    table on its partition projection, not on how the bytes are stored."""
    path = "".join(inspect.getsource(fn) for fn in (
        waf_athena.resolve_log_table,
        waf_athena._resolve_log_table_locked,
        waf_athena._find_existing_table,
        waf_athena._table_metadata,  # reads a candidate table's projection; on the selection path
        waf_athena._cross_check_declared,
        waf_athena._record_table,
    ))
    for key in ("SerdeInfo", "InputFormat", "OutputFormat", "SerializationLib"):
        assert key not in path, (
            f"table resolution reads {key!r}, which is how a storage-format branch begins; keep it "
            f"format-agnostic so a Parquet table you maintain resolves like a JSON one")
