# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The zero-result message on the Athena backend.

Zero rows is the one answer that says nothing about the table that produced it, and on
a mixed bucket it is the *expected* answer for any window before the cutover. So the
resolution block has to appear here and not only beside a result set.

This drives the real `run_logs_query` with the query layer stubbed out, rather than
testing the block builder on its own, because the defect was the wiring: the early
return on zero rows sat above the block and skipped it.
"""

import pytest

from tools import session_state, waf_athena as A, waf_logs, waf_query


@pytest.fixture
def zero_rows(monkeypatch):
    """An Athena-backed session whose query comes back empty, over a mixed bucket."""
    monkeypatch.setattr(waf_query, "query_logs", lambda *a, **k: [])
    monkeypatch.setattr(waf_query, "get_log_type", lambda: "s3")
    monkeypatch.setattr(waf_logs, "get_log_destination", lambda: "arn:aws:s3:::bkt")
    A.reset_table_cache()
    # Left as a resolved table rather than resolving one: this is about what the message
    # says, and the coarse-partition gate still runs for real against this format.
    A._athena_state.update({
        "table": "userdb.waf", "partition_format": "yyyy/MM/dd/HH/mm",
        "table_choice": "Using userdb.waf.",
        "layout_mixed": True, "layout_cutover": "2026/01/05",
        "layout_data_start": "2022/03/07",
    })
    yield
    A.reset_table_cache()
    session_state._state.clear()


def _run(**kw):
    args = dict(query_type="top_blocked_ips", start_time="2026-09-07T14:00",
                duration_minutes=60)
    args.update(kw)
    return waf_logs.run_logs_query._tool_func(**args)


def test_zero_results_names_the_table_and_the_history_it_cannot_reach(zero_rows):
    out = _run()
    # The precondition: this is the empty-result path, not a formatted result set.
    assert "0 results" in out
    assert "TABLE: Using userdb.waf." in out
    assert "2026/01/05" in out, "the cutover the three suggested reasons cannot explain"
    assert "2022/03/07" in out


def test_the_three_suggested_reasons_are_still_there(zero_rows):
    """The block is added beside them, not instead of them. Most zero-result queries
    really are a wrong filter or a quiet window."""
    out = _run()
    assert "Possible reasons:" in out
