# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""One query-window cap, applied everywhere and stated once.

ROADMAP 3.1. Before this there were four numbers for one behaviour: `MAX_MINUTES = 360` in
`waf_logs.py` used at two sites, a bare literal `360` at three more, and a system prompt
telling the model "Athena queries are capped at 60 minutes", which nothing enforced and
which four tools contradicted by defaulting to 180. The enforced number was the one nobody
had written down as a decision.

The tests that matter here are the two sweeps. A single assertion that `MAX_MINUTES == 360`
would pass while a new tool clamps to its own literal, and an assertion about one prompt
line would pass while another line states a different limit.
"""

import ast
import pathlib
import re

import pytest

import agent
from tools import query_limits as Q
from tools import waf_athena as A

TOOLS = sorted(pathlib.Path("tools").glob("*.py"))


def test_the_prompt_states_the_number_the_code_enforces():
    """The defect this closes: the prompt claimed 60 and the code clamped at 360, and
    nothing could notice because the two were written independently."""
    prompt = agent._build_system_prompt(9)
    assert "{MAX_MINUTES}" not in prompt, "placeholder was not rendered"
    assert f"{Q.MAX_MINUTES} min" in prompt


def test_the_prompt_claims_no_window_limit_the_code_does_not_apply():
    """Sweep every number the prompt presents as a per-query window limit and require it to
    be the enforced one. Pinned to the phrasings that carry a cap so a passing run means the
    claims were read, not that the regex found nothing."""
    prompt = agent._build_system_prompt(9)
    claims = re.findall(r"(?:capped at|limited to|max|window cap for both engines:)\s*"
                        r"(\d+)\s*(?:min|minutes)", prompt)
    assert claims, "no window-limit claim found, so this test proves nothing"
    assert set(claims) == {str(Q.MAX_MINUTES)}, claims


def test_every_tool_clamps_to_the_shared_constant():
    """The sweep that survives a new tool. Three of the five original sites were bare
    literals, so `MAX_MINUTES` existing was never the same as `MAX_MINUTES` being used."""
    literal_clamps = []
    for path in TOOLS:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "min"):
                continue
            args = [ast.unparse(a) for a in node.args]
            if "duration_minutes" not in args:
                continue
            if "MAX_MINUTES" not in args:
                literal_clamps.append(f"{path}:{node.lineno}: min({', '.join(args)})")
    # The log-filter probe is a deliberate 60-minute existence check, not a window cap:
    # it asks "are there any ALLOW rows at all" before the scan commits to anything.
    allowed = [c for c in literal_clamps if "waf_bypass.py" in c and "60" in c]
    assert len(allowed) == 1, literal_clamps
    assert not [c for c in literal_clamps if c not in allowed], literal_clamps


def test_the_cap_is_defined_once():
    """`MAX_POLL` was five disagreeing constants before it was one. Same shape, so the same
    guard: only `query_limits` may define this name."""
    definers = [str(p) for p in TOOLS
                if re.search(r"^MAX_MINUTES\s*=", p.read_text(), re.M)]
    assert definers == ["tools/query_limits.py"], definers


# --- the retry advice, which is where partition granularity actually matters ---


@pytest.fixture(autouse=True)
def _clean_state():
    yield
    A.reset_table_cache()


@pytest.mark.parametrize("fmt,granularity", [
    ("yyyy/MM/dd/HH/mm", "minutes"),
    ("yyyy/MM/dd/HH", "hours"),
    ("yyyy/MM/dd", "days"),
])
def test_narrowing_advice_follows_the_partition_granularity(fmt, granularity):
    """On an hourly table a 5-minute request and a 60-minute request scan identical bytes,
    measured in docs/hourly-vs-minute-partitioning.md. "Retry with a quarter of the window"
    is then advice that cannot work, and it spends the one retry the message allows."""
    A._athena_state["partition_format"] = fmt
    assert A._partition_granularity(fmt) == granularity, "fixture does not reach the branch"
    advice = Q._narrowing_advice("Athena")
    if granularity == "minutes":
        assert "a quarter of the window" in advice
    else:
        assert "a quarter of the window" not in advice
        assert granularity[:-1] in advice
        assert "get_waf_overview" in advice


def test_cloudwatch_keeps_the_plain_advice_whatever_athena_resolved():
    """CloudWatch Logs Insights has no partitions, so none of the reasoning transfers. This
    also pins that the branch keys on the engine and not merely on the resolved table."""
    A._athena_state["partition_format"] = "yyyy/MM/dd/HH"
    assert "a quarter of the window" in Q._narrowing_advice("CloudWatch Logs Insights")


def test_advice_falls_back_when_no_table_is_resolved():
    A.reset_table_cache()
    assert A._athena_state.get("partition_format") is None
    assert "a quarter of the window" in Q._narrowing_advice("Athena")


def test_the_timeout_message_carries_the_granularity_advice():
    """End to end through the message the model actually receives, because the advice being
    correct in isolation says nothing about it reaching the caller.

    The reset is required, not defensive. `poll_timeout_message` only gives narrowing advice
    on the FIRST consecutive timeout and withdraws it after that, and the counter lives in
    session state shared across the whole suite. Written without this the test passed alone
    and failed in the suite, and the first attempt reset the wrong key name."""
    from tools.session_state import note_query_success, _state
    note_query_success()
    assert _state["query_timeouts"] == 0
    A._athena_state["partition_format"] = "yyyy/MM/dd/HH"
    msg = Q.poll_timeout_message("Athena", Q.STOP_CONFIRMED)
    assert "partitioned by hour" in msg
    assert "a quarter of the window" not in msg
    note_query_success()
