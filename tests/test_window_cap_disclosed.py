# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A query window narrowed from two days to six hours, and the answer said nothing about it.

**Measured on the deployed v0.27.0.** `run_logs_query(query_type="top_blocked_ips",
start_time="2026-09-08T00:00", duration_minutes=2880)`. The clamp used 360 and the answer was
`Query returned 0 results` with three generic reasons: wrong action filter, wrong window, no matching
traffic. The window it actually covered was the quiet six hours before an attack that produced 566,070
blocks later the same day, so the one true reason, that the request had been narrowed, was the one absent.

The model noticed the contradiction and could not confirm it. Its own words: "工具没有任何一句话告诉我它把窗口
改小了", followed by a guess reconstructed from the tool's documentation.

**`aggregate_logs` already solved this**, in the header `_describe` builds, and its docstring says why: the
model chose the parameters and the window was silently clamped, so a header naming the request is how a
caller notices it got the aggregation it asked for over the window it did not. Three other sites had the
same clamp and no header, and the third of them, `analyze_ip`, is the one users reach most.
"""

import pytest

from tools.query_limits import MAX_MINUTES, window_capped_note

CAPPED = window_capped_note(2880, MAX_MINUTES)


def test_a_narrowed_window_says_both_numbers():
    """Both, because either alone leaves the reader doing arithmetic to find out what happened."""
    assert "2,880" in CAPPED and "360" in CAPPED, CAPPED


def test_it_says_what_the_result_does_not_mean():
    """The sentence exists for the answer that follows it. "0 results" over a sixth of the requested window
    is not a statement about the rest, and the reader has to be told that before reading the rows."""
    assert "says nothing about the rest" in CAPPED, CAPPED
    assert "Split the range" in CAPPED, "and what to do instead"


def test_a_window_inside_the_cap_says_nothing():
    """**The check that is always on is not a check.** Most questions ask for less than the cap, and a note
    on every one of them is noise that trains a reader to skip it."""
    assert window_capped_note(60, 60) == ""
    assert window_capped_note(MAX_MINUTES, MAX_MINUTES) == ""


def test_the_note_is_one_sentence_shared_by_every_site():
    """Three tools clamp and each could have worded it differently, which is how two disclosures drift into
    disagreeing about the same limit. `aggregate_logs` keeps its own header, which names the whole request
    rather than only the window, and is not replaced by this."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    callers = set()
    for path in sorted(root.glob("tools/*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "window_capped_note"):
                callers.add(path.name)
    assert callers == {"waf_logs.py", "waf_block_fp.py"}, (
        f"the set of tools disclosing their clamp has changed: {sorted(callers)}. `waf_logs` has two "
        f"sites, `run_logs_query` and `analyze_ip`; `waf_block_fp` has one.")


@pytest.mark.parametrize("module,count", [("waf_logs.py", 2), ("waf_block_fp.py", 1)])
def test_every_clamp_computes_the_note_beside_it(module, count):
    """**Per clamp, not per module**, because `waf_logs` has two and the first fix caught one of them. The
    one it missed was `analyze_ip`, which is the tool a user reaches for first."""
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1] / "tools" / module).read_text()
    clamps = src.count("min(duration_minutes, MAX_MINUTES)")
    notes = src.count("window_capped_note(duration_minutes,")
    assert clamps == count, f"{module} has {clamps} clamps, expected {count}"
    assert notes == clamps, f"{module} clamps {clamps} times and discloses {notes} times"
