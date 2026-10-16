# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every tool docstring states the window cap the code applies.

Six said "max 360 for CWL, 60 for Athena". The cap is `MAX_MINUTES` for both engines, and these
docstrings are the tool schemas the model reads, so the model was told it could not ask Athena for
more than an hour. Asserted over every `@tool` function, not over the six that were fixed.
"""

import ast
import pathlib
import re

from tools.query_limits import MAX_MINUTES

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _tool_docstrings():
    for path in sorted((ROOT / "tools").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.FunctionDef) and any(
                    (isinstance(d, ast.Name) and d.id == "tool") or
                    (isinstance(d, ast.Call) and getattr(d.func, "id", "") == "tool")
                    for d in node.decorator_list):
                yield f"{path.name}:{node.name}", ast.get_docstring(node) or ""


def test_every_duration_cap_a_tool_states_is_the_one_the_code_applies():
    lines = [(where, line) for where, doc in _tool_docstrings()
             for line in doc.splitlines() if line.strip().startswith("duration_minutes:")]
    assert len(lines) >= 6, f"only {len(lines)} duration_minutes lines found; the sweep broke"
    stated = [(where, n) for where, line in lines for n in re.findall(r"max (\d+)", line)]
    assert stated, "no tool states a cap, so the equality below checks nothing"
    wrong = [(w, n) for w, n in stated if int(n) != MAX_MINUTES]
    assert not wrong, wrong
    assert not [w for w, line in lines if "for Athena" in line], "a per-engine cap is stated again"
