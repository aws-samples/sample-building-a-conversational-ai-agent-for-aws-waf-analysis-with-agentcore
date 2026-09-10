# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A multi-step tool's steps are only reachable if the prompt routes them.

`detect_bypass` dispatches on a `step` argument, and `agent.py` enumerates those steps in
three separate places: an intent-to-step routing list, a shortcut list, and a "Key workflow"
walkthrough. Adding `ja4_ips` in 3.4 updated none of them, so the step existed and nothing
told the model when to reach for it. The scan's own output named it, which covers the path
after a scan, but a user asking "which IPs share that fingerprint" had nowhere to be routed.

Structural for the usual reason: a behavioural test would cover the steps someone remembered,
and the defect is forgetting one.
"""

import ast
import pathlib
import re

import pytest

import agent

ROOT = pathlib.Path(__file__).resolve().parents[1]

# tool -> the module that defines it. Only tools that dispatch on a `step` argument.
STEP_TOOLS = {
    "detect_bypass": "tools/waf_bypass.py",
    "evaluate_count_rules": "tools/waf_count_eval.py",
    "investigate_block_fp": "tools/waf_block_fp.py",
}


def _dispatched_steps(path: str, func: str) -> set[str]:
    """The literal step names a tool compares against, read out of its dispatch.

    From the AST rather than a regex over the file, so a step name that appears in a docstring
    or an error message is not mistaken for one the code accepts."""
    tree = ast.parse((ROOT / path).read_text())
    target = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == func), None)
    assert target, f"{func} not found in {path}"
    steps = set()
    for node in ast.walk(target):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) \
                and node.left.id == "step":
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                    steps.add(comparator.value)
    return steps


@pytest.mark.parametrize("tool,path", sorted(STEP_TOOLS.items()))
def test_the_prompt_names_every_step_the_tool_dispatches(tool, path):
    """One notch stronger than the invariant strictly needs, and that is a known trade.

    A step could legitimately be **output-discovered**: reached only from a tool's own output
    rather than from prompt routing, which is how `ja4_ips` was first going to work. Such a step
    would fail here and the wrong fix is deleting the assertion. The right one is already in this
    suite: an exemption that asserts its own necessity, the way `BACKFILL_FLOOR` in
    `test_release_metadata.py` fails once nothing needs excusing. Add the step to a named
    `OUTPUT_DISCOVERED` set plus a test that its own tool's output does name it, so the exemption
    cannot quietly widen."""
    steps = _dispatched_steps(path, tool)
    assert steps, f"no step literals parsed from {tool}, so this test proves nothing"
    prompt = agent._build_system_prompt(9)
    missing = sorted(s for s in steps if s not in prompt)
    assert not missing, f"{tool} dispatches these and the prompt never names them: {missing}"


def test_the_prompt_names_no_step_the_tool_does_not_dispatch():
    """The other direction, which catches a renamed or deleted step still being advertised. A
    prompt that routes the model to a step the code no longer has produces an error the model
    then has to interpret, and the routing line reads authoritative."""
    prompt = agent._build_system_prompt(9)
    for tool, path in sorted(STEP_TOOLS.items()):
        steps = _dispatched_steps(path, tool)
        advertised = set(re.findall(rf'{tool}\(step="([a-z_]+)"', prompt))
        advertised |= set(re.findall(rf"{tool}\(step='([a-z_]+)'", prompt))
        assert advertised, f"the prompt routes no {tool} step, so this direction proves nothing"
        assert not (advertised - steps), \
            f"prompt routes {tool} steps that do not exist: {sorted(advertised - steps)}"
