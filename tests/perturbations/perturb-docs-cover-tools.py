#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each half of the docs-cover-tools guard and require the test to notice.

The guard exists because the audit it replaces was a word-frequency scan that missed `aggregate_logs`
for six months. Two ways to reintroduce that blind spot: delete a capability's describing phrase from the
doc (a described tool goes silent), or add a tool to the registry without classifying it (a new tool ships
undocumented). Each case restores one.

No reachability probe: one case reads `docs/capabilities.md` as text, and the other edits the `_TOOLS`
list literal, where a bare `raise` cannot be inserted. Each says so.
"""

import sys

from _harness import sweep

T = "tests/test_docs_cover_tools.py"
CAP = "docs/capabilities.md"
AGENT = "agent.py"

CASES = [
    # A capability's describing sentence deleted: the tool it described is now undiscoverable, which is
    # exactly the aggregate_logs state. `run_logs_query` on `pytest file::name` reruns every param, so
    # one missing phrase reddens the node.
    ("aggregate_logs's description removed from capabilities.md",
     [(CAP, "the agent composes an aggregation", "the agent runs a query")],
     [f"{T}::test_every_user_facing_tool_is_described"],
     False),   # textual: the target reads capabilities.md

    ("investigate_injection's description removed from capabilities.md",
     [(CAP, "injection attacks were blocked", "requests were seen")],
     [f"{T}::test_every_user_facing_tool_is_described"],
     False),   # textual: the target reads capabilities.md

    # A registered tool dropped from _TOOLS: `classified - registered` is non-empty, the stale branch of
    # the completeness guard. Standing in for the reverse, a NEW tool added and left unclassified, which
    # cannot be written as a text edit because the new tool would have to be importable.
    ("a tool removed from the registry, so the classification set no longer matches",
     [(AGENT, "          set_log_granularity, aggregate_logs, investigate_injection,",
       "          set_log_granularity, investigate_injection,")],
     [f"{T}::test_every_registered_tool_is_classified"],
     False),   # textual anchor on the _TOOLS list literal; no statement can be inserted into it
]

sys.exit(sweep(CASES))
