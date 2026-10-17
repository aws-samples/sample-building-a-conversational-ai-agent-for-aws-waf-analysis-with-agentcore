#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_kb_antiddos_exempt.py` fail? The corrected statements put back as they were."""

import sys

from _harness import sweep

T = "tests/test_kb_antiddos_exempt.py"
K = "kb-docs/antiddos-amr.md"

CASES = [
    ("the path-anchored form recommended again",
     [(K, "- Anchor a path branch after the host: `^[^/]+\\/api(\\/|$)`",
       "- Always anchor API path branches with `^`: `^\\/api\\/|^\\/query`; or `^[^/]+\\/api(\\/|$)`")],
     [f"{T}::test_a_branch_anchored_at_the_path_appears_only_as_one_that_never_matches"]),

    ("the host-anchored form dropped from the prompt",
     [("agent.py", "so anchor after it, `^[^/]+/api(/|$)`;", "so anchor it;")],
     [f"{T}::test_the_working_forms_are_given"]),

    ("the label described as an event-only signal again",
     [(K, "`ENABLED`, not only during an event, so ordinary logs", "`ENABLED`, during an event, so ordinary logs")],
     [f"{T}::test_an_exemption_is_checked_from_ordinary_logs"]),

    ("the label tied to the challenge action rather than the setting again",
     [(K, "It is applied while the challenge setting (`ClientSideActionConfig` → `Challenge` → `UsageOfAction`) is `ENABLED`,",
       "It is applied whenever the challenge action is enabled,")],
     [f"{T}::test_the_check_names_the_setting_the_label_needs"]),

    ("the prompt's check without the setting it needs",
     [("agent.py", "Check an exemption in ordinary logs: while the challenge setting's UsageOfAction is ENABLED, a",
       "Check an exemption in ordinary logs: a")],
     [f"{T}::test_the_check_names_the_setting_the_label_needs"]),

    ("two instances said to split a baseline again",
     [(K, "Each instance's scope-down limits the requests it observes, which is what AWS says can make the baseline inaccurate;",
       "Each instance then builds its baseline from part of the traffic, which is the inaccuracy AWS warns about;")],
     [f"{T}::test_two_instances_are_not_said_to_split_a_baseline"]),

    ("two instances offered as the default again",
     [(K, "**Last resort: dual AMR instance in the same Web ACL**", "**Good: dual AMR instance in the same Web ACL**")],
     [f"{T}::test_two_instances_are_the_last_resort_with_their_cost_stated"]),
]

sys.exit(sweep(CASES))
