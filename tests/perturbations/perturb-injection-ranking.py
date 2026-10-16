#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_injection_ranking.py` claims and require it to notice.

Two families: Count-mode detectors becoming invisible again (ranked or filtered on BLOCK), and
a failed read becoming an absence again (`_outcome` collapsing failure into "no rows").
"""

import sys

from _harness import sweep

T = "tests/test_injection_ranking.py"
I = "tools/waf_injection.py"

CASES = [
    ("Count-overridden sub-rules dropped from the detectors",
     [(I, "                found += [o[\"Name\"] for o in group.get(\"RuleActionOverrides\", [])\n",
       "                found += [] and [o[\"Name\"] for o in group.get(\"RuleActionOverrides\", [])\n")],
     [f"{T}::test_overridden_sub_rules_of_injection_groups_are_detectors"], True),

    ("ranked on blocks again",
     [(I, "            total = sum(h for _, h in pairs)", '            total = dict(pairs).get("BLOCK", 0)')],
     [f"{T}::test_a_count_mode_detector_with_the_most_matches_is_the_focus",
      f"{T}::test_a_window_with_only_count_matches_is_not_reported_as_quiet"], True),

    ("an unanswered ranking query read as no matches",
     [(I, "            if pairs is None:\n                unread[target] = reason\n                continue",
       "            if pairs is None:\n                pairs = []")],
     [f"{T}::test_a_failed_ranking_query_is_not_read_as_no_matches"], True),

    ("_outcome collapsing a failure into an empty result",
     [(I, '    return None, table.strip().splitlines()[0] if table.strip() else "no answer"',
       "    return [], None")],
     [f"{T}::test_a_failed_ranking_query_is_not_read_as_no_matches",
      f"{T}::test_a_failed_source_query_is_not_classified_as_no_evidence"], True),

    ("a failed WebACL read reported as no coverage again",
     [(I, '        acl_error = f"{type(exc).__name__}: {exc}"\n', "        acl_error = None\n")],
     [f"{T}::test_a_failed_webacl_read_is_not_reported_as_no_coverage"], True),

    ("downstream sections back on BLOCK",
     [(I, '    matched = json.dumps({"rule": focus})', '    matched = json.dumps({"rule": focus, "action": "BLOCK"})')],
     [f"{T}::test_a_count_mode_detector_with_the_most_matches_is_the_focus"], True),

    ("the focus rule's Count mode left unsaid",
     [(I, "    if focus in count_mode:\n", "    if False:\n")],
     [f"{T}::test_a_count_mode_detector_with_the_most_matches_is_the_focus"], True),

    ("an unanswered source query classified anyway",
     [(I, "    if unread_steps:\n        classification", "    if False:\n        classification")],
     [f"{T}::test_a_failed_source_query_is_not_classified_as_no_evidence"], True),
]

sys.exit(sweep(CASES))
