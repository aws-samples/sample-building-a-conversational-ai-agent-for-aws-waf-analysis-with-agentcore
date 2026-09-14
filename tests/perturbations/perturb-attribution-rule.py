#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the attribution rule and require `test_prompt_attribution_rule.py` to notice.

Every case is a rewording a reader could plausibly make, because that is the failure mode for a prompt
rule: nobody deletes it, somebody tightens it. Two of them are the opposite overclaim rather than the
original one, which is the direction an edit fixing "the agent is too confident" goes.

No probe on any case. The anchors are prose inside a string literal, so a `raise` inserted ahead of the
line lands inside the string as text, and the probe would then report a line that never executes for a
case that works. The two structural cases read source rather than run it, which is the other reason.
"""

import sys

from _harness import sweep

T = "tests/test_prompt_attribution_rule.py"
A = "agent.py"
L = "tools/waf_logs.py"

CASES = [
    # The combination the measured answer held, and the one nothing in the repo ruled on.
    ("the User-Agent and JA4 combination generalised away, so the wrong answer has no ruling again",
     [(A, "Same User-Agent with different JA4 is", "Traffic sharing a User-Agent is")],
     [f"{T}::test_the_rule_names_the_evidence_combination_that_produced_the_wrong_answer"], False),

    # The opposite overclaim, which is where an edit fixing overconfidence lands.
    ("a differing JA4 turned into proof of two actors, which is the same defect pointing the other way",
     [(A, "A differing JA4 means the TLS clients differ, which is evidence against one client and not "
          "proof against one operator, since a person can run two tools.",
       "A differing JA4 means it is a different attacker.")],
     [f"{T}::test_the_rule_names_the_evidence_combination_that_produced_the_wrong_answer"], False),

    # Prohibition with no wording offered, which produces an agent that will not attribute at all.
    ("the replacement wording removed, leaving only the ban",
     [(A, "is **related traffic** plus what else would look like this, never",
       "is not something to draw a conclusion from, and never")],
     [f"{T}::test_the_rule_still_lets_the_agent_attribute"], False),

    ("the alternative-cause requirement dropped, so listing the evidence is the whole rule",
     [(A, ", and one other cause that produces the same pattern", "")],
     [f"{T}::test_the_rule_still_lets_the_agent_attribute"], False),

    # The recall half. The measured defect was placement, not labelling.
    ("the recall rule deleted, so a number from an earlier turn lands under any WebACL",
     [(A, "- **A number keeps the WebACL it came from.** Every log and metric result carries a `SOURCE:` "
          "line naming the WebACL that was queried. When you carry a count from an earlier turn into a "
          "table or a summary, carry that WebACL with it and put it only in that WebACL's row. If you "
          "cannot tell which WebACL a recalled number came from, query again rather than placing it.\n",
       "")],
     [f"{T}::test_a_recalled_number_is_told_to_keep_the_webacl_it_came_from"], False),

    ("the rule told to label the source instead of to place the number, which is not the defect",
     [(A, "carry that WebACL with it and put it only in that WebACL's row",
       "mention which WebACL it came from")],
     [f"{T}::test_a_recalled_number_is_told_to_keep_the_webacl_it_came_from"], False),

    # The pairing: the rule names a marker, and the emitter has to still produce it.
    ("the marker renamed on the emitter while the rule still names SOURCE",
     [("tools/session_state.py", '    return (f"SOURCE: ', '    return (f"ORIGIN: ', 2)],
     [f"{T}::test_a_recalled_number_is_told_to_keep_the_webacl_it_came_from"], False),

    # The input the rule depends on. Without this query type, "compare the JA4" cannot be carried out.
    ("the fingerprint query type renamed, so the rule asks for evidence no query returns",
     [(L, '    "ip_ja4_fingerprints": {', '    "ip_fingerprints": {')],
     [f"{T}::test_the_rule_can_be_followed_because_a_query_type_returns_the_fingerprints"], False),
]

sys.exit(sweep(CASES))
