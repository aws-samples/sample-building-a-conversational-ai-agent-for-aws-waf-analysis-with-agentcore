#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Silence the Anti-DDoS section's absence again and require `test_antiddos_section_absence.py` to notice.

Every case is a state the code was in before 2026-09-15, or one step away from it. The first is the state
itself: the section vanished and only an exception could explain it. The last is the substitution the guard
exists to prevent, where a query failure gets relabelled as an idle rule group.
"""

import sys

from _harness import sweep

T = "tests/test_antiddos_section_absence.py"
R = "tools/report.py"

CASES = [
    # The state before the fix: nothing outside the except handlers writes a reason.
    ("the fallback removed, so the section disappears with nothing said",
     [(R, '    if "anti_ddos_events" not in section_skips:\n'
          '        why = _antiddos_skip(bool(caps.get("anti_ddos_amr")), log_group, ddos_num_events)\n'
          "        if why:\n"
          '            section_skips["anti_ddos_events"] = why\n', "")],
     # The behavioural tests below call `_antiddos_skip` directly and stay green when the call site goes,
     # which the sweep reported as HOLLOW. Only the wiring test sees this one.
     [f"{T}::test_the_reason_is_written_into_the_channel_that_reaches_the_report",
      f"{T}::test_a_failure_keeps_its_own_reason"], False),

    # One reason for both non-failure states, which is what the report's own ACTION line forbids.
    ("one sentence for both silences, so the backend case claims the rule group was quiet",
     [(R, '    if not log_group:\n        return ("the Anti-DDoS section reads',
       '    if False:\n        return ("the Anti-DDoS section reads')],
     [f"{T}::test_a_backend_these_queries_cannot_read_gets_a_different_reason",
      f"{T}::test_the_two_reasons_are_not_the_same_sentence"], True),

    ("the event check dropped, so a quiet week is silent again",
     [(R, "    if not num_events:", "    if False:")],
     [f"{T}::test_no_event_says_so_rather_than_disappearing"], True),

    # The other direction: speaking when there is nothing to explain.
    ("a WebACL without the rule group reported as missing a section it never had",
     [(R, "    if not has_amr:\n        return None", "    if not has_amr:\n        pass")],
     [f"{T}::test_a_webacl_without_the_rule_group_stays_silent"], True),

    ("a rendered section also listed as missing",
     [(R, "    if not num_events:\n        return", "    if True:\n        return")],
     [f"{T}::test_a_section_that_rendered_says_nothing"], True),

    # The substitution the guard prevents. No probe: the target reads source.
    ("the guard dropped, so a query failure is relabelled an idle rule group",
     [(R, '    if "anti_ddos_events" not in section_skips:\n        why = _antiddos_skip',
       "    if True:\n        why = _antiddos_skip")],
     [f"{T}::test_a_failure_keeps_its_own_reason"], False),
]

sys.exit(sweep(CASES))
