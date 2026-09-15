#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Restore each way a client's timezone offset crashed the request, require the tests to notice.

The measured failure was one number: `userTimezoneOffset: -480`, which is what a browser's
`getTimezoneOffset()` returns while this field is hours. It produced HTTP 424 wrapping a 500 whose only
content was "check your CloudWatch logs".

Three of the cases are the guard's three parts, and each part alone lets a different real body through:
the range check misses a non-numeric string, the numeric check misses an out-of-range number, and the
`bool` check misses JSON `true`, which `float()` turns into UTC+1 silently. The last two are about where
the guard sits, because the old code validated inside two branches and after building the agent.
"""

import sys

from _harness import sweep

A = "agent.py"
T = "tests/test_client_timezone_offset.py"

CASES = [
    ("the range check removed, which is the crash exactly as measured",
     [(A, "    if offset != offset or abs(offset) >= TZ_OFFSET_LIMIT:      # NaN compares unequal to itself",
       "    if False:")],
     [f"{T}::test_an_offset_no_timezone_has_is_refused",
      f"{T}::test_the_refusal_names_the_mistake_the_caller_actually_made"], True),

    ("NaN allowed through, since it passes float() and fails inside timedelta",
     [(A, "    if offset != offset or abs(offset) >= TZ_OFFSET_LIMIT:",
       "    if abs(offset) >= TZ_OFFSET_LIMIT:")],
     [f"{T}::test_an_offset_no_timezone_has_is_refused"], True),

    ("the conversion left unguarded, so a non-numeric value raises where nobody catches it",
     [(A, "    try:\n        offset = float(raw)\n    except (TypeError, ValueError):",
       "    if True:\n        offset = float(raw)\n    if False:")],
     [f"{T}::test_a_value_that_is_not_a_number_is_refused_with_the_same_shape"], True),

    ("JSON true accepted as UTC+1, because float(True) is 1.0",
     [(A, "    if isinstance(raw, bool):", "    if False:")],
     [f"{T}::test_a_value_that_is_not_a_number_is_refused_with_the_same_shape"], True),

    # The bound itself. 24 is what `timezone()` refuses, so a guard at 25 lets the crash back in for a
    # narrow band and a guard at 14 refuses Chatham and Kiritimati.
    ("the bound loosened past what timezone() accepts",
     [(A, "TZ_OFFSET_LIMIT = 24", "TZ_OFFSET_LIMIT = 25")],
     [f"{T}::test_an_offset_no_timezone_has_is_refused"], True),

    ("the bound tightened to the common offsets, which refuses real ones",
     [(A, "TZ_OFFSET_LIMIT = 24", "TZ_OFFSET_LIMIT = 12")],
     [f"{T}::test_every_real_offset_is_accepted_including_the_fractional_ones"], True),

    # Anchored on the whole `return`, not a line inside it: the middle of a multi-line expression is a
    # continuation line and no statement can be inserted ahead of one, so the probe would have nothing to
    # sit on and the case would join `unprobeable.txt` for no reason.
    ("the refusal saying only that the value is wrong, not which unit it is in",
     [(A, '        return None, (f"forwardedProps.userTimezoneOffset is in hours from UTC and must be '
          'between "\n'
          '                      f"-{TZ_OFFSET_LIMIT} and {TZ_OFFSET_LIMIT}, got {offset}. A browser\'s "\n'
          '                      f"getTimezoneOffset() returns minutes and with the opposite sign; send "\n'
          '                      f"-(getTimezoneOffset() / 60).")',
       '        return None, (f"forwardedProps.userTimezoneOffset is in hours from UTC and must be '
       'between "\n'
       '                      f"-{TZ_OFFSET_LIMIT} and {TZ_OFFSET_LIMIT}, got {offset}.")')],
     [f"{T}::test_the_refusal_names_the_mistake_the_caller_actually_made"], True),

    # Where the guard sits. No probe on these two: the targets read the handler's source, because
    # reaching the resume branch needs a live interrupt.
    ("the bad value written to session state before the check, which is the poisoning half",
     [(A, "        tz_offset = None\n"
          "        raw_tz = (input_data.get(\"forwardedProps\") or {}).get(\"userTimezoneOffset\")\n"
          "        if raw_tz is not None:\n"
          "            tz_offset, tz_error = parse_tz_offset(raw_tz)\n"
          "            if tz_error:\n"
          "                return JSONResponse({\"error\": tz_error}, status_code=400)",
       "        tz_offset = (input_data.get(\"forwardedProps\") or {}).get(\"userTimezoneOffset\")")],
     [f"{T}::test_the_handler_validates_once_above_both_paths"], False),

    ("each branch converting the raw value itself again, so the two can disagree",
     [(A, "            if tz_offset is not None:\n"
          "                from tools.session_state import set_user_timezone\n"
          "                set_user_timezone(tz_offset)\n"
          "                agent.system_prompt = _build_system_prompt(tz_offset)",
       "            if tz_offset is not None:\n"
       "                from tools.session_state import set_user_timezone\n"
       "                set_user_timezone(float(tz_offset))\n"
       "                agent.system_prompt = _build_system_prompt(float(tz_offset))")],
     [f"{T}::test_the_handler_validates_once_above_both_paths"], False),

    ("a missing offset refused instead of skipped, which breaks the CLI and the short form",
     [(A, "        if raw_tz is not None:", "        if True:")],
     [f"{T}::test_no_offset_at_all_is_not_an_error"], False),
]

sys.exit(sweep(CASES))
