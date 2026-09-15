#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Truncate an answer badly again and require `test_output_limit.py` to notice.

The first case is the state the deployed release was in: 4,096 output tokens, three per cent of what the
model allows. The rest are the ways the second half can be lost, which is the half that stays necessary
however high the limit goes.
"""

import sys

from _harness import sweep

T = "tests/test_output_limit.py"
A = "agent.py"

CASES = [
    # The state the release shipped in for four months, and the state the first fix left it in. Anchored on
    # the whole statement rather than a keyword line, because a keyword inside a multi-line call is a
    # continuation line and no statement can be inserted ahead of one.
    ("an output bound back on the request, which is what truncated a real answer",
     [(A, "        _model = BedrockModel(\n"
          "            model_id=MODEL_ID,\n"
          "            region_name=MODEL_REGION,\n"
          "        )",
       "        _model = BedrockModel(\n"
       "            model_id=MODEL_ID,\n"
       "            region_name=MODEL_REGION,\n"
       "            max_tokens=4096,\n"
       "        )")],
     [f"{T}::test_no_output_bound_reaches_the_request"], True),

    ("a larger bound instead of none, which is the shape the first fix had",
     [(A, "        _model = BedrockModel(\n"
          "            model_id=MODEL_ID,\n"
          "            region_name=MODEL_REGION,\n"
          "        )",
       "        _model = BedrockModel(\n"
       "            model_id=MODEL_ID,\n"
       "            region_name=MODEL_REGION,\n"
       "            max_tokens=32768,\n"
       "        )")],
     [f"{T}::test_no_output_bound_reaches_the_request"], True),

    ("the SDK's own sentence put back in the report",
     [(A, '    if "max_tokens" in message or "MaxTokens" in message:', "    if False:")],
     [f"{T}::test_a_truncated_answer_says_so_in_the_reader_s_terms"], True),

    ("the separator dropped, so the error reads as the next table cell",
     [(A, '    prefix = "\\n\\n" if mid_answer else ""', '    prefix = ""')],
     [f"{T}::test_the_message_is_separated_from_the_answer_it_follows"], True),

    ("a separator added when there is nothing to separate from",
     [(A, '    prefix = "\\n\\n" if mid_answer else ""', '    prefix = "\\n\\n"')],
     [f"{T}::test_the_message_is_separated_from_the_answer_it_follows"], True),

    # The narrowing's safety assertion: every other failure keeps its own message.
    ("every error rewritten as a truncation, hiding a permission or throttling failure",
     [(A, '    if "max_tokens" in message or "MaxTokens" in message:', "    if True:")],
     [f"{T}::test_any_other_failure_keeps_its_own_message"], True),

    # The wiring. No probe: the target reads source.
    ("the loop emitting the raw payload again",
     [(A, '                                 "delta": _error_text(payload, has_streamed_text)})',
       '                                 "delta": f"Error: {payload}"})')],
     [f"{T}::test_the_streaming_loop_asks_for_the_formatted_text"], False),
]

sys.exit(sweep(CASES))
