#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Put a sampling override back and require `test_model_inference_config.py` to notice.

The first case is the state v0.26.0 shipped, where the deployed agent answered nothing at all. The second
is the repair a reader reaches for after learning temperature is refused, and it is refused by the same
rule. Both are anchored on the whole `BedrockModel(...)` statement rather than on the keyword line inside
it, so the probe has a statement to sit above.
"""

import sys

from _harness import sweep

T = "tests/test_model_inference_config.py"
A = "agent.py"

CALL = ('        _model = BedrockModel(\n'
        '            model_id=MODEL_ID,\n'
        '            region_name=MODEL_REGION,\n'
        '            **({"max_tokens": ceiling} if ceiling else {}),\n'
        '        )')

CASES = [
    ("temperature back on the request, which is what v0.26.0 shipped",
     [(A, CALL, CALL.replace("            region_name=MODEL_REGION,\n",
                             "            region_name=MODEL_REGION,\n            temperature=0.0,\n"))],
     [f"{T}::test_no_sampling_parameter_reaches_the_request"], True),

    ("top_p reached for instead, refused by the same rule",
     [(A, CALL, CALL.replace("            region_name=MODEL_REGION,\n",
                             "            region_name=MODEL_REGION,\n            top_p=0.9,\n"))],
     [f"{T}::test_no_sampling_parameter_reaches_the_request"], True),

    # The bound is the model's own ceiling, read from Bedrock. Each way of losing that is caught.
    ("no bound sent, which is Bedrock's 4,096 default, the state 0.27 to 0.33 shipped",
     [(A, CALL, CALL.replace('            **({"max_tokens": ceiling} if ceiling else {}),\n', ""))],
     [f"{T}::test_the_request_carries_the_ceiling_bedrock_reports_and_nothing_else"], True),

    ("a number picked here instead of the model's ceiling",
     [(A, CALL, CALL.replace('            **({"max_tokens": ceiling} if ceiling else {}),\n',
                             "            max_tokens=32768,\n"))],
     [f"{T}::test_the_request_carries_the_ceiling_bedrock_reports_and_nothing_else"], True),

    ("the probe asking within the ceiling, so it reads nothing",
     [(A, "_ABOVE_ANY_CEILING = 10_000_000", "_ABOVE_ANY_CEILING = 4096")],
     [f"{T}::test_the_probe_asks_above_any_ceiling_and_samples_nothing"], False),

    ("an unread ceiling failing silently",
     [(A, '        print(f"[agent] could not read the model\'s output ceiling, so answers stop at Bedrock\'s default of "\n'
          '              f"4,096 tokens: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)\n', "")],
     [f"{T}::test_an_unread_ceiling_sends_no_bound_and_says_why"], True),

    ("the model rebuilt on every call, which builds a boto3 client per turn",
     [(A, "    if _model is None:", "    if True:")],
     [f"{T}::test_the_model_is_constructed_once"], True),
]

sys.exit(sweep(CASES))
