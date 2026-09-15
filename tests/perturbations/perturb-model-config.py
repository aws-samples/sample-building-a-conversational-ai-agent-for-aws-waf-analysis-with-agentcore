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

    # The output bound is gone too now, for its own reason, so what this pins is that the request carries
    # nothing this repository chose. Adding either parameter back is what it catches.
    ("an output bound added back beside the sampling ones",
     [(A, CALL, CALL.replace("            region_name=MODEL_REGION,\n",
                             "            region_name=MODEL_REGION,\n            max_tokens=4096,\n"))],
     [f"{T}::test_the_request_carries_no_inference_parameters_at_all"], True),

    ("the model rebuilt on every call, which builds a boto3 client per turn",
     [(A, "    if _model is None:", "    if True:")],
     [f"{T}::test_the_model_is_constructed_once"], True),
]

sys.exit(sweep(CASES))
