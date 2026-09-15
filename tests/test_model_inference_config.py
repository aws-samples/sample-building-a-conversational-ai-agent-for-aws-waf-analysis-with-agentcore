# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The request must carry no sampling override, because the recommended model refuses every one.

**v0.26.0 answered nothing at all, measured on the deployed endpoint 2026-09-15.** Every invocation
returned `ValidationException: The model returned the following errors: `temperature` is deprecated for
this model.` The default model became `global.anthropic.claude-sonnet-5` during 0.25.0's documentation
pass and `_get_model` still sent `temperature=0.0`.

**Nothing had exercised that pairing, and the reason is worth keeping.** This project's default
verification route is locally imported code against the real account, which drives tools directly and
never constructs the model. The deploy checklist's own entries were about window labels and disclosure
lines. So a total outage of the deployed agent sat behind a check nobody had a reason to run, and the
first real invocation found it in four seconds.

Measured against the live model in ap-northeast-1: `maxTokens` alone is accepted; `temperature` at 0.0,
0.5 and 0.9 is refused as deprecated; `temperature=1.0` is accepted; `temperature=1.5` fails the API's
own range check, whose maximum is 1.0; `topP=0.9` is refused the same way as temperature. So 1.0 is both
the ceiling and the model's default, and it is the only value that passes.
"""

import agent

MESSAGES = [{"role": "user", "content": [{"text": "hi"}]}]


def _inference_config() -> dict:
    """The `inferenceConfig` the SDK would put on the wire.

    Read through `BedrockModel._format_request`, which is private, because it is the layer that decides:
    `get_config()` echoes the constructor's keywords, and a parameter dropped between there and the
    request would satisfy an assertion on it while the request still carried one. If a future SDK renames
    the method this fails with `AttributeError`, which is loud rather than quiet.
    """
    return agent._get_model()._format_request(MESSAGES)["inferenceConfig"]


def test_no_sampling_parameter_reaches_the_request():
    """Both parameters, because both are refused and only one of them shipped.

    `topP` has never been set here. It is asserted anyway: the two are refused by the same rule, and the
    obvious way to restore low-variance sampling after reading this file is to reach for the other knob."""
    cfg = _inference_config()
    for key in ("temperature", "topP"):
        assert key not in cfg, (
            f"{key} reaches the request, and `global.anthropic.claude-sonnet-5` refuses every value of "
            f"it except the default, so every invocation fails with ValidationException: {cfg}")


def test_the_request_still_bounds_its_own_length():
    """The control. Dropping the whole `inferenceConfig` would satisfy the assertion above and remove the
    output bound with it, so the one parameter that is still wanted is pinned by name."""
    assert _inference_config().get("maxTokens") == 4096, _inference_config()


def test_the_model_is_constructed_once():
    """`_get_model` memoises into a module global, and the request-formatting above would keep passing if
    it did not. A model per turn rebuilds a boto3 client per turn, which is the shape that shows up as
    latency rather than as an error."""
    assert agent._get_model() is agent._get_model()
