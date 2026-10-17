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

import pytest

import agent

MESSAGES = [{"role": "user", "content": [{"text": "hi"}]}]
LIMIT = ("An error occurred (ValidationException) when calling the Converse operation: The maximum tokens "
         "you requested exceeds the model limit of {n}. Try again with a maximum tokens value that is lower "
         "than {n}.")


class _Bedrock:
    """Answers the ceiling probe the way Bedrock does, measured 2026-10-17 for four Claude models."""
    def __init__(self, error):
        self.error, self.sent = error, []

    def converse(self, **kw):
        self.sent.append(kw)
        raise RuntimeError(self.error)


@pytest.fixture(autouse=True)
def bedrock(monkeypatch):
    fake = _Bedrock(LIMIT.format(n=64000))
    monkeypatch.setattr(agent, "_model", None)
    monkeypatch.setattr(agent, "_bedrock_runtime", lambda: fake, raising=False)
    return fake


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


def test_the_request_carries_the_ceiling_bedrock_reports_and_nothing_else():
    """**Omitting `inferenceConfig` does not lift the bound, it falls back to 4,096.** Measured 2026-10-17
    against `global.anthropic.claude-sonnet-5` in ap-northeast-1, asking for 6,000 numbered lines: no
    `inferenceConfig` stopped at 4,096 output tokens with `stopReason: max_tokens`; `maxTokens` 32,000 and
    128,000 both ran to `end_turn` at about 17,060. So a long investigation was cut at the length the
    0.26 bound had. The ceiling is read off Bedrock's own refusal rather than chosen here: Sonnet 5,
    Sonnet 4.6 and Opus 5.5 report 128,000 and Haiku 4.5 reports 64,000, and a number above a model's
    ceiling would fail every request."""
    assert _inference_config() == {"maxTokens": 64000}, _inference_config()


def test_the_probe_asks_above_any_ceiling_and_samples_nothing(bedrock):
    _inference_config()
    cfg = bedrock.sent[0]["inferenceConfig"]
    assert list(cfg) == ["maxTokens"] and cfg["maxTokens"] > 128000, cfg


def test_an_unread_ceiling_sends_no_bound_and_says_why(bedrock, capsys):
    """A probe that failed some other way leaves the request as it was, and the real call then fails or
    answers on its own terms; the reason is on stderr, since the 4,096 default then applies."""
    bedrock.error = "AccessDeniedException: not authorized to perform bedrock:InvokeModel"
    assert _inference_config() == {}
    assert "AccessDeniedException" in capsys.readouterr().err


def test_the_model_is_constructed_once():
    """`_get_model` memoises into a module global, and the request-formatting above would keep passing if
    it did not. A model per turn rebuilds a boto3 client per turn, which is the shape that shows up as
    latency rather than as an error."""
    assert agent._get_model() is agent._get_model()
