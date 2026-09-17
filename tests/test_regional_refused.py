# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""REGIONAL scope is refused at every agent-facing tool that takes a scope, with one message.

WAF Analyst analyses CLOUDFRONT scope only. The guard is one line per tool, so the failure this
protects against is a scope-taking tool added later without it. The set is therefore discovered by
walking every `@tool` in `tools/` and keeping those whose signature has a `scope` parameter, never
by listing the ones touched in the change that added the guard. A seventh such tool is covered by
construction, and if it ships without the guard the parametrised test below goes red on it.

Called with no credentials, a tool that did not refuse would reach `get_client` and raise, so a
return equal to the message proves the guard fired ahead of every AWS call, not merely that some
string mentioning regions came back."""

import importlib
import inspect
import pkgutil

import pytest

import tools
from tools import session_state as S


def _scope_tools() -> dict:
    found = {}
    for info in pkgutil.iter_modules(tools.__path__, "tools."):
        mod = importlib.import_module(info.name)
        for name, obj in vars(mod).items():
            fn = getattr(obj, "_tool_func", None)  # strands wraps the function; this is the callable
            if fn is not None and "scope" in inspect.signature(fn).parameters:
                found[f"{info.name}.{name}"] = obj
    return found


SCOPE_TOOLS = _scope_tools()


def test_the_helper_keys_on_regional_only():
    """The predicate normalises case and whitespace before matching, because a guard built to not
    trust the model must not bet on the model's formatting. CLOUDFRONT, the empty scope a tool
    resolves from session state, and None are not refused."""
    assert S.refuse_if_regional("REGIONAL") == S.REGIONAL_UNSUPPORTED_MESSAGE
    assert S.refuse_if_regional("regional") == S.REGIONAL_UNSUPPORTED_MESSAGE      # case
    assert S.refuse_if_regional("  REGIONAL  ") == S.REGIONAL_UNSUPPORTED_MESSAGE  # whitespace
    assert S.refuse_if_regional("CLOUDFRONT") is None
    assert S.refuse_if_regional("") is None
    assert S.refuse_if_regional(None) is None


def test_the_walk_found_the_scope_tools():
    """A floor, not an inventory: if an import breakage hid every tool the parametrised test would
    vacuously pass, so require the discovery to have found the known population."""
    assert len(SCOPE_TOOLS) >= 6, sorted(SCOPE_TOOLS)
    names = {label.rsplit(".", 1)[1] for label in SCOPE_TOOLS}
    assert {"list_webacls", "get_waf_config", "get_waf_overview",
            "patrol_scan", "generate_weekly_report", "review_waf_rules_deep"} <= names, names


@pytest.mark.parametrize("label", sorted(SCOPE_TOOLS))
def test_every_scope_tool_refuses_regional(label):
    fn = SCOPE_TOOLS[label]._tool_func
    kwargs = {}
    for p in inspect.signature(fn).parameters.values():
        if p.name == "scope":
            kwargs["scope"] = "REGIONAL"
        elif p.default is inspect.Parameter.empty:
            kwargs[p.name] = "x"  # never read: the guard returns before any argument is used
    out = fn(**kwargs)
    assert out == S.REGIONAL_UNSUPPORTED_MESSAGE, f"{label} did not refuse REGIONAL: {out[:200]}"
