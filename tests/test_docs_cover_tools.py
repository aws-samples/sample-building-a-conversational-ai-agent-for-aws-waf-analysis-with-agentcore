# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every registered tool is either described in the capabilities doc or declared not user-facing.

**This exists because the audit that was supposed to catch a doc gap was a word-frequency scan.**
`aggregate_logs` shipped in 0.21.0 and was documented in no user-facing file for six months; a review
pass that "checked all the docs" missed it, and separately claimed `investigate_injection` was covered
because the string `SQLi` appeared somewhere (it was a different entry). A completeness claim whose
population is "does this word appear" cannot find the tool nobody wrote a sentence for. See
[[a-complete-set-counted-from-your-own-diff]] in the reasoning behind it.

The reliable form walks the real set. `agent._TOOLS` is the registry the model is given, so this
enumerates it and requires every entry to be accounted for: a user-facing tool names the phrase in
`docs/capabilities.md` that describes it, and a tool that is plumbing or orchestration is declared as
such with a reason. A tool added to `_TOOLS` next year fails `test_every_registered_tool_is_classified`
until someone decides which it is, and a capability whose describing sentence is deleted fails
`test_every_user_facing_tool_is_described`.
"""

import pathlib

import agent

CAPABILITIES = (pathlib.Path(__file__).resolve().parents[1] / "docs" / "capabilities.md").read_text()

# Each user-facing tool -> a phrase in capabilities.md specific to the capability it provides, not the
# tool name (the docs describe capabilities in prose and name no tool). The phrase has to be distinctive
# enough that deleting the capability's description removes it.
USER_FACING = {
    "get_waf_overview": "rule effectiveness, bot activity",
    "patrol_scan": "security patrol",
    "detect_bypass": "crawlers bypassing",
    "evaluate_count_rules": "COUNT rules",
    "review_waf_rules_deep": "deep review",
    "investigate_block_fp": "Allow Ratio",
    "get_waf_metrics": "spiked 5x",
    "analyze_ip": "Profiles the IP across all dimensions",
    "check_challenge_compatibility": "token failure reasons",
    "investigate_injection": "injection attacks were blocked",
    "generate_weekly_report": "weekly report",
    "search_waf_knowledge": "knowledge base of AWS WAF documentation",
    "run_logs_query": "predefined log query templates",
    "set_log_granularity": "builds an hourly table over the whole timeline",
    "aggregate_logs": "the agent composes an aggregation",
    "lookup_ja4": "decodes a JA4 TLS fingerprint",
}

# Plumbing: the agent calls these to select and load the WebACL before another capability runs. A user
# does not ask for them as a capability, so capabilities.md does not owe them a sentence.
PRIMITIVE = {"get_waf_config", "list_webacls"}

# Orchestration: these move data between turns or into a report, never a standalone answer.
INTERNAL = {"ask_user", "record_finding", "set_report_summary", "finalize_review_report"}


def _registered_tool_names() -> set:
    names = set()
    for t in agent._TOOLS:
        names.add(getattr(t, "tool_name", None) or getattr(t, "__name__", None))
    return names


def test_every_registered_tool_is_classified():
    """The completeness guard, and it is derived from `_TOOLS` rather than from a list kept by hand, so a
    new tool cannot slip in undocumented and unnoticed the way `aggregate_logs` did."""
    registered = _registered_tool_names()
    classified = set(USER_FACING) | PRIMITIVE | INTERNAL
    missing = registered - classified
    stale = classified - registered
    assert not missing, (
        f"these tools are in agent._TOOLS and classified nowhere: {sorted(missing)}. Add each to "
        f"USER_FACING with a capabilities.md phrase, or to PRIMITIVE/INTERNAL with the reason.")
    assert not stale, (
        f"these are classified here but no longer registered: {sorted(stale)}. Remove them.")


import pytest


@pytest.mark.parametrize("tool,phrase", sorted(USER_FACING.items()))
def test_every_user_facing_tool_is_described(tool, phrase):
    """Each user-facing capability has its describing phrase in capabilities.md. A phrase that vanishes
    means the capability became undiscoverable, which is the state this file exists to prevent."""
    assert phrase in CAPABILITIES, (
        f"{tool}: capabilities.md no longer contains {phrase!r}. Two different things fail here and the "
        f"fix is not the same: if the sentence was REWORDED, update the phrase above to the new wording; "
        f"if the capability was REMOVED, that is a real gap and editing the phrase to something still "
        f"present would silence it. Decide which happened before changing this map.")
