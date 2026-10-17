# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every Bot Control rule and label name the agent reads is one Bot Control publishes.

The verdicts read Bot Control by whether a label is present, so a name that no version emits reads
exactly like "Bot Control did not classify this IP", and nothing fails. `analyze_ip` looked for
`TGT_TokenReuseIP`, and the rules are `TGT_TokenReuseIpLow`, `...Medium` and `...High`, so a token
shared across IPs never reached its findings; the prompt recommended the same missing name.

The fixture is `describe-managed-rule-group` for every version AWS listed on 2026-10-17. Names are
taken by walking the code, the prompt and the Bot Control knowledge base, not from a list kept here.
"""

import json
import pathlib
import re

import pytest

import agent

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / "tests" / "fixtures" / "bot_control_labels_2026-10-17.json").read_text())
LATEST = DATA["versions"][DATA["latest"]]
NAMES = LATEST["rules"] + LATEST["labels"] + DATA["latest_bot_identities"]

RULE = re.compile(r"\b(TGT_[A-Za-z_]+|Signal[A-Z][A-Za-z]+|Category[A-Z][A-Za-z]+)\b")
LABEL = re.compile(r"\b((?:bot|signal|targeted|token_provenance):[a-z0-9_:\-]*[a-z0-9_])")
SOURCES = {**{f"tools/{p.name}": p.read_text() for p in sorted((ROOT / "tools").glob("*.py"))},
           "agent.py SYSTEM_PROMPT": agent.SYSTEM_PROMPT,
           **{f"kb-docs/{p.name}": p.read_text() for p in sorted((ROOT / "kb-docs").glob("*.md"))
              if p.name.startswith(("bot-control", "advanced-bot"))}}


def _read():
    return {(src, m) for src, text in SOURCES.items() for m in set(RULE.findall(text)) | set(LABEL.findall(text))}


def test_the_walk_finds_the_names_the_verdicts_turn_on():
    """The precondition: a walk that matched nothing would pass the test below."""
    found = {m for _, m in _read()}
    assert {"TGT_TokenAbsent", "signal:known_bot_data_center", "bot:verified",
            "signal:cloud_service_provider", "TGT_TokenReuseIp"} <= found, sorted(found)


def test_every_name_read_is_one_the_latest_version_publishes():
    missing = sorted((src, m) for src, m in _read() if not any(m in n for n in NAMES))
    assert not missing, missing


@pytest.mark.parametrize("version", sorted(DATA["versions"]))
def test_the_labels_whose_absence_reads_as_a_bypass_are_in_every_version(version):
    """`bot:verified` and `known_bot_data_center` decide rungs, and a missing one moves the verdict
    toward a bypass. Cloud-provider labels start in Version_2.0 and are not in the RC_COUNT
    listings, so their absence there is the version's, which the knowledge base says."""
    labels = DATA["versions"][version]["labels"]
    assert "bot:verified" in labels and "signal:known_bot_data_center" in labels, version
    provider = any(l.startswith("signal:cloud_service_provider:") for l in labels)
    assert provider == (version != "Version_1.0" and "RC_COUNT" not in version), version


def test_a_token_shared_across_ips_reaches_the_label_findings():
    from tools.waf_logs import _interpret_ip_labels
    out = _interpret_ip_labels([{"Labels": '[{"name":"awswaf:managed:aws:bot-control:TGT_TokenReuseIpLow"}]'}])
    assert "TokenReuseIP" in out, out
