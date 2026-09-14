# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 7.7 item 4's last piece: an attribution has to carry its own uncertainty.

Two measured failures, and they are one rule because the second is the first at a smaller scope.

**Cross-WebACL inference, from the exported conversation.** The agent concluded "highly likely the same
attacker, two-phase" from an identical User-Agent and a 12-minute gap, **in the same answer that reported
the JA4 fingerprints differed**. The traffic was the maintainer's own test fleet, so the shared User-Agent
was a generator artifact. The agent could not know that, which is why this is not a tool defect; a user
with a staging environment gets the same confident wrong attribution.

**Recall inside one conversation, measured 2026-09-13, and cleaner because the ground truth is a number.**
Asked about `shield-sample-webacl`, the answer's history table listed `2026-09-08 11:00–13:00 | 122 | SQLi`
under that WebACL. The 122 is `response-id-on-page`'s, and `shield-sample-webacl`'s SQLi series is empty
for the whole day. Both numbers came from tools in earlier turns and both were labelled correctly at the
time. The answer merged them.

**This is the weak lever and the file says so.** Measured 2026-09-13: the model reads the `SOURCE:` line,
acts on it, and does not relay it, so a prompt rule is a second instruction on a mechanism already
observed to be lossy. It is what is available: no tool sees two WebACLs in one call, and the attribution is
drawn in the answer rather than in any tool. Whether the model follows it is on the post-deploy list.

**7.1's mirror.** There a broken query yields the reassuring answer; here contradictory evidence yields the
alarming one. Both fail the same way, by producing output that does not carry its own uncertainty.
"""

import ast
import pathlib

import agent
from tools.session_state import provenance_source_line

ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADING = "## Attribution: list the evidence, and name what else explains it"


def _section() -> str:
    prompt = agent._build_system_prompt(9)
    assert HEADING in prompt, (
        f"no section headed {HEADING!r}. If it was reworded, update HEADING here after checking the "
        f"rules below survived the rewording; if it was removed, the rule is gone.")
    return prompt.split(HEADING)[1].split("\n## ")[0]


def _catalog() -> dict[str, str]:
    """`TEMPLATES`, flattened to query type -> both engine spellings joined."""
    tree = ast.parse((ROOT / "tools/waf_logs.py").read_text())
    node = next(n for n in tree.body
                if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "TEMPLATES")
    out = {}
    for key, spec in zip(node.value.keys, node.value.values):
        out[key.value] = "\n".join(v.value for v in spec.values
                                  if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return out


def test_the_rule_names_the_evidence_combination_that_produced_the_wrong_answer():
    """**Same User-Agent, different JA4, and nothing in the repository ruled on it.**

    `lookup_ja4`'s own trailer covers the two neighbouring combinations: same JA4 across several IPs means
    one TLS library, several User-Agents behind one JA4 means UA spoofing. The pair the wrong answer
    actually held, one User-Agent across two differing JA4s, had no ruling anywhere, so the model resolved
    it by weighing the signal that agreed with the conclusion.

    Asserted over the union of the prompt section and that trailer, so improving the tool satisfies this
    too. Today the trailer alone does not: it is the prompt that carries the combination."""
    text = _section() + (ROOT / "tools/ja4.py").read_text()
    assert "Same User-Agent with different JA4" in text, (
        "nothing tells the model what to conclude when the User-Agent matches and the JA4 does not, "
        "which is the combination that produced 'highly likely the same attacker'")
    assert "not proof against one operator" in text, (
        "the rule has to stop short of the opposite overclaim: differing JA4 is evidence of two clients, "
        "and one person running two tools is still one operator")


def test_the_rule_still_lets_the_agent_attribute():
    """The half an over-eager edit deletes, and deleting it is worse than the defect.

    A rule that only prohibits produces an agent that will not attribute anything, which is what the tool
    is for. So the section has to name what to say, not only what not to say, and it has to agree with
    `## Confidence Boundaries` rather than outrank it."""
    section = _section()
    assert "**related traffic**" in section, (
        "the rule forbids the overclaim and offers no wording in its place, so the model's options are an "
        "unsupported conclusion or none at all")
    assert "one other cause that produces the same pattern" in section, (
        "listing the evidence is not the rule; naming an alternative is what makes the list falsifiable")


def test_the_rule_can_be_followed_because_a_query_type_returns_the_fingerprints():
    """**Direction 1 of `test_log_content_is_untrusted.py`, applied to evidence instead of markers.** A
    rule telling the model to weigh a signal it cannot fetch is unfollowable, and it fails in the
    direction of the defect: unable to get fingerprints, the model decides on the User-Agent alone, which
    is the original wrong answer with a rule sitting on top of it.

    The dependency is a named query type, not a field spelling. `ip_ja4_fingerprints` is the only way to
    get per-IP fingerprints out of either engine, so the rule to compare them rests on it existing.
    Checked in the catalog rather than in the file, because a mention in a docstring is not a query."""
    catalog = _catalog()
    assert len(catalog) >= 15, f"only {len(catalog)} query types parsed, so this proves nothing"
    ja4 = [name for name, sql in catalog.items() if "ja4" in name.lower() and "ja4" in sql.lower()]
    assert ja4, (
        f"no query type returns JA4 fingerprints, so 'compare the JA4' cannot be carried out on either "
        f"engine: {sorted(catalog)}")
    ua = [name for name, sql in catalog.items() if "ua" in sql.lower()]
    assert ua, "no query type returns a User-Agent, so the matching half of the rule has no input either"


def test_a_recalled_number_is_told_to_keep_the_webacl_it_came_from():
    """The second measured case, and the marker is asserted from both ends.

    The rule points at the `SOURCE:` line, which is the only per-result statement of which WebACL was
    queried. Renaming the marker on the emitter would leave an instruction naming a string no tool
    produces, which is the shape where the rule reads intact and refers to nothing."""
    section = _section()
    assert "SOURCE:" in section, (
        "the recall rule does not name the line that carries the WebACL, so the model has nothing to "
        "carry forward and the 122 goes back under the wrong WebACL")
    assert "put it only in that WebACL's row" in section, (
        "the rule says where a number comes from and not what may be done with it; the measured defect "
        "was placement, not labelling")
    assert "SOURCE:" in provenance_source_line({"webacl": "x", "engines": ["Athena over S3"]}), (
        "the emitter no longer produces the marker the rule names")
