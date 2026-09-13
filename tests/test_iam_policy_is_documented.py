# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every action the execution role grants is in `docs/iam-permissions.md`, and nothing else is.

`docs/iam-permissions.md` opens by telling a reader that WAF Analyst is read-only for their production
resources and lists the four exceptions. Someone deciding whether to deploy this into their account
reads that document and not `deploy/backend.yaml`. So the two drifting apart is not a documentation
tidiness problem, it is a consent problem: the reader agreed to a list.

**The drift was real and had shipped.** `glue:GetDatabases` and `glue:GetTables` were added to the
template when the Athena table search stopped being narrowed to two known database names, and neither
appeared in either language's document. Found on 2026-09-13 while adding `cloudfront:ListDistributions`
for the domain lookup, which would have been the third.

Both directions are asserted, because they fail differently. An undocumented grant is the reader
consenting to less than they got. A documented grant that no longer exists sends someone writing a
least-privilege policy of their own down a path where the extra action looks required.

What this cannot check: whether a purpose column is honest, or whether the third column's claim about
production impact is true. Those are read, not tested, and saying so is better than implying the
coverage is wider than it is.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "deploy/backend.yaml"
DOCS = ("docs/iam-permissions.md", "docs/iam-permissions_zh.md")

# The one policy this is about. `AssumeRolePolicyDocument` grants `sts:AssumeRole` to the AgentCore
# service principal, which is how the role is assumed rather than something the agent may call, and it
# has no business in a document about what the agent can reach in your account.
POLICY = "- PolicyName: AgentPermissions"


def _granted() -> set[str]:
    """Every action inside the `AgentPermissions` policy, in both spellings the template uses.

    **`Action:` appears as a list and as a scalar, and reading only the list form misses one.** The
    conditional knowledge-base statement writes `Action: bedrock:Retrieve` inline, so a parser that
    only collected `- service:Action` lines would report it as documented-but-not-granted and the
    obvious fix would have been to delete a true row from the document."""
    text = TEMPLATE.read_text()
    rest = text[text.index(POLICY):]
    # The policy ends where the next top-level resource key starts, at two spaces of indent.
    end = re.search(r"^  [A-Za-z]", rest, re.M)
    block = rest[:end.start()] if end else rest
    listed = set(re.findall(r"^\s*-\s+([a-z0-9]+:[A-Za-z0-9*]+)\s*$", block, re.M))
    inline = set(re.findall(r"^\s*Action:\s+([a-z0-9]+:[A-Za-z0-9*]+)\s*$", block, re.M))
    return listed | inline


def _documented(rel: str) -> set[str]:
    """Every action named in a table's first column."""
    return set(re.findall(r"\| `([a-zA-Z0-9]+:[A-Za-z0-9*]+)`", (ROOT / rel).read_text()))


def test_the_two_sides_were_actually_parsed():
    """The precondition, and it is not optional here: the assertion below compares two sets for
    equality, and two empty sets are equal. A regex that stopped matching, or a policy block that
    moved, would report perfect agreement."""
    granted = _granted()
    assert len(granted) >= 40, (
        f"only {len(granted)} actions parsed out of {POLICY}; the block moved or the pattern broke, "
        f"and the equality check below would pass on an empty set: {sorted(granted)}")
    assert "bedrock:Retrieve" in granted, "the inline `Action:` form is no longer being collected"
    assert "sts:AssumeRole" not in granted, (
        "the parse has escaped the AgentPermissions policy and is reading the trust policy")
    for rel in DOCS:
        assert len(_documented(rel)) >= 40, f"{rel}: only {len(_documented(rel))} actions in tables"


@pytest.mark.parametrize("rel", DOCS)
def test_the_document_lists_exactly_what_the_role_grants(rel):
    """Both directions in one assertion, reported separately, because the fix differs. Extra grants
    are documented; documented actions that are gone get deleted from the table."""
    granted, documented = _granted(), _documented(rel)
    assert granted == documented, {
        "granted and undocumented, so the reader consented to less than they got":
            sorted(granted - documented),
        "documented and not granted, so a least-privilege policy copied from this doc is too wide":
            sorted(documented - granted),
        "file": rel,
    }


def test_the_two_languages_document_the_same_actions():
    """The Chinese twin lagging is silent: a reader of that file consents to a shorter list than the
    one that gets deployed. Asserted on the identifiers rather than on the prose, which is the only
    half that can be compared."""
    en, zh = _documented(DOCS[0]), _documented(DOCS[1])
    assert en == zh, {"English only": sorted(en - zh), "Chinese only": sorted(zh - en)}
