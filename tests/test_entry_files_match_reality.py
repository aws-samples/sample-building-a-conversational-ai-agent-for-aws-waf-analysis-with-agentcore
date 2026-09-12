# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The entry files are an interface for an agent, not a brochure, so a stale claim is a bug.

`README.md` tells the user to point their coding agent at `AGENTS.md` and let it deploy. That makes
those two files, and the deployment guides they link, the API this project exposes. A human skims and
self-corrects; an agent reads a prerequisite list as a specification. On 2026-09-12 all three of these
were true at once, hours after the CodeBuild path had shipped:

- `README.md` listed Docker as a flat prerequisite, so an agent would tell the user to install it, or
  stop and say they were missing it.
- `README.md` said deployment is "a few CloudFormation stacks plus a container build".
- The Project Structure block listed three of the five templates in `deploy/`, so an agent using it as
  a map could not know `image-build.yaml` or `sessions-api.yaml` existed.

**The Chinese twins are the half that actually rots**, and this file exists mostly for them. PR #72
updated `docs/deployment.md` and left `docs/deployment_zh.md` untouched, so for an hour a
Chinese-reading user or agent had no way to reach the path that had just been built for them. Nothing
failed; the document was simply silent. The parity check below is keyed on identifiers rather than
prose, because an identifier is the part of a fact that survives translation.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).parent.parent
DEPLOY = ROOT / "deploy"

# Every file here is a deployment path someone can take. An entry file that does not name it hides it.
TWINS = [("README.md", "README_zh.md"),
         ("docs/deployment.md", "docs/deployment_zh.md"),
         ("docs/roadmap.md", "docs/roadmap_zh.md")]


def _read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def _structure_block(text):
    """The deploy/ subtree of a README's Project Structure listing."""
    match = re.search(r"^├── deploy/\n((?:│.*\n)+)", text, re.M)
    assert match, "the deploy/ block in Project Structure moved; this test proves nothing"
    return match.group(1)


# --- the map matches the territory ----------------------------------------------

@pytest.mark.parametrize("readme", ["README.md", "README_zh.md"])
def test_every_file_in_deploy_is_listed_in_the_project_structure(readme):
    """An agent uses this block as a map. A template missing from it is a template it cannot know
    about, which is how `image-build.yaml` and `sessions-api.yaml` stayed invisible."""
    block = _structure_block(_read(readme))
    on_disk = sorted(p.name for p in DEPLOY.iterdir() if p.is_file())
    assert on_disk, "deploy/ is empty, so this test proves nothing"
    missing = [name for name in on_disk if name not in block]
    assert not missing, f"{readme} does not list {missing}"


@pytest.mark.parametrize("doc", ["README.md", "README_zh.md", "AGENTS.md",
                                 "docs/deployment.md", "docs/deployment_zh.md"])
def test_every_document_that_explains_deployment_names_the_codebuild_path(doc):
    """The failure this catches is silence, not error. `deploy/image-build.yaml` is the only path for a
    machine with no container tooling, so a deployment document that never names it leaves that reader
    with the impression they cannot deploy at all."""
    assert (DEPLOY / "image-build.yaml").exists(), \
        "the template is gone; delete this test rather than weakening it"
    assert "image-build.yaml" in _read(doc), \
        f"{doc} never mentions image-build.yaml, so its readers cannot find the no-Docker path"


PREREQUISITE_LISTS = [
    ("README.md", "### Prerequisites", r"optional"),
    ("README_zh.md", "### 前置条件", r"可选|可以没有"),
    ("docs/deployment.md", "## Prerequisites", r"optional"),
    ("docs/deployment_zh.md", "## 前置条件", r"可选|可以没有"),
]


def _list_items(text, heading):
    """Split a prerequisite list into items. Both bullet and numbered forms, because the READMEs use
    one and the guides the other, and continuation lines belong to the item above them."""
    block = re.search(rf"^{re.escape(heading)}\n\n((?:(?:- |\d+\. |  |\t).*\n|\n(?=(?:- |\d+\. )))+)",
                      text, re.M)
    assert block, f"the {heading!r} list moved; this test proves nothing"
    items, current = [], None
    for line in block.group(1).splitlines():
        if re.match(r"^(?:- |\d+\. )", line):
            if current is not None:
                items.append(current)
            current = line
        elif current is not None:
            current += " " + line.strip()
    if current is not None:
        items.append(current)
    assert items, f"no list items parsed under {heading!r}"
    return items


@pytest.mark.parametrize("doc,heading,marker", PREREQUISITE_LISTS)
def test_no_prerequisite_item_presents_a_container_tool_as_required(doc, heading, marker):
    """**Judged per item, and the whole-block version of this was hollow.** The first draft asked
    whether the word "optional" appeared anywhere in the list. Adding back the original bare
    `- [Docker](…) with buildx` bullet while leaving the optional one in place kept every assertion
    green, so the list said "you need Docker" and "a container tool is optional" at once and the test
    written to prevent exactly that reported success.

    Every item that names a container tool must carry the marker itself. Scoped to the prerequisite
    list, because the mentions further down are for people who do have one and are correct.

    All four documents, not two. `AGENTS.md` sends the agent to `docs/deployment.md` for the numbered
    steps, so an agent landing there reads item 2 as a requirement no matter how the README reads."""
    items = _list_items(_read(doc), heading)
    naming_a_tool = [i for i in items if "Docker" in i or "finch" in i]
    assert naming_a_tool, f"{doc} no longer names a container tool here; retarget this test"
    bare = [i for i in naming_a_tool if not re.search(marker, i, re.I)]
    assert not bare, (
        f"{doc} has {len(bare)} prerequisite item(s) naming a container tool without marking it "
        f"optional, so an agent reading this list as a specification will install it or stop: {bare}")


# --- the twins say the same things ----------------------------------------------

# Identifiers, not prose: these survive translation, so requiring them in both files checks the fact
# rather than the wording. **Only put a token here if its presence anywhere in the file implies the
# fact.** `READY` failed that bar: it occurs twice in each guide, so a whole-file check for it stays
# green after the caveat is deleted. That is the test below instead.
PARITY = [
    "image-build.yaml", "ReleaseTag", "ARM_CONTAINER",
    # Added after a from-scratch deploy found each of these documented in one language only, or in
    # neither. `empty_bucket` and `waf-agent-image` are Cleanup, which was wrong three ways;
    # `SessionsTableArn` was hand-built from parts while the stack already outputs it; `Bearer` is the
    # headless invoke contract, which lived nowhere in docs/ and had to be reverse-engineered from
    # `frontend/src/agent.js`; `aws-waf-logs-` is why the frontend WebACL has no logging on purpose.
    "empty_bucket", "waf-agent-image", "SessionsTableArn", "Bearer", "aws-waf-logs-",
]


@pytest.mark.parametrize("marker", PARITY)
def test_both_deployment_guides_carry_the_same_facts(marker):
    """A capability documented in one language and not the other is a trap in the other."""
    for doc in ("docs/deployment.md", "docs/deployment_zh.md"):
        assert marker in _read(doc), f"{doc} is missing {marker!r} while its twin has it"


@pytest.mark.parametrize("doc,heading", [("docs/deployment.md", "## Step 2: Deploy Backend"),
                                         ("docs/deployment_zh.md", "## 第 2 步：部署后端")])
def test_both_guides_say_stack_success_is_not_readiness(doc, heading):
    """From a measurement on 2026-09-12: a runtime pointed at an image that exits immediately, listens
    on no port and has no `/ping` still reports `READY`, and its stack still reaches
    `CREATE_COMPLETE`. So the caveat has to be at the step that creates the runtime.

    **Scoped to that step on purpose.** `READY` appears twice in each guide, so asking whether the word
    is in the file somewhere would pass with the caveat deleted. What this cannot check is the
    troubleshooting clause further down, which has no token of its own; that half is unguarded and
    saying so is better than a marker that would imply otherwise."""
    text = _read(doc)
    start = text.index(heading) + len(heading)
    block = text[start:start + text[start:].index("\n### ")]
    assert "READY" in block, (
        f"{doc}'s backend step no longer says a created runtime can still be dead. Stack success is "
        f"not evidence the agent answers, and this is the only place a reader learns that in time.")


def test_the_two_roadmaps_agree_on_what_has_shipped():
    """The roadmap states its own convention: a date on the right means shipped **and verified against
    a real environment**. So a date present in one language and absent in the other is not a wording
    difference, it is two different promises. Found one on 2026-09-12: the hourly-partition row read
    2026-09-10 in English and blank in Chinese."""
    def rows(name):
        out = []
        for line in _read(name).splitlines():
            if line.startswith("|") and not re.match(r"^\|[\s\-]+\|", line):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) == 2 and cells[0]:
                    out.append(cells)
        return out

    en, zh = rows("docs/roadmap.md"), rows("docs/roadmap_zh.md")
    assert en and zh, "no roadmap rows parsed, so this test proves nothing"
    assert len(en) == len(zh), (
        f"docs/roadmap.md has {len(en)} rows, docs/roadmap_zh.md has {len(zh)}; one gained or lost an "
        f"item without the other")
    disagree = [(i, a[1], b[1]) for i, (a, b) in enumerate(zip(en, zh)) if a[1] != b[1]]
    assert not disagree, f"date cells disagree at rows {disagree}"
