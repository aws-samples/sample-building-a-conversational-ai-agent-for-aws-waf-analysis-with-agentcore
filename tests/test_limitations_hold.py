# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A limitations list rots in the dangerous direction, so the entries are checked, not trusted.

`docs/limitations.md` is entirely behavioural claims, and prose the code contradicts is this project's
largest defect class. **The direction matters more than the frequency.** A limitation that has since
been fixed does not merely mislead: the reader stops attempting the thing, so they never find out it
works now, and no feedback ever reaches us. That is the same judgement written into ROADMAP 4.6's
marker, where an overstated DONE was called worse than none because the next reader stops looking. Here
the reader is outside the repository.

So the file's own contract is that every entry either points at the code making it true or carries the
date it was measured, and this file holds the first half of that. **The existence check is the
load-bearing part**: if an entry names a function, field, dimension or API operation, that name must
still be findable. When someone deletes the mechanism, the claim about it should go red rather than
sitting there telling users not to try.

What this cannot check: an entry whose claim is true of a name that still exists. `matchedData` could
start being recorded for every rule type and the identifier would not move. Those entries carry a date
and a measurement source instead, which is the other half of the contract and is enforced by reading,
not by pytest. Saying so beats implying the coverage is wider than it is.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
EN = (ROOT / "docs/limitations.md").read_text()
ZH = (ROOT / "docs/limitations_zh.md").read_text()

# Every identifier the entries lean on, with where it has to still exist. A limitation that names one of
# these is only as good as the name, so a rename or a deletion has to fail here.
# Three columns, not two, because the string the DOC uses and the string the CODE uses are often
# different and an earlier version of this table assumed they were the same. The doc says "log filter";
# the code calls it `is_log_filter_active`. The doc names three metric dimensions in prose; the code
# builds them as dict literals.
IDENTIFIERS = [
    ("matchedData", "matchedData", "tools/waf_block_fp.py"),
    ("log filter", "def is_log_filter_active", "tools/session_state.py"),
    ("AppSync", "AppSync", "tools/waf_injection.py"),
    ("`WebACL`, `Rule` and `Region`", '{"Name": "WebACL"', "tools/waf_metrics.py"),
    ("`WebACL`, `Rule` and `Region`", '{"Name": "Region"', "tools/waf_metrics.py"),
]

# Documents the entries send the reader to. A limitation pointing at a file that no longer exists is a
# dead end at the moment the reader most needs the detail.
# (link text as it appears in the doc, path it must resolve to). Both halves, because checking only
# that the file exists leaves the row passing after someone deletes the link, and checking only that the
# link is present leaves it passing after someone deletes the file.
LINKED_DOCS = [
    ("hourly-vs-minute-partitioning.md", "docs/hourly-vs-minute-partitioning.md"),
    ("iam-permissions.md", "docs/iam-permissions.md"),
    ("data-privacy.md", "docs/data-privacy.md"),
    ("../AGENTS.md", "AGENTS.md"),
]


@pytest.mark.parametrize("in_doc,in_code,path", IDENTIFIERS)
def test_every_identifier_a_limitation_names_still_exists(in_doc, in_code, path):
    """The half a test can actually hold, and it needs both ends. Without the first assertion the row
    could outlive the entry it guards and quietly stop testing anything; without the second it is not
    testing the code at all. Scoped to the file the entry cites rather than the whole tree, because
    "the string appears somewhere in the repo" would survive the mechanism moving out of the module the
    reader was pointed at."""
    assert in_doc in EN, (
        f"docs/limitations.md no longer says {in_doc!r}, so this row guards nothing. Drop it if the "
        f"entry is gone on purpose.")
    source = (ROOT / path).read_text()
    assert in_code in source, (
        f"docs/limitations.md describes a limitation involving {in_code!r} but it is gone from {path}. "
        f"Either the limitation no longer holds, in which case delete the entry rather than softening "
        f"it, or the code moved and the citation needs updating.")


@pytest.mark.parametrize("link,target", LINKED_DOCS)
def test_the_documents_the_entries_point_at_are_linked_and_exist(link, target):
    """A limitation pointing at a file that is gone is a dead end at the moment the reader most needs
    the detail. A row pointing at a link that is gone tests nothing, which is why both ends are here."""
    assert link in EN, f"docs/limitations.md no longer links {link!r}; drop this row if that is deliberate"
    assert (ROOT / target).exists(), f"{target} is linked from docs/limitations.md and does not exist"


def test_no_runtime_session_listing_api_has_appeared():
    """The one entry with a date rather than a code citation, and the only one whose truth can flip
    without any file in this repository changing: AWS could add the operation tomorrow.

    **Read through botocore's own loader, which is what makes this run anywhere.** The first version
    globbed `/usr/local/aws-cli/awscli/botocore/data/...` and skipped when it found nothing, so the
    one limitation that can go stale on its own was checked on one laptop and nowhere else. Deriving
    the directory from `botocore.__file__` does not fix it either: the installed package ships
    `service-2.json.gz` while the CLI bundle ships it uncompressed, so that glob finds zero models
    and skips exactly as silently. The loader handles both and needs no credentials or network.

    So there is no skip branch. botocore arrives with boto3, which the agent cannot run without.
    """
    import botocore.session

    session = botocore.session.get_session()
    required = {}
    for service in ("bedrock-agentcore-control", "bedrock-agentcore"):
        model = session.get_service_model(service)
        for name in model.operation_names:
            shape = model.operation_model(name).input_shape
            required[name] = set(shape.required_members) if shape else set()
    assert len(required) > 150, (
        f"only {len(required)} operations across both AgentCore APIs, which is too few to be the "
        f"real models. An absence claim over a search space that collapsed passes perfectly.")

    # **Matched on the required inputs, not only on the spelling.** An operation that enumerates a
    # runtime's sessions has to take a runtime identifier, whatever it ends up being called, and
    # `ListAgentSessions` would slip past a name pattern looking for "Runtime". The six `List*Session*`
    # operations that do exist each take an identifier for the thing whose sessions they list:
    # `browserIdentifier`, `codeInterpreterIdentifier`, `paymentManagerArn`, or a memory and an actor.
    runtime_ids = {"agentRuntimeArn", "agentRuntimeId", "runtimeIdentifier"}
    enumerators = {name: sorted(required[name]) for name in required
                   if name.startswith("List") and "Session" in name
                   and ("Runtime" in name or runtime_ids & required[name])}
    assert not enumerators, (
        f"{enumerators} now exists, so the limitation in docs/limitations.md is stale. Delete the "
        f"entry, and check whether the stuck-session advice elsewhere should change too.")

    # The entry states both of these verbatim, so both are pinned. The pair is the whole point: one
    # operation exists and cannot be used without an id, the other hands out ids for something else.
    assert required.get("StopRuntimeSession") == {"agentRuntimeArn", "runtimeSessionId"}, (
        f"the entry says StopRuntimeSession takes those two; it now takes "
        f"{sorted(required.get('StopRuntimeSession', ()))}")
    assert required.get("ListSessions") == {"actorId", "memoryId"}, (
        f"the entry says ListSessions is memory-scoped; its required inputs are now "
        f"{sorted(required.get('ListSessions', ()))}")


def test_both_languages_carry_the_same_entries():
    """Section headings and entry count, not wording. The Chinese twin lagging is the specific failure
    that has already happened once today in another file, and it is silent: the reader simply never
    learns about the limitation."""
    def headings(text):
        return [line for line in text.splitlines() if line.startswith("## ")]

    assert len(headings(EN)) == len(headings(ZH)), (
        f"{len(headings(EN))} sections in English, {len(headings(ZH))} in Chinese")
    bold_en = len(re.findall(r"^\*\*", EN, re.M))
    bold_zh = len(re.findall(r"^\*\*", ZH, re.M))
    assert bold_en == bold_zh, f"{bold_en} entries in English, {bold_zh} in Chinese"
    assert bold_en >= 12, "suspiciously few entries; has the file been gutted rather than pruned?"


def test_the_file_states_its_own_contract():
    """The contract is what makes the rest of this file meaningful, and it is prose, so it can be
    edited away by someone tidying. Both halves are pinned: entries are cited or dated, and a fixed
    limitation is deleted rather than reworded."""
    assert "deleted rather than softened" in EN, "the delete-when-fixed rule is gone from the file"
    assert "删掉" in ZH and "软化" in ZH, "the Chinese twin no longer states the same rule"
    for text, marker in ((EN, "What a particular deployment happens to be running is not here"),
                         (ZH, "某一次部署恰好在跑什么，不写在这里")):
        assert marker in text, (
            "the boundary against deployment state is gone. Without it this file acquires facts that "
            "expire on the next deploy, and nobody will think to come here and fix them.")
