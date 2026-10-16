# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""What the Anti-DDoS exempt-URI regex matches, as the knowledge base and the prompt tell it.

`ExemptUriRegularExpressions` is matched against the host followed by the normalized path, e.g.
`www.example.com/api/orders`, so a branch opening `^/` or `^\\/` never matches (API Reference,
`ClientSideAction`). Measured 2026-10-16 on `shield-sample-webacl` with GETs read back by their
`challengeable-request` label: under `^\\/api\\/` the request to `/api/orders` stayed challengeable;
a temporary `^d2uloqf425puyh\\.cloudfront\\.net/api/` exempted it; `^[^/]+\\/api(\\/|$)` exempted
`/api`, `/api/` and `/api/orders` and left `/x/api/orders` challengeable. The knowledge base told
users to anchor every API branch with `^`, which is the form that silently exempts nothing.

The label is on every non-exempt GET whenever the challenge action is enabled, not only during an
event, so an exemption can be checked from ordinary logs.

The dual-instance pattern is a last resort, decided with the maintainer 2026-10-16: AWS recommends
against a scope-down on this rule group, because it limits the traffic the baseline is built from.
"""

import pathlib
import re

import agent

ROOT = pathlib.Path(__file__).resolve().parents[1]
KB = (ROOT / "kb-docs" / "antiddos-amr.md").read_text()


def test_a_branch_anchored_at_the_path_appears_only_as_one_that_never_matches():
    """The old advice wrote `^\\/api\\/|^\\/query|...` as the form to use. The form may still be
    named, as the thing to look for in a review, but only on a line that says it never matches."""
    seen = 0
    for name, text in (("kb-docs/antiddos-amr.md", KB), ("agent.py", agent.SYSTEM_PROMPT)):
        for line in text.splitlines():
            if re.search(r"(?:^|[`|(])\^\\?/", line):
                seen += 1
                assert "never match" in line, f"{name}: {line}"
    assert seen >= 2, "the wrong form is not named anywhere, so a reviewer cannot recognise it"


def test_the_working_forms_are_given():
    assert "^[^/]+\\/api(\\/|$)" in KB and "^api\\.example\\.com\\/" in KB, "the host-anchored forms are missing"
    assert "host followed by its normalized path" in KB and "never matches" in KB
    # The prompt writes it without escapes, which a regex does not need for `/` and a plain string
    # cannot hold without doubling them.
    assert "^[^/]+/api(/|$)" in agent.SYSTEM_PROMPT


def test_an_exemption_is_checked_from_ordinary_logs():
    assert "not only during an event" in KB and "challengeable-request" in KB


def test_two_instances_are_the_last_resort_with_their_cost_stated():
    assert "Last resort: dual AMR instance" in KB, "the dual-instance pattern is still offered as a default"
    assert "recommends against" in KB and "baseline" in KB
