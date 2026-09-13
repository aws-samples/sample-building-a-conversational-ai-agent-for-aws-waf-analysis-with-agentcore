#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_iam_policy_is_documented.py` claims and require it to notice.

That test compares two sets for equality, which is the shape most able to pass while proving nothing:
two empty sets are equal. So four of the seven cases here blind one side of the comparison rather than
changing the data, because a parser that stopped matching reports perfect agreement and reads exactly
like a clean run.

The three data cases perturb the template or a document, which the target reads as text rather than
executing, so they skip the reachability probe. The four parser cases perturb helpers the target calls,
so they ask for it.
"""

import sys

from _harness import sweep

T = "tests/test_iam_policy_is_documented.py"
TPL = "deploy/backend.yaml"
EN = "docs/iam-permissions.md"
ZH = "docs/iam-permissions_zh.md"

GLUE_EN = "| `glue:GetTables` | List the tables in a database, so a table you created yourself is found | None (read) |\n"
GLUE_ZH = "| `glue:GetTables` | 列出某个数据库里有哪些表，这样你自己建的表也能被找到 | 无（只读） |\n"

CASES = [
    # The event that actually happened, in the direction that matters: an action granted and not
    # written down, so the list a user consents to is shorter than the list they get.
    ("an action granted and documented nowhere",
     [(TPL, "                  - wafv2:ListResourcesForWebACL\n",
       "                  - wafv2:ListResourcesForWebACL\n"
       "                  - cloudfront:ListDistributions\n")],
     [f"{T}::test_the_document_lists_exactly_what_the_role_grants"]),

    ("a documented action removed while the grant stays",
     [(EN, GLUE_EN, "")],
     [f"{T}::test_the_document_lists_exactly_what_the_role_grants"]),

    # The Chinese twin lagging is silent in a way the equality check above cannot see on its own,
    # because each language is compared against the template separately and this one is not.
    ("the Chinese document alone losing a row, which the per-language check cannot see",
     [(ZH, GLUE_ZH, "")],
     [f"{T}::test_the_two_languages_document_the_same_actions"]),

    ("the granted-action parser blinded, so the equality check compares nothing to nothing",
     [(T, '    listed = set(re.findall(r"^\\s*-\\s+([a-z0-9]+:[A-Za-z0-9*]+)\\s*$", block, re.M))',
       "    listed = set()")],
     [f"{T}::test_the_two_sides_were_actually_parsed"], True),

    ("the inline Action: form no longer collected, which is how one real grant goes missing",
     [(T, '    inline = set(re.findall(r"^\\s*Action:\\s+([a-z0-9]+:[A-Za-z0-9*]+)\\s*$", block, re.M))',
       "    inline = set()")],
     [f"{T}::test_the_two_sides_were_actually_parsed"], True),

    # The parse must stay inside the AgentPermissions policy. Reading from the top of the file pulls in
    # `sts:AssumeRole` from the trust policy, which is how the role is assumed rather than something the
    # agent may call, and documenting it would be a false statement about what reaches the account.
    ("the parse starting at the top of the file, so the trust policy is read as a grant",
     [(T, "    rest = text[text.index(POLICY):]", "    rest = text[0:]")],
     [f"{T}::test_the_two_sides_were_actually_parsed"], True),

    ("the document parser blinded, so every action reads as undocumented or as nothing at all",
     [(T, '    return set(re.findall(r"\\| `([a-zA-Z0-9]+:[A-Za-z0-9*]+)`", (ROOT / rel).read_text()))',
       "    return set()")],
     [f"{T}::test_the_two_sides_were_actually_parsed"], True),
]

sys.exit(sweep(CASES))
