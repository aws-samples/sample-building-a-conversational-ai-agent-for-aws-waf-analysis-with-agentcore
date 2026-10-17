# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""No guide the model reads calls a Count override of `TGT_TokenAbsent` harmful.

Its default action is Count. Measured 2026-10-15 two ways: `describe-managed-rule-group` for
`AWSManagedRulesBotControlRuleSet` Version_6.1 returns `TGT_TokenAbsent Count`, and on
`response-id-on-page`, whose overrides name only `SignalNonBrowserUserAgent` and
`CategoryHttpLibrary`, it was logged as COUNT 2137 times in 14 days. So "never override it to Count"
forbids a no-op, and the deep review rated that no-op Critical. The harmful direction is Block:
without the SDK or a token-issuing rule in front, it matches every request that has no token.

`kb-docs/` is what the agent retrieves.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
HARMFUL_COUNT = re.compile(r"(NEVER|Do not|Don't|Critical)[^.\n]*(override|overridden)[^.\n]*to Count"
                           r"|(override|overridden)[^.\n]*to Count[^.\n]*(NEVER|Critical)"
                           r"|Do not override to Count", re.I)


def _lines():
    for folder in ("kb-docs",):
        for path in sorted((ROOT / folder).glob("*.md")):
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if "TGT_TokenAbsent" in line:
                    yield f"{folder}/{path.name}:{n}", line


def test_no_guide_treats_a_count_override_of_token_absent_as_harmful():
    lines = list(_lines())
    assert len(lines) >= 4, f"only {len(lines)} lines mention TGT_TokenAbsent; the guides moved"
    assert HARMFUL_COUNT.search("- TGT_TokenAbsent → NEVER override to Count"), "the pattern no longer matches the old text"
    bad = [(where, line) for where, line in lines if HARMFUL_COUNT.search(line)]
    assert not bad, bad


def test_the_guides_name_block_as_the_harmful_direction():
    assert any("Block" in line for where, line in _lines() if where.startswith("kb-docs/"))
