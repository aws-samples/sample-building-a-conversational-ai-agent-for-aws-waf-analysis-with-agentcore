# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A non-UTC Firehose prefix time zone is handled, and four places said otherwise.

`resolve_log_table` has read `CustomTimeZone` off the delivery stream since PR #12 and prunes
partitions in that zone. Verified 2026-09-09 against a throwaway stream at `Asia/Tokyo` with a
UTC control: the detected zone moved the rendered partition bounds nine hours, which is exactly
the miss Athena would have reported as zero rows.

Four places still told users the opposite, and only one of them was reported. `waf_config.py`
told the model on every Firehose destination that the zone MUST be UTC and that a non-UTC zone
returns 0 results, so the agent asked users to confirm a setting it had already read.
`docs/firehose-minute-partitioning.md`, its `_zh` twin and `kb-docs/` carried the same claim in
a setup checklist, telling users a working configuration was broken.

**A sweep because "fix the one that was reported" is what created this.** Same lesson as ROADMAP
4.5, where the falsified sentence was corrected once and a second copy kept shipping. The one
reported here was the code; three were prose, two of them public.

**Paired with a presence check over the same files, which is the half that is easy to skip.** An
absence claim over a search space that shrank to nothing passes perfectly. So each file must
also still carry the corrected statement: the sweep can only go green while the files exist and
say the right thing.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# file -> a phrase the CORRECTED text must contain. Keys are the subjects, so a renamed or
# deleted file fails rather than silently leaving the absence claim true.
SUBJECTS = {
    "tools/waf_config.py": "detected from the delivery",
    "docs/firehose-minute-partitioning.md": "prunes partitions in that zone",
    "kb-docs/firehose-minute-partitioning.md": "prunes partitions in",
    "docs/firehose-minute-partitioning_zh.md": "按该时区裁剪分区",
}

# Only the false assertions. Deliberately not "non-UTC" or "0 rows" on their own, because the
# corrected text uses both: it says a non-UTC zone needs nothing from you, and it keeps the
# genuine symptom, 0 rows while metrics show traffic, as the thing worth reporting.
FALSE_CLAIMS = (
    "must be utc",
    "will cause queries to return 0",
    "makes queries return 0",
    "queries will return 0 results",
    "assumes utc paths",
    "会导致查询返回 0",
    "假设路径为 utc",
)


@pytest.mark.parametrize("rel,corrected", sorted(SUBJECTS.items()))
def test_each_file_still_says_the_true_thing(rel, corrected):
    """The presence half. Without it, deleting a file makes the absence sweep below pass."""
    path = ROOT / rel
    assert path.exists(), f"{rel} is gone, so the absence sweep below proves nothing"
    assert corrected in path.read_text(), \
        f"{rel} no longer states that the zone is detected; did the fix get reverted?"


# `design/` records superseded reasoning on purpose, which is exactly where a falsified claim
# belongs. This file is excluded because it quotes every banned phrase in order to ban them.
#
# **The exclusion is THIS FILE, not all of `tests/`, and the difference is the stated reason.**
# The justification only ever covered one file, and it is the only file under `tests/` containing
# a banned phrase, so narrowing it passes today and stops the next test file from carrying the
# claim in a docstring. Same shape as excluding the registration site rather than the whole
# module, which is the mistake that let the `log_query_error` sweep pass.
EXCLUDED_PREFIXES = ("design/", ".venv/")
EXCLUDED_FILES = ("tests/test_partition_timezone_claim.py",)


def _excluded(rel: str) -> bool:
    """Whether a repo-relative path is out of the search space.

    **`node_modules` is matched anywhere in the path, not as a prefix.** It used to sit in the
    prefix tuple, where it never matched, because the real path is `frontend/node_modules/...`:
    56 of the 147 files swept were inside an npm package, 38% of the search space, walked once
    per parametrized claim. Nothing in there matches a banned phrase today, so the test was
    green, and a dependency bump could have turned a product-claim test red with an offender
    path inside a third-party README. A false-positive generator inside the one test whose whole
    value is a trustworthy signal.

    Not gitignore-aware, so anything untracked but present locally is still swept. Left that way
    deliberately: reading `.gitignore` here would be a second exclusion mechanism to keep in
    step with this one, and an extra file in the search space is the harmless direction."""
    return (rel.startswith(EXCLUDED_PREFIXES) or rel in EXCLUDED_FILES
            or "node_modules" in rel)


def _unreleased_only(lines: list[str]) -> list[str]:
    """Just the part of the CHANGELOG above the newest release heading.

    A released section is a record of what that release shipped, and `0.9.0` accurately says it
    documented the must-be-UTC rule. Rewriting it would falsify history, so history is exempt.
    But exempting the WHOLE file would let a new entry reintroduce the claim as a statement about
    the current product, which is precisely what this sweep is for. So the exemption stops at the
    first version heading."""
    for i, line in enumerate(lines):
        if re.match(r"^## \d+\.\d+\.\d+", line):
            return lines[:i]
    return lines


@pytest.mark.parametrize("claim", FALSE_CLAIMS)
def test_no_file_claims_a_non_utc_prefix_zone_breaks_queries(claim):
    """The absence half, over the whole tree rather than the four known files, because the next
    copy will be written somewhere nobody is looking."""
    offenders = []
    for path in sorted(ROOT.rglob("*")):
        if path.suffix not in (".py", ".md") or not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if _excluded(rel):
            continue
        lines = path.read_text(errors="ignore").splitlines()
        if rel == "CHANGELOG.md":
            lines = _unreleased_only(lines)
        for n, line in enumerate(lines, 1):
            if claim in line.lower():
                offenders.append(f"{rel}:{n}")
    assert not offenders, (
        f"{claim!r} still shipped at: {offenders}. If one of these is a CHANGELOG entry "
        f"DESCRIBING the old claim, that is legitimate and this is not a regression: attribute "
        f"it, as in 'used to say a non-UTC zone returned no rows', so the sentence reads as "
        f"history rather than as the product's current behaviour. Released sections are already "
        f"exempt; the Unreleased section is not, on purpose.")


def test_the_sweep_searched_the_files_it_claims_to_cover():
    """The precondition, named subjects rather than a count. A `rglob` that matched nothing, or
    an exclusion that swallowed the shipped tree, satisfies every absence claim above."""
    searched = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                if p.is_file() and p.suffix in (".py", ".md")
                and not _excluded(p.relative_to(ROOT).as_posix())}
    assert set(SUBJECTS) <= searched, sorted(set(SUBJECTS) - searched)
