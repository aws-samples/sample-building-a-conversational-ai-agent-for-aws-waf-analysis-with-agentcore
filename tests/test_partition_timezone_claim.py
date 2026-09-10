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
# belongs. `tests/` is excluded because this file quotes every banned phrase in order to ban it.
EXCLUDED = ("design/", ".venv/", "node_modules/", "tests/")


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
        if rel.startswith(EXCLUDED):
            continue
        lines = path.read_text(errors="ignore").splitlines()
        if rel == "CHANGELOG.md":
            lines = _unreleased_only(lines)
        for n, line in enumerate(lines, 1):
            if claim in line.lower():
                offenders.append(f"{rel}:{n}")
    assert not offenders, f"{claim!r} still shipped at: {offenders}"


def test_the_sweep_searched_the_files_it_claims_to_cover():
    """The precondition, named subjects rather than a count. A `rglob` that matched nothing, or
    an exclusion that swallowed the shipped tree, satisfies every absence claim above."""
    searched = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                if p.is_file() and p.suffix in (".py", ".md")
                and not p.relative_to(ROOT).as_posix().startswith(EXCLUDED)}
    assert set(SUBJECTS) <= searched, sorted(set(SUBJECTS) - searched)
