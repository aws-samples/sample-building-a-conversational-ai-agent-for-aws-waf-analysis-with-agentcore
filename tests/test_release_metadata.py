# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A release is a CHANGELOG heading, a tag and four agreeing version strings.

Every one of those has drifted at least once. `v0.14.0` tagged a lockfile that still said
0.13.0, because `uv.lock` was hand-edited instead of regenerated. Five releases shipped with
the deployed container four releases behind. And the CHANGELOG heading is not documentation:
`frontend/vite.config.js` regexes the first `## X.Y.Z` into `__APP_VERSION__` at build time,
so writing that heading *is* the frontend version bump.

**Deliberately not a sweep of the docs for version numbers.** That was the first idea and it
has nothing to catch: the pattern `\\d+\\.\\d+\\.\\d+` over `docs/`, `AGENTS.md` and
`README*.md` matches fourteen IP-address fragments (`203.0.113`, `54.254.254` and friends) and
zero version strings. A check whose first run produces an allowlist chore rather than a
finding is not worth having.
"""

import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Tags were backfilled only to v0.13.0. Everything older has a heading and no tag on purpose,
# because reconstructing which commit a 2026-06 release pointed at is archaeology and a wrong
# tag is worse than no tag. So the "every heading is tagged" rule starts here.
BACKFILL_FLOOR = (0, 13, 0)


def _dirty(path: str) -> bool:
    """True when `path` has uncommitted changes.

    Two assertions below describe a release that has LANDED, and a cut in progress is the
    legitimate window where they are false: the heading exists before the tag, and `uv lock`
    rewrites the lockfile before the commit. Keying the exemptions on dirtiness makes them
    self-limiting rather than a flag, because a dirty tree cannot be tagged or shipped, and it
    keeps the real defect failing: a cut that was committed and never tagged has a clean
    CHANGELOG."""
    return bool(subprocess.run(["git", "status", "--porcelain", "--", path], cwd=ROOT,
                               capture_output=True, text=True, check=True).stdout.strip())


def _v(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


@pytest.fixture(scope="module")
def headings() -> list[str]:
    found = re.findall(r"^## (\d+\.\d+\.\d+)", (ROOT / "CHANGELOG.md").read_text(), re.M)
    assert found, "no release headings parsed, so every assertion below is vacuous"
    return found


@pytest.fixture(scope="module")
def tags() -> list[str]:
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout, so there are no tags to compare against")
    out = subprocess.run(["git", "tag", "-l", "v*"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.split()
    assert out, "git reported no v* tags, so every assertion below is vacuous"
    return [t[1:] for t in out]


def test_every_tag_has_a_changelog_section(headings, tags):
    """A tag with no section is a release nobody can read the notes for, and the GitHub
    Release body is copied from that section."""
    orphans = sorted(set(tags) - set(headings), key=_v)
    assert not orphans, f"tagged but absent from CHANGELOG.md: {orphans}"


def test_every_heading_since_the_backfill_floor_is_tagged(headings, tags):
    """The direction that catches a cut nobody tagged, which is the easier half to forget:
    the version bump is four file edits and the tag is a separate step afterwards.

    **This test is expected to fail on a release branch, between the cut commit and the tag, and
    that is the signal rather than a nuisance.** The tag goes on the cut PR's *merge* commit, so
    it cannot exist while the branch does. Once the merge lands and the tag is pushed, this goes
    green on `main`. Do not weaken it to quiet the window: quieting it removes the only check
    that a forgotten tag ever trips."""
    untagged = {h for h in headings if _v(h) >= BACKFILL_FLOOR} - set(tags)
    # Mid-cut the newest heading is written and the tag comes after the merge, so exempt it
    # while CHANGELOG.md is uncommitted. Only the newest: an OLDER untagged heading is the real
    # defect and still fails, dirty tree or not.
    if _dirty("CHANGELOG.md") and headings:
        untagged -= {max(headings, key=_v)}
    assert not sorted(untagged, key=_v), f"in CHANGELOG.md with no v-tag: {sorted(untagged, key=_v)}"


def test_the_backfill_floor_still_describes_reality(headings, tags):
    """The floor is an assertion about history, not a mute constant. If someone backfills the
    older tags this fails and the floor should move down, rather than the exemption silently
    covering releases that are now tagged."""
    below = {h for h in headings if _v(h) < BACKFILL_FLOOR}
    assert below, "nothing sits below the floor any more, so lower BACKFILL_FLOOR"
    assert not (below & set(tags)), \
        f"tagged despite being below the floor, so lower it: {sorted(below & set(tags), key=_v)}"


def test_the_four_version_strings_agree(headings):
    """The three legs a developer can get wrong by hand: `pyproject.toml`,
    `frontend/package.json` and the CHANGELOG heading. The heading matters most, because
    `frontend/vite.config.js` regexes the first `## X.Y.Z` into `__APP_VERSION__`, so a
    mismatch ships a UI labelled with the previous release.

    **`uv.lock` is deliberately absent from this comparison, and the reason is not that its
    failure is hard to synthesize. It is that the assertion could not fail.** `uv run` rewrites
    the lockfile from `pyproject.toml` before pytest reads a byte, measured 2026-09-10 by
    setting it to 0.17.0 and watching it come back 0.18.0. So a test runner that enforces the
    invariant would have been checking it: a tautology, not an unprovable claim. The next
    reader should not go looking for a cleverer perturbation, because there is nothing to
    catch. The check with teeth is the test below."""
    newest = headings[0]
    pyproject = re.search(r'^version = "(.+?)"', (ROOT / "pyproject.toml").read_text(), re.M)
    package = re.search(r'^  "version": "(.+?)"',
                        (ROOT / "frontend/package.json").read_text(), re.M)
    assert pyproject and package, "a version string could not be located at all"
    assert {pyproject.group(1), package.group(1)} == {newest}, {
        "CHANGELOG": newest, "pyproject.toml": pyproject.group(1),
        "frontend/package.json": package.group(1)}


def test_the_committed_lockfile_is_not_stale(tags):
    """The defect `v0.14.0` actually shipped: a tag pointing at a commit whose `uv.lock` still
    read 0.13.0, because the lockfile was hand-edited rather than regenerated.

    Reading the working copy cannot see that, since `uv` has already repaired it. What can is
    the diff: **once `uv` has normalised the working lockfile, any difference against `HEAD` is
    a committed lockfile that disagrees with `pyproject.toml`.** That is exactly the state
    `v0.14.0` was tagged in, and it is the same signal the pre-cut clean-tree step checks by
    hand.

    Not perturbable by editing a file, because synthesizing the failure means committing a
    stale lockfile. It was proven on a throwaway branch instead: committing a lockfile at
    0.17.0 under a `pyproject.toml` at 0.18.0 makes this fail and nothing else in the suite
    notice. Failure-capability and perturbability are different properties, and only the first
    decides whether an assertion earns its place."""
    # `uv.lock` dirty ALONGSIDE `pyproject.toml` is a version bump in flight, which is the cut
    # workflow. `uv.lock` dirty on its own is the defect: uv repaired the working copy because
    # the committed one disagreed with a `pyproject.toml` nobody is editing.
    if _dirty("pyproject.toml"):
        pytest.skip("version bump in flight, so the committed lockfile is expected to lag")
    assert not _dirty("uv.lock"), (
        "uv.lock differs from HEAD after uv normalised it, which means the COMMITTED lockfile "
        "does not match pyproject.toml. Run `uv lock` and commit the result before tagging.")


def test_the_newest_heading_is_the_highest_version(headings):
    """`vite.config.js` takes the FIRST `## X.Y.Z` it finds, not the greatest, so a section
    inserted in the wrong place would silently set the frontend badge to an older release."""
    assert _v(headings[0]) == max((_v(h) for h in headings)), headings[:3]
