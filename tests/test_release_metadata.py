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
    the version bump is four file edits and the tag is a separate step afterwards."""
    untagged = sorted({h for h in headings if _v(h) >= BACKFILL_FLOOR} - set(tags), key=_v)
    assert not untagged, f"in CHANGELOG.md with no v-tag: {untagged}"


def test_the_backfill_floor_still_describes_reality(headings, tags):
    """The floor is an assertion about history, not a mute constant. If someone backfills the
    older tags this fails and the floor should move down, rather than the exemption silently
    covering releases that are now tagged."""
    below = {h for h in headings if _v(h) < BACKFILL_FLOOR}
    assert below, "nothing sits below the floor any more, so lower BACKFILL_FLOOR"
    assert not (below & set(tags)), \
        f"tagged despite being below the floor, so lower it: {sorted(below & set(tags), key=_v)}"


def test_the_four_version_strings_agree(headings):
    """All four, though only three of the legs are perturbation-provable and it is worth
    saying which.

    `uv.lock` was the one that drifted historically: `v0.14.0` tagged a lockfile still reading
    0.13.0, because it was hand-edited instead of regenerated. **That state cannot survive a
    `uv run` in this repo.** Measured 2026-09-10: setting the lockfile back to 0.17.0 and then
    invoking anything through `uv` rewrites it to match `pyproject.toml` before pytest reads a
    byte, so a perturbation of this leg reports a false pass. The leg stays in the comparison,
    because it costs nothing and it fails when `pyproject.toml` itself is wrong, but the
    self-healing is why nobody should treat it as the guard.

    The provable legs are `pyproject.toml`, `frontend/package.json` and the CHANGELOG heading,
    which `uv` does not touch. The heading matters most: `frontend/vite.config.js` regexes the
    first `## X.Y.Z` into `__APP_VERSION__`, so a mismatch ships a UI labelled with the
    previous release."""
    newest = headings[0]
    pyproject = re.search(r'^version = "(.+?)"', (ROOT / "pyproject.toml").read_text(), re.M)
    package = re.search(r'^  "version": "(.+?)"',
                        (ROOT / "frontend/package.json").read_text(), re.M)
    lock = re.search(r'name = "waf-agent"\nversion = "(.+?)"', (ROOT / "uv.lock").read_text())
    assert pyproject and package and lock, "a version string could not be located at all"
    assert {pyproject.group(1), package.group(1), lock.group(1)} == {newest}, {
        "CHANGELOG": newest, "pyproject.toml": pyproject.group(1),
        "frontend/package.json": package.group(1), "uv.lock": lock.group(1)}


def test_the_newest_heading_is_the_highest_version(headings):
    """`vite.config.js` takes the FIRST `## X.Y.Z` it finds, not the greatest, so a section
    inserted in the wrong place would silently set the frontend badge to an older release."""
    assert _v(headings[0]) == max((_v(h) for h in headings)), headings[:3]
