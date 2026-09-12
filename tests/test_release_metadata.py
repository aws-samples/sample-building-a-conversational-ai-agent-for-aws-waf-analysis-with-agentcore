# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A release is a CHANGELOG heading, a tag and six agreeing version strings.

Every one of those has drifted at least once. `v0.14.0` tagged a lockfile that still said
0.13.0, because `uv.lock` was hand-edited instead of regenerated. Five releases shipped with
the deployed container four releases behind. And the CHANGELOG heading is not documentation:
`frontend/vite.config.js` regexes the first `## X.Y.Z` into `__APP_VERSION__` at build time,
so writing that heading *is* the frontend version bump.

**Still not a sweep of the docs for version numbers, and that distinction has now been tested both
ways.** A bare `\\d+\\.\\d+\\.\\d+` over `docs/`, `AGENTS.md` and `README*.md` matches fourteen
IP-address fragments (`203.0.113`, `54.254.254` and friends) and zero version strings, so it produces
an allowlist chore rather than a finding. But a *narrow* doc pattern is a different thing: `ReleaseTag=vX`
appears once per deployment guide and names the release a reader will actually deploy. Cutting 0.23.0
left both guides saying `v0.22.0`, so anyone copying the documented command deployed a release behind,
and the guard missed it because it only knew the template's default. Narrow enough to have exactly one
match per file is the line between the two ideas.
"""

import json
import pathlib
import re
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Tags were backfilled only to v0.13.0. Everything older has a heading and no tag on purpose,
# because reconstructing which commit a 2026-06 release pointed at is archaeology and a wrong
# tag is worse than no tag. So the "every heading is tagged" rule starts here.
BACKFILL_FLOOR = (0, 13, 0)


def _default_branch_ref() -> str | None:
    """A remote-tracking ref for the default branch, or None when none resolves.

    Resolved rather than hardcoded, and that is not defensiveness. This repo's remote is
    `github`, not `origin`, so `origin/main` does not exist, and `merge-base --is-ancestor`
    against a missing ref exits non-zero exactly as it does for "not an ancestor". Hardcoding
    `origin/main` would therefore read every run as unmerged and disable the check permanently,
    which is the one failure direction that matters here."""
    for remote in subprocess.run(["git", "remote"], cwd=ROOT, capture_output=True,
                                 text=True, check=True).stdout.split():
        ref = f"{remote}/main"
        if subprocess.run(["git", "rev-parse", "--verify", "--quiet", ref],
                          cwd=ROOT, capture_output=True).returncode == 0:
            return ref
    return None


def _is_shipped() -> bool:
    """True when HEAD is reachable from the default branch, i.e. this code has landed.

    **Fails closed.** When no remote ref resolves we cannot tell, so the answer is "shipped"
    and the assertion applies. Guessing "unshipped" would be the exemption swallowing the check
    on any clone whose remotes are named unexpectedly.

    **The hole, named rather than left for someone to find.** A local default branch that is
    ahead of its remote counterpart reads as unshipped, so a cut merged locally and not yet
    pushed would go quiet. This workflow merges on GitHub and fast-forwards, so the two agree,
    and the pre-cut step already requires a clean tree in sync with the remote. A branch-name
    check has no such hole but breaks the moment a cut happens on a differently-named branch,
    and that is the likelier accident."""
    ref = _default_branch_ref()
    if ref is None:
        return True
    return subprocess.run(["git", "merge-base", "--is-ancestor", "HEAD", ref],
                          cwd=ROOT, capture_output=True).returncode == 0


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

    **The contract.** Every heading at or above the backfill floor must have a tag, except the
    newest one while this code is unshipped, because the tag goes on the cut PR's merge commit
    and cannot exist while the branch does. An older untagged heading fails always.

    **What still needs protecting, since the exemption is the load-bearing part.** Do not widen
    it past the newest heading, and do not let `_is_shipped` fail open: either turns the only
    check a forgotten tag ever trips into a check that cannot fail. An earlier version of this
    docstring argued the opposite, that failing on a release branch was the signal and should not
    be quieted, and that argument is superseded rather than merely out of date: keying on
    unshipped rather than on uncommitted closes the window without weakening anything."""
    untagged = {h for h in headings if _v(h) >= BACKFILL_FLOOR} - set(tags)
    # Exempt the newest heading until this code has shipped. The tag goes on the cut PR's MERGE
    # commit, so it cannot exist while the branch does, and the window is the whole life of the
    # PR rather than just the uncommitted part. Keying on the dirty tree covered only the
    # uncommitted half and left every release PR red, which costs nothing while CI runs CodeQL
    # only and turns into a standing false alarm the moment ROADMAP 5.4 puts pytest in CI.
    #
    # Ancestry keeps the property the exemption needs: the defect it guards, a heading cut and
    # never tagged, can only manifest on the default branch, because a release branch cannot be
    # shipped. So the exemption keys on being unshipped and cannot cover shipped state. Only the
    # newest heading either way: an OLDER untagged heading is the real defect and still fails.
    if headings and (not _is_shipped() or _dirty("CHANGELOG.md")):
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


# Every place a release number is written by hand, with a pattern narrow enough that it cannot
# match a neighbouring value. Adding a row is the whole cost of adding a seventh place.
#
# **Two of these were added after a cut falsified them within the hour.** Bumping to 0.23.0 left
# `ReleaseTag=v0.22.0` in both deployment guides, so anyone copying the documented command deployed a
# release behind, and the guard did not notice because it only knew the template's default. A
# from-scratch deploy driven by the documentation is what surfaced it.
#
# `frontend/package-lock.json` had said 0.12.0 for eleven releases. `npm install` rewrites it, so
# every reader following the documented frontend build got a dirty working tree and no explanation.
def _rx(pattern):
    return lambda text: re.findall(pattern, text, re.M)


def _lockfile_versions(text):
    """Parsed, not matched. A lockfile carries a `"version"` for every dependency, so any regex loose
    enough to find both of the project's own would also collect several hundred others."""
    data = json.loads(text)
    return [data["version"], data["packages"][""]["version"]]


VERSION_STRINGS = [
    ("pyproject.toml", "pyproject.toml", _rx(r'^version = "(\d+\.\d+\.\d+)"')),
    ("frontend/package.json", "frontend/package.json", _rx(r'^  "version": "(\d+\.\d+\.\d+)"')),
    ("frontend/package-lock.json", "frontend/package-lock.json", _lockfile_versions),
    # Scoped to the ReleaseTag block: the template has three `Default:` lines, and matching the first
    # that happens to look like a version would drift silently.
    ("deploy/image-build.yaml ReleaseTag", "deploy/image-build.yaml",
     _rx(r"^  ReleaseTag:\n(?:    .*\n)*?    Default: v(\d+\.\d+\.\d+)$")),
    ("docs/deployment.md example", "docs/deployment.md", _rx(r"ReleaseTag=v(\d+\.\d+\.\d+)")),
    ("docs/deployment_zh.md example", "docs/deployment_zh.md", _rx(r"ReleaseTag=v(\d+\.\d+\.\d+)")),
]


def test_every_hand_written_version_string_agrees(headings):
    """The four legs a developer can get wrong by hand: `pyproject.toml`,
    `frontend/package.json`, `deploy/image-build.yaml`'s `ReleaseTag` default and the
    CHANGELOG heading. The heading matters most, because `frontend/vite.config.js` regexes
    the first `## X.Y.Z` into `__APP_VERSION__`, so a mismatch ships a UI labelled with the
    previous release.

    **`ReleaseTag` is the odd one, because it names a release that must already EXIST.** The
    remote build downloads `…/archive/refs/tags/<ReleaseTag>.tar.gz`, so between the version
    bump and the tag the default points at a release nobody has published. That window is
    minutes wide, it is the same window this file's other assertions are red in, and its
    failure is loud: the build gets a 404 and the stack rolls back naming the phase. Tracking
    the version being cut is still the right choice, because the alternative is a default one
    release behind forever, which is wrong for every user rather than for a few minutes.

    **`uv.lock` is deliberately absent from this comparison, and the reason is not that its
    failure is hard to synthesize. It is that the assertion could not fail.** `uv run` rewrites
    the lockfile from `pyproject.toml` before pytest reads a byte, measured 2026-09-10 by
    setting it to 0.17.0 and watching it come back 0.18.0. So a test runner that enforces the
    invariant would have been checking it: a tautology, not an unprovable claim. The next
    reader should not go looking for a cleverer perturbation, because there is nothing to
    catch. The check with teeth is the test below."""
    newest = headings[0]
    found = {}
    for label, path, extract in VERSION_STRINGS:
        matches = extract((ROOT / path).read_text())
        assert matches, f"{label}: no version string matched in {path}, so this test proves nothing"
        found[label] = set(matches)

    wrong = {label: sorted(values) for label, values in found.items() if values != {newest}}
    assert not wrong, {"CHANGELOG": newest, **wrong}


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
