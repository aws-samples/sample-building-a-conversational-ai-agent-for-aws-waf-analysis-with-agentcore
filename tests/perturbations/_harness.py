# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The shared guard logic every perturbation script runs on.

A perturbation script breaks one property the test suite claims to hold and requires a named test to
notice. The value is entirely in the guards: a perturbation that never applied, or that broke the
file so badly that pytest died at import, reports red for a reason unrelated to the assertion under
examination, and a green run tells you nothing about whether the assertion works. Nineteen scripts
each carried their own copy of this loop, four of them with no anchor-count check and thirteen with no
reachability probe, and four had drifted into proving nothing by the time they were collected here.

Eight guards, and each one exists because its absence produced a wrong answer at least once:

1. **The targets pass before anything is touched.** Red after a perturbation only means something if
   green was the starting point. A target id with a typo lands here too: pytest reports a missing id
   as an error, so the baseline goes red rather than silently running zero tests and exiting 0.
2. **Every anchor occurs exactly as many times as declared, default once.** An anchor matching zero
   times means the case never applied and the script has drifted from the code. An anchor matching
   three times perturbs two things nobody was measuring.
3. **The edit changes something.** `old == new` slips in while editing a case by hand, and a
   transform located by AST can match nothing and return the file unchanged.
4. **A perturbed `.py` file still parses.** Otherwise the target is red at import and would be red
   for any edit at all, including one that leaves the property intact.
5. **The perturbed line executes**, for the cases that ask for the probe. See `_reachable`.
6. **Red at the assertion, not at collection**, and not from a run in which nothing executed. pytest
   exits non-zero for all three and only the first is evidence, which is why the summary line is read
   rather than just the exit code.
7. **The restore is verified, and the targets pass again.** A restore that writes the wrong bytes
   leaves a mutated tree looking clean.
8. **The count in the report excludes the refused cases**, since that number is the only thing anyone
   reads out of a six-minute run.

**Bytecode is invalidated on mtime AND size, so a same-length edit written and reverted inside one
second leaves a `.pyc` compiled from the perturbed source.** The restored tree then fails while `git
diff` shows nothing. Both halves are closed here: `PYTHONDONTWRITEBYTECODE` stops the perturbed
version from ever being cached, and the `__pycache__` beside a written file is removed so a cache
predating the edit cannot answer for it either.

Scripts run one at a time. They mutate shared source files in place, so two in parallel perturb each
other's baseline.
"""

import ast
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _write(path: pathlib.Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    shutil.rmtree(path.parent / "__pycache__", ignore_errors=True)


def _pytest(targets, root=ROOT):
    """Run pytest over `targets` and return `(returncode, last line of output)`.

    **`sys.executable`, not `uv run`.** A sweep starts one pytest per case plus a baseline and a
    restore per script, around 300 processes, so a fixed per-call cost is multiplied by 300. Measured
    on one target file: `uv run --extra dev python -m pytest` takes 0.61s and the same run under the
    venv interpreter takes 0.39s, because `uv run` re-checks the environment every time. That is a
    minute of the sweep spent proving the lockfile has not changed since a second ago.

    `sys.executable` is whatever interpreter is running this script, which is the venv's python
    whether the script was started by `run-all.py`, by `uv run`, or directly. `-p no:cacheprovider`
    stops 300 rewrites of `.pytest_cache` for runs whose results are never reused.
    """
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *targets],
                          cwd=root, capture_output=True, text=True, env=env)
    lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    return proc.returncode, (lines[-1] if lines else "<no output>")


def _reachable(path, text, old, case_targets, root, run):
    """Does the line about to be perturbed actually execute under these targets?

    Replaces the anchor with a bare `raise` and requires the targets to go red. If they stay green
    the line never runs, so the real perturbation leaving them green would say nothing about the
    assertion. Returns `(problem, note)`, at most one of them set.

    Only meaningful when the target executes the code. A structural sweep reads the file and notices
    the edit textually, so it never runs the line and the probe would call a good perturbation
    unreachable. Those cases pass `probe=False` and say why in the script.

    **Which scripts probed before they moved here, and how to check that without the old copies.**
    Six of the nineteen implemented this, found by grepping the pre-move copies for the string
    `perturbation probe: line reached`: `aggregate-logs`, `concurrent-queries`, `hit-rate`,
    `injection`, `query-failure`, `static-assets`. Those six pass `len(c) == 5`, which is exactly
    their old condition, since every sixth tuple element across them was `TEXTUAL` or `PROBE_BLIND`
    and both meant skip. The other fourteen never had a probe and say so where they call `sweep`.

    The pre-move copies were deleted on 2026-09-13 from a gitignored directory, so that grep cannot be
    repeated. **The set can still be re-derived from this repository**, which is better than taking
    this paragraph's word for it: collect the cases each script passes to `sweep`, count those whose
    fourth element is true, and exactly those six scripts appear, at 21/31, 13/15, 6/13, 12/18, 12/13
    and 10/11. The maintainer's reviewer did that independently and got the same six, which is why the
    claim that the migration preserved behaviour rests on something other than a note.
    """
    indent = " " * (len(old) - len(old.lstrip()))
    _write(path, text.replace(old, f'{indent}raise AssertionError("perturbation probe: line reached")'))
    try:
        try:
            ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            return None, "the probe edit does not parse, so reachability is unestablished"
        rc, _ = run(case_targets, root)
        if rc == 0:
            return ("the perturbed line never executes under these targets, so a green result "
                    "would prove nothing"), None
        return None, None
    finally:
        _write(path, text)


def sweep(cases, root=ROOT, run=_pytest):
    """Apply each case, require its targets to notice, restore, and report.

    A case is `(label, edits, targets)`, or `(label, edits, targets, probe)` to ask for the
    reachability probe above. An edit is `(path, old, new)`, `(path, old, new, count)` when the
    anchor legitimately appears more than once, or `(path, transform)` for a property whose anchor
    is a node rather than a string. `targets` are pytest node ids.

    `run` is injectable so `tests/test_perturbation_harness.py` can prove each guard fires without
    starting a pytest inside a pytest.
    """
    targets = sorted({t for case in cases for t in case[2]})
    rc, tail = run(targets, root)
    print(f"baseline ({len(targets)} targets): {tail}")
    if rc != 0:
        print("\n---RESULT---")
        print("STATUS: ERROR")
        print("DETAIL: the targets do not pass before any perturbation, so nothing below could have "
              "meant anything. A target id that does not exist arrives here as an error too.")
        return 1

    bad, notes = [], []
    for case in cases:
        label, edits, case_targets = case[:3]
        probe = case[3] if len(case) > 3 else False
        originals: dict[pathlib.Path, str] = {}
        problem = None
        try:
            if probe:
                if len(edits) != 1 or callable(edits[0][1]):
                    problem = "the reachability probe needs exactly one literal edit"
                else:
                    path = root / edits[0][0]
                    text = path.read_text(encoding="utf-8")
                    problem, note = _reachable(path, text, edits[0][1], case_targets, root, run)
                    if note:
                        print(f"note     {label}: {note}")
            if problem:
                print(f"INVALID  {label}: {problem}")
                bad.append(label)
                continue
            for edit in edits:
                rel = edit[0]
                path = root / rel
                text = path.read_text(encoding="utf-8")
                originals.setdefault(path, text)
                if callable(edit[1]):
                    # A transform instead of a literal, for a property whose anchor is a node
                    # rather than a string. Quoting prose in order to perturb prose makes the
                    # script a second copy of the thing under guard, and editing the prose is
                    # exactly the event that disarms the anchor. The count guard cannot apply, so
                    # "it changed something" is the substitute.
                    edited = edit[1](text)
                    if edited == text:
                        problem = f"the transform for {rel} changed nothing"
                        break
                    _write(path, edited)
                else:
                    old, new = edit[1], edit[2]
                    want = edit[3] if len(edit) > 3 else 1
                    found = text.count(old)
                    if found != want:
                        problem = f"anchor matched {found}x in {rel}, expected {want}x"
                        break
                    if old == new:
                        problem = f"the edit to {rel} replaces the anchor with itself"
                        break
                    _write(path, text.replace(old, new))
                if path.suffix == ".py":
                    try:
                        ast.parse(path.read_text(encoding="utf-8"))
                    except SyntaxError as exc:
                        problem = f"{rel} no longer parses, so red would mean nothing: {exc}"
                        break
            if problem:
                print(f"INVALID  {label}: {problem}")
                bad.append(label)
                continue
            rc, tail = run(case_targets, root)
            if "no tests ran" in tail:
                # pytest exits non-zero for a target it cannot find, so without this a deleted or
                # renamed test file makes every remaining case report as caught. That happened:
                # `perturb-redactable.py` printed `ok ... no tests ran in 0.00s` for a file that
                # had been replaced months earlier.
                print(f"INVALID  {label}: no test ran, so nothing observed the change, {tail}")
                bad.append(label)
            elif " error" in tail and " failed" not in tail:
                print(f"INVALID  {label}: red at collection rather than at the assertion, {tail}")
                bad.append(label)
            elif rc == 0:
                print(f"HOLLOW   {label}: {tail}")
                bad.append(label)
            else:
                print(f"ok       {label}: {tail}")
        finally:
            for path, text in originals.items():
                _write(path, text)
                if path.read_text(encoding="utf-8") != text:
                    notes.append(f"restoring {path} after {label!r} wrote different bytes")

    rc, tail = run(targets, root)
    print(f"restored ({len(targets)} targets): {tail}")
    if rc != 0:
        notes.append("the targets do not pass after the restore; read `git diff` next")

    print("\n---RESULT---")
    print(f"STATUS: {'PASS' if not bad and not notes else 'FAIL'}")
    print(f"DETAIL: {len(cases) - len(bad)}/{len(cases)} perturbations caught")
    for line in bad + notes:
        print(f"DETAIL: {line}")
    return 0 if not bad and not notes else 1
