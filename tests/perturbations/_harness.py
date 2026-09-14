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
   for any edit at all, including one that leaves the property intact. There is no parse check for a
   `.js` file and none is needed: one that no longer transforms runs zero tests, which guard 6
   already refuses, and adding a JS parser here would be a second thing to keep correct.
5. **The perturbed line executes**, for the cases that ask for the probe. See `_reachable`.
6. **Red at the assertion, not at collection**, and not from a run in which nothing executed. pytest
   exits non-zero for all three and only the first is evidence, which is why the summary line is read
   rather than just the exit code.
7. **The restore is verified, and the targets pass again.** A restore that writes the wrong bytes
   leaves a mutated tree looking clean.
8. **The count in the report excludes the refused cases**, since that number is the only thing anyone
   reads out of a full run.

**Bytecode is invalidated on mtime AND size, so a same-length edit written and reverted inside one
second leaves a `.pyc` compiled from the perturbed source.** The restored tree then fails while `git
diff` shows nothing. Both halves are closed here: `PYTHONDONTWRITEBYTECODE` stops the perturbed
version from ever being cached, and the `__pycache__` beside a written file is removed so a cache
predating the edit cannot answer for it either.

**Two engines, one classifier.** Most scripts run pytest; the one covering `frontend/src/render.test.js`
runs vitest. The eight guards above are the same either way, and the verdict is decided in one place by
reading a pytest-shaped summary line, so `vitest` translates its counts into those words rather than
handing over its own. That translation is the new place a false state could emit the true output, which
is why `tests/test_perturbation_harness.py` pins all four of its outcomes.

Scripts run one at a time. They mutate shared source files in place, so two in parallel perturb each
other's baseline.
"""

import ast
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The statement that stands in for the anchor during the reachability probe, per file type. A file
# type with no entry is refused rather than probed, because a probe that cannot be written cannot
# establish anything and skipping it silently is how the guard stops applying.
PROBE = {
    ".py": 'raise AssertionError("perturbation probe: line reached")',
    ".js": 'throw new Error("perturbation probe: line reached");',
    ".jsx": 'throw new Error("perturbation probe: line reached");',
}


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


# Where the JS suite lives, relative to the repository root. vitest resolves its config and its
# `include` patterns from that directory, so targets are written repo-relative and reduced here.
FRONTEND = "frontend"


def vitest(targets, root=ROOT):
    """Run the frontend suite over `targets` and return `(returncode, tail)` in pytest's vocabulary.

    **Public where `_pytest` is private, because a script has to name it.** `_pytest` is the default
    and nothing imports it; a script covering `render.test.js` passes `run=vitest` to `sweep`.

    **The tail is translated rather than quoted, and that is the load-bearing part.** `sweep` decides
    ok / HOLLOW / INVALID by reading the summary line, and it reads pytest's words: `no tests ran`,
    `N failed`, `N error`. Handing it vitest's own summary would leave every case classified by
    accident, which is the exact shape this whole directory exists to catch. So the JSON reporter is
    read and the counts are re-rendered. `tests/test_perturbation_harness.py` holds the mapping for
    all four outcomes, since a shared classifier needs its own evidence per engine.

    **Selection happens here, not on the command line.** `vitest -t` takes one pattern, so a call
    holding several test names could not be expressed. The whole file runs and the JSON is filtered
    to the requested titles, which also means a renamed test yields zero selected results and lands
    on `no tests ran` rather than being scored as caught.
    """
    files, wanted = set(), set()
    for target in targets:
        rel, _, name = target.partition("::")
        files.add(str(pathlib.PurePosixPath(rel).relative_to(FRONTEND)))
        if name:
            wanted.add(name)
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "vitest.json"
        proc = subprocess.run(
            ["npx", "--no-install", "vitest", "run", "--reporter=json",
             f"--outputFile={report}", *sorted(files)],
            cwd=root / FRONTEND, capture_output=True, text=True)
        try:
            data = json.loads(report.read_text())
        except (OSError, ValueError):
            # No report at all means the run died before any test: a transform error, a missing
            # binary, a config that no longer loads. Red for a reason unrelated to any assertion.
            return (proc.returncode or 1), "1 error in 0.00s"
    results = [r for suite in data.get("testResults", ())
               for r in suite.get("assertionResults", ())
               if not wanted or r.get("title") in wanted or r.get("fullName") in wanted]
    if not results:
        return (proc.returncode or 1), "no tests ran in 0.00s"
    failed = sum(1 for r in results if r.get("status") == "failed")
    passed = len(results) - failed
    if failed:
        return 1, f"{failed} failed, {passed} passed in 0.00s"
    return 0, f"{passed} passed in 0.00s"


def _anchor_lines(text: str, old: str) -> list[tuple[int, int]]:
    """`(line start, anchor start)` for every line the anchor begins on, one entry per line.

    The anchor start is its first non-blank character, so an anchor written with a leading newline
    names the line it quotes rather than the one above it. Shared with the inventory test in
    `tests/test_perturbation_harness.py`, which needs the text between the two offsets: a second copy
    of this walk over there would be a check on the copy.
    """
    seen, at, step = {}, text.find(old), max(len(old), 1)
    while at >= 0:
        first = at + len(old) - len(old.lstrip())
        seen.setdefault(text.rfind("\n", 0, first) + 1, first)
        at = text.find(old, at + step)
    return sorted(seen.items())


def _anchor_shares_its_line(text: str, old: str) -> bool:
    """Is there code before the anchor on its own line, `if c: stmt` or anything after a semicolon?

    **The one shape where inserting the probe above the line proves less than substituting for the
    anchor.** The line is reached whenever the compound header is, while the anchor itself may not run.
    Substitution deleted the anchor and had no such gap. True for 0 of the 109 probeable Python cases on
    2026-09-14, because nothing in this repository writes a single-line compound statement, which is a
    habit rather than a guarantee, so `tests/test_perturbation_harness.py` asserts it.

    Textual, so an anchor that follows a dict key or a colon inside a string reads as sharing its line
    too. None does today, and the answer to a red here is the same either way: re-anchor the case on the
    whole statement.
    """
    for bol, first in _anchor_lines(text, old):
        prefix = text[bol:first].rstrip()
        if ";" in prefix or prefix.endswith(":"):
            return True
    return False


def _probe_edit(text: str, old: str, probe: str) -> str:
    """`text` with `probe` inserted as its own statement ahead of every line the anchor begins on.

    **Ahead of the anchor rather than in place of it, and indented from the line rather than from the
    anchor.** Substituting the probe for the anchor produced an edit that does not parse for 60 of the
    132 Python cases that ask for a probe, measured 2026-09-14 by writing both forms and parsing each:
    it orphans the body of a block opener, it glues the probe onto the following line when the anchor
    ends in a newline, and it dedents the anchor to column 0 whenever the anchor text begins mid-line,
    which is the shape a case gets by quoting a statement without its indentation. A probe edit that
    does not parse is skipped with a note, so those 60 got a verdict with nothing behind it.

    **Counted over `probe is True`**, which excludes the eight cases whose truthy marker asked for a
    probe by accident and includes the one re-enabled with this change. The harness was really probing
    139 then, 66 of which did not parse, and `perturb-harness-guards.py` states that pair beside the
    cases that break this.

    Inserting ahead parses for 37 of the 60, and for every case substitution already handled, which is
    the half worth checking before swapping one form for another. Taking the indentation from the line
    is what makes that true: two cases are anchored mid-line, and indenting from the anchor instead
    would have broken both. 23 remain, listed in `unprobeable.txt`.

    It proves the same property and promises slightly more. A statement that raises immediately before
    the anchor's line goes red exactly when control flow reaches that line, and when it does not the
    file behaves as it did, which substitution could not offer: deleting the anchor changes the program
    on paths that never reach it, so red could come from somewhere else entirely.

    **One shape where it proves less, and it holds for 0 of the 109 probeable Python cases rather than
    by construction.** An anchor with code before it on its own line, `if c: stmt` or anything after a
    semicolon, is reached whenever the line is reached while the anchor itself may not run. Substitution
    had no such gap, since it deleted the anchor. Nothing in this repository writes a single-line
    compound statement, and the inventory test asserts that rather than leaving it as a habit.

    **Every line the anchor matches, because the count guard lets a case declare an anchor that
    legitimately appears three or five times**, and the substituting form edited all of them. Red then
    means at least one of those lines runs, which is what it meant before.
    """
    out, pos = [], 0
    for bol, _ in _anchor_lines(text, old):
        rest = text[bol:]
        out.append(text[pos:bol] + " " * (len(rest) - len(rest.lstrip())) + probe + "\n")
        pos = bol
    return "".join(out) + text[pos:]


def _reachable(path, text, old, case_targets, root, run):
    """Does the line about to be perturbed actually execute under these targets?

    Inserts a bare `raise` ahead of the anchor's line and requires the targets to go red. If they stay
    green the line never runs, so the real perturbation leaving them green would say nothing about the
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
    repeated. **The re-derivation that stood behind this paragraph has since expired, and the recipe is
    recorded because a reader will otherwise try it.** Collecting each script's cases and counting the
    ones asking for a probe isolated exactly those six on 2026-09-13, at 21/31, 13/15, 6/13, 12/18,
    12/13 and 10/11; the maintainer's reviewer did it independently and got the same six. Fourteen
    scripts probe today, so that count no longer isolates anything, and one of the six has moved:
    `query-failure` is 17/19 after cases were added to it.
    """
    if path.suffix not in PROBE:
        return f"no probe form for a {path.suffix} file, so reachability cannot be established", None
    _write(path, _probe_edit(text, old, PROBE[path.suffix]))
    try:
        if path.suffix == ".py":
            try:
                ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                # What is left after the insertion form: an anchor whose line is a continuation of a
                # multi-line expression, and an `elif`/`except` clause header, which cannot have a
                # statement above it. 23 cases, listed in `unprobeable.txt` and pinned by a test, so a
                # new one cannot join them quietly.
                return None, ("no statement can be inserted ahead of this anchor's line, so "
                              "reachability is unestablished")
        rc, tail = run(case_targets, root)
        if rc == 0:
            return ("the perturbed line never executes under these targets, so a green result "
                    "would prove nothing"), None
        # **Red is not enough on its own, and this is the half the `ast.parse` above cannot cover for
        # a `.js` file.** An anchor that is a fragment rather than a whole line leaves the probe
        # statement spliced into the middle of an expression, and the run then dies before any
        # assertion. Red for that reason says nothing about whether the line executes, so the same
        # two tails `sweep` refuses below are refused here.
        if "no tests ran" in tail or (" error" in tail and " failed" not in tail):
            return None, f"the probe run ended before any assertion, so reachability is unestablished: {tail}"
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
            if not isinstance(probe, bool):
                # **A marker meaning "do not probe this" is truthy, so it asked for the probe it says
                # it is skipping.** Eight cases were in that state, all written with `"textual"` in
                # this position, and the substituting probe form hid every one: its edit did not
                # parse, so the probe was skipped with a note and the case reported `ok`. The scripts
                # that predate the shared harness convert their marker with `len(c) == 5` and are
                # unaffected, which is why this reads as an accident rather than a convention.
                problem = (f"probe is {probe!r}, not a bool. A truthy marker asks for the probe it "
                           f"means to skip, so write False and say why in a comment.")
            elif probe:
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
