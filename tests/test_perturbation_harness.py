# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The perturbation scripts are what shows the rest of this suite can fail, so their guards are held here.

The full sweep takes minutes: every script runs its engine once per case plus a baseline and a
restore, and the scripts mutate shared source files so they cannot run in parallel. CI therefore does
not run it, which leaves a gap with a specific shape. `tests/perturbations/_harness.py` decides, for
every case in every script, whether a red run counts as the assertion noticing or as an accident. If
that decision is wrong the whole sweep reports PASS and means nothing.

So the slow sweep stays a command someone runs, and the judgement it depends on is held here, in
milliseconds, on every push. Each test below feeds the harness a case that must be refused and
requires the refusal, using an injected runner rather than starting a pytest inside a pytest.

**Four of the nineteen scripts had drifted when they were first run against current code.** One
anchor had matched nothing since a tool joined a registration line. One dedented a line whose
successor was still inside a `with`, so the file stopped parsing and red said nothing about the lock
it was aimed at. One named a release tag, which the next cut falsified, taking all three of its cases
with it. And one perturbed a test file that had been replaced: with its anchors dead it reported `ok
... no tests ran in 0.00s`, a green-looking verdict from a run in which nothing was observed. That
script is gone rather than repaired, and that last case is why the harness reads the summary line
instead of trusting the exit code.

The static checks at the bottom are aimed at the same rot from the other side: a script naming a test
file that no longer exists, or hand-rolling the loop and skipping the guards.
"""

import ast
import importlib.util
import json
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "tests/perturbations"

_spec = importlib.util.spec_from_file_location("_perturbation_harness", SCRIPTS / "_harness.py")
harness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(harness)

GREEN = (0, "3 passed in 0.10s")
RED = (1, "1 failed, 2 passed in 0.10s")
COLLECTION_ERROR = (2, "1 error in 0.10s")


def _runner(*results):
    """A fake pytest. Returns the given results in order, then repeats the last one."""
    calls = []

    def run(targets, root):
        calls.append(list(targets))
        return results[min(len(calls) - 1, len(results) - 1)]

    run.calls = calls
    return run


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "mod.py").write_text("VALUE = 1\nOTHER = 1\n")
    return tmp_path


def test_a_case_whose_target_stays_green_is_reported_hollow(tree, capsys):
    """The one the whole file exists for. A perturbation that breaks a property and leaves the test
    green is the only outcome that means the assertion is not doing its job, and it has to be told
    apart from every other way a run can end."""
    rc = harness.sweep([("value changed", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"])],
                       root=tree, run=_runner(GREEN, GREEN, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "HOLLOW   value changed" in out
    assert "STATUS: FAIL" in out
    assert "0/1 perturbations caught" in out


def test_a_case_whose_target_goes_red_is_the_only_one_counted_as_caught(tree, capsys):
    """The positive control. Without it every assertion above passes for a harness that refuses
    everything, which would report the whole sweep as broken and be equally useless."""
    rc = harness.sweep([("value changed", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"])],
                       root=tree, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ok       value changed" in out
    assert "1/1 perturbations caught" in out
    assert (tree / "mod.py").read_text() == "VALUE = 1\nOTHER = 1\n", "the restore did not happen"


def test_an_anchor_that_matches_nothing_is_refused_rather_than_silently_skipped(tree, capsys):
    """The guard that caught the real drift. `perturb-aggregate-logs.py` had a case anchored on a
    registration line that gained a second tool name, so the edit had applied to nothing since. A
    script without this guard reports the case as caught if any other case's failure happens to be
    in the same pytest run."""
    rc = harness.sweep([("gone", [("mod.py", "VALUE = 99", "VALUE = 2")], ["t"])],
                       root=tree, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "anchor matched 0x in mod.py, expected 1x" in out


def test_an_anchor_matching_more_than_once_is_refused(tree, capsys):
    """Six times in one day an assertion was computed against a narrow subject and then run against
    a wide one, and a `replace` with no count is the same mistake: two properties break and only one
    was being measured."""
    rc = harness.sweep([("both", [("mod.py", " = 1", " = 2")], ["t"])],
                       root=tree, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "anchor matched 2x in mod.py, expected 1x" in out


def test_a_declared_count_lets_a_legitimately_repeated_anchor_through(tree, capsys):
    """The escape hatch, because sometimes breaking a property genuinely means editing every
    occurrence. Declaring the number is the point: it fails if the number changes."""
    rc = harness.sweep([("both", [("mod.py", " = 1", " = 2", 2)], ["t"])],
                       root=tree, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ok       both" in out
    assert (tree / "mod.py").read_text() == "VALUE = 1\nOTHER = 1\n"


def test_an_edit_that_replaces_the_anchor_with_itself_is_refused(tree, capsys):
    """Writes the file, changes nothing, and the target stays green, so without this guard it reads
    as a hollow assertion and sends the reader to the wrong file."""
    rc = harness.sweep([("noop", [("mod.py", "VALUE = 1", "VALUE = 1")], ["t"])],
                       root=tree, run=_runner(GREEN, GREEN, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "replaces the anchor with itself" in out


def test_a_perturbation_that_breaks_the_syntax_is_not_counted_as_caught(tree, capsys):
    """A file that no longer parses makes its target red no matter what the assertion says, so red
    here is evidence about Python, not about the test."""
    rc = harness.sweep([("broken", [("mod.py", "VALUE = 1", "VALUE = = 1")], ["t"])],
                       root=tree, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "no longer parses" in out


def test_red_at_collection_is_not_red_at_the_assertion(tree, capsys):
    """pytest exits non-zero for a broken import and for a failed assertion alike. Only the second
    says the property is guarded, and telling them apart is why the harness reads the summary line
    rather than just the exit code."""
    rc = harness.sweep([("import broken", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"])],
                       root=tree, run=_runner(GREEN, COLLECTION_ERROR, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "red at collection rather than at the assertion" in out


def test_a_red_baseline_stops_the_sweep_before_it_writes_anything(tree, capsys):
    """Red after a perturbation only means something if green came first, and a target id with a
    typo arrives here as an error rather than as zero tests run."""
    rc = harness.sweep([("value changed", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"])],
                       root=tree, run=_runner(RED))
    out = capsys.readouterr().out
    assert rc == 1
    assert "STATUS: ERROR" in out
    assert "do not pass before any perturbation" in out
    assert (tree / "mod.py").read_text() == "VALUE = 1\nOTHER = 1\n", "the sweep wrote despite a red baseline"


def test_a_tree_still_broken_after_the_restore_is_reported(tree, capsys):
    """The failure that hides itself: the sweep reports every case caught, and the next test run in
    that working copy fails for reasons the reader cannot see in `git diff` if the bytes happen to
    match a cached compile."""
    rc = harness.sweep([("value changed", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"])],
                       root=tree, run=_runner(GREEN, RED, RED))
    out = capsys.readouterr().out
    assert rc == 1
    assert "1/1 perturbations caught" in out, "the case itself was fine; the restore was not"
    assert "do not pass after the restore" in out


def test_a_target_that_ran_no_tests_is_not_counted_as_caught(tree, capsys):
    """The one that actually happened, and the reason the exit code alone is not enough. pytest exits
    non-zero for a node id it cannot find, so a deleted or renamed test file turns every remaining
    case into a green-looking `ok` from a run where nothing observed the change."""
    rc = harness.sweep([("value changed", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"])],
                       root=tree, run=_runner(GREEN, (4, "no tests ran in 0.00s"), GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "no test ran, so nothing observed the change" in out


def test_a_line_that_never_executes_is_refused_before_the_real_edit(tree, capsys):
    """The reachability probe. Replacing the anchor with a bare `raise` and getting a green run means
    the target never reaches that line, so the real perturbation leaving it green would be evidence
    about coverage rather than about the assertion."""
    rc = harness.sweep([("unreached", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"], True)],
                       root=tree, run=_runner(GREEN, GREEN, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "never executes under these targets" in out
    assert (tree / "mod.py").read_text() == "VALUE = 1\nOTHER = 1\n", "the probe left its raise behind"


def test_a_probe_that_goes_red_lets_the_real_perturbation_be_judged(tree, capsys):
    """The positive control for the probe: baseline green, probe red, real edit red. Without this the
    two tests above pass for a probe that refuses everything."""
    rc = harness.sweep([("reached", [("mod.py", "VALUE = 1", "VALUE = 2")], ["t"], True)],
                       root=tree, run=_runner(GREEN, RED, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ok       reached" in out


def test_a_transform_edit_is_applied_and_restored(tree, capsys):
    """The callable form, for a property whose anchor is a node rather than a string. Quoting prose
    in order to perturb prose makes the script a second copy of the thing under guard."""
    rc = harness.sweep([("structural", [("mod.py", lambda t: t.replace("1", "3"))], ["t"])],
                       root=tree, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 0
    assert "ok       structural" in out
    assert (tree / "mod.py").read_text() == "VALUE = 1\nOTHER = 1\n"


def test_a_transform_that_changes_nothing_is_refused(tree, capsys):
    """The count guard cannot apply to a transform, so "it changed something" is the substitute. An
    AST-located edit that silently matches nothing is the failure this replaces."""
    rc = harness.sweep([("inert", [("mod.py", lambda t: t)], ["t"])],
                       root=tree, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "changed nothing" in out


def test_the_bytecode_cache_beside_a_written_file_is_dropped(tree):
    """CPython invalidates a `.pyc` on mtime and size together, so an edit of the same length
    written and reverted inside one second leaves bytecode compiled from the perturbed source. The
    restored tree then fails while `git diff` is empty, which cost an afternoon once."""
    cache = tree / "__pycache__"
    cache.mkdir()
    (cache / "mod.cpython-313.pyc").write_bytes(b"stale")
    harness.sweep([("same length", [("mod.py", "VALUE = 1", "VALUE = 7")], ["t"])],
                  root=tree, run=_runner(GREEN, RED, GREEN))
    assert not cache.exists(), "a cache predating the edit can still answer for the restored file"


def test_the_real_runner_disables_bytecode_writing(monkeypatch):
    """The other half of the same guard, and it is one env var away from being silently absent.

    **The `delenv` is the whole test.** Without it this passed while `_pytest` did nothing but copy
    the environment, because the harness runs its own pytest with `PYTHONDONTWRITEBYTECODE=1` set, so
    a subprocess inherits it and `dict(os.environ)` already contains it. The perturbation that removes
    the assignment reported HOLLOW, which is what a value supplied by the runner rather than by the
    code under test always looks like. Clearing it first makes the source the only possible provider.
    """
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    captured = {}

    class Proc:
        returncode = 0
        stdout = "1 passed in 0.01s"

    def fake_run(argv, **kwargs):
        captured.update(argv=argv, env=kwargs.get("env"), cwd=kwargs.get("cwd"))
        return Proc()

    monkeypatch.setattr(harness.subprocess, "run", fake_run)
    rc, tail = harness._pytest(["tests/some_test.py::test_x"], root=ROOT)
    assert rc == 0 and tail == "1 passed in 0.01s"
    assert captured["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    # `sys.executable`, not `uv run`: a sweep starts about 300 pytest processes, and `uv run` spends
    # 0.22s per call re-checking the environment, which is a minute of the run. Asserted as the
    # running interpreter rather than as a literal path, so it holds under uv, under the venv python
    # and in CI alike.
    assert captured["argv"][:3] == [sys.executable, "-m", "pytest"], captured["argv"][:3]
    assert captured["cwd"] == ROOT, "running outside the repo root would resolve every path wrongly"


# --- the second engine, whose only job is to speak the classifier's vocabulary ----


def _fake_vitest(monkeypatch, report, returncode=1):
    """Stand in for the vitest process, writing `report` as its JSON output. `None` writes nothing."""
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(argv=argv, cwd=kwargs.get("cwd"))
        out = next(a.split("=", 1)[1] for a in argv if a.startswith("--outputFile="))
        if report is not None:
            pathlib.Path(out).write_text(json.dumps(report))

        class Proc:
            pass

        Proc.returncode = returncode
        Proc.stdout = Proc.stderr = ""
        return Proc()

    monkeypatch.setattr(harness.subprocess, "run", fake_run)
    return captured


def _report(*statuses):
    return {"testResults": [{"assertionResults": [
        {"title": title, "fullName": title, "status": status} for title, status in statuses]}]}


def test_the_vitest_runner_reports_a_pass_the_way_the_classifier_reads_one(monkeypatch):
    """`sweep` decides ok / HOLLOW / INVALID by reading a pytest-shaped summary line, and it is the
    only classifier. So the whole risk of a second engine sits in this translation: a green run that
    came back saying something the classifier does not recognise lands on `rc != 0` and reports as
    caught. Four outcomes, four tests, because that is where a false state would emit the true
    output."""
    captured = _fake_vitest(monkeypatch, _report(("a", "passed"), ("b", "passed")), returncode=0)
    rc, tail = harness.vitest(["frontend/src/render.test.js"], root=ROOT)
    assert (rc, tail) == (0, "2 passed in 0.00s"), "a green run must classify as HOLLOW, not as caught"
    assert captured["cwd"] == ROOT / "frontend", "vitest resolves its config from the frontend root"
    assert "src/render.test.js" in captured["argv"], captured["argv"]
    assert "--no-install" in captured["argv"], (
        "without --no-install a missing vitest is fetched from the network mid-sweep instead of "
        "failing, which turns an offline run into a silent download")


def test_the_vitest_runner_reports_a_failure_as_a_failure(monkeypatch):
    _fake_vitest(monkeypatch, _report(("a", "failed"), ("b", "passed")))
    assert harness.vitest(["frontend/src/render.test.js"], root=ROOT) == (1, "1 failed, 1 passed in 0.00s")


def test_a_vitest_run_that_produced_no_report_is_an_error_not_a_failure(monkeypatch):
    """A transform error, a config that no longer loads, a missing binary. The process exits non-zero
    and no test ever ran, which is the pytest collection error by another name."""
    _fake_vitest(monkeypatch, None)
    assert harness.vitest(["frontend/src/render.test.js"], root=ROOT) == (1, "1 error in 0.00s")


def test_a_vitest_target_whose_name_is_gone_runs_no_tests(monkeypatch):
    """The `no tests ran` protection, carried over to the other engine. Selection happens by filtering
    the report rather than on the command line, so a renamed test selects nothing and must not inherit
    an unrelated failure from the same file."""
    _fake_vitest(monkeypatch, _report(("still here", "failed")))
    rc, tail = harness.vitest(["frontend/src/render.test.js::renamed away"], root=ROOT)
    assert (rc, tail) == (1, "no tests ran in 0.00s")


def test_a_vitest_failure_outside_the_requested_test_is_not_credited(monkeypatch):
    """The other half of selection. The requested test passed, so this case is HOLLOW, even though the
    process exited non-zero because of a different test in the same file."""
    _fake_vitest(monkeypatch, _report(("wanted", "passed"), ("other", "failed")))
    rc, tail = harness.vitest(["frontend/src/render.test.js::wanted"], root=ROOT)
    assert (rc, tail) == (0, "1 passed in 0.00s")


def test_a_probe_on_a_file_type_with_no_probe_form_is_refused(tmp_path, capsys):
    """The reachability probe writes a statement in the language of the file it edits. A file type
    with no form for that cannot be probed, and skipping the probe silently is how the guard stops
    applying to exactly the cases that asked for it."""
    (tmp_path / "sheet.css").write_text("body { color: red }\n")
    rc = harness.sweep([("styled", [("sheet.css", "red", "blue")], ["t"], True)],
                       root=tmp_path, run=_runner(GREEN, RED, GREEN))
    out = capsys.readouterr().out
    assert rc == 1
    assert "no probe form for a .css file" in out


def test_a_probe_run_that_died_before_any_assertion_is_reported(tmp_path, capsys):
    """Red proves reachability only if a test actually ran. A probe spliced into the middle of an
    expression breaks the file, and for a `.js` file nothing parses it first, so the run dies at
    transform time and exits non-zero exactly like a real failure."""
    (tmp_path / "mod.js").write_text("export const V = 1;\n")
    rc = harness.sweep([("mid expression", [("mod.js", "1", "2")], ["t"], True)],
                       root=tmp_path,
                       run=_runner(GREEN, (1, "1 error in 0.00s"), RED, GREEN))
    out = capsys.readouterr().out
    assert "the probe run ended before any assertion" in out
    assert "ok       mid expression" in out, (
        "the note is a warning, not a refusal: the real perturbation is still judged")
    assert rc == 0


@pytest.mark.parametrize("suffix", sorted({".py", ".js", ".jsx"}))
def test_every_probe_form_is_a_statement_naming_the_probe(suffix):
    """The dispatch table, swept for what it can be asked for rather than spot-checked. Both halves
    of each entry matter: `_reachable` requires the run to go red, which only happens if the
    statement actually raises, and the marker string is what a reader greps for when a note appears."""
    form = harness.PROBE[suffix]
    assert "perturbation probe: line reached" in form
    assert form.startswith("raise ") or form.startswith("throw "), form


def test_every_case_that_asks_for_a_probe_edits_a_file_with_a_probe_form():
    """The pairing invariant, over what the scripts actually ask for. A case whose file type has no
    entry above is refused rather than probed, so it would report INVALID for a reason that has
    nothing to do with the property it aims at."""
    unsupported = []
    for script in _scripts():
        for case in _cases(script) or ():
            if len(case) > 3 and case[3]:
                suffix = pathlib.PurePosixPath(case[1][0][0]).suffix
                if suffix not in harness.PROBE:
                    unsupported.append(f"{script.name}: {case[0]!r} probes a {suffix} file")
    assert not unsupported, "; ".join(unsupported)


def _scripts():
    return sorted(SCRIPTS.glob("perturb-*.py"))


def test_the_readme_states_the_real_number_of_scripts_and_cases():
    """Prose the code contradicts is this project's largest defect class, and `README.md` puts two
    counts in front of the reader. Both were wrong the first time: it said 235 cases, computed before
    the nineteenth script existed, and 235 then reached three other files by copying.

    A number in prose can be checked. A behavioural claim next to it cannot, which is why these two
    are the ones stated numerically."""
    readme = (SCRIPTS / "README.md").read_text()
    scripts = _scripts()
    cases = sum(len(_cases(s) or ()) for s in scripts)
    assert f"The {len(scripts)} scripts here" in readme, (
        f"README.md does not say there are {len(scripts)} scripts; that is the number on disk")
    assert f"all {cases} cases" in readme, (
        f"README.md does not say {cases} cases; that is what the scripts declare today")


def test_the_directory_holds_the_scripts_this_file_claims_to_cover():
    """The precondition. Every static check below sweeps a glob, and a glob that matches nothing
    satisfies all of them. Eighteen is what moved in: nineteen existed, and `perturb-redactable.py`
    was dropped rather than repaired because the test file it names was replaced by
    `test_redacted_filter.py` and none of its seven test names survives anywhere."""
    found = _scripts()
    assert len(found) >= 18, f"only {len(found)} perturbation scripts found in {SCRIPTS}"


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.name)
def test_every_perturbation_script_runs_on_the_shared_harness(script):
    """Four of the nineteen originally had no anchor-count check, which is how a stale case survived.
    A script that re-rolls the loop can lose any guard again, so the import is required and a loop
    over the cases is refused.

    **The structural half is not decoration.** The first version of this test asked only whether
    `subprocess.run` was absent, and one script kept its entire original loop through the move: it
    called a local `run()` helper, so the token was gone and the assertion passed on a file that
    would have raised `NameError` on its first line.

    **The subprocess check reads the AST rather than the text, for the same reason.** As a substring
    it fails on `perturb-harness-guards.py`, which has to quote the harness's own `subprocess.run`
    line in order to perturb it. A check that goes red on a script quoting the thing it guards is a
    false-positive generator, and the property wanted here is a *call*, not a mention."""
    text = script.read_text()
    tree = ast.parse(text)
    assert "from _harness import" in text, (
        f"{script.name} does not use the shared harness, so its guards are whatever it happens to "
        f"implement. Import `sweep` instead of writing the loop.")
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
             and node.func.attr == "run" and isinstance(node.func.value, ast.Name)
             and node.func.value.id == "subprocess"]
    assert not calls, (
        f"{script.name} calls subprocess.run on line {calls[0].lineno if calls else 0}, which "
        f"bypasses the baseline, anchor, probe, parse and restore guards in _harness.sweep.")
    loops = [node for node in tree.body if isinstance(node, (ast.For, ast.While))]
    assert not loops, (
        f"{script.name} loops at module level on line {loops[0].lineno if loops else 0}. Iterating "
        f"the cases is the harness's job; a script that does its own has its own guards too.")


def _cases(script):
    """The cases a script would run, with every f-string target and constant already resolved.

    **A regex over the source cannot do this, and reported clean while proving nothing.** Almost
    every target is written `f"{T}::test_x"` against a module-level constant, so a pattern looking
    for `tests/...::test_...` matched two scripts out of nineteen and found no problem in either,
    at the same moment a real sweep was reporting that two scripts named tests that do not exist.

    So the script is executed with `sweep` replaced by a collector. It ends in `sys.exit(sweep(...))`,
    which is where the cases arrive, fully evaluated.
    """
    recorded = {}
    stub = types.ModuleType("_harness")
    stub.ROOT = ROOT
    # `vitest` is here because a script naming the second engine imports it, and an ImportError on
    # this stub would empty every static check below for that script alone.
    stub.vitest = harness.vitest
    stub.sweep = lambda cases, root=None, run=None: recorded.setdefault("cases", cases) and 0
    saved = sys.modules.get("_harness")
    sys.modules["_harness"] = stub
    try:
        try:
            exec(compile(script.read_text(), str(script), "exec"),
                 {"__name__": "__main__", "__file__": str(script)})
        except SystemExit:
            pass
    finally:
        sys.modules.pop("_harness", None)
        if saved is not None:
            sys.modules["_harness"] = saved
    return recorded.get("cases")


def _defines(path: pathlib.Path, name: str) -> bool:
    """Whether `path` declares a test called `name`, in either engine's spelling.

    A pytest node id names a function, so the AST answers it. A vitest title is a string argument to
    `it`, and there is no JS parser here, so the call form is required rather than a bare mention: a
    title appearing only in a comment does not count. The narrower thing a substring check cannot see
    is a title assembled at runtime, and none is, which is worth knowing rather than implying."""
    if path.suffix == ".py":
        return name in {node.name for node in ast.walk(ast.parse(path.read_text()))
                        if isinstance(node, ast.FunctionDef)}
    text = path.read_text()
    return any(f"it({quote}{name}{quote}" in text for quote in ("'", '"'))


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.name)
def test_every_case_names_a_test_that_still_exists(script):
    """A renamed test turns every case in a script into a red baseline, and the script then reports
    ERROR for a reason that has nothing to do with what it guards. Two scripts were in that state:
    `test_the_four_version_strings_agree` had become `test_every_hand_written_version_string_agrees`
    when a fifth and sixth version string were added.

    Cheap enough to run on every push, which is the point. Finding it here costs milliseconds; finding
    it in the sweep costs the whole run and only says the baseline was red."""
    cases = _cases(script)
    assert cases, f"{script.name} produced no cases, so nothing below is checked"
    missing = []
    for case in cases:
        for target in case[2]:
            rel, _, name = target.partition("::")
            path = ROOT / rel
            if not path.exists():
                missing.append(f"{case[0]!r}: {rel} does not exist")
            elif name and not _defines(path, name):
                missing.append(f"{case[0]!r}: {rel} has no {name}")
    assert not missing, f"{script.name} names tests that are gone: " + "; ".join(missing)


@pytest.mark.parametrize("script", _scripts(), ids=lambda p: p.name)
def test_every_case_still_applies_to_the_code_it_perturbs(script):
    """Anchor drift is the failure that actually happens, and it is silent. Four of the nineteen
    scripts had drifted, one of them fatally, and nothing said so until somebody ran the full
    sweep. The harness refuses a drifted case, but only while the sweep is running.

    This is the same check on every push. If it goes red on a change of yours, the perturbation
    script names a line you edited: update the anchor so it still breaks the property, or delete the
    case if the property is gone. Leaving it is the one option that isn't available, because a case
    whose anchor matches nothing reports nothing."""
    cases = _cases(script)
    assert cases, f"{script.name} produced no cases, so nothing below is checked"
    problems = []
    for case in cases:
        for edit in case[1]:
            path = ROOT / edit[0]
            if not path.exists():
                problems.append(f"{case[0]!r}: {edit[0]} does not exist")
            elif not callable(edit[1]):
                want = edit[3] if len(edit) > 3 else 1
                found = path.read_text().count(edit[1])
                # A multi-edit case applies its edits in sequence, so only the first is checked
                # against the untouched file. Checking the rest would need the edits replayed.
                if found != want and edit is case[1][0]:
                    problems.append(f"{case[0]!r}: anchor matched {found}x in {edit[0]}, "
                                    f"expected {want}x")
    assert not problems, f"{script.name} has drifted: " + "; ".join(problems)
