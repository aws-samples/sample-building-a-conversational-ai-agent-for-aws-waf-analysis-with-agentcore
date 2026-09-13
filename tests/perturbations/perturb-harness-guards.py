#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Remove each guard from `_harness.py` and require `test_perturbation_harness.py` to notice.

Every other script here proves one test file can fail. This one is the floor under all of them: the
harness decides, for every case in every script, whether a red run counts as the assertion noticing or as an accident.
A harness whose guards have been quietly weakened reports every script PASS, and the whole sweep
becomes a green tick with nothing behind it.

**Editing the file this script imports is safe, and the mechanism is worth knowing.** `sweep` is
already in memory by the time the first case is written, and each case's verdict comes from a pytest
subprocess that reads the perturbed file fresh. So the judging code is the unperturbed version
throughout, which is the only arrangement in which the result means anything.

Every target reads behaviour rather than source, so the reachability probe does not apply: the guard
under examination has to run for its removal to show up.
"""

import re
import sys

from _harness import ROOT, sweep

H = "tests/perturbations/_harness.py"
T = "tests/test_perturbation_harness.py"
README = "tests/perturbations/README.md"

_readme = (ROOT / README).read_text()


def _documented(pattern: str) -> int:
    """A number `README.md` states, or a stop. Two cases below decrement it, and a case anchored on a
    number that has moved applies to nothing while still reporting `ok` for its neighbours."""
    match = re.search(pattern, _readme)
    if not match:
        raise SystemExit(f"{README} no longer states {pattern!r}; the test guarding it reads the "
                         f"same two numbers, so fix them together")
    return int(match.group(1))


SCRIPTS_DOCUMENTED = _documented(r"The (\d+) scripts here")
CASES_DOCUMENTED = _documented(r"all (\d+) cases")

CASES = [
    ("the anchor count guard dropped, so a case that applied to nothing scores as caught",
     [(H, "                    if found != want:", "                    if False:")],
     [f"{T}::test_an_anchor_that_matches_nothing_is_refused_rather_than_silently_skipped",
      f"{T}::test_an_anchor_matching_more_than_once_is_refused"]),

    ("the count taken as a floor rather than exactly, which is the plausible weakening",
     [(H, "                    if found != want:", "                    if found < want:")],
     [f"{T}::test_an_anchor_matching_more_than_once_is_refused"]),

    ("an edit replacing the anchor with itself allowed through",
     [(H, "                    if old == new:", "                    if False:")],
     [f"{T}::test_an_edit_that_replaces_the_anchor_with_itself_is_refused"]),

    ("the parse check dropped, so red at import counts as the assertion working",
     [(H, "                if path.suffix == \".py\":", "                if False:")],
     [f"{T}::test_a_perturbation_that_breaks_the_syntax_is_not_counted_as_caught"]),

    ("a run in which no test executed counted as caught",
     [(H, '            if "no tests ran" in tail:', "            if False:")],
     [f"{T}::test_a_target_that_ran_no_tests_is_not_counted_as_caught"]),

    ("collection errors no longer told apart from assertion failures",
     [(H, '            elif " error" in tail and " failed" not in tail:', "            elif False:")],
     [f"{T}::test_red_at_collection_is_not_red_at_the_assertion"]),

    ("the baseline check dropped, so red-on-red reads as every case caught",
     [(H, "    if rc != 0:\n        print(\"\\n---RESULT---\")", "    if False:\n        print(\"\\n---RESULT---\")")],
     [f"{T}::test_a_red_baseline_stops_the_sweep_before_it_writes_anything"]),

    ("the reachability probe passing an unreachable line",
     [(H, "        rc, tail = run(case_targets, root)\n        if rc == 0:",
       "        rc, tail = run(case_targets, root)\n        if False:")],
     [f"{T}::test_a_line_that_never_executes_is_refused_before_the_real_edit"]),

    ("a probe run that died before any assertion counted as proving reachability",
     [(H, '        if "no tests ran" in tail or (" error" in tail and " failed" not in tail):',
       "        if False:")],
     [f"{T}::test_a_probe_run_that_died_before_any_assertion_is_reported"]),

    ("a file type with no probe form probed anyway",
     [(H, "    if path.suffix not in PROBE:", "    if False:")],
     [f"{T}::test_a_probe_on_a_file_type_with_no_probe_form_is_refused"]),

    # The second engine's translation into the classifier's words. `sweep` reads one summary-line
    # vocabulary, so each of vitest's four outcomes has to arrive spelled the way pytest spells it,
    # and a mistranslation is silent: the wrong verdict, printed in the right format.
    ("a vitest run with no report translated as a failure rather than an error",
     [(H, '            return (proc.returncode or 1), "1 error in 0.00s"',
       '            return (proc.returncode or 1), "1 failed in 0.00s"')],
     [f"{T}::test_a_vitest_run_that_produced_no_report_is_an_error_not_a_failure"]),

    ("a vitest selection matching nothing translated as a failure",
     [(H, '        return (proc.returncode or 1), "no tests ran in 0.00s"',
       '        return (proc.returncode or 1), "1 failed in 0.00s"')],
     [f"{T}::test_a_vitest_target_whose_name_is_gone_runs_no_tests"]),

    ("vitest selection dropped, so an unrelated failure in the same file is credited",
     [(H, "               if not wanted or r.get(\"title\") in wanted or r.get(\"fullName\") in wanted]",
       "               if True]")],
     [f"{T}::test_a_vitest_failure_outside_the_requested_test_is_not_credited"]),

    ("vitest run from the repository root, where it finds neither its config nor jsdom",
     [(H, "            cwd=root / FRONTEND, capture_output=True, text=True)",
       "            cwd=root, capture_output=True, text=True)")],
     [f"{T}::test_the_vitest_runner_reports_a_pass_the_way_the_classifier_reads_one"]),

    ("--no-install dropped, so a missing vitest is fetched from the network mid-sweep",
     [(H, '            ["npx", "--no-install", "vitest", "run", "--reporter=json",',
       '            ["npx", "vitest", "run", "--reporter=json",')],
     [f"{T}::test_the_vitest_runner_reports_a_pass_the_way_the_classifier_reads_one"]),

    ("a transform that changed nothing allowed through",
     [(H, "                    if edited == text:", "                    if False:")],
     [f"{T}::test_a_transform_that_changes_nothing_is_refused"]),

    ("the restore dropped, so the sweep leaves the tree mutated",
     [(H, "            for path, text in originals.items():\n                _write(path, text)",
       "            for path, text in originals.items():\n                pass")],
     [f"{T}::test_a_case_whose_target_goes_red_is_the_only_one_counted_as_caught",
      f"{T}::test_a_declared_count_lets_a_legitimately_repeated_anchor_through"]),

    ("the red-after-restore check dropped",
     [(H, '        notes.append("the targets do not pass after the restore; read `git diff` next")',
       '        pass')],
     [f"{T}::test_a_tree_still_broken_after_the_restore_is_reported"]),

    # The two halves of the stale-bytecode guard. Neither shows up in a normal run, which is exactly
    # why they need a case: a same-length edit reverted inside one second leaves a `.pyc` compiled
    # from the perturbed source, and the restored tree then fails while `git diff` is empty.
    ("the bytecode cache left in place beside a rewritten file",
     [(H, '    shutil.rmtree(path.parent / "__pycache__", ignore_errors=True)', "    pass")],
     [f"{T}::test_the_bytecode_cache_beside_a_written_file_is_dropped"]),

    ("bytecode writing re-enabled for the pytest subprocess",
     [(H, '    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")', "    env = dict(os.environ)")],
     [f"{T}::test_the_real_runner_disables_bytecode_writing"]),

    ("uv run back in the inner loop, which costs 0.22s x 300 processes",
     [(H, '    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *targets],',
       '    proc = subprocess.run(["uv", "run", "python", "-m", "pytest", "-q", *targets],')],
     [f"{T}::test_the_real_runner_disables_bytecode_writing"]),

    ("pytest run from wherever the caller happened to be rather than the repo root",
     [(H, "                          cwd=root, capture_output=True, text=True, env=env)",
       "                          capture_output=True, text=True, env=env)")],
     [f"{T}::test_the_real_runner_disables_bytecode_writing"]),

    # Not a guard, a report. A sweep that miscounts its own catches is how "17/18 caught" gets read
    # as a pass, and the count is the only number anyone reads out of a ten-minute run.
    ("the caught count no longer excluding the refused cases",
     [(H, 'print(f"DETAIL: {len(cases) - len(bad)}/{len(cases)} perturbations caught")',
       'print(f"DETAIL: {len(cases)}/{len(cases)} perturbations caught")')],
     [f"{T}::test_a_case_whose_target_stays_green_is_reported_hollow"]),

    # The two numbers `README.md` puts in front of a reader. Both were wrong on the first pass, and
    # 235 reached three other files by copying before anything checked it.
    #
    # **Read out of the file rather than written down, for the same reason the release-tag script
    # reads the current default.** Quoting them made this rot the moment a twentieth script arrived:
    # the anchor matched nothing, and a case that applies to nothing reports nothing. Decrementing
    # whatever is there survives the next script.
    ("the documented script count left behind",
     [(README, f"The {SCRIPTS_DOCUMENTED} scripts here",
       f"The {SCRIPTS_DOCUMENTED - 1} scripts here")],
     [f"{T}::test_the_readme_states_the_real_number_of_scripts_and_cases"]),

    ("the documented case count left behind, which is how 235 shipped",
     [(README, f"all {CASES_DOCUMENTED} cases", f"all {CASES_DOCUMENTED - 1} cases")],
     [f"{T}::test_the_readme_states_the_real_number_of_scripts_and_cases"]),
]

sys.exit(sweep(CASES))
