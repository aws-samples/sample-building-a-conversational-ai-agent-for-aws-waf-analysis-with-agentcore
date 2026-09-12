# Perturbations

The suite passes. That says nothing about whether any of it can fail.

A test that checks something already enforced one layer upstream passes forever and guards nothing,
and it looks exactly like a test that works. The 20 scripts here settle the question one property at a
time: each breaks something the suite claims to hold, then requires a named test to go red. If the
test stays green, the assertion was decoration.

**Until now these scripts lived in a gitignored directory, so CI proved the assertions pass and
nothing proved they can fail.** On a repository that takes outside pull requests, a green tick meant
less than it looked like.

## What the first honest run found

Four of the 19 had drifted into proving nothing.

One anchor had matched nothing since a second tool name joined a registration line. One dedented a
line whose successor was still inside a `with`, so the file stopped parsing and red said nothing about
the lock the case was aimed at. One quoted a release tag, and the next release falsified it, taking
all three of its cases at once.

The fourth is the one worth remembering. It perturbed a test file that had been replaced months
earlier, and with its anchors dead it printed `ok ... no tests ran in 0.00s`. pytest exits non-zero
for a target it cannot find, so a script reading only the exit code scores that as caught. A run in
which nothing was observed reported the same thing a working run reports. That script was deleted
rather than repaired, and the harness now reads the summary line instead of trusting the exit code.

## Running them

```bash
python tests/perturbations/run-all.py                      # everything, about six minutes
python tests/perturbations/run-all.py hit-rate tool-reach  # just the names matching these
python tests/perturbations/perturb-hit-rate.py             # one script on its own
```

**Serial only.** Every script edits shared source files in place and puts them back, so two at once
perturb each other's baseline and both report nonsense. `run-all.py` also runs the whole suite before
the first script and after the last, because a script that restores wrongly leaves a mutated tree and
the next script reads that as its baseline.

## Reading the output

Each case prints one of four verdicts.

`ok` means the target went red, so that assertion is load-bearing.

`HOLLOW` means the property was broken and the test stayed green. That is the finding, and it means
the test needs fixing, not the script.

`INVALID` means the run ended red or green for a reason other than the assertion: an anchor that
matched the wrong number of times, a file that stopped parsing, pytest failing at collection, a run
where no test executed, or a perturbed line that never runs under those targets.

`STATUS: ERROR` means the targets were already failing before anything was touched, so the whole
script was abandoned. Nothing below that line means anything.

## Adding one

A docstring naming the test file it covers and why those cases, a `CASES` list, and one `sweep(...)`
call. Read the docstring in `_harness.py` first: it holds eight guards and says what went wrong
without each.

Don't write the loop and don't call `subprocess.run`. `tests/test_perturbation_harness.py` refuses
both, and it refuses a module-level `for` loop too, because one script kept its entire original loop
through the move by calling a local helper named `run`, so the banned token wasn't there and the file
would have raised `NameError` on its first line.

The reachability probe is opt-in per case. It replaces the anchor with a bare `raise` and requires the
targets to go red first; if they stay green the line never executes under those tests and the real
perturbation would prove nothing either way. A case whose target reads source rather than running it
skips the probe and says so in a comment.

## What CI runs

On every push, `tests/test_perturbation_harness.py` unit-tests the harness guards and statically
re-checks that all 265 cases still anchor to code that exists and still name tests that exist. It
takes under a second, and anchor drift is silent, so that is where drift gets caught.

The sweep itself is `.github/workflows/perturbations.yml`, on every pull request. What only the sweep
can answer is whether the test actually goes red.

**Every pull request, with no paths filter, because the failure this catches is caused by product code.**
The static check catches an anchor that has stopped matching. It cannot catch an anchor that still
matches while the perturbation no longer changes anything, and that is the failure that happened twice:
a case added a routing line for a tool that did not exist and the tool then shipped; another removed a
tool's only prompt mention after the tool gained a second one. Neither change touched this directory. A
nightly run was the first answer and it was wrong: nothing here rots with time, since these scripts
import only the standard library and read files in the repository, so a schedule reports the failure
later than the commit that caused it and attributes it to nobody.

## The limit

This shows that the properties the suite asserts are load-bearing. It says nothing about whether the
suite asserts the right properties.
