#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Run every perturbation script, one at a time, and report which of them proved anything.

    python tests/perturbations/run-all.py            # all of them, about seven minutes
    python tests/perturbations/run-all.py hit-rate   # just the ones whose name contains this

**Serial on purpose.** Each script edits shared source files and puts them back, so two at once
perturb each other's baseline and both report nonsense.

The whole suite is checked before the first script and after the last. A script whose restore is
wrong leaves a mutated tree that the next script reads as its baseline, and the failure then gets
attributed to whichever script happened to run next.
"""

import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def suite():
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
                          cwd=ROOT, capture_output=True, text=True)
    lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
    return proc.returncode, (lines[-1] if lines else "<no output>")


def main(argv):
    scripts = sorted(HERE.glob("perturb-*.py"))
    if argv:
        scripts = [s for s in scripts if any(a in s.name for a in argv)]
    if not scripts:
        print(f"no perturbation scripts matched {argv}")
        return 1

    rc, tail = suite()
    print(f"suite before: {tail}")
    if rc != 0:
        print("The suite is red before anything was perturbed. Fix that first; every script below "
              "would report ERROR for a reason that has nothing to do with it.")
        return 1

    failed = []
    for script in scripts:
        started = time.time()
        proc = subprocess.run([sys.executable, str(script)], cwd=ROOT, capture_output=True, text=True)
        elapsed = int(time.time() - started)
        status = next((line for line in proc.stdout.splitlines() if line.startswith("STATUS:")),
                      "STATUS: <none printed>")
        print(f"{'PASS' if proc.returncode == 0 else 'FAIL'}  {script.name:36s} {elapsed:4d}s  {status}")
        if proc.returncode != 0:
            failed.append(script.name)
            for line in proc.stdout.splitlines():
                if line.startswith(("HOLLOW", "INVALID", "DETAIL")):
                    print(f"        {line}")
            if proc.stderr.strip():
                print(f"        stderr: {proc.stderr.strip().splitlines()[-1]}")

    rc, tail = suite()
    print(f"suite after:  {tail}")

    print("\n---RESULT---")
    print(f"STATUS: {'PASS' if not failed and rc == 0 else 'FAIL'}")
    print(f"DETAIL: {len(scripts) - len(failed)}/{len(scripts)} scripts proved their tests can fail")
    for name in failed:
        print(f"DETAIL: {name}")
    if rc != 0:
        print("DETAIL: the suite is red after the run, so some script restored the tree wrongly")
    return 0 if not failed and rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
