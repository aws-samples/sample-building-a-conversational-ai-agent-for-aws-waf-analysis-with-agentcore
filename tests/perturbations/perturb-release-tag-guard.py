#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Does `test_every_hand_written_version_string_agrees` actually see `deploy/image-build.yaml`?

The template has three `Default:` lines, so a regex that finds "the first default that looks like a
version" would pass today and drift the moment the parameter order changes. Case 3 is the one that
matters: it removes the real default AND makes a NEIGHBOURING parameter's default version-shaped, so
a leaking regex would read the wrong line and the guard would go green while comparing nothing.

**The anchor is read out of the template rather than written down.** The first version quoted
`v0.22.0`, and cutting `v0.23.0` turned all three cases into `the anchor string is gone`, which is
fail-closed and correct but means the script proved nothing from the moment of the release until
someone noticed. A perturbation script that names the current version is guaranteed to rot at the
next cut, which is exactly when this guard matters most.
"""

import re
import sys

from _harness import ROOT, sweep

TEMPLATE = "deploy/image-build.yaml"
FILE = "tests/test_release_metadata.py"

_defaults = re.findall(r"^    Default: (v\d+\.\d+\.\d+)$", (ROOT / TEMPLATE).read_text(), re.M)
if len(_defaults) != 1:
    raise SystemExit(f"{TEMPLATE} has {len(_defaults)} version-shaped defaults, expected 1: "
                     f"{_defaults}. Perturbing the wrong one would prove nothing.")
CURRENT = f"    Default: {_defaults[0]}"

CASES = [
    # `v0.0.0` rather than the previous tag: it is a version the repository will never cut, so the
    # case cannot accidentally become a no-op the way naming a real neighbour release could.
    ("a stale default", [(TEMPLATE, CURRENT, "    Default: v0.0.0")]),
    ("no default at all", [(TEMPLATE, CURRENT + "\n", "")]),
    ("default gone, neighbour looks like a version",
     [(TEMPLATE, CURRENT + "\n", ""),
      (TEMPLATE, "    Default: aws-samples/sample-building", CURRENT + "\n    Ignored: x")]),
]

# No reachability probe on any case: every target reads source or a document as text, so the
# perturbed line never executes and the probe would report every good perturbation as
# unreachable. The sibling scripts pass `len(c) == 5` here; that idiom does not apply.
sys.exit(sweep([(c[0], c[1], [f"{FILE}::test_every_hand_written_version_string_agrees"]) for c in CASES]))
