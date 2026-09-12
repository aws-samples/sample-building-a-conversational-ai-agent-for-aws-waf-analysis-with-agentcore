#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_memory_identifier.py` fail?

Two of these cases were found by the reviewer against the first version of that file and both stayed
green: reverting one namespace to the raw `user_id`, and deleting `lstrip("_-/")`. The first mattered
because the tests covered the helper and not the call site, where the decision is made; the second
because the corpus had no input whose sanitised form began with an illegal character. Both are cases
here now, so neither can come back quietly.

**Deliberately not a case: removing the `[:48]` truncation.** Nothing guards it and nothing should. It
keeps the identifier readable in the console and the 255-character cap is asserted independently, so a
longer readable part is a cosmetic regression rather than a correctness one. Saying so is better than
adding a case that reports MISSED forever.

Run from the repo root. Restores every touched file on any exit path.
"""

import sys
import pathlib

from _harness import sweep

FILE = "tests/test_memory_identifier.py"
CASES = [
    # Found by the reviewer. The namespaces were half the original bug.
    ("namespace-reverted-to-raw-email", 'f"/facts/{actor}/"', 'f"/facts/{user_id}/"',
     "test_the_call_site_derives_every_identifier_from_the_sanitised_value"),
    ("actor-id-reverted-to-raw-email", "actor_id=actor,", "actor_id=user_id,",
     "test_the_call_site_derives_every_identifier_from_the_sanitised_value"),
    # Not a revert: a DIFFERENT derivation. This is the case that showed the full-equality assertion
    # is the strong one, because `raw not in namespace` still holds here.
    ("namespace-derived-differently", 'f"/facts/{actor}/"', 'f"/facts/{actor.upper()}/"',
     "test_the_call_site_derives_every_identifier_from_the_sanitised_value"),
    # Found by the reviewer. Unguarded until the corpus grew two leading-dot inputs.
    ("leading-strip-removed", '.lstrip("_-/")[:48]', "[:48]",
     "test_the_sanitised_id_is_accepted_where_the_raw_one_is_not"),
    # The hash, both ways it can stop protecting anything.
    ("hash-taken-from-the-sanitised-string", "hashlib.sha256(user_id.encode())",
     "hashlib.sha256(readable.encode())",
     "test_long_addresses_sharing_a_prefix_do_not_collide"),
    ("hash-dropped-entirely", 'return f"{readable}-{digest}" if readable else f"u-{digest}"',
     'return readable or "u"',
     "test_ids_that_differ_only_in_a_substituted_character_do_not_collide"),
    # The bare except is why the charset bug survived nine releases.
    ("failure-swallowed-again",
     'print(f"WARNING: memory disabled, setup failed: {type(exc).__name__}: {exc}")', "pass",
     "test_memory_setup_failure_is_reported_rather_than_swallowed"),
]
TARGET = pathlib.Path("agent.py")

# No reachability probe on any case: every target reads source or a document as text, so the
# perturbed line never executes and the probe would report every good perturbation as
# unreachable. The sibling scripts pass `len(c) == 5` here; that idiom does not apply.
sys.exit(sweep([(c[0], [(TARGET, c[1], c[2])], [f"{FILE}::{c[3]}"]) for c in CASES]))
