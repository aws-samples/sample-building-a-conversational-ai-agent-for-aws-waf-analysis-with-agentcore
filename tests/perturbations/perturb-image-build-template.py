#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_image_build_template.py` fail?

Every assertion in that file reads `deploy/image-build.yaml`, either as text or by exec'ing the
handler out of it, so a regex that stops matching turns an assertion into a tautology rather than a
failure. Each case below breaks one property and names the test that must go red. A case reported
MISSED means the named test cannot see that property at all.

Deliberately absent: a perturbation that makes the polling loop never exit. It would hang this
script instead of failing a test, which is a worse signal than no signal. The deadline is covered by
case `deadline-returns-instead-of-raising`, which reaches the same branch and terminates.

Run from the repo root. Restores the template on every exit path.
"""

import sys
import pathlib

from _harness import sweep

TEMPLATE = pathlib.Path("deploy/image-build.yaml")
FILE = "tests/test_image_build_template.py"
CASES = [
    ("x86-environment-type", "Type: ARM_CONTAINER", "Type: LINUX_CONTAINER",
     "test_the_environment_type_and_the_build_image_agree_on_the_architecture"),
    ("x86-build-image", "amazonlinux-aarch64-standard", "amazonlinux-x86_64-standard",
     "test_the_environment_type_and_the_build_image_agree_on_the_architecture"),
    ("no-privileged-mode", "        PrivilegedMode: true\n", "",
     "test_the_environment_type_and_the_build_image_agree_on_the_architecture"),
    ("platform-flag-back", "                  docker build \\",
     "                  docker build --platform linux/arm64 \\",
     "test_the_buildspec_does_not_ask_for_a_platform"),
    ("build-commit-lost", 'BUILD_COMMIT=$RELEASE_TAG', 'BUILD_COMMIT=unknown',
     "test_the_image_is_tagged_with_the_release_and_never_latest"),
    ("mutable-tags", "ImageTagMutability: IMMUTABLE", "ImageTagMutability: MUTABLE",
     "test_the_image_is_tagged_with_the_release_and_never_latest"),
    ("the-real-ecr-bug", '"countType":"imageCountMoreThan"', '"countType":"imageCountMoreThanN"',
     "test_the_lifecycle_policy_uses_a_count_type_ecr_accepts"),
    ("source-not-no-source", "        Type: NO_SOURCE", "        Type: S3",
     "test_the_no_source_project_carries_its_buildspec_inline"),
    ("location-set", "        Type: NO_SOURCE",
     "        Type: NO_SOURCE\n        Location: s3://bucket/key",
     "test_the_no_source_project_carries_its_buildspec_inline"),
    # The handler. These are the ones whose real-world failure is a stack hung for an hour.
    # Anchors carry the template's own indentation, 14 spaces at statement level inside the
    # handler. The outer guard needs its `respond` line too: the same `except` line appears
    # earlier, inside `respond` itself, and a one-line anchor would perturb the wrong guard.
    ("outer-guard-reraises",
     '              except Exception as exc:                       # noqa: BLE001\n'
     '                  respond(event, context, "FAILED", str(exc), physical_id)',
     "              except Exception:                             # noqa: BLE001\n"
     "                  raise",
     "test_every_request_type_and_build_outcome_sends_exactly_one_response"),
    ("inner-guard-reraises",
     '                  print(f"failed to send {status} response: {exc}")',
     "                  raise",
     "test_an_unreachable_response_url_does_not_raise"),
    ("delete-builds-anyway",
     '                  if event["RequestType"] == "Delete":',
     '                  if event["RequestType"] == "Delete" and False:',
     "test_delete_starts_no_build"),
    ("physical-id-varies",
     '              physical_id = event["ResourceProperties"]["ProjectName"]',
     '              physical_id = event["ResourceProperties"]["ProjectName"] + event["RequestId"]',
     "test_the_physical_id_is_the_same_for_create_and_update"),
    ("deadline-returns-instead-of-raising",
     '              raise RuntimeError(\n'
     '                  f"build {build_id} was still running when this function ran out of time. "',
     '              return RuntimeError(\n'
     '                  f"build {build_id} was still running when this function ran out of time. "',
     "test_running_out_of_time_reports_failure_instead_of_being_killed"),
    ("current-phase-again",
     '                      failed = [p["phaseType"] for p in build.get("phases", [])\n'
     '                                if p.get("phaseStatus") not in (None, "SUCCEEDED")]',
     '                      failed = [build.get("currentPhase", "unknown")]',
     "test_the_failure_reason_names_the_phase_that_failed_not_the_current_one"),
]

# No reachability probe on any case: every target reads source or a document as text, so the
# perturbed line never executes and the probe would report every good perturbation as
# unreachable. The sibling scripts pass `len(c) == 5` here; that idiom does not apply.
sys.exit(sweep([(c[0], [(TEMPLATE, c[1], c[2])], [f"{FILE}::{c[3]}"]) for c in CASES]))
