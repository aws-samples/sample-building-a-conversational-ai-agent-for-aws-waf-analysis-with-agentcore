#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Restore the falsified non-UTC claim in each of the four places it shipped, require red.

The fifth case is the one worth having: the CHANGELOG's released sections are exempt because
they accurately record what 0.9.0 shipped, and rewriting them would falsify history. That
exemption must not cover a NEW entry, so this puts the claim above the newest heading and
requires the sweep to catch it.
"""

import sys

from _harness import sweep

T = "tests/test_partition_timezone_claim.py"
CASES = [
    ("the false claim back in the code", "tools/waf_config.py",
     '            lines.append("  Note: the S3 prefix time zone is detected from the delivery "',
     '            lines.append("  Firehose S3 prefix time zone MUST be UTC. "'),
    ("the false claim back in the public doc", "docs/firehose-minute-partitioning.md",
     "A non-UTC zone works too:", "A non-UTC zone makes queries return 0 results:"),
    ("the false claim back in the Chinese twin", "docs/firehose-minute-partitioning_zh.md",
     "改成别的时区也能用", "改成别的时区会导致查询返回 0 结果"),
    ("the claim smuggled into a NEW changelog entry, i.e. the history exemption widening",
     "CHANGELOG.md", "# Changelog\n", "# Changelog\n\n- prefix time zone must be UTC\n"),
    ("the corrected statement reverted out of the doc", "docs/firehose-minute-partitioning.md",
     "prunes partitions in that zone", "handles it"),
]
# No reachability probe on any case: every target reads source or a document as text, so the
# perturbed line never executes and the probe would report every good perturbation as
# unreachable. The sibling scripts pass `len(c) == 5` here; that idiom does not apply.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], [T]) for c in CASES]))
