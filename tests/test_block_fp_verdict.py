# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""The false-positive verdict does not read an unknown peak as a human one.

The queries that feed this verdict refuse on failure, so `peak_rpm` reaches the renderer as "?"
only when the frequency query answered with no row or with a value that does not parse. That was
`peak_val = 0`, which satisfies `peak_val < 10`, the human-speed condition of the FP-candidate
branch, while the evidence table printed "Unknown" two sections up. An unknown peak now blocks
both directional verdicts.
"""

import pytest

from tools import waf_block_fp as F

BASE = dict(rule_id="SomeRule", rule_type="REGULAR", sub_rule="", allow_count=500, block_count=10,
            total=510, avg_rpm="?", rules_triggered=1, uri_results=[], match_detail=[],
            match_detail_note="", text_transforms=[], insp_label=None, insp_samples=None,
            insp_masked=False, clients={"n": 1, "basis": "ip"})


def _verdict(**over):
    out = F._render_investigation("203.0.113.9", 0, 3600, dict(BASE, **over))
    assert "## Directional Judgment" in out and F.CONFIDENCE_RULES in out
    return out.split("## Directional Judgment", 1)[1].split(F.CONFIDENCE_RULES, 1)[0]


@pytest.mark.parametrize("peak", ["?", "n/a", None])
def test_an_unknown_peak_is_not_a_human_speed_peak(peak):
    verdict = _verdict(peak_rpm=peak)
    assert "FP candidate" not in verdict, verdict
    assert "CANNOT DETERMINE" in verdict and "frequency" in verdict.lower(), verdict


def test_an_unknown_peak_does_not_reach_not_a_false_positive_either():
    """Green before the fix too, since 0 never satisfied `> 200`. It guards the opposite wrong fix,
    an unknown peak read as machine speed, which would turn the same gap into an attack verdict."""
    verdict = _verdict(peak_rpm="?", allow_count=0, rules_triggered=3)
    assert "HIGH CONFIDENCE" not in verdict and "CANNOT DETERMINE" in verdict, verdict


@pytest.mark.parametrize("over,expected", [
    (dict(peak_rpm="5"), "FP candidate"),
    (dict(peak_rpm="300", allow_count=0, rules_triggered=3), "HIGH CONFIDENCE: Not a false positive"),
])
def test_a_known_peak_still_reaches_its_verdict(over, expected):
    """The controls, one per directional branch."""
    assert expected in _verdict(**over)
