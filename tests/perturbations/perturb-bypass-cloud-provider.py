#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_bypass_cloud_provider.py` fail?

The provider signal dropped from each engine's scan filter and from the verdict, and the wrong fix
that calls the signal alone HIGH CONFIDENCE.
"""

import sys

from _harness import sweep

T = "tests/test_bypass_cloud_provider.py"
B = "tools/waf_bypass.py"
SCAN = f"{T}::test_the_scan_selects_cloud_provider_and_data_center_traffic"

CASES = [
    ("the CloudWatch scan on the data-center signal only again",
     [(B, """        _LABELS_ARRAY + " | " "filter action = 'ALLOW' and (lbls like 'known_bot_data_center'"\n"""
          """        " or lbls like 'signal:cloud_service_provider:')\"""",
       """        _LABELS_ARRAY + " | " "filter action = 'ALLOW' and (lbls like 'known_bot_data_center')\"""")],
     [SCAN]),

    ("the Athena scan on the data-center signal only again",
     [(B, """        " OR any_match(labels, l -> l.name LIKE '%signal:cloud_service_provider:%'))\"""", """        ")\"""")],
     [SCAN]),

    ("the verdict blind to the provider signal again",
     [(B, "_all(bool(providers), not has_datacenter", "_all(False, not has_datacenter")],
     [f"{T}::test_an_unclassified_ip_on_a_cloud_provider_is_a_likely_undetected_bot"]),

    ("the wrong fix: the provider signal alone called HIGH CONFIDENCE",
     [(B, 'f"**LIKELY: Undetected automation from a cloud provider', 'f"**HIGH CONFIDENCE: Undetected automation from a cloud provider')],
     [f"{T}::test_an_unclassified_ip_on_a_cloud_provider_is_a_likely_undetected_bot"]),

    ("the provider rung firing on any IP",
     [(B, "_all(bool(providers), not has_datacenter, not has_bot_label, _gt(allowed, 50))",
       "_all(True, not has_datacenter, not has_bot_label, _gt(allowed, 50))")],
     [f"{T}::test_the_control_the_same_ip_without_the_signal_is_undetermined"]),

    ("the 50-a-minute gate back, which the fleet never reached",
     [(B, "not has_bot_label, _gt(allowed, 50)), [", "not has_bot_label, _gt(allowed, 50), _gt(peak_val, 50)), [")],
     [f"{T}::test_the_fleet_at_its_own_pace_is_named"]),

    ("no volume needed, so a handful of requests is called automation",
     [(B, "not has_bot_label, _gt(allowed, 50)), [", "not has_bot_label), [")],
     [f"{T}::test_the_control_a_handful_of_requests_is_not_called_automation"]),
]

sys.exit(sweep(CASES))
