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
     [(B, "_all(bool(providers), not has_datacenter, not has_bot_label, _gt(uri_val, 50))",
       "_all(True, not has_datacenter, not has_bot_label, _gt(uri_val, 50))")],
     [f"{T}::test_the_control_the_same_ip_without_the_signal_is_a_scraper_with_no_provider"]),

    ("an allowed-request bar instead of URIs, which calls people browsing automation",
     [(B, "_all(bool(providers), not has_datacenter, not has_bot_label, _gt(uri_val, 50))",
       "_all(bool(providers), not has_datacenter, not has_bot_label, _gt(allow_count, 50))")],
     [f"{T}::test_the_control_people_browsing_from_a_cloud_address_are_undetermined"]),

    ("the office and VPN reading dropped from the evidence",
     [(B, 'f"looks like this, and so do a partner\'s integration and an office or VPN egress on the "\n'
          '                f"provider\'s addresses.",', 'f"looks like this, and so does a partner\'s integration.",')],
     [f"{T}::test_an_unclassified_ip_on_a_cloud_provider_is_a_likely_undetected_bot"]),

    ("the CDN reading only on the provider rung, not after whichever spoke",
     [(B, "        if providers:\n            lines.append(f\"Provider signal: ", "        if False:\n            lines.append(f\"Provider signal: ")],
     [f"{T}::test_any_provider_is_named_with_the_cdn_reading_whatever_rung_spoke"]),

    ("analyze_ip blind to the provider label",
     [("tools/waf_logs.py", '    providers = sorted(set(re.findall(r"signal:cloud_service_provider:([a-z_]+)", all_labels)))',
       '    providers = []')],
     [f"{T}::test_analyze_ip_names_the_provider_too"]),
]

sys.exit(sweep(CASES))
