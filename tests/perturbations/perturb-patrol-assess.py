#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_patrol_assess.py` claims and require it to notice.

The literal-name case restores the shipped line exactly; the parameter case drops only the
wiring, which a test of the default argument alone would not see.
"""

import sys

from _harness import sweep

T = "tests/test_patrol_assess.py"
P = "tools/waf_patrol.py"

CASES = [
    ("the developer's WebACL name back in the skip set",
     [(P, '    skip_rules = {"ALL", webacl_name}  # WebACL-level aggregates',
       '    skip_rules = {"ALL", "shield-sample-webacl"}  # WebACL-level aggregates')],
     [f"{T}::test_the_webacl_row_is_skipped_for_the_webacl_being_scanned",
      f"{T}::test_no_literal_webacl_name_is_wired_into_the_tools"], True),

    ("the skip set ignoring the scanned WebACL",
     [(P, '    skip_rules = {"ALL", webacl_name}  # WebACL-level aggregates',
       '    skip_rules = {"ALL"}  # WebACL-level aggregates')],
     [f"{T}::test_the_webacl_row_is_skipped_for_the_webacl_being_scanned"], True),

    ("the Chinese baseline text back to yesterday",
     [(P, 'f"上周同期无基线，本期拦截', 'f"昨日无基线，本期拦截')],
     [f"{T}::test_the_no_baseline_text_names_the_week_earlier_window"]),

    ("Count added into the donut total again",
     [(P, '        total_reqs = mitigated + tot["allowed"]', '        total_reqs = mitigated + tot["counted"] + tot["allowed"]')],
     [f"{T}::test_the_traffic_donut_does_not_count_counted_requests_twice"], True),

    ("Count drawn as a third slice again",
     [(P, """json.dumps([mit, tot["allowed"]])""", """json.dumps([mit, tot["counted"], tot["allowed"]])""")],
     [f"{T}::test_the_traffic_donut_does_not_count_counted_requests_twice"], True),

    ("the explicit reads dropped, back to SEARCH alone",
     [(P, "    if rules is not None:\n        names = [\"ALL\"]", "    if False:\n        names = [\"ALL\"]")],
     [f"{T}::test_a_rule_quiet_for_fourteen_days_is_still_read_for_an_old_window"], True),

    ("a metrics-off rule queried anyway",
     [(P, '            if vis.get("CloudWatchMetricsEnabled", True):\n', '            if True:\n')],
     [f"{T}::test_a_rule_with_metrics_off_is_not_queried"], True),

    ("patrol not passing the rules",
     [(P, "    this_week_metrics = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=3600, scope=scope, region=region, rules=acl_rules)",
       "    this_week_metrics = _get_all_rules_metrics_search(cw, webacl_name, start, end, period=3600, scope=scope, region=region)")],
     [f"{T}::test_patrol_passes_the_webacl_rules_to_both_windows"]),

    ("providers read off a name list again",
     [(P, '        if namespace.endswith("cloud_service_provider") and metric_name in _ACTION_METRICS:',
       '        if lbl_name in ("aws", "gcp", "azure", "oracle") and metric_name in _ACTION_METRICS:')],
     [f"{T}::test_every_provider_under_the_namespace_is_counted_whatever_its_name"]),

    ("rule-match and Count series counted as requests again",
     [(P, '        if namespace.endswith("cloud_service_provider") and metric_name in _ACTION_METRICS:',
       '        if namespace.endswith("cloud_service_provider"):')],
     [f"{T}::test_every_provider_under_the_namespace_is_counted_whatever_its_name"]),

    ("the provider item calling it a data center",
     [(P, "                        f'{total:,} requests from cloud provider {name} addresses',",
       "                        f'{total:,} requests from {name.upper()} data center',")],
     [f"{T}::test_a_provider_item_names_the_provider_and_the_cdn_reading"]),

    ("the provider items never raised",
     [(P, '        action_items += _cloud_provider_items(bot_data.get("cloud_providers", {}), lang)\n', "")],
     [f"{T}::test_patrol_raises_the_items_from_the_parsed_providers"]),
]

sys.exit(sweep(CASES))
