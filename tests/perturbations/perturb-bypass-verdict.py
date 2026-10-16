#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_bypass_verdict.py` claims and require it to notice.

The case worth reading is the tri-state one. `_all` returning None whenever any input is None,
rather than False when a known input already rules the rung out, would make every unread input
block every rung, and only the data-center rung's precondition test in `test_query_failure_visible`
sees it.
"""

import sys

from _harness import sweep

T = "tests/test_bypass_verdict.py"
Q = "tests/test_query_failure_visible.py"
B = "tools/waf_bypass.py"

CASES = [
    ("the verified branch removed, so a verified crawler falls to the scraper rung",
     [(B, '    has_verified = any("bot:verified" in r.get("Labels", "") for r in labels)', "    has_verified = False")],
     [f"{T}::test_a_verified_crawler_at_scraper_volume_is_a_verified_bot"], True),

    ("verified keyed on any bot label, which the control is for",
     [(B, '    has_verified = any("bot:verified" in r.get("Labels", "") for r in labels)',
       '    has_verified = any("bot:" in r.get("Labels", "") for r in labels)')],
     [f"{T}::test_an_unverified_ip_at_the_same_volume_is_still_a_scraper"], True),

    ("an unparseable value read as zero again",
     [(B, "            return cast(text)\n        except (ValueError, TypeError):\n            return None",
       "            return cast(text)\n        except (ValueError, TypeError):\n            return 0")],
     [f"{T}::test_an_unparseable_peak_stops_the_verdict"], True),

    ("a failed UA query read as a non-automation UA again",
     [(B, '    ua_known = not failures.get("user_agent")', "    ua_known = True")],
     [f"{T}::test_a_failed_input_stops_the_verdict_instead_of_reading_as_zero"], True),

    ("an undecidable rung skipped instead of stopping the ladder",
     [(B, "            if fires is None:\n                unread", "            if False:\n                unread")],
     [f"{T}::test_a_failed_input_stops_the_verdict_instead_of_reading_as_zero"], True),

    ("_all blind to a known False, so any unread input blocks every rung",
     [(B, "            return False if any(x is False for x in xs) else (None if any(x is None for x in xs) else True)",
       "            return None if any(x is None for x in xs) else all(xs)")],
     [f"{Q}::test_the_verdict_still_fires_when_the_label_query_succeeds",
      f"{T}::test_an_unread_input_a_rung_does_not_need_does_not_block_it"], True),

    ("the investigation's automation-UA list split from the scan's again",
     [(B, "            if any(t in ua.lower() for t in AUTOMATION_UA_TOKENS):",
       '            if any(t in ua.lower() for t in ("curl", "python", "wget", "httpie", "go-http", "java/", "okhttp")):')],
     [f"{T}::test_the_verdict_and_the_scan_agree_on_what_an_automation_ua_is"], True),

    ("the scan's CloudWatch pattern hand-written again",
     [(B, '        " | filter " + AUTOMATION_UA_CWL +',
       '        " | filter ua like /(?i)(curl|python-requests|wget|httpie|go-http-client|java\\\\/|okhttp|libwww-perl)/"')],
     [f"{T}::test_both_scan_queries_use_the_shared_pattern"]),

    ("the data-center rung never firing",
     [(B, "            ((\"frequency\",), _all(has_datacenter, not has_bot_label, _gt(peak_val, 50)), [",
       "            ((\"frequency\",), False, [")],
     [f"{T}::test_a_data_center_ip_with_no_bot_label_is_an_undetected_bot"]),

    ("an empty URI answer read as unanswered again",
     [(B, '''    unique_uris = (uri_data[0].get("unique_uris", "?") or 0) if uri_data else ("?" if failures.get("uri_diversity") else 0)''',
       '''    unique_uris = (uri_data[0].get("unique_uris", "?") or 0) if uri_data else "?"''')],
     [f"{T}::test_an_ip_sending_only_static_assets_is_ranked"], True),

    ("a value that is not a number called unanswered again",
     [(B, "                unread = [n for n in needs if failures.get(n)]\n",
       "                unread = [n for n in needs if failures.get(n)] or list(needs)\n")],
     [f"{T}::test_a_value_that_is_not_a_number_is_not_called_unanswered"], True),

    ("the Count rules read from the top level only on Athena again",
     [(B, '''        " coalesce(flatten(transform(rulegrouplist, rg -> coalesce(transform(filter("''',
       '''        " coalesce(flatten(transform(ARRAY[], rg -> coalesce(transform(filter("''')],
     [f"{T}::test_the_count_rules_read_nested_entries_once_per_request"]),

    ("a request counted once per Count entry, so a group run twice counts it twice",
     [(B, '''        "SELECT t.rule as rule, count(*) as hits FROM (SELECT array_distinct(concat("''',
       '''        "SELECT t.rule as rule, count(*) as hits FROM (SELECT (concat("''')],
     [f"{T}::test_the_count_rules_read_nested_entries_once_per_request"]),

    ("CloudWatch finding only each record's first Count rule again",
     [(B, '''        " | parse @message /.*\\"ruleId\\":\\"(?<last>[^\\"]+)\\",\\"action\\":\\"COUNT\\"/"\n''', "")],
     [f"{T}::test_cloudwatch_finds_a_top_level_count_rule_behind_a_nested_one"]),

    ("the configuration's Count rules not added to the names",
     [(B, "        names |= set(_get_all_count_rules(resolve_region(scope), scope))", "        pass")],
     [f"{T}::test_cloudwatch_finds_a_middle_count_rule_the_configuration_names"], True),

    ("a failed configuration read left unsaid",
     [(B, '''    if failures.get("count_rules_config"):''', "    if False:")],
     [f"{T}::test_a_failed_configuration_read_is_said_beside_the_list"], True),

    ("Athena's NULL peak read as not a number again",
     [(B, '''    peak_rpm = (freq[0].get("peak_rpm", "?") or 0) if freq''', '''    peak_rpm = freq[0].get("peak_rpm", "?") if freq''')],
     [f"{T}::test_athena_reads_no_allowed_traffic_as_zero_not_unknown"], True),

    ("no verdict for an IP with nothing allowed",
     [(B, '''    if not failures.get("actions") and allow_count == 0:''', "    if False:")],
     [f"{T}::test_an_ip_with_no_allowed_request_is_no_bypass"], True),

    ("no bypass declared on a failed action query",
     [(B, '''    if not failures.get("actions") and allow_count == 0:''', "    if allow_count == 0:")],
     [f"{T}::test_a_failed_action_query_is_not_no_bypass"], True),

    ("bypass hammering judged on the overall rate again",
     [(B, "_all(_gt(dyn_val, 200), _lt(uri_val, 10))", "_all(_gt(peak_val, 200), _lt(uri_val, 10))")],
     [f"{T}::test_allowed_static_only_traffic_is_not_called_a_bypass"]),

    ("the bypass scraper judged on the overall rate again",
     [(B, "_all(_gt(dyn_val, 200), _gt(uri_val, 50))", "_all(_gt(peak_val, 200), _gt(uri_val, 50))")],
     [f"{T}::test_many_api_paths_at_a_low_api_rate_are_not_a_high_confidence_scraper"]),

    ("the static-traffic verdict never firing",
     [(B, "_all(_gt(static_floor, 200), None if non_static is None", "_all(False, None if non_static is None")],
     [f"{T}::test_allowed_static_only_traffic_is_not_called_a_bypass",
      f"{T}::test_mostly_static_with_a_few_api_calls_is_judged_on_the_api_part"]),

    ("the static rung on the overall peak again, so an API burst fires it",
     [(B, "_all(_gt(static_floor, 200), None if", "_all(_gt(peak_val, 200), None if")],
     [f"{T}::test_an_api_burst_in_a_mostly_static_window_is_not_static_traffic"]),

    ("the distinct-URI count back among the static rung's inputs",
     [(B, "_all(_gt(static_floor, 200), None if non_static is None or allowed is None else non_static < 0.1 * allowed)",
       "_all(_gt(static_floor, 200), None if non_static is None or allowed is None else non_static < 0.1 * allowed,"
       " None if all_val is None else True)")],
     [f"{T}::test_static_traffic_is_named_without_its_distinct_uri_count"]),

    ("the probable-scraper rung naming the overall rate again",
     [(B, 'no bot labels, at a peak of {dyn_peak} non-static req/min."', 'no bot labels. Frequency moderate ({peak_rpm}/min)."')],
     [f"{T}::test_the_probable_scraper_rung_names_the_non_static_rate_it_compared"]),

    ("the middle shape saying which of nothing again",
     [(B, 'f" It was spread over {distinct} distinct URIs.")',
       'f" It was spread over {distinct} distinct URIs. These signals cannot tell which.")')],
     [f"{T}::test_a_middle_shape_does_not_say_which_of_nothing"]),

    ("partial bypass said with nothing allowed again",
     [(B, "    if allow_count and non_allow_count > allow_count * 5:", "    if non_allow_count > allow_count * 5:")],
     [f"{T}::test_no_allowed_request_is_not_called_a_partial_bypass"]),

    ("the partial-bypass line never printed",
     [(B, "    if allow_count and non_allow_count > allow_count * 5:", "    if False:")],
     [f"{T}::test_the_control_a_few_allowed_among_many_blocked_is_a_partial_bypass"]),

    ("every Count rule counted in one query again",
     [(B, "        if chunks[-1] and len(base", "        if False and len(base")],
     [f"{T}::test_many_count_rules_are_counted_in_queries_under_the_length_limit"]),

    ("the length budget leaving no room for the WebACL filter",
     [(B, '_CWL_QUERY_MAX = 10_000 - len(scope_cwl_query("", "w" * 128))', "_CWL_QUERY_MAX = 10_000")],
     [f"{T}::test_many_count_rules_are_counted_in_queries_under_the_length_limit"]),

    ("a failed counting query after the first one rendered as a partial list",
     [(B, '        if failures.get("count_rules"):\n            return []\n        row.update', '        row.update')],
     [f"{T}::test_a_failed_later_counting_query_loses_the_section_rather_than_shortening_it"], True),
]

sys.exit(sweep(CASES))
