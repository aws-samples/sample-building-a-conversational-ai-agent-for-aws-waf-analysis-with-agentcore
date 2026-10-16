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
     [(B, '''    unique_uris = uri_data[0].get("unique_uris", "?") if uri_data else ("?" if failures.get("uri_diversity") else 0)''',
       '''    unique_uris = uri_data[0].get("unique_uris", "?") if uri_data else "?"''')],
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

    ("CloudWatch's first-rule-only reading left unsaid",
     [(B, '''        if get_log_type() == "cwl":
            lines.append("  (CloudWatch: each request''', '''        if False:
            lines.append("  (CloudWatch: each request''')],
     [f"{T}::test_cloudwatch_says_it_lists_the_first_count_rule_only"], True),
]

sys.exit(sweep(CASES))
