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
]

sys.exit(sweep(CASES))
