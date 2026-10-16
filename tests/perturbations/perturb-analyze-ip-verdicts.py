#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_analyze_ip_verdicts.py` claims and require it to notice.

The shipped defects come back one at a time, and the last case is the wrong fix: a ladder that
refuses on every input is green on every refusal test, and only the per-rung controls catch it.
"""

import sys

from _harness import sweep

T = "tests/test_analyze_ip_verdicts.py"
L = "tools/waf_logs.py"

CASES = [
    ("a failed UA list read as NAT again",
     [(L, "        nat = _is_nat_traffic(ua_rows) if ua_rows else None",
       "        nat = _is_nat_traffic(ua_rows) if ua_rows else True")],
     [f"{T}::test_a_failed_ua_list_is_not_read_as_nat"], True),

    ("too few UAs to judge read as NAT again",
     [(L, "    if len(uas) < 4:\n        return None", "    if len(uas) < 4:\n        return True")],
     [f"{T}::test_a_ua_list_too_short_to_judge_is_not_read_as_nat"], True),

    ("the Mac branch back in front of iPhone",
     [(L, '        elif "iPhone" in ua or "iPad" in ua:\n            os_set.add("iOS")\n'
          '        elif "Macintosh" in ua or "Mac OS" in ua:\n            os_set.add("Mac")\n',
       '        elif "Macintosh" in ua or "Mac OS" in ua:\n            os_set.add("Mac")\n'
       '        elif "iPhone" in ua or "iPad" in ua:\n            os_set.add("iOS")\n')],
     [f"{T}::test_mac_and_iphone_safari_users_are_two_operating_systems"]),

    ("a failed query read as zero again",
     [(L, "        if failures.get(label):\n            return None", "        if False:\n            return None")],
     [f"{T}::test_a_failed_uri_query_does_not_become_endpoint_hammering",
      f"{T}::test_a_failed_rate_query_does_not_rank_the_ip_on_a_zero_peak"], True),

    ("an empty answer read as unanswered again",
     [(L, '        if not rows or rows[0].get(key) in (None, ""):\n            return cast(0)',
       '        if not rows:\n            return None\n        if rows[0].get(key) in (None, ""):\n            return cast(0)')],
     [f"{T}::test_an_ip_pulling_only_static_files_is_a_static_client_not_hammering"], True),

    ("Athena's NULL peak read as not a number again",
     [(L, '        if not rows or rows[0].get(key) in (None, ""):\n            return cast(0)',
       '        if not rows:\n            return cast(0)')],
     [f"{T}::test_athena_no_minutes_is_a_zero_peak_not_a_failure"], True),

    ("Athena's zero-count row taken for records",
     [(L, '    if not diversity or str(diversity[0].get("total", "")) == "0":', '    if not diversity:')],
     [f"{T}::test_athena_no_records_for_the_ip_is_said_so"], True),

    ("the UA-rotation rung never firing",
     [(L, "lambda: ua_count > 1 and ja4_count == 1 and peak_val > 50,", "lambda: False,")],
     [f"{T}::test_one_client_rotating_its_ua_is_named"]),

    ("an unparseable value read as zero again",
     [(L, "            return cast(rows[0].get(key))\n        except (ValueError, TypeError):\n            return None",
       "            return cast(rows[0].get(key))\n        except (ValueError, TypeError):\n            return 0")],
     [f"{T}::test_an_unparseable_peak_is_unknown_not_zero"], True),

    ("a rung with an unknown input skipped instead of stopping the ladder",
     [(L, "        if missing:\n            verdict = (", "        if False:\n            verdict = (")],
     [f"{T}::test_a_failed_uri_query_does_not_become_endpoint_hammering"], True),

    ("an undecided NAT gate no longer refusing the verdict",
     [(L, "    if nat_unknown:\n        verdict = (", "    if False:\n        verdict = (")],
     [f"{T}::test_a_failed_ua_list_is_not_read_as_nat",
      f"{T}::test_a_ua_list_too_short_to_judge_is_not_read_as_nat"], True),

    ("the wrong fix: refuse on every input",
     [(L, "    verdict = None\n    if nat_unknown:", '    verdict = "**CANNOT DETERMINE** — x"\n    if nat_unknown:')],
     [f"{T}::test_answered_inputs_still_reach_their_verdict"], True),

    ("hammering judged on the overall rate again",
     [(L, "lambda: dyn_peak > 200 and uri_val < 10,", "lambda: peak_val > 200 and uri_val < 10,")],
     [f"{T}::test_an_ip_pulling_only_static_files_is_a_static_client_not_hammering"]),

    ("the scraper judged on the overall rate again",
     [(L, "lambda: dyn_peak > 200 and uri_val > 50,", "lambda: peak_val > 200 and uri_val > 50,")],
     [f"{T}::test_many_api_paths_at_a_low_api_rate_are_not_a_high_confidence_scraper"]),

    ("the static-client rung never firing",
     [(L, "lambda: peak_val > 200 and non_static < 0.1 * total,", "lambda: False,")],
     [f"{T}::test_an_ip_pulling_only_static_files_is_a_static_client_not_hammering",
      f"{T}::test_mostly_static_with_a_few_api_calls_is_judged_on_the_api_part"]),

    ("one file pulled over and over not told from many",
     [(L, "if n <= 2 else", "if False else")],
     [f"{T}::test_an_ip_pulling_only_static_files_is_a_static_client_not_hammering"]),

    ("the non-static rate counting static requests again",
     [(L, """    dyn_rate_cwl = (\n        f'filter httpRequest.clientIp = "{safe_ip}"'\n        f"{CWL_EXCLUDE_STATIC}"\n""",
       """    dyn_rate_cwl = (\n        f'filter httpRequest.clientIp = "{safe_ip}"'\n""")],
     [f"{T}::test_the_rate_the_rungs_compare_reads_the_same_requests_as_the_uri_count"]),
]

sys.exit(sweep(CASES))
