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
     [(L, "        if not rows:\n            return None", "        if not rows:\n            return 0")],
     [f"{T}::test_a_failed_uri_query_does_not_become_endpoint_hammering",
      f"{T}::test_a_failed_rate_query_does_not_rank_the_ip_on_a_zero_peak"], True),

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
]

sys.exit(sweep(CASES))
