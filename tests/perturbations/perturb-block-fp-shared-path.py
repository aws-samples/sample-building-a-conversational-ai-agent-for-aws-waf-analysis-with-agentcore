#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_block_fp_shared_path.py` fail?

The look at other traffic on the false positive's paths narrowed, widened or silenced one way at a
time.
"""

import sys

from _harness import sweep

T = "tests/test_block_fp_shared_path.py"
F = "tools/waf_block_fp.py"
QUERY = f"{T}::test_other_ips_blocked_on_the_same_path_are_counted_by_the_same_sub_rule"
RENDER = f"{T}::test_the_render_warns_that_an_exception_for_the_path_lets_the_others_through"

CASES = [
    ("the group's other sub-rules counted on the path",
     [(F, """           + (f" | {_LAST_SUB_RULE_CWL} | filter sub_rule = '{safe_sub}'" if sub_rule else "")""",
       """           + ("")""")],
     [QUERY]),

    ("the false-positive IP's own blocks counted as others'",
     [(F, """           f" sum(if(httpRequest.clientIp != '{ip}', 1, 0)) as hits,""", """           f" count(*) as hits,""")],
     [QUERY]),

    ("every path the rule blocks listed, not only this IP's",
     [(F, """by httpRequest.uri | filter own > 0 | sort hits desc""", """by httpRequest.uri | sort hits desc""")],
     [QUERY]),

    ("the IP itself counted among the other IPs",
     [(F, """max(int(float(r.get("seen") or 0)) - 1, 0))""", """int(float(r.get("seen") or 0)))""")],
     [QUERY]),

    ("only the investigation window looked at, which missed the scanners",
     [(F, "rows = _run_query(cwl, athena, start_epoch - pad - (end_epoch + pad - end), end, limit=_SHARED_PATHS)",
       "rows = _run_query(cwl, athena, start_epoch, end_epoch, limit=_SHARED_PATHS)")],
     [QUERY]),

    ("the widening past now dropped rather than moved before the window",
     [(F, "rows = _run_query(cwl, athena, start_epoch - pad - (end_epoch + pad - end), end, limit=_SHARED_PATHS)",
       "rows = _run_query(cwl, athena, start_epoch - pad, end, limit=_SHARED_PATHS)")],
     [f"{T}::test_a_window_ending_now_looks_further_back_rather_than_less"]),

    ("a day either side again, past the window cap",
     [(F, "    pad = max(MAX_MINUTES * 60 - (end_epoch - start_epoch), 0) // 2", "    pad = 86400")],
     [QUERY]),

    ("other IPs' blocks hidden when the distinct count reads zero",
     [(F, 'other IPs" if hits else f"  {uri}: no other IP")', 'other IPs" if ips else f"  {uri}: no other IP")'),
      (F, "            if any(hits for hits, _ in shared.values()):", "            if any(ips for _, ips in shared.values()):")],
     [f"{T}::test_other_ips_blocks_are_shown_whatever_the_distinct_count_says"]),

    ("no warning that an exception opens the path to others",
     [(F, "            if any(hits for hits, _ in shared.values()):", "            if False:")],
     [RENDER], True),

    ("a failed look read as nobody else blocked",
     [(F, '        return None, f"{type(exc).__name__}: {exc}"\n    # `seen` counts', '        return {}, ""\n    # `seen` counts')],
     [f"{T}::test_a_failed_look_says_so_and_keeps_the_rest"]),

    ("the next action handing straight to scope-down design again",
     [(F, 'lines.append("If user confirms FP → first read \\"Other traffic this rule blocks on these paths\\": where other IPs "',
       'lines.append("If user confirms FP → use search_waf_knowledge to help design scope-down exclusion. "')],
     [RENDER]),
]

sys.exit(sweep(CASES))
