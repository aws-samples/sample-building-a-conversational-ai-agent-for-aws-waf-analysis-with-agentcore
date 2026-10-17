#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_block_fp_verdict.py` claims and require it to notice.

The second case is the opposite wrong fix, an unknown peak read as machine speed, which only the
test that was green before the fix can catch.
"""

import sys

from _harness import sweep

T = "tests/test_block_fp_verdict.py"
F = "tools/waf_block_fp.py"

CASES = [
    ("an unknown peak read as zero again",
     [(F, "        peak_val = float(peak_rpm)\n    except (ValueError, TypeError):\n        peak_val = None\n\n    if clients[\"basis\"] == \"several\":\n",
       "        peak_val = float(peak_rpm)\n    except (ValueError, TypeError):\n        peak_val = 0\n\n    if clients[\"basis\"] == \"several\":\n")],
     [f"{T}::test_an_unknown_peak_is_not_a_human_speed_peak"], True),

    ("an unknown peak read as machine speed",
     [(F, "        peak_val = float(peak_rpm)\n    except (ValueError, TypeError):\n        peak_val = None\n\n    if clients[\"basis\"] == \"several\":\n",
       "        peak_val = float(peak_rpm)\n    except (ValueError, TypeError):\n        peak_val = 1e9\n\n    if clients[\"basis\"] == \"several\":\n")],
     [f"{T}::test_an_unknown_peak_does_not_reach_not_a_false_positive_either"], True),

    ("the wrong fix: refuse on every peak",
     [(F, '    if clients["basis"] == "several":\n        lines.append(f"**CANNOT DETERMINE** — {clients[\'n\']} clients share this address and {clients[\'why\']}, "\n                     f"so the IP\'s allowed history and pace are not the blocked user\'s.")\n        lines.append("→ Ask the user which device or application was blocked; its User-Agent picks the client.")\n    elif peak_val is None:\n        lines.append("**CANNOT DETERMINE**',
       '    if clients["basis"] == "several":\n        lines.append(f"**CANNOT DETERMINE** — {clients[\'n\']} clients share this address and {clients[\'why\']}, "\n                     f"so the IP\'s allowed history and pace are not the blocked user\'s.")\n        lines.append("→ Ask the user which device or application was blocked; its User-Agent picks the client.")\n    elif True:\n        lines.append("**CANNOT DETERMINE**')],
     [f"{T}::test_a_known_peak_still_reaches_its_verdict"], True),
]

sys.exit(sweep(CASES))
