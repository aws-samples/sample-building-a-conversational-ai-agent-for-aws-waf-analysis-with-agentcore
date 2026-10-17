#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_bot_control_names.py` fail? A Bot Control name nobody publishes put back where it
was, in the code and in the prompt, and the knowledge base's provider list made a list again."""

import sys

from _harness import sweep

T = "tests/test_bot_control_names.py"
NAMES = f"{T}::test_every_name_read_is_one_the_latest_version_publishes"

CASES = [
    ("analyze_ip looking for TGT_TokenReuseIP again",
     [("tools/waf_logs.py", '    if "TGT_TokenReuseIp" in all_labels:', '    if "TGT_TokenReuseIP" in all_labels:')],
     [NAMES, f"{T}::test_a_token_shared_across_ips_reaches_the_label_findings"]),

    ("the prompt recommending TGT_TokenReuseIP again",
     [("agent.py", "| Token reuse | TGT_TokenReuseIpMedium (CAPTCHA by default)", "| Token reuse | TGT_TokenReuseIPMedium (CAPTCHA by default)")],
     [NAMES]),

    ("a misspelt signal label in the bypass verdict",
     [("tools/waf_bypass.py", '    has_datacenter = any("known_bot_data_center" in r.get("Labels", "") for r in labels)',
       '    has_datacenter = any("signal:known_bot_datacenter" in r.get("Labels", "") for r in labels)')],
     [NAMES]),
]

sys.exit(sweep(CASES))
