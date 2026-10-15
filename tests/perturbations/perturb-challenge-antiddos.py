#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each property `test_challenge_antiddos.py` claims and require it to notice."""

import sys

from _harness import sweep

T = "tests/test_challenge_antiddos.py"
W = "tools/waf_challenge_check.py"

CASES = [
    ("any anti-ddos label counted as an event again (Athena)",
     [(W, '        ddos_athena = (\n            "SELECT count(*) as hits FROM {TABLE}"\n            " WHERE \\"timestamp\\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"\n            f" AND any_match(labels, l -> l.name = \'{event}\')"\n        )\n',
       '        ddos_athena = (\n            "SELECT count(*) as hits FROM {TABLE}"\n            " WHERE \\"timestamp\\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"\n            " AND any_match(labels, l -> l.name LIKE \'%anti-ddos%\')"\n        )\n')],
     [f"{T}::test_challengeable_request_labels_are_not_an_event",
      f"{T}::test_both_dialects_name_the_event_label_exactly"], True),

    ("the CloudWatch filter unanchored again",
     [(W, '        ddos_cwl = f"filter @message like \'\\"name\\":\\"{event}\\"\' | stats count(*) as hits"', '        ddos_cwl = "filter @message like \'anti-ddos\' | stats count(*) as hits"')],
     [f"{T}::test_both_dialects_name_the_event_label_exactly"], True),

    ("the event label misspelled, which the positive control is for",
     [(W, '        event = "awswaf:managed:aws:anti-ddos:event-detected"',
       '        event = "awswaf:managed:aws:anti-ddos:event-detect"')],
     [f"{T}::test_an_event_detected_label_is_still_reported"], True),
]

sys.exit(sweep(CASES))
