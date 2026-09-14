#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break the metric funnel and require `test_metric_provenance.py` to notice.

The funnel is the CloudWatch client itself, so the ways it can fail are the ways a proxy fails: not
applied, applied to everything, recording the wrong thing, or not delegating. The last one is the
quietest, because a proxy that swallows an attribute breaks a caller somewhere no provenance test looks.

The final case is the one that guards the whole approach: a module building its own client holds an
unwrapped CloudWatch and discloses nothing, while every behavioural test here stays green.
"""

import sys

from _harness import sweep

A = "tools/aws_session.py"
M = "tools/waf_metrics.py"
T = "tests/test_metric_provenance.py"

CASES = [
    ("the wrapper never applied, so the tools hold a raw client",
     [(A, '    return _RecordingCloudWatch(client) if service == "cloudwatch" else client',
       "    return client")],
     [f"{T}::test_get_client_wraps_cloudwatch_and_nothing_else"], True),

    ("every service wrapped, putting a proxy in front of every call in the repository",
     [(A, 'return _RecordingCloudWatch(client) if service == "cloudwatch" else client',
       "return _RecordingCloudWatch(client)")],
     [f"{T}::test_get_client_wraps_cloudwatch_and_nothing_else"], True),

    ("the record dropped, so a metric read discloses nothing again",
     [(A, '            note_query_provenance("CloudWatch metrics", int(start.timestamp()), int(end.timestamp()))\n',
       "")],
     [f"{T}::test_a_metric_read_records_its_window_and_names_the_engine"], True),

    ("a metric read labelled as a log query, which is the misattribution one layer down",
     [(A, '"CloudWatch metrics", int(start.timestamp())', '"CloudWatch Logs Insights", int(start.timestamp())')],
     [f"{T}::test_a_metric_read_records_its_window_and_names_the_engine"], True),

    ("the window read from the wrong end, so the record describes a window nobody asked for",
     [(A, '        start, end = kwargs.get("StartTime"), kwargs.get("EndTime")',
       '        start, end = kwargs.get("EndTime"), kwargs.get("StartTime")')],
     [f"{T}::test_a_metric_read_records_its_window_and_names_the_engine"], True),

    ("the read recorded and then not performed, which no provenance assertion would see",
     [(A, "        return self._client.get_metric_data(**kwargs)", "        return {}")],
     [f"{T}::test_a_metric_read_records_its_window_and_names_the_engine"], True),

    # The quiet one. A proxy is only safe while everything it does not intercept passes through.
    ("the proxy no longer delegating, so every other CloudWatch call breaks somewhere else",
     [(A, "        return getattr(self._client, name)", "        return None")],
     [f"{T}::test_everything_other_than_the_metric_read_delegates_untouched"], True),

    ("the missing-window guard removed, so a call botocore would refuse crashes in the proxy",
     [(A, "        if start is not None and end is not None:", "        if True:")],
     [f"{T}::test_a_read_missing_its_window_records_nothing_and_is_refused_downstream"], True),

    # Structural target, so no probe: it reads source rather than running the line.
    ("a module building its own client, which is how a metric read escapes the funnel",
     [(M, '    client = get_client("cloudwatch", region_name=region)',
       '    client = get_session().client("cloudwatch", region_name=region)')],
     [f"{T}::test_the_only_client_constructor_is_the_one_that_wraps"], False),
]

sys.exit(sweep(CASES))
