#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each guard the metric cross-check needs and require `test_metric_cross_check.py` to notice.

Every guard here exists because the wrong answer looks exactly like the right one. Measured
2026-09-13: a `MetricStat` for a rule name that does not exist, a rule with metrics switched off, and
a resolution no longer retained all return series present, `StatusCode: Complete`, `Values: []`,
`Messages: []`. So each case below removes a guard and the check keeps answering, quietly, with a zero.

The last two cases go the other way and are the ones a careless implementation would fail: a check
that speaks when it could not answer, and a check that speaks about a partial gap it cannot decide.
"""

import sys

from _harness import sweep

T = "tests/test_metric_cross_check.py"
M = "tools/waf_metrics.py"
I = "tools/waf_injection.py"

CASES = [
    # The name check. Without it a typo, or one WebACL's rule name used against another, is a
    # confident zero rather than an error.
    ("the rule name no longer checked against the configured list",
     [(M, "    if match is None:\n", "    if False:\n")],
     [f"{T}::test_a_rule_name_that_is_not_configured_is_refused_rather_than_answered_zero"], True),

    # The dimension. Equal to `Name` for all 20 rules on the measurement account, so only a fixture
    # where they differ can catch this.
    ("the rule's Name used as the dimension instead of its MetricName",
     [(M, '{"Name": "Rule", "Value": visibility.get("MetricName") or rule_name}',
       '{"Name": "Rule", "Value": rule_name}')],
     [f"{T}::test_the_dimension_is_the_metric_name_and_not_the_rule_name"], True),

    ("a rule with metrics switched off answered zero rather than refused",
     [(M, '    if not visibility.get("CloudWatchMetricsEnabled", True):\n', "    if False:\n")],
     [f"{T}::test_a_rule_with_metrics_switched_off_is_refused_rather_than_answered_zero"], True),

    # The period, keyed on the wrong end of the window. This is the shape the reviewer named: the
    # older half of a straddling window comes back empty and Complete.
    ("the period keyed on the newest point, so the older half comes back silently empty",
     [(M, "    age_days = (time.time() - start_epoch) / 86400",
       "    age_days = 0")],
     [f"{T}::test_the_period_follows_the_age_of_the_oldest_point",
      f"{T}::test_the_query_uses_the_period_the_window_earns"], True),

    ("the retention floor removed, so a 500-day window is answered from nothing",
     [(M, "    if period is None:\n", "    if False:\n")],
     [f"{T}::test_a_window_beyond_every_retention_is_refused_without_querying"], True),

    # One target, not two. The "never becomes a claim" test refuses at the membership check before any
    # query runs, so it cannot see a change to the exception handler; naming it here would have let a
    # target that cannot fail sit in the list and look like coverage.
    ("a metric query that failed reported as zero",
     [(M, "        return None, f\"the metric query did not run: {type(exc).__name__}: {exc}\"",
       "        return 0, \"\"")],
     [f"{T}::test_a_failed_metric_query_says_so_instead_of_reporting_zero"], True),

    # The other direction: speaking when there is nothing to say.
    ("a refusal turned into a claim about the logs",
     [(M, "    if count is None:\n", "    if False:\n")],
     [f"{T}::test_a_metric_that_could_not_answer_never_becomes_a_claim_about_the_logs"], True),

    ("the partial-gap gate removed, so an undecidable gap is reported as missed data",
     [(M, "    if log_rows != 0:\n        return \"\"", "    if False:\n        return \"\"")],
     [f"{T}::test_a_partial_gap_is_not_reported_yet_and_the_reason_is_a_dependency"], True),

    ("a zero metric beside zero log rows reported as a missed query",
     [(M, "    if count <= 0:\n        return \"\"", "    if False:\n        return \"\"")],
     [f"{T}::test_a_zero_metric_beside_zero_log_rows_says_nothing"], True),

    # The wiring. Textual: the target reads the tool's source, so a spliced raise would edit nothing
    # that runs, and the guard's own reachability is established by the behavioural cases above.
    ("the injection tool's no-activity branch no longer cross-checking metrics",
     [(I, "                    warning = missed_data_warning(get_webacl_name(), target, acl_rules,",
       "                    warning = _no_cross_check(get_webacl_name(), target, acl_rules,")],
     [f"{T}::test_the_injection_tool_reaches_the_cross_check_from_its_no_activity_branch"],
     "textual"),
]

sys.exit(sweep(CASES))
