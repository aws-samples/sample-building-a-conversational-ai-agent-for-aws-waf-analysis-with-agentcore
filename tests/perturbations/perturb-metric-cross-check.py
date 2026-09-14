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
I2 = "tools/waf_count_eval.py"

CASES = [
    # The refusal restored. It was in this file until 2026-09-13 and it cost a real 33,932-match
    # signal: `TGT_TokenAbsent` publishes a `Rule` dimension while appearing nowhere in the config.
    ("an unconfigured name refused again, i.e. the guard that threw away a real signal",
     [(M, '    return rule_name, "unknown"',
       '    return None, "unknown"')],
     [f"{T}::test_a_name_the_configuration_does_not_know_is_queried_rather_than_refused",
      f"{T}::test_the_dimension_and_the_state_come_from_the_configuration"], True),

    # The dimension. Equal to `Name` for all 20 rules on the measurement account, so only a fixture
    # where they differ can catch this.
    ("the rule's Name used as the dimension instead of its MetricName",
     [(M, '        return visibility.get("MetricName") or rule_name, "top-level"',
       '        return rule_name, "top-level"')],
     [f"{T}::test_the_dimension_and_the_state_come_from_the_configuration"], True),

    # A managed sub-rule's dimension IS its own name, so losing the override branch changes only the
    # reported state. Behaviourally invisible, which is why the state is asserted at all.
    ("the managed sub-rule branch removed, so an override reads as unknown",
     [(M, "    for r in rules:\n        overrides = (r.get(\"Statement\", {}).get(\"ManagedRuleGroupStatement\", {})\n",
       "    for r in []:\n        overrides = (r.get(\"Statement\", {}).get(\"ManagedRuleGroupStatement\", {})\n")],
     [f"{T}::test_the_dimension_and_the_state_come_from_the_configuration"], True),

    ("a rule with metrics switched off answered zero rather than refused",
     [(M, '    if in_config == "metrics-off":\n', "    if False:\n")],
     [f"{T}::test_a_rule_with_metrics_switched_off_is_refused_rather_than_answered_zero",
      f"{T}::test_a_metric_that_could_not_answer_never_becomes_a_claim_about_the_logs"], True),

    ("the metrics-off state never produced, so the refusal above has nothing to fire on",
     [(M, '            return rule_name, "metrics-off"', '            return rule_name, "top-level"')],
     [f"{T}::test_the_dimension_and_the_state_come_from_the_configuration",
      f"{T}::test_a_rule_with_metrics_switched_off_is_refused_rather_than_answered_zero"], True),

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

    # Anchored through the following line, because `if log_rows != 0` now appears in both
    # `missed_data_warning` and `missed_action_warning` and a two-line anchor would match twice.
    ("the partial-gap gate removed, so an undecidable gap is reported as missed data",
     [(M, "    if log_rows != 0:\n        return \"\"\n    count, reason = rule_blocked_per_metrics(",
       "    if False:\n        return \"\"\n    count, reason = rule_blocked_per_metrics(")],
     [f"{T}::test_a_partial_gap_is_not_reported_yet_and_the_reason_is_a_dependency"], True),

    # The action-subject entry point, which has no membership check by design because `ALL` is a
    # service aggregate rather than a name a caller can misspell.
    ("the action metric compared at a rule dimension instead of the WebACL aggregate",
     [(M, '    return _metric_sum(webacl_name, "ALL", metric_name, start_epoch, end_epoch)',
       '    return _metric_sum(webacl_name, "SomeRule", metric_name, start_epoch, end_epoch)')],
     [f"{T}::test_an_action_question_is_compared_at_the_webacl_aggregate"], True),

    ("the action-to-metric mapping inverted, so CHALLENGE is checked against CaptchaRequests",
     [(M, '    metric_name = {"CHALLENGE": "ChallengeRequests", "CAPTCHA": "CaptchaRequests"}.get(action)',
       '    metric_name = {"CHALLENGE": "CaptchaRequests", "CAPTCHA": "ChallengeRequests"}.get(action)')],
     [f"{T}::test_each_action_is_checked_against_its_own_metric"], True),

    ("an unknown action answered instead of skipped",
     [(M, "    if metric_name is None:\n        return \"\"",
       "    if metric_name is None:\n        metric_name = \"ChallengeRequests\"")],
     [f"{T}::test_an_action_with_no_metric_of_its_own_is_skipped"], True),

    ("a zero metric beside zero log rows reported as a missed query",
     [(M, "    if count <= 0:\n        return \"\"", "    if False:\n        return \"\"")],
     [f"{T}::test_a_zero_metric_beside_zero_log_rows_says_nothing"], True),

    # The additive-check property, and the one CI caught rather than review: resolving the dimension
    # needs two wafv2 calls in a branch that previously touched no AWS, so an unguarded read turns a
    # working answer into an exception wherever those calls fail.
    ("the WebACL read unguarded again, so a cross-check failure costs the answer",
     [(I2, "        try:\n"
           "            rules = _get_webacl_rules(resolve_region(scope), scope)\n"
           "        except Exception as exc:                          # noqa: BLE001\n"
           "            print(f\"[waf_count_eval] no metric cross-check for {rule_name}: \"\n"
           "                  f\"{type(exc).__name__}: {exc}\", file=sys.stderr, flush=True)\n"
           "            rules = None\n",
       "        rules = _get_webacl_rules(resolve_region(scope), scope)\n")],
     [f"{T}::test_a_cross_check_that_cannot_run_does_not_cost_the_answer_it_annotates"], True),

    # The wiring. No probe: the target reads the tool's source, so a raise inserted there would sit in
    # a line nothing runs, and the guard's own reachability is established by the behavioural cases
    # above. Written `"textual"` at first, which is truthy, so it asked for the probe it was declining.
    ("the injection tool's no-activity branch no longer cross-checking metrics",
     [(I, "                    warning = missed_data_warning(get_webacl_name(), target, acl_rules,",
       "                    warning = _no_cross_check(get_webacl_name(), target, acl_rules,")],
     [f"{T}::test_the_injection_tool_reaches_the_cross_check_from_its_no_activity_branch"],
     False),
]

sys.exit(sweep(CASES))
