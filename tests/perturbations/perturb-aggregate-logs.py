#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.1: break each property `test_aggregate_logs.py` claims and require it to notice.

Same runner contract as the other perturbation scripts: `ast.parse` first, then a reachability
probe, then the real edit, reporting ANCHOR / INVALID / HOLLOW / ok per entry. The pytest tail is
read as well as the exit code, because a perturbation that adds an unimported name is valid syntax
and fails at collection, which `ast.parse` cannot see and a bare exit-code check scores as `ok`.

`TEXTUAL` marks a target that reads SOURCE rather than running code, where the reachability probe
would call a perfectly good perturbation INVALID.
"""

import sys

from _harness import sweep

T = "tests/test_aggregate_logs.py"
W = "tests/test_window_cap.py"
R = "tests/test_tool_reachability.py"
TEXTUAL = "textual"
CASES = [
    (
        "a dimension with no Athena expression at all",
        "tools/waf_aggregate.py",
        '    "ruletype": _Dim("terminatingruletype", "terminatingRuleType"),',
        '    "ruletype": _Dim("", "terminatingRuleType"),',
        [f"{T}::test_every_group_dimension_renders_in_both_dialects"],
    ),
    (
        "the two engines labelling the same column differently",
        "tools/waf_aggregate.py",
        "    return dim.athena, dim.athena, dim.cwl, dim.cwl_pre, dim.unnest, dim.cwl",
        "    return dim.athena, dim.athena, dim.cwl, dim.cwl_pre, dim.unnest, group_by",
        [f"{T}::test_every_group_dimension_renders_in_both_dialects"],
    ),
    (
        "the percentile scales swapped, i.e. CloudWatch silently returns the near-minimum",
        "tools/waf_aggregate.py",
        '            + "".join(f" approx_percentile(c, {p / 100}) AS p{p}," for p in _PERCENTILES)',
        '            + "".join(f" approx_percentile(c, {p}) AS p{p}," for p in _PERCENTILES)',
        [f"{T}::test_the_percentile_scale_is_right_for_each_engine"],
    ),
    (
        "the CloudWatch percentile taking a fraction, which is the silent direction",
        "tools/waf_aggregate.py",
        '               + "".join(f" pct(c, {p}) as p{p}," for p in _PERCENTILES)',
        '               + "".join(f" pct(c, {p / 100}) as p{p}," for p in _PERCENTILES)',
        [f"{T}::test_the_percentile_scale_is_right_for_each_engine"],
    ),
    (
        "the ratio numerator ALSO scoping the query, i.e. every group reads 100%",
        "tools/waf_aggregate.py",
        '                  f" {a_from} WHERE {a_where} GROUP BY {a_group}"',
        '                  f" {a_from} WHERE {a_where} AND {a_pred} GROUP BY {a_group}"',
        [f"{T}::test_a_ratio_puts_its_filter_in_the_numerator_and_not_in_the_where_clause"],
    ),
    (
        "a ratio with no numerator answered instead of refused",
        "tools/waf_aggregate.py",
        '    if metric == "ratio" and not filters:',
        "    if False:",
        [f"{T}::test_a_ratio_with_no_numerator_is_refused_rather_than_answered"],
    ),
    (
        "the rule filter missing the nested-COUNT array, i.e. a copy of rule_uri_prefix",
        "tools/waf_aggregate.py",
        '    " OR any_match(rulegrouplist, rg -> any_match(rg.nonterminatingmatchingrules,"\n'
        "    \" r -> r.ruleid = '{v}'))\"",
        '    ""',
        [f"{T}::test_the_rule_filter_reaches_every_place_a_match_is_recorded"],
    ),
    (
        "the label filter back to a LIKE, whose `_` wildcard widens what it matches",
        "tools/waf_aggregate.py",
        "\"any_match(labels, l -> strpos(l.name, '{v}') > 0)\"",
        "\"any_match(labels, l -> l.name LIKE '%{v}%')\"",
        [f"{T}::test_the_label_filter_uses_no_wildcard_metacharacter"],
    ),
    (
        "the bucket column renamed, so CloudWatch results stay in UTC",
        "tools/waf_aggregate.py",
        'f"bin({bucket_minutes}m) as time_bucket", (), "", "time_bucket")',
        'f"bin({bucket_minutes}m) as bucket", (), "", "bucket")',
        [f"{T}::test_the_time_bucket_column_is_named_so_the_timezone_shift_finds_it"],
    ),
    (
        "a validator dropped, i.e. the dimension with no guard at all",
        "tools/waf_aggregate.py",
        '    "country": _Filter(_checked(r"[A-Za-z]{2}", "a two-letter country code"),',
        '    "country": _Filter(lambda v: (v, None),',
        [f"{T}::test_a_value_that_would_break_out_of_a_literal_is_refused",
         f"{T}::test_a_refused_value_never_reaches_a_query"],
    ),
    (
        "the value used un-normalised, i.e. the padding that reaches the literal",
        "tools/waf_aggregate.py",
        "        return value, None\n\n    return check",
        "        return raw, None\n\n    return check",
        [f"{T}::test_edge_whitespace_is_removed_rather_than_carried_into_the_literal"],
    ),
    (
        "an unknown filter key accepted rather than refused with the list",
        "tools/waf_aggregate.py",
        "        if key not in _FILTERS:",
        "        if False:",
        [f"{T}::test_filter_by_refuses_what_it_cannot_read"],
    ),
    (
        "the refusal no longer naming the valid dimensions, so the model guesses again",
        "tools/waf_aggregate.py",
        "        return (f\"Error: '{group_by}' is not a group_by dimension. Available: \"\n"
        '                f"{\', \'.join(sorted(_GROUP_BY))}.")',
        '        return f"Error: \'{group_by}\' is not a group_by dimension."',
        [f"{T}::test_an_unknown_key_or_metric_is_refused_with_the_valid_ones_listed"],
    ),
    (
        "the CloudWatch header parse dropped when the header is only a filter",
        "tools/waf_aggregate.py",
        "        stages.extend(stage for stage in spec.cwl_pre if stage not in stages)",
        "        stages.extend([])",
        [f"{T}::test_a_header_dimension_emits_its_cloudwatch_parse_before_any_filter"],
    ),
    (
        "the partition filter dropped, i.e. every query scans the whole bucket",
        "tools/waf_aggregate.py",
        "    a_where = (f'\"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}')",
        "    a_where = (f'\"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}}')",
        [f"{T}::test_every_group_dimension_renders_in_both_dialects"],
    ),
    (
        "the window clamp written as a literal instead of the shared constant",
        "tools/waf_aggregate.py",
        "    duration = min(duration_minutes, MAX_MINUTES)",
        "    duration = min(duration_minutes, 360)",
        [f"{W}::test_every_tool_clamps_to_the_shared_constant"],
        TEXTUAL,
    ),
    (
        "the prompt routing to a tool nobody registered",
        "agent.py",
        # Both names, because a second tool joined this line and the one-name anchor then matched
        # nothing. `aggregate_logs,` on its own appears twice, once here and once in the prose.
        "          aggregate_logs, investigate_injection,\n",
        "          investigate_injection,\n",
        [f"{R}::test_the_prompt_routes_to_nothing_that_does_not_exist"],
        TEXTUAL,
    ),
    (
        "the error-row guard removed from the one query site",
        "tools/waf_aggregate.py",
        "    reason = log_query_error(rows)\n    if reason:\n        return reason",
        "    reason = None\n    if reason:\n        return reason",
        [f"{W}::test_every_query_logs_caller_checks_for_an_error_row"],
        TEXTUAL,
    ),
    (
        "a second query_logs call, i.e. no wrapper owns the result",
        "tools/waf_aggregate.py",
        "        rows = query_logs(cwl, athena, start_epoch, end_epoch, row_limit)",
        "        rows = query_logs(cwl, athena, start_epoch, end_epoch, row_limit)\n"
        "        rows = query_logs(cwl, athena, start_epoch, end_epoch, row_limit)",
        [f"{W}::test_every_query_logs_caller_calls_it_from_exactly_one_place"],
        TEXTUAL,
    ),
    (
        "a filter dimension undocumented, so the model is never told it exists",
        "tools/waf_aggregate.py",
        "            action, rule, ip, country, method, ruletype, ja4, label, host. A label value is",
        "            action, rule, ip, country, method, ruletype, ja4, label. A label value is",
        [f"{T}::test_a_filter_dimension_is_named_where_filter_by_is_documented"],
        TEXTUAL,
    ),
    (
        "a group dimension undocumented, same defect one table over",
        "tools/waf_aggregate.py",
        "            ruletype, ja4, host, ua, referer, label, time_bucket.",
        "            ruletype, ja4, host, ua, label, time_bucket.",
        [f"{T}::test_a_group_dimension_is_named_where_group_by_is_documented"],
        TEXTUAL,
    ),
    (
        "the arg-block split degenerating, so every dimension reads as documented",
        "tests/test_aggregate_logs.py",
        '    for chunk in re.split(rf"\\n {{{indent}}}(?=\\w+:)", body):',
        '    for chunk in [body]:',
        [f"{T}::test_the_docstring_documents_exactly_the_parameters_the_tool_takes"],
        TEXTUAL,
    ),
    (
        "the label filter back to a raw-message substring, i.e. the shipped divergence",
        "tools/waf_aggregate.py",
        "                     \"lbls like '{v}'\", (_LABELS_ARRAY,)),",
        "                     \"@message like '{v}'\"),",
        [f"{T}::test_no_filter_matches_the_raw_record_instead_of_a_field",
         f"{T}::test_the_label_filter_sees_every_label_and_only_labels"],
    ),
    (
        "the label filter reading only the first label, i.e. silent under-matching",
        "tools/waf_aggregate.py",
        "                     \"lbls like '{v}'\", (_LABELS_ARRAY,)),",
        "                     \"label like '{v}'\", (_LABELS_ARRAY, \"filter ispresent(lbls)\",\n"
        "                      r'parse lbls /\"name\":\"(?<label>[^\"]*)\"/')),",
        [f"{T}::test_the_label_filter_sees_every_label_and_only_labels"],
    ),
    (
        "the shared labels stage emitted twice, i.e. lbls redefined after it was read",
        "tools/waf_aggregate.py",
        "        stages.extend(stage for stage in spec.cwl_pre if stage not in stages)",
        "        stages.extend(spec.cwl_pre)",
        [f"{T}::test_the_shared_labels_stage_is_emitted_once_when_it_is_both_group_and_filter"],
    ),
    (
        "an unanchored @message value on a filter that legitimately uses one",
        "tools/waf_aggregate.py",
        "_RULE_CWL = (\"(terminatingRuleId = '{v}' or @message like '\\\"ruleId\\\":\\\"{v}\\\"'\"",
        "_RULE_CWL = (\"(terminatingRuleId = '{v}' or @message like '{v}'\"",
        [f"{T}::test_no_filter_matches_the_raw_record_instead_of_a_field"],
    ),
    (
        "the excluded-rules branch searching the log's own camelCase key, which matches nothing",
        "tools/waf_aggregate.py",
        "    \" OR any_match(rulegrouplist, rg -> strpos(rg.excludedrules, '\\\"ruleid\\\":\\\"{v}\\\"') > 0)\"",
        "    \" OR any_match(rulegrouplist, rg -> strpos(rg.excludedrules, '\\\"ruleId\\\":\\\"{v}\\\"') > 0)\"",
        [f"{T}::test_the_excluded_rules_branch_searches_the_key_the_serde_actually_writes"],
    ),
    (
        "the excluded-rules branch dropped entirely, i.e. Athena under-reports a real match",
        "tools/waf_aggregate.py",
        "    \" OR any_match(rulegrouplist, rg -> strpos(rg.excludedrules, '\\\"ruleid\\\":\\\"{v}\\\"') > 0)\"\n",
        "",
        [f"{T}::test_the_rule_filter_reaches_every_place_a_match_is_recorded",
         f"{T}::test_the_excluded_rules_branch_searches_the_key_the_serde_actually_writes"],
    ),
    (
        "the anchoring sweep left with no floor under it",
        "tools/waf_aggregate.py",
        "_RULE_CWL = (\"(terminatingRuleId = '{v}' or @message like '\\\"ruleId\\\":\\\"{v}\\\"'\"\n"
        "             \" or @message like '\\\"rateBasedRuleName\\\":\\\"{v}\\\"')\")",
        "_RULE_CWL = \"(terminatingRuleId = '{v}' or terminatingRuleType = '{v}')\"",
        [f"{T}::test_no_filter_matches_the_raw_record_instead_of_a_field"],
        TEXTUAL,
    ),
    (
        "the CWL rule clause tightened with a sibling key, i.e. the copy that reopens the gap",
        "tools/waf_aggregate.py",
        "_RULE_CWL = (\"(terminatingRuleId = '{v}' or @message like '\\\"ruleId\\\":\\\"{v}\\\"'\"",
        "_RULE_CWL = (\"(terminatingRuleId = '{v}' or @message like '\\\"ruleId\\\":\\\"{v}\\\",\\\"action\\\":\\\"COUNT\\\"'\"",
        [f"{T}::test_the_cloudwatch_rule_clause_carries_no_sibling_key"],
        TEXTUAL,
    ),
    (
        "a CWL rule location dropped, i.e. the count invariant on the other engine",
        "tools/waf_aggregate.py",
        "             \" or @message like '\\\"rateBasedRuleName\\\":\\\"{v}\\\"')\")",
        "             \")\")",
        [f"{T}::test_both_engines_reach_the_same_number_of_rule_locations"],
        TEXTUAL,
    ),
]

# A case with no marker gets the reachability probe: the anchor is replaced with a bare raise
# and the targets must go red, or the line never executes and a green result from the real
# perturbation below would say nothing. A marker means the target reads source rather than
# running it, or that reachability is established elsewhere; each one says which in a comment.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
