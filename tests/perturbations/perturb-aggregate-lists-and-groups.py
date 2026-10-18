#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Can `tests/test_aggregate_lists_and_groups.py` fail? A list of values ANDed, a bad value skipped
rather than refusing, no bound on a list, a quote let into a path, several dimensions allowed where they
have no answer, and the query string unmasked or grouped with its empty bucket."""

import sys

from _harness import sweep

G = "tools/waf_aggregate.py"
T = "tests/test_aggregate_lists_and_groups.py"

CASES = [
    ("a list of values ANDed",
     [(G, '"(" + " OR ".join(a_one) + ")"', '"(" + " AND ".join(a_one) + ")"')],
     [f"{T}::test_a_list_of_values_is_any_of_them_on_both_engines"], True),

    ("a bad value in a list skipped rather than refusing",
     [(G, "            if bad:\n                return {}, f\"{bad} (filter_by['{key}'])\"\n            cleaned.append(clean)\n",
       "            if bad:\n                continue\n            cleaned.append(clean)\n")],
     [f"{T}::test_one_bad_value_refuses_the_whole_filter"], True),

    ("no bound on a list",
     [(G, "        if not values or len(values) > _FILTER_VALUES_MAX:\n", "        if False:\n")],
     [f"{T}::test_a_list_is_bounded"], True),

    # probe=False: a module-level dict entry; a raise there fails at import.
    ("a quote let into a path",
     [(G, 'r"[A-Za-z0-9/._~%!$&()*+,=:@-]+", "a URI path', 'r"[A-Za-z0-9/._~%!$&()*+,=:@\'-]+", "a URI path')],
     [f"{T}::test_the_uri_filter_takes_a_path_and_nothing_that_leaves_a_literal"], False),

    ("several dimensions allowed with any metric",
     [(G, "        if metric != \"count\" or any(g in _NOT_IN_MULTI for g in named):\n", "        if False:\n")],
     [f"{T}::test_several_dimensions_are_refused_where_they_have_no_answer"], True),

    ("no bound on the number of dimensions",
     [(G, "        if len(named) > _MULTI_GROUP_MAX or len(set(named)) != len(named):\n", "        if False:\n")],
     [f"{T}::test_several_dimensions_are_refused_where_they_have_no_answer"], True),

    # probe=False: a module-level dict entry.
    ("the query string grouped with its empty bucket",
     [(G, "    \"args\": _Dim(\"httprequest.args\", \"httpRequest.args\",\n"
          "                 where=(\"httprequest.args <> ''\", \"ispresent(httpRequest.args) and httpRequest.args != ''\")),",
       "    \"args\": _Dim(\"httprequest.args\", \"httpRequest.args\"),")],
     [f"{T}::test_args_leaves_out_requests_without_a_query_string_on_both_engines"], False),

    ("the query string rendered unmasked",
     [(G, '                cell, m = _redact("args", cell)\n', "                m = False\n")],
     [f"{T}::test_a_query_string_is_masked_when_rendered"], True),

    ("the query string rated or sized",
     [(G, '    if metric != "count" and "args" in group_by.split(","):\n', "    if False:\n")],
     [f"{T}::test_args_is_for_counts_only"], True),
]

sys.exit(sweep(CASES))
