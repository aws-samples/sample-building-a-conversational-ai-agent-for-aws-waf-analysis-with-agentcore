#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.5: restore each defect the shared filter removed, and require red.

Two of the eight are the states that actually shipped -- the unanchored CloudWatch copy
and the missing `jpeg` -- so those are not hypotheticals; they are what the tests were
written against.

Same contract as the other perturbation scripts here: `ast.parse` before pytest so a
perturbation that breaks the build cannot pass for looking red, and a reachability probe
first so a "no change" result cannot be read as "the code is fine".
"""

import sys
import ast

from _harness import sweep

T = "tests/test_static_asset_filter.py"
TEXTUAL = "textual"
PATTERN = r'_PATTERN = r"(?i)\.(" + "|".join(sorted(STATIC_ASSET_EXTENSIONS)) + r")($|\?)"'
CASES = [
    (
        "no (?i), i.e. /IMG_1.PNG counts as a business request",
        "tools/static_assets.py",
        PATTERN,
        r'_PATTERN = r"\.(" + "|".join(sorted(STATIC_ASSET_EXTENSIONS)) + r")($|\?)"',
        [f"{T}::test_an_uppercase_extension_is_still_a_static_asset"],
    ),
    (
        "a bare $, i.e. a versioned asset stops being an asset on a BYOT table",
        "tools/static_assets.py",
        PATTERN,
        r'_PATTERN = r"(?i)\.(" + "|".join(sorted(STATIC_ASSET_EXTENSIONS)) + r")$"',
        [f"{T}::test_every_listed_extension_is_excluded_before_a_query_string"],
    ),
    (
        "unanchored, i.e. the CloudWatch half exactly as it shipped",
        "tools/static_assets.py",
        PATTERN,
        r'_PATTERN = r"(?i)\.(" + "|".join(sorted(STATIC_ASSET_EXTENSIONS)) + r")"',
        [f"{T}::test_the_json_over_match_specifically",
         f"{T}::test_document_and_markup_extensions_stay_in_the_analysis",
         f"{T}::test_a_listed_extension_mid_path_is_not_excluded"],
    ),
    (
        "jpeg dropped, i.e. the gap that was in both halves of the old list",
        "tools/static_assets.py",
        '"png", "jpg", "jpeg", "gif"',
        '"png", "jpg", "gif"',
        [f"{T}::test_the_extensions_the_old_list_got_wrong_are_present"],
    ),
    (
        "the two dialects given separate lists, i.e. the drift this item removed",
        "tools/static_assets.py",
        'ATHENA_EXCLUDE_STATIC = (" AND (httprequest.uri IS NULL"\n'
        "                         f\" OR NOT regexp_like(httprequest.uri, '{_PATTERN}'))\")",
        'ATHENA_EXCLUDE_STATIC = (" AND (httprequest.uri IS NULL"\n'
        "                         r\" OR NOT regexp_like(httprequest.uri, \"\n"
        "                         r\"'(?i)\\.(css|js|png)($|\\?)'))\")",
        [f"{T}::test_both_dialects_render_the_same_extension_list"],
    ),
    (
        "the NULL guard dropped, i.e. Athena loses a real request a BYOT table can carry",
        "tools/static_assets.py",
        'ATHENA_EXCLUDE_STATIC = (" AND (httprequest.uri IS NULL"\n'
        "                         f\" OR NOT regexp_like(httprequest.uri, '{_PATTERN}'))\")",
        "ATHENA_EXCLUDE_STATIC = f\" AND NOT regexp_like(httprequest.uri, '{_PATTERN}')\"",
        [f"{T}::test_a_row_with_no_uri_survives_the_athena_fragment"],
    ),
    (
        "the guard unparenthesised, i.e. OR leaks past the caller's AND",
        "tools/static_assets.py",
        'ATHENA_EXCLUDE_STATIC = (" AND (httprequest.uri IS NULL"\n'
        "                         f\" OR NOT regexp_like(httprequest.uri, '{_PATTERN}'))\")",
        'ATHENA_EXCLUDE_STATIC = (" AND httprequest.uri IS NULL"\n'
        "                         f\" OR NOT regexp_like(httprequest.uri, '{_PATTERN}')\")",
        [f"{T}::test_a_row_with_no_uri_survives_the_athena_fragment"],
    ),
    (
        "CloudWatch syntax in the Athena fragment",
        "tools/static_assets.py",
        'ATHENA_EXCLUDE_STATIC = (" AND (httprequest.uri IS NULL"\n'
        "                         f\" OR NOT regexp_like(httprequest.uri, '{_PATTERN}'))\")",
        'ATHENA_EXCLUDE_STATIC = f" AND httprequest.uri not like /{_PATTERN}/"',
        [f"{T}::test_each_fragment_is_written_in_its_own_dialect"],
    ),
    (
        "one bypass query filtering on CloudWatch only, i.e. per-engine answers",
        "tools/waf_bypass.py",
        "        \" AND ja4fingerprint IS NOT NULL AND ja4fingerprint != ''\"\n"
        '        f"{ATHENA_EXCLUDE_STATIC}"',
        "        \" AND ja4fingerprint IS NOT NULL AND ja4fingerprint != ''\"",
        [f"{T}::test_a_bypass_step_never_excludes_on_one_engine_only"],
    ),
    (
        "one template filtering on CloudWatch only",
        "tools/waf_logs.py",
        '" + ATHENA_EXCLUDE_STATIC + " AND ( labels IS NULL OR none_match(labels, '
        "l -> l.name LIKE '%bot:verified%') ) GROUP BY httprequest.clientip "
        "HAVING count(*) > 200",
        # No leading quote: the exclusion is spliced INTO the template string, so dropping
        # it has to leave one literal rather than closing it early. The first version kept
        # the quote and the perturbation stopped parsing, which the runner reported as
        # INVALID instead of as proof.
        " AND ( labels IS NULL OR none_match(labels, "
        "l -> l.name LIKE '%bot:verified%') ) GROUP BY httprequest.clientip "
        "HAVING count(*) > 200",
        [f"{T}::test_every_template_that_excludes_on_one_engine_excludes_on_the_other"],
    ),
    (
        "a twenty-first hand-written copy, in the module the sweep is named for",
        "tools/waf_logs.py",
        'f"{CWL_EXCLUDE_STATIC}"',
        r"' and httpRequest.uri not like /\\.(js|css|png|jpg|gif|ico|woff2?|svg|ttf|otf)/'",
        [f"{T}::test_no_module_still_carries_a_hand_written_extension_list"],
        TEXTUAL,
    ),
]

# A case with no marker gets the reachability probe: the anchor is replaced with a bare raise
# and the targets must go red, or the line never executes and a green result from the real
# perturbation below would say nothing. A marker means the target reads source rather than
# running it, or that reachability is established elsewhere; each one says which in a comment.
sys.exit(sweep([(c[0], [(c[1], c[2], c[3])], c[4], len(c) == 5) for c in CASES]))
