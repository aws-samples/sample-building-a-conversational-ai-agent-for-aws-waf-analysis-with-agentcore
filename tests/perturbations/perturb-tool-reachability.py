#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.1 prep: prove the tool-reachability sweep can fail, five ways.

The sweep is green today with zero hand-written exemptions, which is exactly the state in
which a hollow sweep is indistinguishable from a real one. Every entry below is the shape of
a mistake someone would actually make: adding a tool with no routing, deleting the output line
that made one reachable, exempting a tool on the strength of an unrouted producer, or letting
the exemption map drift out of step with reality in either direction.
"""

import ast
import sys

from _harness import sweep

T = "tests/test_tool_reachability.py"
TEXTUAL = "textual"          # target reads source, so the probe cannot apply
STRUCTURAL_NO_LOGGING = "structural:no_logging_hint"
def _apply_structural(src: str, which: str) -> str:
    """Edit by locating the node, so rewording the prose cannot disarm the perturbation.

    Finds `get_waf_config` by AST, then drops `get_waf_metrics` from the source lines inside its
    range. The AST gives a JOINED constant for adjacent string literals, which never appears
    verbatim in the source, so a `src.replace(node.value, ...)` finds nothing and silently does
    nothing: that is how the first version of this failed, and the `out != src` assert is what
    turned a silent no-op into a stop. Line-range editing inside an AST-located function keeps
    the structural property that matters here, which is not depending on the surrounding words.
    """
    assert which == STRUCTURAL_NO_LOGGING, which
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "get_waf_config")
    lines = src.splitlines(keepends=True)
    hit = False
    for i in range(fn.lineno - 1, fn.end_lineno):
        if "get_waf_metrics" in lines[i] and '"' in lines[i]:
            lines[i] = lines[i].replace("get_waf_metrics", "the metrics tool")
            hit = True
    assert hit, "no line in get_waf_config names get_waf_metrics inside a string"
    return "".join(lines)
CASES = [
    (
        # Done by REMOVING a tool's only prompt mention rather than by registering a new name.
        # The first version added `query_progress` to `_TOOLS`, which is not imported in
        # agent.py, so pytest failed at COLLECTION with a NameError: red, and red for a reason
        # that has nothing to do with the sweep. `ast.parse` does not catch it because the edit
        # is syntactically valid, which is why the runner now separates errors from failures.
        # BOTH mentions, because the sweep accepts either. The first version removed only the
        # routing line and the tool stayed reachable through the scenario-tool sentence further
        # down, so the case reported HOLLOW for a perturbation that had not broken anything.
        "a registered tool with no routing and no output mention, i.e. 4.1's trap",
        "agent.py",
        # BOTH mentions, as a list of edits, because the sweep accepts either one. The first version
        # removed only the routing line and the tool stayed reachable through the scenario-tool
        # sentence further down, so the case reported HOLLOW for a perturbation that had not broken
        # anything. Each edit still has to match exactly once.
        [('- "challenge not working" / "CAPTCHA issues" / "native app blocked" '
          '\u2192 check_challenge_compatibility(start_time="...")\n', ""),
         ("evaluate_count_rules, investigate_block_fp, detect_bypass, check_challenge_compatibility. "
          "These embed the method",
          "evaluate_count_rules, investigate_block_fp, detect_bypass. These embed the method")],
        None,
        [f"{T}::test_every_registered_tool_is_either_routed_or_output_discovered"],
        TEXTUAL,
    ),
    (
        "the output line that makes lookup_ja4 reachable, deleted",
        "tools/waf_logs.py",
        '    lines.append("→ For JA4 fingerprint analysis: "\n'
        '                 "lookup_ja4(fingerprints=\'<comma-separated fingerprints>\')")',
        '    lines.append("→ For JA4 fingerprint analysis: see the JA4 table above")',
        [f"{T}::test_an_output_discovered_tool_is_named_by_a_tool_the_prompt_routes_to"],
        TEXTUAL,
    ),
    (
        # Anchored STRUCTURALLY, not on the literal. Rewording the string used to break the
        # anchor and the runner reported `matched 0 times`, which is fail-closed and correct, but
        # a perturbation script that quotes the prose it perturbs is a second copy of that prose:
        # editing the prose is the very event that disarms the anchor, and prose is what these
        # tests guard. So this one finds `get_waf_metrics` inside the no-logging append by AST and
        # removes it, whatever the surrounding words happen to be.
        "get_waf_metrics dropped from the no-logging line, i.e. the fix regressed",
        "tools/waf_config.py",
        STRUCTURAL_NO_LOGGING,
        None,
        [f"{T}::test_an_output_discovered_tool_is_named_by_a_tool_the_prompt_routes_to"],
        TEXTUAL,
    ),
    (
        "an exemption justified by a producer the prompt never routes to",
        T,
        '    "lookup_ja4": "analyze_ip",',
        '    "lookup_ja4": "set_report_summary",',
        [f"{T}::test_an_output_discovered_tool_is_named_by_a_tool_the_prompt_routes_to"],
        TEXTUAL,
    ),
    (
        "the exemption map left wider than reality, i.e. it stops self-limiting",
        T,
        '    "set_report_summary": "generate_weekly_report",',
        '    "set_report_summary": "generate_weekly_report",\n    "patrol_scan": "get_waf_config",',
        [f"{T}::test_every_registered_tool_is_either_routed_or_output_discovered"],
        TEXTUAL,
    ),
    (
        # The prompt gains a route to a tool that does not exist, which is what a rename or a
        # deletion leaves behind. The first version set the test's own `unknown = []` and then
        # called the test hollow for passing: an assertion satisfied by construction tests
        # nothing, and this is the second time I have made that mistake in two days.
        "the prompt routing to a tool that does not exist",
        "agent.py",
        '- "what\'s happening" / "any anomalies" / "bot situation" / "overview" \u2192 get_waf_overview',
        '- "what\'s happening" / "any anomalies" / "bot situation" / "overview" \u2192 get_waf_overview\n'
        # Not `investigate_injection`: that tool did not exist when this case was written and
        # shipped in 0.22.0, so the routing line pointed at something real and the sweep was right
        # to stay green. A name nothing in the tree defines is the only durable choice here.
        '- "shield metrics" / "ddos protection" \u2192 check_shield_advanced(ip="...")',
        [f"{T}::test_the_prompt_routes_to_nothing_that_does_not_exist"],
        TEXTUAL,
    ),
    (
        "a ninth overview query type the prompt does not mention",
        "tools/waf_overview.py",
        '    if query_type == "top_rules":',
        '    if query_type == "top_ports":\n        pass\n    elif query_type == "top_rules":',
        [f"{T}::test_the_prompt_names_every_overview_query_type_and_no_others",
         f"{T}::test_the_counts_in_that_sentence_match_the_lists_it_gives"],
        TEXTUAL,
    ),
    (
        "a query type renamed in the code but not in the prompt",
        "tools/waf_overview.py",
        'query_type == "targeted_signals"',
        'query_type == "targeted_sigs"',
        [f"{T}::test_the_prompt_names_every_overview_query_type_and_no_others"],
        TEXTUAL,
    ),
    (
        "the sentence's count left behind when a list changes",
        "agent.py",
        "Five of the eight query types return a time-series",
        "Six of the eight query types return a time-series",
        [f"{T}::test_the_counts_in_that_sentence_match_the_lists_it_gives"],
        TEXTUAL,
    ),
    (
        # Cannot be validated by requiring red on a defect, because the defect's symptom is a
        # FALSE FAILURE. So the target is the decoy test, which pins the fix directly: revert the
        # helper to line scope and it swallows the neighbouring sentences.
        "the sentence helper reverted to line scope",
        "tests/test_tool_reachability.py",
        '    return next(s for s in parts if anchor in s)',
        "    return line",
        [f"{T}::test_the_sentence_helper_returns_a_sentence_and_not_the_line"],
        TEXTUAL,
    ),
    (
        # The reviewer's case: the count a reader acts on, moved away from the list it
        # introduces. This passed everything before the semicolon check, while telling the
        # model to expect totals from five views that do return a series.
        "the series count disagreeing with the list it introduces",
        "agent.py",
        "Five of the eight query types return a time-series",
        "Three of the eight query types return a time-series",
        [f"{T}::test_the_counts_in_that_sentence_match_the_lists_it_gives"],
        TEXTUAL,
    ),
    (
        "a number word the test does not know, reported instead of raising",
        "agent.py",
        "Five of the eight query types return a time-series",
        "Seven of the eight query types return a time-series",
        [f"{T}::test_the_counts_in_that_sentence_match_the_lists_it_gives"],
        TEXTUAL,
    ),
    (
        "the sentence split on every period again, so an abbreviation truncates it",
        "tests/test_tool_reachability.py",
        '    parts = re.split(r\'(?<=\\.)\\s+(?=[A-Z"`])\', line)',
        "    parts = line.split('. ')",
        [f"{T}::test_the_helper_survives_an_abbreviation_inside_the_sentence"],
        TEXTUAL,
    ),
]

def _edits(case):
    """One case's edits, from whichever of the three shapes it was written in.

    A callable in the anchor slot is a transform for a property whose anchor is a node rather than a
    string; a list is several literal edits that all have to land for the property to break.
    """
    label, rel, anchor, replacement = case[:4]
    if anchor == STRUCTURAL_NO_LOGGING:
        return [(rel, lambda src: _apply_structural(src, STRUCTURAL_NO_LOGGING))]
    if isinstance(anchor, list):
        return [(rel, old, new) for old, new in anchor]
    return [(rel, anchor, replacement)]


# No reachability probe on any case: every target reads source or a document as text, so the
# perturbed line never executes and the probe would report every good perturbation as
# unreachable. The sibling scripts pass `len(c) == 5` here; that idiom does not apply.
sys.exit(sweep([(c[0], _edits(c), c[4]) for c in CASES]))
