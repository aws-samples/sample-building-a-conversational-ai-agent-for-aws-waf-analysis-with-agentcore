# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A registered tool the model is never told about is dead surface.

Prep for ROADMAP 4.1, which is the first item in this stretch to add a `@tool`. The rule it
mechanizes was previously prose: a tool that lands with neither a consumer nor prompt routing
is the shape of the `logs:StopQuery` grant for a call the code never made, and of
`_classify_rules`. This makes that a failing test instead of something a reviewer catches.

**"Every registered tool is named in the system prompt" is NOT the invariant, and asserting it
would have been wrong three times over.** `get_waf_metrics`, `lookup_ja4` and
`set_report_summary` are absent from the prompt and all three are still reachable, because the
model sees every registered tool's name and signature through the **tool schema** regardless of
the prompt. Absence from the prompt is a routing gap, not unreachability.

So the invariant is the one `test_prompt_routes_every_step.py` already settled for `ja4_ips`: a
tool may be **output-discovered**, named in the output of a tool the prompt does route to. The
exempt set is DERIVED here rather than hand-written -- it is exactly "registered minus named in
the prompt" -- and every member has to be proved, so it cannot quietly widen. Same shape as
`BACKFILL_FLOOR` in `test_release_metadata.py`, which fails once nothing needs excusing.

**The proof reads string literals out of the producing function's AST, not a substring of the
module.** That distinction is the whole reason this file exists in the form it does: the claim
"all nineteen tools are named in `agent.py`" was checked with a grep over the file, and
`agent.py` imports and registers every tool, so each name was present whether the prompt used it
or not. A name present by construction, read as a name present by use. The same defect as the
module-level `log_query_error` sweep. Reading `ast.Constant` values also excludes comments,
imports and the `_TOOLS` list for free.
"""

import ast
import pathlib
import re
import sys

import pytest

import agent

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"

REGISTERED = {t.tool_name for t in agent._TOOLS}
PROMPT = agent._build_system_prompt(9)


def _routed(name: str) -> bool:
    """Whether the prompt names this tool, on a word boundary.

    `name in PROMPT` would read a tool as routed whenever its name is a substring of one that
    is. No collision among the current nineteen, so this is latent rather than live, but the
    failure direction is the bad one: a new tool would silently inherit another's routing."""
    return re.search(r"\b" + re.escape(name) + r"\b", PROMPT) is not None

# exempt tool -> the tool whose output names it. Values are checked against `REGISTERED` and
# against the prompt, and the keys are checked against the derived set, so neither side of this
# map can drift without a failure.
PRODUCERS = {
    "get_waf_metrics": "get_waf_config",
    "lookup_ja4": "analyze_ip",
    "set_report_summary": "generate_weekly_report",
}


def _tool_functions() -> dict:
    """`{tool name: (path, FunctionDef)}` for every `@tool` in `tools/`.

    Matches `ast.Call` decorators as well as `ast.Name`, because `ask_user` is declared
    `@tool(context=True)` and a bare-name check finds 18 of 19 -- missing the only tool that
    takes a `ToolContext`, which is the one most likely to be special-cased later."""
    found = {}
    for path in sorted(TOOLS_DIR.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(target, ast.Name) and target.id == "tool":
                    found[node.name] = (path, node)
    return found


def _emitted_strings(fn) -> str:
    """Every string literal the function can put in its output, concatenated.

    The whole subtree on purpose, nested helpers included: anything this function can emit is
    part of its output, which is the claim being tested. That is the opposite of
    `test_window_cap.py`'s attribution rule, where a nested wrapper's call must NOT be credited
    to its enclosing function, and the difference is the claim: there it is "who calls this",
    here it is "what can this produce"."""
    body = fn.body
    # Skip the leading docstring. Comments are excluded for free by reading the AST, but a
    # docstring IS an `ast.Constant`, and it is schema text rather than output: deleting the
    # `analyze_ip` hint line and writing "call lookup_ja4 after this" into its docstring would
    # leave this green while nothing the tool emits names the tool. None of the three producers
    # relies on a docstring today, so this closes a latent hole rather than a live one.
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    return "\n".join(n.value for stmt in body for n in ast.walk(stmt)
                     if isinstance(n, ast.Constant) and isinstance(n.value, str))


def test_the_tool_inventory_is_what_this_file_thinks_it_is():
    """The precondition. Every assertion below is about `REGISTERED`, so an empty or truncated
    inventory would make them vacuous, and `_tool_functions` parsing nothing would make the
    producer proofs vacuous too. Named subjects rather than a count: a count passes on the
    wrong nineteen."""
    assert {"get_waf_config", "analyze_ip", "detect_bypass", "ask_user"} <= REGISTERED, \
        sorted(REGISTERED)
    defined = _tool_functions()
    assert REGISTERED <= set(defined), sorted(REGISTERED - set(defined))
    assert len(PROMPT) > 10_000, len(PROMPT)


def test_every_registered_tool_is_either_routed_or_output_discovered():
    """The invariant. A tool in neither camp is dead surface: nothing in the prompt sends the
    model to it and no tool's output mentions it, so it can only be reached by the model
    guessing from the schema."""
    unnamed = {t for t in REGISTERED if not _routed(t)}
    assert unnamed == set(PRODUCERS), {
        "unnamed with no recorded producer": sorted(unnamed - set(PRODUCERS)),
        "recorded as exempt but now named in the prompt, so delete the entry":
            sorted(set(PRODUCERS) - unnamed)}


@pytest.mark.parametrize("exempt,producer", sorted(PRODUCERS.items()))
def test_an_output_discovered_tool_is_named_by_a_tool_the_prompt_routes_to(exempt, producer):
    """Two links in one chain, and both are needed.

    The producer must be reachable: a tool named only by an unrouted tool's output is exempt on
    the strength of another dead end. And the producer's output must actually name the exempt
    tool, read from its own string literals so a mention in a comment or an import does not
    count."""
    assert producer in REGISTERED, f"{producer} is not a registered tool"
    assert _routed(producer), f"the prompt never routes to {producer}, so the chain is broken"
    defined = _tool_functions()
    path, fn = defined[producer]
    assert exempt in _emitted_strings(fn), \
        f"{producer} in {path.name} emits no string naming {exempt}"


def test_the_prompt_routes_to_nothing_that_does_not_exist():
    """The other direction, which catches a renamed or deleted tool still advertised. A prompt
    line telling the model to call something that is gone produces an error it then has to
    interpret, and the line reads authoritative.

    **No exemption list, and removing the need for one also made this sharper.** The first
    version allowed whitespace before the paren, which swallowed four prose parentheticals -- "top_ips_by_volume
    (all actions)", "analyze_ip (e.g. ...)", "get_waf_overview (metrics-based...)",
    "run_logs_query (strip the offset...)". Three were excused for being registered tools, and
    the fourth was the ONLY reason a `waf_logs.TEMPLATES` subtraction existed. Requiring the
    paren to be adjacent takes matches from 12 to 11 and leaves nothing unknown, so the
    subtraction is gone.

    Deleting it is what makes the test do its job: while template keys were subtracted, a prompt
    line telling the model to call `ip_cross_query(ip='...')` as though it were a tool would have
    been excused as a query type, which is exactly the defect this docstring claims to catch."""
    called = set(re.findall(r"\b([a-z][a-z0-9_]*_[a-z0-9_]*)\(", PROMPT))
    assert called, "no call-shaped names parsed from the prompt, so this proves nothing"
    unknown = sorted(called - REGISTERED)
    assert not unknown, f"the prompt routes to names that are not registered tools: {unknown}"


# --- the prompt's claims about get_waf_overview's query types ----------------
#
# Added because the sentence at `agent.py:116` was made PRECISE, and precision is what makes a
# claim able to rot. "Returns full time-series" was too vague to ever be provably stale; naming
# five query types and three others cannot survive a ninth landing. The eight are derivable from
# the dispatch, so the naming half is mechanizable. The series-versus-totals half is derivable
# too, from whether a handler appends inside a `timestamps` loop, and it is deliberately left to
# the prose: that heuristic is fragile enough to become its own false claim, which is how a
# reviewer's probe first mis-sorted `bot_names` by matching "ts" inside `sorted_bots`.

_NUMBER_WORDS = {"three": 3, "five": 5, "eight": 8, "nine": 9, "ten": 10}


def _dispatch_query_types() -> set:
    """The query types `get_waf_overview` actually dispatches, read from its comparisons."""
    tree = ast.parse((TOOLS_DIR / "waf_overview.py").read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) \
                and node.left.id == "query_type":
            for c in node.comparators:
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    found.add(c.value)
    return found


SERIES_ANCHOR = "query types return a time-series"


def _sentence_containing(text: str, anchor: str) -> str:
    """The one sentence of `text` holding `anchor`. A pure function so it can be tested directly.

    **It used to return the LINE, while its name and both failure messages said sentence.** On the
    real prompt that line holds three sentences, and the assertions below passed on it by two
    independent coincidences: the trailing two happen to contain no snake_case token, and the third
    number word happens to come third. Neither is a property anyone maintains.

    The concrete cost was a false failure on a correct edit. `agent.py` already documents
    `start_time` for this tool in the neighbouring section, so anyone consolidating parameter docs
    into this bullet would add a name the dispatch does not have and turn the test red. The quieter
    direction is a false pass: a query type dropped from the prose still satisfies the set
    comparison if the trailing text happens to mention it.

    One more instance of the search space being wider than the claim it supports, which is the
    defect class this session produced six of. Every one erred the same way, because the wider
    expression is the cheaper one to write and gives the right answer most of the time."""
    line = text[text.rindex("\n", 0, text.index(anchor)) + 1:
                text.index("\n", text.index(anchor))]
    return next(s for s in line.split(". ") if anchor in s)


def _series_sentence() -> str:
    """The one sentence in the prompt that enumerates query types by time-series behaviour."""
    assert SERIES_ANCHOR in PROMPT, "the prompt no longer makes this claim; delete these tests"
    return _sentence_containing(PROMPT, SERIES_ANCHOR)


def _query_type_names(sentence: str) -> set:
    """The snake_case tokens in a sentence that could be query types.

    Registered tool names are subtracted, derived from `REGISTERED` rather than listed. The
    sentence currently sits after the one naming the tool, so `get_waf_overview` falls outside it
    and this changes nothing today. It removes a false-failure path: rewording so the tool name
    lands in the same sentence is a correct edit that would otherwise report a name the dispatch
    does not have. A query type can never legitimately share a tool's name, so nothing real is
    hidden, and the missing-type direction is unaffected."""
    tokens = set(re.findall(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b", sentence))
    return tokens - REGISTERED


def test_the_prompt_names_every_overview_query_type_and_no_others():
    """Both directions in one set comparison. A ninth query type makes the sentence incomplete;
    a renamed one makes it wrong, and the model would ask for a type that no longer dispatches."""
    dispatch = _dispatch_query_types()
    assert len(dispatch) >= 5, sorted(dispatch)
    named = _query_type_names(_series_sentence())
    assert named == dispatch, {"named but not dispatched": sorted(named - dispatch),
                              "dispatched but not named": sorted(dispatch - named)}


def test_the_counts_in_that_sentence_match_the_lists_it_gives():
    """"Five of the eight" is the part a reader acts on, so it has to track the lists. Without
    this, a ninth type could be added to the prose and the set comparison above would pass while
    the sentence still said eight."""
    sentence = _series_sentence()
    # Matched by ROLE, not by position. Taking the first two number words in order relied on
    # "a trend from those three" coming third, which is the same wider-than-the-claim shape as
    # the line-versus-sentence bug above, one level down.
    phrase = re.search(r"\b([a-z]+) of the ([a-z]+) query types", sentence, re.I)
    assert phrase, f"no 'N of the M query types' phrase in: {sentence!r}"
    with_series = _NUMBER_WORDS[phrase.group(1).lower()]
    total = _NUMBER_WORDS[phrase.group(2).lower()]
    named = _query_type_names(sentence)
    assert total == len(named), f"sentence says {total} query types, names {len(named)}"
    assert total == len(_dispatch_query_types()), \
        f"sentence says {total} query types, the code dispatches {len(_dispatch_query_types())}"
    assert with_series < total, f"{with_series} of {total} leaves nothing without a series"


def test_the_sentence_helper_returns_a_sentence_and_not_the_line():
    """Pins the fix directly, with a decoy that the line-scoped version would have swallowed.

    The decoy is `start_time`, chosen because it is the real thing that would land here: the
    prompt documents it for this tool one section away, so consolidating parameter docs into this
    bullet is the ordinary edit that used to break the test."""
    # Mirrors the real line's shape: the tool named in a first sentence, the claim in a second,
    # a parameter mentioned in a third. The first version put the tool name inside the anchor
    # sentence, which the real prompt does not do, so the fixture was testing a shape that does
    # not occur. Getting that wrong is the same defect in the test's own inputs.
    line = ("- **get_waf_overview**: `minutes` param. Two of the two query types return a "
            "time-series (top_a, top_b). Pass start_time for a historical window.\n")
    got = _sentence_containing("preamble\n" + line + "trailer\n", SERIES_ANCHOR)
    assert got.endswith("(top_a, top_b)"), got
    assert "start_time" not in got, "the helper swallowed the next sentence"
    assert "minutes" not in got, "the helper swallowed the previous sentence"
    assert _query_type_names(got) == {"top_a", "top_b"}
