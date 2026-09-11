# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 5.3: assert the path does not exist, rather than defend a path that does.

**The item was written as "html.escape the patrol HTML interpolations", and looking for the live XSS
did not find one.** `waf_review_deep._render_html` escapes every line. `waf_patrol`'s log-derived
strings go into the TEXT summary, not into `_render_patrol_html_v2`, whose interpolations are counts,
localized labels, severities and rule names. So an escaping pass would be a mechanism in front of a
signal, and it would rot the moment someone adds a URI column to the patrol report, which is the
natural next enrichment.

What is built instead is the property that fails when log-derived data reaches an HTML generator,
which is the same shape as the routes-through test: assert the path is absent rather than harden a
path that is present.

## What was checked, and how far it reaches

A name-based sweep cannot see a value that arrives through a variable nobody thought to grep for, so
this is per-scope instead: no function that calls an HTML renderer may also hold log rows in that
same scope. Verified across `tools/`, all three renderers clean.

**`report.py` is the one place both meet, and it was traced by hand.** It runs raw Insights queries
at `_poll_log_query`, bypassing `query_logs` entirely, so it is a fourth query path that neither a
`query_logs` sweep nor a name sweep would find. Its only caller is `generate_weekly_report`, which
also builds the HTML. All three call sites coerce: two read `first`/`last` timestamps and a row
count, one reads four `int(float(...))` totals. No attacker-controlled string reaches the template.

**The honest limit: a renderer's ARGUMENTS are not traced.** If someone puts URIs inside
`webacl_results` and passes it in, nothing here catches it, because that needs dataflow rather than a
call-graph check. The durable answer is for the renderer to escape by construction, which is
recorded in ROADMAP 5.3 as the follow-up. This test buys the cheap half: it fires when a renderer
grows a log query beside it, which is how the natural enrichment would be written.
"""

import ast
import pathlib
import re

import pytest

TOOLS = pathlib.Path(__file__).resolve().parents[1] / "tools"

# **HTML is detected by what a function BUILDS, not by a set of renderer names.** A name set was the
# first version and it missed the one case that matters: `report.py` builds its report inline as an
# f-string rather than through a `_render_*` function, so a renderer-name sweep could not see the
# only scope in the repo that holds log rows and HTML together. Detecting a tag in a string literal
# catches both shapes.
HTML_MARKERS = ("<div", "<html", "<td", "<span", "<!DOCTYPE", "<tr", "<p>")
# Kept for the floor below: these must still exist, or a rename would empty the search space.
RENDERERS = {"_render_patrol_html_v2", "_render_html", "_render_investigation"}
# Every way a module reaches log rows, including the raw path `report.py` uses.
LOG_CALLS = {"query_logs", "_safe_query", "_run_query", "_run_q", "_run_log_query",
             "aggregate_logs", "_poll_log_query"}

# `generate_weekly_report` holds both, and it is the one exception, declared with its reason rather
# than excluded silently: its three `_poll_log_query` results are consumed as a row count, two
# timestamps and four `int(float(...))` totals, so no attacker-controlled string reaches the
# template. Traced by hand 2026-09-11. If it grows a fourth call site this list is the wrong place
# to fix it; re-trace instead.
DECLARED = {"report.py:generate_weekly_report"}


def _builds_html(fn) -> bool:
    """Whether this function's own scope contains a string literal carrying an HTML tag.

    Reads `ast.Constant` values, so a tag inside a comment does not count. Stops at nested scopes
    for the same reason `_calls_in_own_scope` does: a helper defined inside is its own subject."""
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and any(m in node.value for m in HTML_MARKERS):
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _emits_html(fn) -> bool:
    """Builds HTML itself, or hands its data to something that does."""
    return _builds_html(fn) or bool(_calls_in_own_scope(fn, RENDERERS))


def _calls_in_own_scope(fn, names: set) -> set:
    """Which of `names` this function calls itself, not counting nested functions.

    Same helper as `test_window_cap.py` and for the same reason: `ast.walk` descends into nested
    `FunctionDef`s, so a wrapper defined inside the function it serves gets credited twice."""
    found, stack = set(), list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in names:
            found.add(node.func.id)
        stack.extend(ast.iter_child_nodes(node))
    return found


def _functions():
    for path in sorted(TOOLS.glob("*.py")):
        tree = ast.parse(path.read_text())
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield path, fn


def test_the_sweep_found_the_renderers_it_names():
    """The floor. Every assertion below is about functions that call a renderer, so a renamed
    renderer would empty the search space and pass. Named subjects, since a count passes on the
    wrong set."""
    defined = {fn.name for _, fn in _functions()}
    missing = RENDERERS - defined
    assert not missing, f"these renderers no longer exist, so the sweep covers nothing: {missing}"
    emitters = {f"{p.name}:{fn.name}" for p, fn in _functions() if _emits_html(fn)}
    assert len(emitters) >= 4, f"too few HTML emitters found, sweep is empty: {emitters}"
    # The inline case must be in the set, or the detection regressed to renderer names.
    assert any("report.py" in e for e in emitters), sorted(emitters)


def test_no_html_renderer_sits_beside_a_log_query():
    """The invariant. A function that holds log rows and builds HTML in one scope is where an
    attacker-controlled URI or User-Agent reaches a file the user opens in a browser.

    Phrased as absence because there is nothing to defend today, and it fires on the enrichment
    that would create something: adding a URI column to the patrol report means querying for it
    next to the render."""
    offenders = {}
    for path, fn in _functions():
        if not _emits_html(fn):
            continue
        queries = _calls_in_own_scope(fn, LOG_CALLS)
        key = f"{path.name}:{fn.name}"
        if queries and key not in DECLARED:
            offenders[key] = sorted(queries)
    assert not offenders, (
        f"these build HTML in the same scope as a log query, so log-derived text can reach the "
        f"rendered file: {offenders}. Either move the query out of that scope, or escape at the "
        f"renderer and add the function to DECLARED with the reason it is safe.")


def test_the_declared_exception_still_exists_and_is_still_the_only_one():
    """`DECLARED` is the shape `BACKFILL_FLOOR` and `PRODUCERS` use: an exemption that has to be
    proved and cannot widen quietly. It fails once nothing needs excusing, so a cleanup that moves
    the query out of `generate_weekly_report` deletes the entry rather than leaving it to rot."""
    both = {f"{p.name}:{fn.name}" for p, fn in _functions()
            if _emits_html(fn) and _calls_in_own_scope(fn, LOG_CALLS)}
    assert both == DECLARED, {
        "declared but no longer holds both, so delete the entry": sorted(DECLARED - both),
        "holds both and is not declared": sorted(both - DECLARED)}


@pytest.mark.parametrize("renderer", sorted(RENDERERS))
def test_a_renderer_does_not_query_logs_itself(renderer):
    """The other direction, which the caller-side check cannot see: a renderer that fetches its own
    data needs no caller to hand it any."""
    for path, fn in _functions():
        if fn.name == renderer:
            assert not _calls_in_own_scope(fn, LOG_CALLS), \
                f"{path.name}:{renderer} queries logs itself"


def test_review_deep_escapes_what_it_renders():
    """The one renderer that DOES take free text escapes it, and that is worth pinning rather than
    assuming, because it is the precedent the other two would copy if they ever need to."""
    src = (TOOLS / "waf_review_deep.py").read_text()
    # **The html MODULE's escape, not any function called escape.** The first version fell back to
    # `"escape(" in src`, which would pass on a local helper of that name doing nothing, and it is
    # the fallback that was actually matching: this module imports html as `html_mod`.
    assert "html_mod.escape(" in src or "html.escape(" in src, \
        "waf_review_deep no longer escapes the markdown it renders with the html module"
    # **Every append of the source line, not a count of escape calls.** A count bound tolerates
    # losing one: dropping escaping from the plain-line branch left the other calls in place and a
    # `>= 4` assertion passed. Each markdown case is its own append, so the property is per append.
    unescaped = [ln.strip() for ln in src.splitlines()
                 if "html_lines.append(" in ln and re.search(r"\bline\b", ln)
                 and "escape(" not in ln]
    assert not unescaped, (
        f"these render the source line into HTML without escaping it: {unescaped}")
