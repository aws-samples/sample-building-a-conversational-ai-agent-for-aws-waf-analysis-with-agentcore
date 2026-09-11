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

# `generate_weekly_report` holds both, and it is the one exception. **Its substance is asserted below
# rather than argued here**, because "traced by hand" has no trigger: the exemption is per function,
# so a fourth `_poll_log_query` whose result is consumed as a string would pass silently while the
# comment told a reader to re-trace and nothing made that happen.
DECLARED = {"report.py:generate_weekly_report"}
# The number of raw-Insights call sites the hand trace covered. A fourth one has to be traced, and
# this is what makes that happen rather than a comment asking for it.
DECLARED_POLL_SITES = 3


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


# --- the declared exemption's substance, asserted rather than argued -----------


def _generate_weekly_report():
    tree = ast.parse((TOOLS / "report.py").read_text())
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef) and fn.name == "generate_weekly_report":
            return fn
    raise AssertionError("generate_weekly_report is gone; the DECLARED exemption is stale")


def test_the_hand_traced_call_sites_are_pinned_by_count():
    """**The trigger the comment did not have.** The exemption covers three `_poll_log_query` sites,
    traced by hand: a row count, two `first`/`last` timestamps, and four `int(float(...))` totals. A
    fourth site is not covered by that trace, and without this the exemption would absorb it.

    A count is the right assertion here for the same reason it is on the rule-filter branches and
    the redactable templates: the claim is about a set whose size is the thing that was verified."""
    fn = _generate_weekly_report()
    sites = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "_poll_log_query"]
    assert len(sites) == DECLARED_POLL_SITES, (
        f"generate_weekly_report now has {len(sites)} raw-Insights call sites, not "
        f"{DECLARED_POLL_SITES}. That path bypasses query_logs, so nothing else in the repo guards "
        f"it. RE-TRACE what the new result is consumed as: if any of it reaches the HTML template "
        f"as free text, it is attacker-controlled and must be escaped at the interpolation.")


# Calls that make a value un-markup-able. A number cannot carry a tag, so a tainted value bound
# through one of these is safe to interpolate; anything else reaching HTML is free text.
NUMERIC = {"int", "float", "len", "round", "abs", "sum"}


def _is_numeric(value) -> bool:
    """Whether this binding expression can only produce a number.

    Both branches of an `IfExp` have to qualify, which is the shape all four ddos totals use:
    `int(float(r.get(...))) if r else 0`."""
    if isinstance(value, ast.IfExp):
        return _is_numeric(value.body) and _is_numeric(value.orelse)
    if isinstance(value, ast.Constant):
        return isinstance(value.value, (int, float)) and not isinstance(value.value, bool)
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return value.func.id in NUMERIC
    return False


def _tainted_names(fn) -> tuple[set, set]:
    """`(names carrying a _poll_log_query result, the subset that can only be numeric)`.

    A small fixpoint rather than a name list, because the interesting case is a value read off the
    result one step later, which is exactly how all three current sites consume theirs.

    **The numeric split is not a loosening, it is the actual property.** The first version asserted
    that no tainted name reaches an HTML interpolation at all, and six do: four ddos totals, a row
    count and `int(event_cnt['cnt'])`. Every one is coerced to an integer, and an integer cannot
    carry markup. Asserting the stricter thing would have been a false claim about the code."""
    tainted, changed = set(), True
    while changed:
        changed = False
        for node in ast.walk(fn):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            refs = {n.func.id for n in ast.walk(value)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            names = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
            if "_poll_log_query" not in refs and not (names & tainted):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name) and n.id not in tainted:
                        tainted.add(n.id)
                        changed = True
    # A name is numeric only if EVERY binding of it is, since one free-text branch is enough.
    numeric = set()
    for name in tainted:
        binds = [n.value for n in ast.walk(fn)
                 if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
        if binds and all(_is_numeric(b) for b in binds):
            numeric.add(name)
    return tainted, numeric


def test_no_raw_insights_value_reaches_an_html_interpolation():
    """**The checkable version of the exemption**, replacing a provenance argument that was not.

    "It comes from `@timestamp` so it cannot carry attacker content" cannot be checked; "nothing
    interpolates it into HTML" can. Reviewer's finding: `ddos_event_first` and `ddos_event_last` are
    assigned at `:554-555`, initialised at `:460-461` and read NOWHERE, which is a stronger property
    than provenance. Verified alongside it that the module contains no `locals()`, `vars()` or
    `.format(**`, so a name cannot reach a template dynamically.

    Those two are therefore dead code. Pre-existing, and left alone rather than removed."""
    fn = _generate_weekly_report()
    tainted, numeric = _tainted_names(fn)
    assert tainted, "no name traced from _poll_log_query, so this proves nothing"
    assert numeric, "no tainted name classified numeric, so the split is not working"
    # **The floor is on the CLASSIFIER, not on the interpolated set.** Pinning which names reach
    # HTML says nothing about whether the numeric split is honest: a classifier returning True for
    # everything empties `leaked` and the assertion below passes by construction. These four are
    # bound from `.get("first")` / `.get("last")`, so they are tainted and are NOT numbers, which is
    # exactly what a permissive classifier would get wrong. Found by the perturbation reporting
    # HOLLOW.
    string_valued = {"event_first", "event_last", "ddos_event_first", "ddos_event_last"}
    assert string_valued <= tainted, sorted(string_valued - tainted)
    assert not (string_valued & numeric), (
        f"the numeric classifier accepted a string-valued name: "
        f"{sorted(string_valued & numeric)}. It is excusing free text.")
    interpolated = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.JoinedStr):
            continue
        literal = "".join(v.value for v in node.values
                          if isinstance(v, ast.Constant) and isinstance(v.value, str))
        if not any(m in literal for m in HTML_MARKERS):
            continue
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                interpolated |= {n.id for n in ast.walk(part) if isinstance(n, ast.Name)}
    leaked = (tainted & interpolated) - numeric
    assert not leaked, (
        f"these carry a raw-Insights result into an HTML interpolation as free text: "
        f"{sorted(leaked)}. That path bypasses query_logs, so nothing else guards it: escape at "
        f"the interpolation, or coerce to a number if that is what it is.")
    # The floor. If the numeric classifier ever passed everything, the assertion above would be
    # satisfied by construction, so what it excuses is pinned.
    assert (tainted & interpolated) == {
        "ddos_high", "ddos_low", "ddos_medium", "ddos_total", "num_events",
        "total_during_event"}, sorted(tainted & interpolated)


def test_no_dynamic_name_can_reach_a_template():
    """The escape hatch that would defeat the check above. `locals()`, `vars()` or `.format(**d)`
    put a value into a template without any name appearing at the interpolation, so the taint walk
    would find nothing to object to."""
    src = (TOOLS / "report.py").read_text()
    for escape in ("locals()", "vars()", ".format(**"):
        assert escape not in src, (
            f"report.py uses {escape}, so a value can reach a template without being named at the "
            f"interpolation and the taint check above no longer covers it")
