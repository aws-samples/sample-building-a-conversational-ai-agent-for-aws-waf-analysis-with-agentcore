# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""One extension list, two dialects, and the same answer from both.

ROADMAP 4.5. Twenty copies of an extension alternation had drifted: the Athena copies
anchored with `$`, the CloudWatch copies did not, so `/api/data.json` was excluded as a
static asset on one engine and counted as a request on the other. That is the case the
roadmap item names as the one that must not happen, because a document extension is a real
business request and a real scrape target.

**Python's `re` stands in for two engines here, and what licenses that is a measurement
rather than an assumption.** `design/scripts/measure-uri-suffix-match.py` ran fifteen
constructs against a real CloudWatch log group and a real Athena query on 2026-09-10 --
`$`, `^`, `?`, alternation, `(?i)` and `($|\\?)`, each with a partner case whose expected
count differs -- and both engines matched all fifteen. So the semantic tests below check
what the shipped pattern MEANS, on a third engine that agrees with both on exactly these
constructs, and the pattern they compile is extracted from the shipped constants rather
than retyped.

What `re` cannot stand in for is whether the fragments are valid in their own dialect, so
that is asserted structurally instead, and the measurement script re-runs the shipped
constants against both engines.
"""

import pathlib
import re

import pytest

from tools import static_assets as S

# Extensions whose absence from the list was itself the defect. `jpeg` was in neither the
# CWL nor the Athena copy, and unanchored `\.jpg` does not match `.jpeg`, so JPEG images
# counted as business requests on both engines for the life of the old list. Named here
# because the sweep below covers whatever the list happens to contain: remove `jpeg` and
# every other test in this file still passes.
MUST_EXCLUDE = {"js", "css", "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2"}

# The roadmap's explicit non-goal, and the direction that shipped broken. Documents and
# markup stay in the analysis.
MUST_KEEP = ("json", "php", "html", "htm", "pdf", "xml", "txt", "csv", "xlsx", "zip",
             "doc", "docx", "aspx", "jsp")


@pytest.fixture(scope="module")
def pattern() -> re.Pattern:
    """The shipped pattern, lifted out of the CWL fragment and compiled.

    Extracted rather than retyped, because a retyped copy is a third definition and this
    file exists to assert there are not three."""
    body = re.fullmatch(r" and httpRequest\.uri not like /(.+)/", S.CWL_EXCLUDE_STATIC)
    assert body, f"the CWL fragment no longer has the shape this file reads: {S.CWL_EXCLUDE_STATIC!r}"
    return re.compile(body.group(1))


def _alternation(fragment: str) -> list[str]:
    """The extension list as it appears inside a rendered fragment."""
    found = re.search(r"\\\.\((.+?)\)\(\$\|\\\?\)", fragment)
    assert found, f"no extension alternation found in {fragment!r}"
    return found.group(1).split("|")


# --- one definition ---------------------------------------------------------


def test_both_dialects_render_the_same_extension_list():
    """The whole point of the item. Twenty hand-maintained copies is how the two engines
    came to disagree, so the invariant is not "the list is correct" but "there is one"."""
    assert _alternation(S.CWL_EXCLUDE_STATIC) == sorted(S.STATIC_ASSET_EXTENSIONS)
    assert _alternation(S.ATHENA_EXCLUDE_STATIC) == sorted(S.STATIC_ASSET_EXTENSIONS)


def test_each_fragment_is_written_in_its_own_dialect():
    """Cheap, and it catches the one mistake every other test here is blind to: a fragment
    carrying the other engine's syntax still contains the right extension list and still
    compiles under `re`, so nothing else in this file would notice."""
    assert S.CWL_EXCLUDE_STATIC.startswith(" and httpRequest.uri not like /")
    assert "regexp_like" not in S.CWL_EXCLUDE_STATIC
    assert "NOT regexp_like(httprequest.uri, '" in S.ATHENA_EXCLUDE_STATIC
    assert "not like" not in S.ATHENA_EXCLUDE_STATIC
    # Both append to a WHERE or a filter that already has a condition, which is why each
    # carries a leading conjunction. A fragment that lost it would produce
    # `WHERE NOT regexp_like(...)` spliced straight onto the previous predicate.
    assert S.CWL_EXCLUDE_STATIC.startswith(" and ")
    assert S.ATHENA_EXCLUDE_STATIC.startswith(" AND ")


def test_the_extension_list_is_a_set_of_bare_extensions():
    """No dot, no dedup needed, no regex metacharacter smuggled into an entry. An entry
    like `woff2?` was in the old list and works, but it makes the list stop being a list:
    the alternation no longer enumerates what it excludes, and a reader counting entries
    gets the wrong answer."""
    assert S.STATIC_ASSET_EXTENSIONS, "empty list, so every sweep below is vacuous"
    assert len(set(S.STATIC_ASSET_EXTENSIONS)) == len(S.STATIC_ASSET_EXTENSIONS), \
        "duplicate extension"
    for ext in S.STATIC_ASSET_EXTENSIONS:
        assert re.fullmatch(r"[a-z0-9]+", ext), ext


def test_the_extensions_the_old_list_got_wrong_are_present():
    """`jpeg` is the one that was simply missing. The rest are the old list, restated so a
    consolidation cannot quietly drop one while the sweeps below stay green: they sweep
    whatever the list contains."""
    assert MUST_EXCLUDE <= set(S.STATIC_ASSET_EXTENSIONS), \
        MUST_EXCLUDE - set(S.STATIC_ASSET_EXTENSIONS)


# --- what it means ----------------------------------------------------------


@pytest.mark.parametrize("ext", sorted(S.STATIC_ASSET_EXTENSIONS))
def test_every_listed_extension_is_excluded_at_the_end_of_a_path(pattern, ext):
    assert pattern.search(f"/assets/thing.{ext}"), ext


@pytest.mark.parametrize("ext", sorted(S.STATIC_ASSET_EXTENSIONS))
def test_every_listed_extension_is_excluded_before_a_query_string(pattern, ext):
    """The cache-busting form. On a table this agent built the branch is unreachable,
    since WAF splits the query string into `httpRequest.args`; it is here for a
    bring-your-own table whose `uri` came from a request line instead."""
    assert pattern.search(f"/assets/thing.{ext}?v=2"), ext


@pytest.mark.parametrize("ext", sorted(S.STATIC_ASSET_EXTENSIONS))
def test_a_listed_extension_mid_path_is_not_excluded(pattern, ext):
    """The anchor, from the other side. `\\.js` unanchored matched `/x.js/download` and
    `/api/data.jsonl` alike, which is how the CloudWatch half came to drop real traffic."""
    assert not pattern.search(f"/x.{ext}/download"), ext
    assert not pattern.search(f"/x.{ext}extra"), ext


@pytest.mark.parametrize("ext", MUST_KEEP)
def test_document_and_markup_extensions_stay_in_the_analysis(pattern, ext):
    """ROADMAP 4.5 in one assertion, and the defect that shipped: `.json` contains `.js`,
    so the unanchored CloudWatch copy excluded every JSON API call."""
    assert not pattern.search(f"/api/data.{ext}"), ext


def test_the_json_over_match_specifically(pattern):
    """Named on its own because it is the observed failure rather than a class member. The
    pattern must not match, and `.js` on the same path must, or this proves nothing."""
    assert not pattern.search("/api/data.json")
    assert pattern.search("/api/data.js")


def test_an_uppercase_extension_is_still_a_static_asset(pattern):
    """Both engines are case-sensitive by default, measured. Without `(?i)`, `/IMG_1.PNG`
    reads as a business request and inflates the unique-URI count that the crawler and
    repeater queries treat as the bot signal."""
    assert pattern.search("/media/IMG_1.PNG")
    assert pattern.search("/media/Logo.SvG")
    assert not pattern.search("/api/DATA.JSON")


def test_a_path_with_no_extension_is_not_excluded(pattern):
    assert not pattern.search("/api/products")
    assert not pattern.search("/")


def test_a_row_with_no_uri_survives_the_athena_fragment():
    """The divergence that would have outlived this change. `NOT regexp_like(NULL, ...)` is
    NULL, so Athena drops a row with a missing `uri` while CloudWatch's `not like` keeps it,
    and on a bring-your-own or user-converted table that row is a real request. Structural
    because SQL semantics cannot be evaluated here; the engine half is in
    `design/scripts/measure-uri-suffix-match.py`, which runs the shipped fragment over a
    synthesised NULL row.

    The CloudWatch side is asserted as an ABSENCE on purpose. Adding `ispresent(...)` there
    would buy parity in the wrong direction, by teaching the engine that already behaves
    correctly to drop the row too."""
    assert "httprequest.uri IS NULL OR NOT regexp_like" in S.ATHENA_EXCLUDE_STATIC
    assert "ispresent" not in S.CWL_EXCLUDE_STATIC

    # The guard has to be parenthesised as a unit, because `OR` binds looser than the `AND`
    # every call site appends this to. Counted rather than pattern-matched: the fragment's
    # own parentheses must balance and must wrap the whole disjunction, so the first `(`
    # after `AND ` has to close at the very end.
    body = S.ATHENA_EXCLUDE_STATIC[len(" AND "):]
    assert body.startswith("(") and body.endswith(")"), S.ATHENA_EXCLUDE_STATIC
    depth = 0
    for i, char in enumerate(body):
        depth += (char == "(") - (char == ")")
        assert depth > 0 or i == len(body) - 1, \
            f"the guard's parentheses close early, so OR leaks: {S.ATHENA_EXCLUDE_STATIC}"
    assert depth == 0, "unbalanced parentheses"


# --- the call sites ---------------------------------------------------------


def test_every_template_that_excludes_on_one_engine_excludes_on_the_other():
    """The pairing invariant, on the dict where both dialects sit side by side. Equal
    counts per file would not catch this: one template could carry two CWL exclusions and
    another none, and the file totals would still match."""
    from tools.waf_logs import TEMPLATES
    excluding = [name for name, t in TEMPLATES.items()
                 if S.CWL_EXCLUDE_STATIC in t["query"]
                 or S.ATHENA_EXCLUDE_STATIC in t["athena"]]
    assert excluding, "no template excludes static assets, so this proves nothing"
    for name in excluding:
        t = TEMPLATES[name]
        assert S.CWL_EXCLUDE_STATIC in t["query"], f"{name}: CWL half missing"
        assert S.ATHENA_EXCLUDE_STATIC in t["athena"], f"{name}: Athena half missing"


@pytest.fixture
def captured(monkeypatch):
    """Every (cwl, athena) pair a bypass step hands to the query layer.

    Patched at `_safe_query` rather than at `query_logs`, because the pair is what the
    caller composed and that is the thing under test. Returns no rows, which every step
    handles as its "none found" path."""
    pairs: list[tuple[str, str]] = []
    from tools import waf_bypass as B

    def capture(cwl, athena, *a, **k):
        pairs.append((cwl, athena))
        return []
    monkeypatch.setattr(B, "_safe_query", capture)
    monkeypatch.setattr(B, "_check_coverage_gaps", lambda: [])
    monkeypatch.setattr(B, "get_client", lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("no AWS in tests")))
    monkeypatch.setattr(B, "get_webacl_name", lambda: "acl")
    monkeypatch.setattr(B, "get_scope", lambda: "CLOUDFRONT")
    monkeypatch.setattr(B, "resolve_region", lambda scope: "us-east-1")
    monkeypatch.setattr(B, "is_log_filter_active", lambda: False)
    return pairs, B


@pytest.mark.parametrize("step", ["scan", "ja4_ips", "investigate_ip"])
def test_a_bypass_step_never_excludes_on_one_engine_only(captured, step):
    """The same pairing invariant on the three bypass steps that filter static assets,
    driven through the real functions so a pair that never reaches the query layer cannot
    satisfy it."""
    pairs, B = captured
    if step == "scan":
        B._step_scan(0, 3600)
    elif step == "ja4_ips":
        B._step_ja4_ips("t13d1516h2", 0, 3600)
    else:
        B._step_investigate_ip("203.0.113.9", 0, 3600)
    assert pairs, f"step {step} issued no queries, so this proves nothing"
    excluding = [(c, a) for c, a in pairs
                 if S.CWL_EXCLUDE_STATIC in c or S.ATHENA_EXCLUDE_STATIC in a]
    assert excluding, f"step {step} excludes static assets nowhere, so this proves nothing"
    for cwl, athena in excluding:
        assert S.CWL_EXCLUDE_STATIC in cwl, f"Athena half only: {athena}"
        assert S.ATHENA_EXCLUDE_STATIC in athena, f"CWL half only: {cwl}"


def test_no_module_still_carries_a_hand_written_extension_list():
    """A sweep, because twenty copies is what this item was opened to remove and a
    twenty-first would reintroduce the drift silently.

    Matches on the shape rather than the old text: any `\\.(` followed by an alternation of
    bare extensions, anywhere in `tools/`, outside the module that owns it. The old literal
    would also be caught by searching for `woff2?`, but that only catches a copy of THIS
    list, not the next one someone writes for video files."""
    tools = pathlib.Path(__file__).resolve().parents[1] / "tools"
    files = sorted(p for p in tools.glob("*.py") if p.name != "static_assets.py")
    # Name the subjects rather than counting the files: these two are where the twenty
    # copies lived, so a glob that misses either has not searched what the claim covers.
    assert {"waf_bypass.py", "waf_logs.py"} <= {p.name for p in files}, \
        sorted(p.name for p in files)
    # Length-independent on purpose. The first version bounded each arm to five characters
    # and `woff2?`, which is six, walked straight through it: the perturbation that pastes
    # the OLD list back into this file came back green. So the shape is "a dot, a group, at
    # least one pipe inside it" and nothing about how long the arms are.
    hand_written = re.compile(r"\\\.\([a-z0-9?|]*\|[a-z0-9?|]*\)")
    offenders = [f"{p.name}:{n}" for p in files
                 for n, line in enumerate(p.read_text().splitlines(), 1)
                 if hand_written.search(line)]
    assert not offenders, offenders
