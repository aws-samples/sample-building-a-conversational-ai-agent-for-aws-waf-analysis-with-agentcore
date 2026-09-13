# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 5.4, frontend half: every path from agent text to the live DOM, and only one of them renders.

Agent output quotes attacker-controlled log content by design: User-Agents, URIs, request bodies a
rule matched. It is rendered into the main origin, which is the origin holding the Cognito tokens, and
marked does not sanitize. `frontend/src/render.js` is the one function that turns that text into HTML.

**This file holds reachability, not correctness.** Whether `renderMarkdown` actually strips a
`javascript:` URL is a behavioural question, and it is answered in `frontend/src/render.test.js` by
running the function. What no behavioural test can answer is whether the function is still the only
way in: a second render site added later bypasses the tested function while every test stays green.
That is the shape where an assertion is aimed one layer away from the thing that decides, so the two
halves are split on purpose and neither is sufficient.

**Why this is Python rather than a lint rule in the JS suite.** `tests/test_no_log_data_reaches_html.py`
is the repo's existing "no log data reaches HTML" check and it `ast.parse`s `tools/*.py`. Its corpus
structurally cannot contain a `.jsx` file, so the frontend was never inside the search space of the
check whose name says it covers this. Adding it here puts it in the suite that already runs on every
push, and it needs no JS toolchain, so the reachability guard held below does not wait on vitest.

## What is not covered, stated rather than implied

The three blob downloads build HTML too, and their content is either `renderMarkdown` output or our
own generated report. They are excluded from the sink inventory because they download rather than
navigate, and the one property that keeps that true is asserted: an anchor that calls `.click()`
without `download` navigates to a `blob:` URL **in this origin**, at which point its scripts run here.

Argument-level dataflow is not traced. Passing a URI into `webacl_results` and rendering that server
side is a different item, recorded as the residual in ROADMAP 5.3.
"""

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "frontend/src"

# The whole search space, with a token that must survive comment stripping for each file. Named
# subjects rather than a count, and the token sits at or near the END of each file on purpose: the
# realistic bug in `_code()` below is a mistracked quote that swallows the rest of a file, and a
# swallowed file satisfies every absence claim here perfectly.
MARKERS = {
    "App.jsx": "'...' : '→'",
    "agent.js": "'DELETE'",
    "auth.js": "changePassword(oldPassword, newPassword)",
    # Deliberately the tail of the repository URL, which sits AFTER a `//` inside a string literal.
    # A stripper that stops tracking quote state reads that as a comment start and eats the rest of
    # the line, and no other marker here would notice.
    "config.js": "waf-analysis-with-agentcore'",
    "main.jsx": "ReactDOM.createRoot(",
    "render.js": "DOMPurify.sanitize(marked.parse(",
}

# `render.test.js` is the behavioural corpus and has to quote `<script>`, `javascript:` and an
# `onerror=` handler verbatim in order to feed them to the function. Same exclusion shape as
# `test_partition_timezone_claim.py`: one named file, with the reason, rather than a directory.
CORPUS = "render.test.js"

# Sinks that put a string into the live document. Written with the leading dot so `.innerHTML` cannot
# match inside `dangerouslySetInnerHTML`, which is the one sink that is allowed and is counted
# separately below.
DOM_SINKS = (".innerHTML", ".outerHTML", ".insertAdjacentHTML(", "document.write(")


def _code(text: str) -> str:
    """`text` with JS comments removed and line count preserved.

    **A substring check over a whole file is the defect this project keeps producing**, and it has
    both directions here. `"DOMPurify.sanitize(" not in other_file` goes red the moment a comment in
    that file explains the sanitizer, and `"DOMPurify.sanitize(" in render_js` passes on a file whose
    only mention is in a comment. Stripping first removes both.

    Quote state is tracked so a `//` inside a string literal is not read as a comment start, which
    `config.js` needs for the repository URL it ships. Newlines inside a block comment are kept so
    the line count is an invariant, which is what `test_the_sweep_reads_the_whole_frontend` checks."""
    out, i, n, quote = [], 0, len(text), None
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
        elif ch in "'\"`":
            quote = ch
            out.append(ch)
            i += 1
        elif ch == "/" and text[i:i + 2] == "//":
            while i < n and text[i] != "\n":
                i += 1
        elif ch == "/" and text[i:i + 2] == "/*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("\n" * text.count("\n", i, end))
            i = end
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _sources() -> dict[str, str]:
    """Every swept file, comment-stripped, keyed by name."""
    return {name: _code((SRC / name).read_text()) for name in MARKERS}


def test_the_sweep_reads_the_whole_frontend():
    """The precondition, and every assertion below depends on it. A glob that missed a file, or a
    comment stripper that ate one, satisfies each absence claim by having nothing left to object to.

    Three separate ways the search space can collapse, so three checks: the file set on disk must be
    exactly the declared one, each file's end marker must survive stripping, and stripping must not
    change any file's line count."""
    on_disk = {p.name for p in SRC.iterdir()
               if p.suffix in (".js", ".jsx") and p.name != CORPUS}
    assert on_disk == set(MARKERS), (
        f"the declared file set and the one on disk differ: only on disk {sorted(on_disk - set(MARKERS))}, "
        f"only declared {sorted(set(MARKERS) - on_disk)}. A new frontend source needs an entry in "
        f"MARKERS, or it sits outside every check in this file while looking covered.")
    for name, marker in MARKERS.items():
        raw = (SRC / name).read_text()
        stripped = _code(raw)
        assert marker in stripped, (
            f"{name}: {marker!r} did not survive comment stripping, so _code() ate real code and "
            f"every absence claim below is being made against a file with a hole in it")
        assert stripped.count("\n") == raw.count("\n"), (
            f"{name}: stripping changed the line count from {raw.count(chr(10))} to "
            f"{stripped.count(chr(10))}")


def test_agent_text_reaches_the_document_through_exactly_one_expression():
    """The reachability property. Not "the sanitizer works" but "there is nowhere else to go".

    Both halves fail differently and both are needed. The count pins that a second render site cannot
    appear; reading the expression pins that the one site still goes through the function the
    behavioural tests exercise. Either alone leaves the other free."""
    sources = _sources()
    sites = [(name, m) for name, src in sources.items()
             for m in re.finditer(r"dangerouslySetInnerHTML=\{\{\s*__html:\s*([^}]+?)\s*\}\}", src)]
    assert len(sites) == 1, (
        f"expected one dangerouslySetInnerHTML site, found {[(n, m.group(1)) for n, m in sites]}. Each "
        f"one is a separate path from agent text into this origin, so a second needs its own "
        f"assertion here rather than inheriting this one.")
    name, match = sites[0]
    expr = match.group(1).strip()
    if not expr.startswith("renderMarkdown("):
        assert re.fullmatch(r"\w+", expr), (
            f"{name} renders {expr!r}, which is neither a renderMarkdown call nor a plain name, so "
            f"what reaches the DOM cannot be read off the source. Bind it to a name first.")
        assert re.search(rf"\b(?:const|let|var)\s+{re.escape(expr)}\s*=\s*renderMarkdown\(",
                         sources[name]), (
            f"{name} renders {expr!r} and nothing in that file binds it from renderMarkdown(), so "
            f"unsanitized text can reach the DOM through the one site this file allows")

    for name, src in sources.items():
        found = [sink for sink in DOM_SINKS if sink in src]
        assert not found, (
            f"{name} writes to the document through {found}, which bypasses renderMarkdown entirely. "
            f"React is not in that path, so nothing else in the frontend guards it.")


def test_the_render_function_has_one_definition_and_one_composition():
    """The other end of the same property. A second copy of the composition is how the order gets
    swapped in one place and stays right in the other, and the behavioural suite would still pass
    because it imports the module rather than the copy."""
    sources = _sources()
    definitions = {name for name, src in sources.items()
                   if re.search(r"function\s+renderMarkdown\s*\(", src)}
    assert definitions == {"render.js"}, (
        f"renderMarkdown is defined in {sorted(definitions)}. render.test.js exercises the one in "
        f"render.js, so any other copy is unguarded.")
    assert "export function renderMarkdown(" in sources["render.js"], \
        "renderMarkdown is no longer exported, so the behavioural suite cannot reach it"

    for library in ("marked.parse(", "DOMPurify.sanitize("):
        elsewhere = sorted(name for name, src in sources.items()
                           if name != "render.js" and library in src)
        assert not elsewhere, (
            f"{library} is called in {elsewhere} as well as render.js. Markdown becoming HTML "
            f"anywhere else is a second sanitizer to keep correct.")

    callers = sorted(name for name, src in sources.items()
                     if name != "render.js" and "renderMarkdown(" in src)
    assert callers, "nothing calls renderMarkdown, so the frontend renders nothing and this is vacuous"
    for name in callers:
        assert re.search(r"import\s*\{[^}]*\brenderMarkdown\b[^}]*\}\s*from\s*'\./render'",
                         sources[name]), \
            f"{name} calls renderMarkdown without importing it from './render'"


def test_the_report_preview_cannot_reach_this_origin():
    """The sink that is deliberately handed unsanitized HTML. The report preview shows what the agent
    generated, markup and all, and what makes that acceptable is the iframe being a foreign origin.

    `allow-scripts` together with `allow-same-origin` is documented as letting the framed document
    remove its own sandbox attribute, so the pair is the assertion rather than either flag alone. One
    token added to a string turns the preview into script execution in the origin holding the tokens."""
    frames = [(name, m) for name, src in _sources().items()
              for m in re.finditer(r"<iframe\b([^>]*)>", src)]
    assert frames, "no iframe found, so this test proves nothing; delete it if the preview is gone"
    for name, match in frames:
        attrs = match.group(1)
        sandbox = re.search(r"sandbox=\"([^\"]*)\"", attrs)
        assert sandbox, f"{name} has an iframe with no sandbox attribute: {attrs.strip()!r}"
        flags = set(sandbox.group(1).split())
        assert not {"allow-scripts", "allow-same-origin"} <= flags, (
            f"{name}: the preview iframe has both allow-scripts and allow-same-origin, so the "
            f"unsanitized report HTML runs in this origin and can read the Cognito tokens")


def test_every_generated_file_is_downloaded_rather_than_navigated_to():
    """Why the blob paths are outside the sink inventory above, asserted instead of argued.

    `URL.createObjectURL` mints a URL that inherits this origin. An anchor with `download` saves the
    file; the same anchor without it navigates, and the generated HTML then executes here. One of the
    four sites builds its blob from the agent's report HTML with no sanitizing at all."""
    clicks = [(name, line.strip()) for name, src in _sources().items()
              for line in src.splitlines() if ".click()" in line]
    assert len(clicks) == 4, f"expected four download sites, found {len(clicks)}: {clicks}"
    for name, line in clicks:
        assert ".download" in line, (
            f"{name} clicks a generated link without setting download: {line!r}. That navigates to a "
            f"blob: URL in this origin instead of saving a file.")


@pytest.mark.parametrize("payload", ["javascript:alert(1)", "<script>", "onerror="])
def test_the_dangerous_payloads_live_only_in_the_behavioural_corpus(payload):
    """A guard on the exclusion rather than on the code. `render.test.js` is excluded from every sweep
    above because it must quote these verbatim, and an exclusion that quietly grows is how a real
    render site ends up outside the search space. So the payloads are required to stay inside it."""
    for name, src in _sources().items():
        assert payload not in src, (
            f"{name} contains {payload!r} outside a comment. If that is a test payload it belongs in "
            f"{CORPUS}, which is the one file excluded from these sweeps.")
