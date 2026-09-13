#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break each reachability property `test_frontend_sanitizer.py` claims and require it to notice.

That file guards the inventory of paths from agent text to the live document. Every one of those
paths deploys and renders perfectly when it is wrong, which is the shape where only a perturbation
tells you whether the assertion is doing anything.

Every target reads the source as text, so no case asks for the reachability probe.

**Three cases perturb the test file itself rather than the frontend, and that is the interesting
third.** The absence claims are made over comment-stripped sources, so the stripper decides the
search space: stop tracking quote state and a `//` inside `config.js`'s repository URL eats the rest
of that line; stop preserving newlines inside a block comment and `agent.js` loses four lines. Both
leave a smaller file that satisfies every absence claim, which is the same collapse as a glob that
matched nothing. The third removes a file from the declared set, which is how a new render site ends
up outside every sweep while the suite stays green.

**The pair aimed at the preview iframe is the one to read.** `allow-same-origin` beside
`allow-scripts` is one token added to a string, it deploys, the preview looks identical, and the
framed document can then drop its own sandbox. Removing the attribute entirely is caught by the other
assertion in that test, so neither can hide behind the other.
"""

import sys

from _harness import sweep

T = "tests/test_frontend_sanitizer.py"
A = "frontend/src/App.jsx"
R = "frontend/src/render.js"
G = "frontend/src/agent.js"

SINK = '<div className="content markdown" dangerouslySetInnerHTML={{ __html: rendered }} />'

CASES = [
    ("a second render site beside the one that is allowed",
     [(A, SINK, SINK + '\n      <div dangerouslySetInnerHTML={{ __html: content }} />')],
     [f"{T}::test_agent_text_reaches_the_document_through_exactly_one_expression"]),

    ("the one site fed the raw agent text instead of the rendered output",
     [(A, "__html: rendered }}", "__html: content }}")],
     [f"{T}::test_agent_text_reaches_the_document_through_exactly_one_expression"]),

    ("a direct innerHTML write, which React is not in the path of",
     [(A, "  function copyMarkdown() {\n",
       "  function copyMarkdown() {\n    document.body.innerHTML = content;\n")],
     [f"{T}::test_agent_text_reaches_the_document_through_exactly_one_expression"]),

    ("a second definition of renderMarkdown, so the tested one is not the rendering one",
     [(A, "function generateSessionId() {",
       "function renderMarkdown(c) { return c; }\n\nfunction generateSessionId() {")],
     [f"{T}::test_the_render_function_has_one_definition_and_one_composition"]),

    ("markdown parsed in a second module, so there are two sanitizers to keep correct",
     [(G, "  if (!config.sessionsApiUrl) return;",
       "  marked.parse(String(targetSessionId));\n  if (!config.sessionsApiUrl) return;")],
     [f"{T}::test_the_render_function_has_one_definition_and_one_composition"]),

    ("the export dropped, so the behavioural suite cannot reach the function",
     [(R, "export function renderMarkdown(", "function renderMarkdown(")],
     [f"{T}::test_the_render_function_has_one_definition_and_one_composition"]),

    ("the caller importing from a copy rather than from the module under test",
     [(A, "from './render'", "from './sanitize'")],
     [f"{T}::test_the_render_function_has_one_definition_and_one_composition"]),

    ("allow-same-origin beside allow-scripts, which lets the framed report drop its own sandbox",
     [(A, 'sandbox="allow-scripts"', 'sandbox="allow-scripts allow-same-origin"')],
     [f"{T}::test_the_report_preview_cannot_reach_this_origin"]),

    ("the sandbox attribute gone altogether, which the other assertion in that test owns",
     [(A, ' sandbox="allow-scripts"', "")],
     [f"{T}::test_the_report_preview_cannot_reach_this_origin"]),

    ("one generated file navigated to rather than downloaded, in this origin",
     [(A, "a.download = 'waf-agent-response.html'; ", "")],
     [f"{T}::test_every_generated_file_is_downloaded_rather_than_navigated_to"]),

    ("a test payload sitting in application code, where the sweeps exclude nothing",
     [(A, "  const prompt = prompts[type] || prompts.roi;",
       "  const fallback = 'javascript:alert(1)';\n"
       "  const prompt = prompts[type] || prompts.roi;")],
     [f"{T}::test_the_dangerous_payloads_live_only_in_the_behavioural_corpus"]),

    ("a frontend source outside the declared set, so it sits outside every sweep",
     [(T, '    "config.js": "waf-analysis-with-agentcore\'",\n', "")],
     [f"{T}::test_the_sweep_reads_the_whole_frontend"]),

    ("the comment stripper stops tracking quote state, so a URL in a string reads as a comment",
     [(T, "elif ch in \"'\\\"`\":", "elif False:")],
     [f"{T}::test_the_sweep_reads_the_whole_frontend"]),

    ("block comments stripped without their newlines, so a file quietly loses four lines",
     [(T, 'out.append("\\n" * text.count("\\n", i, end))', 'out.append("")')],
     [f"{T}::test_the_sweep_reads_the_whole_frontend"]),
]

sys.exit(sweep(CASES))
