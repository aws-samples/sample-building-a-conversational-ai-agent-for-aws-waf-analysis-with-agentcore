#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Break what `frontend/src/render.test.js` claims about `renderMarkdown` and require it to notice.

The only script here that runs vitest rather than pytest, via `run=vitest`. Every case asks for the
reachability probe, because these targets execute the code rather than reading it, and because a new
engine's probe form is itself worth proving: the JS probe is `throw new Error(...)` where the Python
one is `raise`.

**The first case is the reason this file exists.** Swapping the two calls is one token, it deploys, it
renders identically, and it removes the sanitizing entirely for anything markdown builds rather than
copies. Measured: the swap turns four of the nine cases red, and `a raw script tag does not survive`
is not one of them. The payload a reader reaches for first is the one with no power to tell the two
orders apart.

**Five cases perturb the test file's own detector, and they are the ones that would otherwise be
missed.** Every security case in that file asserts the detector found nothing, so a detector that
finds nothing turns the whole suite green while reporting success. One case per branch, matching one
expectation per branch in the positive control, because a blinded branch is invisible from anywhere
else.
"""

import sys

from _harness import sweep, vitest

R = "frontend/src/render.js"
V = "frontend/src/render.test.js"

COMPOSE = "  return DOMPurify.sanitize(marked.parse(content || '', { breaks: true }));"
SWAP = "  return marked.parse(DOMPurify.sanitize(content || ''), { breaks: true });"

TAGS = "    if (tag === 'script' || tag === 'iframe' || tag === 'object' || tag === 'embed') {"
HANDLERS = r"      if (/^on/i.test(attr.name)) findings.push(`${tag}[${attr.name}]`);"
SCHEMES = r"      if (/^(javascript|vbscript):/i.test(value) || /^data:(?!image\/)/i.test(value)) {"


def _t(title):
    return f"{V}::{title}"


CASES = [
    ("the composition order swapped, so DOMPurify sees markdown and marked builds the element after",
     [(R, COMPOSE, SWAP)],
     [_t("a javascript URL built by markdown does not survive")], True),

    # Same edit, separate case, so each of the two URL schemes is individually proven rather than one
    # of them carrying the other.
    ("the composition order swapped, measured against the data: scheme",
     [(R, COMPOSE, SWAP)],
     [_t("a data document URL built by markdown does not survive")], True),

    ("DOMPurify dropped, so marked's output reaches the document raw",
     [(R, COMPOSE, "  return marked.parse(content || '', { breaks: true });")],
     [_t("an inline event handler does not survive")], True),

    ("DOMPurify dropped, measured against the payload that survives either order",
     [(R, COMPOSE, "  return marked.parse(content || '', { breaks: true });")],
     [_t("a raw script tag does not survive")], True),

    ("event handlers added back to the allow list, which is the plausible configuration mistake",
     [(R, COMPOSE,
       "  return DOMPurify.sanitize(marked.parse(content || '', { breaks: true }), "
       "{ ADD_ATTR: ['onerror', 'onmouseover'] });")],
     [_t("an inline event handler does not survive")], True),

    # The capability direction. A sanitizer that renders nothing passes every security case here.
    ("marked dropped, so the agent's tables arrive as plain text",
     [(R, COMPOSE, "  return DOMPurify.sanitize(String(content || ''));")],
     [_t("a markdown table still renders as a table")], True),

    ("marked dropped, measured against an ordinary link",
     [(R, COMPOSE, "  return DOMPurify.sanitize(String(content || ''));")],
     [_t("an ordinary https link keeps its href")], True),

    ("marked dropped, measured against a payload the report has to quote back",
     [(R, COMPOSE, "  return DOMPurify.sanitize(String(content || ''));")],
     [_t("a payload shown as text stays visible and inert")], True),

    ("breaks dropped, so one finding per line runs together in the rendered answer",
     [(R, COMPOSE, "  return DOMPurify.sanitize(marked.parse(content || ''));")],
     [_t("a single newline still becomes a line break")], True),

    ("the detector blinded outright, which would make every security case here pass",
     [(V, "  const findings = [];", "  const findings = [];\n  return findings;")],
     [_t("the detector can find something, and the DOM it needs is here")], True),

    ("the handler branch removed from the detector",
     [(V, HANDLERS, "      if (false) findings.push(tag);")],
     [_t("the detector can find something, and the DOM it needs is here")], True),

    ("the script and iframe branch removed from the detector",
     [(V, TAGS, "    if (false) {")],
     [_t("the detector can find something, and the DOM it needs is here")], True),

    ("the data: branch removed, leaving only javascript: detected",
     [(V, SCHEMES, "      if (/^(javascript|vbscript):/i.test(value)) {")],
     [_t("the detector can find something, and the DOM it needs is here")], True),

    # The other direction on the same branch: over-reporting is a false-positive generator inside the
    # one place a trustworthy signal matters, and an inlined chart is how it would show up.
    ("the image exemption dropped, so a benign data URI reads as an attack",
     [(V, SCHEMES,
       r"      if (/^(javascript|vbscript):/i.test(value) || /^data:/i.test(value)) {")],
     [_t("the detector can find something, and the DOM it needs is here")], True),
]

sys.exit(sweep(CASES, run=vitest))
