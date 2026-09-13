// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
import { marked } from 'marked';
import DOMPurify from 'dompurify';

// Agent output routinely quotes attacker-controlled log content: User-Agents, URIs, request bodies
// that a WAF rule matched. The result is injected into the main origin, which is where the Cognito
// tokens live, and marked does not sanitize.
//
// **The order of the two calls is the property, not the presence of both.** marked has to run
// first. DOMPurify parses HTML, so handed `[x](javascript:alert(1))` it sees text carrying no
// markup and returns it untouched; marked then renders that into `<a href="javascript:alert(1)">`
// and nothing sanitizes it afterwards. Swapping the two reads as equivalent and is a one-token
// edit. `render.test.js` is what makes the order fail rather than the pair, and
// `tests/test_frontend_sanitizer.py` is what keeps this the only way agent text becomes HTML.
export function renderMarkdown(content) {
  return DOMPurify.sanitize(marked.parse(content || '', { breaks: true }));
}
