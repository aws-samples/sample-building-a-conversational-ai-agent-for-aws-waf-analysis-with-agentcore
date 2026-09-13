// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
//
// ROADMAP 5.4, frontend half: what `renderMarkdown` does, run rather than read.
//
// `tests/test_frontend_sanitizer.py` holds the other half, that this function is the only way agent
// text becomes HTML in the live document. Neither half implies the other: a suite that only ran these
// cases would stay green while a second render site bypassed the function entirely.
//
// **The subject is this application's function, never DOMPurify.** Asserting that DOMPurify strips a
// `<script>` tag tests the library, passes on day one, and keeps passing on a build where the two
// calls are composed in the wrong order. Every case below imports `renderMarkdown` and asserts about
// its output.
//
// **The order of the composition is what most of these cases are really for.** marked has to run
// before DOMPurify. Swapped, DOMPurify is handed markdown carrying no markup, finds nothing to strip,
// and marked then builds the dangerous element afterwards with nothing left to sanitize it. So a raw
// `<script>` payload is the weakest case here, not the strongest: it fails under either order, which
// is why it is one case out of several rather than the headline. The markdown-built URLs are the ones
// that tell the two orders apart, and swapping them is a one-token edit.
//
// **The limit, and it is jsdom.** These cases run against jsdom's HTML parser, not Blink's or
// WebKit's, and DOMPurify's decisions depend on how the markup parsed. So this suite answers whether
// the composition is right and whether the function's contract holds; it does not answer whether a
// particular browser's parser produces markup DOMPurify treats differently. Nothing here is a
// substitute for keeping `dompurify` current, which is what the dependabot bumps are for.
//
// **Phrased as "no executable construct in the output", not "the element was removed".** DOMPurify
// keeps `<a>text</a>` and drops the `href`, so an element-removal assertion would false-fail on a
// DOMPurify update that changed nothing about safety. And the capability side is asserted too: a
// payload shown as text, a table, a normal link. A sanitizer that strips those passes a
// security-only suite and breaks the product.

import { expect, it } from 'vitest';

import { renderMarkdown } from './render';

// What is dangerous, read off the parsed result rather than matched against the string. A regex for
// `\son\w+=` reports `once=1` in ordinary prose as an event handler, and a test that goes red on
// harmless text is a false-positive generator sitting in the one place a trustworthy signal matters.
//
// Parsing is inert: the element is never connected to the document, and jsdom does not execute
// scripts unless asked to.
function attackSurface(html) {
  const host = document.createElement('div');
  host.innerHTML = html;
  const findings = [];
  for (const node of host.querySelectorAll('*')) {
    const tag = node.tagName.toLowerCase();
    if (tag === 'script' || tag === 'iframe' || tag === 'object' || tag === 'embed') {
      findings.push(`<${tag}>`);
    }
    for (const attr of node.attributes) {
      if (/^on/i.test(attr.name)) findings.push(`${tag}[${attr.name}]`);
      // Whitespace and control characters inside a URL are ignored when it is dereferenced,
      // so `java\nscript:alert(1)` names the same scheme. They come out before it is read.
      const value = attr.value.replace(/[\s\u0000-\u001f]/g, '');
      if (/^(javascript|vbscript):/i.test(value) || /^data:(?!image\/)/i.test(value)) {
        findings.push(`${tag}[${attr.name}=${attr.value.slice(0, 48)}]`);
      }
    }
  }
  return findings;
}

it('the detector can find something, and the DOM it needs is here', () => {
  // The positive control, and it carries more weight here than a positive control usually does.
  // Every security case asserts that `attackSurface(...)` is empty, so weakening the detector makes
  // all of them pass. This test is the only thing standing between that and a green suite, which
  // means one expectation per branch: a case that blinds one branch has to fail here.
  //
  // Exact findings rather than "not empty", because a detector that returned one fixed string for
  // everything would satisfy that.
  expect(attackSurface('<img src=x onerror=alert(1)>')).toEqual(['img[onerror]']);
  expect(attackSurface('<a href="javascript:alert(1)">x</a>')).toEqual(['a[href=javascript:alert(1)]']);
  expect(attackSurface('<a href="data:text/html,x">y</a>')).toEqual(['a[href=data:text/html,x]']);
  expect(attackSurface('<script>alert(1)</script>')).toEqual(['<script>']);
  expect(attackSurface('<iframe src="https://example.com"></iframe>')).toEqual(['<iframe>']);
  // And the two it must NOT report. A data URI carrying an image is how a chart would be inlined,
  // and `once=1` in ordinary prose is what a regex over the raw string reports as a handler.
  expect(attackSurface('<img src="data:image/png;base64,iVBORw0KGgo=">')).toEqual([]);
  expect(attackSurface('<p>turn it on, once=1 and done</p>')).toEqual([]);
  // The DOM is asserted rather than assumed, though it cannot fail silently: measured on dompurify
  // 3.4.13, running this file under `--environment node` leaves the default export with no
  // `sanitize` method, so all nine cases error instead of passing on unsanitized output.
  expect(typeof document.createElement).toBe('function');
});

it('a javascript URL built by markdown does not survive', () => {
  // The order discriminator. Composed correctly, marked builds `<a href="javascript:alert(1)">` and
  // DOMPurify drops the attribute. Composed the other way round, DOMPurify sees a line of text with
  // no markup in it, returns it untouched, and marked then builds the same element with nothing
  // downstream to strip it.
  const html = renderMarkdown('[click me](javascript:alert(1))');
  expect(attackSurface(html)).toEqual([]);
  expect(html).toContain('click me');
});

it('a data document URL built by markdown does not survive', () => {
  const payload = 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
  expect(attackSurface(renderMarkdown(`[report](${payload})`))).toEqual([]);
});

it('an inline event handler does not survive', () => {
  expect(attackSurface(renderMarkdown('<img src=x onerror=alert(1)>'))).toEqual([]);
  expect(attackSurface(renderMarkdown('<div onmouseover="alert(1)">hover</div>'))).toEqual([]);
});

it('a raw script tag does not survive', () => {
  // Weakest of the security cases: it fails under either composition order. Kept because it is the
  // payload a reader expects to find, and its absence would read as an oversight.
  expect(attackSurface(renderMarkdown('<script>alert(1)</script>'))).toEqual([]);
  expect(attackSurface(renderMarkdown('<iframe src="https://example.com"></iframe>'))).toEqual([]);
});

it('a payload shown as text stays visible and inert', () => {
  // The capability side, and the case the product actually needs: the agent quotes the matched
  // request back to the user. A sanitizer that deletes the payload leaves a report about an attack
  // with the attack missing.
  const html = renderMarkdown('The blocked request was:\n\n```\n<script>alert(1)</script>\n```\n');
  expect(attackSurface(html)).toEqual([]);
  expect(html).toContain('<pre>');
  expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');

  const inline = renderMarkdown("A URI of `' OR 1=1 --` was matched by the SQLi rule.");
  expect(attackSurface(inline)).toEqual([]);
  expect(inline).toContain('OR 1=1');
});

it('a markdown table still renders as a table', () => {
  const html = renderMarkdown('| Rule | Blocked |\n| --- | --- |\n| SQLi | 42 |\n');
  expect(attackSurface(html)).toEqual([]);
  expect(html).toContain('<table>');
  expect(html).toContain('<th>Rule</th>');
  expect(html).toContain('<td>42</td>');
});

it('an ordinary https link keeps its href', () => {
  const html = renderMarkdown('[the docs](https://example.com/waf?rule=SQLi&page=2)');
  expect(attackSurface(html)).toEqual([]);
  expect(html).toContain('href="https://example.com/waf?rule=SQLi&amp;page=2"');
});

it('a single newline still becomes a line break', () => {
  // `breaks: true` is part of the composition, and dropping it is a silent readability regression
  // rather than a crash: the agent writes one line per finding and they would run together.
  expect(renderMarkdown('first finding\nsecond finding')).toContain('<br>');
});
