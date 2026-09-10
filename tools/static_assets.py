# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Which URIs are static assets, in the two query dialects, from one list.

ROADMAP 4.5. The extension alternation was written out ten times in `waf_bypass.py` and
ten times in `waf_logs.py`, five CWL copies and five Athena copies each, and the two
dialects had drifted apart in a way that changed answers.

**The drift, which is the reason this is not a cosmetic dedup.** The Athena copies
anchored with `$`; the CWL copies did not. An unanchored `\\.(js|...)` matches `.js`
anywhere in the string, so on CloudWatch every `/api/data.json` request was being
excluded as a static asset, while the same request on Athena was counted. ROADMAP 4.5
says in as many words not to exclude document and markup extensions, because they are
real business requests and real scrape targets, and one of the two backends was doing
exactly that. The same trap has shipped inside Amazon at least once, in a servlet filter
whose pattern read `.*.css|.*.js|.*.png`.

`.jpeg` was in neither list. Unanchored `\\.jpg` never matches `.jpeg`, so JPEG images
counted as business requests on both engines. That one was not a drift, just a gap.

**Every construct below was measured on both engines rather than read off a doc page**
(2026-09-10, `design/scripts/measure-uri-suffix-match.py`, fifteen cases against a log
group holding exactly two URIs so every expected count is known). `$`, `^`, `?`,
alternation, `(?i)` and `($|\\?)` behave identically on CloudWatch Logs Insights and on
Athena, and both engines are case-SENSITIVE by default. That last one is why `(?i)` is
here: without it `/IMG_1.PNG` is not a static asset, which inflates the URI-diversity
signal that the crawler and repeater queries are built on.

**`($|\\?)` and not a bare `$`. The branch is unreachable on WAF's own data, measured, and
that is a statement about reachability rather than about correctness.** `GET /app.js?v=2`
through a live WAF logged `uri=/app.js` and `args=v=2`, so the query string never reaches
`uri` and a bare `$` would be enough for every table this agent builds. Do not conclude the
six characters are dead weight. They are for bring-your-own table, where `httprequest.uri`
may have been populated from a request line rather than from WAF's own field, and a bare
`$` then silently stops excluding every versioned asset. The branch is right when reached
and costs nothing when not.

What that branch is measured on, precisely, since the next reader may want to shorten it:
Athena excludes a literal `/app.js?v=2` (synthesised row, so the branch does fire). On
CloudWatch the construct is accepted and agrees with Athena on all fifteen cases, but the
`\\?` alternative itself has never been exercised against a row, because no URI in this
account carries a query string. See `design/scripts/measure-uri-suffix-match.py`.

**What stays IN the analysis, deliberately.** pdf, json, html, htm, php, xml, txt, csv
and the office and archive extensions. A request for one of those is a business request or
a scrape target, and excluding it hides the traffic these tools exist to find.

**A NULL `uri` is kept, and the guard that does it is the difference between removing the
drift and moving it.** `NOT regexp_like(NULL, ...)` is NULL, so without the guard Athena
drops every row whose `uri` is missing while CloudWatch's `not like` keeps it: the same
two-answers-per-backend defect this module exists to remove.

Do not remove the guard on the grounds that a WAF log always populates `uri`. That is true
of a table this agent built and is not the population here. `_check_schema` validates that
`httprequest` HAS a `uri` field and says nothing about row values, so a bring-your-own
table passes validation with NULLs in it, and ROADMAP 5.1 adds user-converted Parquet,
where a partial ETL dropping a field on some rows is ordinary. There a NULL `uri` is a real
request. Keeping it is also the right reading on its own terms, since a request with no
recorded URI is not a static asset.

The parentheses are load-bearing. `OR` binds looser than the `AND` this fragment is
appended to, so an unparenthesised guard would make every row with an asset URI pass
whenever some earlier condition held.

**Only this predicate needed the guard, checked rather than assumed.** The other three
negated Athena predicates over nullable columns (`waf_bypass.py:505`, `:543`, `:718`)
require presence on purpose and each has an `ispresent(...)` twin on the CloudWatch side,
so they drop the same rows on both engines.
"""

# Grouped for reading, sorted for rendering. Sorting is not cosmetic: it makes a
# duplicate visible in review and makes the rendered alternation a function of the SET,
# so a test can compare against this tuple without reproducing an ordering rule.
#
# Order is otherwise irrelevant to correctness here, which is worth saying because it is
# not true of an unanchored alternation. `\.(js|json)($|\?)` still excludes `.json` and
# only `.json`, because the boundary group forces the whole extension to match; the
# engine tries `js`, fails the boundary on the `o`, backtracks and takes `json`.
STATIC_ASSET_EXTENSIONS = (
    # scripts and styles
    "js", "mjs", "css", "map",
    # images
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "svgz", "webp", "avif", "tif", "tiff",
    # fonts
    "woff", "woff2", "ttf", "otf", "eot",
    # audio and video
    "mp4", "webm", "mov", "avi", "mp3", "wav", "ogg", "m4a",
)

# `(?i)` leads, `($|\?)` closes, and the two are the whole difference from what this
# replaced. Rendered once here so the two dialects cannot disagree again: the only
# per-dialect part is the syntax that wraps the pattern.
_PATTERN = r"(?i)\.(" + "|".join(sorted(STATIC_ASSET_EXTENSIONS)) + r")($|\?)"

# Both fragments carry their leading conjunction, because every call site appends them to
# a WHERE or a filter that already has at least one condition. Checked: there is no site
# where one of these is the first condition.
#
# CloudWatch needs no NULL guard because `not like` on an absent field already keeps the
# row, measured. Athena needs one, and it is parenthesised: see the docstring.
CWL_EXCLUDE_STATIC = f" and httpRequest.uri not like /{_PATTERN}/"
ATHENA_EXCLUDE_STATIC = (" AND (httprequest.uri IS NULL"
                         f" OR NOT regexp_like(httprequest.uri, '{_PATTERN}'))")
