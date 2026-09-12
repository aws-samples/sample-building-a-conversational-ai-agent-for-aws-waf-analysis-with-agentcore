# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Five positions decide whether a redeploy reaches the user, and none of them errors when wrong.

`deploy/frontend.yaml` shipped with one cache behaviour on `Managed-CachingOptimized`, DefaultTTL
86400, and `aws s3 sync` sets no `Cache-Control`. `index.html` is the only filename Vite keeps stable
across builds, so a cached copy keeps asking for the previous build's asset hashes. Measured on the
first real browser visit after a redeploy: `Age: 3916`.

**The first fix was too blunt, and the tests written with it locked the bluntness in.** Putting
everything on `CachingDisabled` also stopped the content-hashed assets being cached, which is the
entire point of hashing them, and it disables request collapsing so concurrent visitors each cause a
separate S3 GET. Two of the three assertions then actively blocked the correct design: one forbade
`CachingOptimized` anywhere in the file, and one forbade a second cache behaviour. The right shape
splits on path, so the checks have to be per path too.

**Why the default behaviour must be a MinTTL-0 policy, rather than relying on a header.** A cache
policy with MinTTL above zero caches for at least that long "even if the Cache-Control: no-cache,
no-store, or private directives are present in the origin headers". `CachingOptimized` has MinTTL 1.
So serving `index.html` through it would override the object's `no-cache` and no upload flag could
save it.

**`ErrorCachingMinTTL` is the one cache a header cannot switch off.** Defining `CustomErrorResponses`
at all brings a default of 300 seconds, measured at 300 on the live distribution. Error caching is
asymmetric: for 404, 410, 414 and 501 CloudFront honours the origin's `no-store`/`no-cache`, and for
everything else **including 403** it ignores them. S3 behind Origin Access Control answers a missing
key with 403, so a request for an asset that is gone returns `index.html` with status 200, cached at
the edge for five minutes, and the browser parses HTML as JavaScript.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "deploy/frontend.yaml").read_text()

# Managed policy ids and their TTLs, from `aws cloudfront list-cache-policies --type managed`,
# 2026-09-12. The MinTTL is the number that matters for the default behaviour.
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"   # Default/Max/Min all 0
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"  # Default 86400, Max 31536000, Min 1
GUIDES = ("docs/deployment.md", "docs/deployment_zh.md")


def _block(key, indent=8):
    """A top-level block of DistributionConfig, by key."""
    pad = " " * indent
    match = re.search(rf"^{pad}{key}:\n((?:{pad}  .*\n|{pad}#.*\n|\n)+)", TEMPLATE, re.M)
    assert match, f"the {key} block moved; this test proves nothing"
    return match.group(1)


def test_html_is_served_by_a_policy_that_cannot_cache():
    """The default behaviour catches `index.html` and the SPA fallback. Asserted as an id because the
    template can only carry an id, and asserted as *not* the optimized one because that is the value
    it shipped with and the one a reasonable person would put back."""
    default = _block("DefaultCacheBehavior")
    assert CACHING_DISABLED in default, (
        "the default cache behaviour is not Managed-CachingDisabled. Any MinTTL above zero caches "
        "index.html and overrides no-cache on the object, so a redeploy keeps serving the old app.")
    assert CACHING_OPTIMIZED not in default, "CachingOptimized on the default behaviour caches HTML"


def test_hashed_assets_are_cached_and_only_they_are():
    """The other half. Content-hashed names exist so they can be cached forever; leaving them on the
    disabled policy means every page load crosses CloudFront to S3 and request collapsing is off."""
    behaviours = _block("CacheBehaviors")
    assert "PathPattern: /assets/*" in behaviours, (
        "no /assets/* behaviour, so the hashed bundle is served by whatever the default is")
    assert CACHING_OPTIMIZED in behaviours
    # One extra behaviour only. A second path pattern would need its own assertion here rather than
    # silently inheriting this one's.
    assert behaviours.count("PathPattern:") == 1, (
        "more than one extra cache behaviour; add an assertion for each path pattern")


def test_both_error_responses_disable_error_caching():
    """The cache no header can reach. Both entries, because 403 is the one that matters for a missing
    object behind Origin Access Control and it is also the one CloudFront refuses to leave uncached."""
    errors = _block("CustomErrorResponses")
    codes = re.findall(r"- ErrorCode: (\d+)", errors)
    assert sorted(codes) == ["403", "404"], (
        f"expected 403 and 404 mapped to the app, found {codes}. Mapping only 404 leaves deep links "
        f"failing on an unhandled 403 from S3.")
    ttls = re.findall(r"ErrorCachingMinTTL: (\d+)", errors)
    assert ttls == ["0", "0"], (
        f"ErrorCachingMinTTL is {ttls or 'unset'}. Unset means 300 seconds, and for 403 CloudFront "
        f"ignores no-store from the origin, so a missing asset is answered with index.html for five "
        f"minutes and the browser parses HTML as JavaScript.")


def test_the_custom_domain_stays_optional():
    """A first deployment with no domain must be identical to having no such parameters. Both must be
    supplied together, so there is no half state where an alias is set with no certificate."""
    assert re.search(r"^  DomainName:\n    Type: String\n    Default: \"\"", TEMPLATE, re.M)
    assert re.search(r"^  AcmCertificateArn:\n    Type: String\n    Default: \"\"", TEMPLATE, re.M)
    condition = re.search(r"^  HasCustomDomain: !And\n((?:    .*\n)+)", TEMPLATE, re.M)
    assert condition, "HasCustomDomain moved; this test proves nothing"
    assert condition.group(1).count("!Not [!Equals") == 2, "one parameter alone must not be enough"
    assert TEMPLATE.count('!Ref "AWS::NoValue"') == 2, (
        "Aliases and ViewerCertificate must both fall away when no domain is given, or a deployment "
        "without one differs from the template that has no parameters at all")


def test_the_upload_sends_opposite_headers_for_the_two_kinds_of_file():
    """The template half is useless without this one. Both `aws s3 sync` invocations are checked
    including their continuation lines, because the flag sits on the second line and a per-line search
    is what made an earlier version of this test pass while asserting nothing."""
    for guide in GUIDES:
        text = (ROOT / guide).read_text()
        # The greedy `[^\n]*` would swallow the trailing backslash, so the continuation has to be
        # matched as part of the repeated group rather than after it.
        commands = re.findall(r"aws s3 sync dist/(?:[^\n]*\\\n)*[^\n]*", text)
        assert len(commands) == 2, f"{guide} has {len(commands)} frontend upload commands, expected 2"
        assets = [c for c in commands if "--exclude index.html" in c]
        html = [c for c in commands if "--include index.html" in c]
        assert len(assets) == 1 and len(html) == 1, f"{guide}: cannot tell the two passes apart"
        assert "max-age=31536000" in assets[0] and "immutable" in assets[0], assets[0]
        assert "no-cache" in html[0], html[0]
        assert "no-store" not in html[0], (
            "no-store forbids storing a copy at all, so every load is a full transfer. no-cache "
            "allows a stored copy and forces revalidation, which gets a 304 instead.")
        # Scoped to the sync commands. The Cleanup section legitimately uses `delete-objects
        # --delete`, and scanning the whole document for the string is how this assertion failed
        # against a correct document on its first run.
        for command in commands:
            assert "--delete" not in command, (
                f"{guide} deletes old objects on upload: {command!r}. The previous build's hashed "
                f"assets are what a browser still holding the old index.html asks for; removing them "
                f"breaks that tab instead of leaving it merely stale.")
