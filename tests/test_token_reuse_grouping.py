# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`token_reuse_ips` grouped by the whole Cookie header, so one token read as many.

**Measured on a live 7-region replay, 2026-09-15.** One `aws-waf-token`, solved once in a browser and
replayed from seven EC2 IPs, is exactly the shape this query exists to catch: `ip_count` should be 7. It
came back as `ip_count=1`, once per row, because the query grouped by the entire Cookie header value and a
real header is not just the token:

    aws-waf-token=<token>; AWSALBTG=<per-backend>; AWSALBTGCORS=<per-backend>

The load balancer's stickiness cookies differ by backend and rotate, so the same token appeared under many
distinct header strings, one group each, and the cross-IP signal was divided away. The detection reported
the opposite of the truth: a token abused across seven IPs looked like seven unrelated single-IP sessions.

**No synthetic test could hold this**, which is why it shipped: the fixtures used a bare cookie value equal
to the token, and grouping by the whole header is indistinguishable from grouping by the token until a
second cookie rides along. So this test carries a realistic header, with the ALB cookies that were actually
present, and drives the real extraction patterns lifted from the templates.
"""

import re

import pytest

from tools.waf_logs import TEMPLATES

SPEC = TEMPLATES["token_reuse_ips"]

# Two requests, same token, different trailing ALB cookies — the exact shape the live replay produced.
TOKEN = "843a54a6-403b-47c9-8cca-60c2bd1ab667:BgoAmNAA:CXf903GFqq1y4ahdARe5u=="
COOKIE_A = f"aws-waf-token={TOKEN}; AWSALBTG=k04s1Hakb67lEu0hr1AOHVkgl+xZ; AWSALBTGCORS=k04s1Hakb67l+xZ"
COOKIE_B = f"aws-waf-token={TOKEN}; AWSALBTG=zzP8vi2GHM8SdifferentX9; AWSALBTGCORS=zzP8vi2GHM8Sdiff"


def _cwl_token_regex():
    """The parse pattern the CWL query actually uses, converted to Python's named-group syntax.

    Lifted from the template rather than retyped, so a change to the query that this test does not see
    cannot leave the test asserting a pattern the code no longer runs."""
    m = re.search(r"parse @message /(.+?)/ \|", SPEC["query"])
    assert m, f"the CWL query no longer has a `parse @message /.../` stage: {SPEC['query']}"
    return re.compile(m.group(1).replace("(?<", "(?P<"))


def _athena_token_regex():
    """The pattern inside the Athena `regexp_extract`, run in Python against the same header. Matched as
    the quoted literal beginning `aws-waf-token=`, because the extract's first argument is itself a
    `filter(...)` call full of commas and quotes."""
    m = re.search(r"'(aws-waf-token=[^']+)'", SPEC["athena"])
    assert m, f"the Athena query no longer extracts the token with regexp_extract: {SPEC['athena']}"
    return re.compile(m.group(1))


def _cwl_message(cookie: str) -> str:
    """A WAF log line as CloudWatch stores it: the cookie header is one JSON field inside @message."""
    return ('{"webaclId":"...","action":"ALLOW",'
            f'"httpRequest":{{"clientIp":"1.2.3.4","headers":[{{"name":"cookie","value":"{cookie}"}}]}},'
            '"labels":[{"name":"awswaf:managed:token:accepted"}]}')


@pytest.mark.parametrize("engine,extract", [
    ("cwl", lambda c: _cwl_token_regex().search(_cwl_message(c))),
    ("athena", lambda c: _athena_token_regex().search(c)),
])
def test_the_group_key_is_the_token_not_the_whole_cookie_header(engine, extract):
    """**The group key is what decides whether reuse is counted.** Both requests carry the same token and
    different ALB cookies; the extracted key has to be equal for them, or the `count_distinct(ip)` is
    computed within a fragment and a botnet reads as many honest sessions."""
    a = extract(COOKIE_A)
    b = extract(COOKIE_B)
    assert a and b, f"{engine}: the pattern matched nothing in a realistic cookie header"
    ka = a.group("waf_token") if engine == "cwl" else a.group(1)
    kb = b.group("waf_token") if engine == "cwl" else b.group(1)
    assert ka == kb == TOKEN, (
        f"{engine}: grouped by {ka!r} vs {kb!r}; the same token under two ALB cookies did not collapse "
        f"to one group, so seven replay IPs would still read as seven separate sessions")


def test_the_extracted_token_stops_at_the_first_other_cookie():
    """The failure the other direction: a key that swallows the trailing cookies is the original bug in a
    subtler form, equal only when the trailing cookies happen to match. The token has no `;`, so the
    boundary is the first `;`."""
    key = _cwl_token_regex().search(_cwl_message(COOKIE_A)).group("waf_token")
    assert "AWSALBTG" not in key and ";" not in key, f"the key still carries a trailing cookie: {key!r}"
    assert key == TOKEN


def test_neither_engine_groups_by_the_raw_cookie_header_anymore():
    """The regression guard stated on the source. The old query grouped by the whole header, aliased
    `cookie`; the fix keys on the token, aliased `waf_token`. If either engine goes back to grouping by
    the bare cookie value, this fails without needing a log line."""
    assert " by cookie " not in f" {SPEC['query']} ", "the CWL query groups by the whole cookie header again"
    assert "by waf_token" in SPEC["query"], "the CWL query no longer groups by the extracted token"
    # Athena: the GROUP BY must be the regexp_extract, not the bare header value.
    assert "GROUP BY regexp_extract(" in SPEC["athena"], "the Athena query groups by the whole header again"


def test_the_token_column_is_named_so_it_is_masked_on_display():
    """The value is an encrypted session token; replaying it is the attack. The column is keyed so
    `_name_is_sensitive` masks it after the query returns, the same contract the old `cookie` alias had.
    `waf_token` carries the `token` name; `waftoken` would not, and that is the trap this pins."""
    from tools.waf_query import _name_is_sensitive
    assert _name_is_sensitive("waf_token"), "the token column name is not recognised as sensitive"
    # CWL names the field through the parse capture and groups by it; Athena aliases it with `as`.
    assert "(?<waf_token>" in SPEC["query"] and "by waf_token" in SPEC["query"], \
        "the CWL query no longer produces a waf_token field, so masking may not apply"
    assert "as waf_token" in SPEC["athena"], \
        "the Athena query no longer aliases the token waf_token, so masking may not apply"
