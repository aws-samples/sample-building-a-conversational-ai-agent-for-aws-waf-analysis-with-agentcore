# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""`token_reuse_ips` has to group by WAF's session id, not by any part of the Cookie header.

**Measured on a live replay, 2026-09-16.** One WAF session, `awswaf:managed:token:id:75d4ae85-...`,
spanned 18 IPs and 253 requests. Grouped by `token:id` it is one row, `ip_count=18` — the signal this
detection exists for. Grouped by the whole Cookie header it fragmented into many rows (the load balancer's
`AWSALBTG`/`AWSALBTGCORS` stickiness cookies differ per backend and rotate); grouped by the extracted
`aws-waf-token` value it *still* fragmented into five, because the token is `<uuid>:<iv>:<ciphertext>` and
each fresh acquisition re-encrypts the last two segments. So the cookie value is not the session, and
neither is its leading UUID, which is a different value from `token:id`.

Two things a synthetic fixture has to carry to hold these, and the earlier ones did not:
1. **Two distinct full token values under one `token:id`** — otherwise "group by the value" and "group by
   the id" are indistinguishable, which is exactly why the interim value-based fix looked correct in test
   and fragmented in production.
2. **A record whose token arrived in the `x-aws-waf-token` header, not the cookie** — the JS SDK's
   cross-origin path. It is `token:accepted` with a `token:id` label and no `aws-waf-token=` in the
   cookie, so a cookie-keyed query drops it into an empty group that sorts first by `ip_count` with a
   masked value, which is the shape a real finding takes. Grouping by the label never parses the cookie,
   so the group does not exist.
"""

import re

import pytest

from tools.waf_logs import TEMPLATES

SPEC = TEMPLATES["token_reuse_ips"]

SESSION = "75d4ae85-8399-439a-952d-af817bdb4d4b"          # the token:id — one session
OTHER_SESSION = "11112222-3333-4444-5555-666677778888"
# Two acquisitions of the SAME session: same token:id, different <uuid>:<iv>:<ciphertext> cookie values.
TOKEN_V1 = "843a54a6-403b-47c9-8cca-60c2bd1ab667:AQoAaaa:ZZZ97+TZw=="
TOKEN_V2 = "843a54a6-403b-47c9-8cca-60c2bd1ab667:AQoAbbb:XXXwO+V/g=="


def _msg(client_ip, token_id, cookie_token=None, alb="AWSALBTG=x9; AWSALBTGCORS=y9"):
    """A WAF log line as CloudWatch stores it. `cookie_token=None` is the SDK header path: the token
    rode in `x-aws-waf-token`, so the Cookie header has no `aws-waf-token=` at all."""
    cookie = f"aws-waf-token={cookie_token}; {alb}" if cookie_token else alb
    labels = f'{{"name":"awswaf:managed:token:accepted"}},{{"name":"awswaf:managed:token:id:{token_id}"}}'
    return (f'{{"httpRequest":{{"clientIp":"{client_ip}",'
            f'"headers":[{{"name":"cookie","value":"{cookie}"}}]}},"labels":[{labels}]}}')


def _cwl_key_regex():
    """The parse pattern the CWL query actually uses, as Python's named-group syntax, lifted from the
    template so the test cannot drift from the code it checks."""
    m = re.search(r"parse @message /(.+?)/ \|", SPEC["query"])
    assert m, f"the CWL query has no `parse @message /.../` stage: {SPEC['query']}"
    return re.compile(m.group(1).replace("(?<", "(?P<"))


def _group_ip_counts(records):
    """Simulate the query's `count_distinct(clientIp) by <key>` using the real CWL parse pattern.

    Returns {key: set(ips)}; the empty key stands for a record the pattern did not match, the catch-all
    group that would sort first."""
    pat = _cwl_key_regex()
    key_name = pat.groupindex and next(iter(pat.groupindex))
    groups = {}
    for ip, msg in records:
        m = pat.search(msg)
        key = m.group(key_name) if m else ""
        groups.setdefault(key, set()).add(ip)
    return groups


# The replay, as records: one session, two token values, five IPs; plus one SDK-header request.
REPLAY = [
    ("3.147.28.85", _msg("3.147.28.85", SESSION, TOKEN_V1)),
    ("44.247.7.81", _msg("44.247.7.81", SESSION, TOKEN_V1)),
    ("108.131.86.157", _msg("108.131.86.157", SESSION, TOKEN_V2)),   # different token value, same session
    ("63.187.45.97", _msg("63.187.45.97", SESSION, TOKEN_V2)),
    ("13.203.94.72", _msg("13.203.94.72", SESSION, cookie_token=None)),  # SDK header path, no cookie token
]


def test_one_session_across_many_ips_is_one_group_with_the_full_ip_count():
    """**The finding this detection exists for, and the shape that broke it.** Five IPs, one `token:id`,
    two token values, one SDK-header request. The key must merge all five into one group of five IPs. A
    key that splits on the token value gives 2+2 and misses the SDK request; a key on the whole cookie
    header splits further."""
    groups = _group_ip_counts(REPLAY)
    assert set(groups) == {SESSION}, (
        f"expected one group keyed by the session id; got {sorted(groups)} — the key still carries a "
        f"per-request-varying component, so one session fragments into many rows")
    assert len(groups[SESSION]) == 5, f"ip_count={len(groups[SESSION])}, expected 5 distinct IPs in the session"


def test_two_token_values_sharing_one_session_do_not_fragment():
    """The precondition the earlier fixtures could not express: two DIFFERENT full token values under one
    `token:id`. If the key were the token value, these would be two groups; the reviewer measured exactly
    this on real data, one session showing five distinct cookie values."""
    v1 = _group_ip_counts([("1.1.1.1", _msg("1.1.1.1", SESSION, TOKEN_V1))])
    v2 = _group_ip_counts([("2.2.2.2", _msg("2.2.2.2", SESSION, TOKEN_V2))])
    assert list(v1) == list(v2) == [SESSION], (
        f"the two token values did not collapse to one key: {list(v1)} vs {list(v2)}")


def test_the_sdk_header_request_joins_its_session_not_an_empty_group():
    """The cross-origin SDK path: `token:accepted`, a `token:id`, and no `aws-waf-token=` in the cookie.
    Keyed by the label it joins its session; a cookie-keyed query would strand it in the empty group that
    sorts first with a masked value, the false-finding shape."""
    groups = _group_ip_counts([("9.9.9.9", _msg("9.9.9.9", SESSION, cookie_token=None))])
    assert list(groups) == [SESSION], f"the SDK-header request did not key on its session: {list(groups)}"
    assert "" not in groups, "an SDK-header request fell into the empty catch-all group"


def test_distinct_sessions_stay_distinct():
    """The other direction: two real sessions must not merge, or every IP looks like reuse of one token."""
    groups = _group_ip_counts([
        ("1.1.1.1", _msg("1.1.1.1", SESSION, TOKEN_V1)),
        ("2.2.2.2", _msg("2.2.2.2", OTHER_SESSION, TOKEN_V1)),   # same token value, different session id
    ])
    assert set(groups) == {SESSION, OTHER_SESSION}, f"two sessions did not stay separate: {sorted(groups)}"


def test_neither_engine_parses_the_cookie_anymore():
    """The regression guard, on the source. The key is the `token:id` label on both engines; a return to
    parsing `aws-waf-token=` out of the cookie is the interim bug, and parsing the whole cookie header is
    the original. Fails without a log line."""
    assert "awswaf:managed:token:id:" in SPEC["query"] and "by token_id" in SPEC["query"], \
        "the CWL query no longer groups by the token:id label"
    assert "aws-waf-token=" not in SPEC["query"] and "aws-waf-token=" not in SPEC["athena"], \
        "a query still parses the aws-waf-token cookie value, which fragments one session"
    assert "GROUP BY regexp_extract(array_join(transform(labels" in SPEC["athena"], \
        "the Athena query no longer groups by the token:id label"


def test_the_query_requires_the_label_so_there_is_no_empty_catch_all():
    """A `token:accepted` record without a `token:id` would parse to an empty key and sort first by
    `ip_count`. Both engines filter to records that carry the label, so that group cannot form."""
    assert "and @message like 'awswaf:managed:token:id:'" in SPEC["query"], \
        "the CWL query does not require the token:id label"
    assert "any_match(labels, l -> l.name LIKE 'awswaf:managed:token:id:%')" in SPEC["athena"], \
        "the Athena query does not require the token:id label"


def test_the_session_column_is_named_so_it_is_masked_on_display():
    """`token_id` carries the `token` name, so `_name_is_sensitive` masks it, the same display contract the
    cookie alias had. `tokenid` would not, and that is the trap this pins."""
    from tools.waf_query import _name_is_sensitive
    assert _name_is_sensitive("token_id"), "the session-id column name is not recognised as sensitive"
    assert "as token_id" in SPEC["athena"] and "by token_id" in SPEC["query"], \
        "the session id is not aliased token_id on both engines, so masking may not apply"


def test_the_cwl_pattern_reads_a_uuid_shaped_id():
    """The extracted id is a UUID (hex and hyphens); the pattern must stop at the label boundary, not run
    into the next label. Driven against a realistic message."""
    key = _cwl_key_regex().search(_msg("1.1.1.1", SESSION, TOKEN_V1)).group("token_id")
    assert key == SESSION, f"the token:id extraction returned {key!r}, not the session id"
