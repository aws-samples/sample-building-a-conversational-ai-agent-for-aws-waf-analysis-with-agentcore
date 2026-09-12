# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 5.5: the mask fallback covered two of six consumers, and extending it exposed two bugs.

`redact_row_fields`' `_VALUE_SENSITIVE` fallback says in its own docstring that it exists so "a future
template that selects a secret into an innocuously-named column is still covered". It ran from two
call sites. A guarantee holding for a third of its callers is the kind of prose the next reader takes
as universal, which is the defect class this repo spent two days removing.

**Extending it was described as cost-free and was not.** The reasoning was that none of the 30 columns
the four uncovered modules select is name-sensitive, which is true and only covers the NAME path. The
VALUE path had a live false positive, and moving the call into the funnel would have added a second
one. Both are fixed here, and both are the reason this is a change rather than a one-line extension.

1. **`awswaf:managed:token:absent` was masked.** `[=:]` read a namespace separator as an assignment,
   so the `labels` column became `<redacted len=27>` in `run_logs_query` and
   `aggregate_logs(group_by="label")` for every request arriving without a token, which is most of
   them. Pre-existing on main, not introduced by 5.5.
2. **`@message` would have been masked**, and it is the whole record in one cell. Any request with a
   `sessionid=` cookie trips the fallback, the cell becomes `<redacted len=3241>`, and both parsers
   `json.loads` it inside a bare `except`. Match details and headers would vanish silently.
"""

import json
import pathlib

from tools import waf_query as q

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "waf_log_record.json"


def _reset():
    for bucket in q._value_findings.values():
        bucket.clear()


# --- bug 1: a WAF label is not a credential assignment ----------------------

def test_a_waf_label_is_not_read_as_a_credential_assignment():
    """The live case, taken from the real record rather than invented: `token:absent` is on every
    request that arrives without a WAF token.

    Asserted through `redact_row_fields` on the column names the label queries actually produce,
    `label` for `aggregate_logs` and `labels` for the raw array, so this fails if either path
    regresses."""
    real = json.loads(FIXTURE.read_text())["labels"]
    assert any("token" in l["name"] for l in real), \
        "the fixture has no token label, so this proves nothing"
    row = {"label": real[0]["name"], "labels": json.dumps(real), "cnt": "9"}
    before = dict(row)
    assert q.redact_row_fields([row]) is False, f"a WAF label was masked: {row}"
    assert row == before, "a label value was rewritten"


def test_a_credential_name_inside_a_longer_cookie_name_still_masks():
    """Why the lookbehind is `:` and not `\\w`. Excluding a word character would also stop
    `PHPSESSID` and `JSESSIONID` matching, because `sess` sits inside a longer real cookie name, and
    those are the exact values the fallback exists for."""
    for value in ("PHPSESSID=xyzabc123; other=1", "JSESSIONID=abcdef; x=1",
                  "sessionid=abc123def", "user=bob&token=abc123def",
                  "Bearer eyJhbGciOiJIUzI1", "basic dXNlcjpwYXNz",
                  "Authorization: Bearer abc", "cookie: sessionid=abc",
                  "api_key=abcdef123", "access-token=zzz", "csrf_token=aaa"):
        row = {"anything": value}
        assert q.redact_row_fields([row]) is True, f"a real credential stopped masking: {value!r}"


def test_ordinary_values_are_still_left_alone():
    """The negative side, on the shapes that pass through every query: a URI mentioning tokens, a
    JA4, a User-Agent."""
    for value in ("/docs/token-guide", "/index.php?q=1", "Mozilla/5.0 (Windows NT 10.0)",
                  "t12d560700_2f38f8f35a98_f176685d112f",
                  "awswaf:managed:aws:bot-control:bot:name:googlebot"):
        row = {"anything": value}
        assert q.redact_row_fields([row]) is False, f"an ordinary value was masked: {value!r}"


# --- bug 2: @message is the record, not a value -----------------------------

def test_the_raw_record_column_is_never_masked():
    """`@message` holds the whole record, so masking it destroys the record rather than a value.

    Built from the real fixture plus a session cookie, which is the ordinary case: without the
    exclusion the cell becomes `<redacted len=...>` and every `json.loads` downstream fails inside a
    bare `except`, taking match details and headers with it and saying nothing."""
    rec = json.loads(FIXTURE.read_text())
    rec["httpRequest"]["headers"].append({"name": "Cookie", "value": "sessionid=abc123def456"})
    raw = json.dumps(rec, separators=(",", ":"))
    assert q._VALUE_SENSITIVE.search(raw), \
        "the record does not trip the fallback, so the exclusion is untested here"
    row = {"@message": raw}
    assert q.redact_row_fields([row]) is False, "the raw record column was masked"
    json.loads(row["@message"])          # raises if the record was rewritten

    # And the exclusion is scoped to that one column, not to raw-looking values generally.
    other = {"content": raw}
    assert q.redact_row_fields([other]) is True, \
        "the exclusion leaked to a column that is displayed rather than parsed"


def test_no_display_template_selects_the_excluded_column():
    """The exclusion is only safe because `@message` is never shown. Derived from the templates
    rather than asserted as a claim, so a future template that displays it fails here instead of
    quietly shipping an unmasked record."""
    from tools.waf_logs import TEMPLATES
    showing = [n for n, t in TEMPLATES.items() if "fields @message" in t["query"]]
    assert not showing, (
        f"{showing} select @message for display, and it is excluded from masking. Either mask it "
        f"there or drop it from the SELECT.")


# --- 5.5 itself: every consumer, and the order that makes it work -----------

def test_masking_happens_inside_the_funnel_so_no_consumer_can_forget():
    """The point of 5.5. Two of six consumers called the masker; now none of them does and the funnel
    does it for all of them.

    Structural, because a behavioural test would only cover the consumers someone remembered, which
    is exactly the state 5.5 replaces."""
    import pathlib as _p
    tools = _p.Path(q.__file__).parent
    callers = sorted(f.name for f in tools.glob("*.py")
                     if "redact_row_fields(" in f.read_text() and f.name != "waf_query.py")
    assert callers == [], f"{callers} still mask their own rows; the funnel already did it"
    src = (tools / "waf_query.py").read_text()
    assert "if redact_row_fields(rows):" in src, "the funnel no longer masks at all"


def test_the_scan_runs_before_the_mask():
    """**Order is load-bearing for both scanners and neither would say so if it broke.**

    A forged control marker inside a cookie, and AWS's own `REDACTED` in a sensitive-named column, are
    both replaced by `<redacted len=N>`. Scanning after masking would find neither, and the result
    would look exactly like a clean scan. Asserted on positions in the source, since the failure has
    no behavioural signature once the value is gone."""
    src = (pathlib.Path(q.__file__)).read_text()
    body = src.split("def _scan_log_values")[1].split("\ndef ")[0]
    scan_at = body.index('forged |= {(key, m) for m in _HEADING_MARKERS')
    mask_at = body.index("if redact_row_fields(rows):")
    assert scan_at < mask_at, \
        "masking now runs before the scan, so a marker or a REDACTED value inside a masked column is invisible"


def test_a_masked_row_still_tells_the_user_why():
    """The hint moved with the masking. It used to be appended by the two callers; now the funnel
    records and the hook delivers, so the four newly-covered consumers get it too."""
    _reset()
    q._scan_log_values([{"cookie": "sessionid=abc123def"}])
    note = q.drain_log_value_findings()
    assert "deliberate safeguard" in note and "<redacted len=N>" in note, note
    _reset()
    q._scan_log_values([{"httpRequest.uri": "/plain"}])
    assert q.drain_log_value_findings() == "", "an unmasked result claimed something was masked"
