# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Which query surfaces read a field AWS WAF logging can redact. Inventory, not disclosure.

**Inventory is true under either answer to the open question, which is why it is built first.** If
WAF omits a redacted field the inventory is needed everywhere; if WAF writes a literal placeholder
the group-by and display cases become self-identifying from the data, but a **filter** on a redacted
field still matches nothing and returns zero rows with no placeholder anywhere in the result. So the
declaration survives either way. What depends on the answer is what gets SAID when one fires, and
that is deliberately not here.

**The declaration is data, never policy.** No entry carries a message. A field saying what to tell
the user would be the disclosure, and writing it now would settle a question the record shape has
not answered.

**`SingleHeader` declares the header NAME, and that is the load-bearing part.** Header redaction is
per-name while `UriPath`, `Method` and `QueryString` are all-or-nothing, so a template declaring
merely "reads a header" cannot be matched against a real configuration: a config redacting
`authorization` says nothing about `token_reuse_ips`, which needs `cookie`. The assertion below
checks the name, or it would pass on a template declaring the wrong header.

**Why a declaration at all, when the query text is right there.** Drift. The query text determines
exposure and the declaration states it, and they are maintained separately, so a template that grows
a `httprequest.uri` reference without its declaration fails here. Same shape as the test pinning
`_rate`'s quoted measurement against the number the tests use.

The exposure this covers, measured across the query layer: 16 of 37 `run_logs_query` templates, 5 of
13 `aggregate_logs` group dimensions, 2 of 9 filter dimensions. `QueryString` is redactable and maps
to no dimension at all, so the full mapping is UriPath -> uri, Method -> method,
SingleHeader -> {ua, referer, host}, QueryString -> nothing.
"""

import re

import pytest

from tools import waf_aggregate as AG
from tools.waf_logs import TEMPLATES

# Exactly four `FieldToMatch` types are accepted for logging redaction. Body, JsonBody, Cookies,
# Headers, AllQueryArguments, JA3 and JA4 are all unsupported, so a declaration naming one of those
# is a mistake rather than a gap.
ACCEPTED = ("UriPath", "QueryString", "Method", "SingleHeader")


# The two ways a query names a header, hoisted so each has a name and the pattern that carries the
# whole distinction is visible rather than buried in a call.
#
# **The brace is the load-bearing character.** A header parse is `\\{"name":"host","value":"`; the
# LABELS parse is `"name":"(?<lbl>[^"]*)"` with no brace. Without requiring it, the label capture
# group's own name came out as a header called `(?<lbl>[^`.
_CWL_HEADER = r'\\\{"name":"([^"]+)"'
_ATHENA_HEADER = r"lower\(h\.name\)\s*=\s*'([^']+)'"


def _derive(cwl: str, athena: str) -> tuple[set, set]:
    """`(RedactedFields entries this query text reads, names that did not parse as headers)`.

    The second half exists because the first version emitted garbage rather than failing. Matching
    `"name":"` picked up the LABELS parse, `parse lbls /"name":"(?<lbl>[^"]*)"/`, and produced a
    header called `(?<lbl>[^`. A capture group's own name leaking into a header name is a pattern
    matching the wrong construct, so it is surfaced and asserted empty instead of silently declared.

    Requiring the brace is what separates the two: a header parse is `\\{"name":"host","value":"`
    and the label parse has no brace. `token_reuse_ips` reads its header through a glob rather than
    a regex and so has no brace either, but its Athena side names the header explicitly, which is
    why both dialects are read and unioned."""
    out, suspect = set(), set()
    both = cwl + " " + athena
    if re.search(r"httprequest\.uri|httpRequest\.uri", both):
        out.add("UriPath")
    if re.search(r"httprequest\.args|httpRequest\.args", both):
        out.add("QueryString")
    if re.search(r"httprequest\.httpmethod|httpRequest\.httpMethod", both):
        out.add("Method")
    for name in re.findall(_ATHENA_HEADER, athena):
        out.add(f"SingleHeader:{name.lower()}")
    for name in re.findall(_CWL_HEADER, cwl):
        # `(H|h)ost` is a case alternation inside the regex, not a header of that name.
        clean = re.sub(r"\(([A-Za-z])\|[A-Za-z]\)", r"\1", name).lower()
        if re.fullmatch(r"[a-z0-9-]+", clean):
            out.add(f"SingleHeader:{clean}")
        else:
            suspect.add(name)
    return out, suspect


def _text(template: dict) -> tuple[str, str]:
    return template.get("query", ""), template.get("athena", "")


def test_the_derivation_reads_what_it_claims_to_read():
    """The floor. Every assertion below compares a derivation against a declaration, so a
    derivation that reads nothing would make the templates with no declaration pass vacuously, and
    one that reads garbage would demand a garbage declaration.

    Named subjects rather than a count, and chosen as the three shapes the derivation has to handle:
    a plain field, a header named on the Athena side only, and a header whose CWL regex spells its
    name as a case alternation."""
    assert _derive(*_text(TEMPLATES["rule_uri_prefix"]))[0] == {"UriPath"}
    assert _derive(*_text(TEMPLATES["token_reuse_ips"]))[0] == {"SingleHeader:cookie"}
    assert _derive(*_text(TEMPLATES["host_traffic_profile"]))[0] == {
        "Method", "SingleHeader:host", "UriPath"}
    # And the construct that produced garbage: labels are not headers. **Both halves asserted**,
    # because the first version checked only the fields set: with the brace requirement removed the
    # garbage lands in `suspect` rather than in the fields, so the fields stay empty and the
    # assertion passed on exactly the defect it names. Found by the perturbation reporting HOLLOW.
    fields, suspect = _derive(*_text(TEMPLATES["ip_label_breakdown"]))
    assert fields == set(), fields
    assert suspect == set(), (
        f"the labels parse was read as a header: {sorted(suspect)}. The brace in _CWL_HEADER is "
        f"what separates a header parse from the label parse.")


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_each_template_declares_the_redactable_fields_its_query_reads(name):
    """The drift check, per template, both directions.

    A declaration missing an entry means the disclosure will not fire for a field the query really
    reads. An extra entry means it fires for a field the query does not read, which trains the
    reader to ignore it."""
    template = TEMPLATES[name]
    derived, suspect = _derive(*_text(template))
    assert not suspect, (
        f"{name}: could not read a header name out of {sorted(suspect)}. That is the pattern "
        f"matching the wrong construct, not a header called that.")
    declared = set(template.get("redactable", []))
    assert declared == derived, {
        "template": name,
        "declared but not read by the query": sorted(declared - derived),
        "read by the query but not declared": sorted(derived - declared)}


@pytest.mark.parametrize("name", sorted(k for k, d in AG._GROUP_BY.items() if d))
def test_each_group_dimension_declares_what_it_reads(name):
    dim = AG._GROUP_BY[name]
    derived, suspect = _derive(dim.cwl + " " + " ".join(dim.cwl_pre), dim.athena)
    assert not suspect, f"{name}: {sorted(suspect)} is not a header name"
    assert set(dim.redactable) == derived, {
        "dimension": name, "declared": sorted(dim.redactable), "read": sorted(derived)}


@pytest.mark.parametrize("name", sorted(AG._FILTERS))
def test_each_filter_dimension_declares_what_it_reads(name):
    """**The filter half is the one that stays invisible whatever the record shape.** A group-by on
    a redacted field yields a value the reader can see; a filter on one matches nothing and returns
    zero rows with no placeholder in the result at all."""
    spec = AG._FILTERS[name]
    derived, suspect = _derive(spec.cwl + " " + " ".join(spec.cwl_pre), spec.athena)
    assert not suspect, f"{name}: {sorted(suspect)} is not a header name"
    assert set(spec.redactable) == derived, {
        "filter": name, "declared": sorted(spec.redactable), "read": sorted(derived)}


@pytest.mark.parametrize("entry", sorted(
    {e for t in TEMPLATES.values() for e in t.get("redactable", [])}
    | {e for d in AG._GROUP_BY.values() if d for e in d.redactable}
    | {e for s in AG._FILTERS.values() for e in s.redactable}))
def test_every_declared_entry_is_a_field_type_waf_accepts(entry):
    """A declaration naming `Cookies`, `Headers`, `Body`, `JsonBody`, `AllQueryArguments`, `JA3` or
    `JA4` would be a mistake rather than a gap: logging redaction accepts exactly four types, so
    those cannot be redacted and a disclosure keyed on them could never fire."""
    kind, _, header = entry.partition(":")
    assert kind in ACCEPTED, f"{entry}: {kind} is not accepted for logging redaction"
    if kind == "SingleHeader":
        assert re.fullmatch(r"[a-z0-9-]+", header), \
            f"{entry}: SingleHeader must name one lowercase header"
    else:
        assert not header, f"{entry}: {kind} is all-or-nothing and takes no name"


def test_the_inventory_covers_the_surface_it_claims_to():
    """The counts this file's docstring states, asserted rather than left as prose, because a
    number in a comment is the thing that rots. Also pins that the declaration did not quietly
    shrink to nothing."""
    templates = {k for k, t in TEMPLATES.items() if t.get("redactable")}
    assert len(templates) == 16, sorted(templates)
    assert len(TEMPLATES) == 37, len(TEMPLATES)
    groups = {k for k, d in AG._GROUP_BY.items() if d and d.redactable}
    assert len(groups) == 5, sorted(groups)
    filters = {k for k, s in AG._FILTERS.items() if s.redactable}
    assert len(filters) == 2, sorted(filters)
    # `token_reuse_ips` reads the cookie header, which is the single header a privacy-conscious
    # operator is most likely to redact, so it is named rather than left to the count.
    assert TEMPLATES["token_reuse_ips"]["redactable"] == ["SingleHeader:cookie"]


def test_query_string_is_redactable_and_has_no_dimension():
    """Stated so a future dimension does not have to rediscover it. `QueryString` is one of the four
    accepted types and `aggregate_logs` has no `args` dimension, so nothing groups or filters on it
    today. If one is added it needs `redactable=("QueryString",)` and this test will say so."""
    covered = ({e for d in AG._GROUP_BY.values() if d for e in d.redactable}
               | {e for s in AG._FILTERS.values() for e in s.redactable})
    assert "QueryString" not in covered, (
        "a dimension now reads httpRequest.args, so QueryString is in play: this test's premise is "
        "out of date and the disclosure has one more field to cover")
    assert not any("args" in (d.athena + d.cwl) for d in AG._GROUP_BY.values() if d)


def test_no_declaration_carries_a_message():
    """**Data, not policy.** The declaration is inventory; what to tell the user when a field is
    redacted is the disclosure, and that waits on whether WAF omits the field or writes a
    placeholder. A message here would settle that question by accident.

    Checked as a length bound rather than by looking for prose, because any wording would pass a
    keyword check: `SingleHeader:` plus the longest real header name is well under 40 characters,
    and a sentence is not."""
    for name, t in TEMPLATES.items():
        for entry in t.get("redactable", []):
            assert len(entry) < 40, f"{name}: {entry!r} looks like a message, not a field"
            assert " " not in entry, f"{name}: {entry!r} contains a space"
