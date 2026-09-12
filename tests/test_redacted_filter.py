# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 6.13's filter half: the undercount that leaves nothing behind to detect.

The display half, shipped in #66, reads the DATA: a `REDACTED` value in a row proves the result is
affected, which is stronger than any config read. A filter inverts that completely. The predicate
cannot match a redacted value, so those records leave the result entirely, no sentinel appears
anywhere, and the row count is simply lower. **There is no data to read, so the config is not a
weaker corroboration here, it is the only source.**

**Why #62's inventory was closed rather than trimmed, since that decision is what this file
replaces.** It recorded "this query READS field X". The surviving consumer needs "this query FILTERS
on X", and #62 mixed both roles inside single entries: `host_uri_pattern` declared
`["SingleHeader:host", "UriPath"]` where the host is the predicate and the URI is display, and
`host_traffic_profile` declared `SingleHeader:host` while GROUPING by host. Under this consumer the
second is a warning about an undercount that cannot happen. So the declaration is named
`redactable_filter`, with the role in the name.

**The zero-row path is where this matters and where a returned string would have been dropped.** Both
modules return early with a "0 results" message that offers three causes, and a filter on a redacted
field is a fourth producing exactly that symptom. So the notice goes through the accumulator and the
`AfterToolCallEvent` hook, the same delivery as the other two, rather than being appended at each
render branch.
"""

import agent
from tools import session_state
from tools import waf_config
from tools import waf_query as q
from tools.waf_aggregate import _FILTERS
from tools.waf_logs import TEMPLATES

# The four `FieldToMatch` types AWS accepts for logging redaction. Pinned because the normaliser
# skips anything else rather than guessing, so a fifth type would go unwarned.
ACCEPTED = ("UriPath", "QueryString", "SingleHeader", "Method")


def _reset(redacted=()):
    session_state._state["redacted_fields"] = tuple(redacted)
    for bucket in q._value_findings.values():
        bucket.clear()


# --- reading the config ------------------------------------------------------

def test_redacted_fields_absent_is_not_the_same_as_empty():
    """Measured 2026-09-11: `RedactedFields` is **absent** from `GetLoggingConfiguration` when
    unconfigured, not present-and-empty. So it must be read with a default, and the normaliser must
    answer the same way for both, since no caller should have to tell them apart."""
    assert waf_config._normalize_redacted([]) == ()
    assert waf_config._normalize_redacted(None) == ()


def test_every_accepted_field_type_is_normalised_and_nothing_else_is():
    """Both directions. A type the normaliser drops is a query that filters on it with no warning,
    and a key it invents is a comparison that never matches."""
    assert waf_config._normalize_redacted([{"UriPath": {}}]) == ("UriPath",)
    assert waf_config._normalize_redacted([{"QueryString": {}}]) == ("QueryString",)
    assert waf_config._normalize_redacted([{"Method": {}}]) == ("Method",)
    assert waf_config._normalize_redacted(
        [{"SingleHeader": {"Name": "host"}}]) == ("SingleHeader:host",)
    # Not accepted for logging redaction, and guessing at it would invent a vocabulary entry.
    assert waf_config._normalize_redacted([{"Body": {}}, {"AllQueryArguments": {}}]) == ()
    # The docstring's claim about the accepted set, held against the function rather than a comment.
    for kind in ACCEPTED:
        entry = {"SingleHeader": {"Name": "x"}} if kind == "SingleHeader" else {kind: {}}
        assert waf_config._normalize_redacted([entry]), f"{kind} is documented accepted and is dropped"


def test_a_header_name_is_lowercased_because_http_header_names_are_case_insensitive():
    """The direction of this failure is what makes it worth a test: a config spelling it `Host` while
    the declaration says `host` would silently NOT match, and a missed match means no warning about
    an undercount. Silence on the side that matters."""
    for spelling in ("Host", "HOST", "host", "  Host  "):
        assert waf_config._normalize_redacted(
            [{"SingleHeader": {"Name": spelling}}]) == ("SingleHeader:host",), spelling


def test_duplicate_entries_collapse():
    """Two rules may redact the same header; the notice should name it once."""
    assert waf_config._normalize_redacted([
        {"SingleHeader": {"Name": "Host"}}, {"SingleHeader": {"Name": "host"}},
        {"Method": {}}, {"Method": {}}]) == ("SingleHeader:host", "Method")


def test_the_config_read_survives_logging_being_disabled():
    """`get_waf_config` initialises `redacted` before the try, because the
    `WAFNonexistentItemException` path skips every assignment inside it and `set_webacl_context`
    reads it. Asserted structurally: the default has to be established before the try, not inside."""
    import ast
    import inspect
    import textwrap
    src = textwrap.dedent(inspect.getsource(waf_config.get_waf_config))
    fn = ast.parse(src).body[0]
    tries = [n for n in ast.walk(fn) if isinstance(n, ast.Try)]
    assert tries, "no try block found, so this proves nothing"
    before = {t.id for n in fn.body for t in ast.walk(n)
              if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store)
              and not any(n is x or n in ast.walk(x) for x in tries)}
    assert "redacted" in before, \
        "`redacted` is only assigned inside the try, so a WebACL with logging off would raise here"


def test_the_default_is_safe_only_because_the_except_is_narrow():
    """`redacted = ()` means "no redaction configured", which after a FAILED read would be fail-open.

    It is safe for a reason that lives in the `except` rather than in the default: the only caught
    exception is `WAFNonexistentItemException`, meaning logging is not enabled at all, and with no
    delivery destination there is genuinely nothing to redact. `AccessDenied` and throttling propagate.
    Widening that clause to `Exception` would silently turn a permissions problem into "your config
    redacts nothing", so the narrowness is the load-bearing part and is asserted rather than described.
    """
    import ast
    import inspect
    import textwrap
    fn = ast.parse(textwrap.dedent(inspect.getsource(waf_config.get_waf_config))).body[0]
    handlers = [h for n in ast.walk(fn) if isinstance(n, ast.Try) for h in n.handlers]
    assert handlers, "no except clause found, so this proves nothing"
    caught = set()
    for h in handlers:
        assert h.type is not None, "a bare `except` would read any failure as no redaction"
        caught.add(ast.unparse(h.type))
    assert caught == {"client.exceptions.WAFNonexistentItemException"}, (
        f"get_waf_config catches {sorted(caught)}. Anything wider makes `redacted = ()` fail-open: a "
        f"permissions or throttling failure would be reported as a config that redacts nothing.")


# --- the declarations, both directions --------------------------------------

def test_every_filter_that_reads_a_redactable_field_declares_it():
    """The set that has to be complete, derived from the query text rather than from a list.

    A filter reading a redactable field without the declaration is the whole defect: the undercount
    happens and nothing says so. Enumerated at 5 sites and 2 field types, so the count is pinned; if a
    new filter dimension arrives on a redactable field, this fails rather than shipping quiet."""
    declared_agg = {k: v.redactable_filter for k, v in _FILTERS.items() if v.redactable_filter}
    assert declared_agg == {"method": ("Method",), "host": ("SingleHeader:host",)}, declared_agg
    declared_tpl = {k: tuple(v["redactable_filter"]) for k, v in TEMPLATES.items()
                    if "redactable_filter" in v}
    assert declared_tpl == {
        "host_top_ips": ("SingleHeader:host",),
        "host_uri_pattern": ("SingleHeader:host",),
        "host_method_distribution": ("SingleHeader:host",),
    }, declared_tpl
    # Every template that takes a `host` param filters on the Host header, so the two sets must agree.
    by_param = {k for k, v in TEMPLATES.items() if "host" in v.get("params", [])}
    assert by_param == set(declared_tpl), (
        f"templates taking a host param: {sorted(by_param)}; declared: {sorted(declared_tpl)}")


def test_no_declaration_names_a_field_the_predicate_does_not_read():
    """The other direction, and the one #62 got wrong. A declaration on a field the query only GROUPS
    by would warn about an undercount that cannot occur: a group-by returns the affected records under
    a `REDACTED` bucket rather than dropping them."""
    for name, tpl in TEMPLATES.items():
        for field in tpl.get("redactable_filter", ()):
            assert field == "SingleHeader:host", f"{name} declares {field}, unexpected"
            assert "host" in tpl.get("params", []), \
                f"{name} declares a host predicate and takes no host param, so it cannot filter on one"
    for key, spec in _FILTERS.items():
        for field in spec.redactable_filter:
            probe = spec.athena + " " + spec.cwl
            token = "httpmethod" if field == "Method" else "host"
            assert token in probe.lower(), \
                f"filter {key!r} declares {field} and its predicate does not read it: {probe}"


def test_two_of_the_four_redaction_types_have_no_filter_surface_at_all():
    """Stated as a test because it is the thing that makes the surface small, and a future filter on
    a URI or a query string would need a declaration this file does not yet require."""
    everything = {f for v in _FILTERS.values() for f in v.redactable_filter}
    everything |= {f for v in TEMPLATES.values() for f in v.get("redactable_filter", ())}
    assert not {"UriPath", "QueryString"} & everything, (
        f"a filter now reads UriPath or QueryString: {sorted(everything)}. Add it to the expected "
        f"sets above rather than deleting this test.")


# --- the notice -------------------------------------------------------------

def test_the_notice_fires_only_when_the_config_actually_redacts_that_field():
    """Both directions on one mechanism, because a notice that always fires and one that never fires
    are equally uninformative."""
    _reset(("SingleHeader:host",))
    q.note_redacted_filter(("SingleHeader:host",))
    note = q.drain_log_value_findings()
    assert "REDACTED_FILTER" in note and "SingleHeader:host" in note, note
    _reset(("SingleHeader:host",))
    q.note_redacted_filter(("Method",))
    assert q.drain_log_value_findings() == "", "a field the config does not redact raised a notice"
    _reset(())
    q.note_redacted_filter(("SingleHeader:host",))
    assert q.drain_log_value_findings() == "", "no redaction configured and the notice still fired"


def test_the_notice_says_a_zero_row_result_does_not_mean_no_traffic():
    """The one sentence the notice exists for. A filter on a redacted field can empty the result, and
    both modules' zero-row message offers three causes that do not include this one, so without this
    the reader concludes the traffic does not exist.

    Also corrects a line 6.13 wrote for the display half: "redaction does not produce zero rows" holds
    for a group-by and is false for a filter."""
    _reset(("Method",))
    q.note_redacted_filter(("Method",))
    note = q.drain_log_value_findings()
    assert "zero-row" in note and "does NOT mean no such traffic" in note, note
    for phrase in ("undercount", "partial", "cannot be recovered"):
        assert phrase in note, f"the notice does not say the undercount is {phrase}"
    assert "group BY that field instead" in note, "the notice offers no way forward"


def test_the_notice_reaches_the_model_through_the_hook_not_a_render_branch():
    """Delivery, which is the property that makes the zero-row path safe.

    Driven through the hook rather than through a renderer, because the point is that no renderer is
    involved: the two early-returning branches never see this string."""
    _reset(("SingleHeader:host",))
    q.note_redacted_filter(("SingleHeader:host",))
    event = _FakeEvent([{"text": "Query returned 0 results"}])
    agent.LogValueDisclosure().append_disclosure(event)
    assert "REDACTED_FILTER" in event.result["content"][-1]["text"], \
        "the notice never reached the tool result"
    assert event.result["content"][0] == {"text": "Query returned 0 results"}, \
        "the notice was merged into the zero-row message instead of appended"


def test_running_a_declared_filter_records_it_without_reaching_aws():
    """The wiring, asserted at the layer that decides rather than on the helper.

    `test_the_notice_fires...` proves the helper works; this proves a real filter dimension calls it.
    `aggregate_logs` is exercised through its query builder, which is the function that turns a filter
    key into a predicate, so this fails if the call is dropped from the loop."""
    from tools.waf_aggregate import _build
    _reset(("SingleHeader:host",))
    _build("clientIp", "count", {"host": "example.com"}, 5, 60)
    assert "SingleHeader:host" in q.drain_log_value_findings(), \
        "building an aggregate filtered on a redacted header recorded nothing"
    _reset(("Method",))
    _build("clientIp", "count", {"method": "GET"}, 5, 60)
    assert "Method" in q.drain_log_value_findings(), "the method filter recorded nothing"


class _FakeEvent:
    def __init__(self, content):
        self.tool_use = {"name": "run_logs_query", "toolUseId": "t1"}
        self.result = {"toolUseId": "t1", "status": "success", "content": content}
