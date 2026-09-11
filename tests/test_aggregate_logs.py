# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""ROADMAP 4.1: the composable primitive, and the things a generator gets silently wrong.

`aggregate_logs` can emit 13 group dimensions x 3 metrics x 9 filter dimensions in two dialects.
Nobody reads that by eye, and the failure mode is not a crash: one dimension whose Athena
expression is wrong returns all-NULL, which reads as "that field is not populated on this
upstream". So the tests here are sweeps over what the dispatch tables can be ASKED for, not
examples of a few combinations someone thought of.

**Query VALIDITY is verified separately and on the real engines**, by
`design/scripts/verify-aggregate-queries.py`: every group dimension, every metric, every filter
both as a scope and as a ratio numerator, plus each branch of the rule predicate against a match
only that branch can find. A unit test cannot tell a legal query from an illegal one, so it does
not try; it checks the properties that survive without an engine.

The three properties below are the ones worth having, and each is here because getting it wrong
produces a plausible answer rather than an error:

1. **A dimension must reach BOTH engines or neither.** An entry with only an Athena expression
   works perfectly until someone with CloudWatch logging asks for it.
2. **A refused value must not appear in the query anyway.** Refuse-not-substitute is only real if
   nothing downstream interpolates the original.
3. **The percentile scale is per-engine and one direction fails silently.** Athena rejects 95;
   CloudWatch accepts 0.95 and returns the near-minimum. Measured: 1 where the answer was 289549.
"""

import json
import re

import pytest

from tools import waf_aggregate as AG

# Values that pass each dimension's validator, so a sweep exercises the predicate rather than the
# refusal. Keyed by dimension so a new filter without an entry fails the precondition below
# instead of being quietly skipped.
VALID = {
    "action": "BLOCK",
    "rule": "AWS-AWSManagedRulesCommonRuleSet",
    "ip": "203.0.113.9",
    "country": "CN",
    "method": "POST",
    "ruletype": "RATE_BASED",
    "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
    "label": "awswaf:managed:token:absent",
    "host": "example.com",
}


def test_the_sweeps_below_cover_every_dimension_the_module_offers():
    """The precondition. Every assertion in this file iterates a dispatch table, so a table that
    lost its entries, or a `VALID` map that fell behind a new filter dimension, would make the
    sweeps pass over nothing. Named subjects rather than counts: a count passes on the wrong set."""
    assert {"clientIp", "uri", "country", "label", "time_bucket"} <= set(AG._GROUP_BY), \
        sorted(AG._GROUP_BY)
    assert {"action", "rule", "ip", "label", "host"} <= set(AG._FILTERS), sorted(AG._FILTERS)
    assert set(VALID) == set(AG._FILTERS), {
        "filter dimensions with no test value, so they are never exercised":
            sorted(set(AG._FILTERS) - set(VALID)),
        "test values for filters that no longer exist": sorted(set(VALID) - set(AG._FILTERS))}
    assert AG._METRICS == ("count", "ratio", "percentile"), AG._METRICS


# --- 1. both engines or neither ---------------------------------------------


@pytest.mark.parametrize("group_by", sorted(AG._GROUP_BY))
def test_every_group_dimension_renders_in_both_dialects(group_by):
    """The pairing invariant, which is the whole reason the dimensions live in one table.

    A dimension present on one engine only is not a crash: an Athena user gets their answer and a
    CloudWatch user gets a query referring to a field that does not exist, which Insights returns
    as empty rather than as an error. That reads as "no traffic"."""
    cwl, athena = AG._build(group_by, "count", {}, 5, 25)
    assert "stats count(*) as hits by" in cwl, cwl
    assert "count(*) AS hits" in athena, athena
    # **Both engines must label the column identically**, which is the assertion this started as
    # "the dimension key appears in both" and should not have been. CloudWatch has no `as` on a
    # plain field, so its header is the field path (`terminatingRuleType`); an Athena alias of
    # `ruletype` would mean the same request comes back with different headers per backend, and
    # anything downstream reading a column by name breaks on one of them. Found by this test
    # failing on three dimensions.
    a_col = re.search(r'AS "([^"]+)"', athena)
    assert a_col, f"{group_by} has no aliased Athena column: {athena}"
    cwl_col = cwl.split("stats count(*) as hits by ")[1].split(" |")[0].strip()
    cwl_col = cwl_col.split(" as ")[-1].strip()
    assert cwl_col == a_col.group(1), (
        f"{group_by} returns '{cwl_col}' on CloudWatch and '{a_col.group(1)}' on Athena")
    # And each side must actually HAVE an expression. Agreeing column names are not enough: an
    # empty Athena expression renders `SELECT  AS "terminatingRuleType"`, which is invalid SQL and
    # left both assertions above true. Found by the perturbation reporting HOLLOW.
    a_expr = athena.split("SELECT ", 1)[1].split(" AS ", 1)[0].strip()
    assert a_expr, f"{group_by} has no Athena expression: {athena}"
    assert cwl.split("stats count(*) as hits by ")[1].split(" |")[0].strip(), \
        f"{group_by} has no CloudWatch field: {cwl}"
    # `{TABLE}`, `{START_MS}`, `{END_MS}` and `{PARTITION_FILTER}` are substituted by
    # `query_logs`. A dimension that forgot the partition filter would scan the whole bucket.
    for token in ("{TABLE}", "{START_MS}", "{END_MS}", "{PARTITION_FILTER}", "{LIMIT}"):
        assert token in athena, f"{group_by} lost {token}: {athena}"


@pytest.mark.parametrize("key", sorted(AG._FILTERS))
def test_every_filter_dimension_renders_in_both_dialects(key):
    """Same invariant on the filter side, plus the value actually landing in the predicate.

    Asserting the value is present is what makes this more than a smoke test: a template whose
    `{v}` placeholder was misspelled renders a predicate comparing against the literal string
    `{v}`, which is syntactically fine and matches nothing."""
    value = VALID[key]
    cwl, athena = AG._build("uri", "count", {key: value}, 5, 25)
    assert value in cwl, f"{key} value never reached the CloudWatch query: {cwl}"
    assert value in athena, f"{key} value never reached the Athena query: {athena}"
    assert "{v}" not in cwl and "{v}" not in athena, f"{key} left its placeholder unrendered"


def _arg_blocks() -> dict:
    """`{parameter: its Args: paragraph}` from the docstring the model is actually sent.

    **Scoped per paragraph, because a whole-docstring substring check proved almost nothing.**
    Eight of the nine filter dimensions are also group dimensions, so `"host" in doc` was
    satisfied by the `group_by` list, and dropping `host` from the `filter_by` list left the test
    green. Found by the perturbation reporting HOLLOW. Same shape as excluding the registration
    site rather than the whole module: the search space has to be the claim's.

    The indent is derived from the first argument line rather than assumed. A hard-coded 8 spaces
    was the first version and matched nothing, because the docstring reaches here dedented: the
    split returned ONE block holding every argument, which would have made every assertion below
    vacuous had they not all failed at once."""
    doc = AG.aggregate_logs.__doc__ or AG.aggregate_logs._tool_func.__doc__
    body = doc.split("Args:", 1)[1].split("Returns:", 1)[0]
    first = next(line for line in body.splitlines() if line.strip())
    indent = len(first) - len(first.lstrip())
    blocks = {}
    for chunk in re.split(rf"\n {{{indent}}}(?=\w+:)", body):
        if not chunk.strip():
            continue  # the whitespace before the first argument
        name = chunk.strip().split(":", 1)[0]
        blocks[name] = chunk
    return blocks


def test_the_docstring_documents_exactly_the_parameters_the_tool_takes():
    """The precondition for the three sweeps below, and it pins the split as well as the docs.

    A degenerate split yields one block named after the first argument, which satisfies any
    "is this dimension documented" check for every dimension mentioned anywhere. Comparing the
    block names against the real signature catches that, and separately catches an argument that
    was renamed in code and not in the docstring the model reads."""
    import inspect
    params = set(inspect.signature(AG.aggregate_logs._tool_func).parameters)
    assert set(_arg_blocks()) == params, {
        "documented but not a parameter": sorted(set(_arg_blocks()) - params),
        "parameters the model is never told about": sorted(params - set(_arg_blocks()))}


def _arg_block(name: str) -> str:
    return _arg_blocks()[name]


@pytest.mark.parametrize("key", sorted(AG._FILTERS))
def test_a_filter_dimension_is_named_where_filter_by_is_documented(key):
    """A dimension the model is never told about is dead surface, one level down from
    `test_tool_reachability.py`'s claim about tools.

    The docstring IS the schema the model reads, so a dimension missing from it can only be
    reached by guessing. The cost of the gap is invisible, because the feature works perfectly for
    anyone who knows it is there."""
    assert key in _arg_block("filter_by"), \
        f"filter dimension '{key}' is not named where filter_by is documented"


@pytest.mark.parametrize("group_by", sorted(AG._GROUP_BY))
def test_a_group_dimension_is_named_where_group_by_is_documented(group_by):
    assert group_by in _arg_block("group_by"), \
        f"group dimension '{group_by}' is not named where group_by is documented"


@pytest.mark.parametrize("metric", AG._METRICS)
def test_a_metric_is_named_where_metric_is_documented(metric):
    """The third dispatch table, swept for the same reason as the other two."""
    assert metric in _arg_block("metric"), f"metric '{metric}' is not documented"


@pytest.mark.parametrize("key", sorted(AG._FILTERS))
def test_no_filter_matches_the_raw_record_instead_of_a_field(key):
    """**The general form of a real defect, which is why this is a sweep and not one assertion.**

    The `label` filter shipped as `@message like '{v}'`, a substring test over the WHOLE record.
    So `filter_by={"label": "bot"}` also matched a `User-Agent: Googlebot`, a `/robots.txt` URI and
    a referer containing "bot", none of them carrying any label, while Athena matched label names
    only. One filter, two meanings, depending on which backend the WebACL happens to log to.
    Measured: the URI `k6test` matched 293371 records that way and 0 once scoped.

    It came from copying the `label_top_ips` template, and the `host` entry in the same table
    already stated the principle it broke. A per-dimension assertion would have needed someone to
    suspect `label` specifically; enumerating the filters catches the next one to be written this
    way, which is the direction that matters given the copy is right there to be made.

    **A bare `@message` ban was the first version and it was too blunt**: it flagged the `rule`
    filter, whose `@message like '"ruleId":"{v}"'` is how CloudWatch reaches all four nested rule
    arrays at once, with no array accessor available. That predicate is ANCHORED, to a JSON key, so
    the value cannot be satisfied by turning up in a URI. `label`'s was anchored to nothing.

    So the property is the anchoring, not the absence of `@message`: a raw-record comparison must
    carry a quote character, which is what puts the value inside a JSON key/value pair rather than
    loose in the record. `@message` in a PRELUDE is fine either way, since a `parse` has to read
    the raw record to produce a field at all."""
    spec = AG._FILTERS[key]
    if "@message" not in spec.cwl:
        return
    # Only the literals belonging to a `@message` comparison. Taking EVERY quoted literal was the
    # second wrong version: it flagged `rule` again, this time for its `terminatingRuleId = '{v}'`
    # clause, which is a field comparison and needs no anchoring. The search space has to be the
    # claim's, which is the lesson this whole file keeps relearning.
    literals = re.findall(r"@message\s+(?:not\s+)?like\s+'([^']*)'", spec.cwl)
    assert literals, f"the {key} filter names @message outside a `like`: {spec.cwl}"
    for lit in literals:
        assert '"' in lit, (
            f"the {key} filter matches the raw record with an unanchored value, so it also matches "
            f"that value appearing in any other field: {lit!r} in {spec.cwl}")


def test_the_label_filter_sees_every_label_and_only_labels():
    """The two halves of the label fix, and each rules out one of the wrong answers.

    Scoped to the `labels` array, so a value occurring in a URI or a User-Agent cannot satisfy it.
    And scoped to the WHOLE array rather than one extracted name, so it does not inherit the group
    dimension's first-label-only limit: a record's capture carried all 8 of its labels, verified on
    the live group, where a real label returns the same 293371 either way."""
    cwl, athena = AG._build("action", "count", {"label": "bot"}, 5, 25)
    assert '"labels"' in cwl, f"the filter is not scoped to the labels array: {cwl}"
    assert "lbls like 'bot'" in cwl, cwl
    # The extraction that reads only the first label must NOT be in the pipeline when `label` is
    # merely a filter, or the filter would test one name instead of the array.
    assert '(?<label>' not in cwl, f"the filter went through the first-label extraction: {cwl}"
    assert "strpos(l.name" in athena, athena


def test_the_shared_labels_stage_is_emitted_once_when_it_is_both_group_and_filter():
    """`group_by="label"` and `filter_by={"label": ...}` need the same capture. As single strings
    the two preludes differed, nothing deduplicated them, and `lbls` was defined a second time
    after it had already been read. Stages are deduplicated element-wise for this case."""
    cwl, _ = AG._build("label", "count", {"label": "bot"}, 5, 25)
    assert cwl.count(AG._LABELS_ARRAY) == 1, cwl
    # Order still has to hold: the capture, then the extraction that reads it, then the filter.
    assert cwl.index(AG._LABELS_ARRAY) < cwl.index('(?<label>') < cwl.index("lbls like"), cwl


def test_a_header_dimension_emits_its_cloudwatch_parse_before_any_filter():
    """CloudWatch has no array accessor, so a header is reached by parsing the raw JSON, and
    `parse` must come before any `filter` naming the parsed field. Emitted in the wrong order the
    query is rejected; omitted entirely it silently filters on an unset field and matches nothing.

    The discriminating case is a header used ONLY as a filter, never as the group dimension, since
    that is the path where the parse has no other reason to be emitted."""
    cwl, _ = AG._build("clientIp", "count", {"host": "example.com"}, 5, 25)
    assert cwl.index("parse @message") < cwl.index("filter "), cwl
    assert '"name":"host"' in cwl, cwl
    # And not duplicated when the same header is both the group dimension and the filter.
    both, _ = AG._build("host", "count", {"host": "example.com"}, 5, 25)
    assert both.count("parse @message") == 1, both


# --- 2. refuse, and do not interpolate anyway -------------------------------

# One per dimension, each shaped to break out of the single-quoted literal it would land in.
# `rule` and `ip` route to the shared validator and the real parser respectively, so they are
# swept here to prove the dispatch reaches them, not to re-test them.
BREAKING = ["x' OR '1'='1", "x'--", 'x"', "x' AND action = 'BLOCK", "x\\", "x;y", "x'||'"]


@pytest.mark.parametrize("key", sorted(AG._FILTERS))
@pytest.mark.parametrize("bad", BREAKING)
def test_a_value_that_would_break_out_of_a_literal_is_refused(key, bad):
    """Every dimension, every shape, through the public parameter rather than the validator.

    Swept over dimensions instead of spot-checked, because the defect this guards against is one
    dimension whose entry has no validator, and a spot check finds that only by luck. The audit
    that missed two unguarded `rule_name` sites failed exactly this way: it enumerated the
    sanitisers that existed rather than the inputs that reach a query, so a dimension with no
    guard had nothing to find."""
    filters, err = AG._parse_filters(json.dumps({key: bad}))
    assert err is not None, f"{key}={bad!r} was accepted"
    assert filters == {}, "a refusal must not hand back a partially built filter set"


@pytest.mark.parametrize("key", sorted(AG._FILTERS))
def test_a_refused_value_never_reaches_a_query(key):
    """The half that makes refusing meaningful. A guard that refuses and then lets the caller
    interpolate the original value is the defect `checked_rule_name` shipped with: it decided on a
    normalised copy, returned only a verdict, and two of three callers used the raw input."""
    bad = "x' OR '1'='1"
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", group_by="uri",
                                       filter_by=json.dumps({key: bad}))
    assert "Error" in out, out[:200]
    # The refusal echoes what the caller typed, on purpose, so the model can see what it sent.
    # What must not happen is the value reaching a QUERY, and the tool returning before any
    # query is built is how that is guaranteed here.
    assert "rows" not in out.lower(), f"a refused {key} still produced a result: {out[:200]}"


def test_edge_whitespace_is_removed_rather_than_carried_into_the_literal():
    """The bug this file inherits rather than discovers. `rule_name_error` tolerated a padded name
    and passed the padding on, so `r.ruleid = 'MyRule '` matched nothing and an empty result stood
    in for a verdict. Every validator here returns the value it decided on."""
    filters, err = AG._parse_filters(json.dumps({"country": "  CN  ", "action": " BLOCK "}))
    assert err is None, err
    assert filters == {"country": "CN", "action": "BLOCK"}
    _, athena = AG._build("uri", "count", filters, 5, 25)
    assert "'CN'" in athena and "' CN" not in athena, athena


@pytest.mark.parametrize("raw,why", [
    ("{'action': 'BLOCK'}", "single quotes are not JSON"),
    ("[1, 2]", "a JSON array is not an object"),
    ('"BLOCK"', "a bare JSON string is not an object"),
    ('{"nope": "BLOCK"}', "an unknown dimension"),
    ('{"action": 5}', "a non-string value"),
])
def test_filter_by_refuses_what_it_cannot_read(raw, why):
    """`filter_by` is a JSON STRING by decision, which means the model can get the string wrong in
    ways a dict parameter could not. Each of these has to name what is wrong, because the model's
    only recovery is reading the refusal."""
    filters, err = AG._parse_filters(raw)
    assert err is not None, f"accepted {raw!r} ({why})"
    assert filters == {}


def test_an_unknown_key_or_metric_is_refused_with_the_valid_ones_listed():
    """The refusal has to carry the list, or the model's next move is another guess. Derived from
    the dispatch tables rather than hard-coded, so a new dimension is advertised for free."""
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", group_by="clientip")
    assert "not a group_by dimension" in out
    for name in AG._GROUP_BY:
        assert name in out, f"the refusal does not offer {name}"
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", metric="average")
    assert "not a metric" in out
    for name in AG._METRICS:
        assert name in out


# --- 3. the percentile scale, per engine ------------------------------------


def test_the_percentile_scale_is_right_for_each_engine():
    """The one divergence where a mistake is silent on one side.

    Athena's `approx_percentile` takes a 0-1 fraction and REJECTS 95 outright, measured:
    `INVALID_FUNCTION_ARGUMENT: Percentile must be between 0 and 1`. CloudWatch's `pct` takes
    0-100 and quietly accepts 0.95, returning the near-minimum: measured as 1 where the 95th
    percentile was 289549. So the loud direction needs no test and the silent one does.

    Asserted as the INVARIANT rather than as the expected numbers. Checking that "95" appears in
    one string and "0.95" in the other restates the code; checking that no CloudWatch percentile
    argument is below 1 and no Athena one is above 1 is the property that has to hold whatever
    percentiles ship, and it fails if the two are ever swapped."""
    cwl, athena = AG._build("clientIp", "percentile", {}, 5, 25)
    cwl_args = [float(m) for m in re.findall(r"pct\(c,\s*([0-9.]+)\)", cwl)]
    athena_args = [float(m) for m in re.findall(r"approx_percentile\(c,\s*([0-9.]+)\)", athena)]
    assert cwl_args, f"no pct() call in the CloudWatch query: {cwl}"
    assert athena_args, f"no approx_percentile() call in the Athena query: {athena}"
    assert len(cwl_args) == len(athena_args) == len(AG._PERCENTILES)
    assert all(a > 1 for a in cwl_args), f"CloudWatch pct() needs 0-100, got {cwl_args}"
    assert all(a < 1 for a in athena_args), \
        f"Athena approx_percentile() needs 0-1, got {athena_args}"
    # Same percentiles on both engines, which is what one shared tuple is for.
    assert [round(a / 100, 10) for a in cwl_args] == [round(a, 10) for a in athena_args]


def test_percentile_buckets_only_in_the_first_stats():
    """`bin()` in a second `stats` is rejected by CloudWatch, measured: `Compile Error - Unknown
    symbols found in or after stats: @timestamp`. It reads `@timestamp` implicitly and a later
    stats cannot see a field the preceding one did not define."""
    cwl, _ = AG._build("clientIp", "percentile", {}, 5, 25)
    # Split on the `stats` commands themselves, not on `"| stats"`. The first `stats` has no
    # leading pipe when there is no prelude or filter, so the pipe-based split silently yielded
    # one part and the test errored instead of asserting. A split that finds fewer stages than the
    # query has would have passed vacuously had it not raised.
    stages = cwl.split("stats ")
    assert len(stages) == 3, f"expected exactly two stats stages: {cwl}"
    assert "bin(" in stages[1], cwl
    assert "bin(" not in stages[2], f"bin() in the second stats is rejected outright: {cwl}"


# --- what ratio means, which is the property 4.2 builds on ------------------


def test_a_ratio_puts_its_filter_in_the_numerator_and_not_in_the_where_clause():
    """The defining property of `metric="ratio"`, and the one that makes the number a RATE.

    If the filter also scoped the query, matched and total would both be filtered and every group
    would read 100%: a plausible-looking table of meaningless numbers, which is the worst failure
    shape available here. Asserted by locating the value rather than by matching a whole string,
    so it survives any rewording of the SQL."""
    filters = {"rule": VALID["rule"]}
    cwl, athena = AG._build("uri", "ratio", filters, 5, 25)
    where = athena.split(" WHERE ", 1)[1].split(" GROUP BY ", 1)[0]
    assert VALID["rule"] not in where, f"the numerator also scoped the query: {where}"
    assert VALID["rule"] in athena.split(" WHERE ", 1)[0], "the numerator is not in the SELECT"
    assert "count_if" in athena and "hit_rate_pct" in athena, athena
    assert "sum(if(" in cwl and "hit_rate_pct" in cwl, cwl
    assert not cwl.startswith("filter "), f"the numerator also scoped the CloudWatch query: {cwl}"

    # And the contrast, which is what proves the assertion above is about `ratio` and not about
    # the value being absent everywhere: with `count` the same filter DOES scope the query.
    cwl_c, athena_c = AG._build("uri", "count", filters, 5, 25)
    assert VALID["rule"] in athena_c.split(" WHERE ", 1)[1], athena_c
    assert "filter " in cwl_c, cwl_c


def test_a_ratio_with_no_numerator_is_refused_rather_than_answered():
    """Without a filter every group reads 100%, which is a table of numbers that all look fine."""
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", group_by="uri",
                                       metric="ratio")
    assert "needs filter_by" in out, out[:200]


def test_the_rule_filter_names_all_four_places_a_match_is_recorded():
    """The nested-COUNT trap, ROADMAP 2.6. A rule match lands in one of four places and a filter
    built on fewer misses exactly the case a COUNT investigation is looking for.

    The existing `rule_uri_prefix` template covers three of the four, so this is the assertion
    that stops someone copying it. Verified against real data by
    `verify-aggregate-queries.py`'s `nested` phase, which matches each branch with a rule only
    that branch can find: 4 hits via `rulegrouplist[].nonterminatingmatchingrules[]`, 30136 via
    `ratebasedrulelist`, 30136 via the top-level id. The fourth,
    `rulegrouplist[].terminatingrule`, is NULL on every row of that window, so it is asserted
    here and unexercised there."""
    _, athena = AG._build("uri", "count", {"rule": "R"}, 5, 25)
    for path in ("terminatingruleid = 'R'",
                 "any_match(nonterminatingmatchingrules",
                 "rg.terminatingrule.ruleid = 'R'",
                 "any_match(rg.nonterminatingmatchingrules",
                 "rb.ratebasedrulename = 'R'"):
        assert path in athena, f"the rule filter cannot match via {path}: {athena}"


def test_the_label_filter_uses_no_wildcard_metacharacter():
    """`LIKE '%v%'` would widen the filter past what it says: `_` is in the validated label
    charset AND is a LIKE wildcard matching any single character, so `bot_verified` would also
    match `botXverified`. A filter matching more than it claims is the defect class this item
    kept producing, so the substring test is spelled without wildcards."""
    _, athena = AG._build("uri", "count", {"label": "awswaf:managed:token:absent"}, 5, 25)
    assert "strpos(" in athena, athena
    assert "LIKE" not in athena.upper().replace("ANY_MATCH", ""), athena


def test_the_time_bucket_column_is_named_so_the_timezone_shift_finds_it():
    """`waf_query._shift_time_fields` converts CloudWatch's UTC output to the session timezone by
    matching column NAMES. A bucket column named anything else comes back in UTC while every
    other tool returns local time, and the agent then misreports the hour of an event: a wrong
    answer that looks like a right one.

    Asserted against the real set rather than the string `"time_bucket"`, so renaming one and not
    the other fails here instead of in an incident."""
    from tools.waf_query import _TIME_FIELD_NAMES
    cwl, athena = AG._build("time_bucket", "count", {}, 5, 25)
    named = re.findall(r"as (\w+)", cwl) + re.findall(r'AS "(\w+)"', athena)
    assert set(named) & _TIME_FIELD_NAMES, (
        f"no bucket column is in _TIME_FIELD_NAMES {sorted(_TIME_FIELD_NAMES)}, so CloudWatch "
        f"results stay in UTC: {named}")
    # The Athena side offsets in SQL, so it must carry the placeholder `query_logs` fills in.
    assert "{TZ_OFFSET_SECONDS}" in athena, athena


def test_the_window_and_bucket_are_refused_when_the_bucket_cannot_divide_it():
    """A bucket wider than the window puts every request in one bucket, so a percentile over
    those buckets has a sample size of one and reports the total as its own p99. Refused with the
    two numbers, because the model chose one of them and clamping was applied to the other."""
    out = AG.aggregate_logs._tool_func(start_time="2026-09-10T00:00", duration_minutes=30,
                                       group_by="clientIp", metric="percentile",
                                       bucket_minutes=60)
    assert "larger than the window" in out, out[:200]
    assert "60" in out and "30" in out, out[:200]
