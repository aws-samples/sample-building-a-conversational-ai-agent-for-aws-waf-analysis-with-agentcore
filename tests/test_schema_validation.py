# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Bind-time schema validation of a user's own Athena table.

ROADMAP 6.12 step 3, issue #2 acceptance item 4. Validation used to be name-only, on
`action` and `httprequest`. A table whose `httprequest` was the wrong shape, or whose
`timestamp` was declared `string`, bound successfully and then failed once per query
with a raw Athena error naming a column but not saying what the agent wanted it for.

Three tiers, all swept from `_COLUMN_SPEC` rather than re-listed here, so moving a
column between tiers cannot leave a stale assertion passing. REQUIRED means nothing
worth running runs, so the table is refused. SHARED_ONLY means refused on a table whose
location covers several WebACLs and not asked for otherwise. OPTIONAL means accepted
with the lost features named.
"""

import pytest

from tools import waf_athena as A
from test_table_resolution import WAF_COLS

TIERS = {tier: sorted(c for c, (t, *_) in A._COLUMN_SPEC.items() if t == tier)
         for tier in (A.REQUIRED, A.SHARED_ONLY, A.OPTIONAL)}


def cols(**overrides):
    """The columns a table built from DDL_TEMPLATE has, with edits applied.

    A value of None drops the column; a string replaces its type."""
    out = []
    for c in WAF_COLS:
        if c["Name"] in overrides:
            if overrides[c["Name"]] is None:
                continue
            out.append({"Name": c["Name"], "Type": overrides[c["Name"]]})
        else:
            out.append(dict(c))
    return out


def check(shared=True, **overrides):
    """Validate an edited DDL_TEMPLATE schema. Shared location by default, which is the
    stricter case: it is the one where `webaclid` is asked for."""
    types = {c["Name"].lower(): c["Type"].lower() for c in cols(**overrides)}
    return A._check_schema("db.t", types, shared_location=shared)


def trimmed(col, drop):
    """`col`'s declared type with one top-level field removed, wrapper preserved."""
    original = next(c["Type"] for c in WAF_COLS if c["Name"] == col)
    kept = [f for f in A._struct_fields(original) if f != drop]
    typ = f"struct<{','.join(f'{f}:string' for f in kept)}>"
    return f"array<{typ}>" if original.strip().lower().startswith("array<") else typ


def test_every_tier_is_non_empty_and_they_partition_the_spec():
    """The load-bearing guard for every sweep below, and the only test that can catch an
    emptied tier. `parametrize` over an empty list SKIPS rather than fails, so moving the
    last column out of a tier makes its sweeps silently stop running and report green.
    Perturbation-checked: emptying SHARED_ONLY leaves its own tests skipped, and this is
    what goes red."""
    assert sum(len(v) for v in TIERS.values()) == len(A._COLUMN_SPEC)
    assert all(TIERS.values()), TIERS


def test_the_agents_own_schema_is_clean():
    """An invariant, and the precondition every other test rests on: DDL_TEMPLATE is
    where the required schema is defined, so a table built from it needs neither a
    rejection nor a note. Without this a sweep below could 'pass' because the baseline
    was already broken."""
    assert check(shared=True) == (None, None)
    assert check(shared=False) == (None, None)


# --- REQUIRED: refuse, and say which column and why ------------------------


@pytest.mark.parametrize("col", TIERS[A.REQUIRED])
def test_a_required_column_is_refused_when_absent(col):
    rejection, note = check(**{col: None})
    assert rejection is not None and f"`{col}`" in rejection
    assert note is None


@pytest.mark.parametrize("col", TIERS[A.REQUIRED])
def test_a_required_column_is_refused_when_wrongly_typed(col):
    """The half name-only checking could never see."""
    kind = A._COLUMN_SPEC[col][1]
    wrong = "bigint" if kind == "string" else "string"
    rejection, note = check(**{col: wrong})
    assert rejection is not None
    assert f"`{col}`" in rejection and wrong in rejection
    assert note is None


@pytest.mark.parametrize("col,field", sorted(
    (c, f) for c in TIERS[A.REQUIRED] for f in A._COLUMN_SPEC[c][2]))
def test_a_required_nested_field_is_refused_when_absent(col, field):
    """Drop one field and keep the rest, which is what a hand-written subset or an older
    WAF schema actually looks like."""
    rejection, _ = check(**{col: trimmed(col, field)})
    assert rejection is not None
    assert field in rejection and f"`{col}`" in rejection


@pytest.mark.parametrize("col", sorted(A._COLUMN_SPEC))
def test_every_why_splices_into_both_sentence_frames(col):
    """One `why` string feeds three frames: `It is read by <why>.`, `..., but it is read
    by <why>, so ...`, and `` `col`, needed by <why> ``. A `why` written as a full clause
    reads correctly in none of them, and that was the actual defect: `timestamp` carried
    'every window bound is `"timestamp" BETWEEN` epoch milliseconds', which rendered as
    "missing WAF log column `timestamp`, which every window bound is ...". Guards the two
    mechanical properties that produced it."""
    why = A._COLUMN_SPEC[col][3]
    assert why and not why.endswith("."), why
    opening = set(why.split(",")[0].split())
    assert not (opening & {"is", "are", "was", "were", "has", "have"}), why


# --- SHARED_ONLY: required only when the location covers several WebACLs ----


@pytest.mark.parametrize("col", TIERS[A.SHARED_ONLY])
def test_a_shared_only_column_is_refused_on_a_shared_location(col):
    rejection, _ = check(shared=True, **{col: None})
    assert rejection is not None and f"`{col}`" in rejection


@pytest.mark.parametrize("col", TIERS[A.SHARED_ONLY])
def test_a_shared_only_column_is_not_asked_for_on_a_scoped_table(col):
    """The wrong refusal this tier exists to prevent. On a vended-log table whose
    location already names the WebACL, no query mentions `webaclid`, so refusing the
    table over it would refuse a table for a column nothing reads."""
    rejection, note = check(shared=False, **{col: None})
    assert rejection is None, rejection
    assert note is None, note


# --- OPTIONAL: accept, and name what is lost -------------------------------


@pytest.mark.parametrize("col", TIERS[A.OPTIONAL])
def test_a_missing_optional_column_is_a_note_and_not_a_refusal(col):
    rejection, note = check(**{col: None})
    assert rejection is None, rejection
    assert note is not None and f"`{col}`" in note
    assert A._COLUMN_SPEC[col][3] in note


@pytest.mark.parametrize("col", TIERS[A.OPTIONAL])
def test_a_wrongly_typed_optional_column_reads_as_lost(col):
    """Absent and unusable lose the same queries, so they get the same sentence."""
    kind = A._COLUMN_SPEC[col][1]
    rejection, note = check(**{col: "bigint" if kind != "int" else "string"})
    assert rejection is None, rejection
    assert note is not None and f"`{col}`" in note


@pytest.mark.parametrize("col,field", sorted(
    (c, f) for c in TIERS[A.OPTIONAL] for f in A._COLUMN_SPEC[c][2]))
def test_an_optional_column_missing_a_dereferenced_field_reads_as_lost(col, field):
    rejection, note = check(**{col: trimmed(col, field)})
    assert rejection is None, rejection
    assert note is not None and f"`{col}`" in note


def test_the_note_keeps_each_column_beside_its_own_reason():
    """The defect this asserts against: two independently sorted lists, one of columns
    and one of reasons, invite positional pairing and every pair is wrong. Drop three
    optional columns whose alphabetical order differs from their reasons' and require
    each column to be adjacent to its own reason."""
    dropped = ["captcharesponse", "challengeresponse", "ja4fingerprint"]
    _, note = check(**{c: None for c in dropped})
    assert note is not None
    for col in dropped:
        why = A._COLUMN_SPEC[col][3]
        assert f"`{col}`, needed by {why}" in note, note
    # And the reasons are not emitted as a second detached list.
    for col in dropped:
        assert note.count(f"`{col}`") == 1


def test_a_table_predating_labels_is_accepted():
    """The case that made this a two-tier check rather than one list. AWS WAF added
    columns over the years and JsonSerDe ignores fields a table does not declare, so a
    Glue table written before `labels`, `ja4fingerprint` and `challengeresponse` existed
    still reads today's logs. Refusing it is what bring-your-own-table exists to avoid.
    `labels` is the load-bearing part: it used to be in the required tier, so this shape
    was refused outright."""
    old = {c: None for c in ("labels", "ja3fingerprint", "ja4fingerprint",
                            "challengeresponse", "captcharesponse", "oversizefields",
                            "requestbodysize", "requestbodysizeinspectedbywaf")}
    rejection, note = check(**old)
    assert rejection is None, rejection
    assert note is not None
    for named in ("labels", "ja4fingerprint", "challengeresponse", "captcharesponse"):
        assert f"`{named}`" in note
    # ja3fingerprint is declared by DDL_TEMPLATE and read by nothing, so warning about
    # it would name a feature that does not exist.
    assert "ja3" not in note


def test_the_older_17_column_shape_in_the_verification_account():
    """Two real tables in account 636696231660 declare exactly this. Kept alongside the
    pre-labels case because it is the shape actually present, and it does have `labels`,
    which is why on its own it could not have caught the required-tier mistake."""
    old = {"ja3fingerprint": None, "ja4fingerprint": None, "challengeresponse": None,
           "oversizefields": None, "requestbodysize": None,
           "requestbodysizeinspectedbywaf": None,
           "httprequest": "struct<clientip:string,country:string,"
                          "headers:array<struct<name:string,value:string>>,uri:string,"
                          "args:string,httpversion:string,httpmethod:string,"
                          "requestid:string>"}
    rejection, note = check(**old)
    assert rejection is None
    assert note is not None
    assert "`ja4fingerprint`" in note and "`challengeresponse`" in note
    assert "`labels`" not in note and "`httprequest`" not in note


# --- the struct-type parse -------------------------------------------------
#
# Its own tests because the substring version of it is the plausible implementation and
# it is wrong in a way no schema test above would notice.


@pytest.mark.parametrize("typ,expected", [
    ("struct<a:string,b:int>", ["a", "b"]),
    ("array<struct<name:string,value:string>>", ["name", "value"]),
    # The discriminator: `name` appears only INSIDE headers, so a substring test for
    # "name:" would report a top-level field that is not there.
    ("struct<clientip:string,headers:array<struct<name:string,value:string>>>",
     ["clientip", "headers"]),
    ("struct<a:map<string,string>,b:string>", ["a", "b"]),
    ("string", []),
    ("", []),
])
def test_struct_fields_reads_only_the_top_level(typ, expected):
    assert A._struct_fields(typ) == expected


def test_a_nested_name_field_does_not_satisfy_labels():
    """The bug the depth-aware parse prevents, asserted end to end. `labels` is optional
    now, so a nested-only `name` shows up as lost rather than refused, but the parse is
    still what tells the two shapes apart."""
    _, note = check(labels="array<struct<meta:struct<name:string>>>")
    assert note is not None and "`labels`" in note


# --- types real catalogs use ------------------------------------------------


@pytest.mark.parametrize("typ", ["bigint", "int", "integer", "smallint", "tinyint"])
def test_integer_spellings_are_all_accepted_for_timestamp(typ):
    assert check(timestamp=typ) == (None, None)


@pytest.mark.parametrize("typ", ["string", "varchar", "varchar(255)", "char(10)"])
def test_string_spellings_are_all_accepted_for_action(typ):
    assert check(action=typ) == (None, None)
