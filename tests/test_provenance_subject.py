# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""A tool that takes its own `webacl_name` must disclose that one, not the session's.

**Measured 2026-09-14 on the live account, and the disclosure was the thing lying.** Session context held
`response-id-on-page`. `get_waf_metrics(webacl_name="shield-sample-webacl", metric_name="BlockedRequests")`
answered `## BlockedRequests — shield-sample-webacl (last 24h) / Total: 6`, and the `SOURCE:` line
appended to that answer read:

    SOURCE: response-id-on-page via CloudWatch metrics. That is the WebACL from the last get_waf_config
    call, not from your question. If it is not the one you asked about, call get_waf_config(...) and run
    this again.

So one WebACL's number arrived labelled with another's name, plus an instruction to throw away a correct
answer. That is 7.7 item 4's second measured misattribution, produced by the mechanism built to prevent
it: the funnel records `get_webacl_name()`, and six `@tool` entry points take a `webacl_name` and use it
as the metric dimension without ever writing it to session state.

**The prompt rule this file precedes is what makes it load-bearing.** The rule tells the model to keep the
WebACL from a result's `SOURCE:` line when it carries a number into a table. Against the line above, that
rule would have produced exactly the wrong table it exists to prevent.
"""

import ast
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from tools import aws_session as A
from tools import session_state as S

ROOT = pathlib.Path(__file__).resolve().parents[1]
START = datetime(2026, 9, 8, 4, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=2)

# A call that may issue a query. Deliberately wider than "reads a metric": `get_client` fires before the
# read it hands out, so requiring the declaration ahead of it is the conservative direction.
QUERY_CALLS = {"get_client", "get_metric_data", "query_logs", "_run_athena_select", "run_concurrently"}


class FakeClient:
    def get_metric_data(self, **kwargs):
        return {"MetricDataResults": []}


@pytest.fixture(autouse=True)
def clean():
    S._state.pop("provenance", None)
    S._state.pop("provenance_subject", None)
    S.set_webacl_context("session-acl", "arn:x", "CLOUDFRONT", "us-east-1")
    # Bound the way `PreQueryGuard` binds it at `BeforeToolCallEvent`, because the record is keyed by tool
    # call: a fixture that skips this writes into the slot no hook owns, which is what the old single-slot
    # version could not tell apart.
    S.begin_tool_call("t1")
    yield
    S.begin_tool_call("")


def _read(**kwargs) -> dict:
    """One metric read through the real funnel, returning the record the hook would drain."""
    A._RecordingCloudWatch(FakeClient()).get_metric_data(
        MetricDataQueries=[], StartTime=kwargs.get("start", START), EndTime=END)
    return dict((S._state.get("provenance") or {}).get(S.current_tool_call()) or {})


def _tools_taking_a_webacl_name() -> dict[str, ast.FunctionDef]:
    out = {}
    for path in sorted(ROOT.glob("tools/*.py")):
        for node in ast.parse(path.read_text()).body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(isinstance(d, ast.Name) and d.id == "tool" for d in node.decorator_list):
                continue
            if "webacl_name" in [a.arg for a in node.args.args]:
                out[f"{path.name}::{node.name}"] = node
    return out


def _called_names(node: ast.AST) -> dict[str, int]:
    """Every function name called anywhere under `node`, mapped to its first line."""
    out: dict[str, int] = {}
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = sub.func.id if isinstance(sub.func, ast.Name) else getattr(sub.func, "attr", "")
            out.setdefault(name, sub.lineno)
    return out


def test_every_tool_taking_a_webacl_name_says_which_one_it_queried():
    """**The rule is per parameter, not per behaviour**, and that is what stops it going stale.

    A criterion like "the tools that read metrics" needs re-deciding every time a tool changes what it
    reads, and nothing would notice when one starts. So: a tool that takes a `webacl_name` either writes it
    to session state, which makes `get_webacl_name()` correct by construction, or declares it. Exactly one
    does the first, `get_waf_config`, and it is the reason the other five were wrong rather than an
    exception to anything.

    `review_waf_rules_deep` queries nothing and still declares, which costs one line and no output:
    declaring creates no record, so no `SOURCE:` line is appended. The day it reads a metric, its
    disclosure is already right."""
    tools = _tools_taking_a_webacl_name()
    assert len(tools) >= 6, f"extraction found only {sorted(tools)}, so this proves nothing"
    silent = [name for name, node in tools.items()
              if not {"declare_query_subject", "set_webacl_context"} & set(_called_names(node))]
    assert not silent, (
        f"these tools take a webacl_name and never say which WebACL they queried, so their SOURCE line "
        f"names whatever the last get_waf_config loaded: {silent}")


def test_the_declaration_comes_before_the_first_query():
    """A declaration after the first read leaves that read recorded against the session's WebACL, and the
    merge keeps the first value for `webacl`, so the late declaration would never show up at all. Order is
    the whole property here, and it is invisible in the output of any single tool call."""
    checked = 0
    for name, node in _tools_taking_a_webacl_name().items():
        calls = _called_names(node)
        if "declare_query_subject" not in calls:
            continue
        first_query = min((ln for fn, ln in calls.items() if fn in QUERY_CALLS), default=None)
        assert first_query is not None, f"{name} declares a subject and issues no query at all: {calls}"
        assert calls["declare_query_subject"] < first_query, (
            f"{name} declares its subject at line {calls['declare_query_subject']}, after a query at "
            f"{first_query}, so that query is recorded against the session's WebACL")
        checked += 1
    assert checked >= 5, f"only {checked} tools declare a subject, so this proves nothing"


def test_a_metric_read_names_the_declared_webacl_not_the_session_one():
    """The measured defect, driven through the funnel the tools actually use."""
    S.declare_query_subject("shield-sample-webacl")
    record = _read()
    assert record["webacl"] == "shield-sample-webacl", (
        f"the read was about shield-sample-webacl and the record says {record['webacl']!r}")
    line = S.provenance_source_line(record)
    assert "session-acl" not in line, line


def test_the_line_does_not_tell_the_model_to_reload_a_context_the_tool_never_read():
    """**The same defect as the explicit-log-group wording, on a second path.** The session-derived text
    ends "call get_waf_config(webacl_name='...') and run this again", and running `get_waf_metrics` again
    changes nothing: the dimension comes from its own argument, not from session state. So the instruction
    would ask the model to discard a correct answer, which is what the live measurement showed it doing.

    Asserted on the whole string rather than on the subject inside it, because the identifier was already
    right in the version that carried this instruction."""
    S.declare_query_subject("shield-sample-webacl")
    line = S.provenance_source_line(_read())
    assert "get_waf_config" not in line, line
    assert "not consulted" in line, "it has to say the session context did not decide this, not imply it"

    S._state.pop("provenance", None)
    S._state.pop("provenance_subject", None)
    assert "get_waf_config" in S.provenance_source_line(_read()), (
        "a session-derived subject still needs the instruction; that is the whole point of the line")


def test_declaring_creates_no_record_so_a_tool_that_queries_nothing_stays_silent():
    """`review_waf_rules_deep` reads wafv2 and queries no logs or metrics. A declaration that created the
    record eagerly would give it `SOURCE: acl via no engine`, a claim about a query that never ran, which
    is the state `test_query_provenance.py` already forbids for every config-only tool."""
    S.declare_query_subject("shield-sample-webacl")
    assert "provenance" not in S._state, "declaring a subject invented a record with no query behind it"


def test_the_pin_does_not_outlive_the_tool_call_that_set_it():
    """Same shape as the accumulation the hook's drain fixed: a subject that survives its tool call labels
    the next one's numbers. Driven as two tool calls, the second being a tool with no `webacl_name` at
    all, which is the eight that read the session context."""
    S.declare_query_subject("shield-sample-webacl")
    S.stash_query_provenance("t1")

    S.begin_tool_call("t2")          # the next tool call, which is what must not inherit
    record = _read()
    assert record["webacl"] == "session-acl", (
        f"the second tool call inherited the first's declared subject: {record}")
    assert not record["subject_explicit"], "and it would have claimed the session context was bypassed"


def test_a_tool_that_declared_and_then_refused_leaves_nothing_behind():
    """The other branch, and it is why the pin is popped outside the `if record` guard. Every one of the
    five declares before validating its arguments, so `patrol_scan(webacl_name="x", start_time="")`
    declares and then returns an error with no query behind it. Nothing is stashed on that path, so a pop
    inside the guard would leave the subject standing."""
    S.declare_query_subject("shield-sample-webacl")
    assert S.stash_query_provenance("t1") == {}, "a refusal has no record to stash"
    S.begin_tool_call("t2")
    assert _read()["webacl"] == "session-acl", "the refused tool's subject labelled the next tool's read"


def test_the_fallback_drain_clears_the_pin_too():
    """`take_query_provenance` is the fallback for a hook that never fires, and in that world no `SOURCE:`
    line is appended at all, so the pin's only remaining reader is the next tool call's record. The chip
    would then name a WebACL that tool never asked about."""
    S.declare_query_subject("shield-sample-webacl")
    S.take_query_provenance("t1")
    S.begin_tool_call("t2")
    assert _read()["webacl"] == "session-acl", "the pin outlived the fallback drain"
