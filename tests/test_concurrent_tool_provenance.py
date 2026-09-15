# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Two tool calls running at once collapsed into one provenance record, naming the wrong WebACL.

**Measured on the deployed v0.27.0.** One question, "the BlockedRequests total for shield-sample-webacl and
for response-id-on-page on 2026-09-08". The stream shows `TOOL_CALL_START, TOOL_CALL_START, TOOL_CALL_END,
TOOL_CALL_END`, so the two `get_waf_metrics` calls overlap, and exactly one provenance event arrived:

    {"webacl": "response-id-on-page", "subject_explicit": true, "queries": 2, ...}

So the chip for the shield call named the other WebACL, and the second call got no chip at all. A second
case the same session, two `run_logs_query` calls, produced one record whose window spanned 855 days.

**This is the defect `declare_query_subject` was built to remove, reintroduced by concurrency.** The record
lived in one slot per session, and `p["webacl"] = subject or declared or get_webacl_name()` is last-writer
wins on a shared slot.

**A `ContextVar` and not a thread-local, and that distinction is the whole fix.** Strands' concurrent
executor is `asyncio.create_task` per tool use with no thread boundary anywhere in the path: no
`to_thread`, no `run_in_executor`. Two concurrent tool calls therefore interleave on one thread, where a
thread-local would hand both of them the same value and reproduce the defect exactly. `create_task` copies
the context, so a `set()` inside a task is invisible to its siblings, and `BeforeToolCallEvent` is invoked
inside the task, which is what makes it the place to bind.

**The other half is the reverse failure.** A tool call's own queries run in a `ThreadPoolExecutor`, and a
worker thread does not inherit the asyncio task's context, so a record written there would land in the slot
belonging to no tool call and the chip would lose it. A thread-local fails at the task boundary and a
`ContextVar` fails at the thread boundary; both halves are needed.
"""

import asyncio
import concurrent.futures
import threading
from datetime import datetime, timedelta, timezone

import pytest

from tools import aws_session as A
from tools import session_state as S

START = datetime(2026, 9, 8, 4, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=2)


class FakeClient:
    def get_metric_data(self, **kwargs):
        return {"MetricDataResults": []}


@pytest.fixture(autouse=True)
def clean():
    S._state.pop("provenance", None)
    S._state.pop("provenance_stash", None)
    S._state.pop("provenance_subject", None)
    S.set_webacl_context("session-acl", "arn:x", "CLOUDFRONT", "us-east-1")
    S.begin_tool_call("")
    yield
    S.begin_tool_call("")


def _record_as(tool_call: str, subject: str):
    """What one tool call does: bind its slot, declare its subject, read a metric."""
    S.begin_tool_call(tool_call)
    S.declare_query_subject(subject)
    A._RecordingCloudWatch(FakeClient()).get_metric_data(
        MetricDataQueries=[], StartTime=START, EndTime=END)


def test_two_concurrent_tool_calls_keep_their_own_subject():
    """**The measured defect, driven the way the SDK drives it.** Two `asyncio` tasks, interleaved on one
    thread, each declaring its own WebACL. Before the fix both wrote into one slot and the second
    declaration won, so one chip named the other tool's WebACL."""
    async def run():
        async def one(tool_call, subject):
            _record_as(tool_call, subject)
            await asyncio.sleep(0)          # yield, so the two interleave rather than run to completion
            A._RecordingCloudWatch(FakeClient()).get_metric_data(
                MetricDataQueries=[], StartTime=START, EndTime=END)
        await asyncio.gather(one("call-A", "acl-A"), one("call-B", "acl-B"))

    asyncio.run(run())
    a = S.take_query_provenance("call-A")
    b = S.take_query_provenance("call-B")
    assert a.get("webacl") == "acl-A", a
    assert b.get("webacl") == "acl-B", b
    assert a.get("queries") == 2 and b.get("queries") == 2, (a, b)


def test_a_thread_local_would_not_have_separated_them():
    """**The premise of choosing a `ContextVar`, asserted rather than argued**, because the two primitives
    look interchangeable and only one works here.

    Both tasks run on one thread, so a thread-local set by the second task is what the first one reads.
    Driven side by side: the `ContextVar` answers each task with its own value while a thread-local answers
    both with the last writer's."""
    local = threading.local()
    seen = {}

    async def run():
        async def one(name):
            local.value = name
            S.begin_tool_call(name)
            await asyncio.sleep(0)
            seen[name] = (getattr(local, "value", None), S.current_tool_call())
        await asyncio.gather(one("call-A"), one("call-B"))

    asyncio.run(run())
    assert seen["call-A"] == ("call-B", "call-A"), seen
    assert seen["call-B"] == ("call-B", "call-B"), seen


def test_a_fan_out_worker_records_into_its_own_tool_call():
    """The reverse failure. `run_concurrently` submits a tool call's queries to a `ThreadPoolExecutor`, and
    a worker thread starts from an empty context, so without `Context.run` the record lands in the slot that
    belongs to no tool call and the chip shows nothing."""
    S.begin_tool_call("call-A")
    ctx = S.copy_call_context()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(ctx.run, lambda: A._RecordingCloudWatch(FakeClient()).get_metric_data(
            MetricDataQueries=[], StartTime=START, EndTime=END)).result()
    assert S.take_query_provenance("call-A").get("queries") == 1, (
        "a query issued by a fan-out worker did not reach its own tool call's record")


def test_a_fan_out_worker_without_the_context_is_the_defect_this_prevents():
    """The control for the case above, so the `Context.run` is shown to be load-bearing rather than
    decorative. Submitting the job bare puts its record in the empty slot."""
    S.begin_tool_call("call-A")
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(lambda: A._RecordingCloudWatch(FakeClient()).get_metric_data(
            MetricDataQueries=[], StartTime=START, EndTime=END)).result()
    assert S.take_query_provenance("call-A") == {}, "the bare submit should have missed the slot"
    assert S.take_query_provenance("").get("queries") == 1, "and landed in the slot nobody owns"


def test_the_fan_out_hands_each_job_its_own_context():
    """Structural, because reaching it needs a real fan-out. `Context.run` refuses to run one context twice
    concurrently, so a single shared copy would raise on the second job rather than mislabel it, and the
    failure would be a stack trace in the middle of a scan."""
    import pathlib

    from tools import waf_query

    src = pathlib.Path(waf_query.__file__).read_text()
    line = next(ln for ln in src.splitlines() if "executor.submit(" in ln)
    assert "copy_call_context().run" in line, line
    assert "copy_call_context()" in line and line.count("copy_call_context") == 1, (
        f"one context per job, created inside the comprehension: {line.strip()}")


def test_the_slot_is_bound_for_every_tool_and_before_the_guard_returns():
    """`PreQueryGuard` returns early for the tools it does not guard, and every tool needs a slot. Asserted
    on the source because the alternative is a live agent: the binding has to sit above that return."""
    import pathlib

    import agent

    src = pathlib.Path(agent.__file__).read_text()
    body = src[src.index("def check_prerequisites"):]
    body = body[:body.index("\n\nclass ")]
    bind = body.index("begin_tool_call(")
    early_return = body.index("GUARDED_TOOLS")
    assert bind < early_return, (
        "the slot is bound after the guard's early return, so every unguarded tool records into the slot "
        "that belongs to no tool call")


def test_outside_a_tool_call_the_records_still_land_somewhere_readable():
    """The CLI path and any direct call from a script have no tool call at all. They record into the empty
    slot, which `take_query_provenance()` reads with no argument, so those paths keep working rather than
    becoming a special case."""
    S.begin_tool_call("")
    A._RecordingCloudWatch(FakeClient()).get_metric_data(
        MetricDataQueries=[], StartTime=START, EndTime=END)
    assert S.take_query_provenance().get("queries") == 1


def test_a_finished_tool_call_leaves_nothing_in_either_slot_dict():
    """**What the `pop` calls are for now, which is not what they were for before.**

    Until the record was keyed by tool call, they prevented the next call inheriting this one's subject and
    window. Keying makes that structural: tool use ids are unique, so a later call cannot read an earlier
    call's slot whatever the drain does. The sweep found this by reporting three cases HOLLOW, which is
    exactly right, because removing the drain no longer changes an answer.

    What removing it does change is that two dict entries per tool call are never reclaimed. This runs as a
    server, so that is unbounded growth rather than untidiness, and it is the property those cases guard
    now."""
    S.begin_tool_call("call-A")
    S.declare_query_subject("acl-A")
    A._RecordingCloudWatch(FakeClient()).get_metric_data(
        MetricDataQueries=[], StartTime=START, EndTime=END)
    assert S._state["provenance"].get("call-A"), "premise: the record is there before the drain"
    assert S._state["provenance_subject"].get("call-A"), "premise: so is the subject"

    S.stash_query_provenance("call-A")
    assert "call-A" not in S._state["provenance"], "the record's slot outlived its tool call"
    assert "call-A" not in S._state["provenance_subject"], "the subject's slot outlived its tool call"

    S.take_query_provenance("call-A")
    assert not S._state.get("provenance_stash"), "the stash outlived the reader that collected it"

    # **The refusal path, which is a separate branch and the one a drain inside `if record` misses.** Every
    # tool that declares a subject does it before validating its arguments, so `patrol_scan(start_time="")`
    # declares and returns an error with nothing recorded. Its slot still has to be reclaimed.
    S.begin_tool_call("call-C")
    S.declare_query_subject("acl-C")
    assert S.stash_query_provenance("call-C") == {}, "premise: a refusal records nothing to stash"
    assert "call-C" not in S._state["provenance_subject"], (
        "a tool call that declared and then refused left its subject behind")


def test_the_fallback_reader_reclaims_the_slot_too():
    """The other drain point. A hook that never fires leaves the record for `take_query_provenance`, which
    is the fallback that keeps the chip working, and that path has to reclaim the slot as well or the leak
    just moves."""
    S.begin_tool_call("call-B")
    S.declare_query_subject("acl-B")
    A._RecordingCloudWatch(FakeClient()).get_metric_data(
        MetricDataQueries=[], StartTime=START, EndTime=END)
    assert S.take_query_provenance("call-B").get("webacl") == "acl-B"
    assert "call-B" not in S._state["provenance"]
    assert "call-B" not in S._state["provenance_subject"]
