# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Every CloudWatch metric read discloses the window it asked for, ROADMAP 7.2's second job.

The date-offset defect that opened section 7 lived in `get_waf_metrics`, and it was invisible because
nothing in the output said which window had been read. `query_logs` is the funnel that made that
disclosure possible for log queries; the three tools that read CloudWatch metrics directly bypass it,
and so do both report generators.

**The funnel is the client, not a wrapper function.** `get_metric_data` is called at 30 sites in five
files and the plan for this change counted 29 in four, missing `waf_bypass.py:304`. A funnel that has to
be adopted per call site depends on an inventory nobody can keep; one built into the client covers a
call site written next year. `tools/aws_session.get_client` is the only place a boto3 client is
constructed in this repository, which is what makes that possible.
"""

from datetime import datetime, timedelta, timezone

import pytest

from tools import aws_session as A
from tools import session_state as S

START = datetime(2026, 9, 8, 4, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=2)


class FakeClient:
    """Stands in for a botocore CloudWatch client, recording what reached it."""

    def __init__(self):
        self.calls = []

    def get_metric_data(self, **kwargs):
        self.calls.append(kwargs)
        return {"MetricDataResults": []}

    def list_metrics(self, **kwargs):
        self.calls.append(("list_metrics", kwargs))
        return {"Metrics": []}


@pytest.fixture(autouse=True)
def clean():
    S._state.pop("provenance", None)
    S.set_webacl_context("acl", "arn:x", "CLOUDFRONT", "us-east-1")
    S.set_user_timezone(8.0)
    yield
    S._state.pop("provenance", None)


def test_a_metric_read_records_its_window_and_names_the_engine():
    inner = FakeClient()
    A._RecordingCloudWatch(inner).get_metric_data(MetricDataQueries=[{"Id": "a"}],
                                                  StartTime=START, EndTime=END)
    p = S.take_query_provenance()
    assert p["engines"] == ["CloudWatch metrics"]
    assert (p["start"], p["end"]) == (int(START.timestamp()), int(END.timestamp()))
    assert p["queries"] == 1
    assert inner.calls == [{"MetricDataQueries": [{"Id": "a"}], "StartTime": START, "EndTime": END}], (
        "the call has to reach the real client unchanged")


def test_the_count_is_per_read_because_one_tool_makes_several():
    """**Recording once per tool call instead would print `1 query` where patrol makes seven reads**,
    which is a false statement of the same kind the whole record exists to remove. The window widens to
    the union, so a tool reading last week for a comparison discloses that it did."""
    cw = A._RecordingCloudWatch(FakeClient())
    cw.get_metric_data(MetricDataQueries=[], StartTime=START, EndTime=END)
    cw.get_metric_data(MetricDataQueries=[], StartTime=START - timedelta(days=7),
                       EndTime=END - timedelta(days=7))
    p = S.take_query_provenance()
    assert p["queries"] == 2
    assert p["start"] == int((START - timedelta(days=7)).timestamp())
    assert p["end"] == int(END.timestamp()), "the union, so the comparison read is disclosed too"


def test_everything_other_than_the_metric_read_delegates_untouched():
    """A proxy that swallowed an attribute would break a caller in a way no provenance test would see."""
    inner = FakeClient()
    cw = A._RecordingCloudWatch(inner)
    assert cw.list_metrics(Namespace="AWS/WAFV2") == {"Metrics": []}
    assert inner.calls == [("list_metrics", {"Namespace": "AWS/WAFV2"})]
    assert S.take_query_provenance() == {}, "only a metric read has a window to disclose"


def test_a_read_missing_its_window_records_nothing_and_is_refused_downstream():
    """botocore rejects the call for the missing parameter immediately afterwards, so nothing proceeds
    unrecorded. Raising here would replace a clear API error with an obscure one from the wrong layer."""
    cw = A._RecordingCloudWatch(FakeClient())
    cw.get_metric_data(MetricDataQueries=[])
    assert S.take_query_provenance() == {}


def test_get_client_wraps_cloudwatch_and_nothing_else(monkeypatch):
    """**The pairing, and it is where a bypass would live.** The wrapper is worth nothing if the client
    the tools actually receive is the raw one, and `session.client` appears in exactly one place in this
    repository, which is what lets the funnel be built rather than adopted."""
    built = []

    class FakeSession:
        def client(self, service, region_name=None):
            built.append(service)
            return FakeClient()

    monkeypatch.setattr(A, "get_session", lambda **kw: FakeSession())
    assert isinstance(A.get_client("cloudwatch"), A._RecordingCloudWatch)
    assert not isinstance(A.get_client("wafv2"), A._RecordingCloudWatch), (
        "only metric reads have a window to record; wrapping every service would record nothing and "
        "add a proxy in front of every call in the repository")
    assert built == ["cloudwatch", "wafv2"]


def test_the_only_client_constructor_is_the_one_that_wraps():
    """Structural, and the reason the funnel can be built into the client at all. A module calling
    `boto3.client` or `session.client` for itself would hold an unwrapped CloudWatch client, and its
    metric reads would disclose nothing while every test here stayed green."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    session_src = (root / "tools/aws_session.py").read_text()
    # The exemption is the line range of `get_client` itself, read from the AST rather than written
    # down, because a line number in a test is a number that goes stale silently.
    wrapper = next(n for n in ast.walk(ast.parse(session_src))
                   if isinstance(n, ast.FunctionDef) and n.name == "get_client")
    offenders, found = [], 0
    for path in sorted(root.glob("tools/*.py")) + [root / "agent.py"]:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "client":
                continue
            found += 1
            if path.name == "aws_session.py" and wrapper.lineno <= node.lineno <= wrapper.end_lineno:
                continue
            offenders.append(f"{path.name}:{node.lineno}")
    assert found, "no client construction found at all, so this test proves nothing"
    assert not offenders, (
        f"these build a client without going through get_client, so a CloudWatch client from one of "
        f"them records no provenance: {offenders}")
