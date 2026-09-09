# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""What happens when a query outlives its poll budget.

Two separate defects met here. A CloudWatch poll timeout returned `[]`, which
`run_logs_query` reported as "0 results" with three suggested reasons, none of which is
"the query never finished". And the Athena timeout text told the *model* to narrow and
retry while `agent.py` promised reduction always ends in success, with no counter
anywhere, so three attempts was fifteen minutes of silence.

Every test here runs on a **fake clock**, where sleeping advances time. At `MAX_POLL` 120
and `POLL_INTERVAL` 2 a real timeout path takes two minutes, and a test suite nobody runs
proves nothing. A no-op sleep was enough while the loops counted their own sleeps; now that
they measure a monotonic deadline, a frozen clock would spin one at full speed for the whole
budget instead.
"""

import time

import pytest

from tools import query_limits as Q
from tools import session_state as S
from tools import waf_athena as A
from tools import waf_query as WQ


@pytest.fixture(autouse=True)
def clean_state():
    S._state.clear()
    yield
    S._state.clear()


@pytest.fixture
def no_sleep(monkeypatch):
    """A fake clock, where sleeping advances time.

    A no-op sleep was enough while the loops counted their own sleeps. They now measure a
    monotonic deadline, which is the honest way to spend a budget denominated in seconds,
    and against a frozen clock that loop spins at full speed for the entire real budget.
    Advancing a fake clock keeps the tests instant *and* keeps the poll count faithful, so
    the "did it use its whole budget" assertions still mean something.
    """
    clock = {"t": 1_000.0}
    monkeypatch.setattr(time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    monkeypatch.setattr(time, "monotonic", lambda: clock["t"])


# --- the retry bound --------------------------------------------------------


def test_first_timeout_invites_one_retry_and_the_second_withdraws_it():
    """The bound has to live in the message, because the retrier is the model and
    nothing else can stop it. Before this, every timeout said the same thing."""
    first = Q.poll_timeout_message("Athena")
    assert "retry ONCE" in first
    second = Q.poll_timeout_message("Athena")
    assert "do NOT retry" in second
    assert "retry ONCE" not in second


def test_a_success_resets_the_bound():
    """Consecutive, not cumulative. One slow query early in a session must not change
    what a later query is told, or a long investigation degrades for no reason."""
    Q.poll_timeout_message("Athena")
    Q.poll_timeout_message("Athena")
    S.note_query_success()
    assert "retry ONCE" in Q.poll_timeout_message("Athena")


def test_an_engine_failure_does_not_count_against_the_bound():
    """Failed and Cancelled are not "too much data", so they must not consume the one
    narrowing that a genuine scale problem is entitled to."""
    Q.poll_timeout_message("Athena")
    Q.query_failed_message("CloudWatch Logs Insights", "Failed")
    Q.query_failed_message("CloudWatch Logs Insights", "Cancelled")
    assert S._state["query_timeouts"] == 1
    assert "do NOT retry" in Q.poll_timeout_message("Athena")


def test_the_timeout_message_does_not_promise_that_narrowing_works():
    """The clause this replaced was "Always able to reduce until query succeeds", which
    is an assurance that reduction terminates in success. That, not the 60/30/15 ladder,
    is what made the loop unbounded."""
    for msg in (Q.poll_timeout_message("Athena"), Q.poll_timeout_message("Athena")):
        assert "until query succeeds" not in msg
        assert "NOT a data error" in msg


# --- a stopped query must not read as an absence of traffic -----------------


class FakeCwl:
    """A CloudWatch Logs client whose query never leaves the status it is given."""

    def __init__(self, status):
        self.status = status
        self.polls = 0

    def start_query(self, **_):
        return {"queryId": "q-1"}

    def get_query_results(self, queryId):
        self.polls += 1
        return {"status": self.status, "results": []}


def _run(monkeypatch, no_sleep, status):
    fake = FakeCwl(status)
    monkeypatch.setattr(WQ, "get_client", lambda *a, **k: fake)
    monkeypatch.setattr(WQ, "get_logs_region", lambda: "us-east-1")
    rows = WQ._run_cwl("lg", "fields @message", 0, 60, 10)
    return fake, rows


def test_a_cwl_poll_timeout_is_not_reported_as_zero_rows(monkeypatch, no_sleep):
    """The headline defect. `Running` forever returned `[]`, indistinguishable from a
    quiet window, and the agent then told the user no traffic matched."""
    fake, rows = _run(monkeypatch, no_sleep, "Running")
    # The precondition: the loop really did exhaust its budget rather than exit early.
    assert fake.polls == Q.MAX_POLL // Q.POLL_INTERVAL
    assert rows != []
    assert len(rows) == 1 and "_error" in rows[0]
    assert "STOPPED" in rows[0]["_error"]


def test_a_cwl_engine_failure_is_not_reported_as_zero_rows(monkeypatch, no_sleep):
    """Same shape, different cause, and it must not consume the retry allowance."""
    fake, rows = _run(monkeypatch, no_sleep, "Failed")
    assert fake.polls == 1, "a terminal status should break the loop immediately"
    assert len(rows) == 1 and "_error" in rows[0]
    assert "Failed" in rows[0]["_error"]
    assert S._state.get("query_timeouts", 0) == 0


def test_a_completed_cwl_query_still_returns_rows_and_clears_the_count(monkeypatch, no_sleep):
    """The control. The `_error` paths above must not have swallowed the success path."""
    S.note_query_timeout()
    fake = FakeCwl("Complete")
    fake.get_query_results = lambda queryId: {
        "status": "Complete", "results": [[{"field": "ip", "value": "1.2.3.4"}]]}
    monkeypatch.setattr(WQ, "get_client", lambda *a, **k: fake)
    monkeypatch.setattr(WQ, "get_logs_region", lambda: "us-east-1")
    rows = WQ._run_cwl("lg", "fields @message", 0, 60, 10)
    assert rows == [{"ip": "1.2.3.4"}]
    assert S._state["query_timeouts"] == 0


# --- the Athena side -------------------------------------------------------


class FakeAthena:
    def __init__(self, *states):
        self.states = list(states)

    def get_query_execution(self, QueryExecutionId):
        state = self.states.pop(0) if self.states else "RUNNING"
        return {"QueryExecution": {"Status": {"State": state}}}


def test_athena_timeout_raises_the_user_facing_message(no_sleep):
    with pytest.raises(RuntimeError) as e:
        A._wait_query(FakeAthena(), "q-1")
    assert "STOPPED" in str(e.value)
    assert "duration_minutes=30" not in str(e.value), "the old model-directed text"
    assert S._state["query_timeouts"] == 1


def test_athena_success_clears_the_count(no_sleep):
    S.note_query_timeout()
    A._wait_query(FakeAthena("SUCCEEDED"), "q-1")
    assert S._state["query_timeouts"] == 0


def test_an_athena_failure_carries_its_reason_and_the_do_not_retry_guidance(no_sleep):
    """Found by running a real query: a wide one came back `HIVE_S3_THROTTLING`, which is
    precisely the failure where an unprompted retry makes things worse. The CloudWatch path
    already said "not an absence of traffic, do not re-run unchanged"; Athena's said only
    `Athena query FAILED: <reason>` and left the model to decide."""
    class Failing(FakeAthena):
        def get_query_execution(self, QueryExecutionId):
            return {"QueryExecution": {"Status": {
                "State": "FAILED", "StateChangeReason": "HIVE_S3_THROTTLING: S3 throttling"}}}

    with pytest.raises(RuntimeError) as e:
        A._wait_query(Failing(), "q-1")
    msg = str(e.value)
    assert "HIVE_S3_THROTTLING" in msg, "the engine's own reason has to survive"
    assert "NOT an absence of traffic" in msg
    assert "throttling" in msg and "worse" in msg
    # A failure is not a timeout, so it must not spend the retry allowance.
    assert S._state.get("query_timeouts", 0) == 0


def test_the_budget_is_wall_clock_not_a_count_of_sleeps(no_sleep):
    """`elapsed += POLL_INTERVAL` ignored the time each poll itself costs, so a budget
    described as 120 seconds ran 131 when measured against real Athena: 60 sleeps of 2 plus
    60 GetQueryExecution round trips.

    This is the test that can tell the two apart. The fake poll advances the clock by 1 s,
    so a wall-clock deadline affords 120 / (2 + 1) = 40 polls while a sleep-counting loop
    would still take 60. Without the clock-advancing poll, both implementations look
    identical and the test proves nothing.
    """
    class SlowPoll(FakeAthena):
        def __init__(self):
            super().__init__()
            self.polls = 0

        def get_query_execution(self, QueryExecutionId):
            self.polls += 1
            time.sleep(1)  # the fake clock advances; stands in for the API round trip
            return {"QueryExecution": {"Status": {"State": "RUNNING"}}}

    fake = SlowPoll()
    with pytest.raises(RuntimeError):
        A._wait_query(fake, "q-1")
    assert fake.polls == Q.MAX_POLL // (Q.POLL_INTERVAL + 1) == 40, fake.polls


# --- the debt this item was filed about ------------------------------------


def test_the_poll_budget_has_exactly_one_definition():
    """`MAX_POLL` was five module-level constants reading 120, 120, 120, 300 and 600, and
    `POLL_INTERVAL` four copies of 2. Reconciling by editing each file is the trap, since
    the next person to move the number has to find all of them again. This is the
    roadmap's own done-when condition, as a test rather than as a grep someone remembers
    to run.

    **The first version of this test guarded a string, not the idea, and passed while two
    more budgets existed.** It looked only for lines starting `MAX_POLL =`, so
    `report._poll_log_query`'s `max_wait=120` and `waf_patrol._poll_log_query`'s
    `max_wait: int = 60` were invisible to it, and the second was spending its budget
    through `range(max_wait // 2)` rather than a comparison. A test for "one definition"
    has to look for any parameter or constant that *is* a poll budget, whatever it is
    called.

    Matched over the parsed syntax tree rather than over the text, because the text version
    then failed on the docstrings that *describe* the removed parameters. A test that cannot
    tell code from prose about code is not much of a guard.
    """
    import ast
    import pathlib

    BUDGET_NAMES = {"max_wait", "max_poll", "MAX_POLL", "POLL_INTERVAL", "poll_timeout",
                    "timeout_seconds", "wait_seconds", "poll_interval"}
    root = pathlib.Path(__file__).resolve().parent.parent / "tools"
    found = []
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            # A module-level or class-level constant.
            targets = []
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target.id]
            if targets and isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                found += [(path.name, t) for t in targets if t in BUDGET_NAMES]
            # A numeric default on a function parameter, which is how two of them hid.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                defaults = list(node.args.defaults) + list(node.args.kw_defaults)
                for arg in args:
                    if arg.arg in BUDGET_NAMES and any(
                            isinstance(d, ast.Constant) and isinstance(d.value, int)
                            for d in defaults if d is not None):
                        found.append((path.name, f"{node.name}({arg.arg}=...)"))

    assert sorted(found) == [("query_limits.py", "MAX_POLL"),
                            ("query_limits.py", "POLL_INTERVAL")], found
