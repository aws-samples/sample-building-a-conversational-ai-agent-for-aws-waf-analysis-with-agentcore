# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""What happens when a query outlives its poll budget.

Two separate defects met here. A CloudWatch poll timeout returned `[]`, which
`run_logs_query` reported as "0 results" with three suggested reasons, none of which is
"the query never finished". And the Athena timeout text told the *model* to narrow and
retry while `agent.py` promised reduction always ends in success, with no counter
anywhere, so three attempts was fifteen minutes of silence.

`time.sleep` is patched out in every test here. At `MAX_POLL` 120 and `POLL_INTERVAL` 2
an un-patched timeout path takes two minutes, and a test suite nobody runs proves
nothing.
"""

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
    """Spin the poll loops instantly, in each module that owns one."""
    for mod in (A, WQ):
        monkeypatch.setattr(mod.time, "sleep", lambda _s: None)


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


# --- the debt this item was filed about ------------------------------------


def test_the_poll_budget_has_exactly_one_definition():
    """`MAX_POLL` was five module-level constants reading 120, 120, 120, 300 and 600, and
    `POLL_INTERVAL` four copies of 2. Reconciling by editing each file is the trap, since
    the next person to move the number has to find all of them again. This is the
    roadmap's own done-when condition, as a test rather than as a grep someone remembers
    to run."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "tools"
    defs = [(p.name, line.strip())
            for p in root.glob("*.py")
            for line in p.read_text().splitlines()
            if line.startswith(("MAX_POLL =", "POLL_INTERVAL ="))]
    assert [f for f, _ in defs] == ["query_limits.py", "query_limits.py"], defs
