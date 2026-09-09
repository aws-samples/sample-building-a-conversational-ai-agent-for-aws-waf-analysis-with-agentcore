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


def test_the_timeout_message_does_not_claim_to_know_why():
    """It used to say "the window was too large to scan interactively". On the bucket the
    public roadmap cell was verified against, that was wrong: the window was fine and the
    object count was the problem, which Athena itself reports as HIVE_S3_THROTTLING eleven
    seconds later. Narrowing is still the right action, being the only lever available, but
    it must not arrive dressed as a diagnosis."""
    msg = Q.poll_timeout_message("Athena")
    assert "window was too large" not in msg
    assert "retry ONCE" in msg, "the action survives the removal of the assertion"
    assert "cannot tell which" in msg, "and it says the cause is unknown"


def test_a_failure_reason_is_punctuated_before_the_next_sentence():
    """Only visible in real output: Athena's StateChangeReason ends without punctuation, so
    concatenating gave "...requested resources This is a query-execution failure"."""
    msg = Q.query_failed_message("Athena", "FAILED", "COLUMN_NOT_FOUND: Column 'x' missing")
    assert "missing. This is" in msg
    # An engine that does punctuate must not get two terminators.
    assert ".. This is" not in Q.query_failed_message("Athena", "FAILED", "Ends already.")


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


# --- cancelling a query we stopped waiting for ------------------------------


class FakeStoppable:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def stop_query(self, queryId):
        self.calls.append(queryId)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return {"success": self.outcome}


def test_stopping_a_running_query_reports_that_it_was_cancelled():
    c = FakeStoppable(True)
    assert Q.stop_query(c, "q-1") is True
    assert c.calls == ["q-1"]


def test_stopping_an_already_finished_query_is_not_an_error():
    """The race this path is made of: the query can complete between the last poll and the
    stop. Measured against real CloudWatch, that raises `InvalidParameterException`, and the
    docs say so outright. It must not propagate, because this runs where a timeout message is
    already waiting to be delivered and a failed cancel must neither replace nor swallow it."""
    class InvalidParameterException(Exception):
        pass

    c = FakeStoppable(InvalidParameterException("Query is not running"))
    assert Q.stop_query(c, "q-1") is False


def test_a_false_success_flag_is_not_an_error_either():
    """`success: false` arrives in a normal 200 and means this call is not what stopped it."""
    assert Q.stop_query(FakeStoppable(False), "q-1") is False


def test_the_verb_says_cancelled_only_when_it_was():
    """Once CloudWatch cancels and Athena does not, one shared sentence would tell a user the
    query was abandoned while the code had stopped it, or the reverse."""
    S._state.clear()
    stopped = Q.poll_timeout_message("CloudWatch Logs Insights", cancelled=True)
    S._state.clear()
    abandoned = Q.poll_timeout_message("Athena", cancelled=False)
    # Assert the *fate* clause, not a bare substring: both messages open with "was still
    # running after 120 seconds", which describes the state before the give-up rather than
    # after it, so `"still running" not in stopped` was a wrong assertion about right code.
    assert "was cancelled, so it has stopped scanning" in stopped
    assert "still running and still scanning" not in stopped
    assert "still running and still scanning" in abandoned
    assert "was cancelled" not in abandoned


def test_a_cwl_poll_timeout_cancels_the_query_and_says_so(monkeypatch, no_sleep):
    """The two halves together at the one site that has both a stop and a message."""
    fake = FakeCwl("Running")
    fake.stop_query = lambda queryId: {"success": True}
    monkeypatch.setattr(WQ, "get_client", lambda *a, **k: fake)
    monkeypatch.setattr(WQ, "get_logs_region", lambda: "us-east-1")
    rows = WQ._run_cwl("lg", "fields @message", 0, 60, 10)
    assert "was cancelled" in rows[0]["_error"]


def test_a_terminal_status_is_not_stopped_because_there_is_nothing_to_stop(monkeypatch, no_sleep):
    fake = FakeCwl("Failed")
    stops = []
    fake.stop_query = lambda queryId: stops.append(queryId) or {"success": True}
    monkeypatch.setattr(WQ, "get_client", lambda *a, **k: fake)
    monkeypatch.setattr(WQ, "get_logs_region", lambda: "us-east-1")
    WQ._run_cwl("lg", "fields @message", 0, 60, 10)
    assert stops == [], "a Failed query has already ended"


def test_every_module_that_starts_a_query_also_stops_one():
    """Five `start_query` sites existed and the first draft of this change would have added a
    stop to one. That is the shape that has bitten repeatedly here: five `MAX_POLL`
    definitions, two fan-out copies with one fixed, two memos with one locked. Structural
    rather than behavioural on purpose, because a sixth site added later would otherwise be
    invisible until someone noticed a query left running."""
    import ast
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "tools"
    for path in sorted(root.glob("*.py")):
        tree = ast.parse(path.read_text())
        names = {getattr(n.func, "attr", getattr(n.func, "id", ""))
                 for n in ast.walk(tree) if isinstance(n, ast.Call)}
        if "start_query" in names:
            assert "stop_query" in names, f"{path.name} starts queries and never stops one"


# --- the fan-out budget, which is what actually bounds patrol ---------------


def test_a_fanout_timeout_costs_the_detail_not_the_whole_report(monkeypatch):
    """`as_completed(timeout=...)` raises from the iterator, at the `for`, so the `except`
    inside the loop body never saw it and it propagated out of `_get_log_details` into
    `patrol_scan`. One slow CloudWatch query killed the entire patrol report instead of
    costing it the per-rule detail section.

    Already reachable before the poll budgets were unified: fifteen futures over five
    workers is three waves, and three waves at 60 s overruns a 120 s batch.
    """
    from tools import waf_patrol as P

    # One query hangs past the batch budget; the rest answer at once. A real timeout, but
    # a short one, since this asserts the exception does not escape rather than a duration.
    # Patrol imports the constant into its own namespace, so this is the binding one.
    monkeypatch.setattr(P, "MAX_FANOUT_WAIT", 0.1)
    calls = {"n": 0}

    def one_hangs(logs_client, log_group, start, end, rule_name):
        calls["n"] += 1
        if calls["n"] == 1:
            # A real sleep, not the fake clock: as_completed's timeout is real wall time.
            # The pool joins its threads on exit, so this sets the test's floor.
            time.sleep(1)
        return [{"ip": "1.2.3.4", "cnt": "9"}]

    for fn in ("_query_top_ips_by_rule", "_query_top_uris_by_rule", "_query_content_by_rule"):
        monkeypatch.setattr(P, fn, one_hangs)

    # The precondition: without the catch this raises concurrent.futures.TimeoutError.
    details = P._get_log_details(object(), "lg", 0, 60, ["ruleA", "ruleB"])
    assert isinstance(details, dict), "the exception must not escape"


def test_a_fanout_timeout_returns_at_the_budget_not_after_the_stragglers(monkeypatch):
    """Catching the timeout stops the crash without stopping the *wait*, and the six
    perturbations behind the previous commit could not tell the difference.

    `Executor.__exit__` calls `shutdown(wait=True)`, so a `with` block blocks until every
    submitted future finishes even after the collection loop has given up on their results.
    That meant returning after up to three waves at `MAX_POLL`, about 360 s, while discarding
    waves two and three: waiting for work it throws away. Removing the `except TimeoutError`
    makes the earlier test fail because the crash returns, which confirms the catch and never
    touches the wait, so this asserts the elapsed time instead.
    """
    from tools import waf_patrol as P

    monkeypatch.setattr(P, "MAX_FANOUT_WAIT", 0.3)

    def all_hang(logs_client, log_group, start, end, rule_name):
        time.sleep(3)  # every query outlives the batch budget, ten times over
        return [{"ip": "1.2.3.4", "cnt": "9"}]

    for fn in ("_query_top_ips_by_rule", "_query_top_uris_by_rule", "_query_content_by_rule"):
        monkeypatch.setattr(P, fn, all_hang)

    t0 = time.monotonic()
    P._get_log_details(object(), "lg", 0, 60, ["a", "b", "c", "d", "e"])
    elapsed = time.monotonic() - t0
    # Fifteen futures over five workers is three waves. Under `wait=True` this returns after
    # all three, so ~9 s; bounded by the batch budget it returns after ~0.3 s plus overhead.
    assert elapsed < 2.0, f"returned after {elapsed:.1f}s, so it waited for discarded work"


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
                    "timeout_seconds", "wait_seconds", "poll_interval", "MAX_FANOUT_WAIT",
                    "fanout_wait", "batch_timeout"}
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

    assert sorted(found) == [("query_limits.py", "MAX_FANOUT_WAIT"),
                            ("query_limits.py", "MAX_POLL"),
                            ("query_limits.py", "POLL_INTERVAL")], found

    # A budget can also hide as a bare literal at the call site, with no name at all, which
    # is how the second fan-out kept `timeout=120` while the first used the constant. One
    # name with two values is the defect this whole item exists to remove.
    literals = []
    for path in sorted(root.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            fname = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if fname not in ("as_completed", "wait", "result"):
                continue
            for kw in node.keywords:
                if kw.arg == "timeout" and isinstance(kw.value, ast.Constant):
                    literals.append((path.name, f"{fname}(timeout={kw.value.value})"))
    assert literals == [], f"a wait budget as a bare literal: {literals}"
