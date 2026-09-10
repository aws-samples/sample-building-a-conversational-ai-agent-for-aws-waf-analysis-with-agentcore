# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Per-query polling limits, and what to say when one runs out.

One definition each, imported by every polling site. `MAX_POLL` used to be five separate
module-level constants disagreeing at 120, 120, 120, 300 and 600, and `POLL_INTERVAL`
four copies of 2. Two of those files defined both and used neither, so the count of
definitions was not even a count of behaviours.

**What `MAX_POLL` is, because it reads as something else.** It caps a *single* query's
poll loop. There is no chain-level or per-turn budget anywhere in the product, so a
methodology of N queries runs N of these back to back. The value therefore answers "how
long may one query run before we call it stuck", not "how long may an investigation
take". A long chain is a query-count problem instead.

**The two engines reach that number for different reasons, and only one of them is about
pruning.** On Athena, a query needing more than a couple of minutes has almost certainly
failed to prune, so the budget doubles as a partition-pruning smoke test. CloudWatch Logs
Insights has no partitions at all, so none of that transfers: there it is a flat bet that
the log group is small enough to scan in the window asked for, and when the bet loses the
only remedy is a narrower window, which is what the message says.

**Not to be confused with the query window cap**, `MAX_MINUTES` below, which is how many
minutes of logs a query may ask for. Both now live here, which is the point: the window cap
used to be applied at five sites, two through a `MAX_MINUTES` in `waf_logs.py` and three as
a bare literal `360`, while the prompt separately told the model Athena was capped at 60.
Four numbers for one behaviour, and the only enforced one was the one nobody had written
down as a decision.

**Why one number and not one per engine.** ROADMAP 3.1 asked for a separate, tighter Athena
cap, on the reasoning that a wide window on an hourly table is the path that fails badly.
Three things say otherwise. The prompt's 60 was never true, since four tools default to 180
and work. The cost is small and measured: at 4000 RPS an hour of logs is about 1.1 GB
scanned, so 360 minutes is roughly 6.6 GB, and
`docs/hourly-vs-minute-partitioning.md` finds the dominant cost is the *number* of queries
rather than the width of one. And a static per-engine window is wrong in both directions,
because what a query can finish depends on the install: at 10 TB/day 60 minutes may time
out, and on a small bucket 360 finishes easily. `MAX_POLL` is the limit that adapts, since
it measures what actually happened instead of guessing beforehand.

So what a window cap still earns is a cheap refusal instead of an expensive discovery:
rejecting a 10,000-minute request costs nothing, while discovering it at the poll budget
costs two minutes and a scan. That is an argument for *a* ceiling, not for a tight one.

**The inconsistency this file used to record is still open, and it is not about 60 versus
360.** It is that a 360-minute request gets a 120-second poll budget: the product accepts a
six-hour window and abandons it after two minutes. Picking a side needs evidence about how
long a real six-hour query takes at production volume, which nobody has gathered, and this
account cannot supply it because its log volume is too small to be representative.
"""

# One deliberate value, the tightest of the five it replaces. Raising this is almost
# always the wrong response to a timeout: see the module docstring.
#
# Seconds of wall clock, and the polling loops measure it with a monotonic deadline
# rather than by adding up their sleeps. Counting sleeps undercounts: each iteration also
# pays a GetQueryExecution round trip, so a 120 that meant "60 sleeps of 2" actually ran
# 131 s when measured, and the message promising 120 seconds was wrong by the polling
# overhead. It also means the budget stretched on a slow link and shrank on a fast one.
MAX_POLL = 120
POLL_INTERVAL = 2

# The query WINDOW cap: how many minutes of logs one query may ask for, both engines. Six
# hours. Every tool that takes `duration_minutes` clamps to this, and `agent.py` renders the
# number into the system prompt from here rather than restating it, so the model cannot be
# told a limit the code does not apply.
MAX_MINUTES = 360

# The fan-out budget, which is a different kind of limit and the one that actually governs
# patrol. `MAX_POLL` bounds ONE query; this bounds a whole batch submitted to a thread pool,
# in wall clock, and it is what `concurrent.futures.as_completed(timeout=...)` takes.
#
# **This bounds when patrol stops collecting, and only since the executor stopped being a
# `with` block does it also bound when patrol returns.** The two are not the same thing, and
# an earlier version of this comment claimed the batch budget capped patrol's wall clock. It
# did not. `Executor.__exit__` calls `shutdown(wait=True)`, so the old `with` block waited
# for every submitted future even after `as_completed` gave up on their results: fifteen
# futures over five workers is three waves, so patrol returned after roughly 3 x `MAX_POLL`
# and threw away waves two and three. Raising the per-query budget from 60 to 120 therefore
# *did* double patrol's worst case, from about 180s to about 360s, which the same comment
# denied. Both sites now shut down with `wait=False, cancel_futures=True`, which drops the
# un-started futures and leaves the five in flight to finish in the background, so the
# function returns at this budget.
#
# Kept at 120 rather than widened to cover three full waves. Widening makes patrol slower to
# give up without making it likelier to answer.
MAX_FANOUT_WAIT = 120


# What a stop call can honestly report. Three values and not a bool, because the two engines
# do not know the same amount and a bool forced them to claim they did.
#
# CloudWatch's StopQuery returns a `success` flag, so a True there is the engine saying it
# stopped a running query. Athena's StopQueryExecution returns an **empty body**: the only
# available truth is "the call did not raise", and a stop against an already-SUCCEEDED
# execution also returns normally with the state unchanged (measured, and undocumented). So an
# Athena acceptance cannot be told apart from "it had already finished and the stop did
# nothing", over exactly the window CloudWatch reports as InvalidParameterException and Athena
# stays silent about. Collapsing that into `cancelled=True` would put "so it has stopped
# scanning" on a query that finished on its own.
STOP_CONFIRMED = "confirmed"   # the engine said it stopped a query that was running
STOP_REQUESTED = "requested"   # the call was accepted, and that is all the engine reports
STOP_NOT_DONE = "not done"     # the call did not go through


def stop_query(logs_client, query_id: str) -> str:
    """Best-effort cancel of a CloudWatch Logs Insights query we stopped waiting for.

    Returns one of the three constants above. **Never raises**, and that is the whole
    contract: this runs on a give-up path that already has a message to deliver, so a failure
    here must neither replace that message nor swallow it.

    **The interesting failure is not an error.** Measured against real CloudWatch: stopping a
    running query returns `success: True`, stopping one that has already finished raises
    `InvalidParameterException`, and an unknown id raises `ResourceNotFoundException`. The
    first of those is the race this path is made of, since the query can complete between the
    last poll and this call, so it is expected rather than exceptional. (Stopping an
    already-*stopped* query returns True, which is harmless.)

    **Why the failure case does not distinguish "already finished" from "cancel failed".**
    Measurement says `InvalidParameterException` means the former, but the API reference names
    its exceptions without saying which case produces which, so branching on the exception
    would build a user-facing sentence on undocumented behaviour. The header below therefore
    words `STOP_NOT_DONE` conditionally instead of asserting the query is still running.

    Lives beside the messages rather than with the AWS clients because the two have to agree:
    the header says what happened based on what this returned, and splitting them is how a
    string ends up describing behaviour the code no longer has.
    """
    try:
        ok = bool(logs_client.stop_query(queryId=query_id).get("success"))
    except Exception:
        return STOP_NOT_DONE
    return STOP_CONFIRMED if ok else STOP_NOT_DONE


def stop_athena_query(athena_client, qid: str) -> str:
    """Best-effort cancel of an Athena query we stopped waiting for. Never raises.

    Returns `STOP_REQUESTED` rather than `STOP_CONFIRMED` on success, and the difference is
    the point: see the constants above. Athena reports nothing back, so this function cannot
    honestly claim more than that the request was accepted.

    **No terminal-state guard here, and the reason is the control flow rather than Athena
    being forgiving.** CloudWatch's caller checks the status first to avoid paying for an
    exception on an already-finished query. Athena needs no such check, not because a terminal
    target is a harmless no-op there (it is, measured), but because the only call site sits
    *after* the poll loop, which is reachable only when the last poll saw a non-terminal
    state: `SUCCEEDED` returns and `FAILED`/`CANCELLED` raise, both from inside the loop. The
    forgiveness covers the race, not the ordinary case. So nobody should add a guard the
    control flow already provides.

    **The un-redeployed window is self-describing, which is deliberate.** Between this
    shipping and `athena:StopQueryExecution` reaching the deployed role, the call gets
    `AccessDeniedException`, this returns `STOP_NOT_DONE`, and the message says the query was
    given up on and the cancel did not go through. Which is true. So the code degrades into
    the previous behaviour rather than into a wrong statement, and the redeploy is not
    time-pressured.
    """
    try:
        athena_client.stop_query_execution(QueryExecutionId=qid)
    except Exception:
        return STOP_NOT_DONE
    return STOP_REQUESTED


def _stop_header(engine: str, stop: str = STOP_NOT_DONE) -> str:
    """The first line of a give-up message, and it has to say which give-up happened.

    `stop` is not decoration. One shared sentence would tell a user the query was abandoned
    while the code had in fact stopped it, or the reverse. That is the permission-table defect
    inverted, a string understating what the code does rather than a document overstating it,
    so the verb takes what actually happened as an argument.

    Three branches rather than two, and the middle one is the honest reading of an engine that
    accepts a cancel and reports nothing. Same discipline as the retry advice below, which
    gives the action without asserting the cause: here the action was taken, and the sentence
    declines to promise an effect the engine never confirmed.

    `STOP_NOT_DONE` is worded conditionally on purpose. It covers a cancel that was refused
    and a query that had already ended, and nothing available here separates those, so
    "it is still running and still scanning" would be an assertion in the same class as the
    one already removed from the timeout advice.
    """
    fates = {
        STOP_CONFIRMED: "and was cancelled, so it has stopped scanning",
        STOP_REQUESTED: ("and a cancel was requested for it. This engine reports nothing back, "
                         "so that is not a promise the scan ended, and it does not rule out "
                         "the query having finished on its own a moment earlier"),
        STOP_NOT_DONE: ("and was given up on. The cancel did not go through, so if it is still "
                        "running it is still scanning"),
    }
    # `.get` and not `[]`. This builds a message on the give-up path, whose entire purpose is
    # to deliver an explanation instead of a crash, so a `KeyError` escaping here would replace
    # the explanation with the failure it exists to prevent. Unreachable today, since every
    # call site passes a helper's return value or the default, so the question is only what a
    # sixth site gets. The fallback costs nothing in honesty: it is both the parameter default
    # and the most conservative of the three, claiming no cancel happened. The case for `[]`
    # is that a bad value is a developer error and should fail loudly, and that is a fair
    # reading, but the tests on the sites that speak already deliver most of that, while the
    # crash mode lands on a user.
    fate = fates.get(stop, fates[STOP_NOT_DONE])
    return (f"STOPPED: the {engine} query was still running after {MAX_POLL} seconds "
            f"{fate}. This is a scan-size limit, NOT a data error and NOT a tool failure, "
            f"and it says nothing about whether traffic existed.")


def _athena_granularity() -> str | None:
    """The resolved table's partition granularity, or None when nothing is resolved.

    Derived from `partition_format` rather than read from a `partition_granularity` key,
    because `_record_table` publishes no such key: the granularity lives only in the
    metadata dicts `_table_metadata` and `_create_named_table` return.

    Imported inside the function because `waf_athena` imports this module at module level,
    so a top-level import here would be circular. `ImportError` only: any other failure
    should surface rather than quietly downgrade the advice below."""
    try:
        from tools.waf_athena import _athena_state, _partition_granularity
    except ImportError:
        return None
    return _partition_granularity(_athena_state.get("partition_format"))


def _narrowing_advice(engine: str) -> str:
    """Whether narrowing the window is worth anything on this table, which is not a given.

    Athena prunes by partition directory, so on an hourly table there is no sub-hour
    directory to skip: a 5-minute request and a 60-minute request scan **identical bytes**,
    measured in `docs/hourly-vs-minute-partitioning.md`. "Retry with a quarter of the
    window" is then advice that cannot work, and it spends the single retry this message
    allows. Narrowing still helps down to one hour, because that drops whole hour
    directories; below an hour it does nothing.

    The requested window is deliberately not threaded in here (see the caller's docstring),
    so this states the rule and lets the model apply it to the number it already knows."""
    generic = "retry ONCE with roughly a quarter of the window you just asked for."
    if engine != "Athena":
        # CloudWatch Logs Insights has no partitions, so a narrower window always scans
        # less. None of the reasoning below transfers.
        return generic
    granularity = _athena_granularity()
    if granularity not in ("hours", "days"):
        return generic
    unit = granularity[:-1]
    return (f"do NOT just cut the window. This table is partitioned by {unit}, so Athena "
            f"reads a whole {unit} whatever narrower window you ask for. Narrowing helps "
            f"only down to one {unit}, by dropping whole {granularity}; below that a "
            f"smaller window scans exactly the same bytes. If you already asked for one "
            f"{unit} or less, do not narrow at all, use get_waf_overview instead.")


def poll_timeout_message(engine: str, stop: str = STOP_NOT_DONE) -> str:
    """What to say when a query outlives `MAX_POLL`, and the retry bound.

    `stop` is one of the three constants above and changes the first sentence. It defaults to
    `STOP_NOT_DONE`, which is the safe default: the only thing it overstates is our own
    failure to cancel.

    Written for the user rather than as an instruction to the model, which is the whole
    point of the change. The text this replaced read "Narrow the time window, try
    duration_minutes=30 or duration_minutes=15", which the model received as a
    tool-result string and obeyed, while `agent.py` separately promised it was "always
    able to reduce until query succeeds". With no counter anywhere, three attempts was 15
    minutes of wall clock with nothing reaching the browser.

    So the bound lives here, in the only place that can hold it: consecutive timeouts are
    counted, one narrowing is invited, and the second timeout withdraws the invitation
    instead of repeating it. The count resets on any successful query, so a slow query
    mid-investigation does not poison the rest of the session.

    The narrower window is described proportionally rather than named. Naming it would
    mean threading the requested duration through three call layers for a cosmetic gain,
    and the model already knows what it asked for.
    """
    from tools.session_state import note_query_timeout
    attempt = note_query_timeout()
    if attempt == 1:
        narrow = _narrowing_advice(engine)
        # Says what happened and declines to say why, matching `_stop_header` two functions
        # up. The text here used to assert "the window was too large to scan
        # interactively", and on the one bucket this was verified against that was wrong:
        # the window was fine and the object count was the problem. Narrowing is still the
        # right *action*, because it is the only lever available from here, but it must not
        # arrive dressed as a diagnosis.
        return (f"{_stop_header(engine, stop)}\n"
                f"ACTION: {narrow} If you do not already know which minutes spiked, call "
                f"get_waf_overview first and query only those minutes. Do not retry more "
                f"than once. Tell the user the scan did not finish in time, that this can "
                f"be either too wide a window or data denser than the window suggests, and "
                f"that you cannot tell which from here.")
    return (f"{_stop_header(engine, stop)}\n"
            f"ACTION: do NOT retry. That is {attempt} timeouts in a row, so narrowing is "
            f"not working and the cost is in the scan rather than in the window. Tell the "
            f"user what you were trying to measure and that it needs either a much smaller "
            f"time range or an aggregate view, and offer get_waf_overview, which reads "
            f"pre-aggregated CloudWatch metrics and does not scan logs at all.")


def query_failed_message(engine: str, status: str, reason: str = "") -> str:
    """What to say when the engine itself reports a terminal non-success state.

    Separate from a poll timeout and deliberately not counted against the retry bound:
    `Failed` and `Cancelled` are not "too much data", so narrowing the window is not the
    remedy and inviting it would be misdirection. CloudWatch's own `Timeout` status is
    routed to `poll_timeout_message` instead, being the same situation as running out of
    poll budget.

    **`reason` defaults to empty because only one of the two engines has one, and that is a
    fact about the API rather than an omission at the call sites.** Athena's
    `GetQueryExecution` returns `Status.StateChangeReason`, and `_wait_query` passes it.
    CloudWatch's `GetQueryResults` has no reason or message field at all: checked against the
    botocore service model, its output shape is `encryptionKey`, `nextToken`, `queryLanguage`,
    `results`, `statistics`, `status`, and `status` is a bare enum. So the two CloudWatch call
    sites have nothing to pass. Said here because a defaulted parameter that only one of three
    callers uses looks exactly like the case where two of them forgot, which is the defect the
    Athena half was just fixed for.

    The throttling advice below keys off the engine's own text rather than a status code, which
    is deliberate: `HIVE_S3_THROTTLING` arrives as a reason string and cannot be reproduced on
    demand once the poll budget pre-empts it, so matching the word is how that knowledge
    survives without a test that can reach it.
    """
    # Athena's StateChangeReason does not end in punctuation, so concatenating produced
    # "...requested resources This is a query-execution failure". Seen in real output.
    reason = reason.strip()
    if reason and reason[-1] not in ".!?":
        reason += "."
    detail = f" Reason: {reason}" if reason else ""
    return (f"STOPPED: {engine} reported the query as {status}, so no rows were returned."
            f"{detail} This is a query-execution failure, NOT an absence of traffic.\n"
            f"ACTION: say so plainly rather than reporting zero results, and do not re-run the "
            f"same query unchanged. If the reason mentions throttling, re-running it "
            f"immediately makes the throttling worse rather than better.")
