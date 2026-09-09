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

**Not to be confused with the query window cap**, which is how many minutes of logs a
query may ask for. Athena's is prose-only and enforcing it is ROADMAP 3.1. CloudWatch's is
real: `MAX_MINUTES = 360` in `waf_logs.py`. **That pair is inconsistent and 2.1 records it
as an open decision** rather than pretending this file settled it: the product will accept
a six-hour CloudWatch request and give it two minutes. Either the window comes down or
this comes up, and picking one needs evidence about how long a real six-hour Insights
query takes, which nobody has gathered.
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

# The fan-out budget, which is a different kind of limit and the one that actually governs
# patrol. `MAX_POLL` bounds ONE query; this bounds a whole batch submitted to a thread pool,
# in wall clock, and it is what `concurrent.futures.as_completed(timeout=...)` takes.
#
# **Their relative size decides which one fires, and patrol's answer is this one.** Patrol
# submits three queries per rule for up to five rules, so fifteen futures over five workers
# is three waves. At any per-query budget above a third of this, the batch runs out first and
# the per-query budget is unreachable there. That was already true before `MAX_POLL` was
# unified: 60 per query over three waves is 180, against 120 here. So patrol has always been
# bounded by the batch rather than by the query, and raising its per-query budget to 120
# changed nothing about how long a patrol takes.
#
# Kept at 120 for that reason, rather than widened to cover three full waves. Widening it
# would make patrol slower to give up without making it more likely to answer.
MAX_FANOUT_WAIT = 120


def _stop_header(engine: str) -> str:
    # "given up on" rather than "cancelled", because nothing cancels it. There is no
    # StopQueryExecution or StopQuery call anywhere in the product, so the query keeps
    # running after this message is written. ROADMAP 2.4 owns cancellation, and 2.1's
    # status records why the retry bound here wants it.
    return (f"STOPPED: the {engine} query was still running after {MAX_POLL} seconds and "
            f"was given up on. This is a scan-size limit, NOT a data error and NOT a tool "
            f"failure, and it says nothing about whether traffic existed.")


def poll_timeout_message(engine: str) -> str:
    """What to say when a query outlives `MAX_POLL`, and the retry bound.

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
        return (f"{_stop_header(engine)}\n"
                f"ACTION: tell the user the window was too large to scan interactively, "
                f"then retry ONCE with roughly a quarter of the window you just asked for. "
                f"If you do not already know which minutes spiked, call get_waf_overview "
                f"first and query only those minutes. Do not retry more than once.")
    return (f"{_stop_header(engine)}\n"
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
    """
    detail = f" Reason: {reason}" if reason else ""
    return (f"STOPPED: {engine} reported the query as {status}, so no rows were returned."
            f"{detail} This is a query-execution failure, NOT an absence of traffic.\n"
            f"ACTION: say so plainly rather than reporting zero results, and do not re-run the "
            f"same query unchanged. If the reason mentions throttling, re-running it "
            f"immediately makes the throttling worse rather than better.")
