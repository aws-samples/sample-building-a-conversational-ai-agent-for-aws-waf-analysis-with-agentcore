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
take". A query needing more than a couple of minutes has almost certainly failed to
prune; a long chain is a query-count problem instead.

**Not to be confused with the query window cap.** That is a different number: how many
minutes of logs a query may ask for, `MAX_MINUTES` in `waf_logs.py` for CloudWatch Logs.
Athena's window cap currently exists only in prose. Enforcing that one is ROADMAP 3.1.
"""

# One deliberate value, the tightest of the five it replaces. Raising this is almost
# always the wrong response to a timeout: see the module docstring.
MAX_POLL = 120
POLL_INTERVAL = 2


def _stop_header(engine: str) -> str:
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


def query_failed_message(engine: str, status: str) -> str:
    """What to say when the engine itself reports a terminal non-success state.

    Separate from a poll timeout and deliberately not counted against the retry bound:
    `Failed` and `Cancelled` are not "too much data", so narrowing the window is not the
    remedy and inviting it would be misdirection. CloudWatch's own `Timeout` status is
    routed to `poll_timeout_message` instead, being the same situation as running out of
    poll budget.
    """
    return (f"STOPPED: {engine} reported the query as {status}, so no rows were returned. "
            f"This is a query-execution failure, NOT an absence of traffic.\n"
            f"ACTION: say so plainly rather than reporting zero results, and do not "
            f"re-run the same query unchanged.")
