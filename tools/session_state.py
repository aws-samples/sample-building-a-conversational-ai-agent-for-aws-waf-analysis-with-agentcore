# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Session state — stores current WebACL context for cross-tool coordination."""

# Populated by get_waf_config, consumed by other tools
import threading

_state: dict = {}


def set_webacl_context(name: str, arn: str, scope: str, region: str, log_destination: str | None = None,
                       log_filter_active: bool = False, log_filter_default: str | None = None,
                       redacted_fields: tuple = ()):
    """Store current WebACL context."""
    _state["webacl_name"] = name
    _state["webacl_arn"] = arn
    _state["scope"] = scope
    _state["waf_region"] = region
    _state["metrics_region"] = "us-east-1" if scope == "CLOUDFRONT" else region
    _state["log_destination"] = log_destination
    _state["log_filter_active"] = log_filter_active
    _state["log_filter_default"] = log_filter_default
    # ROADMAP 6.13's filter half. Normalised at the read so nothing downstream normalises again;
    # `()` and not None because `RedactedFields` is ABSENT from GetLoggingConfiguration when
    # unconfigured rather than present-and-empty, and a caller must not have to tell those apart.
    _state["redacted_fields"] = tuple(redacted_fields)
    _state["findings"] = []

    # The resolved-table state (waf_athena._athena_state) is keyed to the previous
    # WebACL's S3 path, and it also memoizes the destination-to-path translation and
    # the Athena output location. Reset it on every WebACL switch so we never reuse a
    # stale, wrong-location table. There is exactly one such cache; an earlier
    # duplicate in waf_query is gone. Local import avoids a module-level circular
    # dependency.
    try:
        from tools.waf_query import reset_table_cache
        reset_table_cache()
    except Exception:
        pass


def note_query_timeout() -> int:
    """Record a query poll timeout and return how many have happened in a row.

    The retry bound in `query_limits.poll_timeout_message` reads this. Consecutive rather
    than cumulative: one slow query early in a session should not change what the tenth
    query is told, so any success clears it.
    """
    _state["query_timeouts"] = _state.get("query_timeouts", 0) + 1
    return _state["query_timeouts"]


def note_query_success():
    """Clear the consecutive-timeout count. Called wherever a query completes."""
    _state["query_timeouts"] = 0


def set_capabilities(capabilities: dict):
    """Store detected AWS WAF capabilities."""
    _state["capabilities"] = capabilities


def get_capabilities() -> dict:
    """Get detected AWS WAF capabilities."""
    return _state.get("capabilities", {})


def get_logs_region() -> str:
    """Raw accessor for the region where WAF logs live (CWL group / Athena S3).

    Used by the query executors (waf_query, waf_logs) which run only AFTER the
    log destination has been resolved, so session state is always initialized.
    For scope-based region derivation use resolve_region(scope) instead — it is
    fail-loud (returns None when REGIONAL session state is missing).
    """
    return _state.get("metrics_region", "us-east-1")


def get_log_destination() -> str | None:
    """Get the discovered log destination (CW Logs group or S3 bucket)."""
    return _state.get("log_destination")


def is_log_filter_active() -> bool:
    """Check if a log filter is active (logs may be incomplete)."""
    return _state.get("log_filter_active", False)


def set_user_timezone(offset: float):
    """Store user's timezone offset (hours from UTC). Supports half-hour offsets (e.g. 5.5 for India)."""
    _state["user_tz_offset"] = offset


def get_user_timezone() -> float | None:
    """Get user's timezone offset. Returns None if not yet determined."""
    return _state.get("user_tz_offset")


def get_webacl_name() -> str | None:
    return _state.get("webacl_name")


def resolve_region(scope: str) -> str | None:
    """Resolve the correct AWS region for a given scope.

    Returns the region string, or None if REGIONAL scope is used but session
    state hasn't been initialized (caller should return error to LLM).
    """
    if scope == "CLOUDFRONT":
        return "us-east-1"
    # REGIONAL: need session state to know the region
    if not _state.get("webacl_name"):
        return None
    return _state.get("metrics_region", "us-east-1")


def get_scope() -> str:
    return _state.get("scope", "CLOUDFRONT")


def set_host_profiles(profiles: dict):
    """Store host traffic profiles (frontend/backend/mixed classification)."""
    _state["host_profiles"] = profiles


def get_host_profiles() -> dict:
    """Get host traffic profiles."""
    return _state.get("host_profiles", {})


# Investigation findings accumulator
def add_finding(finding: dict):
    """Append a finding to the session."""
    _state.setdefault("findings", []).append(finding)


def get_redacted_fields() -> tuple:
    """The WebACL's logging RedactedFields, normalised, or `()` when none are configured.

    Vocabulary matches the `redactable_filter` declarations exactly: `Method`, `UriPath`,
    `QueryString`, `SingleHeader:<lowercased name>`. Header names are lowercased here because HTTP
    header names are case-insensitive while a config may spell one any way at all, so comparing raw
    would miss `Host` against a declaration written `host`."""
    return _state.get("redacted_fields", ())


def get_findings() -> list:
    """Get all findings recorded in this session."""
    return _state.get("findings", [])


def clear_findings():
    """Reset findings (for new investigation)."""
    _state["findings"] = []


# --- ROADMAP 7.2: provenance the frontend renders, not the model ------------
#
# **Measured 2026-09-13: the model reads the `SOURCE:` line and does not relay it.** In one verification
# session `SOURCE:` appeared nowhere in the answer while the same answer proved the line had been read,
# because it noticed the loaded WebACL was the wrong one and reloaded. So instruction-following is the
# link that is already failing here, and another prompt rule would be a second layer on the same
# unreliable mechanism. These facts are recorded by the query layer and emitted as their own event, so
# what the user sees does not depend on the model choosing to repeat it.

_provenance_lock = threading.Lock()


def note_query_provenance(engine: str, start_epoch: int, end_epoch: int, subject: str | None = None):
    """Record which engine was asked and over which window. Once per query ATTEMPT, merged per tool call.

    **`subject` overrides the session WebACL, and one path needs it.** `run_logs_query(log_group=...)`
    builds its own CloudWatch client and calls `start_query` directly, so it never reaches `query_logs`
    and the session's WebACL was not consulted at all. Naming that WebACL would be a false statement of
    exactly the kind this record exists to remove, so that path passes the log group instead.

    **`webacl` stays one value while `engines` is a list, and that asymmetry is measured rather than
    accidental.** Two engines in one tool call is ordinary: three tools pair a log query with a metric
    read. Two subjects in one tool call is not reachable today, because every query's destination comes
    from session state and the single path that overrides it is a one-query tool. If a tool ever mixes
    them, this field needs what `engines` got.

    **`engines` is a list because one tool call reads two, and a single field would name the last
    writer.** It was a single value while `query_logs` was the only recorder, since the log destination
    fixes one engine for the session. Three tools already pair a log query with a CloudWatch metric read
    in the same call, through `missed_data_warning` and `missed_action_warning`: `waf_injection`,
    `waf_challenge_check` and `waf_count_eval`. The last is the clearest case for a list rather than a
    field: its log query is at line 55 and its metric read at line 490, so last-writer-wins would label a
    conclusion drawn from logs `CloudWatch metrics`. In reading order rather than sorted, because a set's
    iteration order is randomised per process and a display string that changes between runs cannot be
    asserted.

    **`queries` counts attempts, not queries that ran, and that follows from where this is called.** It
    runs as the first statement of each engine branch, before `_ensure_athena_table`, before the
    coarse-partition refusal and before the `range_problem` refusal, so `Athena over S3 · 1 query` beside
    zero executed queries is a reachable state: the coarse-partition case is pre-checked at all nine tool
    entry points and this is only a backstop there, but a table that fails to build and an unprojectable
    range have no such pre-check. That is the intended side. **A query that dies in table resolution
    still discloses the window it asked about**, which is exactly when a user needs to know what was
    asked, and it is the same reason the record is written on entry rather than on completion.

    `queries` counts them because one tool call issues up to fifteen, and a user reading "CloudWatch,
    12:37 to 18:37" deserves to know whether that describes one query or fifteen. The window is stored
    as epochs so the renderer can show both the session-local and the UTC pair without re-deriving
    either from a string.

    **Locked, because all three merges are read-modify-write and concurrency reaches this by default.**
    `waf_query.run_concurrently` submits every independent query of a tool call to a
    `ThreadPoolExecutor` and `_cwl_semaphore` allows eight at once, so two threads read `queries` as 3
    and both write 4. Both losses point the wrong way: an undercount reports fifteen queries as fewer,
    which is the one thing this counter exists to say, and a lost `min` reports a window narrower than
    what was read, which attributes a finding from 05:00 to a window starting at 06:46. That is a
    misattribution, and misattribution is what this whole record was built to prevent.

    The lock is `waf_query._value_findings_lock`'s shape, four call sites in the file that calls this
    one, and not using it was the sixth time a capability sat in this repository unreferenced.

    Read through the accessors rather than by key. Both were guessed from their function names on the
    first draft and `user_timezone` is spelled `user_tz_offset`, so the offset silently recorded as
    None: a plausible key name for a value that is never there is the same defect as a plausible API
    field, and it fails the same quiet way.
    """
    with _provenance_lock:
        p = _state.setdefault("provenance", {})
        p["webacl"] = subject or get_webacl_name()
        # Which of the two `SOURCE:` texts applies. Carried as a bit rather than inferred from the
        # subject's shape, because "does it start with 'log group'" is a guess about a string and this is
        # a fact the caller knows.
        p["subject_explicit"] = subject is not None
        engines = p.setdefault("engines", [])
        if engine not in engines:
            engines.append(engine)
        p["tz_offset"] = get_user_timezone()
        p["start"] = min(start_epoch, p["start"]) if "start" in p else start_epoch
        p["end"] = max(end_epoch, p["end"]) if "end" in p else end_epoch
        p["queries"] = p.get("queries", 0) + 1


# Only the streaming loop pops from the stash and the CLI never does, so without a bound a long CLI
# process would keep every record it ever made. A tool call issues at most fifteen queries and a turn a
# handful of tool calls, so this is far above anything real; it exists to make the growth impossible
# rather than unlikely.
_STASH_LIMIT = 64


def stash_query_provenance(tool_use_id: str) -> dict:
    """Drain the record and keep it under this tool call's id. Returns what was drained.

    **The hook is the only drain point, and that is what fixes the CLI path.** `take_query_provenance`
    used to be called once, inside the SSE generator, so `invoke` never cleared anything: measured on
    2026-09-14, a second tool call in one CLI run rendered `SOURCE: webacl-B` over a 167-hour window that
    spanned the first tool's query of webacl-A. A subject and a window contradicting each other is the
    misattribution this record exists to remove, and before the hook existed the CLI line was rendered
    fresh with no window at all, so this was a regression on that path rather than an old gap.

    Draining here rather than clearing in `invoke` is the part that matters: clearing at the end of a turn
    still lets the second tool call in that turn inherit the first one's window.

    **An empty `tool_use_id` drains without stashing**, so the model would get its line and the chip
    nothing, with no live record left for the fallback. Counted in `SourceDisclosure`'s docstring rather
    than guarded: `toolResult.toolUseId` is required by the Converse API and is where the streaming loop's
    id comes from, so the state is unreachable, and a guard against an impossible input hides the reason it
    is impossible.
    """
    with _provenance_lock:
        record = _state.pop("provenance", {})
        if record and tool_use_id:
            # **Inside `_state` rather than a module global**, because `tests/conftest.py`'s autouse
            # `_isolate_module_state` clears `_state` and nothing else. A module-level dict here made that
            # fixture's own claim false for one container in this file: harmless while a single test file
            # touched the stash, and a leak between files the day a second one does.
            stash = _state.setdefault("provenance_stash", {})
            stash[tool_use_id] = record
            while len(stash) > _STASH_LIMIT:
                stash.pop(next(iter(stash)))
        return record


def provenance_source_line(p: dict) -> str:
    """The `SOURCE:` line, for the model rather than for the user.

    **The model reads this and acts on it, and does not repeat it**, measured 2026-09-13: in one
    verification session it noticed the loaded WebACL was wrong and reloaded before querying, and the
    line appeared nowhere in its answer. So this text and the frontend chip are two renderings of one
    record with two audiences, and this one carries the instruction because the model is the only reader
    who can act on it.

    The defect it exists for: a log tool takes its destination from session state and has no idea which
    WebACL the question was about, so a question about one WebACL is answered from another's logs with no
    error. Measured 2026-09-12 on a real investigation, where the answer came from a WebACL logging to
    Firehose while the question was about one logging to CloudWatch.
    """
    engines = " + ".join(p.get("engines") or []) or "no engine"
    subject = p.get("webacl") or "(none set)"
    if p.get("subject_explicit"):
        # **The other text, and dropping it made the line contradict itself.** Merging the two emitters
        # kept only the session-derived wording, so on the one path that needs a subject the line called a
        # log group "the WebACL from the last get_waf_config call" and then told the model to call
        # get_waf_config and run the query again. The user had just bypassed the session context
        # deliberately; that instruction is an order to bypass the bypass, issued on a false premise. Same
        # class as the ALLOW probe that told a user to change their logging filter because a query timed
        # out.
        return (f"SOURCE: {subject} via {engines}, passed explicitly, so the session's WebACL context was "
                f"not consulted.")
    return (f"SOURCE: {subject} via {engines}. That is the WebACL from the last "
            f"get_waf_config call, not from your question. If it is not the one you asked about, call "
            f"get_waf_config(webacl_name='...') and run this again.")


def take_query_provenance(tool_use_id: str | None = None) -> dict:
    """The record for the tool call that just finished, and clear it.

    Cleared on read so the next tool call cannot inherit the previous one's window. Returning `{}` for a
    tool that ran no log query is the point: a config-only tool has no window to disclose, and inventing
    one would be the same defect this exists to fix.

    **The stash first, then the live record, and the fallback is deliberate.** `SourceDisclosure` drains
    into the stash before this runs, so the stash is the normal path. Falling back keeps the two
    degradations independent: if the hook does not fire, the model loses its `SOURCE:` line and the chip
    still renders, where a stash with no fallback would lose both. "Does the hook fire" is on the
    post-deploy checklist precisely because nothing here can answer it.
    """
    with _provenance_lock:
        if tool_use_id is not None:
            record = (_state.get("provenance_stash") or {}).pop(tool_use_id, None)
            if record:
                return record
        return _state.pop("provenance", {})
