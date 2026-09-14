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


def note_query_provenance(engine: str, start_epoch: int, end_epoch: int):
    """Record which engine was asked and over which window. Once per query ATTEMPT, merged per tool call.

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
        p["webacl"] = get_webacl_name()
        engines = p.setdefault("engines", [])
        if engine not in engines:
            engines.append(engine)
        p["tz_offset"] = get_user_timezone()
        p["start"] = min(start_epoch, p["start"]) if "start" in p else start_epoch
        p["end"] = max(end_epoch, p["end"]) if "end" in p else end_epoch
        p["queries"] = p.get("queries", 0) + 1


def take_query_provenance() -> dict:
    """The record for the tool call that just finished, and clear it.

    Cleared on read so the next tool call cannot inherit the previous one's window. Returning `{}` for a
    tool that ran no log query is the point: a config-only tool has no window to disclose, and inventing
    one would be the same defect this exists to fix.
    """
    with _provenance_lock:
        return _state.pop("provenance", {})
