# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF CloudWatch Metrics tool."""

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import declare_query_subject, get_scope, get_webacl_name, resolve_region

MAX_RESULTS = 25


@tool
def get_waf_metrics(
    webacl_name: str,
    metric_name: str = "AllowedRequests",
    period_hours: int = 168,
    stat: str = "Sum",
    dimension_filters: str = "",
    region: str = "auto",
    use_search: bool = False,
    search_expression: str = "",
) -> str:
    """Query CloudWatch Metrics for AWS WAF statistics.

    Args:
        webacl_name: WebACL name (used as dimension value).
        metric_name: One of: AllowedRequests, BlockedRequests, CountedRequests,
            ChallengeRequests, BlockRuleMatch, CountRuleMatch, ChallengeRuleMatch.
        period_hours: Time range to query (default 168 = 7 days).
        stat: Statistic — Sum, Average, Maximum, SampleCount.
        dimension_filters: Optional JSON string of extra dimensions, e.g.
            '{"Rule": "my-rate-rule"}' or '{"Country": "CN"}'.
        region: AWS region. Defaults to "auto" (resolved from WebACL context);
            REGIONAL scope requires get_waf_config to have been called first.
        use_search: If true, use SEARCH expression instead of specific metric.
        search_expression: CloudWatch SEARCH expression. Only used if use_search=true.
            Example: SEARCH('{AWS/WAFV2,LabelName,LabelNamespace,WebACL} WebACL="xxx"', 'Sum', 3600)

    Returns:
        Metric data points formatted as a table, or SEARCH results.
    """
    declare_query_subject(webacl_name)
    if region == "auto":
        from tools.session_state import resolve_region
        scope = get_scope()
        region = resolve_region(scope)
        if region is None:
            return ("Error: REGIONAL scope requires get_waf_config to be called first "
                    "(need to know which region the WebACL is in). "
                    "Call get_waf_config(webacl_name='...') first.")
    client = get_client("cloudwatch", region_name=region)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=period_hours)

    if use_search and search_expression:
        return _search_metrics(client, search_expression, start_time, end_time)

    # Build dimensions
    dimensions = [{"Name": "WebACL", "Value": webacl_name}, {"Name": "Rule", "Value": "ALL"}]
    if get_scope() != "CLOUDFRONT":
        dimensions.append({"Name": "Region", "Value": region})
    if dimension_filters:
        extra = json.loads(dimension_filters)
        # Replace default Rule if specified
        if "Rule" in extra:
            dimensions = [d for d in dimensions if d["Name"] != "Rule"]
        dimensions.extend([{"Name": k, "Value": v} for k, v in extra.items()])

    # Granularity, and **never 86400**. A daily period buckets from `StartTime`, which is
    # `now - period_hours`, so the buckets begin at whatever time of day the question was asked
    # while the "Date" column below labels each one with its own start. Measured 2026-09-13 at
    # 10:50 UTC: `period_hours=720` reported the 566,070-request rate-limit attack under
    # `2026-09-07`, when 2026-09-07 00:00-24:00 UTC holds zero and the attack was 2026-09-08
    # 04:15 UTC, 12:15 in the session's UTC+8. Asked in the morning and in the evening, the same
    # event landed on different days.
    #
    # Hour buckets are aligned to the hour, so grouping them by local date is correct for every
    # offset the frontend offers, including the quarter-hour ones. `period_hours <= 168` already
    # took this path and answered correctly, which is why the two ranges disagreed with each other
    # and neither said which to believe. 1-hour resolution is retained for 455 days, so this
    # costs nothing in reach; it costs datapoints, and a year of hours is 8760 against the
    # 100,800 a single request may return.
    if period_hours > 24 * 455:
        return (f"Error: CloudWatch keeps 1-hour metric data for 455 days, so a {period_hours}h "
                f"window would silently drop everything older and report the remainder as the "
                f"whole. Ask for 10920 hours or less, or say that the earlier period is "
                f"unavailable.")
    period = 300 if period_hours <= 24 else 3600

    resp = client.get_metric_data(
        MetricDataQueries=[{
            "Id": "m1",
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/WAFV2",
                    "MetricName": metric_name,
                    "Dimensions": dimensions,
                },
                "Period": period,
                "Stat": stat,
            },
        }],
        StartTime=start_time,
        EndTime=end_time,
        ScanBy="TimestampAscending",
    )

    results = resp.get("MetricDataResults", [])
    if not results or not results[0].get("Values"):
        return f"No data for {metric_name} (WebACL={webacl_name}, last {period_hours}h)"

    data = results[0]
    timestamps = data["Timestamps"]
    values = data["Values"]
    total = sum(values)

    # Convert timestamps to user timezone
    from tools.session_state import get_user_timezone
    tz_off = get_user_timezone()
    if tz_off is not None:
        user_tz = timezone(timedelta(hours=tz_off))
        timestamps = [t.astimezone(user_tz) for t in timestamps]

    # Format output
    lines = [
        f"## {metric_name} — {webacl_name} (last {period_hours}h)",
        f"Total: {total:,.0f}",
        f"Data points: {len(values)}",
        "",
    ]

    # Show daily aggregates for 7-day queries
    if period_hours >= 168:
        daily = {}
        for ts, val in zip(timestamps, values):
            day = ts.strftime("%Y-%m-%d")
            daily[day] = daily.get(day, 0) + val
        lines.append("| Date | Count |")
        lines.append("|------|-------|")
        for day in sorted(daily.keys()):
            lines.append(f"| {day} | {daily[day]:,.0f} |")
    else:
        # Show last N data points
        for ts, val in zip(timestamps[-MAX_RESULTS:], values[-MAX_RESULTS:]):
            lines.append(f"  {ts.strftime('%m-%d %H:%M')}  {val:,.0f}")

    lines.append("\n---\nFor quick overview: get_waf_overview(query_type='top_rules', webacl_name='...')\nFor IP/URI details: ask user for time period, then use run_logs_query with start_time.")

    return "\n".join(lines)


# --- ROADMAP 7.1/7.7: the one observation that says a log query missed data -----------------
#
# A log query returning zero is byte-identical to the attack not having happened, so the
# reassuring answer is the one a broken query produces. CloudWatch metrics are the only witness
# that no partition layout, engine difference, logging filter or query timeout can touch. That is
# an accuracy property; it happens to also be free, and the accuracy is the reason.
#
# **The invariant, and it covers the reads and not only the returns: a diagnostic's own failure is
# never a message about the thing it diagnoses.** Written this wide because the narrow version, "every
# refusal path returns silence with the reason on stderr", was satisfied while a `get_web_acl` call
# added to resolve a dimension propagated its exception out and took an answer the tool had already
# produced. That read was outside a rule about return values and inside this one. So anything a
# diagnostic does, including the calls it makes to decide what to say, either yields silence with a
# stderr line or does not belong here.

# CloudWatch metric retention, in days, per resolution. Measured 2026-09-13: asking for a
# resolution that is no longer retained returns `StatusCode: Complete` with an empty `Values` and
# no `Messages`, which is indistinguishable from "this rule blocked nothing". For a day 20 days old
# holding 2 blocked requests, `Period=60` returned nothing and `Period=300` returned 2.
_RETENTION_DAYS = ((15, 60), (63, 300), (455, 3600))


def _period_for_window(start_epoch: int) -> int | None:
    """The finest resolution still retained for the OLDEST point in the window, or None.

    **Keyed on the oldest point, not the newest, and that is the whole content of this function.**
    A 30-day window ending today straddles the 15-day boundary: choosing by its recent end gives
    `Period=60`, and the older half comes back silently empty. Choosing by its oldest point gives
    `Period=300`, which covers the whole span.

    `get_waf_metrics` above can pick by range length instead, because its window always ends now,
    so the range and the age of its oldest point are the same number. Anything taking an arbitrary
    window must use this.
    """
    age_days = (time.time() - start_epoch) / 86400
    for limit, period in _RETENTION_DAYS:
        if age_days <= limit:
            return period
    return None


def rule_blocked_per_metrics(webacl_name: str, rule_name: str, rules: list, start_epoch: int,
                             end_epoch: int, metric_name: str = "BlockedRequests"):
    """What CloudWatch says this rule terminated in this window. `(count, reason)`, never raises.

    `count` is None whenever the question could not be asked, and `reason` says which of the four
    ways. A zero is only ever returned when the query really answered.

    **The rule name is checked against `rules` on the way into the query, not trusted because it
    came from a config read somewhere upstream.** Measured 2026-09-13: a `MetricStat` for a rule
    name that does not exist returns series present, `StatusCode: Complete`, `Values: []`,
    `Messages: []` — byte-identical to a real rule that blocked nothing. Nothing in the response
    can tell them apart, so a typo would arrive as a confident zero, and the only defence is the
    name's provenance. A name three calls old, or one the model composed, is not that. The
    membership test's own input is a configuration read, which 7.4's first rule says needs no
    qualifier because it is complete and verifiable.

    **The dimension value is `VisibilityConfig.MetricName`, never the rule's `Name`.** They are
    equal for all 20 rules on the measurement account, which is exactly why assuming it would never
    be caught here. Reading the metric name removes the assumption instead of testing it.
    """
    dimension, in_config = resolve_rule_dimension(rule_name, rules)
    if in_config == "metrics-off":
        return None, (f"'{rule_name}' has CloudWatchMetricsEnabled false, so it publishes no "
                      f"metric at all and its absence here means nothing")
    return _metric_sum(webacl_name, dimension, metric_name, start_epoch, end_epoch)


def resolve_rule_dimension(rule_name: str, rules: list):
    """The CloudWatch `Rule` dimension value for a rule name, and whether the config knew it.

    Returns `(dimension_value, state)` where state is `"top-level"`, `"override"`, `"metrics-off"`
    or `"unknown"`.

    **When a caller must read `state`, stated here so the field carries its own condition rather than
    waiting for someone to guess what it is for: if you are going to treat a returned zero as
    evidence of anything, you must require `"top-level"` or `"override"` and refuse otherwise.** On
    `"unknown"` a zero is uninformative, because a misspelled name and a rule that published nothing
    produce the identical response. A caller that only acts on a count above zero may ignore `state`
    entirely, which is why `missed_data_warning` does. There is no such zero-as-evidence caller today;
    the field exists so that adding one is a decision instead of an oversight.

    **The WebACL configuration is not a complete list of the names that publish a `Rule`
    dimension, and that is measured rather than assumed.** On `shield-sample-webacl`,
    `TGT_TokenAbsent` publishes `CountedRequests` 33,932 for 2026-09-08 while appearing in no
    `Rules[].Name` and in no `RuleActionOverrides`: a managed rule group publishes metrics for its
    internal rules, and only the overridden ones are written into the config. A `SEARCH` over
    `{AWS/WAFV2,Rule,WebACL}` does find it, but SEARCH's 14-day discovery window means absent
    there does not mean invalid either. So no available source can separate "this name is
    misspelled" from "this rule published nothing".

    **Which is why `"unknown"` queries anyway instead of refusing.** An earlier version refused,
    and it refused `TGT_TokenAbsent`: the guard cost a real 33,932-match signal and prevented
    nothing, because the only consumer speaks when the count is above zero, where a misspelling
    yields zero and stays silent. The state is returned rather than dropped so a future caller that
    wants to treat a zero as evidence can demand `"top-level"` or `"override"` and get the refusal
    this path should not have.
    """
    match = next((r for r in rules if r.get("Name") == rule_name), None)
    if match is not None:
        visibility = match.get("VisibilityConfig") or {}
        if not visibility.get("CloudWatchMetricsEnabled", True):
            return rule_name, "metrics-off"
        return visibility.get("MetricName") or rule_name, "top-level"
    for r in rules:
        overrides = (r.get("Statement", {}).get("ManagedRuleGroupStatement", {})
                     .get("RuleActionOverrides", []))
        if any(o.get("Name") == rule_name for o in overrides):
            return rule_name, "override"
    return rule_name, "unknown"


def webacl_action_total(webacl_name: str, metric_name: str, start_epoch: int, end_epoch: int):
    """The same question asked of the whole WebACL, for a tool whose subject is an action.

    `check_challenge_compatibility` asks "were there any CHALLENGE requests", which names no rule,
    and `ChallengeRequests` / `CaptchaRequests` on `Rule=ALL` is a witness with exactly that
    subject. **No membership check here, and its absence is not an oversight**: `ALL` is an
    aggregate the service publishes rather than a name a caller can misspell, so the failure mode
    that guard exists for cannot occur. The retention guard still applies and lives in
    `_metric_sum`.
    """
    return _metric_sum(webacl_name, "ALL", metric_name, start_epoch, end_epoch)


def _metric_sum(webacl_name: str, rule_dimension: str, metric_name: str, start_epoch: int,
                end_epoch: int):
    """One `MetricStat` over one window. `(sum, "")`, or `(None, reason)`. Never raises.

    The retention guard sits here rather than in each caller, because a period no longer retained
    returns `StatusCode: Complete` with an empty `Values`, so a caller that skipped it would get a
    confident zero and never know.
    """
    period = _period_for_window(start_epoch)
    if period is None:
        return None, ("the window starts more than 455 days ago, beyond every CloudWatch metric "
                      "resolution, so there is no metric to compare against")

    dimensions = [{"Name": "WebACL", "Value": webacl_name},
                  {"Name": "Rule", "Value": rule_dimension}]
    scope = get_scope()
    region = resolve_region(scope)
    if region is None:
        return None, "REGIONAL scope needs get_waf_config first, so the metrics region is unknown"
    if scope != "CLOUDFRONT":
        dimensions.append({"Name": "Region", "Value": region})

    try:
        resp = get_client("cloudwatch", region_name=region).get_metric_data(
            MetricDataQueries=[{"Id": "m1", "MetricStat": {
                "Metric": {"Namespace": "AWS/WAFV2", "MetricName": metric_name,
                           "Dimensions": dimensions},
                "Period": period, "Stat": "Sum"}}],
            StartTime=datetime.fromtimestamp(start_epoch, timezone.utc),
            EndTime=datetime.fromtimestamp(end_epoch, timezone.utc),
            ScanBy="TimestampAscending")
    except Exception as exc:                              # noqa: BLE001
        return None, f"the metric query did not run: {type(exc).__name__}: {exc}"

    results = resp.get("MetricDataResults", [])
    if not results:
        return None, "the metric query returned no series, so it answered nothing"
    return int(sum(results[0].get("Values", []))), ""


def missed_data_warning(webacl_name: str, rule_name: str, rules: list, start_epoch: int,
                        end_epoch: int, log_rows: int, metric_name: str = "BlockedRequests") -> str:
    """The sentence to add when the metric says a rule fired and the logs hold less than it says.

    **Widened past the exactly-zero case on 2026-09-15, and `log_rows` has to mean requests.** The
    earlier limit was written as a dependency on the truncation disclosure, and reading the callers
    showed that was only half of it. All three passed a literal `0` that their own emptiness test had
    established, so the `!= 0` gate was narrowing nothing. What blocked the widening was that the one
    caller with rows to count had them from `stats count(*) as hits by httpRequest.clientIp | limit 5`,
    where the row count is a number of distinct IPs capped at five. Summing that column instead would
    have given a lower bound that goes silent exactly on windows with many distinct clients, which are
    the busy ones, where missing data matters most. So the caller sends one ungrouped count with the
    same filter, which is immune to truncation by construction rather than corrected for it.

    **The two counts are only comparable on a window aligned to the metric period**, measured on
    2026-09-08 against `rate-limit`, whose 566,070 blocks make the skew visible:

        04:16-04:22, 6 min, spans the traffic   metric 566,070  log 566,070   0.000%
        04:15-04:25, 10 min, spans the traffic  metric 566,070  log 566,070   0.000%
        04:17-04:21, a boundary cuts traffic    metric 477,480  log 478,880  -0.293%
        04:16:30-04:20:30, unaligned            metric 432,530  log 478,488 -10.630%

    A window whose boundaries do not fall on the period covers a different span in the metric than in
    the logs, so it is refused rather than compared. Within an aligned window the residual skew is
    `@timestamp` against the request's own time, which shifts records across a boundary.

    **The threshold is `max(1, 5%)` and both numbers have a basis.** 5% is seventeen times the
    largest aligned skew measured; the absolute floor of one handles a quiet window, where a
    percentage of three requests means nothing. All four measurements above have the metric lower than
    the logs, which is the harmless direction here, but three of them sit inside one ramping attack, so
    the direction is not established and the threshold is two-sided in effect.

    **What the threshold hides, stated rather than left out.** A real gap between 0.3% and 5% is not
    distinguishable from boundary skew with what is available. The failure modes this check exists for
    are all far above that: a `LoggingFilter` dropping an action drops all of it, a partition or
    timezone mismatch drops whole hours, and a silently failed query drops everything. So the blind
    spot is a band this check cannot resolve rather than a class of failure it declines to look at.

    Returns "" when there is nothing to say, which includes every case where the metric could not
    answer. A failure to reach CloudWatch must not turn into a claim about the logs, and the reason
    is on stderr rather than in the report because this runs beside a conclusion the tool already
    reached.
    """
    count, reason = rule_blocked_per_metrics(webacl_name, rule_name, rules, start_epoch, end_epoch,
                                             metric_name)
    if log_rows == 0:
        return _missed_data_sentence(count, reason, f"rule '{rule_name}'", webacl_name, metric_name)
    return _partial_gap_sentence(count, reason, rule_name, webacl_name, metric_name, log_rows,
                                 start_epoch, end_epoch)


_GAP_FRACTION = 0.05


def _partial_gap_sentence(count, reason: str, rule_name: str, webacl_name: str, metric_name: str,
                          log_rows: int, start_epoch: int, end_epoch: int) -> str:
    """The sentence for a metric above a non-zero log count. See `missed_data_warning` for the numbers.

    Every refusal is silence with the reason on stderr, the same rule the zero case follows.
    """
    if count is None:
        print(f"[waf_metrics] no metric cross-check for rule '{rule_name}': {reason}",
              file=sys.stderr, flush=True)
        return ""
    period = _period_for_window(start_epoch)
    if period is None:
        return ""
    # **The bound is derived, not picked, and requiring exact alignment would have been wrong.** An
    # unaligned boundary shifts the metric's window by up to one period at that end, so the two counts can
    # differ by one period's traffic per unaligned end. Refusing every unaligned window silences the common
    # case: `end_epoch` is `min(start + duration*60, now)`, so any window reaching the present ends on a
    # second rather than a minute. What matters is whether that shift can exceed the threshold, which is a
    # question about the ratio of period to span.
    shifted = (1 if start_epoch % period else 0) + (1 if end_epoch % period else 0)
    span = max(end_epoch - start_epoch, 1)
    if shifted * period > _GAP_FRACTION * span:
        print(f"[waf_metrics] no partial-gap check for rule '{rule_name}': the window is unaligned to the "
              f"{period}s metric period and {shifted * period}s of shift is more than {_GAP_FRACTION:.0%} "
              f"of its {span}s span, so the two counts are not comparable",
              file=sys.stderr, flush=True)
        return ""
    gap = count - log_rows
    if gap <= max(1, _GAP_FRACTION * count):
        return ""
    return (f"\n⚠️  **The logs hold less than the metric says.** CloudWatch reports {count:,} "
            f"{metric_name} for rule '{rule_name}' on {webacl_name} in this window and the log query "
            f"counted {log_rows:,}, a gap of {gap:,} ({gap / count * 100:.1f}%). The rows below are "
            f"therefore a subset, so do NOT present their totals or their client list as complete. "
            f"Likely causes: a Log Filter dropping some of these records, a partition or timezone "
            f"mismatch on the log table, or a query that failed for part of the window.")


def missed_action_warning(webacl_name: str, action: str, start_epoch: int, end_epoch: int,
                          log_rows: int) -> str:
    """The same sentence for a tool whose subject is an action rather than a rule.

    `check_challenge_compatibility` asks whether any CHALLENGE or CAPTCHA request exists, so the
    witness is `ChallengeRequests` or `CaptchaRequests` on the whole WebACL. The zero-only limit and
    the silence-on-refusal rule are the shared ones; see `missed_data_warning`.
    """
    if log_rows != 0:
        return ""
    metric_name = {"CHALLENGE": "ChallengeRequests", "CAPTCHA": "CaptchaRequests"}.get(action)
    if metric_name is None:
        return ""
    count, reason = webacl_action_total(webacl_name, metric_name, start_epoch, end_epoch)
    return _missed_data_sentence(count, reason, f"action {action}", webacl_name, metric_name)


# The four terminating actions, which are disjoint: a request ends in exactly one of them. `COUNT` is
# absent on purpose. It is not terminating, so a counted request also ends in one of these four and adding
# it would double count, and a WAF log record's `action` field never holds `COUNT` anyway.
_ACTION_METRIC = {"BLOCK": "BlockedRequests", "ALLOW": "AllowedRequests",
                  "CHALLENGE": "ChallengeRequests", "CAPTCHA": "CaptchaRequests"}


def _control_query(action: str | None):
    """The pair of engine spellings for "did the log path return any row at all in this window".

    Deliberately not a copy of the caller's query with its subject filter removed. What is being asked is
    whether the path was returning rows, so one shape serves every caller, and a per-tool control is one
    more query to keep in step with the tool it mirrors.
    """
    where = f" AND action = '{action}'" if action else ""
    cwl = f"filter action = '{action}' | " if action else ""
    return (f"{cwl}stats count(*) as cnt",
            f'SELECT count(*) as cnt FROM {{TABLE}} WHERE "timestamp" BETWEEN {{START_MS}} AND '
            f"{{END_MS}} {{PARTITION_FILTER}}{where}")


def control_rows(webacl_name: str, action: str | None, start_epoch: int, end_epoch: int):
    """How many rows the log path returned for `action` with no subject filter. `(count, reason)`.

    **`webacl_name` is taken and checked rather than trusted, because the two witnesses can otherwise be
    about different WebACLs.** The metric witness follows its argument; this one follows session state
    twice over, for the query's WebACL scope and for the log destination it runs against. A caller naming
    X while the session holds Y would compare X's metric against Y's log group, and the mismatch does not
    merely risk a wrong answer, it guarantees one: X's records are not in Y's destination, so the control
    is zero by construction and the one cell that speaks fires every time.

    Refused rather than resolved. Running the control for X needs X's own logging configuration, which is
    an API call and a second destination this layer has no way to query against. **So a mismatch is
    silence**, which is what a witness that cannot answer is required to produce. The consequence worth
    stating: a tool that passes its own name and never writes session state, which is what `patrol_scan`
    and `generate_weekly_report` do, gets silence from this check rather than a false statement.

    Third of the same family in three days, after `declare_query_subject` and the CloudWatch scope filter.
    Each one was a subject coming from one place and data from another, with nothing binding them.

    **`None` and `0` are different answers and the caller must not merge them.** A control that could not
    run is not a control that found nothing, and treating them the same is what would make this check fire
    on a failed query. `query_logs` returns an `_error` row on every give-up path, so that row is the
    distinguishing evidence.

    An empty result list is a real zero, measured rather than assumed: `stats count(*) as cnt` over a
    window with no matching records returns no rows at all on CloudWatch Logs Insights, and returns one row
    with the count when there are records. A missing `cnt` key is neither, so it refuses; the key is
    written by `_control_query` two functions up, which is why that state is unreachable rather than
    handled, and a default of `0` there would have turned an unreachable shape into the firing value.
    """
    from tools.waf_query import log_query_error, query_logs
    session_acl = get_webacl_name()
    if webacl_name != session_acl:
        return None, (f"the metric witness is about {webacl_name} and the log destination in session "
                      f"state belongs to {session_acl!r}, so a control query here would answer about a "
                      f"different WebACL")
    cwl, athena = _control_query(action)
    try:
        rows = query_logs(cwl, athena, start_epoch, end_epoch, 1)
    except Exception as exc:
        return None, f"the control query raised {type(exc).__name__}"
    if rows is None:
        return None, "no log destination is configured, so there is no control to run"
    if log_query_error(rows):
        return None, "the control query did not complete, so it says nothing about the log path"
    if not rows:
        return 0, ""
    if "cnt" not in rows[0]:
        return None, f"the control query returned a row with no count in it: {sorted(rows[0])}"
    return int(rows[0]["cnt"]), ""


def log_path_warning(webacl_name: str, action: str | None, start_epoch: int, end_epoch: int,
                     narrow_rows: int) -> str:
    """The sentence to add when a tool found nothing for an IP, URI, User-Agent or JA4.

    **No metric has those subjects, so this cross-check asks a different question**: was the log path
    returning rows at all in this window. Two witnesses answer it together, the WebACL-level metric for the
    action and one control log query with no subject filter, and neither alone is enough.

    | metric | control | what is said |
    |---|---|---|
    | > 0 | > 0 | nothing. The path works, so the narrow zero is genuine |
    | > 0 | = 0 | **the log path missed data.** The only actionable cell |
    | = 0 | = 0 | nothing. The window held nothing for anyone, so the narrow zero is genuine |
    | = 0 | > 0 | one line. Metrics lag or a dimension mismatch, not a verdict |

    **The control alone would flag every quiet hour, which is measured rather than argued.** 2026-09-08
    12:00 to 13:00 UTC on `shield-sample-webacl`: the narrow query for one IP returned 0 rows, the
    unfiltered control returned 0 rows, and the WebACL `BlockedRequests` metric returned no datapoints. The
    hour was genuinely quiet. The hour before it: metric sum 1, log query 1 row, both agree. So a zero
    control is not evidence of a broken path, and requiring both witnesses is what keeps this check off
    every idle window.

    **A refusal on either witness is silence**, the rule the sibling checks already follow: a witness that
    could not answer must never become a claim about the logs.

    `action=None` sums the four terminating actions, which is a presence test rather than a total. Measured
    on this account for one week: allowed 352,526 plus blocked 566,162 came to 918,688 against 919,495 WAF
    log records, and challenged and captcha'd were both zero in that window, so the four-way sum is the
    two-way sum there and the other two can only narrow the 807 difference. Close enough to answer "did
    anything happen", which is the only question asked of it.
    """
    if narrow_rows != 0:
        return ""
    metric_names = [_ACTION_METRIC[action]] if action in _ACTION_METRIC else list(_ACTION_METRIC.values())
    if action is not None and action not in _ACTION_METRIC:
        return ""
    total, reason = 0, ""
    for name in metric_names:
        count, why = webacl_action_total(webacl_name, name, start_epoch, end_epoch)
        if count is None:
            total, reason = None, why
            break
        total += count
    if total is None:
        print(f"[waf_metrics] no log-path cross-check: {reason}", file=sys.stderr, flush=True)
        return ""

    control, why = control_rows(webacl_name, action, start_epoch, end_epoch)
    if control is None:
        print(f"[waf_metrics] no log-path cross-check: {why}", file=sys.stderr, flush=True)
        return ""

    subject = f"action {action}" if action else "any action"
    if total > 0 and control == 0:
        return (f"\n⚠️  **The log path returned nothing for anyone in this window.** CloudWatch reports "
                f"{total:,} requests for {subject} on {webacl_name}, and a control query with the subject "
                f"filter removed returned no rows at all. So this answer's empty result is about the "
                f"log path and "
                f"not about the subject asked. Do NOT report it as absence. Likely causes: a Log Filter "
                f"dropping the action before it reaches the destination, a partition or timezone mismatch "
                f"on the log table, or a query that failed silently upstream.")
    if total == 0 and control > 0:
        return (f"\nNote: the log path returned rows in this window while CloudWatch reports no "
                f"{subject} requests on {webacl_name}. Metrics can lag by a few minutes, and a dimension "
                f"mismatch produces the same shape. The log rows are the better evidence here.")
    return ""


def _missed_data_sentence(count, reason: str, subject: str, webacl_name: str,
                          metric_name: str) -> str:
    """One wording for both entry points, so the two cannot drift into different confidence.

    A refusal returns "" with the reason on stderr. **A metric that could not answer must never
    become a claim about the logs**, which is this file's own defect class pointed the other way.
    """
    if count is None:
        print(f"[waf_metrics] no metric cross-check for {subject}: {reason}",
              file=sys.stderr, flush=True)
        return ""
    if count <= 0:
        return ""
    return (f"\n⚠️  **The log query missed data.** CloudWatch reports {count:,} "
            f"{metric_name} for {subject} on {webacl_name} in this window, and the log "
            f"query returned no rows for it. It did fire; the logs this answer is built on do "
            f"not show it. Do NOT report this window as quiet. Likely causes: a Log Filter dropping "
            f"the action before it reaches the log destination, a partition or timezone mismatch on "
            f"the log table, or a query that failed silently upstream. Say this to the user and "
            f"check get_webacl_config for a LoggingFilter.")


def _search_metrics(client, expression: str, start_time, end_time) -> str:
    """Execute a SEARCH expression and return results."""
    resp = client.get_metric_data(
        MetricDataQueries=[{
            "Id": "search1",
            "Expression": expression,
        }],
        StartTime=start_time,
        EndTime=end_time,
        ScanBy="TimestampAscending",
    )

    results = resp.get("MetricDataResults", [])
    if not results:
        return "SEARCH returned no results."

    lines = [f"SEARCH returned {len(results)} metric(s):\n"]
    for i, r in enumerate(results[:MAX_RESULTS]):
        label = r.get("Label", f"metric-{i}")
        values = r.get("Values", [])
        total = sum(values)
        lines.append(f"  {label}: {total:,.0f} (total over period)")

    if len(results) > MAX_RESULTS:
        lines.append(f"\n  ... and {len(results) - MAX_RESULTS} more (truncated)")

    lines.append("\n---\nFor quick overview: get_waf_overview(query_type='top_rules', webacl_name='...')\nFor IP/URI details: ask user which peak day/hour to investigate, then use run_logs_query with start_time.")

    return "\n".join(lines)
