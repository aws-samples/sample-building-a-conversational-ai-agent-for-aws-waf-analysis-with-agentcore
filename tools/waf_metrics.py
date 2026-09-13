# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF CloudWatch Metrics tool."""

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_scope, resolve_region

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
    match = next((r for r in rules if r.get("Name") == rule_name), None)
    if match is None:
        names = ", ".join(sorted(r.get("Name", "?") for r in rules)) or "none"
        return None, (f"'{rule_name}' is not a rule on {webacl_name}, so no metric was queried: a "
                      f"CloudWatch query for a name that does not exist answers zero rather than "
                      f"failing. Configured rules: {names}")
    visibility = match.get("VisibilityConfig") or {}
    if not visibility.get("CloudWatchMetricsEnabled", True):
        return None, (f"'{rule_name}' has CloudWatchMetricsEnabled false, so it publishes no "
                      f"metric at all and its absence here means nothing")

    period = _period_for_window(start_epoch)
    if period is None:
        return None, (f"the window starts more than 455 days ago, beyond every CloudWatch metric "
                      f"resolution, so there is no metric to compare against")

    dimensions = [{"Name": "WebACL", "Value": webacl_name},
                  {"Name": "Rule", "Value": visibility.get("MetricName") or rule_name}]
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
    """The sentence to add when the metric says a rule fired and the log query found nothing.

    **Only the exactly-zero case, and that limit is a dependency rather than caution.** If the
    metric says 122 and the log query returned 40 rows, the gap may be a `limit` on the query rather
    than data it missed, and nothing available today can tell those apart. ROADMAP 7.7's second item
    is the truncation disclosure that makes a partial gap decidable; **when it lands, come back and
    widen this**, because a partial gap is the more common shape and it is unreported until then.

    Returns "" when there is nothing to say, which includes every case where the metric could not
    answer. A failure to reach CloudWatch must not turn into a claim about the logs, and the reason
    is on stderr rather than in the report because this runs beside a conclusion the tool already
    reached.
    """
    if log_rows != 0:
        return ""
    count, reason = rule_blocked_per_metrics(webacl_name, rule_name, rules, start_epoch, end_epoch,
                                             metric_name)
    if count is None:
        print(f"[waf_metrics] no metric cross-check for {rule_name}: {reason}",
              file=sys.stderr, flush=True)
        return ""
    if count <= 0:
        return ""
    return (f"\n⚠️  **The log query missed data.** CloudWatch reports {count:,} "
            f"{metric_name} for rule '{rule_name}' on {webacl_name} in this window, and the log "
            f"query returned no rows for it. The rule did fire; the logs this answer is built on do "
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
