# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF CloudWatch Metrics tool."""

import json
from datetime import datetime, timedelta, timezone
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_metrics_region, get_scope

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
        region: AWS region. Auto-detected from WebACL context if not specified.
        use_search: If true, use SEARCH expression instead of specific metric.
        search_expression: CloudWatch SEARCH expression. Only used if use_search=true.
            Example: SEARCH('{AWS/WAFV2,LabelName,LabelNamespace,WebACL} WebACL="xxx"', 'Sum', 3600)

    Returns:
        Metric data points formatted as a table, or SEARCH results.
    """
    if region == "auto":
        region = get_metrics_region()
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

    # Determine period (granularity)
    if period_hours <= 24:
        period = 300  # 5 min
    elif period_hours <= 168:
        period = 3600  # 1 hour
    else:
        period = 86400  # 1 day

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
