"""WAF CloudWatch Logs Insights query tool."""

import time
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_logs_region

MAX_RESULTS = 25
POLL_INTERVAL = 2
MAX_POLL = 60


@tool
def run_logs_query(
    log_group: str,
    query: str,
    hours_ago: int = 24,
    limit: int = 25,
    region: str = "auto",
) -> str:
    """Run a CloudWatch Logs Insights query against WAF logs.

    Args:
        log_group: CloudWatch Logs log group name (e.g. aws-waf-logs-xxx).
        query: CWL Insights query string.
            Example: filter action = 'BLOCK' | stats count(*) as cnt by httpRequest.clientIp | sort cnt desc | limit 10
        hours_ago: How far back to query (default 24 hours).
        limit: Max results to return (default 25, max 25).
        region: AWS region. Auto-detected from WebACL context if not specified.

    Returns:
        Query results formatted as a table, or error message.
    """
    if region == "auto":
        region = get_logs_region()
    limit = min(limit, MAX_RESULTS)
    if not query.rstrip().endswith(f"limit {limit}") and "limit" not in query:
        query = f"{query} | limit {limit}"

    client = get_client("logs", region_name=region)

    end_time = int(time.time())
    start_time = end_time - (hours_ago * 3600)

    resp = client.start_query(
        logGroupName=log_group,
        startTime=start_time,
        endTime=end_time,
        queryString=query,
        limit=limit,
    )
    query_id = resp["queryId"]

    # Poll for results
    elapsed = 0
    while elapsed < MAX_POLL:
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
        result = client.get_query_results(queryId=query_id)
        status = result["status"]
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            break

    if status != "Complete":
        return f"Query {status}. QueryId: {query_id}"

    results = result.get("results", [])
    stats = result.get("statistics", {})

    if not results:
        return f"Query returned 0 results. (scanned {stats.get('bytesScanned', 0) / 1e6:.1f} MB)"

    # Format as table
    columns = [field["field"] for field in results[0] if not field["field"].startswith("@ptr")]
    lines = [
        f"Query returned {len(results)} results (scanned {stats.get('bytesScanned', 0) / 1e6:.1f} MB)\n",
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for row in results[:MAX_RESULTS]:
        row_dict = {f["field"]: f["value"] for f in row}
        values = [row_dict.get(col, "") for col in columns]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines)
