# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Challenge/CAPTCHA compatibility check — one-shot query tool."""

import time
import threading
from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_log_destination, get_logs_region, is_log_filter_active

_cwl_semaphore = threading.Semaphore(8)
MAX_POLL = 120
POLL_INTERVAL = 2


@tool
def check_challenge_compatibility(start_time: str, hours_ago: int = 6, action_type: str = "CHALLENGE") -> str:
    """Check which URIs/methods are being challenged or CAPTCHA'd. Identifies requests that
    cannot complete Challenge/CAPTCHA due to technical requirements.

    This tool provides evidence for the USER to judge — it does NOT determine false positives.
    Challenge/CAPTCHA requires: (1) browser with JS execution, (2) GET method, (3) Accept: text/html.
    Requests not meeting ALL conditions are effectively blocked.

    Use when user reports API/native-app requests failing after enabling Challenge/CAPTCHA rules,
    or when user wants to check Challenge/CAPTCHA compatibility proactively.

    Args:
        start_time: Start time for log query (e.g., "2026-05-12T14:00").
        hours_ago: Duration in hours (default 6, max 6).
        action_type: "CHALLENGE" or "CAPTCHA". Default "CHALLENGE".
    """
    from tools.waf_logs import _parse_start_time

    dest = get_log_destination()
    if not dest or ":log-group:" not in dest:
        return ("Error: No CloudWatch Logs destination configured. "
                "Cannot query Challenge/CAPTCHA logs. Enable WAF logging first.")

    log_group = dest.split(":log-group:")[-1].rstrip(":*")
    region = get_logs_region()

    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'."

    hours_ago = min(hours_ago, 6)
    end_epoch = start_epoch + (hours_ago * 3600)

    action = action_type.upper()
    if action not in ("CHALLENGE", "CAPTCHA"):
        return f"Error: action_type must be 'CHALLENGE' or 'CAPTCHA', got '{action_type}'."

    # Query: URI + method distribution for challenged/captcha'd requests
    query = (
        f"filter action = '{action}'"
        " | stats count(*) as hits by httpRequest.uri, httpRequest.httpMethod"
        " | sort hits desc | limit 25"
    )

    results = _run_query(log_group, region, query, start_epoch, end_epoch)

    if not results:
        msg = f"No {action} requests found in this time window."
        if is_log_filter_active():
            msg += f"\n⚠️  Log Filter is active — {action} logs may be filtered out."
        return msg

    # Check for anti-ddos event (ChallengeAllDuringEvent)
    antiddos_note = ""
    if action == "CHALLENGE":
        ddos_query = (
            "filter @message like 'anti-ddos'"
            " | stats count(*) as hits"
        )
        ddos_results = _run_query(log_group, region, ddos_query, start_epoch, end_epoch)
        if ddos_results and int(ddos_results[0].get("hits", 0)) > 0:
            antiddos_note = (
                "\n⚠️  Anti-DDoS event detected in this time window. "
                "ChallengeAllDuringEvent was likely active — ALL challengeable requests "
                "were challenged regardless of specific rules. This is expected DDoS mitigation behavior.\n"
            )

    # Build output
    lines = [
        f"## {action} Compatibility Check",
        f"**Time window**: {start_time} + {hours_ago}h",
        f"**Total URI/method combinations**: {len(results)}",
    ]

    if antiddos_note:
        lines.append(antiddos_note)

    lines.append("")
    lines.append(f"| {'URI':<40} | {'Method':<7} | {'Hits':>6} | Compatibility |")
    lines.append(f"| {'-'*40} | {'-'*7} | {'-'*6} | ------------- |")

    for r in results:
        uri = r.get("httpRequest.uri", "?")[:40]
        method = r.get("httpRequest.httpMethod", "?")
        hits = r.get("hits", "?")
        # Flag incompatible combinations
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            compat = "❌ Cannot complete (non-GET)"
        elif any(uri.startswith(p) for p in ("/api/", "/v1/", "/v2/", "/graphql", "/.well-known/")):
            compat = "⚠️ Likely API (verify)"
        else:
            compat = "✅ Likely OK"
        lines.append(f"| {uri:<40} | {method:<7} | {hits:>6} | {compat} |")

    lines.append("")
    lines.append("---")
    lines.append("## Challenge/CAPTCHA Technical Requirements")
    lines.append("")
    lines.append("For a request to successfully complete Challenge/CAPTCHA, ALL conditions must be met:")
    lines.append("1. **Client is a browser** capable of executing JavaScript")
    lines.append("2. **HTTP method is GET**")
    lines.append("3. **Accept header contains `text/html`**")
    lines.append("")
    lines.append("Requests NOT meeting all conditions receive:")
    lines.append("- Non-GET requests → effectively blocked (cannot render challenge page)")
    lines.append("- API calls (Accept: application/json) → HTTP 202 response (cannot proceed)")
    lines.append("- Native apps / SDKs → effectively blocked (no JS engine)")
    lines.append("- Binary downloads / media → HTTP 202 (cannot render HTML)")
    lines.append("")
    lines.append("## Your Next Action")
    lines.append("")
    lines.append("Present the table above to the user. Ask:")
    lines.append("\"Which of these URIs are accessed by native apps, APIs, or non-browser clients?\"")
    lines.append("")
    lines.append("For URIs the user confirms as non-browser:")
    lines.append("- Recommend adding a scope-down statement to EXCLUDE those URIs from the Challenge/CAPTCHA rule")
    lines.append("- Or recommend switching those specific URIs to a different action (Block with rate-limit, or Allow with token check)")
    lines.append("")
    lines.append("## Confidence Rules")
    lines.append("- PRESENT-ONLY: all data in this tool. Agent does NOT judge which URIs are legitimate.")
    lines.append("- ASK: user decides which URIs are browser-accessible vs API/native-app.")

    return "\n".join(lines)


def _run_query(log_group: str, region: str, query: str, start_epoch: int, end_epoch: int) -> list[dict]:
    """Execute CWL query and return parsed results."""
    client = get_client("logs", region_name=region)
    with _cwl_semaphore:
        resp = client.start_query(
            logGroupName=log_group, startTime=start_epoch, endTime=end_epoch,
            queryString=query, limit=25,
        )
        query_id = resp["queryId"]
        elapsed = 0
        while elapsed < MAX_POLL:
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            result = client.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
                break
    if result["status"] != "Complete":
        return []
    return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]
