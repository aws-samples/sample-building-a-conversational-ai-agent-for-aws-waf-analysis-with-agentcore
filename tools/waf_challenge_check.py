# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Challenge/CAPTCHA compatibility check — one-shot query tool."""

import threading
from strands import tool
from tools.session_state import get_webacl_name, is_log_filter_active
from tools.waf_query import query_logs, get_log_type

_cwl_semaphore = threading.Semaphore(8)
MAX_POLL = 120
POLL_INTERVAL = 2


@tool
def check_challenge_compatibility(start_time: str, duration_minutes: int = 180, action_type: str = "CHALLENGE") -> str:
    """Check which URIs/methods are being challenged or CAPTCHA'd. Identifies requests that
    cannot complete Challenge/CAPTCHA due to technical requirements.

    This tool provides evidence for the USER to judge — it does NOT determine false positives.
    Challenge/CAPTCHA requires: (1) browser with JS execution, (2) GET method, (3) Accept: text/html.
    Requests not meeting ALL conditions are effectively blocked.

    Use when user reports API/native-app requests failing after enabling Challenge/CAPTCHA rules,
    or when user wants to check Challenge/CAPTCHA compatibility proactively.

    Prerequisite: call get_waf_config first (after selecting the WebACL). This tool
    reads session state populated there; without it it errors out.

    Args:
        start_time: Start time for log query (e.g., "2026-05-12T14:00").
        duration_minutes: Duration in minutes (default 180, max 360 for CWL, 60 for Athena).
        action_type: "CHALLENGE" or "CAPTCHA". Default "CHALLENGE".
    """
    from tools.waf_logs import _parse_start_time
    _duration = min(duration_minutes, 360)

    if not get_webacl_name():
        return ("Error: No WebACL selected. Call get_waf_config(webacl_name='...') first, "
                "or call list_webacls() to see available WebACLs.")

    if get_log_type() == "none":
        return ("Error: No logging configured for this WebACL. "
                "Cannot query Challenge/CAPTCHA logs. Enable WAF logging first.")
    from tools.waf_query import check_hourly_partition_block
    hourly_err = check_hourly_partition_block()
    if hourly_err:
        return hourly_err

    start_epoch = _parse_start_time(start_time)
    if start_epoch is None:
        return f"Error: cannot parse start_time '{start_time}'."

    
    end_epoch = start_epoch + _duration * 60

    action = action_type.upper()
    if action not in ("CHALLENGE", "CAPTCHA"):
        return f"Error: action_type must be 'CHALLENGE' or 'CAPTCHA', got '{action_type}'."

    # Query: URI + method distribution for challenged/captcha'd requests
    cwl = (
        f"filter action = '{action}'"
        " | stats count(*) as hits by httpRequest.uri, httpRequest.httpMethod"
        " | sort hits desc | limit 25"
    )
    athena = (
        f"SELECT httprequest.uri as \"httpRequest.uri\", httprequest.httpmethod as \"httpRequest.httpMethod\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND action = '{action}'"
        f" GROUP BY httprequest.uri, httprequest.httpmethod ORDER BY hits DESC LIMIT 25"
    )

    results = _run_q(cwl, athena, start_epoch, end_epoch)

    if not results:
        msg = f"No {action} requests found in this time window."
        if is_log_filter_active():
            msg += f"\n⚠️  Log Filter is active — {action} logs may be filtered out."
        return msg

    # Token failure-reason breakdown for the same action/window. Why a real user
    # can't pass the challenge has two sides: the URI/method table above (client
    # type — non-browser, non-GET) and this (token problems — missing/expired/
    # domain mismatch). The response object follows the action: CHALLENGE →
    # challengeResponse, CAPTCHA → captchaResponse. Field paths differ by backend:
    # CWL is camelCase nested JSON (challengeResponse.failureReason); Athena is
    # lowercase top-level columns (challengeresponse.failurereason). Verified live.
    resp_obj_cwl = "challengeResponse" if action == "CHALLENGE" else "captchaResponse"
    resp_col_athena = "challengeresponse" if action == "CHALLENGE" else "captcharesponse"
    fr_cwl = (
        f"filter action = '{action}' and ispresent({resp_obj_cwl}.failureReason)"
        f" | stats count(*) as hits by {resp_obj_cwl}.failureReason"
        " | sort hits desc | limit 10"
    )
    fr_athena = (
        f"SELECT {resp_col_athena}.failurereason as \"failureReason\", count(*) as hits"
        f" FROM {{TABLE}} WHERE \"timestamp\" BETWEEN {{START_MS}} AND {{END_MS}} {{PARTITION_FILTER}}"
        f" AND action = '{action}' AND {resp_col_athena}.failurereason IS NOT NULL"
        f" GROUP BY {resp_col_athena}.failurereason ORDER BY hits DESC LIMIT 10"
    )
    fr_results = _run_q(fr_cwl, fr_athena, start_epoch, end_epoch)

    # Check for anti-ddos event (ChallengeAllDuringEvent)
    antiddos_note = ""
    if action == "CHALLENGE":
        ddos_cwl = "filter @message like 'anti-ddos' | stats count(*) as hits"
        ddos_athena = (
            "SELECT count(*) as hits FROM {TABLE}"
            " WHERE \"timestamp\" BETWEEN {START_MS} AND {END_MS} {PARTITION_FILTER}"
            " AND any_match(labels, l -> l.name LIKE '%anti-ddos%')"
        )
        ddos_results = _run_q(ddos_cwl, ddos_athena, start_epoch, end_epoch)
        if ddos_results and int(ddos_results[0].get("hits", 0)) > 0:
            antiddos_note = (
                "\n⚠️  Anti-DDoS event detected in this time window. "
                "ChallengeAllDuringEvent was likely active — ALL challengeable requests "
                "were challenged regardless of specific rules. This is expected DDoS mitigation behavior.\n"
            )

    # Build output
    lines = [
        f"## {action} Compatibility Check",
        f"**Time window**: {start_time} + {_duration}min",
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

    # Token failure-reason distribution (the other half of "why can't they pass")
    if fr_results:
        # CWL returns the field keyed as e.g. "challengeResponse.failureReason";
        # Athena as "failureReason". Read whichever is present.
        def _fr(row):
            return (row.get("failureReason")
                    or row.get(f"{resp_obj_cwl}.failureReason")
                    or "?")
        lines.append("")
        lines.append(f"### Token Failure Reasons ({action})")
        lines.append("")
        lines.append(f"| {'Failure Reason':<24} | {'Hits':>6} | Meaning |")
        lines.append(f"| {'-'*24} | {'-'*6} | ------- |")
        _fr_meaning = {
            "TOKEN_MISSING": "No WAF token sent — non-browser client, or never solved the challenge",
            "TOKEN_INVALID": "Token present but not valid — tampering, or wrong/forged token",
            "TOKEN_EXPIRED": "Token expired — session older than the token TTL",
            "TOKEN_DOMAIN_MISMATCH": "Token issued for a different domain — multi-domain/SDK misconfig",
            "TOKEN_NOT_SOLVED": "Challenge/CAPTCHA was served but never solved",
        }
        for r in fr_results:
            reason = _fr(r)
            meaning = _fr_meaning.get(reason, "")
            lines.append(f"| {reason:<24} | {r.get('hits', '?'):>6} | {meaning} |")

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
    lines.append("Two angles on \"why can't they pass\": the URI/method table (client type) and the")
    lines.append("Token Failure Reasons table (token problems). Read them together:")
    lines.append("- Mostly **TOKEN_MISSING** on API/native-app URIs → those clients can't run the JS")
    lines.append("  challenge at all. Recommend scope-down to EXCLUDE those URIs, or a different action.")
    lines.append("- **TOKEN_DOMAIN_MISMATCH** → the WAF token SDK is misconfigured for the domain")
    lines.append("  (common with multi-domain / CDN setups). Point the user at the token domain config.")
    lines.append("- **TOKEN_EXPIRED / TOKEN_NOT_SOLVED** on browser URIs → real users hitting friction")
    lines.append("  (slow solves, long sessions). Consider token TTL or whether the rule is too aggressive.")
    lines.append("- **TOKEN_INVALID** → possible tampering/forgery; treat as a potential abuse signal, not FP.")
    lines.append("")
    lines.append("Present the URI/method table to the user. Ask:")
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


def _run_q(cwl: str, athena: str, start_epoch: int, end_epoch: int) -> list[dict]:
    """Execute log query via unified layer (CWL or Athena)."""
    results = query_logs(cwl, athena, start_epoch, end_epoch, limit=25)
    return results if results is not None else []
