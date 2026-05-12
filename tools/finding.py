# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Record investigation findings tool."""

from strands import tool
from tools.session_state import add_finding, get_findings


@tool
def record_finding(
    title: str,
    severity: str,
    conclusion: str,
    evidence: str,
    recommendation: str = "",
) -> str:
    """Record an investigation finding with evidence and recommendation.

    Call this when you reach a conclusion about a specific aspect of the investigation.
    Multiple findings can be recorded per session. At the end, all findings form the
    investigation report.

    Args:
        title: Short title (e.g., "CRS XSS rule is false positive on /api/posts")
        severity: One of: critical, high, medium, low, info
        conclusion: What you determined (e.g., "False positive — rich text content triggers XSS rule")
        evidence: Key evidence supporting the conclusion (e.g., "95% of hits from 3 IPs with normal allow ratio, all on /api/posts endpoint")
        recommendation: Actionable next step (e.g., "Add scope-down to exclude URI=/api/posts from XSS_BODY rule")

    Returns:
        Confirmation with finding number.
    """
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "medium"

    finding = {
        "number": len(get_findings()) + 1,
        "title": title,
        "severity": severity,
        "conclusion": conclusion,
        "evidence": evidence,
        "recommendation": recommendation,
    }
    add_finding(finding)
    return f"Finding #{finding['number']} recorded: [{severity.upper()}] {title}"
