# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Generate Report Header: Extract issues from report and prepend Summary table + header.

Usage: python3 waf-generate-report-header.py <output_dir>
  output_dir: directory containing waf-review-report.md and waf-summary.json

Reads waf-review-report.md (Issue sections only, no header/summary).
Prepends: report header (Web ACL name, date, objective) + Summary table.

The report file is modified in-place.
"""
import json
import os
import re
import sys
from datetime import date
from pathlib import Path
from waf_utils import fatal




SEVERITY_ORDER = {
    "critical": 0, "🔴 critical": 0, "🔴": 0,
    "medium": 1, "🟡 medium": 1, "🟡": 1,
    "low": 2, "🟢 low": 2, "🟢": 2,
    "awareness": 3, "🔵 awareness": 3, "🔵": 3,
}

SEVERITY_EMOJI = {
    "critical": "🔴 Critical", "🔴 critical": "🔴 Critical", "🔴": "🔴 Critical",
    "medium": "🟡 Medium", "🟡 medium": "🟡 Medium", "🟡": "🟡 Medium",
    "low": "🟢 Low", "🟢 low": "🟢 Low", "🟢": "🟢 Low",
    "awareness": "🔵 Awareness", "🔵 awareness": "🔵 Awareness", "🔵": "🔵 Awareness",
}


def _extract_issues(report: str) -> list[dict]:
    """Extract issue number, severity, and title from ## Issue sections."""
    issues = []
    pattern = re.compile(
        r'^##\s+(?:Issue|问题)\s+#?(\d+)\s*\(([^)]+)\)\s*[:：]\s*(.+)',
        re.MULTILINE
    )
    for m in pattern.finditer(report):
        severity_raw = m.group(2).strip().lower()
        issues.append({
            "number": int(m.group(1)),
            "severity_raw": m.group(2).strip(),
            "severity_key": severity_raw,
            "title": m.group(3).strip(),
        })
    return issues


def _extract_impact(report: str, issue_number: int) -> str:
    """Try to extract a one-line impact/problem summary for the Summary table."""
    # Find the Issue section and look for the first line of **Problem**:
    pattern = re.compile(
        rf'^##\s+(?:Issue|问题)\s+#?{issue_number}\s*\([^)]+\)\s*[:：].*?\n'
        r'.*?(?:\*\*(?:Problem|问题)\*\*\s*[:：]\s*\n\s*[-•]\s*(.+?))\n',
        re.MULTILINE | re.DOTALL
    )
    m = pattern.search(report)
    if m:
        impact = m.group(1).strip()
        if len(impact) > 80:
            impact = impact[:77] + "..."
        return impact
    return ""


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-generate-report-header.py <output_dir>")

    output_dir = sys.argv[1]
    report_path = os.path.join(output_dir, "waf-review-report.md")
    summary_path = os.path.join(output_dir, "waf-summary.json")

    if not os.path.isfile(report_path):
        fatal(f"waf-review-report.md not found in {output_dir}")
    if not os.path.isfile(summary_path):
        fatal(f"waf-summary.json not found in {output_dir}")

    report = Path(report_path).read_text(encoding="utf-8")
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))

    web_acl = summary.get("web_acl", {})
    acl_name = web_acl.get("name", "unknown")
    today = date.today().isoformat()

    issues = _extract_issues(report)
    if not issues:
        fatal("No Issue sections found in report")

    # Sort by severity for Summary table display (issues keep original order in report)
    sorted_issues = sorted(issues, key=lambda i: SEVERITY_ORDER.get(i["severity_key"], 9))

    # Build Summary table
    table_lines = [
        "| Severity | Issue | Impact |",
        "|----------|-------|--------|",
    ]
    for issue in sorted_issues:
        severity_display = SEVERITY_EMOJI.get(issue["severity_key"], issue["severity_raw"])
        impact = _extract_impact(report, issue["number"])
        table_lines.append(f"| {severity_display} | #{issue['number']} {issue['title']} | {impact} |")

    summary_table = "\n".join(table_lines)

    # Build header
    header = f"""# AWS WAF Web ACL Rules Review Report

**Web ACL**: {acl_name}
**Review Date**: {today}
**Objective**: Review WAF configuration for security issues, misconfigurations, and optimization opportunities

## Summary

{summary_table}

---

"""

    # Strip existing header if present (idempotent re-runs)
    first_issue = re.search(r'^## Issue \d+', report, re.MULTILINE)
    if first_issue:
        report = report[first_issue.start():]

    # Prepend header to report
    new_report = header + report
    Path(report_path).write_text(new_report, encoding="utf-8")

    print(f"Generated header with {len(issues)} issues in Summary table", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"ISSUE_COUNT: {len(issues)}")


if __name__ == "__main__":
    main()
