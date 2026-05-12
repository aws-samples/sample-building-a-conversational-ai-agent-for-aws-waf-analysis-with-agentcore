# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Validate Report: Mechanical checks on the generated review report.

Usage: python3 waf-validate-report.py <output_dir> <input_file>
  output_dir: directory containing waf-review-report.md, waf-summary.json, mermaid-metadata.json
  input_file: original WAF JSON file (unused currently, reserved for future checks)

Outputs: {output_dir}/validation.json
"""
import json
import os
import re
import sys
from pathlib import Path
from waf_utils import fatal




def _load_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        fatal(f"Failed to read {path}: {e}")


def _count_summary_rows(report: str) -> int:
    """Count data rows in the Summary table (exclude header and separator)."""
    in_summary = False
    count = 0
    for line in report.split("\n"):
        stripped = line.strip()
        if not in_summary and stripped.startswith("| ") and ("严重" in stripped or "Severity" in stripped):
            in_summary = True
            continue
        if in_summary and stripped.startswith("|"):
            if stripped.startswith("|--") or stripped.startswith("| --"):
                continue  # separator row
            # Count any data row (starts with | and contains at least 2 more |)
            if stripped.count("|") >= 3:
                count += 1
        elif in_summary and not stripped.startswith("|"):
            break  # end of table
    return count


def _count_issue_sections(report: str) -> list[dict]:
    """Find all ## Issue sections and extract number, severity, title."""
    issues = []
    # Match patterns like: ## Issue #1 (Critical): Title
    # or: ## Issue #1 (🔴 Critical): Title
    # or Chinese: ## 问题 #1 (严重): Title
    pattern = re.compile(
        r'^##\s+(?:Issue|问题)\s+#?(\d+)\s*\(([^)]+)\)\s*[:：]\s*(.+)',
        re.MULTILINE
    )
    for m in pattern.finditer(report):
        issues.append({
            "number": int(m.group(1)),
            "severity": m.group(2).strip(),
            "title": m.group(3).strip(),
        })
    return issues


def _extract_rule_refs(report: str) -> list[dict]:
    """Extract rule name and priority references from **Rule**: or **Rules**: lines."""
    refs = []
    # Match: **Rule**: name (priority N)
    # Match: **Rules**: name1 (priority N1), name2 (priority N2)
    # Match: **规则**: name (priority N)
    pattern = re.compile(
        r'\*\*(?:Rules?|规则)\*\*\s*[:：]\s*(.+)',
        re.MULTILINE
    )
    for m in pattern.finditer(report):
        line = m.group(1).strip()
        if line.startswith("N/A") or line.startswith("不存在") or line.startswith("无"):
            continue
        # Extract individual rule references
        for ref_match in re.finditer(r'([\w\-.:]+)\s*\(priority\s+(\d+)\)', line):
            refs.append({
                "name": ref_match.group(1),
                "priority": int(ref_match.group(2)),
            })
    return refs


def _check_summary_issue_count(report: str) -> dict:
    """Check that Summary table rows == Issue sections."""
    summary_rows = _count_summary_rows(report)
    issue_sections = _count_issue_sections(report)
    issue_count = len(issue_sections)

    if summary_rows == issue_count:
        return {"status": "PASS", "summary_rows": summary_rows,
                "issue_sections": issue_count}
    return {"status": "FAIL", "summary_rows": summary_rows,
            "issue_sections": issue_count,
            "detail": f"Summary has {summary_rows} rows but found {issue_count} Issue sections"}


def _check_summary_detail_match(report: str) -> dict:
    """Check that each Summary row matches its Issue section."""
    issues = _count_issue_sections(report)
    # We can't easily parse Summary rows to match against Issue sections
    # without knowing the exact table format. Just verify issue numbers are sequential.
    mismatches = []
    numbers = [i["number"] for i in issues]
    for i, num in enumerate(numbers):
        if num != i + 1:
            mismatches.append(f"Issue #{num} found at position {i+1} (expected #{i+1})")

    if mismatches:
        return {"status": "FAIL", "mismatches": mismatches}
    return {"status": "PASS", "mismatches": []}


def _check_rule_references(report: str, summary: dict) -> dict:
    """Check that rule names and priorities in findings exist in waf-summary.json."""
    refs = _extract_rule_refs(report)
    rules = summary.get("rules", [])
    rule_lookup = {r["name"]: r["priority"] for r in rules}

    invalid = []
    for ref in refs:
        if ref["name"] not in rule_lookup:
            invalid.append(f"Rule '{ref['name']}' not found in WAF JSON")
        elif rule_lookup[ref["name"]] != ref["priority"]:
            invalid.append(
                f"Rule '{ref['name']}' has priority {rule_lookup[ref['name']]} "
                f"in JSON but {ref['priority']} in report")

    if invalid:
        return {"status": "FAIL", "invalid_refs": invalid}
    return {"status": "PASS", "invalid_refs": []}


def _check_mermaid_completeness(metadata: dict) -> dict:
    """Check that Mermaid diagram covers all rules (using metadata, not parsing Mermaid)."""
    rule_count = metadata.get("rule_count", 0)
    node_count = metadata.get("node_count", 0)
    fold_groups = metadata.get("fold_groups", [])

    # In detailed mode: node_count should == rule_count
    # In grouped mode: node_count = rule_count - folded_rules + fold_group_count
    folded_rules = sum(len(fg["rule_names"]) for fg in fold_groups)
    expected_nodes = rule_count - folded_rules + len(fold_groups)

    if node_count == expected_nodes:
        return {"status": "PASS", "missing_rules": [],
                "rule_count": rule_count, "node_count": node_count}

    return {"status": "FAIL",
            "missing_rules": [f"Expected {expected_nodes} nodes, got {node_count}"],
            "rule_count": rule_count, "node_count": node_count}


def _check_prechecks_coverage(report: str, prechecks: dict) -> dict:
    """Check that every FAIL pre-check has its rule referenced in a **Rule**: line."""
    # Extract all rule names from **Rule**:/**Rules**: lines
    rule_refs = {r["name"].lower() for r in _extract_rule_refs(report)}

    missing = []
    for name, check in prechecks.get("pre_checks", {}).items():
        if check.get("status") != "FAIL":
            continue
        # Collect rule names from the pre-check result
        check_rules = []
        if "rule" in check:
            check_rules.append(check["rule"])
        for r in check.get("rules", []):
            rname = r.get("name", "") if isinstance(r, dict) else str(r)
            if rname:
                check_rules.append(rname)
        if not check_rules:
            continue  # No specific rule to match (e.g., global checks)
        # At least one rule from this check must appear in report
        found = any(r.lower() in rule_refs for r in check_rules)
        if not found:
            finding = check.get("finding", "")
            missing.append({"check": name, "rules": check_rules,
                            "finding": finding[:100]})
    if missing:
        return {"status": "FAIL", "missing": missing,
                "detail": f"{len(missing)} pre-check FAIL items not found in report **Rule**: lines"}
    return {"status": "PASS", "missing": []}


def main():
    if len(sys.argv) < 3:
        fatal("Usage: waf-validate-report.py <output_dir> <input_file>")

    output_dir = sys.argv[1]
    report_path = os.path.join(output_dir, "waf-review-report.md")
    summary_path = os.path.join(output_dir, "waf-summary.json")
    meta_path = os.path.join(output_dir, "mermaid-metadata.json")

    for p in (report_path, summary_path, meta_path):
        if not os.path.isfile(p):
            fatal(f"Required file not found: {p}")

    report = Path(report_path).read_text(encoding="utf-8")
    summary = _load_json(summary_path)
    metadata = _load_json(meta_path)

    # Load pre-checks if available
    prechecks_path = os.path.join(output_dir, "pre-checks.json")
    prechecks = _load_json(prechecks_path) if os.path.isfile(prechecks_path) else None

    # Run checks
    checks = {
        "summary_issue_count": _check_summary_issue_count(report),
        "summary_detail_match": _check_summary_detail_match(report),
        "rule_references": _check_rule_references(report, summary),
        "mermaid_completeness": _check_mermaid_completeness(metadata),
    }
    if prechecks:
        checks["prechecks_coverage"] = _check_prechecks_coverage(report, prechecks)

    # Write output
    output_file = os.path.join(output_dir, "validation.json")
    Path(output_file).write_text(
        json.dumps(checks, indent=2, ensure_ascii=False), encoding="utf-8")

    passed = sum(1 for v in checks.values() if v["status"] == "PASS")
    failed = sum(1 for v in checks.values() if v["status"] == "FAIL")

    print(f"Validation: {passed} passed, {failed} failed", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"CHECKS_PASSED: {passed}")
    print(f"CHECKS_FAILED: {failed}")


if __name__ == "__main__":
    main()
