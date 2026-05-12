# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Build Issue Map: Merge scripted + LLM findings into issue-rule-mapping.json.

Usage: python3 waf-build-issue-map.py <output_dir>
  output_dir: directory containing findings-metadata.json and waf-review-report.md

Outputs: {output_dir}/issue-rule-mapping.json
"""
import json
import os
import re
import sys
from pathlib import Path
from waf_utils import fatal




def _extract_llm_rule_refs(report: str, min_issue: int, valid_rules: set) -> dict:
    """Parse **Rule**:/**Rules**: lines from LLM-written Issue sections."""
    mapping = {}
    current_issue = None
    for line in report.split("\n"):
        m = re.match(r'^## Issue (\d+)\s', line)
        if m:
            num = int(m.group(1))
            current_issue = num if num >= min_issue else None
            continue
        if current_issue is None:
            continue
        if not line.startswith("**Rule"):
            continue
        # Extract rule names from **Rule**: or **Rules**: lines
        # Patterns: "name (priority N)", "name (PN)"
        for rm in re.finditer(r'([\w.\-:]+)\s*\((?:priority\s*|P)(\d+)\)', line):
            rule_name = rm.group(1)
            if rule_name not in valid_rules:
                continue
            if rule_name in mapping:
                mapping[rule_name] += f", #{current_issue}"
            else:
                mapping[rule_name] = f"⚠️ Issue #{current_issue}"
    return mapping


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-build-issue-map.py <output_dir>")

    output_dir = sys.argv[1]
    meta_path = os.path.join(output_dir, "findings-metadata.json")
    report_path = os.path.join(output_dir, "waf-review-report.md")
    summary_path = os.path.join(output_dir, "waf-summary.json")

    for p in (meta_path, report_path, summary_path):
        if not os.path.isfile(p):
            fatal(f"{os.path.basename(p)} not found in {output_dir}")

    metadata = json.loads(Path(meta_path).read_text(encoding="utf-8"))
    report = Path(report_path).read_text(encoding="utf-8")
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))

    # Build set of valid rule names
    valid_rules = {r["name"] for r in summary.get("rules", [])}

    # Start with scripted mappings
    mapping = dict(metadata.get("issue_rule_mapping", {}))

    # Add LLM-written findings
    next_issue = metadata.get("next_issue_number", 1)
    llm_refs = _extract_llm_rule_refs(report, next_issue, valid_rules)
    for rule_name, annotation in llm_refs.items():
        if rule_name not in valid_rules:
            continue
        if rule_name in mapping:
            existing = mapping[rule_name]
            new_issues = annotation.replace("⚠️ Issue ", "")
            mapping[rule_name] = f"{existing}, {new_issues}"
        else:
            mapping[rule_name] = annotation

    # Write output
    output = {"annotations": mapping}
    output_file = os.path.join(output_dir, "issue-rule-mapping.json")
    Path(output_file).write_text(
        json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Mapped {len(mapping)} rules to issues", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {output_file}")
    print(f"RULES_MAPPED: {len(mapping)}")


if __name__ == "__main__":
    main()
