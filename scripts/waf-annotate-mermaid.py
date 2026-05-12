# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Annotate Mermaid: Apply issue annotations to base Mermaid diagram.

Usage: python3 waf-annotate-mermaid.py <output_dir>
  output_dir: directory containing mermaid-base.md, mermaid-metadata.json,
              issue-rule-mapping.json, and waf-review-report.md

Reads issue-rule-mapping.json (written by LLM in Step 4):
  {"annotations": {"rule_name": "⚠️ Issue #1", ...}}

Outputs:
  {output_dir}/mermaid-final.md — annotated diagram
  Appends "## Appendix: Rule Execution Flow" to waf-review-report.md
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


def _build_rule_to_node(metadata: dict) -> dict[str, str]:
    """Map rule name → node_id from metadata."""
    mapping = {}
    for r in metadata.get("rules", []):
        mapping[r["name"]] = r["node_id"]
    return mapping


def _build_fold_lookup(metadata: dict) -> dict[str, dict]:
    """Map rule name → fold group info if the rule is folded."""
    lookup = {}
    for fg in metadata.get("fold_groups", []):
        for name in fg["rule_names"]:
            lookup[name] = fg
    return lookup


def _build_node_label(name: str, priority: int, summary_rules: list) -> str:
    """Build a full node label from waf-summary.json rule data."""
    rule = next((r for r in summary_rules if r["name"] == name), None)
    if not rule:
        return f"P{priority}: {name}"
    action_map = {"managed_default": "Managed", "allow": "Allow", "block": "Block",
                  "count": "Count", "challenge": "Challenge", "captcha": "CAPTCHA"}
    action = action_map.get(rule.get("action", ""), rule.get("action", "?"))
    parts = [f"P{priority}: {name}", f"Action: {action}"]
    mg = rule.get("managed")
    if mg:
        overrides = mg.get("overrides", [])
        if overrides:
            ov = [f"{o['rule_name']}→{action_map.get(o['action'], o['action'])}"
                  for o in overrides[:3]]
            if len(overrides) > 3:
                ov.append(f"+{len(overrides)-3} more")
            parts.append("Overrides: " + ", ".join(ov))
    sd = rule.get("scope_down")
    if sd:
        s = sd.get("summary", "")
        if len(s) > 60:
            s = s[:57] + "..."
        parts.append(f"Scope: {s}")
    return "\\n".join(parts)


def _expand_fold_group(mermaid_lines: list, fold_group: dict,
                        metadata: dict, summary_rules: list) -> list[str]:
    """Replace a fold group node with individual rule nodes.
    Returns new lines with the group node replaced by expanded nodes."""
    gid = f"group_{fold_group['priorities'][0]}_{fold_group['priorities'][-1]}"
    new_lines = []
    for line in mermaid_lines:
        stripped = line.strip()
        # Only expand node definition lines (gid followed by [ or {), not arrow lines
        if stripped.startswith(gid) and len(stripped) > len(gid) and stripped[len(gid)] in ('[', '{'):
            # Replace group node with individual expanded nodes
            for i, name in enumerate(fold_group["rule_names"]):
                priority = fold_group["priorities"][i]
                node_id = f"rule_{priority}"
                label = _build_node_label(name, priority, summary_rules)
                # Determine shape from rule data
                rule = next((r for r in summary_rules if r["name"] == name), None)
                if rule and (rule.get("scope_down") or rule.get("type") == "rate_based"):
                    new_lines.append(f'    {node_id}{{{{"{label}"}}}}')
                else:
                    new_lines.append(f'    {node_id}["{label}"]')
            # Add internal flow arrows
            for i in range(len(fold_group["priorities"]) - 1):
                curr = f"rule_{fold_group['priorities'][i]}"
                nxt = f"rule_{fold_group['priorities'][i + 1]}"
                new_lines.append(f"    {curr} --> {nxt}")
            continue
        # Arrow lines referencing the group id — replace with appropriate rule id
        if gid in stripped:
            first_id = f"rule_{fold_group['priorities'][0]}"
            last_id = f"rule_{fold_group['priorities'][-1]}"
            # Determine direction: if gid is the source (before -->), use last rule;
            # if gid is the target (after -->), use first rule
            if "-->" in stripped or "-.->" in stripped:
                arrow_pos = stripped.find("-->")
                if arrow_pos < 0:
                    arrow_pos = stripped.find("-.->")
                gid_pos = stripped.find(gid)
                if gid_pos < arrow_pos:
                    # gid is source — outgoing arrow should come from last rule
                    line = line.replace(gid, last_id)
                else:
                    # gid is target — incoming arrow should go to first rule
                    line = line.replace(gid, first_id)
            else:
                line = line.replace(gid, first_id)
        new_lines.append(line)

    return new_lines


def _annotate_node(line: str, node_id: str, annotation: str) -> str:
    """Add issue annotation to a node's label."""
    # Must match exact node_id followed by [ or { (node definition), not substrings
    if not re.search(rf'\b{re.escape(node_id)}(?=[\[{{])', line):
        return line
    if "-->" in line or "-.->" in line:
        return line

    # Find the closing bracket pattern and insert annotation before it
    for close_pattern in ('"]', '"}}'):
        if close_pattern in line:
            return line.replace(close_pattern,
                                f"\\n{annotation}{close_pattern}", 1)
    return line


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-annotate-mermaid.py <output_dir>")

    output_dir = sys.argv[1]

    # Load inputs
    base_path = os.path.join(output_dir, "mermaid-base.md")
    meta_path = os.path.join(output_dir, "mermaid-metadata.json")
    mapping_path = os.path.join(output_dir, "issue-rule-mapping.json")
    report_path = os.path.join(output_dir, "waf-review-report.md")

    for p in (base_path, meta_path, mapping_path, report_path):
        if not os.path.isfile(p):
            fatal(f"Required file not found: {p}")

    base_text = Path(base_path).read_text(encoding="utf-8")
    metadata = _load_json(meta_path)
    mapping = _load_json(mapping_path)
    annotations = mapping.get("annotations", {})

    # Load summary for full rule labels during fold group expansion
    summary_path = os.path.join(output_dir, "waf-summary.json")
    summary_rules = []
    if os.path.isfile(summary_path):
        summary_rules = _load_json(summary_path).get("rules", [])

    if not annotations:
        # No annotations — just copy base to final and append
        Path(os.path.join(output_dir, "mermaid-final.md")).write_text(
            base_text, encoding="utf-8")
        _append_to_report(report_path, base_text)
        print("No annotations to apply", file=sys.stderr)
        _print_result(0)
        return

    rule_to_node = _build_rule_to_node(metadata)
    fold_lookup = _build_fold_lookup(metadata)

    # Strip mermaid code fence for processing
    mermaid_content = base_text
    mermaid_content = re.sub(r'^```mermaid\s*\n', '', mermaid_content)
    mermaid_content = re.sub(r'\n```\s*$', '', mermaid_content)
    lines = mermaid_content.split("\n")

    # Phase 1: Expand fold groups that contain annotated rules
    expanded_groups = set()
    for rule_name in annotations:
        if rule_name in fold_lookup:
            fg = fold_lookup[rule_name]
            fg_key = f"{fg['priorities'][0]}_{fg['priorities'][-1]}"
            if fg_key not in expanded_groups:
                lines = _expand_fold_group(lines, fg, metadata, summary_rules)
                expanded_groups.add(fg_key)

    # Phase 2: Apply annotations to node lines
    applied = 0
    for rule_name, annotation in annotations.items():
        node_id = rule_to_node.get(rule_name)
        if not node_id:
            continue
        new_lines = []
        for line in lines:
            new_line = _annotate_node(line, node_id, annotation)
            if new_line != line:
                applied += 1
            new_lines.append(new_line)
        lines = new_lines

    # Reassemble
    final_mermaid = "```mermaid\n" + "\n".join(lines) + "\n```\n"
    final_path = os.path.join(output_dir, "mermaid-final.md")
    Path(final_path).write_text(final_mermaid, encoding="utf-8")

    # Append to report
    _append_to_report(report_path, final_mermaid)

    # Append appendix if exists
    appendix_path = os.path.join(output_dir, "appendix.md")
    if os.path.isfile(appendix_path):
        appendix_text = Path(appendix_path).read_text(encoding="utf-8")
        with open(report_path, "a", encoding="utf-8") as f:
            f.write(appendix_text)
        print("Appended appendix.md to report", file=sys.stderr)

    print(f"Applied {applied} annotations, expanded {len(expanded_groups)} fold groups",
          file=sys.stderr)
    _print_result(applied)


def _append_to_report(report_path: str, mermaid_text: str):
    """Append Mermaid diagram as appendix to the report."""
    appendix = f"\n---\n\n## Appendix: Rule Execution Flow\n\n{mermaid_text}"
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(appendix)


def _print_result(applied: int):
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"ANNOTATIONS_APPLIED: {applied}")


if __name__ == "__main__":
    main()
