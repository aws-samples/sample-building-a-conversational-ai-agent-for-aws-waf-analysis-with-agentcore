# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Generate Mermaid: Create base Mermaid diagram from waf-summary.json.

Usage: python3 waf-generate-mermaid.py <output_dir>
  output_dir: directory containing waf-summary.json (from waf-preprocess.py)

Outputs:
  {output_dir}/mermaid-base.md      — Mermaid flowchart without issue annotations
  {output_dir}/mermaid-metadata.json — node list, label deps, fold groups for validation
"""
import json
import os
import re
import sys
from pathlib import Path
from waf_utils import fatal

GROUPED_MODE_THRESHOLD = 25
SCRIPTS_DIR = Path(__file__).parent

# ── Label dependency discovery ─────────────────────────────────────────────

def _load_managed_labels() -> dict:
    p = SCRIPTS_DIR / "managed-labels.json"
    if not p.exists():
        return {"label_producers": {}, "managed_label_prefixes": {},
                "shared_token_labels": [], "token_label_producers": []}
    return json.loads(p.read_text(encoding="utf-8"))

def _find_label_refs_in_statement(stmt_summary: str) -> list[str]:
    """Extract label keys from statement summary strings."""
    return re.findall(r"label_match '([^']+)'", stmt_summary)

def _find_label_refs_in_rule(rule: dict) -> list[str]:
    """Find all label references in a rule (statement + scope_down)."""
    refs = []
    refs.extend(_find_label_refs_in_statement(rule.get("statement", {}).get("summary", "")))
    sd = rule.get("scope_down")
    if sd:
        refs.extend(_find_label_refs_in_statement(sd.get("summary", "")))
    return refs

def _resolve_label_producers(label: str, rules: list, managed_labels: dict) -> list[str]:
    """Find all rules that produce a given label. Returns list of rule names."""
    producers = []
    # Check custom rule labels
    for r in rules:
        if label in r.get("rule_labels", []):
            producers.append(r["name"])
    if producers:
        return producers
    # Check managed rule group labels (exact match)
    for group_name, labels in managed_labels.get("label_producers", {}).items():
        if label in labels:
            for r in rules:
                mg = r.get("managed", {})
                if mg.get("group_name") == group_name:
                    producers.append(r["name"])
    if producers:
        return producers
    # Check managed label prefixes (prefix match for category labels etc.)
    for prefix, group_name in managed_labels.get("managed_label_prefixes", {}).items():
        if label.startswith(prefix):
            for r in rules:
                mg = r.get("managed", {})
                if mg.get("group_name") == group_name:
                    producers.append(r["name"])
    if producers:
        return producers
    # Check shared token labels
    for tl in managed_labels.get("shared_token_labels", []):
        if label == tl or label.startswith(tl + ":"):
            for producer_group in managed_labels.get("token_label_producers", []):
                for r in rules:
                    mg = r.get("managed", {})
                    if mg.get("group_name") == producer_group:
                        producers.append(r["name"])
            break
    return producers

def _build_label_dependencies(rules: list, managed_labels: dict) -> list[dict]:
    """Build list of {producer, consumer, label} dependencies."""
    deps = []
    for r in rules:
        refs = _find_label_refs_in_rule(r)
        for label in refs:
            producers = _resolve_label_producers(label, rules, managed_labels)
            for producer in producers:
                if producer != r["name"]:
                    deps.append({
                        "producer": producer,
                        "consumer": r["name"],
                    "label": label,
                })
    return deps

# ── Node building ──────────────────────────────────────────────────────────

def _safe_id(priority: int) -> str:
    return f"rule_{priority}"

def _escape_mermaid(text: str) -> str:
    """Escape characters that break Mermaid syntax."""
    return text.replace('"', "'").replace("\n", "\\n")

def _short_action(action: str) -> str:
    return {"managed_default": "Managed", "allow": "Allow", "block": "Block",
            "count": "Count", "challenge": "Challenge", "captcha": "CAPTCHA",
            "unknown": "?"}.get(action, action)

def _build_node_label(rule: dict) -> str:
    name = rule["name"]
    priority = rule["priority"]
    action = _short_action(rule["action"])
    parts = [f"P{priority}: {name}", f"Action: {action}"]
    mg = rule.get("managed")
    if mg:
        overrides = mg.get("overrides", [])
        if overrides:
            ov_strs = [f"{o['rule_name']}→{_short_action(o['action'])}" for o in overrides[:3]]
            if len(overrides) > 3:
                ov_strs.append(f"+{len(overrides)-3} more")
            parts.append("Overrides: " + ", ".join(ov_strs))
    sd = rule.get("scope_down")
    if sd:
        summary = sd["summary"]
        if len(summary) > 60:
            summary = summary[:57] + "..."
        parts.append(f"Scope: {summary}")
    return "\\n".join(parts)

def _node_shape(rule: dict) -> tuple[str, str]:
    """Return (open_bracket, close_bracket) for Mermaid node shape."""
    if rule.get("scope_down") or rule["type"] == "rate_based":
        return '{{"', '"}}'  # diamond/rhombus
    if rule["action"] in ("allow", "block"):
        return '["', '"]'  # rectangle (terminating)
    return '["', '"]'  # rectangle

# ── Grouping logic (>25 rules) ─────────────────────────────────────────────

def _build_fold_groups(rules: list, label_dep_rules: set) -> list[dict]:
    """Identify consecutive same-type rules that can be folded.
    Never fold: Allow rules, rules with label deps, rules that will get issue annotations."""
    groups = []
    i = 0
    while i < len(rules):
        r = rules[i]
        # Never fold these
        if (r["action"] == "allow" or r["name"] in label_dep_rules
                or r["rule_labels"]):
            i += 1
            continue
        # Try to start a group of consecutive same-type managed rules
        if r["type"] == "managed_rule_group":
            j = i + 1
            while j < len(rules):
                rj = rules[j]
                if (rj["type"] != "managed_rule_group" or rj["action"] == "allow"
                        or rj["name"] in label_dep_rules or rj["rule_labels"]):
                    break
                j += 1
            if j - i >= 2:
                groups.append({
                    "start_idx": i, "end_idx": j - 1,
                    "rule_names": [rules[k]["name"] for k in range(i, j)],
                    "priorities": [rules[k]["priority"] for k in range(i, j)],
                    "label": f"P{rules[i]['priority']}-P{rules[j-1]['priority']}: {j-i} managed rule groups",
                })
                i = j
                continue
        # Try consecutive rate-based rules
        if r["type"] == "rate_based":
            j = i + 1
            while j < len(rules):
                rj = rules[j]
                if (rj["type"] != "rate_based" or rj["action"] == "allow"
                        or rj["name"] in label_dep_rules or rj["rule_labels"]):
                    break
                j += 1
            if j - i >= 2:
                groups.append({
                    "start_idx": i, "end_idx": j - 1,
                    "rule_names": [rules[k]["name"] for k in range(i, j)],
                    "priorities": [rules[k]["priority"] for k in range(i, j)],
                    "label": f"P{rules[i]['priority']}-P{rules[j-1]['priority']}: {j-i} rate-based rules",
                })
                i = j
                continue
        i += 1
    return groups

# ── Mermaid generation ─────────────────────────────────────────────────────

def _generate_detailed(rules: list, deps: list, default_action: str) -> str:
    """Generate detailed Mermaid (every rule = one node)."""
    lines = ["flowchart TD"]
    lines.append(f'    START(["Request"]) --> {_safe_id(rules[0]["priority"])}')
    lines.append("")

    for i, r in enumerate(rules):
        rid = _safe_id(r["priority"])
        label = _escape_mermaid(_build_node_label(r))
        ob, cb = _node_shape(r)
        lines.append(f'    {rid}{ob}{label}{cb}')

        # Terminating action branches
        if r["action"] == "allow":
            lines.append(f'    {rid} -->|"Allow"| ALLOW_{rid}["✅ Allowed"]')
        elif r["action"] == "block":
            lines.append(f'    {rid} -->|"Block"| BLOCK_{rid}["🚫 Blocked"]')
        elif r["action"] in ("challenge", "captcha"):
            act = "Challenge" if r["action"] == "challenge" else "CAPTCHA"
            lines.append(f'    {rid} -->|"non-browser → {act} = Block"| BLOCK_{rid}["🚫 Blocked"]')

        # Flow to next rule
        if i < len(rules) - 1:
            next_rid = _safe_id(rules[i + 1]["priority"])
            if r["action"] in ("allow", "block"):
                lines.append(f'    {rid} -->|"no match"| {next_rid}')
            elif r["action"] in ("challenge", "captcha"):
                lines.append(f'    {rid} -->|"valid token / no match"| {next_rid}')
            else:
                lines.append(f'    {rid} --> {next_rid}')
        lines.append("")

    # Default action
    last_rid = _safe_id(rules[-1]["priority"])
    da = "✅ Allowed" if default_action == "allow" else "🚫 Blocked"
    lines.append(f'    DEFAULT_ACTION["{da}\\nDefault Action: {default_action}"]')
    if rules[-1]["action"] not in ("allow", "block"):
        lines.append(f'    {last_rid} --> DEFAULT_ACTION')

    # Label dependency arrows (dashed)
    lines.append("")
    for dep in deps:
        prod_rule = next((r for r in rules if r["name"] == dep["producer"]), None)
        cons_rule = next((r for r in rules if r["name"] == dep["consumer"]), None)
        if prod_rule and cons_rule:
            short_label = dep["label"].split(":")[-1] if ":" in dep["label"] else dep["label"]
            if len(short_label) > 30:
                short_label = short_label[:27] + "..."
            lines.append(f'    {_safe_id(prod_rule["priority"])} -.->|"{short_label}"| {_safe_id(cons_rule["priority"])}')

    return "\n".join(lines)

def _generate_grouped(rules: list, deps: list, default_action: str,
                       fold_groups: list) -> str:
    """Generate grouped Mermaid (folded nodes for >25 rules)."""
    # Build set of folded rule indices
    folded_indices = set()
    for fg in fold_groups:
        for idx in range(fg["start_idx"], fg["end_idx"] + 1):
            folded_indices.add(idx)

    lines = ["flowchart TD"]
    lines.append(f'    START(["Request"]) --> {_first_node_id(rules, folded_indices, fold_groups)}')
    lines.append("")

    i = 0
    node_order = []  # track node IDs in order for linking
    while i < len(rules):
        # Check if this index starts a fold group
        fg = next((g for g in fold_groups if g["start_idx"] == i), None)
        if fg:
            gid = f"group_{fg['priorities'][0]}_{fg['priorities'][-1]}"
            label = _escape_mermaid(fg["label"])
            lines.append(f'    {gid}["{label}"]')
            node_order.append(gid)
            i = fg["end_idx"] + 1
            lines.append("")
            continue

        r = rules[i]
        rid = _safe_id(r["priority"])
        label = _escape_mermaid(_build_node_label(r))
        ob, cb = _node_shape(r)
        lines.append(f'    {rid}{ob}{label}{cb}')
        node_order.append(rid)

        if r["action"] == "allow":
            lines.append(f'    {rid} -->|"Allow"| ALLOW_{rid}["✅ Allowed"]')
        elif r["action"] == "block":
            lines.append(f'    {rid} -->|"Block"| BLOCK_{rid}["🚫 Blocked"]')
        elif r["action"] in ("challenge", "captcha"):
            act = "Challenge" if r["action"] == "challenge" else "CAPTCHA"
            lines.append(f'    {rid} -->|"non-browser → {act} = Block"| BLOCK_{rid}["🚫 Blocked"]')

        i += 1
        lines.append("")

    # Link nodes in order
    for idx in range(len(node_order) - 1):
        curr = node_order[idx]
        nxt = node_order[idx + 1]
        # Determine link style based on current node's rule
        curr_rule = _rule_for_node(curr, rules, fold_groups)
        if curr_rule and curr_rule["action"] in ("allow", "block"):
            lines.append(f'    {curr} -->|"no match"| {nxt}')
        elif curr_rule and curr_rule["action"] in ("challenge", "captcha"):
            lines.append(f'    {curr} -->|"valid token / no match"| {nxt}')
        else:
            lines.append(f'    {curr} --> {nxt}')

    # Default action
    da = "✅ Allowed" if default_action == "allow" else "🚫 Blocked"
    lines.append(f'    DEFAULT_ACTION["{da}\\nDefault Action: {default_action}"]')
    if node_order:
        last_rule = _rule_for_node(node_order[-1], rules, fold_groups)
        if not last_rule or last_rule["action"] not in ("allow", "block"):
            lines.append(f'    {node_order[-1]} --> DEFAULT_ACTION')

    # Label deps
    lines.append("")
    for dep in deps:
        prod_rule = next((r for r in rules if r["name"] == dep["producer"]), None)
        cons_rule = next((r for r in rules if r["name"] == dep["consumer"]), None)
        if prod_rule and cons_rule:
            prod_id = _node_id_for_rule(prod_rule, fold_groups)
            cons_id = _node_id_for_rule(cons_rule, fold_groups)
            short_label = dep["label"].split(":")[-1] if ":" in dep["label"] else dep["label"]
            if len(short_label) > 30:
                short_label = short_label[:27] + "..."
            lines.append(f'    {prod_id} -.->|"{short_label}"| {cons_id}')

    return "\n".join(lines)

def _first_node_id(rules, folded_indices, fold_groups):
    if 0 in folded_indices:
        fg = next(g for g in fold_groups if g["start_idx"] == 0)
        return f"group_{fg['priorities'][0]}_{fg['priorities'][-1]}"
    return _safe_id(rules[0]["priority"])

def _rule_for_node(node_id: str, rules: list, fold_groups: list) -> dict | None:
    if node_id.startswith("group_"):
        return None  # fold group, no single rule
    m = re.match(r"rule_(\d+)", node_id)
    if m:
        p = int(m.group(1))
        return next((r for r in rules if r["priority"] == p), None)
    return None

def _node_id_for_rule(rule: dict, fold_groups: list) -> str:
    for fg in fold_groups:
        if rule["name"] in fg["rule_names"]:
            return f"group_{fg['priorities'][0]}_{fg['priorities'][-1]}"
    return _safe_id(rule["priority"])

# ── Main ──────────────────────────────────────────────────────────────────


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-generate-mermaid.py <output_dir>")

    output_dir = sys.argv[1]
    summary_file = os.path.join(output_dir, "waf-summary.json")

    if not os.path.isfile(summary_file):
        fatal(f"waf-summary.json not found in {output_dir}")

    try:
        summary = json.loads(Path(summary_file).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        fatal(f"Failed to read {summary_file}: {e}")

    rules = summary.get("rules", [])
    if not rules:
        fatal("No rules found in waf-summary.json")

    default_action = summary.get("web_acl", {}).get("default_action", "allow")
    managed_labels = _load_managed_labels()

    # Build label dependencies
    deps = _build_label_dependencies(rules, managed_labels)

    # Determine mode
    use_grouped = len(rules) > GROUPED_MODE_THRESHOLD
    mode = "grouped" if use_grouped else "detailed"

    # Collect rules involved in label deps (never fold these)
    label_dep_rules = set()
    for d in deps:
        label_dep_rules.add(d["producer"])
        label_dep_rules.add(d["consumer"])

    fold_groups = []
    if use_grouped:
        fold_groups = _build_fold_groups(rules, label_dep_rules)
        mermaid_text = _generate_grouped(rules, deps, default_action, fold_groups)
    else:
        mermaid_text = _generate_detailed(rules, deps, default_action)

    # Count rule nodes only (skip arrow lines that define inline terminal nodes)
    node_count = 0
    for line in mermaid_text.split("\n"):
        stripped = line.strip()
        if "-->" in stripped or "-.->" in stripped:
            continue
        if stripped.startswith("rule_") or stripped.startswith("group_"):
            node_count += 1

    # Write mermaid-base.md
    mermaid_md = f"```mermaid\n{mermaid_text}\n```\n"
    mermaid_path = os.path.join(output_dir, "mermaid-base.md")
    Path(mermaid_path).write_text(mermaid_md, encoding="utf-8")

    # Write mermaid-metadata.json
    metadata = {
        "mode": mode,
        "rule_count": len(rules),
        "node_count": node_count,
        "rules": [{"name": r["name"], "priority": r["priority"],
                    "node_id": _safe_id(r["priority"])} for r in rules],
        "label_dependencies": deps,
        "fold_groups": fold_groups,
    }
    meta_path = os.path.join(output_dir, "mermaid-metadata.json")
    Path(meta_path).write_text(json.dumps(metadata, indent=2, ensure_ascii=False),
                                encoding="utf-8")

    print(f"Generated {mode} Mermaid diagram ({node_count} nodes, {len(deps)} label deps)",
          file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"MODE: {mode}")
    print(f"NODE_COUNT: {node_count}")
    print(f"LABEL_DEPS: {len(deps)}")

if __name__ == "__main__":
    main()
