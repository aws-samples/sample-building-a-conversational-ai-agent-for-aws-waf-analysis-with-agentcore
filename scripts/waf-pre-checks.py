# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Pre-checks: Run mechanical checks and extract flags from waf-summary.json.

Usage: python3 waf-pre-checks.py <output_dir> <input_file>
  output_dir: directory containing waf-summary.json
  input_file: original WAF JSON file (for detailed field inspection)

Outputs: {output_dir}/pre-checks.json
"""
import json
import os
import re
import sys
from pathlib import Path
from waf_utils import fatal

# ── Forgeability mapping ──────────────────────────────────────────────────
# Source of truth: managed-labels.json (forgeability section).
# Hardcoded here to avoid file I/O at import time. Keep in sync.

FORGEABLE_FIELDS = {
    "single_header", "single_query_argument", "cookie", "cookies",
    "body", "json_body", "uri_path", "query_string", "method",
    "header_order", "headers",
}
UNFORGEABLE_STMT_TYPES = {
    "ip_set", "asn_match", "geo_match", "rate_based",
}
UNFORGEABLE_FIELDS = {
    "ja3_fingerprint", "ja4_fingerprint",
}

ALL_KNOWN_FIELDS = FORGEABLE_FIELDS | UNFORGEABLE_FIELDS | UNFORGEABLE_STMT_TYPES | {"label_match"}

def _classify_condition(summary: str) -> tuple[list, list]:
    """Parse statement summary and classify conditions as forgeable/unforgeable.

    IMPORTANT: This regex is tightly coupled to the summary format produced by
    _summarize_statement() in waf-preprocess.py. If that format changes, update
    the patterns here accordingly.
    """
    forgeable = []
    unforgeable = []

    # Extract known field types from summary (ignore quoted values)
    # Match patterns like: "single_header:user-agent EXACTLY", "ip_set '...'", "asn_match [..."
    for match in re.finditer(r'([\w]+(?::[\w:.-]+)?)\s+(?:EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS|\'|\[)', summary):
        field = match.group(1)
        base_field = field.split(":")[0]

        if base_field not in ALL_KNOWN_FIELDS:
            continue  # skip non-field tokens (e.g., search_string values)

        if base_field in UNFORGEABLE_FIELDS or base_field in UNFORGEABLE_STMT_TYPES:
            unforgeable.append(field)
        elif base_field == "label_match":
            unforgeable.append(field)
        else:
            forgeable.append(field)

    # Check for statement-level patterns not caught by field regex
    for stmt_type in UNFORGEABLE_STMT_TYPES:
        if stmt_type in summary and stmt_type not in [u.split(":")[0] for u in unforgeable]:
            unforgeable.append(stmt_type)

    return forgeable, unforgeable

def _has_uri_constraint(summary: str) -> bool:
    """Check if statement contains a meaningful URI path constraint.
    uri_path STARTS_WITH '/' matches all traffic — not a real constraint."""
    if not re.search(r'uri_path\s+(?:EXACTLY|STARTS_WITH|ENDS_WITH|CONTAINS)', summary):
        return False
    # STARTS_WITH '/' matches everything — treat as no constraint
    if re.search(r"uri_path\s+STARTS_WITH\s+'/'", summary):
        return False
    return True

# ── Pre-checks ────────────────────────────────────────────────────────────

def _check_token_domain(web_acl: dict) -> dict:
    """Check #11: token_domains redundancy."""
    domains = web_acl.get("token_domains", [])
    if not domains:
        return {"status": "PASS", "finding": None}

    # Find apex domains and their subdomains.
    # Heuristic: the shortest domain for each TLD suffix is the apex.
    # This handles multi-part TLDs like .co.uk, .com.cn, .co.jp.
    issues = []

    # Group domains by their last-2 parts (potential simple TLD)
    # Then identify apex as the shortest domain in each suffix group
    apex_domains = set()
    # Sort by part count ascending — shortest first
    sorted_domains = sorted(domains, key=lambda d: len(d.split(".")))
    for d in sorted_domains:
        # A domain is an apex if no existing apex is a suffix of it
        is_sub = any(d.endswith("." + apex) for apex in apex_domains)
        if not is_sub:
            apex_domains.add(d)

    redundant = []
    for d in domains:
        if d in apex_domains:
            continue  # apex itself
        # Check if any apex covers this subdomain (suffix match)
        covering_apex = next((a for a in apex_domains if d.endswith("." + a)), None)
        if covering_apex:
            redundant.append(d)

    # Check for missing apex: domains whose apex (shortest covering suffix)
    # is not in the token_domains list
    missing_apex = set()
    for d in domains:
        if d in apex_domains:
            continue
        has_covering = any(d.endswith("." + a) for a in apex_domains)
        if not has_covering:
            # This domain has no covering apex in the list — it IS an apex
            # (already handled above), or its apex is missing.
            # Since we already identified all apexes, this shouldn't happen,
            # but guard against it.
            missing_apex.add(d)

    if redundant:
        issues.append(f"Redundant subdomains (covered by apex): {', '.join(redundant)}")
    if missing_apex:
        issues.append(f"Missing apex domains (add to cover subdomains): {', '.join(missing_apex)}")

    if issues:
        return {"status": "FAIL", "finding": "; ".join(issues),
                "domains": domains, "redundant": redundant,
                "missing_apex": list(missing_apex)}
    return {"status": "PASS", "finding": None}

def _check_managed_versions(rules: list) -> dict:
    """Check #12: managed rule group versions."""
    issues = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        gn = mg.get("group_name", "")
        ver = mg.get("version", "")

        if "SQLiRuleSet" in gn or "sqli" in gn.lower():
            # Check if version < 2.0
            m = re.search(r'(\d+)\.(\d+)', ver)
            if m and int(m.group(1)) < 2:
                issues.append(f"{r['name']}: SQLiRuleSet version {ver} < 2.0 (recommend upgrading)")

        if "BotControlRuleSet" in gn or "bot_control" in gn.lower():
            m = re.search(r'(\d+)\.(\d+)', ver)
            if m and int(m.group(1)) < 5:
                issues.append(f"{r['name']}: BotControlRuleSet version {ver} < 5.0 (recommend upgrading)")

    if issues:
        return {"status": "FAIL", "finding": "; ".join(issues), "details": issues}
    return {"status": "PASS", "finding": None}

def _check_default_action_redundancy(web_acl: dict, rules: list) -> dict:
    """Check #15: redundant trailing Allow-all rule."""
    if web_acl.get("default_action") != "allow":
        return {"status": "PASS", "finding": None}
    if not rules:
        return {"status": "PASS", "finding": None}

    last = rules[-1]
    if last["action"] == "allow":
        summary = last.get("statement", {}).get("summary", "")
        # Check if it matches all traffic (URI STARTS_WITH '/' or similar)
        if ("STARTS_WITH '/'" in summary or summary == "EMPTY"
                or "uri_path STARTS_WITH '/'" in summary):
            return {"status": "FAIL",
                    "finding": f"Rule '{last['name']}' (priority {last['priority']}) matches all traffic with Allow, "
                               f"but default_action is already Allow. This rule is redundant.",
                    "rule": last["name"], "priority": last["priority"]}
    return {"status": "PASS", "finding": None}

def _check_count_without_labels(rules: list) -> dict:
    """Check #17a: custom Count rules without RuleLabels."""
    flagged = []
    for r in rules:
        if (r["action"] == "count" and r["type"] == "custom"
                and not r.get("rule_labels")):
            flagged.append({"name": r["name"], "priority": r["priority"]})

    if flagged:
        names = ", ".join(f["name"] for f in flagged)
        return {"status": "FAIL",
                "finding": f"Custom Count rules without labels (metric-only): {names}",
                "rules": flagged}
    return {"status": "PASS", "finding": None}


def _check_challenge_on_post_api(rules: list) -> dict:
    """Check #4: Challenge/CAPTCHA on POST or API paths (effectively Block)."""
    flagged = []
    for r in rules:
        if r["action"] not in ("challenge", "captcha"):
            continue
        summary = r.get("statement", {}).get("summary", "")
        reasons = []
        if "method EXACTLY 'POST'" in summary or "method EXACTLY 'PUT'" in summary:
            reasons.append("targets POST/PUT requests")
        if "/api/" in summary or "/api'" in summary:
            reasons.append("targets API path")
        if reasons:
            flagged.append({"name": r["name"], "priority": r["priority"],
                            "reasons": reasons})
    if flagged:
        details = "; ".join(f"{f['name']} (P{f['priority']}): {', '.join(f['reasons'])}" for f in flagged)
        return {"status": "FAIL",
                "finding": f"Challenge/CAPTCHA on non-browser paths (effectively Block): {details}",
                "rules": flagged}
    return {"status": "PASS", "finding": None}

def _check_hosting_provider_allow(rules: list) -> dict:
    """Check #7: HostingProviderIPList overridden to Allow (dangerous)."""
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        for override in mg.get("overrides", []):
            if override.get("rule_name") == "HostingProviderIPList" and override.get("action") == "allow":
                return {"status": "FAIL",
                        "finding": f"HostingProviderIPList overridden to Allow in {r['name']} (priority {r['priority']}). "
                                   f"Cloud-hosted attack traffic bypasses all subsequent rules. Override to Count instead.",
                        "rule": r["name"], "priority": r["priority"]}
    return {"status": "PASS", "finding": None}

# ── Flags ─────────────────────────────────────────────────────────────────

def _flag_allow_rules(rules: list) -> list:
    """Flag all Allow rules with forgeability analysis."""
    flags = []
    for r in rules:
        if r["action"] != "allow":
            continue
        summary = r.get("statement", {}).get("summary", "")
        forgeable, unforgeable = _classify_condition(summary)
        all_forgeable = len(unforgeable) == 0 and len(forgeable) > 0
        blast_radius = "path_scoped" if _has_uri_constraint(summary) else "global"

        flags.append({
            "name": r["name"],
            "priority": r["priority"],
            "statement_summary": summary,
            "forgeable_conditions": forgeable,
            "unforgeable_conditions": unforgeable,
            "all_forgeable": all_forgeable,
            "blast_radius": blast_radius,
        })
    return flags

def _flag_scope_downs(rules: list) -> list:
    """Flag all scope-down statements for LLM review."""
    flags = []
    for r in rules:
        sd = r.get("scope_down")
        if not sd:
            continue
        flags.append({
            "rule": r["name"],
            "priority": r["priority"],
            "rule_type": r["type"],
            "scope_down_summary": sd["summary"],
            "source_lines": sd.get("source_lines"),
        })
    return flags

def _split_regex_branches(regex: str) -> list[str]:
    """Split regex on | only at top level (outside parentheses)."""
    branches = []
    depth = 0
    current = []
    escaped = False
    for ch in regex:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == '\\':
            current.append(ch)
            escaped = True
            continue
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == '|' and depth == 0:
            branches.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        branches.append(''.join(current))
    return branches

def _flag_exempt_regex(rules: list) -> list:
    """Flag AntiDDoS AMR exempt URI regex branches with anchoring analysis."""
    flags = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        cfg = mg.get("config") or {}
        exempt = cfg.get("uris_exempt_from_challenge", [])
        if not exempt:
            continue

        regex_str = exempt[0] if isinstance(exempt, list) and exempt else str(exempt)
        branches = _split_regex_branches(regex_str)
        branch_analysis = []
        for b in branches:
            b = b.strip()
            branch_analysis.append({
                "pattern": b,
                "anchored_start": b.startswith("^"),
                "anchored_end": b.endswith("$"),
            })
        flags.append({
            "rule": r["name"],
            "priority": r["priority"],
            "full_regex": regex_str,
            "branches": branch_analysis,
        })
    return flags

# ── Main ──────────────────────────────────────────────────────────────────


def main():
    if len(sys.argv) < 3:
        fatal("Usage: waf-pre-checks.py <output_dir> <input_file>")

    output_dir = sys.argv[1]
    input_file = sys.argv[2]
    summary_file = os.path.join(output_dir, "waf-summary.json")

    if not os.path.isfile(summary_file):
        fatal(f"waf-summary.json not found in {output_dir}")

    try:
        summary = json.loads(Path(summary_file).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        fatal(f"Failed to read {summary_file}: {e}")

    web_acl = summary.get("web_acl", {})
    rules = summary.get("rules", [])

    # Run pre-checks
    pre_checks = {
        "token_domain": _check_token_domain(web_acl),
        "managed_versions": _check_managed_versions(rules),
        "default_action_redundancy": _check_default_action_redundancy(web_acl, rules),
        "count_without_labels": _check_count_without_labels(rules),
        "challenge_on_post_api": _check_challenge_on_post_api(rules),
        "hosting_provider_allow": _check_hosting_provider_allow(rules),
    }

    # Build flags
    flags = {
        "allow_rules": _flag_allow_rules(rules),
        "scope_downs": _flag_scope_downs(rules),
        "exempt_regex_branches": _flag_exempt_regex(rules),
    }

    result = {"pre_checks": pre_checks, "flags": flags}

    # Write output
    output_file = os.path.join(output_dir, "pre-checks.json")
    try:
        Path(output_file).write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        fatal(f"Failed to write {output_file}: {e}")

    checks_run = len(pre_checks)
    checks_failed = sum(1 for v in pre_checks.values() if v["status"] == "FAIL")

    print(f"Ran {checks_run} checks, {checks_failed} failed", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"CHECKS_RUN: {checks_run}")
    print(f"CHECKS_FAILED: {checks_failed}")

if __name__ == "__main__":
    main()
