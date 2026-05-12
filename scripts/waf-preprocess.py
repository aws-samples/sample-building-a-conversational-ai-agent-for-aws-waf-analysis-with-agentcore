# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Preprocess: Extract structured summary from AWS WAF Web ACL JSON.

Usage: python3 waf-preprocess.py <input_path> <output_dir>
  input_path: WAF JSON file or directory containing one
  output_dir: absolute path for output files (created if needed)

Supports: AWS CLI (PascalCase), Console export, snake_case custom formats.
"""
import json
import os
import re
import sys
from pathlib import Path
from waf_utils import fatal

# Keys to skip during processing (internal/display-only fields)
SKIP_KEYS = frozenset({
    "visible_scope_down_statement", "VisibleScopeDownStatement",
    "shadow_ip_set_reference_statement", "ShadowIpSetReferenceStatement",
    "payer_token", "PayerToken",
    "isolation_status", "IsolationStatus",
    "retrofitted_by_fms", "RetrofittedByFirewallManager",
    "simplified_web_acl", "alb_web_acl_attributes",
    "oversize_fields_handling_compliant",
})

SAMPLE_THRESHOLD = 3  # OR branches with more same-type leaves get sampled

# ── Key normalization ──────────────────────────────────────────────────────

_PASCAL_RE = re.compile(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])')

# Known acronyms that _PASCAL_RE mishandles (consecutive uppercase)
_ACRONYM_FIXES = {
    "d_do_s": "ddos",
    "ur_is": "uris",
    "a_w_s": "aws",
    "i_p": "ip",
    "a_c_l": "acl",
    "a_r_n": "arn",
    "x_s_s": "xss",
    "sq_li": "sqli",
    "s_q_l": "sql",
}

def _to_snake(name: str) -> str:
    result = _PASCAL_RE.sub('_', name).lower()
    for wrong, right in _ACRONYM_FIXES.items():
        result = result.replace(wrong, right)
    return result

def _normalize_keys(obj):
    """Recursively convert all dict keys to snake_case, skipping SKIP_KEYS."""
    if isinstance(obj, dict):
        return {_to_snake(k): _normalize_keys(v) for k, v in obj.items()
                if k not in SKIP_KEYS and _to_snake(k) not in SKIP_KEYS}
    if isinstance(obj, list):
        return [_normalize_keys(i) for i in obj]
    return obj

# ── Input discovery & normalization ────────────────────────────────────────

def _find_input_file(input_path: str) -> str:
    p = Path(input_path)
    if p.is_file():
        return str(p.resolve())
    if p.is_dir():
        candidates = []
        for f in p.rglob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                if _detect_format(data) is not None:
                    candidates.append(f)
            except (json.JSONDecodeError, OSError):
                continue
        if len(candidates) == 0:
            fatal(f"No WAF JSON found in {p}")
        if len(candidates) > 1:
            names = ", ".join(c.name for c in candidates)
            fatal(f"Multiple WAF JSON files found: {names}. Please specify the exact file path.")
        return str(candidates[0].resolve())
    fatal(f"Path not found: {input_path}")

def _detect_format(data: dict) -> str | None:
    if "WebACL" in data and isinstance(data["WebACL"], dict):
        return "aws_cli"
    if "web_acl" in data and isinstance(data["web_acl"], dict):
        return "snake_case_custom"
    if "Rules" in data and isinstance(data["Rules"], list):
        return "console_export"
    if "rules" in data and isinstance(data["rules"], list):
        return "console_export"
    return None

def _extract_web_acl(data: dict) -> tuple[dict, str]:
    fmt = _detect_format(data)
    if fmt == "aws_cli":
        return data["WebACL"], fmt
    if fmt == "snake_case_custom":
        return data["web_acl"], fmt
    if fmt == "console_export":
        return data, fmt
    fatal("Unrecognized WAF JSON format")

# ── Line number tracking ──────────────────────────────────────────────────

def _build_line_index(text: str, rules_key: str) -> dict[int, tuple[int, int]]:
    """Map rule index → (start_line, end_line) by scanning JSON text."""
    lines = text.split('\n')
    # Find each rule by looking for "name" or "Name" keys at the rule level
    # Strategy: find the rules array, then track brace depth for each element
    result = {}
    in_rules = False
    depth = 0
    rule_idx = -1
    rule_start = -1
    brace_depth_at_rules = 0

    # Simple state machine: find "rules": [ or "Rules": [
    rules_pattern = re.compile(r'"(?:rules|Rules)"\s*:\s*\[')
    rules_line = -1
    for i, line in enumerate(lines):
        if rules_pattern.search(line):
            rules_line = i
            break

    if rules_line < 0:
        return result

    # Now track braces from rules_line onwards
    depth = 0
    started = False
    in_string = False
    escaped = False
    for i in range(rules_line, len(lines)):
        line = lines[i]
        for ch in line:
            if escaped:
                escaped = False
                continue
            if ch == '\\':
                if in_string:
                    escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '[' and not started:
                started = True
                depth = 0
                continue
            if not started:
                continue
            if ch == '{':
                if depth == 0:
                    rule_idx += 1
                    rule_start = i + 1  # 1-indexed
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and rule_start > 0:
                    result[rule_idx] = (rule_start, i + 1)  # 1-indexed inclusive
            elif ch == ']' and depth == 0:
                return result
    return result

# ── Statement summarization ───────────────────────────────────────────────

def _field_to_match_str(ftm: dict) -> str:
    if not ftm or not isinstance(ftm, dict):
        return "unknown_field"
    for key, val in ftm.items():
        if key == "single_header":
            name = val.get("name", "?") if isinstance(val, dict) else "?"
            return f"single_header:{name}"
        if key == "uri_path" or key == "uri":
            return "uri_path"
        if key == "query_string":
            return "query_string"
        if key == "body":
            return "body"
        if key == "json_body":
            return "json_body"
        if key == "method":
            return "method"
        if key == "single_query_argument":
            name = val.get("name", "?") if isinstance(val, dict) else "?"
            return f"single_query_argument:{name}"
        if key in ("ja3_fingerprint", "ja4_fingerprint"):
            return key
        if key == "cookie" or key == "cookies":
            return "cookie"
        if key == "headers":
            return "headers"
        if key == "header_order":
            return "header_order"
        return key
    return "unknown_field"

def _summarize_statement(stmt: dict) -> dict:
    """Return {summary: str, leaf_count: int, leaf_types: set, samples: dict|None}."""
    if not stmt or not isinstance(stmt, dict):
        return {"summary": "EMPTY", "leaf_count": 0, "leaf_types": set(), "samples": None}

    # Leaf: byte_match_statement
    if "byte_match_statement" in stmt:
        bm = stmt["byte_match_statement"]
        ftm = _field_to_match_str(bm.get("field_to_match", {}))
        ss = bm.get("search_string", "?")
        pc = bm.get("positional_constraint", "?")
        return {"summary": f"{ftm} {pc} '{ss}'", "leaf_count": 1,
                "leaf_types": {"byte_match"}, "samples": None}

    # Leaf: sqli_match_statement
    if "sqli_match_statement" in stmt:
        sm = stmt["sqli_match_statement"]
        ftm = _field_to_match_str(sm.get("field_to_match", {}))
        return {"summary": f"sqli_match({ftm})", "leaf_count": 1,
                "leaf_types": {"sqli_match"}, "samples": None}

    # Leaf: xss_match_statement
    if "xss_match_statement" in stmt:
        xm = stmt["xss_match_statement"]
        ftm = _field_to_match_str(xm.get("field_to_match", {}))
        return {"summary": f"xss_match({ftm})", "leaf_count": 1,
                "leaf_types": {"xss_match"}, "samples": None}

    # Leaf: size_constraint_statement
    if "size_constraint_statement" in stmt:
        sc = stmt["size_constraint_statement"]
        ftm = _field_to_match_str(sc.get("field_to_match", {}))
        op = sc.get("comparison_operator", "?")
        sz = sc.get("size", "?")
        return {"summary": f"size({ftm}) {op} {sz}", "leaf_count": 1,
                "leaf_types": {"size_constraint"}, "samples": None}

    # Leaf: geo_match_statement
    if "geo_match_statement" in stmt:
        gm = stmt["geo_match_statement"]
        codes = gm.get("country_codes", [])
        return {"summary": f"geo_match {codes}", "leaf_count": 1,
                "leaf_types": {"geo_match"}, "samples": None}

    # Leaf: ip_set_reference_statement
    if "ip_set_reference_statement" in stmt:
        ips = stmt["ip_set_reference_statement"]
        arn = ips.get("ip_set_arn", ips.get("arn", "?"))
        return {"summary": f"ip_set '{arn}'", "leaf_count": 1,
                "leaf_types": {"ip_set"}, "samples": None}

    # Leaf: regex_match_statement
    if "regex_match_statement" in stmt:
        rm = stmt["regex_match_statement"]
        ftm = _field_to_match_str(rm.get("field_to_match", {}))
        regex = rm.get("regex_string", "?")
        return {"summary": f"regex_match({ftm}, '{regex}')", "leaf_count": 1,
                "leaf_types": {"regex_match"}, "samples": None}

    # Leaf: regex_pattern_set_reference_statement
    if "regex_pattern_set_reference_statement" in stmt:
        rp = stmt["regex_pattern_set_reference_statement"]
        ftm = _field_to_match_str(rp.get("field_to_match", {}))
        arn = rp.get("regex_pattern_set_arn", rp.get("arn", "?"))
        return {"summary": f"regex_set({ftm}, '{arn}')", "leaf_count": 1,
                "leaf_types": {"regex_pattern_set"}, "samples": None}

    # Leaf: label_match_statement
    if "label_match_statement" in stmt:
        lm = stmt["label_match_statement"]
        key = lm.get("key", "?")
        scope = lm.get("scope", "LABEL")
        return {"summary": f"label_match '{key}' (scope={scope})", "leaf_count": 1,
                "leaf_types": {"label_match"}, "samples": None}

    # Leaf: asn_match_statement
    if "asn_match_statement" in stmt:
        am = stmt["asn_match_statement"]
        asns = am.get("asn_list", [])
        return {"summary": f"asn_match {asns}", "leaf_count": 1,
                "leaf_types": {"asn_match"}, "samples": None}

    # Logic: and_statement
    if "and_statement" in stmt:
        children = stmt["and_statement"].get("statements", [])
        return _summarize_logic("AND", children)

    # Logic: or_statement
    if "or_statement" in stmt:
        children = stmt["or_statement"].get("statements", [])
        return _summarize_logic("OR", children)

    # Logic: not_statement
    if "not_statement" in stmt:
        inner = stmt["not_statement"].get("statement", {})
        child = _summarize_statement(inner)
        return {"summary": f"NOT({child['summary']})",
                "leaf_count": child["leaf_count"],
                "leaf_types": child["leaf_types"],
                "samples": child["samples"]}

    # Rate-based (top-level only, scope_down handled separately)
    if "rate_based_statement" in stmt:
        rb = stmt["rate_based_statement"]
        return {"summary": f"rate_based(limit={rb.get('limit', '?')}, window={rb.get('time_window', rb.get('evaluation_window_sec', '?'))}s)",
                "leaf_count": 0, "leaf_types": set(), "samples": None}

    # Managed rule group
    for mkey in ("managed_rule_group_statement", "managed_rule_set_statement"):
        if mkey in stmt:
            mg = stmt[mkey]
            vendor = mg.get("vendor_name", "AWS")
            name = mg.get("name", "")
            if not name:
                arn = mg.get("managed_rule_set_arn", mg.get("managed_rule_group_arn", ""))
                if "/" in arn and not arn.startswith("<"):
                    parts = arn.split("/")
                    name = parts[-2] if len(parts) >= 3 else parts[-1]
            version = mg.get("managed_rule_set_version", mg.get("version", ""))
            # name may still be empty; caller will fill via _extract_managed_group_name
            return {"summary": f"managed: {vendor}/{name} {version}".strip(),
                    "leaf_count": 0, "leaf_types": set(), "samples": None}

    # Rule group reference
    if "rule_group_reference_statement" in stmt:
        rg = stmt["rule_group_reference_statement"]
        arn = rg.get("rule_group_arn", rg.get("arn", "?"))
        return {"summary": f"rule_group '{arn}'", "leaf_count": 0,
                "leaf_types": set(), "samples": None}

    # Unknown
    keys = list(stmt.keys())
    return {"summary": f"UNKNOWN: {keys}", "leaf_count": 0,
            "leaf_types": set(), "samples": None}

def _summarize_logic(op: str, children: list) -> dict:
    child_results = [_summarize_statement(c) for c in children]
    total_leaves = sum(r["leaf_count"] for r in child_results)
    all_types = set()
    for r in child_results:
        all_types.update(r["leaf_types"])

    # Check for sampling: if all children are same leaf type and count > threshold
    samples = None
    if len(child_results) > SAMPLE_THRESHOLD and len(all_types) == 1 and all(r["leaf_count"] == 1 for r in child_results):
        leaf_type = next(iter(all_types))
        summaries = [r["summary"] for r in child_results]
        # Extract search_string values from summaries for sampling
        values = []
        for s in summaries:
            m = re.search(r"'([^']*)'", s)
            if m:
                values.append(m.group(1))
        if values:
            sample_vals = values[:2] + values[-1:]
            samples = {"type": leaf_type, "total": len(child_results), "values": sample_vals}
        summary = f"{op}({len(child_results)} {leaf_type} matches)"
    else:
        parts = [r["summary"] for r in child_results]
        summary = f"{op}({', '.join(parts)})"

    # Propagate first child's samples if only one child has them
    if samples is None:
        for r in child_results:
            if r["samples"] is not None:
                samples = r["samples"]
                break

    return {"summary": summary, "leaf_count": total_leaves,
            "leaf_types": all_types, "samples": samples}

# ── Rule extraction ───────────────────────────────────────────────────────

def _extract_action(rule: dict) -> str:
    # Custom rules: rule_action / action
    for key in ("rule_action", "action"):
        ra = rule.get(key, {})
        if ra and isinstance(ra, dict):
            for act in ("allow", "block", "count", "challenge", "captcha"):
                if act in ra:
                    return act

    # Managed rule groups: rule_group_action / override_action
    for key in ("rule_group_action", "override_action"):
        rga = rule.get(key, {})
        if rga and isinstance(rga, dict):
            if "none" in rga:
                return "managed_default"
            for act in ("allow", "block", "count", "challenge", "captcha"):
                if act in rga:
                    return act

    return "unknown"

def _extract_overrides(mg: dict) -> list:
    overrides = mg.get("rule_action_overrides", [])
    result = []
    for o in overrides:
        name = o.get("name", "?")
        action_obj = o.get("action_to_use", {})
        action = "excluded"
        for act in ("allow", "block", "count", "challenge", "captcha"):
            if act in action_obj:
                action = act
                break
        result.append({"rule_name": name, "action": action})
    return result

def _extract_excluded_rules(mg: dict) -> list:
    excluded = mg.get("excluded_rules", [])
    return [e.get("name", "?") for e in excluded if isinstance(e, dict) and "name" in e]

def _extract_managed_config(mg: dict) -> dict | None:
    configs = mg.get("managed_rule_set_configs", mg.get("managed_rule_group_configs", []))
    if not configs:
        return None
    result = {}
    for cfg in configs:
        if isinstance(cfg, dict):
            for key, val in cfg.items():
                if isinstance(val, dict):
                    result.update(val)
                else:
                    result[key] = val
    return result or None

def _extract_managed_group_name(mg: dict, rule_name: str) -> tuple[str, str]:
    """Return (vendor, group_name)."""
    vendor = mg.get("vendor_name", "AWS")
    name = mg.get("name", "")
    if name:
        return vendor, name
    # Fallback: extract from ARN (format: arn:aws:wafv2:...:managed-rule-set/vendor/name/id)
    arn = mg.get("managed_rule_set_arn", mg.get("managed_rule_group_arn", ""))
    if "/" in arn and not arn.startswith("<"):
        parts = arn.split("/")
        if len(parts) >= 3:
            return parts[-3], parts[-2]  # vendor, name
        return vendor, parts[-1]
    # Last resort: use rule name — strip common prefixes like "AWS-"
    gn = rule_name
    if gn.startswith("AWS-"):
        gn = gn[4:]
    return vendor, gn

def _extract_scope_down(container: dict) -> dict | None:
    sd = container.get("scope_down_statement")
    if not sd:
        return None
    s = _summarize_statement(sd)
    return {"summary": s["summary"], "source_lines": None}  # source_lines filled later

def _process_rule(rule: dict, idx: int, line_index: dict, jsonpath_prefix: str) -> dict:
    name = rule.get("name", f"rule_{idx}")
    priority = rule.get("priority", idx)
    action = _extract_action(rule)
    stmt = rule.get("statement", {})

    # Determine type
    rule_type = "custom"
    managed_info = None
    rate_info = None
    scope_down = None

    # Check for managed rule group
    mg = None
    for mkey in ("managed_rule_group_statement", "managed_rule_set_statement"):
        if mkey in stmt:
            mg = stmt[mkey]
            rule_type = "managed_rule_group"
            break

    if mg:
        vendor, group_name = _extract_managed_group_name(mg, name)
        version = mg.get("managed_rule_set_version", mg.get("version", ""))
        managed_info = {
            "vendor": vendor,
            "group_name": group_name,
            "version": version,
            "overrides": _extract_overrides(mg),
            "excluded_rules": _extract_excluded_rules(mg),
            "config": _extract_managed_config(mg),
        }
        scope_down = _extract_scope_down(mg)

    # Check for rate-based
    if "rate_based_statement" in stmt:
        rule_type = "rate_based"
        rb = stmt["rate_based_statement"]
        rate_info = {
            "limit": rb.get("limit"),
            "evaluation_window_sec": rb.get("time_window", rb.get("evaluation_window_sec")),
            "aggregate_key_type": rb.get("aggregate_key_type", "IP"),
        }
        scope_down = _extract_scope_down(rb)

    # Statement summary
    stmt_result = _summarize_statement(stmt)

    # Fix managed rule group summary with resolved group_name
    if managed_info and stmt_result["summary"].startswith("managed:"):
        version = managed_info["version"]
        stmt_result["summary"] = f"managed: {managed_info['vendor']}/{managed_info['group_name']} {version}".strip()

    # Rule labels
    labels_raw = rule.get("rule_labels", [])
    labels = [l.get("name", l) if isinstance(l, dict) else l for l in labels_raw]

    # Visibility config
    vc = rule.get("visibility_config", {})
    vis = {
        "metric_name": vc.get("metric_name", ""),
        "sampled_requests_enabled": vc.get("sampled_requests_enabled", False),
        "cloudwatch_metrics_enabled": vc.get("cloud_watch_metrics_enabled",
                                              vc.get("cloudwatch_metrics_enabled", False)),
    }

    # Challenge/CAPTCHA config at rule level
    challenge_cfg = None
    cc = rule.get("challenge_config", {})
    if cc:
        itp = cc.get("immunity_time_property", {})
        if itp:
            challenge_cfg = {"immunity_time": itp.get("immunity_time")}

    # Source lines
    lines = line_index.get(idx)
    source = {
        "lines": list(lines) if lines else None,
        "jsonpath": f"{jsonpath_prefix}[{idx}]",
    }

    # Fill scope_down source_lines from rule's source lines
    if scope_down and lines:
        scope_down["source_lines"] = list(lines)

    result = {
        "name": name,
        "priority": priority,
        "type": rule_type,
        "action": action,
        "rule_labels": labels,
        "visibility_config": vis,
        "statement": {
            "summary": stmt_result["summary"],
            "leaf_count": stmt_result["leaf_count"],
            "leaf_types": sorted(stmt_result["leaf_types"]),
            "samples": stmt_result["samples"],
        },
        "source": source,
        "scope_down": scope_down,
    }

    if managed_info:
        result["managed"] = managed_info
    if rate_info:
        result["rate_based"] = rate_info
    if challenge_cfg:
        result["challenge_config"] = challenge_cfg

    return result

# ── Main ──────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        fatal("Usage: waf-preprocess.py <input_path> <output_dir>")

    input_path = sys.argv[1]
    output_dir = sys.argv[2]

    # Find input file
    input_file = _find_input_file(input_path)
    print(f"Input file: {input_file}", file=sys.stderr)

    # Read and parse
    try:
        raw_text = Path(input_file).read_text(encoding="utf-8", errors="replace")
        raw_data = json.loads(raw_text)
    except (json.JSONDecodeError, OSError) as e:
        fatal(f"Failed to parse {input_file}: {e}")

    # Detect format and extract web_acl
    fmt = _detect_format(raw_data)
    if fmt is None:
        fatal(f"Unrecognized WAF JSON format in {input_file}")

    web_acl_raw, fmt = _extract_web_acl(raw_data)

    # Normalize keys to snake_case
    web_acl = _normalize_keys(web_acl_raw)

    # Build line index from raw text
    line_index = _build_line_index(raw_text, "rules")

    # Determine jsonpath prefix based on format
    if fmt == "aws_cli":
        jp_prefix = "$.WebACL.Rules"
    elif fmt == "snake_case_custom":
        jp_prefix = "$.web_acl.rules"
    else:
        jp_prefix = "$.Rules"

    # Extract rules
    rules_raw = web_acl.get("rules", [])
    rules = []
    for idx, rule in enumerate(rules_raw):
        rules.append(_process_rule(rule, idx, line_index, jp_prefix))

    # Extract web_acl metadata
    default_action = "unknown"
    da = web_acl.get("default_action", {})
    if "allow" in da:
        default_action = "allow"
    elif "block" in da:
        default_action = "block"

    da_custom = bool(da.get("allow", {}) or da.get("block", {}))
    # Check for custom request/response handling
    da_obj = da.get("allow", da.get("block", {}))
    has_custom_handling = False
    if isinstance(da_obj, dict) and da_obj:
        has_custom_handling = bool(da_obj.get("custom_request_handling") or
                                   da_obj.get("custom_response_bodies"))

    token_domains = web_acl.get("token_domains", [])
    capacity = web_acl.get("capacity")

    challenge_config = None
    cc = web_acl.get("challenge_config", {})
    if cc:
        itp = cc.get("immunity_time_property", {})
        if itp:
            challenge_config = {"immunity_time": itp.get("immunity_time")}

    captcha_config = None
    capc = web_acl.get("captcha_config", {})
    if capc:
        itp = capc.get("immunity_time_property", {})
        if itp:
            captcha_config = {"immunity_time": itp.get("immunity_time")}

    summary = {
        "schema_version": "1.0",
        "input_file": input_file,
        "input_format": fmt,
        "web_acl": {
            "name": web_acl.get("name", "unknown"),
            "id": web_acl.get("id", ""),
            "arn": web_acl.get("arn", web_acl.get("resource_arn", "")),
            "description": web_acl.get("description", ""),
            "default_action": default_action,
            "default_action_custom_handling": has_custom_handling,
            "capacity": capacity,
            "token_domains": token_domains,
            "challenge_config": challenge_config,
            "captcha_config": captcha_config,
        },
        "rule_count": len(rules),
        "rules": rules,
    }

    # Write output
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "waf-summary.json")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
    except OSError as e:
        fatal(f"Failed to write {output_file}: {e}")

    print(f"Processed {len(rules)} rules", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {output_file}")
    print(f"INPUT_FILE: {input_file}")
    print(f"RULE_COUNT: {len(rules)}")

if __name__ == "__main__":
    main()
