# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#!/usr/bin/env python3
"""WAF Generate Findings: Produce deterministic findings from pre-checks and flags.

Usage: python3 waf-generate-findings.py <output_dir> [--lang en|zh]
  output_dir: directory containing waf-summary.json and pre-checks.json
  --lang: output language (default: en)

Outputs:
  {output_dir}/scripted-findings.md   — Issue section Markdown
  {output_dir}/findings-metadata.json — structured metadata
"""
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from waf_utils import fatal

# ── Constants ──────────────────────────────────────────────────────────────

ALWAYS_LLM_SECTIONS = {5, 8, 17}
APPENDIX_ONLY_SECTIONS = {10}

SEVERITY_ORDER = {"Critical": 0, "Medium": 1, "Low": 2, "Awareness": 3}

RECOMMENDED_ORDER = [
    ("ip_allow", "IP whitelist/blacklist"),
    ("crawler_labeling", "Crawler labeling rule"),
    ("antiddos_amr", "AntiDDoS AMR"),
    ("ip_reputation", "IP reputation / Anonymous IP"),
    ("rate_based", "Rate-based rules"),
    ("custom_block_challenge", "Custom Block/Challenge rules"),
    ("always_on_challenge", "Always-on Challenge"),
    ("app_layer", "Application-layer rule groups (CRS, KnownBadInputs)"),
    ("bot_control", "Bot Control / ATP / ACFP"),
]

MANAGED_BASELINE_GROUPS = {
    "AWSManagedRulesCommonRuleSet": "CRS",
    "AWSManagedRulesKnownBadInputsRuleSet": "KnownBadInputs",
}

IP_REPUTATION_GROUPS = {
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
}

CRAWLER_LABEL_PATTERNS = ("crawler:", "custom:crawler")

NOT_APPLICABLE = "NOT_APPLICABLE"
AMBIGUOUS = "AMBIGUOUS"


# ── Helpers ────────────────────────────────────────────────────────────────



def _classify_rule_type(rule: dict) -> str:
    """Classify a rule into a recommended-order category."""
    mg = rule.get("managed")
    if mg:
        gn = mg.get("group_name", "")
        if "AntiDDoS" in gn:
            return "antiddos_amr"
        if "IpReputation" in gn or "AnonymousIp" in gn:
            return "ip_reputation"
        if "BotControl" in gn:
            return "bot_control"
        if "ATP" in gn or "ACFP" in gn:
            return "bot_control"
        if gn in MANAGED_BASELINE_GROUPS:
            return "app_layer"
        return "app_layer"
    if rule.get("type") == "rate_based":
        return "rate_based"
    # Custom rules
    if rule.get("action") == "allow":
        # IP-set-based Allow = ip_allow
        leaf_types = rule.get("statement", {}).get("leaf_types", [])
        if "ip_set" in leaf_types:
            return "ip_allow"
    if rule.get("action") in ("challenge", "captcha"):
        stmt = rule.get("statement", {}).get("summary", "")
        # Check if it's an always-on challenge (label-based challenge)
        if "label_match" in stmt:
            return "always_on_challenge"
    # Crawler labeling: Count + ASN + produces label
    if (rule.get("action") == "count" and
            "asn_match" in rule.get("statement", {}).get("leaf_types", [])):
        return "crawler_labeling"
    return "custom_block_challenge"


def _has_opaque_value(value: str) -> str:
    """Check if a string looks like a hash/secret. Returns 'yes', 'maybe', or 'no'."""
    if len(value) < 16:
        return "no"
    # Exclude common non-secret patterns
    if value.startswith("/"):  # URI paths
        return "no"
    if re.match(r'^[\w.-]+\.\w{2,}$', value):  # hostnames like example.com
        return "no"
    if value in ("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"):
        return "no"
    classes = 0
    if re.search(r'[a-z]', value):
        classes += 1
    if re.search(r'[A-Z]', value):
        classes += 1
    if re.search(r'[0-9]', value):
        classes += 1
    if re.search(r'[^a-zA-Z0-9]', value):
        classes += 1
    if classes >= 3:
        return "yes"
    if classes >= 2 and len(value) >= 24:
        return "maybe"
    return "no"


def _extract_exactly_values(summary: str) -> list[tuple[str, str]]:
    """Extract (field, value) pairs from EXACTLY matches in statement summary."""
    results = []
    for m in re.finditer(r"([\w:.-]+)\s+EXACTLY\s+'([^']*)'", summary):
        results.append((m.group(1), m.group(2)))
    return results

from waf_finding_templates import TEMPLATES_EN, TEMPLATES_ZH

# ── Generators ─────────────────────────────────────────────────────────────
# Each returns (issue_md, metadata_dict) | NOT_APPLICABLE | AMBIGUOUS

def _gen_forgeable_allow(summary, pre_checks, flags, T, lang):
    allow_flags = flags.get("allow_rules", [])
    # Exclude rules handled by default_action_redundancy
    redundant_rule = None
    dar = pre_checks.get("default_action_redundancy", {})
    if dar.get("status") == "FAIL":
        redundant_rule = dar.get("rule")
    # Only handle all_forgeable + global blast radius
    candidates = [a for a in allow_flags
                  if a.get("all_forgeable") and a.get("blast_radius") == "global"
                  and a["name"] != redundant_rule]
    if not candidates:
        # If all Allow rules have unforgeable conditions, section is safe
        remaining = [a for a in allow_flags if a["name"] != redundant_rule]
        if not remaining:
            return NOT_APPLICABLE
        if all(not a.get("all_forgeable") for a in remaining):
            return NOT_APPLICABLE
        # Mixed forgeability within a group — needs LLM judgment
        return AMBIGUOUS

    # Group by forgeable_conditions content
    groups = defaultdict(list)
    for a in candidates:
        key = tuple(sorted(a.get("forgeable_conditions", [])))
        groups[key].append(a)

    results = []
    for key, group in groups.items():
        names = [a["name"] for a in group]
        rule_names = " / ".join(names)
        if len(group) == 1:
            rule_line = f"{names[0]} (priority {group[0]['priority']})"
            dup_note = ""
            dup_rec = ""
        else:
            rule_line = ", ".join(f"{a['name']} (priority {a['priority']})" for a in group)
            if lang == "zh":
                dup_note = f"- {len(group)} 条规则逻辑完全相同，只需保留一条\n"
                dup_rec = "- 删除重复规则，保留一条即可\n"
            else:
                dup_note = f"- {len(group)} rules have identical logic, only one is needed\n"
                dup_rec = "- Remove duplicate rules, keep one\n"

        fc = group[0]["forgeable_conditions"]
        forgeable_fields = ", ".join(fc)
        is_are = "is" if len(fc) == 1 else "are"
        # Build example
        if any("user-agent" in c for c in fc):
            forgeable_example = "the matching User-Agent header"
        elif any("header" in c for c in fc):
            forgeable_example = "the matching custom header"
        else:
            forgeable_example = "the matching condition"

        # Check for opaque/secret values in the statement (fix #1)
        opaque_note = ""
        opaque_rec = ""
        for a in group:
            for field, value in _extract_exactly_values(a.get("statement_summary", "")):
                if _has_opaque_value(value) == "yes":
                    truncated = value[:30] + "..." if len(value) > 30 else value
                    if lang == "zh":
                        opaque_note = f"- 匹配值 `{truncated}` 存储在 WAF 配置中，任何能读取 Web ACL 配置的人均可获取——泄露即意味着完全绕过 WAF\n"
                        opaque_rec = "- 定期轮换密钥值，并审计 WAF 配置的 IAM 访问权限\n"
                    else:
                        opaque_note = f"- The match value `{truncated}` is stored in the WAF configuration — anyone with read access to the Web ACL can obtain it, and a leaked value means full WAF bypass\n"
                        opaque_rec = "- Periodically rotate the secret value and audit IAM access to WAF configuration\n"
                    break
            if opaque_note:
                break

        md = T["forgeable_allow"].format(
            n="{n}", rule_names=rule_names, rule_line=rule_line,
            stmt_summary=group[0]["statement_summary"],
            forgeable_fields=forgeable_fields, is_are=is_are,
            forgeable_example=forgeable_example,
            dup_note=dup_note, dup_rec=dup_rec,
            opaque_note=opaque_note, opaque_rec=opaque_rec)
        results.append((md, {"severity": "Critical", "title_key": "forgeable_allow",
                             "rules": names, "sections": [1]}))
    return results if results else NOT_APPLICABLE


def _gen_hosting_provider_allow(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("hosting_provider_allow", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    md = T["hosting_provider_allow"].format(
        n="{n}", rule_name=check["rule"], priority=check["priority"])
    return [(md, {"severity": "Critical", "title_key": "hosting_provider_allow",
                  "rules": [check["rule"]], "sections": [7]})]


def _gen_scope_down_too_narrow(summary, pre_checks, flags, T, lang):
    scope_downs = flags.get("scope_downs", [])
    narrow = [s for s in scope_downs
              if s.get("scope_down_summary") == "uri_path EXACTLY '/'"
              and any(g in s.get("rule", "") for g in ("IpReputation", "AnonymousIp"))]
    if not narrow:
        # Check if IP reputation groups exist but have no scope-down
        return NOT_APPLICABLE
    rule_line = " and ".join(f"{s['rule']} (priority {s['priority']})" for s in narrow)
    md = T["scope_down_too_narrow"].format(n="{n}", rule_line=rule_line)
    return [(md, {"severity": "Medium", "title_key": "scope_down_too_narrow",
                  "rules": [s["rule"] for s in narrow], "sections": [2]})]


def _gen_challenge_on_post_api(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("challenge_on_post_api", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    rule_line = ", ".join(f"{r['name']} (priority {r['priority']})" for r in rules)
    # Check for duplicates
    dup_rec = ""
    names = [r["name"] for r in rules]
    md = T["challenge_on_post_api"].format(n="{n}", rule_line=rule_line, dup_rec=dup_rec)
    return [(md, {"severity": "Medium", "title_key": "challenge_on_post_api",
                  "rules": names, "sections": [4]})]


def _gen_missing_baseline(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    present = set()
    for r in rules:
        mg = r.get("managed")
        if mg:
            gn = mg.get("group_name", "")
            if gn in MANAGED_BASELINE_GROUPS:
                present.add(MANAGED_BASELINE_GROUPS[gn])
    missing = {"CRS", "KnownBadInputs"} - present
    if not missing:
        return NOT_APPLICABLE
    missing_names = " and ".join(sorted(missing))
    details = []
    recs = []
    if "CRS" in missing:
        if lang == "zh":
            details.append("CRS 提供 OWASP Top 10 防护（SQLi、XSS 等），是大多数 Web 应用的基础防护层")
            recs.append("- 评估是否需要添加 CRS；如果添加，务必将 `SizeRestrictions_Body` 覆盖为 Count，避免对大 payload 的 API 端点产生误报（实现步骤见附录 F）")
        else:
            details.append("CRS provides OWASP Top 10 protection (SQLi, XSS, etc.) — the baseline protection layer for most web applications")
            recs.append("- Evaluate whether to add CRS; if adding, override `SizeRestrictions_Body` to Count to avoid false positives on large-payload API endpoints (see Appendix F)")
    if "KnownBadInputs" in missing:
        if lang == "zh":
            details.append("KnownBadInputsRuleSet 防护 Log4Shell（CVE-2021-44228）、Java 反序列化漏洞等已知恶意输入模式，WCU 消耗低、误报率低")
            recs.append("- 添加 AWSManagedRulesKnownBadInputsRuleSet（WCU 消耗低，建议优先添加）")
        else:
            details.append("KnownBadInputsRuleSet protects against Log4Shell (CVE-2021-44228), Java deserialization exploits, and other known malicious input patterns — low WCU cost, low false positive rate")
            recs.append("- Add AWSManagedRulesKnownBadInputsRuleSet (low WCU cost, recommended as priority)")
    cap = summary.get("web_acl", {}).get("capacity")
    if cap is not None:
        if lang == "zh":
            recs.append(f"- 添加前请在 AWS 控制台确认剩余 WCU 容量（当前已使用 {cap} WCU，上限 5000）")
        else:
            recs.append(f"- Verify remaining WCU capacity in AWS Console before adding (current: {cap} / 5000)")
    md = T["missing_baseline"].format(
        n="{n}", missing_names=missing_names,
        missing_detail="\n- ".join(details), missing_rec="\n".join(recs))
    return [(md, {"severity": "Medium", "title_key": "missing_baseline",
                  "rules": [], "sections": [9]})]


def _gen_token_domain(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("token_domain", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    domains = check.get("domains", [])
    redundant = check.get("redundant", [])
    if not redundant:
        return NOT_APPLICABLE
    # Find apex
    apex = [d for d in domains if len(d.split(".")) == 2]
    apex_str = apex[0] if apex else domains[0]
    domain_list = ", ".join(f"`{d}`" for d in domains)
    md = T["token_domain"].format(n="{n}", domain_list=domain_list, apex=apex_str)
    return [(md, {"severity": "Low", "title_key": "token_domain",
                  "rules": [], "sections": [11]})]


def _gen_no_logging(summary, pre_checks, flags, T, lang):
    # WAF JSON exports typically don't include logging config.
    # We flag this as Awareness unconditionally — the LLM sanity check can override.
    md = T["no_logging"].format(n="{n}")
    return [(md, {"severity": "Awareness", "title_key": "no_logging",
                  "rules": [], "sections": [13]})]


def _gen_default_action_redundancy(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("default_action_redundancy", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rule_name = check["rule"]
    priority = check["priority"]
    # Find statement summary
    stmt = ""
    for r in summary.get("rules", []):
        if r["name"] == rule_name:
            stmt = r.get("statement", {}).get("summary", "")
            break
    md = T["default_action_redundancy"].format(
        n="{n}", rule_name=rule_name, priority=priority, stmt_summary=stmt)
    return [(md, {"severity": "Low", "title_key": "default_action_redundancy",
                  "rules": [rule_name], "sections": [15]})]


def _gen_count_without_labels(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("count_without_labels", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    rules = check.get("rules", [])
    names = [r["name"] for r in rules]
    rule_names = " / ".join(names)
    rule_line = ", ".join(f"{r['name']} (priority {r['priority']})" for r in rules)
    # Check for duplicates within the group
    dup_note = ""
    dup_rec = ""
    if len(rules) > 1:
        if lang == "zh":
            dup_note = f"- {len(rules)} 条规则可能逻辑相同——请检查是否存在重复\n"
            dup_rec = "- 如果逻辑相同，删除重复规则\n"
        else:
            dup_note = f"- {len(rules)} rules may have identical logic — check if duplicates exist\n"
            dup_rec = "- Remove duplicate rules if logic is identical\n"
    md = T["count_without_labels"].format(
        n="{n}", rule_names=rule_names, rule_line=rule_line,
        dup_note=dup_note, dup_rec=dup_rec)
    return [(md, {"severity": "Awareness", "title_key": "count_without_labels",
                  "rules": names, "sections": [17]})]


def _gen_challenge_all_during_event(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    amr = None
    for r in rules:
        mg = r.get("managed")
        if mg and "AntiDDoS" in mg.get("group_name", ""):
            amr = r
            break
    if not amr:
        return NOT_APPLICABLE
    overrides = amr.get("managed", {}).get("overrides", [])
    disabled = any(o.get("rule_name") == "ChallengeAllDuringEvent" and o.get("action") == "count"
                   for o in overrides)
    if not disabled:
        return NOT_APPLICABLE
    cfg = amr.get("managed", {}).get("config", {})
    block_sens = cfg.get("sensitivity_to_block", "unknown")
    sens_map = {"LOW": ("high-suspicion", "medium and low-suspicion"),
                "MEDIUM": ("medium and high-suspicion", "low-suspicion"),
                "HIGH": ("all suspicion levels of", "no")}
    block_desc, remaining_desc = sens_map.get(block_sens, ("some", "remaining"))
    md = T["challenge_all_during_event"].format(
        n="{n}", rule_name=amr["name"], priority=amr["priority"],
        block_sens=block_sens, block_desc=block_desc, remaining_desc=remaining_desc)
    return [(md, {"severity": "Medium", "title_key": "challenge_all_during_event",
                  "rules": [amr["name"]], "sections": [3]})]


def _gen_unanchored_exempt_regex(summary, pre_checks, flags, T, lang):
    regex_flags = flags.get("exempt_regex_branches", [])
    if not regex_flags:
        return NOT_APPLICABLE
    results = []
    for rf in regex_flags:
        unanchored = [b for b in rf.get("branches", [])
                      if not b.get("anchored_start") and not b.get("anchored_end")]
        if not unanchored:
            continue
        unanchored_list = ", ".join(f"`{b['pattern']}`" for b in unanchored)
        examples = ", ".join(f"`/admin{b['pattern'].replace(chr(92), '')}/export`"
                             for b in unanchored[:2])
        anchored = "`" + "|".join(
            f"^{b['pattern']}" if not b.get("anchored_start") else b["pattern"]
            for b in rf["branches"]) + "`"
        md = T["unanchored_exempt_regex"].format(
            n="{n}", rule_name=rf["rule"], priority=rf["priority"],
            regex=rf["full_regex"], unanchored_list=unanchored_list,
            examples=examples, anchored_suggestion=anchored)
        results.append((md, {"severity": "Medium", "title_key": "unanchored_exempt_regex",
                             "rules": [rf["rule"]], "sections": [3]}))
    return results if results else NOT_APPLICABLE


def _gen_missing_crawler_labeling(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    has_amr = any("AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules)
    if not has_amr:
        return NOT_APPLICABLE
    # Check for crawler labeling rule
    for r in rules:
        labels = r.get("rule_labels", [])
        for lbl in labels:
            if any(lbl.startswith(p) for p in CRAWLER_LABEL_PATTERNS):
                return NOT_APPLICABLE
        # Structural: Count + asn_match + produces any label
        if (r.get("action") == "count" and
                "asn_match" in r.get("statement", {}).get("leaf_types", []) and
                labels):
            return NOT_APPLICABLE
    md = T["missing_crawler_labeling"].format(n="{n}")
    return [(md, {"severity": "Medium", "title_key": "missing_crawler_labeling",
                  "rules": [], "sections": [3]})]


def _gen_bot_control_search_allow(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    for r in rules:
        mg = r.get("managed")
        if not mg or "BotControl" not in mg.get("group_name", ""):
            continue
        search_allows = [o for o in mg.get("overrides", [])
                         if o.get("action") == "allow" and
                         o.get("rule_name", "") in ("CategorySearchEngine", "CategorySeo")]
        if search_allows:
            override_names = " / ".join(o["rule_name"] for o in search_allows)
            md = T["bot_control_search_allow"].format(
                n="{n}", rule_name=r["name"], priority=r["priority"],
                override_names=override_names)
            return [(md, {"severity": "Low", "title_key": "bot_control_search_allow",
                          "rules": [r["name"]], "sections": [5]})]
    return NOT_APPLICABLE


def _gen_duplicate_rules(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    # Group rate-based rules
    rate_groups = defaultdict(list)
    for r in rules:
        if r.get("type") != "rate_based":
            continue
        rb = r.get("rate_based", {})
        sd = r.get("scope_down", {})
        sd_summary = sd.get("summary", "") if sd else ""
        key = (r["action"], rb.get("limit"), rb.get("evaluation_window_sec"), sd_summary)
        rate_groups[key].append(r)

    results = []
    all_dup_names = []
    all_pair_lines = []
    for key, group in rate_groups.items():
        if len(group) < 2:
            continue
        sorted_g = sorted(group, key=lambda x: x["priority"])
        for i in range(0, len(sorted_g) - 1, 2):
            all_pair_lines.append(f"{sorted_g[i]['name']} (P{sorted_g[i]['priority']}) / {sorted_g[i+1]['name']} (P{sorted_g[i+1]['priority']})")
        all_dup_names.extend(r["name"] for r in group)

    if not all_pair_lines:
        return NOT_APPLICABLE

    rule_line = "; ".join(all_pair_lines)
    pair_count = len(all_pair_lines)
    if lang == "zh":
        dup_problem = "对于 scope-down 重叠的速率限制规则，只有阈值最低的规则会对重叠流量生效——阈值更高的重复规则没有额外效果"
        match_desc = "scope-down、limit 和 window"
        rule_type = "速率限制"
    else:
        dup_problem = "For rate-based rules with overlapping scope-downs, only the lowest-threshold rule triggers for overlapping traffic — higher-threshold duplicates have no additional effect"
        match_desc = "scope-down, limit, and window"
        rule_type = "rate-limit "
    md = T["duplicate_rules"].format(
        n="{n}", rule_type=rule_type, rule_line=rule_line,
        pair_count=pair_count, match_desc=match_desc,
        dup_problem=dup_problem)
    results.append((md, {"severity": "Awareness", "title_key": "duplicate_rules",
                         "rules": all_dup_names, "sections": [6]}))
    return results


def _gen_managed_versions(summary, pre_checks, flags, T, lang):
    check = pre_checks.get("managed_versions", {})
    if check.get("status") != "FAIL":
        return NOT_APPLICABLE
    results = []
    for detail_str in check.get("details", []):
        # Parse "rule_name: GroupName version X < Y (recommend upgrading)"
        parts = detail_str.split(":", 1)
        rule_name = parts[0].strip() if parts else "unknown"
        # Find rule
        priority = 0
        current_version = "unknown"
        for r in summary.get("rules", []):
            if r["name"] == rule_name:
                priority = r["priority"]
                current_version = r.get("managed", {}).get("version", "unknown")
                break
        if "BotControl" in detail_str:
            version_problem = "BotControlRuleSet Version_5.0 Common level can identify close to 700 bot types (based on UA and IP), far more than earlier versions"
            version_rec = "Upgrade BotControlRuleSet to Version_5.0"
            detail_en = f"Bot Control version outdated ({current_version}), recommend upgrading to 5.0"
            version_problem_zh = "BotControlRuleSet Version_5.0 的 Common level 可识别近 700 种 Bot 类型（基于 UA 和 IP），远超早期版本"
            version_rec_zh = "将 BotControlRuleSet 升级至 Version_5.0"
            detail_zh = f"Bot Control 版本过旧（{current_version}），建议升级至 5.0"
        elif "SQLi" in detail_str:
            version_problem = "SQLiRuleSet version 2.0 has significantly higher SQLi detection coverage than 1.0"
            version_rec = "Upgrade SQLiRuleSet to version 2.0"
            detail_en = f"SQLiRuleSet version outdated ({current_version}), recommend upgrading to 2.0"
            version_problem_zh = "SQLiRuleSet 2.0 版本的 SQLi 检测覆盖率显著高于 1.0"
            version_rec_zh = "将 SQLiRuleSet 升级至 2.0 版本"
            detail_zh = f"SQLiRuleSet 版本过旧（{current_version}），建议升级至 2.0"
        else:
            continue
        # Select language-appropriate strings
        if lang == "zh":
            detail, vp, vr = detail_zh, version_problem_zh, version_rec_zh
        else:
            detail, vp, vr = detail_en, version_problem, version_rec
        md = T["managed_versions"].format(
            n="{n}", detail=detail, rule_name=rule_name, priority=priority,
            current_version=current_version, version_problem=vp,
            version_rec=vr)
        results.append((md, {"severity": "Low", "title_key": "managed_versions",
                             "rules": [rule_name], "sections": [12]}))
    return results if results else NOT_APPLICABLE


def _gen_missing_always_on_challenge(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    has_amr = any("AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules)
    if not has_amr:
        return NOT_APPLICABLE
    # Check for always-on challenge pattern
    # Pattern 1: Challenge rule consuming a label
    label_producers = {}
    for r in rules:
        for lbl in r.get("rule_labels", []):
            label_producers[lbl] = r["name"]
    for r in rules:
        if r.get("action") != "challenge" or r.get("type") != "custom":
            continue
        stmt = r.get("statement", {}).get("summary", "")
        # Check if it references a label
        label_refs = re.findall(r"label_match '([^']+)'", stmt)
        for lref in label_refs:
            if lref in label_producers:
                return NOT_APPLICABLE
    # Pattern 2: Challenge on landing page URIs directly
    landing_patterns = ("/", "/login", "/signup", "/register", "/index", "/home")
    for r in rules:
        if r.get("action") != "challenge" or r.get("type") != "custom":
            continue
        stmt = r.get("statement", {}).get("summary", "")
        if any(f"'{p}'" in stmt for p in landing_patterns):
            return NOT_APPLICABLE
    md = T["missing_always_on_challenge"].format(n="{n}")
    return [(md, {"severity": "Medium", "title_key": "missing_always_on_challenge",
                  "rules": [], "sections": [16]})]


def _gen_priority_order(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    if len(rules) < 2:
        return NOT_APPLICABLE
    # Classify each rule
    classified = [(r, _classify_rule_type(r)) for r in rules]
    order_index = {cat: i for i, (cat, _) in enumerate(RECOMMENDED_ORDER)}

    violations = []
    seen_cat_pairs = {}  # (cat1, cat2) -> (r1_name, r2_name) representative
    for i, (r1, cat1) in enumerate(classified):
        if cat1 not in order_index:
            continue
        for j in range(i + 1, len(classified)):
            r2, cat2 = classified[j]
            if cat2 not in order_index:
                continue
            if order_index[cat1] > order_index[cat2]:
                pair = (cat1, cat2)
                if pair not in seen_cat_pairs:
                    seen_cat_pairs[pair] = (r1, r2)

    for (cat1, cat2), (r1, r2) in seen_cat_pairs.items():
        desc1 = dict(RECOMMENDED_ORDER).get(cat1, cat1)
        desc2 = dict(RECOMMENDED_ORDER).get(cat2, cat2)
        violations.append(
            f"- {r1['name']} (P{r1['priority']}, {desc1}) is before "
            f"{r2['name']} (P{r2['priority']}, {desc2}), but recommended order is reversed")

    if not violations:
        return NOT_APPLICABLE
    if len(violations) > 8:
        violations = violations[:8]
        violations.append("- ... and more ordering issues")

    problems = "\n".join(violations)
    if lang == "zh":
        summary_text = f"发现 {len(violations)} 处顺序问题"
    else:
        summary_text = f"{len(violations)} ordering violations found"
    current_state = ", ".join(f"{r['name']} (P{r['priority']})" for r in rules[:5])
    if len(rules) > 5:
        current_state += f" ... ({len(rules)} rules total)"
    md = T["priority_order"].format(
        n="{n}", summary=summary_text, current_state=current_state, problems=problems)
    all_rules = [r["name"] for r in rules]
    return [(md, {"severity": "Medium", "title_key": "priority_order",
                  "rules": all_rules[:10], "sections": [18]})]


def _gen_opaque_search_string(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    # Skip rules already flagged as forgeable Allow (they get their own Critical finding)
    forgeable_allow_names = set()
    for a in flags.get("allow_rules", []):
        if a.get("all_forgeable") and a.get("blast_radius") == "global":
            forgeable_allow_names.add(a["name"])
    results = []
    seen_values = set()
    for r in rules:
        if r.get("type") != "custom":
            continue
        if r["name"] in forgeable_allow_names:
            continue
        stmt_summary = r.get("statement", {}).get("summary", "")
        for field, value in _extract_exactly_values(stmt_summary):
            if value in seen_values:
                continue
            opacity = _has_opaque_value(value)
            if opacity == "no":
                continue
            if opacity == "maybe":
                return AMBIGUOUS
            seen_values.add(value)
            is_allow = r.get("action") == "allow"
            if is_allow:
                risk_note = "Since this rule's action is Allow, a leaked value means full WAF bypass for anyone who knows it"
                rec_note = "If this is a shared secret for probe/monitoring access, switch to an unforgeable condition (IP Set or WAF Token)"
            else:
                risk_note = "This value may be a shared secret or redacted content"
                rec_note = "Verify whether this value is a secret that should be protected from exposure"
            md = T["opaque_search_string"].format(
                n="{n}", rule_name=r["name"], priority=r["priority"],
                stmt_summary=stmt_summary[:100], value=value[:30] + "..." if len(value) > 30 else value,
                risk_note=risk_note, rec_note=rec_note)
            results.append((md, {"severity": "Awareness", "title_key": "opaque_search_string",
                                 "rules": [r["name"]], "sections": [14]}))
    return results if results else NOT_APPLICABLE


def _gen_managed_allow_override(summary, pre_checks, flags, T, lang):
    rules = summary.get("rules", [])
    handled_rules = {"HostingProviderIPList", "CategorySearchEngine", "CategorySeo"}
    results = []
    for r in rules:
        mg = r.get("managed")
        if not mg:
            continue
        for o in mg.get("overrides", []):
            if o.get("action") == "allow" and o.get("rule_name", "") not in handled_rules:
                override_detail = f"`{o['rule_name']}` overridden to Allow"
                md = T["managed_allow_override"].format(
                    n="{n}", rule_name=r["name"], priority=r["priority"],
                    override_detail=override_detail)
                results.append((md, {"severity": "Awareness",
                                     "title_key": "managed_allow_override",
                                     "rules": [r["name"]], "sections": [1]}))
    return results if results else NOT_APPLICABLE


# ── Main ───────────────────────────────────────────────────────────────────

ALL_GENERATORS = [
    # (function, covered_sections, fully_covers_sections)
    (_gen_forgeable_allow, [1], True),
    (_gen_managed_allow_override, [1], True),
    (_gen_scope_down_too_narrow, [2], True),
    (_gen_challenge_all_during_event, [3], True),
    (_gen_unanchored_exempt_regex, [3], True),
    (_gen_missing_crawler_labeling, [3], True),
    (_gen_challenge_on_post_api, [4], True),
    (_gen_bot_control_search_allow, [5], False),  # Section 5 is always-LLM
    (_gen_duplicate_rules, [6], True),
    (_gen_hosting_provider_allow, [7], True),
    (_gen_missing_baseline, [9], True),
    (_gen_token_domain, [11], True),
    (_gen_managed_versions, [12], True),
    (_gen_no_logging, [13], True),
    (_gen_opaque_search_string, [14], True),
    (_gen_default_action_redundancy, [15], True),
    (_gen_missing_always_on_challenge, [16], True),
    (_gen_count_without_labels, [17], True),  # Covers 17a only; 17 is always-LLM
    (_gen_priority_order, [18], True),
]


def main():
    if len(sys.argv) < 2:
        fatal("Usage: waf-generate-findings.py <output_dir> [--lang en|zh]")

    output_dir = sys.argv[1]
    lang = "en"
    if "--lang" in sys.argv:
        idx = sys.argv.index("--lang")
        if idx + 1 < len(sys.argv):
            lang = sys.argv[idx + 1]
    if lang not in ("en", "zh"):
        lang = "en"

    T = TEMPLATES_EN if lang == "en" else TEMPLATES_ZH

    summary_path = os.path.join(output_dir, "waf-summary.json")
    prechecks_path = os.path.join(output_dir, "pre-checks.json")

    if not os.path.isfile(summary_path):
        fatal(f"waf-summary.json not found in {output_dir}")
    if not os.path.isfile(prechecks_path):
        fatal(f"pre-checks.json not found in {output_dir}")

    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    pre_checks_data = json.loads(Path(prechecks_path).read_text(encoding="utf-8"))
    pre_checks = pre_checks_data.get("pre_checks", {})
    flags = pre_checks_data.get("flags", {})

    # Run all generators
    all_findings = []  # (md_template, metadata)
    section_outcomes = defaultdict(list)  # section -> list of (outcome_type, fully_covers)

    for gen_func, sections, fully_covers in ALL_GENERATORS:
        result = gen_func(summary, pre_checks, flags, T, lang)
        if result == NOT_APPLICABLE:
            for s in sections:
                section_outcomes[s].append(("not_applicable", fully_covers))
        elif result == AMBIGUOUS:
            for s in sections:
                section_outcomes[s].append(("ambiguous", fully_covers))
        else:
            # List of (md, metadata)
            for md, meta in result:
                all_findings.append((md, meta))
            for s in sections:
                section_outcomes[s].append(("finding", fully_covers))

    # Sort by severity then by first rule priority
    def sort_key(item):
        md, meta = item
        sev = SEVERITY_ORDER.get(meta["severity"], 99)
        # Get min priority from rules
        min_pri = 999
        for r in summary.get("rules", []):
            if r["name"] in meta.get("rules", []):
                min_pri = min(min_pri, r["priority"])
        return (sev, min_pri)

    all_findings.sort(key=sort_key)

    # Assign issue numbers
    findings_md = []
    scripted_issues = []
    issue_rule_mapping = {}

    for i, (md_template, meta) in enumerate(all_findings, 1):
        md = md_template.replace("{n}", str(i))
        findings_md.append(md)
        # Extract title from first line
        first_line = md.strip().split("\n")[0]
        title = first_line.split("): ", 1)[1] if "): " in first_line else first_line
        scripted_issues.append({
            "number": i,
            "severity": meta["severity"],
            "title": title.strip(),
            "rules": meta.get("rules", []),
            "checklist_sections": meta.get("sections", []),
        })
        for rule_name in meta.get("rules", []):
            if rule_name in issue_rule_mapping:
                issue_rule_mapping[rule_name] += f", #{i}"
            else:
                issue_rule_mapping[rule_name] = f"⚠️ Issue #{i}"

    # Compute llm_sections
    llm_sections = sorted(ALWAYS_LLM_SECTIONS)
    for s in range(1, 19):
        if s in ALWAYS_LLM_SECTIONS or s in APPENDIX_ONLY_SECTIONS:
            continue
        outcomes = section_outcomes.get(s, [])
        if not outcomes:
            # No generator covers this section — add to LLM
            llm_sections.append(s)
            continue
        # Check if any AMBIGUOUS from a fully-covering generator
        if any(otype == "ambiguous" and fc for otype, fc in outcomes):
            llm_sections.append(s)
            continue
        # Check if all fully-covering generators returned finding or not_applicable
        fully_covering = [(otype, fc) for otype, fc in outcomes if fc]
        if not fully_covering:
            # Only partial generators — section needs LLM
            llm_sections.append(s)
    llm_sections = sorted(set(llm_sections))

    # Compute llm_context
    rules = summary.get("rules", [])
    llm_context = {
        "ua_allow_found": any(
            "user-agent" in " ".join(a.get("forgeable_conditions", []))
            for a in flags.get("allow_rules", [])),
        "has_antiddos_amr": any(
            "AntiDDoS" in r.get("managed", {}).get("group_name", "") for r in rules),
        "has_bot_control": any(
            "BotControl" in r.get("managed", {}).get("group_name", "") for r in rules),
        "has_always_on_challenge": any(
            r.get("action") == "challenge" and r.get("type") == "custom" and
            "label_match" in r.get("statement", {}).get("summary", "")
            for r in rules),
        "has_crawler_labeling_rule": any(
            any(lbl.startswith(p) for p in CRAWLER_LABEL_PATTERNS)
            for r in rules for lbl in r.get("rule_labels", [])),
    }

    next_issue_number = len(all_findings) + 1

    # Write scripted-findings.md
    findings_path = os.path.join(output_dir, "scripted-findings.md")
    Path(findings_path).write_text("".join(findings_md), encoding="utf-8")

    # Write findings-metadata.json
    metadata = {
        "scripted_count": len(all_findings),
        "scripted_issues": scripted_issues,
        "issue_rule_mapping": issue_rule_mapping,
        "llm_sections": llm_sections,
        "llm_context": llm_context,
        "next_issue_number": next_issue_number,
        "lang": lang,
    }
    meta_path = os.path.join(output_dir, "findings-metadata.json")
    Path(meta_path).write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Generated {len(all_findings)} scripted findings ({lang}), "
          f"LLM sections: {llm_sections}", file=sys.stderr)
    print("---RESULT---")
    print("SPEC: 1")
    print("STATUS: OK")
    print(f"OUTPUT_FILE: {findings_path}")
    print(f"SCRIPTED_COUNT: {len(all_findings)}")
    print(f"LLM_SECTIONS: {','.join(str(s) for s in llm_sections)}")
    print(f"NEXT_ISSUE_NUMBER: {next_issue_number}")


if __name__ == "__main__":
    main()
