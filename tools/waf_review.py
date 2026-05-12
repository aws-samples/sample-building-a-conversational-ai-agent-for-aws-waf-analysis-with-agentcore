# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""WAF Rule Review tool — deterministic checks based on checklist."""

from strands import tool
from tools.aws_session import get_client
from tools.session_state import get_capabilities, get_host_profiles

# Recommended priority order (lower index = should be earlier)
PRIORITY_ORDER = [
    "ip_whitelist",        # 0
    "ip_blacklist",        # 1
    "count_label",         # 2 (label producers)
    "crawler_label",       # 3
    "antiddos_amr",        # 4
    "ip_reputation",       # 5
    "anonymous_ip",        # 6
    "rate_based",          # 7
    "always_on_challenge", # 8
    "custom_block",        # 9
    "crs_knownbad",        # 10 (application layer)
    "bot_control",         # 11 (per-request pricing, last)
]

# Forgeable conditions
FORGEABLE_FIELDS = {"SingleHeader", "SingleQueryArgument", "Cookies", "QueryString", "Body", "JsonBody"}
UNFORGEABLE_FIELDS = {"IPSetReferenceStatement", "AsnMatchStatement"}

# Known managed rule groups
MANAGED_GROUPS = {
    "AWSManagedRulesCommonRuleSet": "crs_knownbad",
    "AWSManagedRulesKnownBadInputsRuleSet": "crs_knownbad",
    "AWSManagedRulesAmazonIpReputationList": "ip_reputation",
    "AWSManagedRulesAnonymousIpList": "anonymous_ip",
    "AWSManagedRulesBotControlRuleSet": "bot_control",
    "AWSManagedRulesAntiDDoSRuleSet": "antiddos_amr",
    "AWSManagedRulesATPRuleSet": "bot_control",
    "AWSManagedRulesACFPRuleSet": "bot_control",
}


@tool
def review_waf_rules(webacl_name: str, scope: str = "CLOUDFRONT", region: str = "us-east-1") -> str:
    """Review WAF WebACL rules for security issues, misconfigurations, and optimization opportunities.

    Performs deterministic checks based on AWS WAF best practices checklist:
    - Allow rules on forgeable conditions
    - Scope-down issues
    - AntiDDoS AMR configuration
    - Challenge on non-browser traffic
    - Bot Control configuration
    - Rate-based rule issues
    - IP reputation configuration
    - Missing baseline protections
    - Rule priority ordering
    - Redundant rules

    Args:
        webacl_name: Name of the WebACL to review.
        scope: AWS WAF scope — "CLOUDFRONT" or "REGIONAL".
        region: AWS region.

    Returns:
        Structured findings with severity, rule, problem, and recommendation.
    """
    if scope == "CLOUDFRONT":
        region = "us-east-1"

    client = get_client("wafv2", region_name=region)
    acls = client.list_web_acls(Scope=scope).get("WebACLs", [])
    match = next((a for a in acls if a["Name"] == webacl_name), None)
    if not match:
        return f"WebACL '{webacl_name}' not found."

    resp = client.get_web_acl(Name=webacl_name, Scope=scope, Id=match["Id"])
    webacl = resp["WebACL"]
    rules = sorted(webacl.get("Rules", []), key=lambda r: r["Priority"])
    default_action = list(webacl["DefaultAction"].keys())[0]

    findings = []

    # Run all checks
    _check_allow_rules(rules, findings)
    _check_scope_down(rules, findings)
    _check_antiddos_amr(rules, findings)
    _check_challenge_applicability(rules, findings)
    _check_bot_control(rules, findings)
    _check_rate_based(rules, findings)
    _check_ip_reputation(rules, findings)
    _check_missing_baselines(rules, findings)
    _check_landing_page_challenge(rules, findings)
    _check_default_action(rules, default_action, findings)
    _check_count_without_labels(rules, findings)
    _check_priority_order(rules, findings)
    _check_managed_versions(rules, findings)

    # Format output
    if not findings:
        return "No issues found. WebACL configuration looks good."

    lines = [f"## WAF Rule Review: {webacl_name}", f"Found {len(findings)} issue(s):\n"]

    # Sort by severity
    severity_order = {"Critical": 0, "Medium": 1, "Low": 2, "Awareness": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    for i, f in enumerate(findings, 1):
        lines.append(f"### Issue {i} ({f['severity']}): {f['title']}")
        lines.append(f"**Rule**: {f['rule']}")
        lines.append(f"**Problem**: {f['problem']}")
        lines.append(f"**Recommendation**: {f['recommendation']}")
        lines.append("")

    lines.append("---\nCall ask_user() tool to ask:")
    lines.append("- Which findings are most urgent to address?")
    lines.append("- Are there native apps or APIs sharing this WebACL? (affects Challenge recommendations)")
    lines.append("- For COUNT→Block decisions: offer to run count_rule_top_ips to validate traffic before switching")

    return "\n".join(lines)


def _add(findings, severity, title, rule, problem, recommendation):
    findings.append({"severity": severity, "title": title, "rule": rule, "problem": problem, "recommendation": recommendation})


def _get_mrg(rule):
    """Extract ManagedRuleGroupStatement from a rule."""
    stmt = rule.get("Statement", {})
    return stmt.get("ManagedRuleGroupStatement", {})


def _get_action_str(rule):
    if "Action" in rule:
        return list(rule["Action"].keys())[0]
    if "OverrideAction" in rule:
        return "managed"
    return "?"


def _is_forgeable_statement(stmt):
    """Check if a statement matches on forgeable conditions."""
    if "ByteMatchStatement" in stmt:
        field = stmt["ByteMatchStatement"].get("FieldToMatch", {})
        return any(k in FORGEABLE_FIELDS for k in field.keys())
    if "RegexMatchStatement" in stmt:
        field = stmt["RegexMatchStatement"].get("FieldToMatch", {})
        return any(k in FORGEABLE_FIELDS for k in field.keys())
    if "SizeConstraintStatement" in stmt:
        field = stmt["SizeConstraintStatement"].get("FieldToMatch", {})
        return any(k in FORGEABLE_FIELDS for k in field.keys())
    # And/Or statements — check all sub-statements
    if "AndStatement" in stmt:
        # If ALL conditions are forgeable, the whole thing is forgeable
        return all(_is_forgeable_statement(s) for s in stmt["AndStatement"].get("Statements", []))
    if "OrStatement" in stmt:
        # If ANY condition is forgeable, the whole thing is forgeable
        return any(_is_forgeable_statement(s) for s in stmt["OrStatement"].get("Statements", []))
    return False


# === Check implementations ===

def _check_allow_rules(rules, findings):
    """Section 1: Allow rules audit."""
    for rule in rules:
        action = _get_action_str(rule)
        if action != "Allow":
            continue
        stmt = rule.get("Statement", {})
        if _is_forgeable_statement(stmt):
            _add(findings, "Critical",
                 f"Allow rule '{rule['Name']}' based on forgeable condition",
                 f"{rule['Name']} (priority {rule['Priority']})",
                 "Allow action with forgeable matching condition (header/UA/cookie). Attacker can forge this to bypass all subsequent rules.",
                 "Change to Count+Label, or use unforgeable condition (IP set, AWS WAF token, ASN).")

        # Check managed rule group Allow overrides
        mrg = _get_mrg(rule)
        if mrg:
            for override in mrg.get("RuleActionOverrides", []):
                if "Allow" in override.get("ActionToUse", {}):
                    rule_name = override["Name"]
                    if rule_name == "HostingProviderIPList":
                        _add(findings, "Critical",
                             "HostingProviderIPList overridden to Allow",
                             f"{rule['Name']} (priority {rule['Priority']})",
                             "Allow override lets cloud-hosted attack traffic bypass all subsequent rules.",
                             "Override to Count instead of Allow.")
                    elif rule_name in ("CategorySearchEngine", "CategorySeo"):
                        _add(findings, "Low",
                             f"{rule_name} overridden to Allow",
                             f"{rule['Name']} (priority {rule['Priority']})",
                             "Lets unverified search engine bots bypass subsequent rules. Limited blast radius.",
                             "Remove Allow override. Use crawler labeling rule (ASN+UA) for SEO protection instead.")


def _check_scope_down(rules, findings):
    """Section 2: Scope-down statements."""
    for rule in rules:
        mrg = _get_mrg(rule)
        if not mrg:
            continue
        scope_down = mrg.get("ScopeDownStatement", {})
        if not scope_down:
            continue
        # Check for overly narrow scope-down
        if "ByteMatchStatement" in scope_down:
            bm = scope_down["ByteMatchStatement"]
            field = bm.get("FieldToMatch", {})
            if "UriPath" in field:
                search = bm.get("SearchString", "")
                constraint = bm.get("PositionalConstraint", "")
                if constraint == "EXACTLY" and search in ("b'/'", "/", "b'/'"):
                    _add(findings, "Medium",
                         f"Scope-down too narrow on '{rule['Name']}'",
                         f"{rule['Name']} (priority {rule['Priority']})",
                         f"Scope-down URI EXACTLY '/' means rule group only checks homepage. All other paths unprotected.",
                         "Remove scope-down or expand to cover all critical paths.")


def _check_antiddos_amr(rules, findings):
    """Section 3: AntiDDoS AMR configuration."""
    amr_found = False
    crawler_label_found = False
    crawler_priority = 999

    for rule in rules:
        # Check for crawler labeling rule
        labels = rule.get("RuleLabels", [])
        for label in labels:
            if "crawler" in label.get("Name", "").lower():
                crawler_label_found = True
                crawler_priority = rule["Priority"]

    for rule in rules:
        mrg = _get_mrg(rule)
        if mrg.get("Name") != "AWSManagedRulesAntiDDoSRuleSet":
            continue
        amr_found = True

        # Check ChallengeAllDuringEvent override
        for override in mrg.get("RuleActionOverrides", []):
            if override.get("Name") == "ChallengeAllDuringEvent":
                if "Count" in override.get("ActionToUse", {}):
                    _add(findings, "Medium",
                         "ChallengeAllDuringEvent overridden to Count",
                         f"{rule['Name']} (priority {rule['Priority']})",
                         "Core DDoS soft-mitigation disabled. During DDoS events, medium/low-suspicion traffic won't be challenged.",
                         "Enable ChallengeAllDuringEvent (remove Count override), or use dual AMR instance pattern for mixed browser/API traffic.")

        # Check exempt URI regex anchoring
        configs = mrg.get("ManagedRuleGroupConfigs", [])
        for cfg in configs:
            amr_cfg = cfg.get("AWSManagedRulesAntiDDoSRuleSet", {})
            challenge_cfg = amr_cfg.get("ClientSideActionConfig", {}).get("Challenge", {})
            for exempt in challenge_cfg.get("ExemptUriRegularExpressions", []):
                regex = exempt.get("RegexString", "")
                # Check for unanchored API paths
                parts = regex.split("|")
                unanchored = [p for p in parts if p.startswith("\\/") and not p.startswith("^\\/") and not p.startswith("\\.(")]
                if unanchored:
                    _add(findings, "Medium",
                         "AMR exempt URI regex has unanchored paths",
                         f"{rule['Name']} (priority {rule['Priority']})",
                         f"Unanchored patterns ({', '.join(unanchored[:3])}) are 'contains' matches. Attackers can bypass via paths containing these keywords.",
                         "Add ^ anchor to API path branches in the regex.")

        # Check crawler labeling
        if not crawler_label_found:
            _add(findings, "Medium",
                 "No crawler labeling rule before AntiDDoS AMR",
                 "N/A (missing rule)",
                 "During DDoS events, ChallengeAllDuringEvent will challenge search engine crawlers, damaging SEO.",
                 "Add ASN+UA crawler labeling rule before AMR. Exclude crawler label from AMR scope-down.")
        elif crawler_priority > rule["Priority"]:
            _add(findings, "Medium",
                 "Crawler labeling rule is after AntiDDoS AMR",
                 f"label rule at P{crawler_priority}, AMR at P{rule['Priority']}",
                 "Crawler label not available when AMR evaluates. Crawlers will be challenged during DDoS events.",
                 "Move crawler labeling rule before AntiDDoS AMR.")


def _check_challenge_applicability(rules, findings):
    """Section 4: Challenge action on non-browser traffic."""
    for rule in rules:
        action = _get_action_str(rule)
        if action not in ("Challenge", "Captcha"):
            continue
        # Check if rule targets API/POST paths
        stmt = rule.get("Statement", {})
        # Simple heuristic: if rule name contains 'api' or 'payment' or 'post'
        name_lower = rule["Name"].lower()
        if any(kw in name_lower for kw in ("api", "payment", "post")):
            _add(findings, "Medium",
                 f"Challenge on likely API/POST path: '{rule['Name']}'",
                 f"{rule['Name']} (priority {rule['Priority']})",
                 "Challenge only works for browser GET text/html. API/POST/native app requests cannot complete Challenge = effectively Block.",
                 "Use rate-based rule for API abuse prevention, or apply Challenge on the corresponding GET landing page instead.")


def _check_bot_control(rules, findings):
    """Section 5: Bot Control configuration."""
    for rule in rules:
        mrg = _get_mrg(rule)
        if mrg.get("Name") != "AWSManagedRulesBotControlRuleSet":
            continue

        configs = mrg.get("ManagedRuleGroupConfigs", [])
        level = "common"
        for cfg in configs:
            bc_cfg = cfg.get("AWSManagedRulesBotControlRuleSet", {})
            if bc_cfg.get("InspectionLevel") == "TARGETED":
                level = "targeted"

        overrides = {o["Name"]: list(o.get("ActionToUse", {}).keys())[0] for o in mrg.get("RuleActionOverrides", [])}

        # Check SignalNonBrowserUserAgent and CategoryHttpLibrary
        # Only flag if WebACL likely has non-browser traffic (API/native app)
        # If pure frontend, blocking non-browser UA is correct behavior
        host_profiles = get_host_profiles()
        has_backend = any("BACKEND" in str(v) or "MIXED" in str(v) for v in host_profiles.values()) if host_profiles else True  # default to flagging if unknown

        if has_backend and "SignalNonBrowserUserAgent" not in overrides:
            _add(findings, "Low",
                 "SignalNonBrowserUserAgent not overridden to Count",
                 f"{rule['Name']} (priority {rule['Priority']})",
                 "Default Block will block legitimate non-browser clients (native apps, API clients, monitoring tools). Only relevant if WebACL protects API/native app traffic.",
                 "Override SignalNonBrowserUserAgent to Count if WebACL has non-browser traffic.")

        if has_backend and "CategoryHttpLibrary" not in overrides:
            _add(findings, "Low",
                 "CategoryHttpLibrary not overridden to Count",
                 f"{rule['Name']} (priority {rule['Priority']})",
                 "Default Block will block legitimate HTTP libraries used by native apps and API clients. Only relevant if WebACL has non-browser traffic.",
                 "Override CategoryHttpLibrary to Count if WebACL has non-browser traffic.")

        # Check TGT_TokenAbsent override — Count is the DEFAULT and correct
        # Only flag if overridden to Allow (which would suppress the label)
        if "TGT_TokenAbsent" in overrides and overrides["TGT_TokenAbsent"] == "Allow":
            _add(findings, "Critical",
                 "TGT_TokenAbsent overridden to Allow",
                 f"{rule['Name']} (priority {rule['Priority']})",
                 "Allow override suppresses the TGT_TokenAbsent label. Downstream rules and VolumetricIpTokenAbsent lose visibility.",
                 "Use Count (default) or Challenge. Never Allow.")

        # Check Allow overrides on category rules
        for name in ("CategorySearchEngine", "CategorySeo"):
            if name in overrides and overrides[name] == "Allow":
                _add(findings, "Low",
                     f"{name} overridden to Allow in Bot Control",
                     f"{rule['Name']} (priority {rule['Priority']})",
                     "Lets unverified search engine bots bypass all subsequent rules.",
                     "Remove Allow override. Use crawler labeling rule for SEO protection.")

        # Check if Bot Control signals are forwarded to origin via Dynamic Label Interpolation
        has_interpolation = _has_label_interpolation(rules)
        if not has_interpolation:
            _add(findings, "Awareness",
                 "Bot Control signals not forwarded to origin",
                 f"{rule['Name']} (priority {rule['Priority']})",
                 "Origin application has no visibility into Bot Control classification (bot category, signals, verified/unverified status). "
                 "Dynamic Label Interpolation can forward these as request headers with a single rule — no per-label rules needed.",
                 "Add a Count rule with LabelMatchStatement (Scope: NAMESPACE, Key: awswaf:managed:aws:bot-control:bot:category:) "
                 "and CustomRequestHandling.InsertHeaders using ${awswaf:managed:aws:bot-control:bot:category:} syntax. "
                 "See https://docs.aws.amazon.com/waf/latest/developerguide/waf-dynamic-label-interpolation.html")



def _has_label_interpolation(rules) -> bool:
    """Check if any rule uses ${...} interpolation in custom headers."""
    for rule in rules:
        action = rule.get("Action", {})
        for act in action.values():
            if not isinstance(act, dict):
                continue
            crh = act.get("CustomRequestHandling", {})
            for header in crh.get("InsertHeaders", []):
                if "${" in header.get("Value", ""):
                    return True
    return False

def _check_rate_based(rules, findings):
    """Section 6: Rate-based rules."""
    for rule in rules:
        stmt = rule.get("Statement", {})
        rbs = stmt.get("RateBasedStatement", {})
        if not rbs:
            continue
        action = _get_action_str(rule)
        if action in ("Challenge", "Captcha"):
            # Check if it has scope-down targeting API paths
            scope_down = rbs.get("ScopeDownStatement", {})
            name_lower = rule["Name"].lower()
            if any(kw in name_lower for kw in ("api", "payment")):
                _add(findings, "Low",
                     f"Rate-based Challenge on API path: '{rule['Name']}'",
                     f"{rule['Name']} (priority {rule['Priority']})",
                     "Challenge action on rate-based rule targeting API paths. Non-browser clients cannot complete Challenge.",
                     "Consider Block action for API rate limiting, or apply Challenge only to browser-facing paths.")


def _check_ip_reputation(rules, findings):
    """Section 7: IP reputation and Anonymous IP."""
    has_ip_rep = False
    has_anon_ip = False

    for rule in rules:
        mrg = _get_mrg(rule)
        group_name = mrg.get("Name", "")

        if group_name == "AWSManagedRulesAmazonIpReputationList":
            has_ip_rep = True
        elif group_name == "AWSManagedRulesAnonymousIpList":
            has_anon_ip = True
            # Check HostingProviderIPList override
            overrides = {o["Name"]: list(o.get("ActionToUse", {}).keys())[0] for o in mrg.get("RuleActionOverrides", [])}
            if "HostingProviderIPList" in overrides and overrides["HostingProviderIPList"] == "Allow":
                _add(findings, "Critical",
                     "HostingProviderIPList overridden to Allow",
                     f"{rule['Name']} (priority {rule['Priority']})",
                     "Cloud-hosted attack traffic bypasses all subsequent rules.",
                     "Override to Count instead of Allow.")


def _check_missing_baselines(rules, findings):
    """Section 9: Missing baseline protections."""
    has_crs = False
    has_known_bad = False
    has_ip_rep = False

    for rule in rules:
        mrg = _get_mrg(rule)
        name = mrg.get("Name", "")
        if name == "AWSManagedRulesCommonRuleSet":
            has_crs = True
        elif name == "AWSManagedRulesKnownBadInputsRuleSet":
            has_known_bad = True
        elif name == "AWSManagedRulesAmazonIpReputationList":
            has_ip_rep = True

    if not has_crs:
        _add(findings, "Medium",
             "Missing CRS (Common Rule Set)",
             "N/A (missing rule)",
             "No OWASP Top 10 protection (SQLi, XSS, etc.). Application layer attacks not blocked.",
             "Add AWSManagedRulesCommonRuleSet. Override SizeRestrictions_BODY to Count to avoid false positives on file uploads.")

    if not has_known_bad:
        _add(findings, "Medium",
             "Missing KnownBadInputsRuleSet",
             "N/A (missing rule)",
             "No protection against Log4Shell (CVE-2021-44228), Java deserialization, and other known malicious input patterns.",
             "Add AWSManagedRulesKnownBadInputsRuleSet. Low WCU, low false positive rate.")

    if not has_ip_rep:
        _add(findings, "Medium",
             "Missing IP Reputation rule group",
             "N/A (missing rule)",
             "No filtering of known malicious IPs (botnets, scanners, DDoS sources).",
             "Add AWSManagedRulesAmazonIpReputationList.")


def _check_landing_page_challenge(rules, findings):
    """Section 16: Always-on Challenge for landing pages."""
    has_always_on = False
    for rule in rules:
        name_lower = rule["Name"].lower()
        action = _get_action_str(rule)
        if "always" in name_lower and "challenge" in name_lower:
            has_always_on = True
        # Also detect pattern: Challenge action + label match on landing-page
        if action == "Challenge":
            stmt = rule.get("Statement", {})
            if "LabelMatchStatement" in str(stmt) and "landing" in str(stmt).lower():
                has_always_on = True

    if not has_always_on:
        # Only flag if DDoS protection is a goal (has AMR or rate-based)
        has_ddos_goal = any(
            _get_mrg(r).get("Name") == "AWSManagedRulesAntiDDoSRuleSet" or
            "RateBasedStatement" in r.get("Statement", {})
            for r in rules
        )
        if has_ddos_goal:
            _add(findings, "Medium",
                 "Missing Always-on Challenge for landing pages",
                 "N/A (missing rule)",
                 "All reactive protections (AMR, rate-based) have detection delay. Always-on Challenge proactively filters non-browser traffic from first request.",
                 "Add two-rule pattern: Count+Label on landing page URIs → Challenge on label (exclude verified crawlers). Set token immunity ≥ 4 hours.")


def _check_default_action(rules, default_action, findings):
    """Section 15: Default action and redundant trailing Allow."""
    if default_action == "Allow":
        # Check for redundant trailing Allow-all rule
        if rules:
            last_rule = rules[-1]
            action = _get_action_str(last_rule)
            if action == "Allow":
                stmt = last_rule.get("Statement", {})
                # Check if it matches all traffic
                if "ByteMatchStatement" in stmt:
                    bm = stmt["ByteMatchStatement"]
                    if bm.get("PositionalConstraint") == "STARTS_WITH":
                        search = bm.get("SearchString", "")
                        if search in ("/", "b'/'"):
                            _add(findings, "Low",
                                 f"Redundant Allow-all rule '{last_rule['Name']}'",
                                 f"{last_rule['Name']} (priority {last_rule['Priority']})",
                                 "Default action is already Allow. This rule matches all traffic and does nothing extra.",
                                 "Remove this rule to reduce WCU and evaluation overhead.")


def _check_count_without_labels(rules, findings):
    """Section 17a: Custom Count rules without labels."""
    for rule in rules:
        action = _get_action_str(rule)
        if action != "Count":
            continue
        # Skip managed rule groups (they have internal labels)
        if _get_mrg(rule):
            continue
        labels = rule.get("RuleLabels", [])
        if not labels:
            _add(findings, "Awareness",
                 f"Count rule '{rule['Name']}' has no labels",
                 f"{rule['Name']} (priority {rule['Priority']})",
                 "Count without labels only produces CloudWatch metrics. Downstream rules cannot act on this match.",
                 "If monitoring-only: acceptable. If intent is 'label then act': add RuleLabels.")


def _check_priority_order(rules, findings):
    """Section 18: Rule priority ordering."""
    # Classify each rule
    rule_categories = []
    for rule in rules:
        mrg = _get_mrg(rule)
        group_name = mrg.get("Name", "")
        action = _get_action_str(rule)
        name_lower = rule["Name"].lower()

        if group_name in MANAGED_GROUPS:
            cat = MANAGED_GROUPS[group_name]
        elif action == "Allow" and ("whitelist" in name_lower or "allow" in name_lower):
            cat = "ip_whitelist"
        elif action == "Block" and ("blacklist" in name_lower or "ban" in name_lower):
            cat = "ip_blacklist"
        elif "RateBasedStatement" in rule.get("Statement", {}):
            cat = "rate_based"
        elif "crawler" in name_lower and action == "Count":
            cat = "crawler_label"
        elif ("landing" in name_lower or "challenge" in name_lower) and action == "Count" and rule.get("RuleLabels"):
            cat = "always_on_challenge"  # label producer for challenge rule
        elif action == "Count" and rule.get("RuleLabels"):
            cat = "count_label"
        elif "landing" in name_lower and action == "Count":
            cat = "count_label"
        elif action == "Challenge" and "always" in name_lower:
            cat = "always_on_challenge"
        elif action in ("Block", "Challenge", "Captcha"):
            cat = "custom_block"
        else:
            cat = "count_label"

        rule_categories.append((rule, cat))

    # Check for ordering violations
    reported = 0
    for i in range(len(rule_categories)):
        for j in range(i + 1, len(rule_categories)):
            rule_i, cat_i = rule_categories[i]
            rule_j, cat_j = rule_categories[j]
            order_i = PRIORITY_ORDER.index(cat_i) if cat_i in PRIORITY_ORDER else 99
            order_j = PRIORITY_ORDER.index(cat_j) if cat_j in PRIORITY_ORDER else 99
            # Only flag when expensive rules (bot_control) are before cheap ones,
            # or when label consumers are before their producers
            if order_i > order_j and abs(order_i - order_j) >= 4:
                _add(findings, "Medium",
                     f"Rule ordering issue: '{rule_i['Name']}' should be after '{rule_j['Name']}'",
                     f"{rule_i['Name']} (P{rule_i['Priority']}) before {rule_j['Name']} (P{rule_j['Priority']})",
                     f"'{rule_i['Name']}' ({cat_i}) is before '{rule_j['Name']}' ({cat_j}), but recommended order is reversed.",
                     "Reorder rules according to best practice: label producers → AMR → IP reputation → rate-based → Challenge → CRS → Bot Control (last).")
                reported += 1
                if reported >= 3:
                    return
                break  # next i


def _check_managed_versions(rules, findings):
    """Section 12: Managed rule group versions."""
    for rule in rules:
        mrg = _get_mrg(rule)
        if not mrg:
            continue
        name = mrg.get("Name", "")
        version = mrg.get("Version", "")

        if name == "AWSManagedRulesBotControlRuleSet" and version:
            # Extract version number
            try:
                ver_num = float(version.replace("Version_", ""))
                if ver_num < 5.0:
                    _add(findings, "Low",
                         f"Bot Control version outdated ({version})",
                         f"{rule['Name']} (priority {rule['Priority']})",
                         f"Version 5.0 identifies ~700 bot types. Current {version} has fewer detections.",
                         "Upgrade to Version_5.0. Test in Count mode first.")
            except ValueError:
                pass
