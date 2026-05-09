"""WAF configuration tools — list WebACLs and get config."""

from strands import tool
from tools.aws_session import get_client
from tools.session_state import set_webacl_context, set_capabilities


@tool
def list_webacls(scope: str = "CLOUDFRONT", region: str = "us-east-1") -> str:
    """List all WAF WebACLs in the account.

    Args:
        scope: WAF scope — "CLOUDFRONT" (global) or "REGIONAL". Default CLOUDFRONT.
        region: AWS region. For CLOUDFRONT scope, must be us-east-1.

    Returns:
        Formatted list of WebACL names, IDs, and ARNs.
    """
    if scope == "CLOUDFRONT":
        region = "us-east-1"

    client = get_client("wafv2", region_name=region)
    resp = client.list_web_acls(Scope=scope)
    acls = resp.get("WebACLs", [])

    if not acls:
        return f"No WebACLs found (scope={scope}, region={region})"

    lines = [f"Found {len(acls)} WebACL(s) (scope={scope}, region={region}):\n"]
    for acl in acls:
        lines.append(f"  - {acl['Name']} (ID: {acl['Id']})")
        lines.append(f"    ARN: {acl['ARN']}")
    return "\n".join(lines)


@tool
def get_waf_config(webacl_name: str, scope: str = "CLOUDFRONT", region: str = "us-east-1") -> str:
    """Get WebACL configuration including rules and logging destination.

    Args:
        webacl_name: Name of the WebACL.
        scope: WAF scope — "CLOUDFRONT" or "REGIONAL".
        region: AWS region. For CLOUDFRONT, must be us-east-1.

    Returns:
        WebACL rule summary and logging configuration.
    """
    if scope == "CLOUDFRONT":
        region = "us-east-1"

    client = get_client("wafv2", region_name=region)

    # Find WebACL by name
    acls = client.list_web_acls(Scope=scope).get("WebACLs", [])
    match = next((a for a in acls if a["Name"] == webacl_name), None)
    if not match:
        return f"WebACL '{webacl_name}' not found (scope={scope}, region={region})"

    # Get full config
    resp = client.get_web_acl(Name=webacl_name, Scope=scope, Id=match["Id"])
    webacl = resp["WebACL"]

    # Summarize rules
    rules = webacl.get("Rules", [])
    rules_sorted = sorted(rules, key=lambda r: r["Priority"])
    lines = [
        f"# WebACL: {webacl_name}",
        f"ARN: {webacl['ARN']}",
        f"Default Action: {list(webacl['DefaultAction'].keys())[0]}",
        f"Rules ({len(rules)}):\n",
    ]
    for r in rules_sorted:
        action = _extract_action(r)
        lines.append(f"  {r['Priority']:>4}  {r['Name']:<50} {action}")

    # Get logging config
    lines.append("\n## Logging Configuration")
    log_dest = None
    try:
        log_resp = client.get_logging_configuration(ResourceArn=webacl["ARN"])
        log_config = log_resp["LoggingConfiguration"]
        destinations = log_config.get("LogDestinationConfigs", [])
        for dest in destinations:
            lines.append(f"  Destination: {dest}")
            log_dest = dest
    except client.exceptions.WAFNonexistentItemException:
        lines.append("  ⚠️  Logging NOT enabled for this WebACL")

    # Store context for other tools
    set_webacl_context(
        name=webacl_name,
        arn=webacl["ARN"],
        scope=scope,
        region=region,
        log_destination=log_dest,
    )

    # Detect capabilities from rules
    caps = _detect_capabilities(rules)
    set_capabilities(caps)
    lines.append("\n## Detected Capabilities")
    lines.append(f"  Bot Control: {caps['bot_control']}")
    lines.append(f"  Anti-DDoS AMR: {'Yes' if caps['anti_ddos_amr'] else 'No'}")
    lines.append(f"  Challenge/Token: {'Yes' if caps['has_challenge'] else 'No'}")
    lines.append(f"  Rate-based rules: {'Yes' if caps['has_rate_based'] else 'No'}")
    lines.append(f"  Token reuse detection: {'Yes' if caps['has_token_reuse_rule'] else 'No'}")

    return "\n".join(lines)


def _extract_action(rule: dict) -> str:
    """Extract action string from a rule."""
    if "Action" in rule:
        action_keys = list(rule["Action"].keys())
        return action_keys[0] if action_keys else "?"
    if "OverrideAction" in rule:
        oa = rule["OverrideAction"]
        if "none" in oa or "None" in oa:
            return "(managed-group)"
        return f"override:{list(oa.keys())[0]}"
    return "?"


def _detect_capabilities(rules: list) -> dict:
    """Detect WAF capabilities from rule configuration."""
    caps = {
        "bot_control": "none",       # none / common / targeted
        "anti_ddos_amr": False,
        "has_challenge": False,
        "has_rate_based": False,
        "has_token_reuse_rule": False,
    }

    for rule in rules:
        name = rule.get("Name", "")
        stmt = rule.get("Statement", {})

        # Check for Challenge action
        action = rule.get("Action", {})
        if "Challenge" in action or "Captcha" in action:
            caps["has_challenge"] = True

        # Check for rate-based
        if "RateBasedStatement" in stmt:
            caps["has_rate_based"] = True

        # Check managed rule groups
        mrg = stmt.get("ManagedRuleGroupStatement") or {}
        if not mrg:
            # Check inside override/nested statements
            for key in ("RateBasedStatement", "OrStatement", "AndStatement", "NotStatement"):
                nested = stmt.get(key, {})
                if isinstance(nested, dict):
                    mrg = nested.get("ScopeDownStatement", {}).get("ManagedRuleGroupStatement") or {}
                    if mrg:
                        break

        vendor = mrg.get("VendorName", "")
        group_name = mrg.get("Name", "")

        if vendor == "AWS":
            if group_name == "AWSManagedRulesBotControlRuleSet":
                # Determine Common vs Targeted from ManagedRuleGroupConfigs
                configs = mrg.get("ManagedRuleGroupConfigs", [])
                level = "common"
                for cfg in configs:
                    if cfg.get("AWSManagedRulesBotControlRuleSet", {}).get("InspectionLevel") == "TARGETED":
                        level = "targeted"
                caps["bot_control"] = level
                caps["has_challenge"] = True  # Bot Control implies token
                # Check for token reuse rule
                caps["has_token_reuse_rule"] = level == "targeted"

            elif group_name in ("AWSManagedRulesACFPRuleSet", "AWSManagedRulesATPRuleSet"):
                caps["has_challenge"] = True  # ACFP/ATP use tokens

            elif group_name == "AWSManagedRulesAntiDDoSRuleSet":
                caps["anti_ddos_amr"] = True
                caps["has_challenge"] = True  # Anti-DDoS AMR uses Challenge

    return caps
