"""WAF configuration tools — list WebACLs and get config."""

import re
from strands import tool
from strands.types.tools import ToolContext
from tools.aws_session import get_client
from tools.session_state import set_webacl_context, set_capabilities


def _numbered_list(names: list[str]) -> str:
    """Format WebACL names as numbered list for interrupt questions."""
    return "\n".join(f"  {i+1}. {n}" for i, n in enumerate(names))


def _parse_region(text: str) -> str:
    """Extract AWS region from user text (e.g., 'Tokyo (ap-northeast-1)' → 'ap-northeast-1')."""
    m = re.search(r'[a-z]{2}-[a-z]+-\d', text)
    return m.group(0) if m else text.strip()


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
    if len(acls) > 1:
        lines.append("\n⚠️ Multiple WebACLs found. You MUST call get_waf_config(webacl_name=\"...\") to select one before proceeding. Do NOT ask the user yourself — get_waf_config will handle it.")
    else:
        lines.append(f"\n→ Only one WebACL. Call get_waf_config(webacl_name=\"{acls[0]['Name']}\") to load its configuration.")
    return "\n".join(lines)


@tool(context=True)
def get_waf_config(tool_context: ToolContext, webacl_name: str = "", scope: str = "CLOUDFRONT", region: str = "us-east-1") -> str:
    """Get WebACL configuration including rules and logging destination.

    Args:
        webacl_name: Name of the WebACL. If empty or ambiguous, will ask user to choose.
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

    # If no name given and multiple WebACLs exist, interrupt to ask user
    if not webacl_name:
        if len(acls) == 1:
            webacl_name = acls[0]["Name"]
        elif len(acls) > 1:
            names = [a["Name"] for a in acls]
            webacl_name = tool_context.interrupt("select_webacl", reason={
                "question": f"Found {len(acls)} WebACLs. Enter number or full name:\n{_numbered_list(names)}",
                "options": names,
            })
        elif scope == "REGIONAL":
            # No WebACLs in this region — ask user which region, then retry
            new_region = tool_context.interrupt("select_region", reason={
                "question": f"No WebACLs found in {region}. Which AWS region is your WebACL in? (e.g., us-west-2, ap-northeast-1)",
            })
            region = _parse_region(new_region)
            client = get_client("wafv2", region_name=region)
            acls = client.list_web_acls(Scope=scope).get("WebACLs", [])
            if not acls:
                return f"No WebACLs found in {region} either."
            if len(acls) == 1:
                webacl_name = acls[0]["Name"]
            else:
                names = [a["Name"] for a in acls]
                webacl_name = tool_context.interrupt("select_webacl", reason={
                    "question": f"Found {len(acls)} WebACLs in {region}. Enter number or full name:\n{_numbered_list(names)}",
                    "options": names,
                })
        else:
            return f"No WebACLs found (scope={scope}, region={region})"

    # Fuzzy match if exact match fails (user might reply with partial name or extra text)
    match = next((a for a in acls if a["Name"] == webacl_name), None)
    if not match:
        # Direction 1: ACL name appears in user reply (user added extra text like ", 5月9号")
        candidates = [a for a in acls if a["Name"].lower() in webacl_name.lower()]
        if len(candidates) == 1:
            match = candidates[0]
        elif len(candidates) > 1:
            match = max(candidates, key=lambda a: len(a["Name"]))  # longest match wins
        # Direction 2: user reply appears in ACL name (user gave partial name like "shield")
        if not match:
            candidates = [a for a in acls if webacl_name.strip().lower() in a["Name"].lower()]
            if len(candidates) == 1:
                match = candidates[0]
            # Multiple partial matches → don't guess, will fall through to interrupt below
        if match:
            webacl_name = match["Name"]
    if not match:
        try:
            idx = int(webacl_name.strip().rstrip('.')) - 1
            if 0 <= idx < len(acls):
                match = acls[idx]
                webacl_name = match["Name"]
        except (ValueError, IndexError):
            pass
    if not match:
        if scope == "REGIONAL":
            new_region = tool_context.interrupt("select_region", reason={
                "question": f"WebACL '{webacl_name}' not found in {region}. Which region is it in?",
            })
            region = _parse_region(new_region)
            client = get_client("wafv2", region_name=region)
            acls = client.list_web_acls(Scope=scope).get("WebACLs", [])
            match = next((a for a in acls if a["Name"] == webacl_name), None)
            if not match:
                match = next((a for a in acls if webacl_name.lower() in a["Name"].lower()), None)
                if match:
                    webacl_name = match["Name"]
        if not match:
            # Ambiguous or not found — re-interrupt with available options
            names = [a["Name"] for a in acls]
            if names:
                webacl_name = tool_context.interrupt("select_webacl", reason={
                    "question": f"Could not match '{webacl_name}'. Enter number or full name:\n{_numbered_list(names)}",
                    "options": names,
                })
                match = next((a for a in acls if a["Name"] == webacl_name), None)
                if not match:
                    match = next((a for a in acls if a["Name"].lower() in webacl_name.lower()), None)
                    if match:
                        webacl_name = match["Name"]
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

    # Guide LLM on which log query tool to use
    lines.append("\n## Log Query Tool")
    if log_dest and ":log-group:" in log_dest:
        lines.append("  Use: run_logs_query (CloudWatch Logs Insights)")
    elif log_dest and (":s3:::" in log_dest or ":firehose:" in log_dest):
        lines.append("  Use: run_athena_query (S3 logs via Athena)")
    else:
        lines.append("  ⚠️ Logging NOT enabled — log queries unavailable. Use get_waf_metrics only.")

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
