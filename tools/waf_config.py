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
        Numbered list of WebACL names. If only one exists, hint to use it directly.
    """
    if scope == "CLOUDFRONT":
        region = "us-east-1"

    client = get_client("wafv2", region_name=region)
    acls = client.list_web_acls(Scope=scope).get("WebACLs", [])

    if not acls:
        return f"No WebACLs found (scope={scope}, region={region})"

    lines = [f"Found {len(acls)} WebACL(s) (scope={scope}, region={region}):\n"]
    for i, acl in enumerate(acls, 1):
        lines.append(f"  {i}. {acl['Name']}")

    if len(acls) == 1:
        lines.append(f"\n→ Only one WebACL. Call get_waf_config(webacl_name=\"{acls[0]['Name']}\") to load its configuration.")
    else:
        lines.append("\n---\nHints:")
        lines.append("Consider asking the user:")
        lines.append("- Which WebACL? (give the numbered list above)")
        lines.append("- Time range? (e.g., 'May 9 afternoon', 'last 6 hours')")
        lines.append("- Specific domain/host affected?")
        lines.append("- CloudFront or ALB/regional?")

    return "\n".join(lines)


@tool
def get_waf_config(webacl_name: str, scope: str = "CLOUDFRONT", region: str = "us-east-1") -> str:
    """Get WebACL configuration including rules and logging destination.

    You must provide the exact WebACL name (case-insensitive). Call list_webacls first
    if you don't know the name. If multiple WebACLs exist, ask the user which one to use.

    Args:
        webacl_name: Exact name of the WebACL (case-insensitive).
        scope: WAF scope — "CLOUDFRONT" or "REGIONAL".
        region: AWS region. For CLOUDFRONT, must be us-east-1.

    Returns:
        WebACL rule summary and logging configuration, or error with available names.
    """
    if scope == "CLOUDFRONT":
        region = "us-east-1"

    client = get_client("wafv2", region_name=region)
    acls = client.list_web_acls(Scope=scope).get("WebACLs", [])

    # Case-insensitive exact match
    match = next((a for a in acls if a["Name"].lower() == webacl_name.lower()), None)
    if not match:
        names = [a["Name"] for a in acls]
        if names:
            return f"WebACL '{webacl_name}' not found. Available: {', '.join(names)}"
        return f"No WebACLs found (scope={scope}, region={region})"

    webacl_name = match["Name"]  # use canonical casing

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

    # Contextual hints — what to ask user before proceeding
    lines.append("\n---\nHints:")
    lines.append("- Specific time range? (e.g., 'yesterday 2-4pm', not just a date)")
    lines.append("- Which domain/host is affected? (if multiple hosts behind this WebACL)")
    lines.append("- What's the concern? (crawler/bypass, DDoS, false positive, rule evaluation)")
    if caps["bot_control"] != "none":
        lines.append("- Is the site SPA? Is WAF Client SDK integrated? (affects Bot Control recommendations)")
    if caps["has_challenge"]:
        lines.append("- Are there native apps/APIs on the same domain? (Challenge doesn't work for non-browser)")

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
        "bot_control": "none",
        "anti_ddos_amr": False,
        "has_challenge": False,
        "has_rate_based": False,
        "has_token_reuse_rule": False,
    }
    for r in rules:
        stmt = r.get("Statement", {})
        mgr = stmt.get("ManagedRuleGroupStatement", {})
        group_name = mgr.get("Name", "")

        # Bot Control — detect by managed rule group name (not user's rule name)
        if group_name == "AWSManagedRulesBotControlRuleSet":
            ml = mgr.get("ManagedRuleGroupConfigs", [])
            for cfg in ml:
                if cfg.get("AWSManagedRulesBotControlRuleSetProperty", {}).get("InspectionLevel") == "TARGETED":
                    caps["bot_control"] = "Targeted"
                    break
            else:
                if caps["bot_control"] != "Targeted":
                    caps["bot_control"] = "Common"

        # Anti-DDoS AMR — detect by managed rule group name
        if group_name == "AWSManagedRulesAntiDDoSRuleSet":
            caps["anti_ddos_amr"] = True

        # Challenge
        action = r.get("Action", {})
        if "Challenge" in action or "Captcha" in action:
            caps["has_challenge"] = True

        # Rate-based
        if "RateBasedStatement" in stmt:
            caps["has_rate_based"] = True

        # Token reuse (custom rule checking for TGT_TokenReuseIP label)
        name = r.get("Name", "")
        if "TokenReuse" in name or "token_reuse" in name.lower():
            caps["has_token_reuse_rule"] = True

    return caps
