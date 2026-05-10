"""Session state — stores current WebACL context for cross-tool coordination."""

# Populated by get_waf_config, consumed by other tools
_state: dict = {}


def set_webacl_context(name: str, arn: str, scope: str, region: str, log_destination: str | None = None):
    """Store current WebACL context."""
    _state["webacl_name"] = name
    _state["webacl_arn"] = arn
    _state["scope"] = scope
    _state["waf_region"] = region
    _state["metrics_region"] = "us-east-1" if scope == "CLOUDFRONT" else region
    _state["log_destination"] = log_destination
    _state["findings"] = []


def set_capabilities(capabilities: dict):
    """Store detected WAF capabilities."""
    _state["capabilities"] = capabilities


def get_capabilities() -> dict:
    """Get detected WAF capabilities."""
    return _state.get("capabilities", {})


def get_metrics_region() -> str:
    """Get the correct region for CloudWatch Metrics queries."""
    return _state.get("metrics_region", "us-east-1")


def get_logs_region() -> str:
    """Get the correct region for CW Logs queries."""
    return _state.get("metrics_region", "us-east-1")


def get_log_destination() -> str | None:
    """Get the discovered log destination (CW Logs group or S3 bucket)."""
    return _state.get("log_destination")


def get_webacl_name() -> str | None:
    return _state.get("webacl_name")


def get_scope() -> str:
    return _state.get("scope", "CLOUDFRONT")


def set_host_profiles(profiles: dict):
    """Store host traffic profiles (frontend/backend/mixed classification)."""
    _state["host_profiles"] = profiles


def get_host_profiles() -> dict:
    """Get host traffic profiles."""
    return _state.get("host_profiles", {})


# Investigation findings accumulator
def add_finding(finding: dict):
    """Append a finding to the session."""
    _state.setdefault("findings", []).append(finding)


def get_findings() -> list:
    """Get all findings recorded in this session."""
    return _state.get("findings", [])


def clear_findings():
    """Reset findings (for new investigation)."""
    _state["findings"] = []
