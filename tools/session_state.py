# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Session state — stores current WebACL context for cross-tool coordination."""

# Populated by get_waf_config, consumed by other tools
_state: dict = {}


def set_webacl_context(name: str, arn: str, scope: str, region: str, log_destination: str | None = None,
                       log_filter_active: bool = False, log_filter_default: str | None = None):
    """Store current WebACL context."""
    _state["webacl_name"] = name
    _state["webacl_arn"] = arn
    _state["scope"] = scope
    _state["waf_region"] = region
    _state["metrics_region"] = "us-east-1" if scope == "CLOUDFRONT" else region
    _state["log_destination"] = log_destination
    _state["log_filter_active"] = log_filter_active
    _state["log_filter_default"] = log_filter_default
    _state["findings"] = []


def set_capabilities(capabilities: dict):
    """Store detected AWS WAF capabilities."""
    _state["capabilities"] = capabilities


def get_capabilities() -> dict:
    """Get detected AWS WAF capabilities."""
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


def is_log_filter_active() -> bool:
    """Check if a log filter is active (logs may be incomplete)."""
    return _state.get("log_filter_active", False)


def set_user_timezone(offset: float):
    """Store user's timezone offset (hours from UTC). Supports half-hour offsets (e.g. 5.5 for India)."""
    _state["user_tz_offset"] = offset


def get_user_timezone() -> float | None:
    """Get user's timezone offset. Returns None if not yet determined."""
    return _state.get("user_tz_offset")


def get_webacl_name() -> str | None:
    return _state.get("webacl_name")


def resolve_region(scope: str) -> str | None:
    """Resolve the correct AWS region for a given scope.

    Returns the region string, or None if REGIONAL scope is used but session
    state hasn't been initialized (caller should return error to LLM).
    """
    if scope == "CLOUDFRONT":
        return "us-east-1"
    # REGIONAL: need session state to know the region
    if not _state.get("webacl_name"):
        return None
    return _state.get("metrics_region", "us-east-1")


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
