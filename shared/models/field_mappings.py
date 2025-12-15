"""Field mapping definitions between CLI and Web models.

This module documents and provides utilities for mapping between the field names
used in the CLI models and the Web models. When migrating or sharing data between
systems, use these mappings.
"""

from typing import Dict, Any

# Mapping from CLI field names to standardized field names
CLI_TO_STANDARD: Dict[str, str] = {
    # User fields
    "is_2fa_enrolled": "two_factor_enabled",
    "inactive_days": "days_inactive",
    "user_email": "email",  # CLI uses user_email, standard uses email
    # File fields
    "is_externally_shared": "is_externally_shared",  # Same
    "size_bytes": "file_size",
    "has_pii": "pii_detected",
    # Generic
    "scan_timestamp": "detected_at",
}

# Mapping from Web field names to standardized field names
WEB_TO_STANDARD: Dict[str, str] = {
    # User fields
    "two_factor_enabled": "two_factor_enabled",  # Same
    "days_since_last_login": "days_inactive",
    "email": "email",  # Same
    # File fields
    "is_shared_externally": "is_externally_shared",
    "file_size": "file_size",  # Same
    "pii_detected": "pii_detected",  # Same
    # Generic
    "detected_at": "detected_at",  # Same
}

# Standardized to CLI
STANDARD_TO_CLI: Dict[str, str] = {v: k for k, v in CLI_TO_STANDARD.items()}

# Standardized to Web
STANDARD_TO_WEB: Dict[str, str] = {v: k for k, v in WEB_TO_STANDARD.items()}


def map_cli_to_standard(data: Dict[str, Any]) -> Dict[str, Any]:
    """Map CLI field names to standardized field names.

    Args:
        data: Dictionary with CLI field names

    Returns:
        Dictionary with standardized field names
    """
    result = {}
    for key, value in data.items():
        new_key = CLI_TO_STANDARD.get(key, key)
        result[new_key] = value
    return result


def map_web_to_standard(data: Dict[str, Any]) -> Dict[str, Any]:
    """Map Web field names to standardized field names.

    Args:
        data: Dictionary with Web field names

    Returns:
        Dictionary with standardized field names
    """
    result = {}
    for key, value in data.items():
        new_key = WEB_TO_STANDARD.get(key, key)
        result[new_key] = value
    return result


def map_standard_to_cli(data: Dict[str, Any]) -> Dict[str, Any]:
    """Map standardized field names to CLI field names.

    Args:
        data: Dictionary with standardized field names

    Returns:
        Dictionary with CLI field names
    """
    result = {}
    for key, value in data.items():
        new_key = STANDARD_TO_CLI.get(key, key)
        result[new_key] = value
    return result


def map_standard_to_web(data: Dict[str, Any]) -> Dict[str, Any]:
    """Map standardized field names to Web field names.

    Args:
        data: Dictionary with standardized field names

    Returns:
        Dictionary with Web field names
    """
    result = {}
    for key, value in data.items():
        new_key = STANDARD_TO_WEB.get(key, key)
        result[new_key] = value
    return result


# Type definitions for findings that can be shared between CLI and web
# These define the expected structure for interoperability

USER_FINDING_FIELDS = {
    "required": ["email", "full_name"],
    "optional": [
        "is_admin",
        "is_suspended",
        "two_factor_enabled",
        "last_login_time",
        "creation_time",
        "org_unit_path",
        "is_inactive",
        "days_inactive",
        "risk_score",
        "risk_factors",
        "detected_at",
    ],
}

FILE_FINDING_FIELDS = {
    "required": ["file_id", "file_name"],
    "optional": [
        "owner_email",
        "mime_type",
        "file_size",
        "is_externally_shared",
        "is_public",
        "pii_detected",
        "pii_types",
        "risk_score",
        "risk_factors",
        "detected_at",
    ],
}

OAUTH_FINDING_FIELDS = {
    "required": ["client_id"],
    "optional": [
        "display_text",
        "scopes",
        "user_count",
        "users",
        "is_verified",
        "is_google_app",
        "is_internal",
        "risk_score",
        "risk_factors",
        "detected_at",
    ],
}

SECURITY_FINDING_FIELDS = {
    "required": ["check_id", "title", "severity", "passed"],
    "optional": [
        "description",
        "current_value",
        "expected_value",
        "impact",
        "remediation",
        "frameworks",
        "resource_type",
        "resource_id",
        "detected_at",
    ],
}
