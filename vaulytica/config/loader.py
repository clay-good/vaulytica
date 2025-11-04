"""Configuration file loader and validator."""

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
import structlog

logger = structlog.get_logger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""

    pass


def expand_env_vars(value: Any) -> Any:
    """Recursively expand environment variables in configuration values.

    Supports ${VAR_NAME} syntax.

    Args:
        value: Configuration value (can be dict, list, str, etc.)

    Returns:
        Value with environment variables expanded
    """
    if isinstance(value, str):
        # Find all ${VAR_NAME} patterns
        pattern = r"\$\{([^}]+)\}"
        matches = re.findall(pattern, value)

        for var_name in matches:
            env_value = os.environ.get(var_name, "")
            if not env_value:
                logger.warning("environment_variable_not_set", var_name=var_name)
            value = value.replace(f"${{{var_name}}}", env_value)

        return value

    elif isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}

    elif isinstance(value, list):
        return [expand_env_vars(item) for item in value]

    return value


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load and validate configuration from YAML file.

    Args:
        config_path: Path to configuration file (default: config.yaml)

    Returns:
        Configuration dictionary with environment variables expanded

    Raises:
        ConfigurationError: If configuration is invalid or file not found
    """
    if config_path is None:
        config_path = Path("config.yaml")

    if not config_path.exists():
        raise ConfigurationError(
            f"Configuration file not found: {config_path}\n"
            f"Run 'vaulytica init' to create one."
        )

    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        if not config:
            raise ConfigurationError("Configuration file is empty")

        # Expand environment variables
        config = expand_env_vars(config)

        # Validate configuration
        validate_config(config)

        logger.info("configuration_loaded", config_path=str(config_path))
        return config

    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
    except Exception as e:
        raise ConfigurationError(f"Error loading configuration: {e}")


def validate_config(config: Dict[str, Any]) -> None:
    """Validate configuration structure and required fields.

    Args:
        config: Configuration dictionary

    Raises:
        ConfigurationError: If configuration is invalid
    """
    # Check for required top-level sections
    required_sections = ["google_workspace"]
    for section in required_sections:
        if section not in config:
            raise ConfigurationError(f"Missing required configuration section: {section}")

    # Validate Google Workspace configuration
    gws_config = config["google_workspace"]

    if "domain" not in gws_config:
        raise ConfigurationError("google_workspace.domain is required")

    # Check that at least one authentication method is configured
    has_service_account = "credentials_file" in gws_config
    has_oauth = "oauth_credentials" in gws_config

    if not has_service_account and not has_oauth:
        raise ConfigurationError(
            "Either google_workspace.credentials_file or "
            "google_workspace.oauth_credentials must be specified"
        )

    # Validate scanning configuration if present
    if "scanning" in config:
        scanning_config = config["scanning"]

        # Validate PII patterns if check_pii is enabled
        if scanning_config.get("check_pii", False):
            if "pii_patterns" not in scanning_config:
                logger.warning("check_pii_enabled_but_no_patterns_specified")

    # Validate alerts configuration if present
    if "alerts" in config:
        alerts_config = config["alerts"]

        # Validate email configuration if enabled
        if alerts_config.get("email", {}).get("enabled", False):
            email_config = alerts_config["email"]
            required_email_fields = ["smtp_host", "smtp_port", "smtp_user", "recipients"]

            for field in required_email_fields:
                if field not in email_config:
                    raise ConfigurationError(f"alerts.email.{field} is required when email is enabled")

    logger.info("configuration_validated")


def get_config_value(config: Dict[str, Any], key_path: str, default: Any = None) -> Any:
    """Get a configuration value using dot notation.

    Args:
        config: Configuration dictionary
        key_path: Dot-separated path to value (e.g., "google_workspace.domain")
        default: Default value if key not found

    Returns:
        Configuration value or default

    Example:
        >>> config = {"google_workspace": {"domain": "example.com"}}
        >>> get_config_value(config, "google_workspace.domain")
        'example.com'
    """
    keys = key_path.split(".")
    value = config

    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default

    return value

