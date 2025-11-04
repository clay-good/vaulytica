"""Tests for configuration loader."""

import os
import pytest
from pathlib import Path

from vaulytica.config.loader import (
    load_config,
    validate_config,
    expand_env_vars,
    get_config_value,
    ConfigurationError,
)


class TestExpandEnvVars:
    """Tests for environment variable expansion."""

    def test_expand_simple_var(self, monkeypatch):
        """Test expanding a simple environment variable."""
        monkeypatch.setenv("TEST_VAR", "test_value")
        result = expand_env_vars("${TEST_VAR}")
        assert result == "test_value"

    def test_expand_var_in_string(self, monkeypatch):
        """Test expanding variable within a string."""
        monkeypatch.setenv("HOST", "smtp.example.com")
        result = expand_env_vars("Host: ${HOST}")
        assert result == "Host: smtp.example.com"

    def test_expand_multiple_vars(self, monkeypatch):
        """Test expanding multiple variables."""
        monkeypatch.setenv("USER", "admin")
        monkeypatch.setenv("DOMAIN", "example.com")
        result = expand_env_vars("${USER}@${DOMAIN}")
        assert result == "admin@example.com"

    def test_expand_in_dict(self, monkeypatch):
        """Test expanding variables in dictionary."""
        monkeypatch.setenv("PASSWORD", "secret123")
        data = {"smtp_password": "${PASSWORD}", "other": "value"}
        result = expand_env_vars(data)
        assert result["smtp_password"] == "secret123"
        assert result["other"] == "value"

    def test_expand_in_list(self, monkeypatch):
        """Test expanding variables in list."""
        monkeypatch.setenv("EMAIL", "test@example.com")
        data = ["${EMAIL}", "other@example.com"]
        result = expand_env_vars(data)
        assert result[0] == "test@example.com"
        assert result[1] == "other@example.com"

    def test_missing_env_var(self):
        """Test handling of missing environment variable."""
        result = expand_env_vars("${MISSING_VAR}")
        assert result == ""


class TestValidateConfig:
    """Tests for configuration validation."""

    def test_valid_config_with_service_account(self):
        """Test validation of valid service account config."""
        config = {
            "google_workspace": {
                "domain": "example.com",
                "credentials_file": "service-account.json",
            }
        }
        validate_config(config)  # Should not raise

    def test_valid_config_with_oauth(self):
        """Test validation of valid OAuth config."""
        config = {
            "google_workspace": {
                "domain": "example.com",
                "oauth_credentials": "oauth.json",
            }
        }
        validate_config(config)  # Should not raise

    def test_missing_google_workspace_section(self):
        """Test error when google_workspace section is missing."""
        config = {}
        with pytest.raises(ConfigurationError, match="Missing required configuration section"):
            validate_config(config)

    def test_missing_domain(self):
        """Test error when domain is missing."""
        config = {"google_workspace": {"credentials_file": "test.json"}}
        with pytest.raises(ConfigurationError, match="domain is required"):
            validate_config(config)

    def test_missing_credentials(self):
        """Test error when no credentials are specified."""
        config = {"google_workspace": {"domain": "example.com"}}
        with pytest.raises(ConfigurationError, match="Either google_workspace.credentials_file or google_workspace.oauth_credentials must be specified"):
            validate_config(config)

    def test_email_alerts_missing_fields(self):
        """Test error when email alerts are enabled but fields are missing."""
        config = {
            "google_workspace": {
                "domain": "example.com",
                "credentials_file": "test.json",
            },
            "alerts": {"email": {"enabled": True}},
        }
        with pytest.raises(ConfigurationError, match="smtp_host is required"):
            validate_config(config)


class TestLoadConfig:
    """Tests for configuration loading."""

    def test_load_valid_config(self, temp_config_file):
        """Test loading a valid configuration file."""
        config = load_config(temp_config_file)
        assert config is not None
        assert "google_workspace" in config
        assert config["google_workspace"]["domain"] == "example.com"

    def test_load_missing_file(self):
        """Test error when config file doesn't exist."""
        with pytest.raises(ConfigurationError, match="not found"):
            load_config(Path("missing.yaml"))

    def test_load_empty_file(self, tmp_path):
        """Test error when config file is empty."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")

        with pytest.raises(ConfigurationError, match="empty"):
            load_config(config_file)

    def test_load_invalid_yaml(self, tmp_path):
        """Test error when YAML is invalid."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("invalid: yaml: content:")

        with pytest.raises(ConfigurationError, match="Invalid YAML"):
            load_config(config_file)

    def test_load_with_env_vars(self, tmp_path, monkeypatch):
        """Test loading config with environment variables."""
        monkeypatch.setenv("SMTP_PASSWORD", "secret123")

        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            """
google_workspace:
  domain: example.com
  credentials_file: test.json
alerts:
  email:
    smtp_password: ${SMTP_PASSWORD}
"""
        )

        config = load_config(config_file)
        assert config["alerts"]["email"]["smtp_password"] == "secret123"


class TestGetConfigValue:
    """Tests for getting config values with dot notation."""

    def test_get_simple_value(self):
        """Test getting a simple value."""
        config = {"key": "value"}
        result = get_config_value(config, "key")
        assert result == "value"

    def test_get_nested_value(self):
        """Test getting a nested value."""
        config = {"level1": {"level2": {"level3": "value"}}}
        result = get_config_value(config, "level1.level2.level3")
        assert result == "value"

    def test_get_missing_value_with_default(self):
        """Test getting missing value returns default."""
        config = {"key": "value"}
        result = get_config_value(config, "missing.key", default="default")
        assert result == "default"

    def test_get_missing_value_without_default(self):
        """Test getting missing value returns None."""
        config = {"key": "value"}
        result = get_config_value(config, "missing.key")
        assert result is None

