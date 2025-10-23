"""Configuration management for Vaulytica."""

import os
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    """Deployment environment."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TESTING = "testing"


class VaulyticaConfig(BaseSettings):
    """Main configuration for Vaulytica."""

    model_config = SettingsConfigDict(
        env_prefix="VAULYTICA_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"  # Ignore extra environment variables
    )

    # Environment configuration
    environment: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Deployment environment"
    )

    debug: bool = Field(
        default=False,
        description="Enable debug mode"
    )

    anthropic_api_key: str = Field(
        description="Anthropic API key for Claude access"
    )

    model_name: str = Field(
        default="claude-3-haiku-20240307",
        description="Claude model to use for analysis"
    )

    max_tokens: int = Field(
        default=4000,
        description="Maximum tokens for LLM responses"
    )

    temperature: float = Field(
        default=0.0,
        description="Temperature for LLM sampling (0.0 for deterministic)"
    )

    chunk_size: int = Field(
        default=50000,
        description="Maximum characters per chunk for analysis"
    )

    chroma_db_path: Path = Field(
        default=Path("./chroma_db"),
        description="Path to ChromaDB storage"
    )

    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )

    output_dir: Path = Field(
        default=Path("./outputs"),
        description="Directory for analysis outputs and cache"
    )

    enable_rag: bool = Field(
        default=True,
        description="Enable RAG for historical incident correlation"
    )

    max_historical_incidents: int = Field(
        default=5,
        description="Maximum number of historical incidents to retrieve"
    )

    enable_cache: bool = Field(
        default=True,
        description="Enable caching for repeated analyses"
    )

    batch_max_workers: int = Field(
        default=3,
        description="Maximum parallel workers for batch processing"
    )

    webhook_secret: Optional[str] = Field(
        default=None,
        description="Secret key for webhook signature verification"
    )

    # Notification settings
    slack_webhook_url: Optional[str] = Field(
        default=None,
        description="Slack webhook URL for notifications"
    )

    slack_channel: Optional[str] = Field(
        default=None,
        description="Slack channel override"
    )

    teams_webhook_url: Optional[str] = Field(
        default=None,
        description="Microsoft Teams webhook URL"
    )

    smtp_host: Optional[str] = Field(
        default=None,
        description="SMTP server host for email notifications"
    )

    smtp_port: int = Field(
        default=587,
        description="SMTP server port"
    )

    smtp_username: Optional[str] = Field(
        default=None,
        description="SMTP username"
    )

    smtp_password: Optional[str] = Field(
        default=None,
        description="SMTP password"
    )

    smtp_from: Optional[str] = Field(
        default=None,
        description="From email address"
    )

    smtp_to: Optional[str] = Field(
        default=None,
        description="To email address(es), comma-separated"
    )

    min_risk_score_notify: int = Field(
        default=5,
        description="Minimum risk score to trigger notifications"
    )

    notify_on_cache_hit: bool = Field(
        default=False,
        description="Send notifications for cached results"
    )

    # Threat Feed Integration (v0.9.0)
    virustotal_api_key: Optional[str] = Field(
        default=None,
        description="VirusTotal API key for IOC enrichment"
    )

    alienvault_otx_api_key: Optional[str] = Field(
        default=None,
        description="AlienVault OTX API key for threat intelligence"
    )

    abuseipdb_api_key: Optional[str] = Field(
        default=None,
        description="AbuseIPDB API key for IP reputation"
    )

    shodan_api_key: Optional[str] = Field(
        default=None,
        description="Shodan API key for IP intelligence"
    )

    enable_threat_feeds: bool = Field(
        default=True,
        description="Enable external threat feed integration"
    )

    threat_feed_cache_ttl: int = Field(
        default=24,
        description="Threat feed cache TTL in hours"
    )

    threat_feed_timeout: int = Field(
        default=10,
        description="Threat feed API timeout in seconds"
    )

    # URLScan.io Integration
    urlscan_api_key: Optional[str] = Field(
        default=None,
        description="URLScan.io API key for screenshot capture and phishing detection"
    )

    urlscan_max_wait_seconds: int = Field(
        default=60,
        description="Maximum seconds to wait for URLScan.io scan completion"
    )

    # WHOIS Integration
    enable_whois: bool = Field(
        default=True,
        description="Enable WHOIS domain lookups"
    )

    whois_recently_registered_threshold_days: int = Field(
        default=30,
        description="Days threshold for recently registered domain detection"
    )

    # Cross-Platform Investigation
    enable_investigation_queries: bool = Field(
        default=True,
        description="Enable cross-platform investigation query generation"
    )

    # Jira Integration (v1.0.0)
    jira_url: Optional[str] = Field(
        default=None,
        description="Jira instance URL (e.g., 'https://your-company.atlassian.net')"
    )

    jira_username: Optional[str] = Field(
        default=None,
        description="Jira username/email"
    )

    jira_api_token: Optional[str] = Field(
        default=None,
        description="Jira API token"
    )

    jira_project_key: Optional[str] = Field(
        default=None,
        description="Jira project key (e.g., 'SEC')"
    )

    jira_auto_create_issues: bool = Field(
        default=False,
        description="Automatically create Jira issues for incidents"
    )

    # Wiz Integration
    wiz_client_id: Optional[str] = Field(
        default=None,
        description="Wiz service account client ID"
    )

    wiz_client_secret: Optional[str] = Field(
        default=None,
        description="Wiz service account client secret"
    )

    wiz_region: str = Field(
        default="us17",
        description="Wiz region (us17, eu1, etc.)"
    )

    wiz_enabled: bool = Field(
        default=False,
        description="Enable Wiz cloud security integration"
    )

    # Socket.dev Integration
    socketdev_api_key: Optional[str] = Field(
        default=None,
        description="Socket.dev API key for supply chain security"
    )

    socketdev_enabled: bool = Field(
        default=False,
        description="Enable Socket.dev integration"
    )

    # GitLab Integration
    gitlab_url: Optional[str] = Field(
        default="https://gitlab.example.com",
        description="GitLab instance URL"
    )

    gitlab_token: Optional[str] = Field(
        default=None,
        description="GitLab personal access token"
    )

    gitlab_enabled: bool = Field(
        default=False,
        description="Enable GitLab integration"
    )

    # GitHub Integration
    github_token: Optional[str] = Field(
        default=None,
        description="GitHub personal access token"
    )

    github_enabled: bool = Field(
        default=False,
        description="Enable GitHub integration"
    )

    @field_validator("anthropic_api_key")
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        """Validate Anthropic API key format."""
        if not v or v == "your-api-key-here":
            raise ValueError("Valid Anthropic API key required")
        if not v.startswith("sk-ant-"):
            raise ValueError("Invalid Anthropic API key format (should start with 'sk-ant-')")
        return v

    @field_validator("chroma_db_path", "output_dir")
    @classmethod
    def ensure_path_exists(cls, v: Path) -> Path:
        """Ensure required directories exist."""
        v.mkdir(parents=True, exist_ok=True)
        return v

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in valid_levels:
            raise ValueError(f"Invalid log level. Must be one of: {', '.join(valid_levels)}")
        return v

    @model_validator(mode='after')
    def validate_production_settings(self) -> 'VaulyticaConfig':
        """Validate production-specific settings."""
        if self.environment == Environment.PRODUCTION:
            # Ensure critical settings are configured for production
            if self.debug:
                raise ValueError("Debug mode must be disabled in production")
            if self.log_level == "DEBUG":
                raise ValueError("Log level should not be DEBUG in production")
            if not self.enable_cache:
                import warnings
                warnings.warn("Cache is disabled in production - this may impact performance")
        return self

    def get_environment_name(self) -> str:
        """Get the current environment name."""
        return self.environment.value

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION

    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == Environment.DEVELOPMENT

    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.

        Args:
            mask_secrets: If True, mask sensitive values

        Returns:
            Dictionary representation of configuration
        """
        config_dict = self.model_dump()

        if mask_secrets:
            # Mask sensitive fields
            sensitive_fields = [
                'anthropic_api_key', 'webhook_secret', 'slack_webhook_url',
                'teams_webhook_url', 'smtp_password', 'jira_api_token',
                'servicenow_password', 'pagerduty_api_key', 'opsgenie_api_key'
            ]
            for field in sensitive_fields:
                if field in config_dict and config_dict[field]:
                    config_dict[field] = "***MASKED***"

        return config_dict


def load_config(api_key: Optional[str] = None, environment: Optional[str] = None) -> VaulyticaConfig:
    """
    Load configuration with optional overrides.

    Args:
        api_key: Optional Anthropic API key override
        environment: Optional environment override (development, staging, production)

    Returns:
        Loaded configuration

    Raises:
        ValueError: If configuration is invalid
    """
    kwargs = {}
    if api_key:
        kwargs['anthropic_api_key'] = api_key
    if environment:
        kwargs['environment'] = environment

    return VaulyticaConfig(**kwargs)


def load_config_from_file(config_file: Path) -> VaulyticaConfig:
    """
    Load configuration from a specific file.

    Args:
        config_file: Path to configuration file

    Returns:
        Loaded configuration
    """
    import json
    import yaml

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")

    # Load based on file extension
    if config_file.suffix == '.json':
        with open(config_file) as f:
            config_data = json.load(f)
    elif config_file.suffix in ['.yaml', '.yml']:
        with open(config_file) as f:
            config_data = yaml.safe_load(f)
    else:
        raise ValueError(f"Unsupported configuration file format: {config_file.suffix}")

    return VaulyticaConfig(**config_data)

# Global configuration instance
_global_config: Optional[VaulyticaConfig] = None


def get_config() -> VaulyticaConfig:
    """
    Get the global configuration instance.

    Creates a new configuration if one doesn't exist.
    Uses environment variables or defaults.

    Returns:
        Global VaulyticaConfig instance
    """
    global _global_config
    if _global_config is None:
        try:
            _global_config = VaulyticaConfig()
        except Exception:
            # If config fails (e.g., missing API key), create with test defaults
            _global_config = VaulyticaConfig(
                anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "sk-ant-test-key-for-testing-only")
            )
    return _global_config


def set_config(config: VaulyticaConfig) -> None:
    """
    Set the global configuration instance.

    Args:
        config: Configuration to set as global
    """
    global _global_config
    _global_config = config
