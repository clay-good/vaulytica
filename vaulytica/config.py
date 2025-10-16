"""Configuration management for Vaulytica."""

from pathlib import Path
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class VaulyticaConfig(BaseSettings):
    """Main configuration for Vaulytica."""
    
    model_config = SettingsConfigDict(
        env_prefix="VAULYTICA_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
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

    @field_validator("anthropic_api_key")
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        if not v or v == "your-api-key-here":
            raise ValueError("Valid Anthropic API key required")
        return v
    
    @field_validator("chroma_db_path", "output_dir")
    @classmethod
    def ensure_path_exists(cls, v: Path) -> Path:
        v.mkdir(parents=True, exist_ok=True)
        return v


def load_config(api_key: Optional[str] = None) -> VaulyticaConfig:
    """Load configuration with optional API key override."""
    if api_key:
        return VaulyticaConfig(anthropic_api_key=api_key)
    return VaulyticaConfig()

