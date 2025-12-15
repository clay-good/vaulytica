"""Application configuration using pydantic-settings."""

import os
import secrets
from functools import lru_cache
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings


# Insecure defaults that must be changed in production
_INSECURE_SECRET_KEY = "change-this-to-a-secure-random-string"
_INSECURE_DB_PASSWORD = "postgresql://vaulytica:password@"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "Vaulytica API"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"  # development, staging, production

    # Database
    database_url: str = "postgresql://vaulytica:password@localhost:5432/vaulytica"

    # Authentication
    secret_key: str = _INSECURE_SECRET_KEY
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:3001"]

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Rate limiting
    rate_limit_requests: int = 100  # requests per window
    rate_limit_window: int = 60  # window in seconds

    # Database connection pool
    db_pool_size: int = 5  # Number of connections to keep open
    db_pool_max_overflow: int = 10  # Max additional connections beyond pool_size
    db_pool_timeout: int = 30  # Seconds to wait for a connection from the pool
    db_pool_recycle: int = 1800  # Seconds before a connection is recycled (30 min)
    db_pool_pre_ping: bool = True  # Verify connections before using them

    # Email settings (SMTP)
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "noreply@vaulytica.local"
    smtp_from_name: str = "Vaulytica"
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False

    # Frontend URL for password reset links
    frontend_url: str = "http://localhost:3000"

    # Logging settings
    log_level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    log_json: bool = True  # Output logs as JSON for aggregation
    log_file: Optional[str] = None  # Optional file path for logs

    # Secret management
    secret_backend: str = "chained"  # env, file, vault, aws, chained

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate secret key is not the insecure default in production."""
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production" and v == _INSECURE_SECRET_KEY:
            raise ValueError(
                "SECRET_KEY must be set to a secure random value in production. "
                "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Validate database URL doesn't use default password in production."""
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production" and _INSECURE_DB_PASSWORD in v:
            raise ValueError(
                "DATABASE_URL must not use the default password in production. "
                "Set a secure database password."
            )
        return v

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, v: list[str]) -> list[str]:
        """Validate CORS origins in production."""
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production":
            insecure_origins = ["http://localhost", "http://127.0.0.1"]
            for origin in v:
                for insecure in insecure_origins:
                    if origin.startswith(insecure):
                        raise ValueError(
                            f"CORS_ORIGINS should not include localhost in production: {origin}"
                        )
        return v

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"


def validate_settings_on_startup(settings: "Settings") -> None:
    """Additional validation run on application startup."""
    if settings.is_production():
        # Ensure debug is disabled in production
        if settings.debug:
            raise ValueError("DEBUG must be False in production")

        # Warn about token expiration
        if settings.access_token_expire_minutes > 60:
            import warnings
            warnings.warn(
                f"ACCESS_TOKEN_EXPIRE_MINUTES is {settings.access_token_expire_minutes}. "
                "Consider a shorter expiration for production security."
            )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    validate_settings_on_startup(settings)
    return settings
