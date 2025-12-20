"""
Secret Management for Vaulytica

This module provides a pluggable secret management system that supports
multiple backends for securely storing and retrieving secrets.

Supported backends:
- Environment variables (default)
- File-based secrets (Kubernetes secrets, Docker secrets)
- HashiCorp Vault
- AWS Secrets Manager

Usage:
    from core.secrets import get_secret_manager

    secrets = get_secret_manager()
    db_password = secrets.get("DATABASE_PASSWORD")
"""

import os
import json
import base64
from abc import ABC, abstractmethod
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from .logging import get_logger

logger = get_logger(__name__)


class SecretBackend(ABC):
    """Abstract base class for secret backends."""

    @abstractmethod
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a secret value by key."""
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if a secret exists."""
        pass

    def get_json(self, key: str, default: Optional[dict] = None) -> Optional[dict]:
        """Get a secret value and parse it as JSON."""
        value = self.get(key)
        if value is None:
            return default
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse secret {key} as JSON")
            return default


class EnvironmentSecretBackend(SecretBackend):
    """
    Secret backend that reads from environment variables.

    This is the default backend and is suitable for development
    and simple deployments.
    """

    def __init__(self, prefix: str = ""):
        """
        Initialize environment backend.

        Args:
            prefix: Optional prefix for environment variable names
        """
        self.prefix = prefix

    def _get_key(self, key: str) -> str:
        """Get the full environment variable name."""
        if self.prefix:
            return f"{self.prefix}_{key}"
        return key

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from environment variable."""
        full_key = self._get_key(key)
        return os.environ.get(full_key, default)

    def exists(self, key: str) -> bool:
        """Check if environment variable exists."""
        full_key = self._get_key(key)
        return full_key in os.environ


class FileSecretBackend(SecretBackend):
    """
    Secret backend that reads from files.

    This is compatible with:
    - Kubernetes secrets mounted as files
    - Docker secrets (/run/secrets/)
    - Any file-based secret system
    """

    def __init__(self, secrets_dir: str = "/run/secrets"):
        """
        Initialize file backend.

        Args:
            secrets_dir: Directory containing secret files
        """
        self.secrets_dir = Path(secrets_dir)

    def _get_path(self, key: str) -> Path:
        """Get the file path for a secret."""
        # Convert key to filename (lowercase, underscores)
        filename = key.lower().replace("-", "_")
        # Sanitize to prevent path traversal
        filename = filename.replace("..", "").replace("/", "").replace("\\", "")
        path = self.secrets_dir / filename
        # Verify path is within secrets directory
        if not path.resolve().is_relative_to(self.secrets_dir.resolve()):
            raise ValueError(f"Invalid secret key: {key}")
        return path

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from file."""
        path = self._get_path(key)
        if not path.exists():
            return default
        try:
            return path.read_text().strip()
        except Exception as e:
            logger.warning(f"Failed to read secret file {path}: {e}")
            return default

    def exists(self, key: str) -> bool:
        """Check if secret file exists."""
        return self._get_path(key).exists()


class VaultSecretBackend(SecretBackend):
    """
    Secret backend that reads from HashiCorp Vault.

    Requires:
    - hvac library: pip install hvac
    - VAULT_ADDR environment variable
    - VAULT_TOKEN environment variable (or other auth method)
    """

    def __init__(
        self,
        addr: Optional[str] = None,
        token: Optional[str] = None,
        mount_point: str = "secret",
        path_prefix: str = "vaulytica",
    ):
        """
        Initialize Vault backend.

        Args:
            addr: Vault server address (default: VAULT_ADDR env var)
            token: Vault token (default: VAULT_TOKEN env var)
            mount_point: KV secrets engine mount point
            path_prefix: Path prefix for secrets
        """
        self.mount_point = mount_point
        self.path_prefix = path_prefix
        self._client = None

        try:
            import hvac
            self._hvac = hvac
            self.addr = addr or os.environ.get("VAULT_ADDR", "http://localhost:8200")
            self.token = token or os.environ.get("VAULT_TOKEN")
        except ImportError:
            logger.warning("hvac library not installed, Vault backend unavailable")
            self._hvac = None

    @property
    def client(self):
        """Get or create Vault client."""
        if self._client is None and self._hvac:
            self._client = self._hvac.Client(url=self.addr, token=self.token)
        return self._client

    def _get_path(self, key: str) -> str:
        """Get the Vault path for a secret."""
        return f"{self.path_prefix}/{key.lower()}"

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from Vault."""
        if not self.client:
            return default

        path = self._get_path(key)
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point,
            )
            data = response.get("data", {}).get("data", {})
            return data.get("value", default)
        except Exception as e:
            logger.debug(f"Failed to read secret from Vault {path}: {e}")
            return default

    def exists(self, key: str) -> bool:
        """Check if secret exists in Vault."""
        return self.get(key) is not None


class AWSSecretsBackend(SecretBackend):
    """
    Secret backend that reads from AWS Secrets Manager.

    Requires:
    - boto3 library: pip install boto3
    - AWS credentials configured
    """

    def __init__(
        self,
        region: Optional[str] = None,
        prefix: str = "vaulytica",
    ):
        """
        Initialize AWS Secrets Manager backend.

        Args:
            region: AWS region (default: from environment)
            prefix: Prefix for secret names
        """
        self.prefix = prefix
        self._client = None

        try:
            import boto3
            self._boto3 = boto3
            self.region = region or os.environ.get("AWS_REGION", "us-east-1")
        except ImportError:
            logger.warning("boto3 library not installed, AWS Secrets Manager backend unavailable")
            self._boto3 = None

    @property
    def client(self):
        """Get or create AWS Secrets Manager client."""
        if self._client is None and self._boto3:
            self._client = self._boto3.client(
                "secretsmanager",
                region_name=self.region,
            )
        return self._client

    def _get_secret_name(self, key: str) -> str:
        """Get the AWS secret name."""
        return f"{self.prefix}/{key.lower()}"

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from AWS Secrets Manager."""
        if not self.client:
            return default

        secret_name = self._get_secret_name(key)
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            if "SecretString" in response:
                return response["SecretString"]
            elif "SecretBinary" in response:
                return base64.b64decode(response["SecretBinary"]).decode("utf-8")
            return default
        except Exception as e:
            logger.debug(f"Failed to read secret from AWS {secret_name}: {e}")
            return default

    def exists(self, key: str) -> bool:
        """Check if secret exists in AWS Secrets Manager."""
        return self.get(key) is not None


class ChainedSecretBackend(SecretBackend):
    """
    Secret backend that chains multiple backends together.

    Secrets are looked up in order until one is found.
    """

    def __init__(self, backends: list[SecretBackend]):
        """
        Initialize chained backend.

        Args:
            backends: List of backends to chain, in priority order
        """
        self.backends = backends

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get secret from first backend that has it."""
        for backend in self.backends:
            value = backend.get(key)
            if value is not None:
                return value
        return default

    def exists(self, key: str) -> bool:
        """Check if any backend has the secret."""
        return any(backend.exists(key) for backend in self.backends)


class SecretManager:
    """
    High-level secret manager that provides a convenient interface
    for accessing secrets with caching and validation.
    """

    def __init__(self, backend: SecretBackend):
        """
        Initialize secret manager.

        Args:
            backend: Secret backend to use
        """
        self.backend = backend
        self._cache: dict[str, str] = {}
        self._cache_enabled = True

    def get(
        self,
        key: str,
        default: Optional[str] = None,
        required: bool = False,
        cache: bool = True,
    ) -> Optional[str]:
        """
        Get a secret value.

        Args:
            key: Secret key
            default: Default value if not found
            required: Raise error if not found
            cache: Whether to cache the result

        Returns:
            Secret value

        Raises:
            ValueError: If required=True and secret not found
        """
        # Check cache
        if cache and self._cache_enabled and key in self._cache:
            return self._cache[key]

        value = self.backend.get(key, default)

        if value is None and required:
            raise ValueError(f"Required secret '{key}' not found")

        # Cache the result
        if cache and self._cache_enabled and value is not None:
            self._cache[key] = value

        return value

    def get_json(
        self,
        key: str,
        default: Optional[dict] = None,
        required: bool = False,
    ) -> Optional[dict]:
        """
        Get a secret value and parse as JSON.

        Args:
            key: Secret key
            default: Default value if not found
            required: Raise error if not found

        Returns:
            Parsed JSON value
        """
        value = self.get(key, required=required, cache=False)
        if value is None:
            return default
        try:
            return json.loads(value)
        except json.JSONDecodeError as e:
            if required:
                raise ValueError(f"Secret '{key}' is not valid JSON: {e}")
            return default

    def exists(self, key: str) -> bool:
        """Check if a secret exists."""
        if key in self._cache:
            return True
        return self.backend.exists(key)

    def clear_cache(self):
        """Clear the secret cache."""
        self._cache.clear()

    def disable_cache(self):
        """Disable caching."""
        self._cache_enabled = False
        self._cache.clear()

    def enable_cache(self):
        """Enable caching."""
        self._cache_enabled = True


def create_secret_backend(backend_type: str = "env", **kwargs) -> SecretBackend:
    """
    Create a secret backend by type.

    Args:
        backend_type: Type of backend (env, file, vault, aws, chained)
        **kwargs: Backend-specific arguments

    Returns:
        Configured secret backend
    """
    if backend_type == "env":
        return EnvironmentSecretBackend(**kwargs)
    elif backend_type == "file":
        return FileSecretBackend(**kwargs)
    elif backend_type == "vault":
        return VaultSecretBackend(**kwargs)
    elif backend_type == "aws":
        return AWSSecretsBackend(**kwargs)
    elif backend_type == "chained":
        # Default chain: file -> env
        backends = [
            FileSecretBackend(kwargs.get("secrets_dir", "/run/secrets")),
            EnvironmentSecretBackend(kwargs.get("prefix", "")),
        ]
        return ChainedSecretBackend(backends)
    else:
        raise ValueError(f"Unknown secret backend type: {backend_type}")


@lru_cache
def get_secret_manager() -> SecretManager:
    """
    Get the configured secret manager instance.

    The backend is determined by the SECRET_BACKEND environment variable:
    - env: Environment variables (default)
    - file: File-based secrets
    - vault: HashiCorp Vault
    - aws: AWS Secrets Manager
    - chained: Chain of file -> env

    Returns:
        Configured secret manager
    """
    backend_type = os.environ.get("SECRET_BACKEND", "chained")
    logger.info(f"Initializing secret manager with backend: {backend_type}")

    backend = create_secret_backend(backend_type)
    return SecretManager(backend)


# Convenience function for quick secret access
def get_secret(key: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """
    Get a secret value using the default secret manager.

    Args:
        key: Secret key
        default: Default value if not found
        required: Raise error if not found

    Returns:
        Secret value
    """
    return get_secret_manager().get(key, default=default, required=required)
