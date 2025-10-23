"""
Secrets Management Module

Provides secure secrets management with support for:
- Environment variables
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- GCP Secret Manager
- Encrypted local storage
"""

import os
import json
import base64
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass
from enum import Enum
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class SecretBackend(str, Enum):
    """Supported secret backends"""
    ENVIRONMENT = "environment"
    VAULT = "vault"
    AWS_SECRETS = "aws_secrets"
    AZURE_KEYVAULT = "azure_keyvault"
    GCP_SECRET = "gcp_secret"
    ENCRYPTED_FILE = "encrypted_file"


@dataclass
class SecretConfig:
    """Configuration for secrets management"""
    backend: SecretBackend = SecretBackend.ENVIRONMENT

    # Vault configuration
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    vault_namespace: Optional[str] = None

    # AWS configuration
    aws_region: Optional[str] = None
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None

    # Azure configuration
    azure_vault_url: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None

    # GCP configuration
    gcp_project_id: Optional[str] = None
    gcp_credentials_path: Optional[str] = None

    # Encrypted file configuration
    encryption_key: Optional[str] = None
    secrets_file_path: str = ".secrets.enc"


class SecretsManager:
    """
    Unified secrets management interface.

    Supports multiple backends for storing and retrieving secrets securely.
    """

    def __init__(self, config: Optional[SecretConfig] = None):
        """
        Initialize secrets manager.

        Args:
            config: Secrets configuration
        """
        self.config = config or SecretConfig()
        self.backend = self.config.backend

        # Initialize backend-specific clients
        self._vault_client = None
        self._aws_client = None
        self._azure_client = None
        self._gcp_client = None
        self._fernet = None

        # In-memory cache
        self._cache: Dict[str, Any] = {}

        self._initialize_backend()
        logger.info(f"SecretsManager initialized with {self.backend} backend")

    def _initialize_backend(self):
        """Initialize the configured backend"""
        if self.backend == SecretBackend.VAULT:
            self._initialize_vault()
        elif self.backend == SecretBackend.AWS_SECRETS:
            self._initialize_aws()
        elif self.backend == SecretBackend.AZURE_KEYVAULT:
            self._initialize_azure()
        elif self.backend == SecretBackend.GCP_SECRET:
            self._initialize_gcp()
        elif self.backend == SecretBackend.ENCRYPTED_FILE:
            self._initialize_encrypted_file()

    def _initialize_vault(self):
        """Initialize HashiCorp Vault client"""
        try:
            import hvac
            self._vault_client = hvac.Client(
                url=self.config.vault_url or os.getenv("VAULT_ADDR"),
                token=self.config.vault_token or os.getenv("VAULT_TOKEN"),
                namespace=self.config.vault_namespace
            )
            if not self._vault_client.is_authenticated():
                logger.error("Vault authentication failed")
        except ImportError:
            logger.error("hvac library not installed. Install with: pip install hvac")
        except Exception as e:
            logger.error(f"Failed to initialize Vault: {e}")

    def _initialize_aws(self):
        """Initialize AWS Secrets Manager client"""
        try:
            import boto3
            self._aws_client = boto3.client(
                'secretsmanager',
                region_name=self.config.aws_region or os.getenv("AWS_REGION", "us-east-1"),
                aws_access_key_id=self.config.aws_access_key or os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=self.config.aws_secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
            )
        except ImportError:
            logger.error("boto3 library not installed. Install with: pip install boto3")
        except Exception as e:
            logger.error(f"Failed to initialize AWS Secrets Manager: {e}")

    def _initialize_azure(self):
        """Initialize Azure Key Vault client"""
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import ClientSecretCredential

            credential = ClientSecretCredential(
                tenant_id=self.config.azure_tenant_id or os.getenv("AZURE_TENANT_ID"),
                client_id=self.config.azure_client_id or os.getenv("AZURE_CLIENT_ID"),
                client_secret=self.config.azure_client_secret or os.getenv("AZURE_CLIENT_SECRET")
            )

            self._azure_client = SecretClient(
                vault_url=self.config.azure_vault_url or os.getenv("AZURE_VAULT_URL"),
                credential=credential
            )
        except ImportError:
            logger.error("azure-keyvault-secrets library not installed. Install with: pip install azure-keyvault-secrets azure-identity")
        except Exception as e:
            logger.error(f"Failed to initialize Azure Key Vault: {e}")

    def _initialize_gcp(self):
        """Initialize GCP Secret Manager client"""
        try:
            from google.cloud import secretmanager
            self._gcp_client = secretmanager.SecretManagerServiceClient()
        except ImportError:
            logger.error("google-cloud-secret-manager library not installed. Install with: pip install google-cloud-secret-manager")
        except Exception as e:
            logger.error(f"Failed to initialize GCP Secret Manager: {e}")

    def _initialize_encrypted_file(self):
        """Initialize encrypted file storage"""
        try:
            # Derive encryption key from password or use provided key
            key = self.config.encryption_key or os.getenv("SECRETS_ENCRYPTION_KEY")
            if not key:
                logger.warning("No encryption key provided, generating new key")
                key = Fernet.generate_key().decode()
                logger.info(f"Generated encryption key: {key}")

            if isinstance(key, str):
                # Derive key from password
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'vaulytica_salt',  # In production, use random salt
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(key.encode()))

            self._fernet = Fernet(key)
        except Exception as e:
            logger.error(f"Failed to initialize encrypted file storage: {e}")

    def get_secret(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Get a secret value.

        Args:
            key: Secret key
            default: Default value if secret not found

        Returns:
            Secret value or default
        """
        # Check cache first
        if key in self._cache:
            return self._cache[key]

        value = None

        try:
            if self.backend == SecretBackend.ENVIRONMENT:
                value = os.getenv(key, default)

            elif self.backend == SecretBackend.VAULT and self._vault_client:
                response = self._vault_client.secrets.kv.v2.read_secret_version(path=key)
                value = response['data']['data'].get('value', default)

            elif self.backend == SecretBackend.AWS_SECRETS and self._aws_client:
                response = self._aws_client.get_secret_value(SecretId=key)
                value = response.get('SecretString', default)

            elif self.backend == SecretBackend.AZURE_KEYVAULT and self._azure_client:
                secret = self._azure_client.get_secret(key)
                value = secret.value

            elif self.backend == SecretBackend.GCP_SECRET and self._gcp_client:
                project_id = self.config.gcp_project_id or os.getenv("GCP_PROJECT_ID")
                name = f"projects/{project_id}/secrets/{key}/versions/latest"
                response = self._gcp_client.access_secret_version(request={"name": name})
                value = response.payload.data.decode('UTF-8')

            elif self.backend == SecretBackend.ENCRYPTED_FILE and self._fernet:
                value = self._load_from_encrypted_file(key, default)

            # Cache the value
            if value is not None:
                self._cache[key] = value

        except Exception as e:
            logger.error(f"Failed to get secret '{key}': {e}")
            value = default

        return value

    def set_secret(self, key: str, value: Any) -> bool:
        """
        Set a secret value.

        Args:
            key: Secret key
            value: Secret value

        Returns:
            True if successful
        """
        try:
            if self.backend == SecretBackend.VAULT and self._vault_client:
                self._vault_client.secrets.kv.v2.create_or_update_secret(
                    path=key,
                    secret={'value': value}
                )

            elif self.backend == SecretBackend.AWS_SECRETS and self._aws_client:
                self._aws_client.put_secret_value(
                    SecretId=key,
                    SecretString=str(value)
                )

            elif self.backend == SecretBackend.AZURE_KEYVAULT and self._azure_client:
                self._azure_client.set_secret(key, str(value))

            elif self.backend == SecretBackend.GCP_SECRET and self._gcp_client:
                project_id = self.config.gcp_project_id or os.getenv("GCP_PROJECT_ID")
                parent = f"projects/{project_id}/secrets/{key}"
                self._gcp_client.add_secret_version(
                    request={
                        "parent": parent,
                        "payload": {"data": str(value).encode('UTF-8')}
                    }
                )

            elif self.backend == SecretBackend.ENCRYPTED_FILE and self._fernet:
                self._save_to_encrypted_file(key, value)

            # Update cache
            self._cache[key] = value
            logger.info(f"Secret '{key}' set successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to set secret '{key}': {e}")
            return False

    def _load_from_encrypted_file(self, key: str, default: Any = None) -> Optional[Any]:
        """Load secret from encrypted file"""
        try:
            if not os.path.exists(self.config.secrets_file_path):
                return default

            with open(self.config.secrets_file_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = self._fernet.decrypt(encrypted_data)
            secrets = json.loads(decrypted_data.decode())
            return secrets.get(key, default)
        except Exception as e:
            logger.error(f"Failed to load from encrypted file: {e}")
            return default

    def _save_to_encrypted_file(self, key: str, value: Any):
        """Save secret to encrypted file"""
        try:
            # Load existing secrets
            secrets = {}
            if os.path.exists(self.config.secrets_file_path):
                with open(self.config.secrets_file_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self._fernet.decrypt(encrypted_data)
                secrets = json.loads(decrypted_data.decode())

            # Update secret
            secrets[key] = value

            # Encrypt and save
            encrypted_data = self._fernet.encrypt(json.dumps(secrets).encode())
            with open(self.config.secrets_file_path, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to save to encrypted file: {e}")

    def delete_secret(self, key: str) -> bool:
        """Delete a secret"""
        try:
            if key in self._cache:
                del self._cache[key]

            # Backend-specific deletion would go here
            logger.info(f"Secret '{key}' deleted from cache")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret '{key}': {e}")
            return False

    def clear_cache(self) -> None:
        """Clear the secrets cache"""
        self._cache.clear()
        logger.info("Secrets cache cleared")


# Global secrets manager instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager(config: Optional[SecretConfig] = None) -> SecretsManager:
    """Get the global secrets manager instance."""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager(config)
    return _secrets_manager


def get_secret(key: str, default: Any = None) -> Optional[Any]:
    """Convenience function to get a secret"""
    return get_secrets_manager().get_secret(key, default)


def set_secret(key: str, value: Any) -> bool:
    """Convenience function to set a secret"""
    return get_secrets_manager().set_secret(key, value)
