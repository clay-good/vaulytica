"""
Vaulytica Security Module

Provides security utilities including:
- Password management with bcrypt/argon2
- Secrets management with multiple backends
- Encryption utilities
- Authentication and authorization
"""

from .password_manager import (
    PasswordManager,
    PasswordPolicy,
    PasswordMetadata,
    get_password_manager
)

from .secrets_manager import (
    SecretsManager,
    SecretConfig,
    SecretBackend,
    get_secrets_manager,
    get_secret,
    set_secret
)

__all__ = [
    # Password management
    'PasswordManager',
    'PasswordPolicy',
    'PasswordMetadata',
    'get_password_manager',

    # Secrets management
    'SecretsManager',
    'SecretConfig',
    'SecretBackend',
    'get_secrets_manager',
    'get_secret',
    'set_secret',
]
