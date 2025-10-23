"""
Secure Password Management Module

Provides secure password hashing, verification, and management using industry-standard
cryptographic algorithms (bcrypt, argon2).
"""

import os
import secrets
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class PasswordPolicy:
    """Password policy configuration"""
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    max_age_days: int = 90
    prevent_reuse_count: int = 5
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 30


@dataclass
class PasswordMetadata:
    """Metadata for password management"""
    user_id: str
    password_hash: str
    algorithm: str
    created_at: datetime
    last_changed: datetime
    expires_at: Optional[datetime]
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    previous_hashes: list = None

    def __post_init__(self):
        if self.previous_hashes is None:
            self.previous_hashes = []


class PasswordManager:
    """
    Secure password management with bcrypt/argon2 hashing.

    Features:
    - Secure password hashing (bcrypt or argon2)
    - Password policy enforcement
    - Password expiration tracking
    - Failed login attempt tracking
    - Account lockout protection
    - Password history to prevent reuse
    """

    def __init__(self, policy: Optional[PasswordPolicy] = None, algorithm: str = "argon2"):
        """
        Initialize password manager.

        Args:
            policy: Password policy configuration
            algorithm: Hashing algorithm ('bcrypt' or 'argon2')
        """
        self.policy = policy or PasswordPolicy()
        self.algorithm = algorithm.lower()

        # Initialize hasher based on algorithm
        if self.algorithm == "argon2":
            if not ARGON2_AVAILABLE:
                logger.warning("argon2-cffi not available, falling back to bcrypt")
                self.algorithm = "bcrypt"
            else:
                self.argon2_hasher = PasswordHasher(
                    time_cost=3,  # Number of iterations
                    memory_cost=65536,  # Memory usage in KiB (64 MB)
                    parallelism=4,  # Number of parallel threads
                    hash_len=32,  # Length of hash in bytes
                    salt_len=16  # Length of salt in bytes
                )

        if self.algorithm == "bcrypt":
            if not BCRYPT_AVAILABLE:
                raise ImportError("bcrypt library not available. Install with: pip install bcrypt")
            self.bcrypt_rounds = 12  # Cost factor

        # In-memory storage (replace with database in production)
        self.password_store: Dict[str, PasswordMetadata] = {}

        logger.info(f"PasswordManager initialized with {self.algorithm} algorithm")

    def hash_password(self, password: str) -> str:
        """
        Hash a password using the configured algorithm.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        if self.algorithm == "argon2":
            return self.argon2_hasher.hash(password)
        elif self.algorithm == "bcrypt":
            salt = bcrypt.gensalt(rounds=self.bcrypt_rounds)
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password
            password_hash: Hashed password

        Returns:
            True if password matches, False otherwise
        """
        try:
            if self.algorithm == "argon2":
                self.argon2_hasher.verify(password_hash, password)
                return True
            elif self.algorithm == "bcrypt":
                return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except (VerifyMismatchError, VerificationError, InvalidHash, ValueError):
            return False

        return False

    def validate_password_policy(self, password: str) -> tuple[bool, list[str]]:
        """
        Validate password against policy.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, list of error messages)
        """
        errors = []

        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters")

        if self.policy.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if self.policy.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if self.policy.require_digits and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if self.policy.require_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")

        return len(errors) == 0, errors

    def set_password(self, user_id: str, password: str) -> tuple[bool, Optional[str]]:
        """
        Set password for a user with policy validation.

        Args:
            user_id: User identifier
            password: New password

        Returns:
            Tuple of (success, error_message)
        """
        # Validate password policy
        is_valid, errors = self.validate_password_policy(password)
        if not is_valid:
            return False, "; ".join(errors)

        # Check password history
        if user_id in self.password_store:
            metadata = self.password_store[user_id]
            for old_hash in metadata.previous_hashes[-self.policy.prevent_reuse_count:]:
                if self.verify_password(password, old_hash):
                    return False, f"Password was used recently. Cannot reuse last {self.policy.prevent_reuse_count} passwords"

        # Hash password
        password_hash = self.hash_password(password)

        # Create or update metadata
        now = datetime.utcnow()
        expires_at = now + timedelta(days=self.policy.max_age_days) if self.policy.max_age_days > 0 else None

        if user_id in self.password_store:
            # Update existing
            metadata = self.password_store[user_id]
            metadata.previous_hashes.append(metadata.password_hash)
            metadata.previous_hashes = metadata.previous_hashes[-self.policy.prevent_reuse_count:]
            metadata.password_hash = password_hash
            metadata.last_changed = now
            metadata.expires_at = expires_at
            metadata.failed_attempts = 0
            metadata.locked_until = None
        else:
            # Create new
            metadata = PasswordMetadata(
                user_id=user_id,
                password_hash=password_hash,
                algorithm=self.algorithm,
                created_at=now,
                last_changed=now,
                expires_at=expires_at,
                previous_hashes=[]
            )
            self.password_store[user_id] = metadata

        logger.info(f"Password set for user {user_id}")
        return True, None

    def authenticate(self, user_id: str, password: str) -> tuple[bool, Optional[str]]:
        """
        Authenticate a user with password.

        Args:
            user_id: User identifier
            password: Password to verify

        Returns:
            Tuple of (success, error_message)
        """
        if user_id not in self.password_store:
            return False, "User not found"

        metadata = self.password_store[user_id]

        # Check if account is locked
        if metadata.locked_until and datetime.utcnow() < metadata.locked_until:
            remaining = (metadata.locked_until - datetime.utcnow()).seconds // 60
            return False, f"Account locked. Try again in {remaining} minutes"

        # Check if password expired
        if metadata.expires_at and datetime.utcnow() > metadata.expires_at:
            return False, "Password expired. Please reset your password"

        # Verify password
        if self.verify_password(password, metadata.password_hash):
            # Success - reset failed attempts
            metadata.failed_attempts = 0
            metadata.locked_until = None
            logger.info(f"User {user_id} authenticated successfully")
            return True, None
        else:
            # Failed - increment attempts
            metadata.failed_attempts += 1

            if metadata.failed_attempts >= self.policy.max_failed_attempts:
                # Lock account
                metadata.locked_until = datetime.utcnow() + timedelta(minutes=self.policy.lockout_duration_minutes)
                logger.warning(f"User {user_id} account locked after {metadata.failed_attempts} failed attempts")
                return False, f"Too many failed attempts. Account locked for {self.policy.lockout_duration_minutes} minutes"

            remaining = self.policy.max_failed_attempts - metadata.failed_attempts
            logger.warning(f"Failed authentication for user {user_id}. {remaining} attempts remaining")
            return False, f"Invalid password. {remaining} attempts remaining"

    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate a cryptographically secure random password.

        Args:
            length: Password length

        Returns:
            Generated password
        """
        if length < self.policy.min_length:
            length = self.policy.min_length

        # Character sets
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Ensure at least one of each required type
        password = []
        if self.policy.require_uppercase:
            password.append(secrets.choice(uppercase))
        if self.policy.require_lowercase:
            password.append(secrets.choice(lowercase))
        if self.policy.require_digits:
            password.append(secrets.choice(digits))
        if self.policy.require_special:
            password.append(secrets.choice(special))

        # Fill remaining length
        all_chars = uppercase + lowercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - len(password)))

        # Shuffle
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)

        return ''.join(password_list)

    def check_password_expiration(self, user_id: str) -> tuple[bool, Optional[int]]:
        """
        Check if password is expired or expiring soon.

        Args:
            user_id: User identifier

        Returns:
            Tuple of (is_expired, days_until_expiration)
        """
        if user_id not in self.password_store:
            return False, None

        metadata = self.password_store[user_id]
        if not metadata.expires_at:
            return False, None

        now = datetime.utcnow()
        if now > metadata.expires_at:
            return True, 0

        days_remaining = (metadata.expires_at - now).days
        return False, days_remaining


# Global password manager instance
_password_manager: Optional[PasswordManager] = None


def get_password_manager(algorithm: str = "argon2") -> PasswordManager:
    """Get the global password manager instance."""
    global _password_manager
    if _password_manager is None:
        _password_manager = PasswordManager(algorithm=algorithm)
    return _password_manager
