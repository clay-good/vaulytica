"""Input validation utilities for CLI commands.

This module provides validation functions for common input types
used in the Vaulytica CLI.
"""

import re
from pathlib import Path
from typing import Optional


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def validate_email(email: str, allow_empty: bool = False) -> str:
    """Validate an email address format.

    Args:
        email: Email address to validate
        allow_empty: If True, empty strings are allowed

    Returns:
        The validated email address

    Raises:
        ValidationError: If the email format is invalid
    """
    if not email:
        if allow_empty:
            return email
        raise ValidationError("Email address cannot be empty")

    # Basic email regex - more permissive than RFC 5322 but catches obvious errors
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        raise ValidationError(f"Invalid email format: {email}")

    return email.lower()


def validate_domain(domain: str, allow_empty: bool = False) -> str:
    """Validate a domain name format.

    Args:
        domain: Domain name to validate
        allow_empty: If True, empty strings are allowed

    Returns:
        The validated domain name

    Raises:
        ValidationError: If the domain format is invalid
    """
    if not domain:
        if allow_empty:
            return domain
        raise ValidationError("Domain name cannot be empty")

    # Domain regex - supports subdomains
    domain_pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if not re.match(domain_pattern, domain):
        raise ValidationError(f"Invalid domain format: {domain}")

    return domain.lower()


def validate_file_path(path: str, must_exist: bool = False, must_be_file: bool = False) -> Path:
    """Validate a file path.

    Args:
        path: File path to validate
        must_exist: If True, the path must exist
        must_be_file: If True, the path must be a file (not directory)

    Returns:
        The validated Path object

    Raises:
        ValidationError: If the path is invalid or doesn't meet requirements
    """
    if not path:
        raise ValidationError("File path cannot be empty")

    try:
        file_path = Path(path).expanduser().resolve()
    except Exception as e:
        raise ValidationError(f"Invalid file path: {e}")

    if must_exist and not file_path.exists():
        raise ValidationError(f"File does not exist: {file_path}")

    if must_be_file and file_path.exists() and not file_path.is_file():
        raise ValidationError(f"Path is not a file: {file_path}")

    return file_path


def validate_directory_path(path: str, must_exist: bool = False) -> Path:
    """Validate a directory path.

    Args:
        path: Directory path to validate
        must_exist: If True, the directory must exist

    Returns:
        The validated Path object

    Raises:
        ValidationError: If the path is invalid or doesn't exist
    """
    if not path:
        raise ValidationError("Directory path cannot be empty")

    try:
        dir_path = Path(path).expanduser().resolve()
    except Exception as e:
        raise ValidationError(f"Invalid directory path: {e}")

    if must_exist and not dir_path.exists():
        raise ValidationError(f"Directory does not exist: {dir_path}")

    if dir_path.exists() and not dir_path.is_dir():
        raise ValidationError(f"Path is not a directory: {dir_path}")

    return dir_path


def validate_positive_integer(value: int, name: str = "value") -> int:
    """Validate that a value is a positive integer.

    Args:
        value: Value to validate
        name: Name of the parameter (for error messages)

    Returns:
        The validated integer

    Raises:
        ValidationError: If the value is not a positive integer
    """
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")

    if value < 1:
        raise ValidationError(f"{name} must be a positive integer (got {value})")

    return value


def validate_percentage(value: int, name: str = "value") -> int:
    """Validate that a value is a percentage (0-100).

    Args:
        value: Value to validate
        name: Name of the parameter (for error messages)

    Returns:
        The validated percentage

    Raises:
        ValidationError: If the value is not between 0 and 100
    """
    if not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")

    if value < 0 or value > 100:
        raise ValidationError(f"{name} must be between 0 and 100 (got {value})")

    return value


def validate_scan_type(scan_type: str) -> str:
    """Validate a scan type.

    Args:
        scan_type: Scan type to validate

    Returns:
        The validated scan type

    Raises:
        ValidationError: If the scan type is invalid
    """
    valid_types = ["files", "users", "oauth", "posture", "all"]
    scan_type_lower = scan_type.lower()

    if scan_type_lower not in valid_types:
        raise ValidationError(
            f"Invalid scan type: {scan_type}. "
            f"Valid types are: {', '.join(valid_types)}"
        )

    return scan_type_lower


def validate_output_format(format: str) -> str:
    """Validate an output format.

    Args:
        format: Output format to validate

    Returns:
        The validated format

    Raises:
        ValidationError: If the format is invalid
    """
    valid_formats = ["csv", "json", "html"]
    format_lower = format.lower()

    if format_lower not in valid_formats:
        raise ValidationError(
            f"Invalid output format: {format}. "
            f"Valid formats are: {', '.join(valid_formats)}"
        )

    return format_lower


def validate_database_url(url: str) -> str:
    """Validate a database URL format.

    Args:
        url: Database URL to validate

    Returns:
        The validated URL

    Raises:
        ValidationError: If the URL format is invalid
    """
    if not url:
        raise ValidationError("Database URL cannot be empty")

    # Check for common database URL prefixes
    valid_prefixes = [
        "postgresql://",
        "postgres://",
        "sqlite:///",
        "mysql://",
        "mysql+pymysql://",
    ]

    if not any(url.startswith(prefix) for prefix in valid_prefixes):
        raise ValidationError(
            f"Invalid database URL format. "
            f"Expected URL starting with one of: {', '.join(valid_prefixes)}"
        )

    return url
