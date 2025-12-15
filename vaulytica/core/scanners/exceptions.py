"""Custom exceptions for scanner modules.

This module defines specific exception types to replace bare Exception catches,
enabling better error handling and categorization.
"""


class ScannerError(Exception):
    """Base exception for all scanner errors."""

    pass


class NetworkError(ScannerError):
    """Raised when a network-related error occurs during scanning.

    This includes:
    - Connection timeouts
    - DNS resolution failures
    - SSL/TLS errors
    - HTTP 5xx errors
    """

    pass


class AuthenticationError(ScannerError):
    """Raised when authentication fails during scanning.

    This includes:
    - Invalid credentials
    - Expired tokens
    - HTTP 401 errors
    """

    pass


class PermissionError(ScannerError):
    """Raised when insufficient permissions prevent scanning.

    This includes:
    - HTTP 403 errors
    - Missing required scopes
    - Admin access required
    """

    pass


class RateLimitError(ScannerError):
    """Raised when API rate limits are exceeded.

    This includes:
    - HTTP 429 errors
    - Quota exceeded errors
    """

    pass


class ValidationError(ScannerError):
    """Raised when input validation fails.

    This includes:
    - Invalid email formats
    - Invalid domain names
    - Invalid parameter values
    """

    pass


class ResourceNotFoundError(ScannerError):
    """Raised when a requested resource is not found.

    This includes:
    - HTTP 404 errors
    - User not found
    - File not found
    """

    pass


class APIError(ScannerError):
    """Raised when an API returns an unexpected error.

    This is used for API errors that don't fit other categories.
    """

    def __init__(self, message: str, status_code: int = None, response: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response
