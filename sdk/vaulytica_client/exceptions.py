"""
Vaulytica API Client Exceptions
"""


class VaulyticaError(Exception):
    """Base exception for Vaulytica API errors."""

    def __init__(self, message: str, status_code: int | None = None, response: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response = response or {}

    def __str__(self) -> str:
        if self.status_code:
            return f"[{self.status_code}] {self.message}"
        return self.message


class AuthenticationError(VaulyticaError):
    """Raised when authentication fails (401)."""

    pass


class AuthorizationError(VaulyticaError):
    """Raised when user lacks permission (403)."""

    pass


class NotFoundError(VaulyticaError):
    """Raised when a resource is not found (404)."""

    pass


class RateLimitError(VaulyticaError):
    """Raised when rate limit is exceeded (429)."""

    def __init__(
        self, message: str, retry_after: int | None = None, **kwargs
    ):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ValidationError(VaulyticaError):
    """Raised when request validation fails (422)."""

    def __init__(self, message: str, errors: list | None = None, **kwargs):
        super().__init__(message, **kwargs)
        self.errors = errors or []


class ConnectionError(VaulyticaError):
    """Raised when connection to API fails."""

    pass


class TimeoutError(VaulyticaError):
    """Raised when request times out."""

    pass
