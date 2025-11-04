"""Utility modules for Vaulytica."""

from vaulytica.core.utils.retry import (
    RetryConfig,
    RetryableError,
    RateLimitError,
    QuotaExceededError,
    TransientError,
    PermanentError,
    retry_on_error,
    with_error_handling,
    CircuitBreaker,
    safe_api_call,
)

from vaulytica.core.utils.rate_limiter import (
    QuotaConfig,
    RateLimitBucket,
    RateLimiter,
    AdaptiveRateLimiter,
)

__all__ = [
    # Retry utilities
    "RetryConfig",
    "RetryableError",
    "RateLimitError",
    "QuotaExceededError",
    "TransientError",
    "PermanentError",
    "retry_on_error",
    "with_error_handling",
    "CircuitBreaker",
    "safe_api_call",
    # Rate limiting
    "QuotaConfig",
    "RateLimitBucket",
    "RateLimiter",
    "AdaptiveRateLimiter",
]

