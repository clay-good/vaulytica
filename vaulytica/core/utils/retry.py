"""Retry logic and error handling utilities."""

import time
import functools
from typing import Callable, TypeVar, Optional, Type, Tuple, Any
from dataclasses import dataclass

import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)

T = TypeVar("T")


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_attempts: int = 5
    initial_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True


class RetryableError(Exception):
    """Base class for errors that should trigger a retry."""

    pass


class RateLimitError(RetryableError):
    """Raised when API rate limit is hit."""

    pass


class QuotaExceededError(RetryableError):
    """Raised when API quota is exceeded."""

    pass


class TransientError(RetryableError):
    """Raised for transient errors that should be retried."""

    pass


class PermanentError(Exception):
    """Raised for permanent errors that should not be retried."""

    pass


def is_retryable_http_error(error: HttpError) -> bool:
    """Check if an HTTP error is retryable.

    Args:
        error: HttpError from Google API

    Returns:
        True if error should be retried
    """
    # Rate limit errors (429)
    if error.resp.status == 429:
        return True

    # Server errors (5xx)
    if 500 <= error.resp.status < 600:
        return True

    # Specific retryable errors
    retryable_reasons = [
        "rateLimitExceeded",
        "userRateLimitExceeded",
        "quotaExceeded",
        "backendError",
        "internalError",
    ]

    try:
        error_details = error.error_details
        if isinstance(error_details, list):
            for detail in error_details:
                if detail.get("reason") in retryable_reasons:
                    return True
    except (AttributeError, KeyError):
        pass

    return False


def calculate_backoff_delay(
    attempt: int,
    config: RetryConfig,
) -> float:
    """Calculate exponential backoff delay.

    Args:
        attempt: Current attempt number (0-indexed)
        config: Retry configuration

    Returns:
        Delay in seconds
    """
    import random

    # Exponential backoff
    delay = min(
        config.initial_delay * (config.exponential_base ** attempt),
        config.max_delay,
    )

    # Add jitter to prevent thundering herd
    if config.jitter:
        delay = delay * (0.5 + random.random() * 0.5)

    return delay


def retry_on_error(
    config: Optional[RetryConfig] = None,
    retryable_exceptions: Tuple[Type[Exception], ...] = (RetryableError, HttpError),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator to retry function on specific errors.

    Args:
        config: Retry configuration
        retryable_exceptions: Tuple of exception types to retry on

    Returns:
        Decorated function
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            last_exception = None

            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)

                except PermanentError:
                    # Don't retry permanent errors
                    raise

                except HttpError as e:
                    last_exception = e

                    # Check if retryable
                    if not is_retryable_http_error(e):
                        logger.error(
                            "non_retryable_http_error",
                            status=e.resp.status,
                            error=str(e),
                        )
                        raise

                    # Log and retry
                    delay = calculate_backoff_delay(attempt, config)

                    logger.warning(
                        "http_error_retrying",
                        attempt=attempt + 1,
                        max_attempts=config.max_attempts,
                        status=e.resp.status,
                        delay=delay,
                    )

                    if attempt < config.max_attempts - 1:
                        time.sleep(delay)

                except retryable_exceptions as e:
                    last_exception = e

                    delay = calculate_backoff_delay(attempt, config)

                    logger.warning(
                        "retryable_error",
                        attempt=attempt + 1,
                        max_attempts=config.max_attempts,
                        error=str(e),
                        delay=delay,
                    )

                    if attempt < config.max_attempts - 1:
                        time.sleep(delay)

            # All retries exhausted
            logger.error(
                "max_retries_exhausted",
                max_attempts=config.max_attempts,
                error=str(last_exception),
            )
            raise last_exception

        return wrapper

    return decorator


def with_error_handling(
    default_return: Optional[Any] = None,
    log_errors: bool = True,
) -> Callable[[Callable[..., T]], Callable[..., Optional[T]]]:
    """Decorator to handle errors gracefully.

    Args:
        default_return: Value to return on error
        log_errors: Whether to log errors

    Returns:
        Decorated function
    """

    def decorator(func: Callable[..., T]) -> Callable[..., Optional[T]]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Optional[T]:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    logger.error(
                        "function_error",
                        function=func.__name__,
                        error=str(e),
                        error_type=type(e).__name__,
                    )
                return default_return

        return wrapper

    return decorator


class CircuitBreaker:
    """Circuit breaker pattern for API calls."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        expected_exception: Type[Exception] = Exception,
    ):
        """Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type to track
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "closed"  # closed, open, half_open

        logger.info(
            "circuit_breaker_initialized",
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
        )

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Call function with circuit breaker protection.

        Args:
            func: Function to call
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            Exception: If circuit is open or function fails
        """
        if self.state == "open":
            # Check if recovery timeout has passed
            if (
                self.last_failure_time
                and time.time() - self.last_failure_time >= self.recovery_timeout
            ):
                self.state = "half_open"
                logger.info("circuit_breaker_half_open")
            else:
                raise Exception("Circuit breaker is open")

        try:
            result = func(*args, **kwargs)

            # Success - reset if in half_open state
            if self.state == "half_open":
                self.state = "closed"
                self.failure_count = 0
                logger.info("circuit_breaker_closed")

            return result

        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()

            logger.warning(
                "circuit_breaker_failure",
                failure_count=self.failure_count,
                threshold=self.failure_threshold,
            )

            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.error("circuit_breaker_opened")

            raise


def safe_api_call(
    func: Callable[..., T],
    *args: Any,
    config: Optional[RetryConfig] = None,
    **kwargs: Any,
) -> Optional[T]:
    """Safely call an API function with retry logic.

    Args:
        func: Function to call
        *args: Positional arguments
        config: Retry configuration
        **kwargs: Keyword arguments

    Returns:
        Function result or None on failure
    """
    if config is None:
        config = RetryConfig()

    @retry_on_error(config=config)
    def _wrapped():
        return func(*args, **kwargs)

    try:
        return _wrapped()
    except Exception as e:
        logger.error(
            "safe_api_call_failed",
            function=func.__name__,
            error=str(e),
        )
        return None

