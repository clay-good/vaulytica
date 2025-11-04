"""Rate limiting and quota management for Google API calls."""

import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from threading import Lock
from collections import deque

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class QuotaConfig:
    """Configuration for API quota limits."""

    # Google Workspace API default quotas (per 100 seconds)
    drive_queries_per_100s: int = 1000
    drive_queries_per_user_per_100s: int = 1000
    admin_queries_per_100s: int = 2400
    gmail_queries_per_100s: int = 250

    # Safety margin (percentage of quota to use)
    safety_margin: float = 0.8


@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting."""

    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    lock: Lock = field(default_factory=Lock, init=False)

    def __post_init__(self):
        """Initialize bucket."""
        self.tokens = float(self.capacity)
        self.last_refill = time.time()

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill

        # Add tokens based on refill rate
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    def consume(self, tokens: int = 1, block: bool = True) -> bool:
        """Consume tokens from bucket.

        Args:
            tokens: Number of tokens to consume
            block: Whether to block until tokens are available

        Returns:
            True if tokens were consumed, False otherwise
        """
        with self.lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            if not block:
                return False

            # Calculate wait time
            tokens_needed = tokens - self.tokens
            wait_time = tokens_needed / self.refill_rate

            logger.debug(
                "rate_limit_waiting",
                tokens_needed=tokens_needed,
                wait_time=wait_time,
            )

        # Wait outside the lock
        time.sleep(wait_time)

        # Try again
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

        return False

    def get_available_tokens(self) -> float:
        """Get number of available tokens.

        Returns:
            Number of available tokens
        """
        with self.lock:
            self._refill()
            return self.tokens


class RateLimiter:
    """Rate limiter for Google Workspace API calls."""

    def __init__(self, config: Optional[QuotaConfig] = None):
        """Initialize rate limiter.

        Args:
            config: Quota configuration
        """
        self.config = config or QuotaConfig()

        # Create buckets for different API types
        # Convert per-100s limits to per-second rates
        self.buckets: Dict[str, RateLimitBucket] = {
            "drive": RateLimitBucket(
                capacity=int(self.config.drive_queries_per_100s * self.config.safety_margin),
                refill_rate=self.config.drive_queries_per_100s * self.config.safety_margin / 100,
            ),
            "admin": RateLimitBucket(
                capacity=int(self.config.admin_queries_per_100s * self.config.safety_margin),
                refill_rate=self.config.admin_queries_per_100s * self.config.safety_margin / 100,
            ),
            "gmail": RateLimitBucket(
                capacity=int(self.config.gmail_queries_per_100s * self.config.safety_margin),
                refill_rate=self.config.gmail_queries_per_100s * self.config.safety_margin / 100,
            ),
        }

        # Per-user rate limiting
        self.user_buckets: Dict[str, RateLimitBucket] = {}
        self.user_bucket_lock = Lock()

        # Quota tracking
        self.quota_usage: Dict[str, int] = {
            "drive": 0,
            "admin": 0,
            "gmail": 0,
        }
        self.quota_lock = Lock()

        logger.info("rate_limiter_initialized", config=self.config)

    def _get_user_bucket(self, user_email: str) -> RateLimitBucket:
        """Get or create rate limit bucket for a user.

        Args:
            user_email: User email

        Returns:
            RateLimitBucket for the user
        """
        with self.user_bucket_lock:
            if user_email not in self.user_buckets:
                self.user_buckets[user_email] = RateLimitBucket(
                    capacity=int(
                        self.config.drive_queries_per_user_per_100s
                        * self.config.safety_margin
                    ),
                    refill_rate=self.config.drive_queries_per_user_per_100s
                    * self.config.safety_margin
                    / 100,
                )
            return self.user_buckets[user_email]

    def acquire(
        self,
        api_type: str,
        user_email: Optional[str] = None,
        tokens: int = 1,
        block: bool = True,
    ) -> bool:
        """Acquire rate limit tokens.

        Args:
            api_type: API type (drive, admin, gmail)
            user_email: User email for per-user rate limiting
            tokens: Number of tokens to acquire
            block: Whether to block until tokens are available

        Returns:
            True if tokens were acquired
        """
        # Check global bucket
        bucket = self.buckets.get(api_type)
        if not bucket:
            logger.warning("unknown_api_type", api_type=api_type)
            return True

        if not bucket.consume(tokens, block):
            return False

        # Check per-user bucket for Drive API
        if api_type == "drive" and user_email:
            user_bucket = self._get_user_bucket(user_email)
            if not user_bucket.consume(tokens, block):
                # Refund global bucket
                with bucket.lock:
                    bucket.tokens = min(bucket.capacity, bucket.tokens + tokens)
                return False

        # Track quota usage
        with self.quota_lock:
            self.quota_usage[api_type] += tokens

        return True

    def get_quota_usage(self) -> Dict[str, int]:
        """Get current quota usage.

        Returns:
            Dictionary of quota usage by API type
        """
        with self.quota_lock:
            return self.quota_usage.copy()

    def get_available_capacity(self, api_type: str) -> float:
        """Get available capacity for an API type.

        Args:
            api_type: API type

        Returns:
            Available tokens
        """
        bucket = self.buckets.get(api_type)
        if not bucket:
            return 0.0

        return bucket.get_available_tokens()

    def reset_quota_tracking(self) -> None:
        """Reset quota usage tracking."""
        with self.quota_lock:
            self.quota_usage = {
                "drive": 0,
                "admin": 0,
                "gmail": 0,
            }
        logger.info("quota_tracking_reset")


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on API responses."""

    def __init__(self, initial_rate: float = 10.0, min_rate: float = 1.0, max_rate: float = 100.0):
        """Initialize adaptive rate limiter.

        Args:
            initial_rate: Initial requests per second
            min_rate: Minimum requests per second
            max_rate: Maximum requests per second
        """
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate

        self.success_count = 0
        self.failure_count = 0

        self.last_request_time = 0.0
        self.lock = Lock()

        logger.info(
            "adaptive_rate_limiter_initialized",
            initial_rate=initial_rate,
            min_rate=min_rate,
            max_rate=max_rate,
        )

    def acquire(self) -> None:
        """Acquire permission to make a request."""
        with self.lock:
            now = time.time()

            # Calculate required delay
            delay = 1.0 / self.current_rate

            # Wait if needed
            if self.last_request_time > 0:
                elapsed = now - self.last_request_time
                if elapsed < delay:
                    time.sleep(delay - elapsed)

            self.last_request_time = time.time()

    def report_success(self) -> None:
        """Report a successful request."""
        with self.lock:
            self.success_count += 1

            # Gradually increase rate on success
            if self.success_count >= 10:
                self.current_rate = min(self.max_rate, self.current_rate * 1.1)
                self.success_count = 0

                logger.debug("rate_increased", current_rate=self.current_rate)

    def report_failure(self, is_rate_limit: bool = False) -> None:
        """Report a failed request.

        Args:
            is_rate_limit: Whether failure was due to rate limiting
        """
        with self.lock:
            self.failure_count += 1

            # Decrease rate on failure
            if is_rate_limit:
                # Aggressive decrease for rate limit errors
                self.current_rate = max(self.min_rate, self.current_rate * 0.5)
                logger.warning("rate_decreased_rate_limit", current_rate=self.current_rate)
            else:
                # Gradual decrease for other errors
                if self.failure_count >= 3:
                    self.current_rate = max(self.min_rate, self.current_rate * 0.9)
                    self.failure_count = 0
                    logger.debug("rate_decreased_errors", current_rate=self.current_rate)

    def get_current_rate(self) -> float:
        """Get current rate limit.

        Returns:
            Current requests per second
        """
        with self.lock:
            return self.current_rate

