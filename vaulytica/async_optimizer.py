"""
Async Operations Optimizer

Provides optimized async execution patterns, connection pooling, and performance utilities.
"""

import asyncio
import time
from typing import Any, Callable, Coroutine, List, Optional, TypeVar, Dict
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class AsyncMetrics:
    """Metrics for async operations"""
    operation_name: str
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    success: bool = True
    error: Optional[str] = None

    def complete(self, success: bool = True, error: Optional[str] = None) -> None:
        """Mark operation as complete"""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.success = success
        self.error = error


class AsyncPool:
    """
    Async operation pool with concurrency control.

    Features:
    - Concurrent execution with configurable limits
    - Automatic retry with exponential backoff
    - Circuit breaker pattern
    - Performance metrics collection
    """

    def __init__(self, max_concurrent: int = 10, timeout: float = 30.0):
        """
        Initialize async pool.

        Args:
            max_concurrent: Maximum concurrent operations
            timeout: Operation timeout in seconds
        """
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.metrics: List[AsyncMetrics] = []

        # Circuit breaker
        self.failure_count = 0
        self.failure_threshold = 5
        self.circuit_open = False
        self.circuit_open_time: Optional[float] = None
        self.circuit_timeout = 60.0  # seconds

    async def execute(
        self,
        coro: Coroutine[Any, Any, T],
        operation_name: str = "async_operation",
        retries: int = 3,
        retry_delay: float = 1.0
    ) -> Optional[T]:
        """
        Execute async operation with retry and circuit breaker.

        Args:
            coro: Coroutine to execute
            operation_name: Name for metrics
            retries: Number of retry attempts
            retry_delay: Initial retry delay (exponential backoff)

        Returns:
            Operation result or None on failure
        """
        # Check circuit breaker
        if self.circuit_open:
            if time.time() - self.circuit_open_time > self.circuit_timeout:
                logger.info(f"Circuit breaker reset for {operation_name}")
                self.circuit_open = False
                self.failure_count = 0
            else:
                logger.warning(f"Circuit breaker open, rejecting {operation_name}")
                return None

        metric = AsyncMetrics(operation_name=operation_name, start_time=time.time())

        async with self.semaphore:
            for attempt in range(retries + 1):
                try:
                    result = await asyncio.wait_for(coro, timeout=self.timeout)
                    metric.complete(success=True)
                    self.metrics.append(metric)

                    # Reset failure count on success
                    if self.failure_count > 0:
                        self.failure_count = max(0, self.failure_count - 1)

                    return result

                except asyncio.TimeoutError:
                    error_msg = f"Timeout after {self.timeout}s"
                    logger.warning(f"{operation_name} attempt {attempt + 1}/{retries + 1}: {error_msg}")

                    if attempt < retries:
                        await asyncio.sleep(retry_delay * (2 ** attempt))
                    else:
                        metric.complete(success=False, error=error_msg)
                        self.metrics.append(metric)
                        self._handle_failure()
                        return None

                except Exception as e:
                    error_msg = str(e)
                    logger.error(f"{operation_name} attempt {attempt + 1}/{retries + 1}: {error_msg}")

                    if attempt < retries:
                        await asyncio.sleep(retry_delay * (2 ** attempt))
                    else:
                        metric.complete(success=False, error=error_msg)
                        self.metrics.append(metric)
                        self._handle_failure()
                        return None

        return None

    def _handle_failure(self):
        """Handle operation failure for circuit breaker"""
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            logger.error(f"Circuit breaker opened after {self.failure_count} failures")
            self.circuit_open = True
            self.circuit_open_time = time.time()

    async def execute_batch(
        self,
        coros: List[Coroutine[Any, Any, T]],
        operation_name: str = "batch_operation"
    ) -> List[Optional[T]]:
        """
        Execute multiple coroutines concurrently.

        Args:
            coros: List of coroutines to execute
            operation_name: Name for metrics

        Returns:
            List of results (None for failed operations)
        """
        tasks = [
            self.execute(coro, f"{operation_name}_{i}")
            for i, coro in enumerate(coros)
        ]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of async operation metrics"""
        if not self.metrics:
            return {"error": "No metrics collected"}

        successful = [m for m in self.metrics if m.success]
        failed = [m for m in self.metrics if not m.success]

        durations = [m.duration for m in successful if m.duration is not None]

        return {
            "total_operations": len(self.metrics),
            "successful": len(successful),
            "failed": len(failed),
            "success_rate": len(successful) / len(self.metrics) * 100,
            "avg_duration": sum(durations) / len(durations) if durations else 0,
            "min_duration": min(durations) if durations else 0,
            "max_duration": max(durations) if durations else 0,
            "circuit_breaker_open": self.circuit_open,
            "failure_count": self.failure_count
        }


class AsyncCache:
    """
    Async-aware cache with TTL support.

    Features:
    - Time-to-live (TTL) expiration
    - Automatic cleanup of expired entries
    - Thread-safe operations
    """

    def __init__(self, default_ttl: float = 300.0):
        """
        Initialize async cache.

        Args:
            default_ttl: Default time-to-live in seconds
        """
        self.default_ttl = default_ttl
        self.cache: Dict[str, tuple[Any, float]] = {}
        self.lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        async with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if time.time() < expiry:
                    return value
                else:
                    del self.cache[key]
        return None

    async def set(self, key: str, value: Any, ttl: Optional[float] = None):
        """Set value in cache with TTL"""
        async with self.lock:
            expiry = time.time() + (ttl or self.default_ttl)
            self.cache[key] = (value, expiry)

    async def delete(self, key: str):
        """Delete value from cache"""
        async with self.lock:
            if key in self.cache:
                del self.cache[key]

    async def clear(self):
        """Clear all cache entries"""
        async with self.lock:
            self.cache.clear()

    async def cleanup_expired(self):
        """Remove expired entries"""
        async with self.lock:
            now = time.time()
            expired_keys = [k for k, (_, expiry) in self.cache.items() if now >= expiry]
            for key in expired_keys:
                del self.cache[key]
            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")


def async_cached(ttl: float = 300.0, cache: Optional[AsyncCache] = None) -> None:
    """
    Decorator for caching async function results.

    Args:
        ttl: Time-to-live in seconds
        cache: AsyncCache instance (creates new if None)
    """
    _cache = cache or AsyncCache(default_ttl=ttl)

    def decorator(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., Coroutine[Any, Any, T]]:
        """Decorator for async caching."""
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"

            # Try to get from cache
            cached_value = await _cache.get(cache_key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_value

            # Execute function and cache result
            result = await func(*args, **kwargs)
            await _cache.set(cache_key, result, ttl)
            logger.debug(f"Cache miss for {func.__name__}, result cached")

            return result

        return wrapper

    return decorator


def async_timed(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., Coroutine[Any, Any, T]]:
    """
    Decorator for timing async function execution.

    Logs execution time at INFO level.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs) -> T:
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            logger.info(f"{func.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{func.__name__} failed after {duration:.3f}s: {e}")
            raise

    return wrapper


async def gather_with_concurrency(
    n: int,
    *coros: Coroutine[Any, Any, T]
) -> List[T]:
    """
    Execute coroutines with limited concurrency.

    Args:
        n: Maximum concurrent operations
        *coros: Coroutines to execute

    Returns:
        List of results
    """
    semaphore = asyncio.Semaphore(n)

    async def sem_coro(coro: Coroutine[Any, Any, T]) -> T:
        async with semaphore:
            return await coro

    return await asyncio.gather(*(sem_coro(c) for c in coros))


# Global async pool instance
_async_pool: Optional[AsyncPool] = None


def get_async_pool(max_concurrent: int = 10) -> AsyncPool:
    """Get the global async pool instance."""
    global _async_pool
    if _async_pool is None:
        _async_pool = AsyncPool(max_concurrent=max_concurrent)
    return _async_pool
