"""Caching utilities for frequently accessed data.

Provides an in-memory cache with TTL support. Can be extended to use Redis
when available for distributed caching across multiple instances.
"""

import hashlib
import json
import time
from typing import Any, Callable, Optional
from functools import wraps


class InMemoryCache:
    """Simple in-memory cache with TTL support."""

    def __init__(self):
        self._cache: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired."""
        if key in self._cache:
            value, expires_at = self._cache[key]
            if time.time() < expires_at:
                return value
            # Expired, remove it
            del self._cache[key]
        return None

    def set(self, key: str, value: Any, ttl: int = 60) -> None:
        """Set value in cache with TTL in seconds."""
        expires_at = time.time() + ttl
        self._cache[key] = (value, expires_at)

    def delete(self, key: str) -> None:
        """Delete a key from cache."""
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cached data."""
        self._cache.clear()

    def clear_prefix(self, prefix: str) -> None:
        """Clear all keys starting with a prefix."""
        keys_to_delete = [k for k in self._cache.keys() if k.startswith(prefix)]
        for key in keys_to_delete:
            del self._cache[key]

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count of removed entries."""
        now = time.time()
        expired_keys = [k for k, (_, exp) in self._cache.items() if exp <= now]
        for key in expired_keys:
            del self._cache[key]
        return len(expired_keys)


# Global cache instance
_cache = InMemoryCache()


def get_cache() -> InMemoryCache:
    """Get the global cache instance."""
    return _cache


def make_cache_key(prefix: str, **kwargs) -> str:
    """Create a cache key from prefix and keyword arguments."""
    # Sort kwargs for consistent key generation
    sorted_items = sorted(kwargs.items())
    key_data = json.dumps(sorted_items, sort_keys=True, default=str)
    # Use SHA-256 instead of MD5 for better collision resistance
    key_hash = hashlib.sha256(key_data.encode()).hexdigest()[:16]
    return f"{prefix}:{key_hash}"


def cached(prefix: str, ttl: int = 60):
    """Decorator to cache function results.

    Args:
        prefix: Cache key prefix (e.g., "scan_stats", "findings_summary")
        ttl: Time to live in seconds (default 60)

    Usage:
        @cached("scan_stats", ttl=300)
        async def get_scan_stats(domain: str = None, days: int = 30):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Build cache key from function arguments
            cache_key = make_cache_key(prefix, **kwargs)

            # Try to get from cache
            cache = get_cache()
            cached_value = cache.get(cache_key)
            if cached_value is not None:
                return cached_value

            # Execute function and cache result
            result = await func(*args, **kwargs)
            cache.set(cache_key, result, ttl)
            return result

        return wrapper
    return decorator


def invalidate_cache(prefix: str) -> None:
    """Invalidate all cache entries with given prefix.

    Call this when data is modified that would affect cached results.

    Args:
        prefix: The cache prefix to invalidate (e.g., "scan_stats")
    """
    get_cache().clear_prefix(prefix)


# Cache key prefixes for different data types
CACHE_PREFIX_SCAN_STATS = "scan_stats"
CACHE_PREFIX_FINDINGS_SUMMARY = "findings_summary"
CACHE_PREFIX_DASHBOARD = "dashboard"


# Default TTL values (in seconds)
CACHE_TTL_SCAN_STATS = 300  # 5 minutes
CACHE_TTL_FINDINGS_SUMMARY = 300  # 5 minutes
CACHE_TTL_DASHBOARD = 60  # 1 minute (more dynamic data)
