"""Caching utilities for API responses."""

import hashlib
import json
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Callable, Dict
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class CacheEntry:
    """Represents a cache entry."""

    key: str
    value: Any
    timestamp: float
    ttl: int  # Time to live in seconds


class Cache:
    """Simple in-memory cache with TTL support."""

    def __init__(self, default_ttl: int = 3600):
        """Initialize cache.

        Args:
            default_ttl: Default time-to-live in seconds
        """
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._hits = 0
        self._misses = 0

        logger.info("cache_initialized", default_ttl=default_ttl)

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        entry = self._cache.get(key)

        if entry is None:
            self._misses += 1
            logger.debug("cache_miss", key=key)
            return None

        # Check if expired
        if time.time() - entry.timestamp > entry.ttl:
            del self._cache[key]
            self._misses += 1
            logger.debug("cache_expired", key=key)
            return None

        self._hits += 1
        logger.debug("cache_hit", key=key)
        return entry.value

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if not specified)
        """
        if ttl is None:
            ttl = self.default_ttl

        entry = CacheEntry(
            key=key,
            value=value,
            timestamp=time.time(),
            ttl=ttl,
        )

        self._cache[key] = entry
        logger.debug("cache_set", key=key, ttl=ttl)

    def delete(self, key: str) -> None:
        """Delete value from cache.

        Args:
            key: Cache key
        """
        if key in self._cache:
            del self._cache[key]
            logger.debug("cache_delete", key=key)

    def clear(self) -> None:
        """Clear all cache entries."""
        count = len(self._cache)
        self._cache.clear()
        logger.info("cache_cleared", entries_removed=count)

    def cleanup_expired(self) -> int:
        """Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        now = time.time()
        expired_keys = [
            key
            for key, entry in self._cache.items()
            if now - entry.timestamp > entry.ttl
        ]

        for key in expired_keys:
            del self._cache[key]

        if expired_keys:
            logger.info("cache_cleanup", entries_removed=len(expired_keys))

        return len(expired_keys)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0

        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
        }


class FileCache:
    """Persistent file-based cache."""

    def __init__(self, cache_dir: Path, default_ttl: int = 3600):
        """Initialize file cache.

        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default time-to-live in seconds
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl

        logger.info("file_cache_initialized", cache_dir=str(cache_dir), default_ttl=default_ttl)

    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for key.

        Args:
            key: Cache key

        Returns:
            Path to cache file
        """
        # Hash the key to create a safe filename
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            logger.debug("file_cache_miss", key=key)
            return None

        try:
            with open(cache_path, "rb") as f:
                entry = pickle.load(f)

            # Check if expired
            if time.time() - entry.timestamp > entry.ttl:
                cache_path.unlink()
                logger.debug("file_cache_expired", key=key)
                return None

            logger.debug("file_cache_hit", key=key)
            return entry.value

        except Exception as e:
            logger.error("file_cache_read_error", key=key, error=str(e))
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if not specified)
        """
        if ttl is None:
            ttl = self.default_ttl

        entry = CacheEntry(
            key=key,
            value=value,
            timestamp=time.time(),
            ttl=ttl,
        )

        cache_path = self._get_cache_path(key)

        try:
            with open(cache_path, "wb") as f:
                pickle.dump(entry, f)

            logger.debug("file_cache_set", key=key, ttl=ttl)

        except Exception as e:
            logger.error("file_cache_write_error", key=key, error=str(e))

    def delete(self, key: str) -> None:
        """Delete value from cache.

        Args:
            key: Cache key
        """
        cache_path = self._get_cache_path(key)

        if cache_path.exists():
            cache_path.unlink()
            logger.debug("file_cache_delete", key=key)

    def clear(self) -> None:
        """Clear all cache entries."""
        count = 0
        for cache_file in self.cache_dir.glob("*.cache"):
            cache_file.unlink()
            count += 1

        logger.info("file_cache_cleared", entries_removed=count)

    def cleanup_expired(self) -> int:
        """Remove expired entries from cache.

        Returns:
            Number of entries removed
        """
        now = time.time()
        removed = 0

        for cache_file in self.cache_dir.glob("*.cache"):
            try:
                with open(cache_file, "rb") as f:
                    entry = pickle.load(f)

                if now - entry.timestamp > entry.ttl:
                    cache_file.unlink()
                    removed += 1

            except Exception as e:
                logger.error("file_cache_cleanup_error", file=str(cache_file), error=str(e))
                # Remove corrupted cache files
                cache_file.unlink()
                removed += 1

        if removed > 0:
            logger.info("file_cache_cleanup", entries_removed=removed)

        return removed


def cached(cache: Cache, ttl: Optional[int] = None, key_func: Optional[Callable] = None):
    """Decorator to cache function results.

    Args:
        cache: Cache instance to use
        ttl: Time-to-live in seconds
        key_func: Function to generate cache key from args/kwargs

    Returns:
        Decorated function
    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default: use function name and args
                cache_key = f"{func.__name__}:{str(args)}:{str(kwargs)}"

            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result

            # Call function and cache result
            result = func(*args, **kwargs)
            cache.set(cache_key, result, ttl)

            return result

        return wrapper

    return decorator

