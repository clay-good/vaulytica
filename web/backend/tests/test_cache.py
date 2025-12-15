"""Tests for caching utilities."""

import pytest
import time

from backend.core.cache import (
    InMemoryCache,
    get_cache,
    make_cache_key,
    invalidate_cache,
    CACHE_PREFIX_SCAN_STATS,
    CACHE_PREFIX_FINDINGS_SUMMARY,
)


class TestInMemoryCache:
    """Test InMemoryCache class."""

    def test_set_and_get(self):
        """Test basic set and get operations."""
        cache = InMemoryCache()
        cache.set("test_key", {"value": 123}, ttl=60)
        result = cache.get("test_key")
        assert result == {"value": 123}

    def test_get_nonexistent_key(self):
        """Test getting a key that doesn't exist."""
        cache = InMemoryCache()
        result = cache.get("nonexistent")
        assert result is None

    def test_ttl_expiration(self):
        """Test that cached values expire after TTL."""
        cache = InMemoryCache()
        cache.set("expiring_key", "value", ttl=1)

        # Should be available immediately
        assert cache.get("expiring_key") == "value"

        # Wait for expiration
        time.sleep(1.1)

        # Should be None after expiration
        assert cache.get("expiring_key") is None

    def test_delete(self):
        """Test deleting a cache entry."""
        cache = InMemoryCache()
        cache.set("to_delete", "value", ttl=60)
        assert cache.get("to_delete") == "value"

        cache.delete("to_delete")
        assert cache.get("to_delete") is None

    def test_delete_nonexistent(self):
        """Test deleting a key that doesn't exist doesn't raise."""
        cache = InMemoryCache()
        cache.delete("nonexistent")  # Should not raise

    def test_clear(self):
        """Test clearing all cache entries."""
        cache = InMemoryCache()
        cache.set("key1", "value1", ttl=60)
        cache.set("key2", "value2", ttl=60)

        cache.clear()

        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_clear_prefix(self):
        """Test clearing entries by prefix."""
        cache = InMemoryCache()
        cache.set("scan_stats:abc", "value1", ttl=60)
        cache.set("scan_stats:def", "value2", ttl=60)
        cache.set("findings:xyz", "value3", ttl=60)

        cache.clear_prefix("scan_stats:")

        assert cache.get("scan_stats:abc") is None
        assert cache.get("scan_stats:def") is None
        assert cache.get("findings:xyz") == "value3"

    def test_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = InMemoryCache()
        cache.set("short_ttl", "value1", ttl=1)
        cache.set("long_ttl", "value2", ttl=60)

        time.sleep(1.1)

        removed = cache.cleanup_expired()

        assert removed == 1
        assert cache.get("short_ttl") is None
        assert cache.get("long_ttl") == "value2"


class TestCacheKey:
    """Test cache key generation."""

    def test_make_cache_key_basic(self):
        """Test basic cache key generation."""
        key = make_cache_key("scan_stats", domain="example.com", days=30)
        assert key.startswith("scan_stats:")
        assert len(key) > len("scan_stats:")

    def test_make_cache_key_consistent(self):
        """Test that same inputs produce same key."""
        key1 = make_cache_key("test", domain="example.com", days=30)
        key2 = make_cache_key("test", domain="example.com", days=30)
        assert key1 == key2

    def test_make_cache_key_order_independent(self):
        """Test that kwargs order doesn't affect key."""
        key1 = make_cache_key("test", a=1, b=2, c=3)
        key2 = make_cache_key("test", c=3, a=1, b=2)
        assert key1 == key2

    def test_make_cache_key_different_values(self):
        """Test that different values produce different keys."""
        key1 = make_cache_key("test", domain="example1.com")
        key2 = make_cache_key("test", domain="example2.com")
        assert key1 != key2


class TestGlobalCache:
    """Test global cache instance and invalidation."""

    def test_get_cache_returns_singleton(self):
        """Test that get_cache returns the same instance."""
        cache1 = get_cache()
        cache2 = get_cache()
        assert cache1 is cache2

    def test_invalidate_cache_by_prefix(self):
        """Test cache invalidation by prefix."""
        cache = get_cache()

        # Set some test data
        cache.set(f"{CACHE_PREFIX_SCAN_STATS}:test1", "data1", ttl=60)
        cache.set(f"{CACHE_PREFIX_SCAN_STATS}:test2", "data2", ttl=60)
        cache.set(f"{CACHE_PREFIX_FINDINGS_SUMMARY}:test", "data3", ttl=60)

        # Invalidate scan stats
        invalidate_cache(CACHE_PREFIX_SCAN_STATS)

        # Scan stats should be gone
        assert cache.get(f"{CACHE_PREFIX_SCAN_STATS}:test1") is None
        assert cache.get(f"{CACHE_PREFIX_SCAN_STATS}:test2") is None

        # Findings should still be there
        assert cache.get(f"{CACHE_PREFIX_FINDINGS_SUMMARY}:test") == "data3"

        # Cleanup
        cache.clear()


class TestCacheIntegration:
    """Integration tests for cache with different data types."""

    def test_cache_dict(self):
        """Test caching dictionary data."""
        cache = InMemoryCache()
        data = {"total": 100, "items": [1, 2, 3], "nested": {"key": "value"}}
        cache.set("dict_key", data, ttl=60)
        result = cache.get("dict_key")
        assert result == data

    def test_cache_list(self):
        """Test caching list data."""
        cache = InMemoryCache()
        data = [1, 2, 3, "string", {"key": "value"}]
        cache.set("list_key", data, ttl=60)
        result = cache.get("list_key")
        assert result == data

    def test_cache_numeric(self):
        """Test caching numeric data."""
        cache = InMemoryCache()
        cache.set("int_key", 42, ttl=60)
        cache.set("float_key", 3.14, ttl=60)
        assert cache.get("int_key") == 42
        assert cache.get("float_key") == 3.14
