"""Tests for caching functionality."""

import time
from pathlib import Path
import tempfile
import pytest

from vaulytica.core.utils.cache import Cache, FileCache, cached


class TestCache:
    """Test in-memory cache."""

    def test_cache_set_get(self):
        """Test basic cache set and get."""
        cache = Cache(default_ttl=60)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_cache_miss(self):
        """Test cache miss returns None."""
        cache = Cache()
        assert cache.get("nonexistent") is None

    def test_cache_ttl_expiration(self):
        """Test cache entries expire after TTL."""
        cache = Cache(default_ttl=1)
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Wait for expiration
        time.sleep(1.1)
        assert cache.get("key1") is None

    def test_cache_custom_ttl(self):
        """Test custom TTL per entry."""
        cache = Cache(default_ttl=60)
        cache.set("key1", "value1", ttl=1)
        assert cache.get("key1") == "value1"
        
        time.sleep(1.1)
        assert cache.get("key1") is None

    def test_cache_clear(self):
        """Test cache clear."""
        cache = Cache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        
        cache.clear()
        assert cache.get("key1") is None
        assert cache.get("key2") is None

    def test_cache_delete(self):
        """Test cache delete."""
        cache = Cache()
        cache.set("key1", "value1")
        cache.delete("key1")
        assert cache.get("key1") is None

    def test_cache_contains(self):
        """Test checking if cache contains key."""
        cache = Cache()
        cache.set("key1", "value1")
        assert cache.get("key1") is not None
        assert cache.get("key2") is None

    def test_cache_stats(self):
        """Test cache statistics."""
        cache = Cache()
        cache.set("key1", "value1")
        
        # Hit
        cache.get("key1")
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 0
        
        # Miss
        cache.get("key2")
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        
        # Hit rate
        assert stats["hit_rate"] == 0.5

    def test_cache_cleanup_expired(self):
        """Test cleanup of expired entries."""
        cache = Cache(default_ttl=1)
        cache.set("key1", "value1")
        cache.set("key2", "value2", ttl=60)
        
        time.sleep(1.1)
        cache.cleanup_expired()
        
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"


class TestFileCache:
    """Test file-based cache."""

    def test_file_cache_set_get(self):
        """Test basic file cache set and get."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir, default_ttl=60)
            cache.set("key1", {"data": "value1"})
            
            result = cache.get("key1")
            assert result == {"data": "value1"}

    def test_file_cache_persistence(self):
        """Test file cache persists across instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # First instance
            cache1 = FileCache(cache_dir=tmpdir, default_ttl=60)
            cache1.set("key1", {"data": "value1"})
            
            # Second instance
            cache2 = FileCache(cache_dir=tmpdir, default_ttl=60)
            result = cache2.get("key1")
            assert result == {"data": "value1"}

    def test_file_cache_expiration(self):
        """Test file cache entries expire."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir, default_ttl=1)
            cache.set("key1", {"data": "value1"})
            
            time.sleep(1.1)
            assert cache.get("key1") is None

    def test_file_cache_clear(self):
        """Test file cache clear."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir)
            cache.set("key1", {"data": "value1"})
            cache.set("key2", {"data": "value2"})
            
            cache.clear()
            assert cache.get("key1") is None
            assert cache.get("key2") is None

    def test_file_cache_complex_data(self):
        """Test file cache with complex data structures."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir)
            
            data = {
                "list": [1, 2, 3],
                "dict": {"nested": "value"},
                "tuple": (1, 2, 3),
                "string": "test",
                "number": 42,
            }
            
            cache.set("complex", data)
            result = cache.get("complex")
            
            assert result["list"] == [1, 2, 3]
            assert result["dict"] == {"nested": "value"}
            assert result["string"] == "test"
            assert result["number"] == 42


class TestCachedDecorator:
    """Test @cached decorator."""

    def test_cached_decorator_basic(self):
        """Test basic cached decorator functionality."""
        cache = Cache()
        call_count = 0

        @cached(cache)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        # First call - should execute
        result1 = expensive_function(5)
        assert result1 == 10
        assert call_count == 1

        # Second call - should use cache
        result2 = expensive_function(5)
        assert result2 == 10
        assert call_count == 1  # Not incremented

    def test_cached_decorator_different_args(self):
        """Test cached decorator with different arguments."""
        cache = Cache()
        call_count = 0

        @cached(cache)
        def expensive_function(x, y):
            nonlocal call_count
            call_count += 1
            return x + y

        result1 = expensive_function(1, 2)
        assert result1 == 3
        assert call_count == 1

        result2 = expensive_function(3, 4)
        assert result2 == 7
        assert call_count == 2

        # Same args - should use cache
        result3 = expensive_function(1, 2)
        assert result3 == 3
        assert call_count == 2  # Not incremented

    def test_cached_decorator_with_ttl(self):
        """Test cached decorator with TTL."""
        cache = Cache()
        call_count = 0

        @cached(cache, ttl=1)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        result1 = expensive_function(5)
        assert result1 == 10
        assert call_count == 1

        # Wait for expiration
        time.sleep(1.1)

        result2 = expensive_function(5)
        assert result2 == 10
        assert call_count == 2  # Re-executed

    def test_cached_decorator_with_kwargs(self):
        """Test cached decorator with keyword arguments."""
        cache = Cache()
        call_count = 0

        @cached(cache)
        def expensive_function(x, y=10):
            nonlocal call_count
            call_count += 1
            return x + y

        result1 = expensive_function(5, y=10)
        assert result1 == 15
        assert call_count == 1

        result2 = expensive_function(5, y=10)
        assert result2 == 15
        assert call_count == 1  # Cached

        result3 = expensive_function(5, y=20)
        assert result3 == 25
        assert call_count == 2  # Different args


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

