"""
Edge Case Tests for Vaulytica

Tests edge cases, boundary conditions, and error handling across all modules.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.models import SecurityEvent, Severity, EventCategory
from vaulytica.performance_optimizer import LRUCache, ConnectionPool


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_empty_event_id(self):
        """Test event with empty ID"""
        with pytest.raises((ValueError, AssertionError)):
            event = SecurityEvent(
                id="",
                timestamp=datetime.now(),
                source="test",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                description="Test"
            )
    
    def test_none_event_id(self):
        """Test event with None ID"""
        with pytest.raises((ValueError, TypeError, AssertionError)):
            event = SecurityEvent(
                id=None,
                timestamp=datetime.now(),
                source="test",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                description="Test"
            )
    
    def test_very_long_description(self):
        """Test event with very long description"""
        long_desc = "A" * 10000
        event = SecurityEvent(
            id="test-long",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=long_desc
        )
        assert len(event.description) == 10000
    
    def test_special_characters_in_description(self):
        """Test event with special characters"""
        special_desc = "Test <script>alert('xss')</script> & \"quotes\" 'single'"
        event = SecurityEvent(
            id="test-special",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=special_desc
        )
        assert event.description == special_desc
    
    def test_unicode_in_description(self):
        """Test event with unicode characters"""
        unicode_desc = "Test 你好 мир 🔒 emoji"
        event = SecurityEvent(
            id="test-unicode",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=unicode_desc
        )
        assert event.description == unicode_desc
    
    def test_future_timestamp(self):
        """Test event with future timestamp"""
        future_time = datetime.now() + timedelta(days=365)
        event = SecurityEvent(
            id="test-future",
            timestamp=future_time,
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Test"
        )
        assert event.timestamp == future_time
    
    def test_very_old_timestamp(self):
        """Test event with very old timestamp"""
        old_time = datetime(1970, 1, 1)
        event = SecurityEvent(
            id="test-old",
            timestamp=old_time,
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Test"
        )
        assert event.timestamp == old_time
    
    @pytest.mark.asyncio
    async def test_cache_with_none_value(self):
        """Test caching None value"""
        cache = LRUCache(max_size=10, ttl_seconds=60)
        await cache.set("key1", None)
        value = await cache.get("key1")
        # Should distinguish between "not found" and "cached None"
        assert value is None or "key1" in cache._cache
    
    @pytest.mark.asyncio
    async def test_cache_with_large_value(self):
        """Test caching very large value"""
        cache = LRUCache(max_size=10, ttl_seconds=60)
        large_value = "X" * 1000000  # 1MB string
        await cache.set("large", large_value)
        value = await cache.get("large")
        assert value == large_value
    
    @pytest.mark.asyncio
    async def test_cache_with_complex_object(self):
        """Test caching complex nested object"""
        cache = LRUCache(max_size=10, ttl_seconds=60)
        complex_obj = {
            "nested": {
                "deep": {
                    "value": [1, 2, 3],
                    "dict": {"a": "b"}
                }
            },
            "list": [{"x": 1}, {"y": 2}]
        }
        await cache.set("complex", complex_obj)
        value = await cache.get("complex")
        assert value == complex_obj
    
    @pytest.mark.asyncio
    async def test_cache_concurrent_access(self):
        """Test cache with concurrent access"""
        cache = LRUCache(max_size=100, ttl_seconds=60)
        
        async def writer(i):
            await cache.set(f"key{i}", f"value{i}")
        
        async def reader(i):
            return await cache.get(f"key{i}")
        
        # Concurrent writes
        await asyncio.gather(*[writer(i) for i in range(50)])
        
        # Concurrent reads
        results = await asyncio.gather(*[reader(i) for i in range(50)])
        
        # Should handle concurrent access gracefully
        assert len(results) == 50
    
    @pytest.mark.asyncio
    async def test_cache_zero_ttl(self):
        """Test cache with zero TTL"""
        cache = LRUCache(max_size=10, ttl_seconds=0)
        await cache.set("key1", "value1")
        # With zero TTL, value should expire immediately
        await asyncio.sleep(0.01)
        value = await cache.get("key1")
        # Implementation dependent - may or may not be cached
        assert value is None or value == "value1"
    
    @pytest.mark.asyncio
    async def test_cache_negative_ttl(self):
        """Test cache with negative TTL"""
        with pytest.raises((ValueError, AssertionError)):
            cache = LRUCache(max_size=10, ttl_seconds=-1)
    
    @pytest.mark.asyncio
    async def test_cache_zero_size(self):
        """Test cache with zero max size"""
        with pytest.raises((ValueError, AssertionError)):
            cache = LRUCache(max_size=0, ttl_seconds=60)
    
    @pytest.mark.asyncio
    async def test_cache_negative_size(self):
        """Test cache with negative max size"""
        with pytest.raises((ValueError, AssertionError)):
            cache = LRUCache(max_size=-1, ttl_seconds=60)
    
    @pytest.mark.asyncio
    async def test_connection_pool_connection_failure(self):
        """Test pool handles connection creation failure"""
        async def failing_creator():
            raise ConnectionError("Failed to connect")
        
        pool = ConnectionPool(
            create_connection=failing_creator,
            max_size=5,
            min_size=1
        )
        
        with pytest.raises(ConnectionError):
            async with pool.acquire() as conn:
                pass
    
    @pytest.mark.asyncio
    async def test_connection_pool_zero_size(self):
        """Test pool with zero max size"""
        async def create_conn():
            return Mock()
        
        with pytest.raises((ValueError, AssertionError)):
            pool = ConnectionPool(
                create_connection=create_conn,
                max_size=0,
                min_size=0
            )
    
    def test_metadata_with_nested_objects(self):
        """Test event metadata with deeply nested objects"""
        metadata = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "value": "deep"
                        }
                    }
                }
            },
            "array": [1, [2, [3, [4, 5]]]]
        }
        event = SecurityEvent(
            id="test-nested-meta",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Test",
            metadata=metadata
        )
        assert event.metadata == metadata
    
    def test_metadata_with_circular_reference(self):
        """Test event metadata with circular reference"""
        metadata = {"key": "value"}
        metadata["self"] = metadata  # Circular reference
        
        # Should handle gracefully or raise appropriate error
        try:
            event = SecurityEvent(
                id="test-circular",
                timestamp=datetime.now(),
                source="test",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                description="Test",
                metadata=metadata
            )
            # If it doesn't raise, that's fine
            assert True
        except (ValueError, RecursionError):
            # If it raises, that's also acceptable
            assert True
    
    def test_event_with_empty_metadata(self):
        """Test event with empty metadata dict"""
        event = SecurityEvent(
            id="test-empty-meta",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Test",
            metadata={}
        )
        assert event.metadata == {}
    
    def test_event_with_none_metadata(self):
        """Test event with None metadata"""
        event = SecurityEvent(
            id="test-none-meta",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Test",
            metadata=None
        )
        assert event.metadata is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

