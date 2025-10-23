"""
Performance Benchmark Tests for Vaulytica

Tests performance characteristics and validates optimization improvements.
"""

import pytest
import asyncio
import time
from datetime import datetime
from unittest.mock import Mock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.models import SecurityEvent, Severity, EventCategory
from vaulytica.performance_optimizer import LRUCache, ConnectionPool, BatchProcessor


class TestPerformanceBenchmarks:
    """Performance benchmark tests"""
    
    @pytest.mark.asyncio
    async def test_cache_performance_1000_ops(self):
        """Test cache performance with 1000 operations"""
        cache = LRUCache(max_size=500, ttl_seconds=60)
        
        start_time = time.time()
        
        # 1000 write operations
        for i in range(1000):
            await cache.set(f"key{i}", f"value{i}")
        
        write_time = time.time() - start_time
        
        start_time = time.time()
        
        # 1000 read operations
        for i in range(1000):
            await cache.get(f"key{i}")
        
        read_time = time.time() - start_time
        
        # Performance assertions
        assert write_time < 1.0, f"Write time {write_time}s exceeds 1s"
        assert read_time < 0.5, f"Read time {read_time}s exceeds 0.5s"
        
        print(f"\nCache Performance:")
        print(f"  1000 writes: {write_time:.3f}s ({1000/write_time:.0f} ops/s)")
        print(f"  1000 reads: {read_time:.3f}s ({1000/read_time:.0f} ops/s)")
    
    @pytest.mark.asyncio
    async def test_cache_concurrent_performance(self):
        """Test cache performance with concurrent operations"""
        cache = LRUCache(max_size=1000, ttl_seconds=60)
        
        async def concurrent_ops(worker_id):
            for i in range(100):
                await cache.set(f"worker{worker_id}_key{i}", f"value{i}")
                await cache.get(f"worker{worker_id}_key{i}")
        
        start_time = time.time()
        
        # 10 concurrent workers, 100 ops each = 1000 total ops
        await asyncio.gather(*[concurrent_ops(i) for i in range(10)])
        
        elapsed_time = time.time() - start_time
        
        assert elapsed_time < 2.0, f"Concurrent ops time {elapsed_time}s exceeds 2s"
        
        print(f"\nConcurrent Cache Performance:")
        print(f"  1000 ops (10 workers): {elapsed_time:.3f}s ({1000/elapsed_time:.0f} ops/s)")
    
    def test_event_creation_performance(self):
        """Test event creation performance"""
        start_time = time.time()
        
        events = []
        for i in range(10000):
            event = SecurityEvent(
                id=f"perf-test-{i}",
                timestamp=datetime.now(),
                source="benchmark",
                category=EventCategory.NETWORK,
                severity=Severity.INFO,
                description=f"Performance test event {i}"
            )
            events.append(event)
        
        elapsed_time = time.time() - start_time
        
        assert elapsed_time < 1.0, f"Event creation time {elapsed_time}s exceeds 1s"
        assert len(events) == 10000
        
        print(f"\nEvent Creation Performance:")
        print(f"  10000 events: {elapsed_time:.3f}s ({10000/elapsed_time:.0f} events/s)")
    
    def test_event_with_metadata_performance(self):
        """Test event creation with metadata performance"""
        metadata = {
            "user": "admin",
            "ip": "192.168.1.1",
            "action": "login",
            "result": "success",
            "details": {"method": "password", "mfa": True}
        }
        
        start_time = time.time()
        
        events = []
        for i in range(5000):
            event = SecurityEvent(
                id=f"meta-test-{i}",
                timestamp=datetime.now(),
                source="benchmark",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.MEDIUM,
                description=f"Auth event {i}",
                metadata=metadata.copy()
            )
            events.append(event)
        
        elapsed_time = time.time() - start_time
        
        assert elapsed_time < 1.0, f"Event with metadata time {elapsed_time}s exceeds 1s"
        assert len(events) == 5000
        
        print(f"\nEvent with Metadata Performance:")
        print(f"  5000 events: {elapsed_time:.3f}s ({5000/elapsed_time:.0f} events/s)")
    
    @pytest.mark.asyncio
    async def test_batch_processor_throughput(self):
        """Test batch processor throughput"""
        processed_count = 0
        
        async def process_batch(items):
            nonlocal processed_count
            processed_count += len(items)
        
        processor = BatchProcessor(
            process_func=process_batch,
            batch_size=100,
            flush_interval=0.1
        )
        
        start_time = time.time()
        
        # Add 1000 items
        for i in range(1000):
            await processor.add(f"item{i}")
        
        # Wait for processing
        await asyncio.sleep(0.5)
        
        elapsed_time = time.time() - start_time
        
        assert processed_count >= 900, f"Only processed {processed_count}/1000 items"
        
        print(f"\nBatch Processor Performance:")
        print(f"  1000 items: {elapsed_time:.3f}s ({1000/elapsed_time:.0f} items/s)")
        print(f"  Processed: {processed_count} items")
    
    @pytest.mark.asyncio
    async def test_connection_pool_performance(self):
        """Test connection pool performance"""
        connection_count = 0
        
        async def create_conn():
            nonlocal connection_count
            connection_count += 1
            await asyncio.sleep(0.001)  # Simulate connection time
            return Mock()
        
        pool = ConnectionPool(
            create_connection=create_conn,
            max_size=10,
            min_size=2
        )
        
        start_time = time.time()
        
        # Acquire and release 100 times
        for i in range(100):
            async with pool.acquire() as conn:
                pass
        
        elapsed_time = time.time() - start_time
        
        # Should reuse connections, not create 100
        assert connection_count < 20, f"Created {connection_count} connections (should reuse)"
        assert elapsed_time < 1.0, f"Pool operations time {elapsed_time}s exceeds 1s"
        
        print(f"\nConnection Pool Performance:")
        print(f"  100 acquire/release: {elapsed_time:.3f}s")
        print(f"  Connections created: {connection_count} (reused {100-connection_count} times)")
    
    @pytest.mark.asyncio
    async def test_cache_hit_rate(self):
        """Test cache hit rate"""
        cache = LRUCache(max_size=100, ttl_seconds=60)
        
        # Populate cache
        for i in range(100):
            await cache.set(f"key{i}", f"value{i}")
        
        # Access with 80% hit rate
        hits = 0
        misses = 0
        
        for i in range(1000):
            key = f"key{i % 120}"  # 100 keys exist, 20 don't
            value = await cache.get(key)
            if value is not None:
                hits += 1
            else:
                misses += 1
        
        hit_rate = hits / (hits + misses)
        
        assert hit_rate > 0.7, f"Hit rate {hit_rate:.2%} is below 70%"
        
        print(f"\nCache Hit Rate:")
        print(f"  Hits: {hits}")
        print(f"  Misses: {misses}")
        print(f"  Hit Rate: {hit_rate:.2%}")
    
    def test_memory_efficiency(self):
        """Test memory efficiency with large number of events"""
        import sys
        
        # Create 1000 events
        events = []
        for i in range(1000):
            event = SecurityEvent(
                id=f"mem-test-{i}",
                timestamp=datetime.now(),
                source="benchmark",
                category=EventCategory.NETWORK,
                severity=Severity.INFO,
                description=f"Memory test event {i}"
            )
            events.append(event)
        
        # Rough memory estimate
        total_size = sys.getsizeof(events)
        avg_size = total_size / len(events)
        
        # Each event should be reasonably sized
        assert avg_size < 10000, f"Average event size {avg_size} bytes is too large"
        
        print(f"\nMemory Efficiency:")
        print(f"  1000 events: {total_size:,} bytes")
        print(f"  Average per event: {avg_size:.0f} bytes")
    
    @pytest.mark.asyncio
    async def test_cache_eviction_performance(self):
        """Test cache eviction performance"""
        cache = LRUCache(max_size=100, ttl_seconds=60)
        
        start_time = time.time()
        
        # Add 1000 items to cache with max_size=100
        # Should trigger many evictions
        for i in range(1000):
            await cache.set(f"key{i}", f"value{i}")
        
        elapsed_time = time.time() - start_time
        
        # Eviction should be fast
        assert elapsed_time < 1.0, f"Eviction time {elapsed_time}s exceeds 1s"
        
        # Cache should contain only most recent 100
        cache_size = len(cache._cache)
        assert cache_size <= 100, f"Cache size {cache_size} exceeds max_size"
        
        print(f"\nCache Eviction Performance:")
        print(f"  1000 inserts (max_size=100): {elapsed_time:.3f}s")
        print(f"  Final cache size: {cache_size}")
    
    @pytest.mark.asyncio
    async def test_ttl_cleanup_performance(self):
        """Test TTL cleanup performance"""
        cache = LRUCache(max_size=1000, ttl_seconds=0.1)
        
        # Add 500 items
        for i in range(500):
            await cache.set(f"key{i}", f"value{i}")
        
        # Wait for TTL expiration
        await asyncio.sleep(0.2)
        
        start_time = time.time()
        
        # Access expired items (should trigger cleanup)
        for i in range(500):
            await cache.get(f"key{i}")
        
        elapsed_time = time.time() - start_time
        
        # Cleanup should be fast
        assert elapsed_time < 0.5, f"TTL cleanup time {elapsed_time}s exceeds 0.5s"
        
        print(f"\nTTL Cleanup Performance:")
        print(f"  500 expired items: {elapsed_time:.3f}s")


class TestScalability:
    """Test scalability characteristics"""
    
    def test_linear_scaling_event_creation(self):
        """Test event creation scales linearly"""
        sizes = [100, 1000, 10000]
        times = []
        
        for size in sizes:
            start_time = time.time()
            
            events = []
            for i in range(size):
                event = SecurityEvent(
                    id=f"scale-test-{i}",
                    timestamp=datetime.now(),
                    source="benchmark",
                    category=EventCategory.NETWORK,
                    severity=Severity.INFO,
                    description=f"Scale test event {i}"
                )
                events.append(event)
            
            elapsed_time = time.time() - start_time
            times.append(elapsed_time)
        
        # Check for linear scaling (within reasonable bounds)
        # 10x more events should take roughly 10x time (±50%)
        ratio_1 = times[1] / times[0]
        ratio_2 = times[2] / times[1]
        
        assert 5 < ratio_1 < 15, f"Scaling ratio {ratio_1} not linear"
        assert 5 < ratio_2 < 15, f"Scaling ratio {ratio_2} not linear"
        
        print(f"\nScalability Test:")
        print(f"  100 events: {times[0]:.3f}s")
        print(f"  1000 events: {times[1]:.3f}s (ratio: {ratio_1:.1f}x)")
        print(f"  10000 events: {times[2]:.3f}s (ratio: {ratio_2:.1f}x)")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])

