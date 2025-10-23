"""
Performance Optimization Module

Provides advanced performance optimization utilities including:
- Connection pooling for databases and external services
- Query optimization and caching
- Memory-efficient data processing
- Batch operations
- Lazy loading
- Performance profiling
"""

import asyncio
import time
import functools
from typing import Any, Callable, Dict, List, Optional, TypeVar, Generic
from dataclasses import dataclass, field
from collections import OrderedDict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class PerformanceMetrics:
    """Performance metrics for operations"""
    operation_name: str
    call_count: int = 0
    total_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    avg_time: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0

    def record(self, duration: float, cache_hit: bool = False) -> None:
        """Record an operation"""
        self.call_count += 1
        self.total_time += duration
        self.min_time = min(self.min_time, duration)
        self.max_time = max(self.max_time, duration)
        self.avg_time = self.total_time / self.call_count

        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

    def get_cache_hit_rate(self) -> float:
        """Get cache hit rate"""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0


class LRUCache(Generic[T]):
    """Thread-safe LRU cache with TTL support"""

    def __init__(self, max_size: int = 1000, ttl_seconds: float = 300.0):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: OrderedDict[str, tuple[T, float]] = OrderedDict()
        self.lock = asyncio.Lock()
        self.metrics = PerformanceMetrics("LRUCache")

    async def get(self, key: str) -> Optional[T]:
        """Get value from cache"""
        start = time.time()

        async with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]

                # Check if expired
                if time.time() < expiry:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    self.metrics.record(time.time() - start, cache_hit=True)
                    return value
                else:
                    # Remove expired entry
                    del self.cache[key]

        self.metrics.record(time.time() - start, cache_hit=False)
        return None

    async def set(self, key: str, value: T):
        """Set value in cache"""
        async with self.lock:
            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size and key not in self.cache:
                self.cache.popitem(last=False)

            expiry = time.time() + self.ttl_seconds
            self.cache[key] = (value, expiry)
            self.cache.move_to_end(key)

    async def clear(self):
        """Clear cache"""
        async with self.lock:
            self.cache.clear()

    def get_metrics(self) -> PerformanceMetrics:
        """Get cache metrics"""
        return self.metrics


class ConnectionPool:
    """Generic connection pool for external services"""

    def __init__(
        self,
        create_connection: Callable,
        max_connections: int = 10,
        min_connections: int = 2,
        connection_timeout: float = 30.0
    ):
        self.create_connection = create_connection
        self.max_connections = max_connections
        self.min_connections = min_connections
        self.connection_timeout = connection_timeout

        self.available: asyncio.Queue = asyncio.Queue(maxsize=max_connections)
        self.in_use: list = []  # Use list instead of set for unhashable objects
        self.total_created = 0
        self.metrics = PerformanceMetrics("ConnectionPool")
        self._initialized = False

    async def initialize(self):
        """Initialize connection pool"""
        if self._initialized:
            return

        # Create minimum connections
        for _ in range(self.min_connections):
            conn = await self.create_connection()
            await self.available.put(conn)
            self.total_created += 1

        self._initialized = True
        logger.info(f"Connection pool initialized with {self.min_connections} connections")

    async def acquire(self):
        """Acquire a connection from the pool"""
        start = time.time()

        if not self._initialized:
            await self.initialize()

        try:
            # Try to get available connection
            conn = await asyncio.wait_for(
                self.available.get(),
                timeout=self.connection_timeout
            )
            self.in_use.append(conn)
            self.metrics.record(time.time() - start)
            return conn

        except asyncio.TimeoutError:
            # Create new connection if under limit
            if self.total_created < self.max_connections:
                conn = await self.create_connection()
                self.total_created += 1
                self.in_use.append(conn)
                self.metrics.record(time.time() - start)
                logger.debug(f"Created new connection (total: {self.total_created})")
                return conn
            else:
                raise Exception("Connection pool exhausted")

    async def release(self, conn):
        """Release a connection back to the pool"""
        try:
            self.in_use.remove(conn)
            await self.available.put(conn)
        except ValueError:
            # Connection not in use list
            pass

    async def close_all(self):
        """Close all connections"""
        # Close available connections
        while not self.available.empty():
            conn = await self.available.get()
            if hasattr(conn, 'close'):
                await conn.close()

        # Close in-use connections
        for conn in self.in_use:
            if hasattr(conn, 'close'):
                await conn.close()

        self.in_use.clear()
        self.total_created = 0
        self._initialized = False
        logger.info("Connection pool closed")


class BatchProcessor(Generic[T]):
    """Batch processor for efficient bulk operations"""

    def __init__(
        self,
        process_func: Callable[[List[T]], Any],
        batch_size: int = 100,
        flush_interval: float = 5.0
    ):
        self.process_func = process_func
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self.buffer: List[T] = []
        self.lock = asyncio.Lock()
        self.last_flush = time.time()
        self.metrics = PerformanceMetrics("BatchProcessor")

    async def add(self, item: T):
        """Add item to batch"""
        async with self.lock:
            self.buffer.append(item)

            # Flush if batch is full or interval elapsed
            should_flush = (
                len(self.buffer) >= self.batch_size or
                time.time() - self.last_flush >= self.flush_interval
            )

            if should_flush:
                await self._flush()

    async def _flush(self):
        """Flush buffer"""
        if not self.buffer:
            return

        start = time.time()
        batch = self.buffer.copy()
        self.buffer.clear()
        self.last_flush = time.time()

        try:
            await self.process_func(batch)
            self.metrics.record(time.time() - start)
            logger.debug(f"Processed batch of {len(batch)} items")
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            # Re-add items to buffer
            self.buffer.extend(batch)

    async def flush(self):
        """Manually flush buffer"""
        async with self.lock:
            await self._flush()


def profile_performance(func: Callable) -> Callable:
    """Decorator to profile function performance"""
    metrics = PerformanceMetrics(func.__name__)

    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        start = time.time()
        try:
            result = await func(*args, **kwargs)
            metrics.record(time.time() - start)
            return result
        except Exception as e:
            metrics.record(time.time() - start)
            raise

    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs) -> Any:
        """Synchronous wrapper for performance profiling."""
        start = time.time()
        try:
            result = func(*args, **kwargs)
            metrics.record(time.time() - start)
            return result
        except Exception as e:
            metrics.record(time.time() - start)
            raise

    # Store metrics on wrapper
    wrapper = async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    wrapper.metrics = metrics  # type: ignore

    return wrapper


def lazy_property(func: Callable) -> property:
    """Decorator for lazy-loaded properties"""
    attr_name = '_lazy_' + func.__name__

    @functools.wraps(func)
    def wrapper(self) -> Any:
        """Wrapper function for lazy loading."""
        if not hasattr(self, attr_name):
            setattr(self, attr_name, func(self))
        return getattr(self, attr_name)

    return property(wrapper)


class PerformanceMonitor:
    """Global performance monitor"""

    def __init__(self):
        self.metrics: Dict[str, PerformanceMetrics] = {}
        self.start_time = time.time()

    def register(self, name: str, metrics: PerformanceMetrics) -> None:
        """Register metrics"""
        self.metrics[name] = metrics

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        uptime = time.time() - self.start_time

        summary = {
            'uptime_seconds': uptime,
            'operations': {}
        }

        for name, metrics in self.metrics.items():
            summary['operations'][name] = {
                'call_count': metrics.call_count,
                'total_time': metrics.total_time,
                'avg_time': metrics.avg_time,
                'min_time': metrics.min_time if metrics.min_time != float('in') else 0,
                'max_time': metrics.max_time,
                'cache_hit_rate': metrics.get_cache_hit_rate()
            }

        return summary

    def reset(self) -> None:
        """Reset all metrics"""
        self.metrics.clear()
        self.start_time = time.time()


# Global performance monitor instance
performance_monitor = PerformanceMonitor()
