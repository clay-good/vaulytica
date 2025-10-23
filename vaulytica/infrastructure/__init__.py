"""
Vaulytica Infrastructure Module

Provides infrastructure components for horizontal scaling and distributed systems.
"""

from .redis_cache import (
    RedisCache,
    get_redis_cache
)

from .message_queue import (
    MessageQueue,
    Message,
    QueuePriority,
    get_message_queue
)

__all__ = [
    # Redis cache
    'RedisCache',
    'get_redis_cache',

    # Message queue
    'MessageQueue',
    'Message',
    'QueuePriority',
    'get_message_queue',
]
