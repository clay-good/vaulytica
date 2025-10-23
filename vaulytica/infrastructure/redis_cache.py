"""
Redis Cache Module

Provides distributed caching with Redis for horizontal scaling.
"""

import json
import pickle
from typing import Any, Optional, Union
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

# Try to import redis
try:
    import redis
    from redis.connection import ConnectionPool
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("redis library not available. Install with: pip install redis")


class RedisCache:
    """
    Distributed Redis cache.

    Features:
    - Distributed caching across multiple instances
    - TTL support
    - JSON and pickle serialization
    - Connection pooling
    - Pub/sub support
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        max_connections: int = 50,
        decode_responses: bool = False
    ):
        """
        Initialize Redis cache.

        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            max_connections: Maximum connections in pool
            decode_responses: Decode responses to strings
        """
        self.host = host
        self.port = port
        self.db = db

        if not REDIS_AVAILABLE:
            logger.error("Redis not available, cache operations will fail")
            self.client = None
            self.pool = None
            return

        try:
            # Create connection pool
            self.pool = ConnectionPool(
                host=host,
                port=port,
                db=db,
                password=password,
                max_connections=max_connections,
                decode_responses=decode_responses
            )

            # Create Redis client
            self.client = redis.Redis(connection_pool=self.pool)

            # Test connection
            self.client.ping()
            logger.info(f"Redis cache connected to {host}:{port}")

        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.client = None
            self.pool = None

    def get(self, key: str, default: Any = None) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key
            default: Default value if key not found

        Returns:
            Cached value or default
        """
        if not self.client:
            return default

        try:
            value = self.client.get(key)
            if value is None:
                return default

            # Try to deserialize
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                try:
                    return pickle.loads(value)
                except Exception:
                    return value

        except Exception as e:
            logger.error(f"Failed to get key '{key}': {e}")
            return default

    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[Union[int, timedelta]] = None,
        serialize: str = "json"
    ) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live (seconds or timedelta)
            serialize: Serialization method ('json' or 'pickle')

        Returns:
            True if successful
        """
        if not self.client:
            return False

        try:
            # Serialize value
            if serialize == "json":
                serialized = json.dumps(value)
            elif serialize == "pickle":
                serialized = pickle.dumps(value)
            else:
                serialized = value

            # Set with TTL
            if ttl:
                if isinstance(ttl, timedelta):
                    ttl = int(ttl.total_seconds())
                self.client.setex(key, ttl, serialized)
            else:
                self.client.set(key, serialized)

            return True

        except Exception as e:
            logger.error(f"Failed to set key '{key}': {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self.client:
            return False

        try:
            self.client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Failed to delete key '{key}': {e}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self.client:
            return False

        try:
            return bool(self.client.exists(key))
        except Exception as e:
            logger.error(f"Failed to check key '{key}': {e}")
            return False

    def expire(self, key: str, ttl: Union[int, timedelta]) -> bool:
        """Set expiration on key"""
        if not self.client:
            return False

        try:
            if isinstance(ttl, timedelta):
                ttl = int(ttl.total_seconds())
            self.client.expire(key, ttl)
            return True
        except Exception as e:
            logger.error(f"Failed to set expiration on key '{key}': {e}")
            return False

    def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter"""
        if not self.client:
            return None

        try:
            return self.client.incrby(key, amount)
        except Exception as e:
            logger.error(f"Failed to increment key '{key}': {e}")
            return None

    def decrement(self, key: str, amount: int = 1) -> Optional[int]:
        """Decrement counter"""
        if not self.client:
            return None

        try:
            return self.client.decrby(key, amount)
        except Exception as e:
            logger.error(f"Failed to decrement key '{key}': {e}")
            return None

    def get_many(self, keys: list[str]) -> dict[str, Any]:
        """Get multiple keys at once"""
        if not self.client:
            return {}

        try:
            values = self.client.mget(keys)
            result = {}
            for key, value in zip(keys, values):
                if value is not None:
                    try:
                        result[key] = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        try:
                            result[key] = pickle.loads(value)
                        except Exception:
                            result[key] = value
            return result
        except Exception as e:
            logger.error(f"Failed to get multiple keys: {e}")
            return {}

    def set_many(self, mapping: dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Set multiple keys at once"""
        if not self.client:
            return False

        try:
            # Serialize all values
            serialized = {}
            for key, value in mapping.items():
                try:
                    serialized[key] = json.dumps(value)
                except (TypeError, ValueError):
                    serialized[key] = pickle.dumps(value)

            # Set all keys
            self.client.mset(serialized)

            # Set TTL if specified
            if ttl:
                for key in serialized.keys():
                    self.client.expire(key, ttl)

            return True
        except Exception as e:
            logger.error(f"Failed to set multiple keys: {e}")
            return False

    def clear(self) -> bool:
        """Clear all keys in current database"""
        if not self.client:
            return False

        try:
            self.client.flushdb()
            logger.info("Redis cache cleared")
            return True
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return False

    def keys(self, pattern: str = "*") -> list[str]:
        """Get all keys matching pattern"""
        if not self.client:
            return []

        try:
            return [k.decode() if isinstance(k, bytes) else k for k in self.client.keys(pattern)]
        except Exception as e:
            logger.error(f"Failed to get keys: {e}")
            return []

    def publish(self, channel: str, message: Any) -> bool:
        """Publish message to channel"""
        if not self.client:
            return False

        try:
            serialized = json.dumps(message)
            self.client.publish(channel, serialized)
            return True
        except Exception as e:
            logger.error(f"Failed to publish to channel '{channel}': {e}")
            return False

    def subscribe(self, channels: list[str]) -> None:
        """Subscribe to channels"""
        if not self.client:
            return None

        try:
            pubsub = self.client.pubsub()
            pubsub.subscribe(*channels)
            return pubsub
        except Exception as e:
            logger.error(f"Failed to subscribe to channels: {e}")
            return None

    def close(self) -> None:
        """Close Redis connection"""
        if self.client:
            self.client.close()
        if self.pool:
            self.pool.disconnect()
        logger.info("Redis cache connection closed")


# Global Redis cache instance
_redis_cache: Optional[RedisCache] = None


def get_redis_cache(
    host: str = "localhost",
    port: int = 6379,
    db: int = 0,
    password: Optional[str] = None
) -> RedisCache:
    """Get the global Redis cache instance."""
    global _redis_cache
    if _redis_cache is None:
        _redis_cache = RedisCache(host=host, port=port, db=db, password=password)
    return _redis_cache
