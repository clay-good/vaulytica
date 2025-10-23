"""
Message Queue Module

Provides distributed message queuing with RabbitMQ/Redis for async task processing.
"""

import json
import uuid
from typing import Any, Callable, Optional, Dict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging
import asyncio

logger = logging.getLogger(__name__)

# Try to import pika (RabbitMQ)
try:
    import pika
    RABBITMQ_AVAILABLE = True
except ImportError:
    RABBITMQ_AVAILABLE = False
    logger.warning("pika library not available. Install with: pip install pika")


class QueuePriority(str, Enum):
    """Message priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Message:
    """Queue message"""
    message_id: str
    queue_name: str
    payload: Dict[str, Any]
    priority: QueuePriority = QueuePriority.NORMAL
    created_at: datetime = field(default_factory=datetime.utcnow)
    retry_count: int = 0
    max_retries: int = 3

    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'message_id': self.message_id,
            'queue_name': self.queue_name,
            'payload': self.payload,
            'priority': self.priority.value,
            'created_at': self.created_at.isoformat(),
            'retry_count': self.retry_count,
            'max_retries': self.max_retries
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Message':
        """Create from dictionary"""
        return cls(
            message_id=data['message_id'],
            queue_name=data['queue_name'],
            payload=data['payload'],
            priority=QueuePriority(data.get('priority', 'normal')),
            created_at=datetime.fromisoformat(data['created_at']),
            retry_count=data.get('retry_count', 0),
            max_retries=data.get('max_retries', 3)
        )


class MessageQueue:
    """
    Distributed message queue.

    Features:
    - RabbitMQ integration
    - Priority queues
    - Dead letter queues
    - Retry logic
    - Message persistence
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5672,
        username: str = "guest",
        password: str = "guest",
        virtual_host: str = "/"
    ):
        """
        Initialize message queue.

        Args:
            host: RabbitMQ host
            port: RabbitMQ port
            username: RabbitMQ username
            password: RabbitMQ password
            virtual_host: RabbitMQ virtual host
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.virtual_host = virtual_host

        self.connection = None
        self.channel = None
        self.consumers: Dict[str, Callable] = {}

        if not RABBITMQ_AVAILABLE:
            logger.error("RabbitMQ not available, queue operations will fail")
            return

        self._connect()

    def _connect(self):
        """Connect to RabbitMQ"""
        try:
            credentials = pika.PlainCredentials(self.username, self.password)
            parameters = pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                virtual_host=self.virtual_host,
                credentials=credentials,
                heartbeat=600,
                blocked_connection_timeout=300
            )

            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()

            logger.info(f"Connected to RabbitMQ at {self.host}:{self.port}")

        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {e}")
            self.connection = None
            self.channel = None

    def declare_queue(
        self,
        queue_name: str,
        durable: bool = True,
        max_priority: int = 10
    ) -> bool:
        """
        Declare a queue.

        Args:
            queue_name: Name of the queue
            durable: Whether queue survives broker restart
            max_priority: Maximum priority level

        Returns:
            True if successful
        """
        if not self.channel:
            return False

        try:
            self.channel.queue_declare(
                queue=queue_name,
                durable=durable,
                arguments={'x-max-priority': max_priority}
            )
            logger.info(f"Queue '{queue_name}' declared")
            return True

        except Exception as e:
            logger.error(f"Failed to declare queue '{queue_name}': {e}")
            return False

    def publish(
        self,
        queue_name: str,
        payload: Dict[str, Any],
        priority: QueuePriority = QueuePriority.NORMAL
    ) -> Optional[str]:
        """
        Publish message to queue.

        Args:
            queue_name: Queue name
            payload: Message payload
            priority: Message priority

        Returns:
            Message ID if successful
        """
        if not self.channel:
            logger.error("Cannot publish: not connected to RabbitMQ")
            return None

        try:
            message = Message(
                message_id=str(uuid.uuid4()),
                queue_name=queue_name,
                payload=payload,
                priority=priority
            )

            # Priority mapping
            priority_map = {
                QueuePriority.LOW: 1,
                QueuePriority.NORMAL: 5,
                QueuePriority.HIGH: 8,
                QueuePriority.CRITICAL: 10
            }

            self.channel.basic_publish(
                exchange='',
                routing_key=queue_name,
                body=json.dumps(message.to_dict()),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Persistent
                    priority=priority_map[priority],
                    content_type='application/json',
                    message_id=message.message_id
                )
            )

            logger.debug(f"Published message {message.message_id} to queue '{queue_name}'")
            return message.message_id

        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            return None

    def consume(
        self,
        queue_name: str,
        callback: Callable[[Message], bool],
        auto_ack: bool = False
    ) -> None:
        """
        Consume messages from queue.

        Args:
            queue_name: Queue name
            callback: Callback function (returns True if message processed successfully)
            auto_ack: Automatically acknowledge messages
        """
        if not self.channel:
            logger.error("Cannot consume: not connected to RabbitMQ")
            return

        def on_message(ch: Any, method: Any, properties: Any, body: bytes) -> None:
            """Callback function for processing messages."""
            try:
                data = json.loads(body)
                message = Message.from_dict(data)

                # Process message
                success = callback(message)

                if success:
                    if not auto_ack:
                        ch.basic_ack(delivery_tag=method.delivery_tag)
                    logger.debug(f"Message {message.message_id} processed successfully")
                else:
                    # Retry logic
                    if message.retry_count < message.max_retries:
                        message.retry_count += 1
                        self.publish(queue_name, message.payload, message.priority)
                        logger.warning(f"Message {message.message_id} requeued (retry {message.retry_count})")
                    else:
                        logger.error(f"Message {message.message_id} exceeded max retries, moving to DLQ")
                        # Move to dead letter queue
                        self.publish(f"{queue_name}_dlq", message.payload, message.priority)

                    if not auto_ack:
                        ch.basic_ack(delivery_tag=method.delivery_tag)

            except Exception as e:
                logger.error(f"Error processing message: {e}")
                if not auto_ack:
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

        try:
            self.channel.basic_qos(prefetch_count=1)
            self.channel.basic_consume(
                queue=queue_name,
                on_message_callback=on_message,
                auto_ack=auto_ack
            )

            self.consumers[queue_name] = callback
            logger.info(f"Started consuming from queue '{queue_name}'")

            self.channel.start_consuming()

        except Exception as e:
            logger.error(f"Failed to consume from queue '{queue_name}': {e}")

    def stop_consuming(self) -> None:
        """Stop consuming messages"""
        if self.channel:
            self.channel.stop_consuming()
            logger.info("Stopped consuming messages")

    def purge_queue(self, queue_name: str) -> bool:
        """Purge all messages from queue"""
        if not self.channel:
            return False

        try:
            self.channel.queue_purge(queue_name)
            logger.info(f"Queue '{queue_name}' purged")
            return True
        except Exception as e:
            logger.error(f"Failed to purge queue '{queue_name}': {e}")
            return False

    def get_queue_size(self, queue_name: str) -> Optional[int]:
        """Get number of messages in queue"""
        if not self.channel:
            return None

        try:
            method = self.channel.queue_declare(queue=queue_name, passive=True)
            return method.method.message_count
        except Exception as e:
            logger.error(f"Failed to get queue size for '{queue_name}': {e}")
            return None

    def close(self) -> None:
        """Close connection"""
        if self.connection:
            self.connection.close()
            logger.info("RabbitMQ connection closed")


# Global message queue instance
_message_queue: Optional[MessageQueue] = None


def get_message_queue(
    host: str = "localhost",
    port: int = 5672,
    username: str = "guest",
    password: str = "guest"
) -> MessageQueue:
    """Get the global message queue instance."""
    global _message_queue
    if _message_queue is None:
        _message_queue = MessageQueue(host=host, port=port, username=username, password=password)
    return _message_queue
