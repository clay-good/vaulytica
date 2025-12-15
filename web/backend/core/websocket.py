"""WebSocket connection manager for real-time updates."""

import logging
from typing import Dict, Set, Optional
from fastapi import WebSocket
import json
import asyncio

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""

    def __init__(self):
        # Map of scan_id -> set of connected websockets
        self.scan_connections: Dict[int, Set[WebSocket]] = {}
        # Map of user_id -> set of connected websockets (for domain-wide updates)
        self.user_connections: Dict[int, Set[WebSocket]] = {}
        # All connected websockets for broadcast
        self.all_connections: Set[WebSocket] = set()
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user_id: Optional[int] = None):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self.all_connections.add(websocket)
            if user_id:
                if user_id not in self.user_connections:
                    self.user_connections[user_id] = set()
                self.user_connections[user_id].add(websocket)

    async def disconnect(self, websocket: WebSocket, user_id: Optional[int] = None):
        """Remove a WebSocket connection."""
        async with self._lock:
            self.all_connections.discard(websocket)
            if user_id and user_id in self.user_connections:
                self.user_connections[user_id].discard(websocket)
                if not self.user_connections[user_id]:
                    del self.user_connections[user_id]
            # Remove from all scan subscriptions
            for scan_id in list(self.scan_connections.keys()):
                self.scan_connections[scan_id].discard(websocket)
                if not self.scan_connections[scan_id]:
                    del self.scan_connections[scan_id]

    async def subscribe_to_scan(self, websocket: WebSocket, scan_id: int):
        """Subscribe a websocket to updates for a specific scan."""
        async with self._lock:
            if scan_id not in self.scan_connections:
                self.scan_connections[scan_id] = set()
            self.scan_connections[scan_id].add(websocket)

    async def unsubscribe_from_scan(self, websocket: WebSocket, scan_id: int):
        """Unsubscribe a websocket from a specific scan."""
        async with self._lock:
            if scan_id in self.scan_connections:
                self.scan_connections[scan_id].discard(websocket)
                if not self.scan_connections[scan_id]:
                    del self.scan_connections[scan_id]

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send a message to a specific websocket."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            # Connection closed, will be cleaned up on disconnect
            logger.debug(f"Failed to send personal message (connection likely closed): {type(e).__name__}")

    async def send_scan_update(self, scan_id: int, message: dict):
        """Send an update to all websockets subscribed to a scan."""
        async with self._lock:
            connections = self.scan_connections.get(scan_id, set()).copy()

        failed_count = 0
        for websocket in connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                # Connection closed, clean up
                logger.debug(f"Failed to send scan update for scan_id={scan_id}: {type(e).__name__}")
                failed_count += 1
                await self.disconnect(websocket)

        if failed_count > 0:
            logger.debug(f"Cleaned up {failed_count} dead connections for scan_id={scan_id}")

    async def send_to_user(self, user_id: int, message: dict):
        """Send a message to all connections for a specific user."""
        async with self._lock:
            connections = self.user_connections.get(user_id, set()).copy()

        failed_count = 0
        for websocket in connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.debug(f"Failed to send message to user_id={user_id}: {type(e).__name__}")
                failed_count += 1
                await self.disconnect(websocket, user_id)

        if failed_count > 0:
            logger.debug(f"Cleaned up {failed_count} dead connections for user_id={user_id}")

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected websockets."""
        async with self._lock:
            connections = self.all_connections.copy()

        failed_count = 0
        for websocket in connections:
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.debug(f"Failed to broadcast message: {type(e).__name__}")
                failed_count += 1
                await self.disconnect(websocket)

        if failed_count > 0:
            logger.debug(f"Cleaned up {failed_count} dead connections during broadcast")


# Global connection manager instance
manager = ConnectionManager()


async def broadcast_scan_progress(scan_id: int, progress_data: dict):
    """Helper function to broadcast scan progress updates."""
    message = {
        "type": "scan_progress",
        "scan_id": scan_id,
        "data": progress_data
    }
    await manager.send_scan_update(scan_id, message)


async def broadcast_scan_status(scan_id: int, status: str, details: Optional[dict] = None):
    """Helper function to broadcast scan status changes."""
    message = {
        "type": "scan_status",
        "scan_id": scan_id,
        "status": status,
        "details": details or {}
    }
    await manager.send_scan_update(scan_id, message)


async def broadcast_scan_completed(scan_id: int, result: dict):
    """Helper function to broadcast scan completion."""
    message = {
        "type": "scan_completed",
        "scan_id": scan_id,
        "result": result
    }
    await manager.send_scan_update(scan_id, message)


async def broadcast_scan_failed(scan_id: int, error: str):
    """Helper function to broadcast scan failure."""
    message = {
        "type": "scan_failed",
        "scan_id": scan_id,
        "error": error
    }
    await manager.send_scan_update(scan_id, message)
