"""Tests for WebSocket API endpoints."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import User, Domain, ScanRun
from backend.auth.security import create_access_token
from backend.core.websocket import ConnectionManager


class TestWebSocketConnection:
    """Test WebSocket connection handling."""

    def test_connect_without_token(self, client: TestClient):
        """Should accept connection without token (anonymous)."""
        with client.websocket_connect("/api/v1/ws") as websocket:
            data = websocket.receive_json()
            assert data["type"] == "connected"
            assert data["user_id"] is None

    def test_connect_with_valid_token(self, client: TestClient, test_user: User):
        """Should authenticate user with valid token."""
        token = create_access_token(data={"sub": str(test_user.id), "user_id": test_user.id})

        with client.websocket_connect(f"/api/v1/ws?token={token}") as websocket:
            data = websocket.receive_json()
            assert data["type"] == "connected"
            assert data["user_id"] == test_user.id

    def test_connect_with_invalid_token(self, client: TestClient):
        """Should close connection with invalid token."""
        with pytest.raises(Exception):  # WebSocket close
            with client.websocket_connect("/api/v1/ws?token=invalid_token"):
                pass

    def test_ping_pong(self, client: TestClient):
        """Should respond to ping with pong."""
        with client.websocket_connect("/api/v1/ws") as websocket:
            # Skip connected message
            websocket.receive_json()

            websocket.send_json({"action": "ping"})
            data = websocket.receive_json()
            assert data["type"] == "pong"

    def test_invalid_json(self, client: TestClient):
        """Should handle invalid JSON gracefully."""
        with client.websocket_connect("/api/v1/ws") as websocket:
            # Skip connected message
            websocket.receive_json()

            websocket.send_text("not valid json")
            data = websocket.receive_json()
            assert data["type"] == "error"
            assert "Invalid JSON" in data["message"]

    def test_unknown_action(self, client: TestClient):
        """Should respond with error for unknown actions."""
        with client.websocket_connect("/api/v1/ws") as websocket:
            # Skip connected message
            websocket.receive_json()

            websocket.send_json({"action": "unknown_action"})
            data = websocket.receive_json()
            assert data["type"] == "error"
            assert "Unknown action" in data["message"]


class TestWebSocketScanSubscription:
    """Test scan subscription functionality."""

    def test_subscribe_to_scan(self, client: TestClient, db: Session):
        """Should allow subscription to scan updates."""
        # Create a scan
        scan = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="running",
        )
        db.add(scan)
        db.commit()

        with client.websocket_connect("/api/v1/ws") as websocket:
            # Skip connected message
            websocket.receive_json()

            websocket.send_json({"action": "subscribe_scan", "scan_id": scan.id})
            data = websocket.receive_json()
            assert data["type"] == "subscribed"
            assert data["scan_id"] == scan.id

    def test_unsubscribe_from_scan(self, client: TestClient, db: Session):
        """Should allow unsubscription from scan updates."""
        scan = ScanRun(
            scan_type="files",
            domain_name="test.com",
            status="running",
        )
        db.add(scan)
        db.commit()

        with client.websocket_connect("/api/v1/ws") as websocket:
            # Skip connected message
            websocket.receive_json()

            # Subscribe first
            websocket.send_json({"action": "subscribe_scan", "scan_id": scan.id})
            websocket.receive_json()

            # Unsubscribe
            websocket.send_json({"action": "unsubscribe_scan", "scan_id": scan.id})
            data = websocket.receive_json()
            assert data["type"] == "unsubscribed"
            assert data["scan_id"] == scan.id


class TestWebSocketScanEndpoint:
    """Test scan-specific WebSocket endpoint."""

    def test_connect_to_scan_endpoint(self, client: TestClient, db: Session):
        """Should auto-subscribe to scan when connecting to scan endpoint."""
        scan = ScanRun(
            scan_type="users",
            domain_name="test.com",
            status="running",
        )
        db.add(scan)
        db.commit()

        with client.websocket_connect(f"/api/v1/ws/scans/{scan.id}") as websocket:
            data = websocket.receive_json()
            assert data["type"] == "connected"
            assert data["scan_id"] == scan.id

    def test_scan_endpoint_with_token(self, client: TestClient, db: Session, test_user: User):
        """Should authenticate on scan-specific endpoint."""
        scan = ScanRun(
            scan_type="oauth",
            domain_name="test.com",
            status="running",
        )
        db.add(scan)
        db.commit()

        token = create_access_token(data={"sub": str(test_user.id), "user_id": test_user.id})

        with client.websocket_connect(
            f"/api/v1/ws/scans/{scan.id}?token={token}"
        ) as websocket:
            data = websocket.receive_json()
            assert data["type"] == "connected"

    def test_scan_endpoint_ping_pong(self, client: TestClient, db: Session):
        """Should respond to ping on scan endpoint."""
        scan = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="running",
        )
        db.add(scan)
        db.commit()

        with client.websocket_connect(f"/api/v1/ws/scans/{scan.id}") as websocket:
            # Skip connected message
            websocket.receive_json()

            websocket.send_json({"action": "ping"})
            data = websocket.receive_json()
            assert data["type"] == "pong"


class TestConnectionManager:
    """Test the ConnectionManager class."""

    @pytest.mark.asyncio
    async def test_connect_disconnect(self):
        """Should track connections properly."""
        manager = ConnectionManager()

        # Create mock websocket
        websocket = AsyncMock()
        websocket.accept = AsyncMock()
        websocket.send_json = AsyncMock()

        # Connect
        await manager.connect(websocket, user_id=1)
        assert websocket in manager.active_connections
        websocket.accept.assert_called_once()

        # Disconnect
        await manager.disconnect(websocket, user_id=1)
        assert websocket not in manager.active_connections

    @pytest.mark.asyncio
    async def test_scan_subscription(self):
        """Should track scan subscriptions."""
        manager = ConnectionManager()

        websocket = AsyncMock()
        websocket.accept = AsyncMock()
        websocket.send_json = AsyncMock()

        await manager.connect(websocket, user_id=1)

        # Subscribe to scan
        await manager.subscribe_to_scan(websocket, scan_id=123)
        assert 123 in manager.scan_subscribers
        assert websocket in manager.scan_subscribers[123]

        # Unsubscribe
        await manager.unsubscribe_from_scan(websocket, scan_id=123)
        assert websocket not in manager.scan_subscribers.get(123, set())

    @pytest.mark.asyncio
    async def test_broadcast_to_scan(self):
        """Should broadcast message to scan subscribers."""
        manager = ConnectionManager()

        # Create multiple mock websockets
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_json = AsyncMock()

        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.send_json = AsyncMock()

        await manager.connect(ws1, user_id=1)
        await manager.connect(ws2, user_id=2)

        # Subscribe both to same scan
        await manager.subscribe_to_scan(ws1, scan_id=456)
        await manager.subscribe_to_scan(ws2, scan_id=456)

        # Broadcast
        message = {"type": "scan_progress", "progress": 50}
        await manager.broadcast_to_scan(456, message)

        ws1.send_json.assert_called_with(message)
        ws2.send_json.assert_called_with(message)

    @pytest.mark.asyncio
    async def test_send_personal_message(self):
        """Should send message to specific websocket."""
        manager = ConnectionManager()

        websocket = AsyncMock()
        websocket.accept = AsyncMock()
        websocket.send_json = AsyncMock()

        await manager.connect(websocket, user_id=1)

        message = {"type": "notification", "text": "Hello"}
        await manager.send_personal_message(message, websocket)

        websocket.send_json.assert_called_with(message)

    @pytest.mark.asyncio
    async def test_broadcast_handles_disconnected(self):
        """Should handle disconnected clients during broadcast."""
        manager = ConnectionManager()

        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_json = AsyncMock()

        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        # Simulate disconnection
        ws2.send_json = AsyncMock(side_effect=Exception("Connection closed"))

        await manager.connect(ws1, user_id=1)
        await manager.connect(ws2, user_id=2)

        await manager.subscribe_to_scan(ws1, scan_id=789)
        await manager.subscribe_to_scan(ws2, scan_id=789)

        # Should not raise even with failed send
        message = {"type": "scan_completed"}
        await manager.broadcast_to_scan(789, message)

        # ws1 should still receive message
        ws1.send_json.assert_called_with(message)
