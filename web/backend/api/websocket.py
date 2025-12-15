"""WebSocket API endpoints for real-time updates."""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from typing import Optional
import json

from ..core.websocket import manager
from ..auth.security import decode_token
from ..db.database import get_db
from ..db.models import User
from sqlalchemy.orm import Session
from jose import JWTError

logger = logging.getLogger(__name__)

router = APIRouter()


async def get_current_user_ws(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get current user from WebSocket query parameter token."""
    if not token:
        logger.debug("WebSocket connection attempted without token")
        return None
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            logger.warning("WebSocket token missing 'sub' claim")
            return None
        user = db.query(User).filter(User.id == int(user_id)).first()
        if user:
            logger.debug(f"WebSocket authenticated user: {user.id}")
        return user
    except JWTError as e:
        logger.warning(f"WebSocket JWT validation failed: {e}")
        return None
    except ValueError as e:
        logger.warning(f"WebSocket token parsing error: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in WebSocket authentication: {type(e).__name__}: {e}")
        return None


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    Main WebSocket endpoint for real-time updates.

    Connect with: ws://host/api/ws?token=<jwt_token>

    Messages from client:
    - {"action": "subscribe_scan", "scan_id": 123}
    - {"action": "unsubscribe_scan", "scan_id": 123}
    - {"action": "ping"}

    Messages from server:
    - {"type": "connected", "user_id": 123}
    - {"type": "scan_progress", "scan_id": 123, "data": {...}}
    - {"type": "scan_status", "scan_id": 123, "status": "completed"}
    - {"type": "scan_completed", "scan_id": 123, "result": {...}}
    - {"type": "scan_failed", "scan_id": 123, "error": "..."}
    - {"type": "pong"}
    - {"type": "error", "message": "..."}
    """
    # Validate token
    user_id = None
    if token:
        try:
            payload = decode_token(token)
            user_id = int(payload.get("sub"))
            logger.debug(f"WebSocket /ws connected for user_id={user_id}")
        except JWTError as e:
            logger.warning(f"WebSocket /ws invalid JWT token: {e}")
            await websocket.close(code=4001, reason="Invalid token")
            return
        except (ValueError, TypeError) as e:
            logger.warning(f"WebSocket /ws token parsing error: {e}")
            await websocket.close(code=4001, reason="Invalid token format")
            return

    # Accept connection
    await manager.connect(websocket, user_id)

    try:
        # Send connected message
        await manager.send_personal_message({
            "type": "connected",
            "user_id": user_id,
            "message": "WebSocket connection established"
        }, websocket)

        # Listen for messages from client
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                action = message.get("action")

                if action == "subscribe_scan":
                    scan_id = message.get("scan_id")
                    if scan_id:
                        await manager.subscribe_to_scan(websocket, scan_id)
                        await manager.send_personal_message({
                            "type": "subscribed",
                            "scan_id": scan_id
                        }, websocket)

                elif action == "unsubscribe_scan":
                    scan_id = message.get("scan_id")
                    if scan_id:
                        await manager.unsubscribe_from_scan(websocket, scan_id)
                        await manager.send_personal_message({
                            "type": "unsubscribed",
                            "scan_id": scan_id
                        }, websocket)

                elif action == "ping":
                    await manager.send_personal_message({
                        "type": "pong"
                    }, websocket)

                else:
                    await manager.send_personal_message({
                        "type": "error",
                        "message": f"Unknown action: {action}"
                    }, websocket)

            except json.JSONDecodeError:
                await manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON"
                }, websocket)

    except WebSocketDisconnect:
        logger.debug(f"WebSocket /ws disconnected normally for user_id={user_id}")
        await manager.disconnect(websocket, user_id)
    except Exception as e:
        logger.error(f"WebSocket /ws unexpected error for user_id={user_id}: {type(e).__name__}: {e}")
        await manager.disconnect(websocket, user_id)


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_endpoint(
    websocket: WebSocket,
    scan_id: int,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for a specific scan's updates.

    Connect with: ws://host/api/ws/scans/123?token=<jwt_token>

    Automatically subscribes to the scan on connection.
    """
    # Validate token (optional for now, but recommended)
    user_id = None
    if token:
        try:
            payload = decode_token(token)
            user_id = int(payload.get("sub"))
            logger.debug(f"WebSocket /ws/scans/{scan_id} connected for user_id={user_id}")
        except JWTError as e:
            logger.warning(f"WebSocket /ws/scans/{scan_id} invalid JWT token: {e}")
            await websocket.close(code=4001, reason="Invalid token")
            return
        except (ValueError, TypeError) as e:
            logger.warning(f"WebSocket /ws/scans/{scan_id} token parsing error: {e}")
            await websocket.close(code=4001, reason="Invalid token format")
            return

    # Accept and connect
    await manager.connect(websocket, user_id)
    await manager.subscribe_to_scan(websocket, scan_id)

    try:
        # Send connected message
        await manager.send_personal_message({
            "type": "connected",
            "scan_id": scan_id,
            "message": f"Subscribed to scan {scan_id} updates"
        }, websocket)

        # Keep connection alive and handle messages
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                action = message.get("action")

                if action == "ping":
                    await manager.send_personal_message({
                        "type": "pong"
                    }, websocket)

            except json.JSONDecodeError:
                await manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON"
                }, websocket)

    except WebSocketDisconnect:
        logger.debug(f"WebSocket /ws/scans/{scan_id} disconnected normally for user_id={user_id}")
        await manager.unsubscribe_from_scan(websocket, scan_id)
        await manager.disconnect(websocket, user_id)
    except Exception as e:
        logger.error(
            f"WebSocket /ws/scans/{scan_id} unexpected error for user_id={user_id}: "
            f"{type(e).__name__}: {e}"
        )
        await manager.unsubscribe_from_scan(websocket, scan_id)
        await manager.disconnect(websocket, user_id)
