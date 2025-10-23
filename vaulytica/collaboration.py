"""
Real-Time Collaboration Engine for Vaulytica.

Enables multiple analysts to work together on incidents in real-time with:
- Shared workspaces
- Live updates via WebSocket
- Integrated chat
- Activity feeds
- Presence indicators
- Collaborative annotations
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

import logging

logger = logging.getLogger(__name__)


class ActivityType(str, Enum):
    """Types of activities that can be tracked."""
    INCIDENT_OPENED = "incident_opened"
    INCIDENT_CLOSED = "incident_closed"
    COMMENT_ADDED = "comment_added"
    ANNOTATION_ADDED = "annotation_added"
    STATUS_CHANGED = "status_changed"
    PRIORITY_CHANGED = "priority_changed"
    ASSIGNEE_CHANGED = "assignee_changed"
    EVIDENCE_ADDED = "evidence_added"
    PLAYBOOK_EXECUTED = "playbook_executed"
    ANALYST_JOINED = "analyst_joined"
    ANALYST_LEFT = "analyst_left"
    CHAT_MESSAGE = "chat_message"


class PresenceStatus(str, Enum):
    """Analyst presence status."""
    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    OFFLINE = "offline"


@dataclass
class Analyst:
    """Analyst information."""
    analyst_id: str
    name: str
    email: str
    role: str
    avatar_url: Optional[str] = None


@dataclass
class PresenceInfo:
    """Analyst presence information."""
    analyst: Analyst
    status: PresenceStatus
    current_incident_id: Optional[str] = None
    last_seen: datetime = field(default_factory=datetime.utcnow)
    current_activity: Optional[str] = None


@dataclass
class Activity:
    """Activity log entry."""
    activity_id: str
    activity_type: ActivityType
    analyst: Analyst
    incident_id: str
    timestamp: datetime
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChatMessage:
    """Chat message."""
    message_id: str
    incident_id: str
    analyst: Analyst
    content: str
    timestamp: datetime
    reply_to: Optional[str] = None
    mentions: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Annotation:
    """Collaborative annotation."""
    annotation_id: str
    incident_id: str
    analyst: Analyst
    target_type: str  # "event", "log_entry", "timeline_item", etc.
    target_id: str
    content: str
    timestamp: datetime
    color: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class SharedWorkspace:
    """Shared workspace for incident collaboration."""
    workspace_id: str
    incident_id: str
    created_at: datetime
    active_analysts: Set[str] = field(default_factory=set)
    activities: List[Activity] = field(default_factory=list)
    chat_messages: List[ChatMessage] = field(default_factory=list)
    annotations: List[Annotation] = field(default_factory=list)
    shared_state: Dict[str, Any] = field(default_factory=dict)


class CollaborationEngine:
    """
    Real-time collaboration engine.

    Manages shared workspaces, presence, activities, chat, and annotations.
    """

    def __init__(self):
        self.workspaces: Dict[str, SharedWorkspace] = {}
        self.presence: Dict[str, PresenceInfo] = {}
        self.websocket_connections: Dict[str, Set[Any]] = {}  # incident_id -> set of websocket connections

    # ==================== Workspace Management ====================

    def create_workspace(self, incident_id: str) -> SharedWorkspace:
        """Create a new shared workspace for an incident."""
        workspace_id = str(uuid4())
        workspace = SharedWorkspace(
            workspace_id=workspace_id,
            incident_id=incident_id,
            created_at=datetime.utcnow()
        )
        self.workspaces[incident_id] = workspace
        logger.info(f"Created workspace {workspace_id} for incident {incident_id}")
        return workspace

    def get_workspace(self, incident_id: str) -> Optional[SharedWorkspace]:
        """Get workspace for an incident."""
        return self.workspaces.get(incident_id)

    def get_or_create_workspace(self, incident_id: str) -> SharedWorkspace:
        """Get or create workspace for an incident."""
        workspace = self.get_workspace(incident_id)
        if not workspace:
            workspace = self.create_workspace(incident_id)
        return workspace

    # ==================== Presence Management ====================

    def update_presence(
        self,
        analyst: Analyst,
        status: PresenceStatus,
        current_incident_id: Optional[str] = None,
        current_activity: Optional[str] = None
    ) -> PresenceInfo:
        """Update analyst presence."""
        presence = PresenceInfo(
            analyst=analyst,
            status=status,
            current_incident_id=current_incident_id,
            last_seen=datetime.utcnow(),
            current_activity=current_activity
        )
        self.presence[analyst.analyst_id] = presence

        # Broadcast presence update
        if current_incident_id:
            asyncio.create_task(self._broadcast_presence_update(current_incident_id, presence))

        return presence

    def get_presence(self, analyst_id: str) -> Optional[PresenceInfo]:
        """Get analyst presence."""
        return self.presence.get(analyst_id)

    def get_active_analysts(self, incident_id: str) -> List[PresenceInfo]:
        """Get all analysts currently working on an incident."""
        return [
            presence for presence in self.presence.values()
            if presence.current_incident_id == incident_id and presence.status != PresenceStatus.OFFLINE
        ]

    # ==================== Activity Tracking ====================

    async def log_activity(
        self,
        incident_id: str,
        analyst: Analyst,
        activity_type: ActivityType,
        description: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Activity:
        """Log an activity."""
        workspace = self.get_or_create_workspace(incident_id)

        activity = Activity(
            activity_id=str(uuid4()),
            activity_type=activity_type,
            analyst=analyst,
            incident_id=incident_id,
            timestamp=datetime.utcnow(),
            description=description,
            metadata=metadata or {}
        )

        workspace.activities.append(activity)

        # Broadcast activity to all connected analysts
        await self._broadcast_activity(incident_id, activity)

        logger.info(f"Logged activity: {activity_type} by {analyst.name} on incident {incident_id}")
        return activity

    def get_activities(
        self,
        incident_id: str,
        limit: Optional[int] = None,
        activity_types: Optional[List[ActivityType]] = None
    ) -> List[Activity]:
        """Get activities for an incident."""
        workspace = self.get_workspace(incident_id)
        if not workspace:
            return []

        activities = workspace.activities

        # Filter by activity types
        if activity_types:
            activities = [a for a in activities if a.activity_type in activity_types]

        # Sort by timestamp (most recent first)
        activities = sorted(activities, key=lambda a: a.timestamp, reverse=True)

        # Limit results
        if limit:
            activities = activities[:limit]

        return activities

    # ==================== Chat ====================

    async def send_chat_message(
        self,
        incident_id: str,
        analyst: Analyst,
        content: str,
        reply_to: Optional[str] = None,
        mentions: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> ChatMessage:
        """Send a chat message."""
        workspace = self.get_or_create_workspace(incident_id)

        message = ChatMessage(
            message_id=str(uuid4()),
            incident_id=incident_id,
            analyst=analyst,
            content=content,
            timestamp=datetime.utcnow(),
            reply_to=reply_to,
            mentions=mentions or [],
            attachments=attachments or []
        )

        workspace.chat_messages.append(message)

        # Broadcast message to all connected analysts
        await self._broadcast_chat_message(incident_id, message)

        # Log activity
        await self.log_activity(
            incident_id=incident_id,
            analyst=analyst,
            activity_type=ActivityType.CHAT_MESSAGE,
            description=f"Sent chat message: {content[:50]}...",
            metadata={"message_id": message.message_id}
        )

        return message

    def get_chat_messages(
        self,
        incident_id: str,
        limit: Optional[int] = None,
        since: Optional[datetime] = None
    ) -> List[ChatMessage]:
        """Get chat messages for an incident."""
        workspace = self.get_workspace(incident_id)
        if not workspace:
            return []

        messages = workspace.chat_messages

        # Filter by timestamp
        if since:
            messages = [m for m in messages if m.timestamp > since]

        # Sort by timestamp
        messages = sorted(messages, key=lambda m: m.timestamp)

        # Limit results
        if limit:
            messages = messages[-limit:]  # Get most recent N messages

        return messages

    # ==================== Annotations ====================

    async def add_annotation(
        self,
        incident_id: str,
        analyst: Analyst,
        target_type: str,
        target_id: str,
        content: str,
        color: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Annotation:
        """Add a collaborative annotation."""
        workspace = self.get_or_create_workspace(incident_id)

        annotation = Annotation(
            annotation_id=str(uuid4()),
            incident_id=incident_id,
            analyst=analyst,
            target_type=target_type,
            target_id=target_id,
            content=content,
            timestamp=datetime.utcnow(),
            color=color,
            tags=tags or []
        )

        workspace.annotations.append(annotation)

        # Broadcast annotation to all connected analysts
        await self._broadcast_annotation(incident_id, annotation)

        # Log activity
        await self.log_activity(
            incident_id=incident_id,
            analyst=analyst,
            activity_type=ActivityType.ANNOTATION_ADDED,
            description=f"Added annotation to {target_type}: {content[:50]}...",
            metadata={"annotation_id": annotation.annotation_id, "target_type": target_type, "target_id": target_id}
        )

        return annotation

    def get_annotations(
        self,
        incident_id: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> List[Annotation]:
        """Get annotations for an incident."""
        workspace = self.get_workspace(incident_id)
        if not workspace:
            return []

        annotations = workspace.annotations

        # Filter by target type
        if target_type:
            annotations = [a for a in annotations if a.target_type == target_type]

        # Filter by target ID
        if target_id:
            annotations = [a for a in annotations if a.target_id == target_id]

        # Filter by tags
        if tags:
            annotations = [a for a in annotations if any(tag in a.tags for tag in tags)]

        return annotations

    # ==================== Analyst Join/Leave ====================

    async def analyst_join(self, incident_id: str, analyst: Analyst) -> None:
        """Analyst joins an incident workspace."""
        workspace = self.get_or_create_workspace(incident_id)
        workspace.active_analysts.add(analyst.analyst_id)

        # Update presence
        self.update_presence(
            analyst=analyst,
            status=PresenceStatus.ONLINE,
            current_incident_id=incident_id,
            current_activity="Viewing incident"
        )

        # Log activity
        await self.log_activity(
            incident_id=incident_id,
            analyst=analyst,
            activity_type=ActivityType.ANALYST_JOINED,
            description=f"{analyst.name} joined the incident",
            metadata={"analyst_id": analyst.analyst_id}
        )

        logger.info(f"Analyst {analyst.name} joined incident {incident_id}")

    async def analyst_leave(self, incident_id: str, analyst: Analyst) -> None:
        """Analyst leaves an incident workspace."""
        workspace = self.get_workspace(incident_id)
        if workspace and analyst.analyst_id in workspace.active_analysts:
            workspace.active_analysts.remove(analyst.analyst_id)

        # Update presence
        self.update_presence(
            analyst=analyst,
            status=PresenceStatus.ONLINE,
            current_incident_id=None,
            current_activity=None
        )

        # Log activity
        await self.log_activity(
            incident_id=incident_id,
            analyst=analyst,
            activity_type=ActivityType.ANALYST_LEFT,
            description=f"{analyst.name} left the incident",
            metadata={"analyst_id": analyst.analyst_id}
        )

        logger.info(f"Analyst {analyst.name} left incident {incident_id}")

    # ==================== WebSocket Broadcasting ====================

    def register_websocket(self, incident_id: str, websocket: Any) -> None:
        """Register a WebSocket connection for an incident."""
        if incident_id not in self.websocket_connections:
            self.websocket_connections[incident_id] = set()
        self.websocket_connections[incident_id].add(websocket)
        logger.debug(f"Registered WebSocket for incident {incident_id}")

    def unregister_websocket(self, incident_id: str, websocket: Any) -> None:
        """Unregister a WebSocket connection."""
        if incident_id in self.websocket_connections:
            self.websocket_connections[incident_id].discard(websocket)
            logger.debug(f"Unregistered WebSocket for incident {incident_id}")

    async def _broadcast_activity(self, incident_id: str, activity: Activity) -> None:
        """Broadcast activity to all connected analysts."""
        await self._broadcast_message(incident_id, {
            "type": "activity",
            "data": {
                "activity_id": activity.activity_id,
                "activity_type": activity.activity_type,
                "analyst": {
                    "analyst_id": activity.analyst.analyst_id,
                    "name": activity.analyst.name,
                    "role": activity.analyst.role
                },
                "timestamp": activity.timestamp.isoformat(),
                "description": activity.description,
                "metadata": activity.metadata
            }
        })

    async def _broadcast_chat_message(self, incident_id: str, message: ChatMessage) -> None:
        """Broadcast chat message to all connected analysts."""
        await self._broadcast_message(incident_id, {
            "type": "chat_message",
            "data": {
                "message_id": message.message_id,
                "analyst": {
                    "analyst_id": message.analyst.analyst_id,
                    "name": message.analyst.name,
                    "role": message.analyst.role
                },
                "content": message.content,
                "timestamp": message.timestamp.isoformat(),
                "reply_to": message.reply_to,
                "mentions": message.mentions,
                "attachments": message.attachments
            }
        })

    async def _broadcast_annotation(self, incident_id: str, annotation: Annotation) -> None:
        """Broadcast annotation to all connected analysts."""
        await self._broadcast_message(incident_id, {
            "type": "annotation",
            "data": {
                "annotation_id": annotation.annotation_id,
                "analyst": {
                    "analyst_id": annotation.analyst.analyst_id,
                    "name": annotation.analyst.name,
                    "role": annotation.analyst.role
                },
                "target_type": annotation.target_type,
                "target_id": annotation.target_id,
                "content": annotation.content,
                "timestamp": annotation.timestamp.isoformat(),
                "color": annotation.color,
                "tags": annotation.tags
            }
        })

    async def _broadcast_presence_update(self, incident_id: str, presence: PresenceInfo) -> None:
        """Broadcast presence update to all connected analysts."""
        await self._broadcast_message(incident_id, {
            "type": "presence_update",
            "data": {
                "analyst_id": presence.analyst.analyst_id,
                "name": presence.analyst.name,
                "status": presence.status,
                "current_activity": presence.current_activity,
                "last_seen": presence.last_seen.isoformat()
            }
        })

    async def _broadcast_message(self, incident_id: str, message: Dict[str, Any]) -> None:
        """Broadcast a message to all WebSocket connections for an incident."""
        if incident_id not in self.websocket_connections:
            return

        message_json = json.dumps(message)
        disconnected = set()

        for websocket in self.websocket_connections[incident_id]:
            try:
                await websocket.send_text(message_json)
            except Exception as e:
                logger.warning(f"Failed to send message to WebSocket: {e}")
                disconnected.add(websocket)

        # Remove disconnected WebSockets
        for websocket in disconnected:
            self.websocket_connections[incident_id].discard(websocket)


# Global collaboration engine instance
_collaboration_engine: Optional[CollaborationEngine] = None


def get_collaboration_engine() -> CollaborationEngine:
    """Get the global collaboration engine instance."""
    global _collaboration_engine
    if _collaboration_engine is None:
        _collaboration_engine = CollaborationEngine()
    return _collaboration_engine
