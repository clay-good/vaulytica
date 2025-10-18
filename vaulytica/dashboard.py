from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from vaulytica.models import SecurityEvent, AnalysisResult, Severity
from vaulytica.ml_engine import MLEngine
from vaulytica.agents.security_analyst import SecurityAnalystAgent
from vaulytica.playbooks import PlaybookEngine
from vaulytica.threat_feeds import ThreatFeedIntegration
from vaulytica.correlation import CorrelationEngine
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class DashboardStats(BaseModel):
    """Dashboard statistics model."""
    total_events: int
    events_last_24h: int
    critical_events: int
    high_events: int
    anomalies_detected: int
    threats_predicted: int
    playbooks_executed: int
    avg_analysis_time: float
    ml_accuracy: float
    threat_feed_hits: int


class EventSummary(BaseModel):
    """Event summary for dashboard display."""
    event_id: str
    timestamp: datetime
    severity: str
    category: str
    title: str
    source_system: str
    ml_anomaly_score: Optional[float] = None
    ml_threat_level: Optional[str] = None
    status: str = "pending"  # pending, analyzing, complete, error


class DashboardManager:
    """
    Manages the web dashboard for Vaulytica.
    
    Features:
    - Real-time event streaming via WebSockets
    - Interactive charts and visualizations
    - ML predictions and anomaly detection
    - Playbook execution monitoring
    - Threat intelligence dashboard
    - System health monitoring
    """
    
    def __init__(
        self,
        ml_engine: Optional[MLEngine] = None,
        analyst_agent: Optional[SecurityAnalystAgent] = None,
        playbook_engine: Optional[PlaybookEngine] = None,
        threat_feeds: Optional[ThreatFeedIntegration] = None,
        correlation_engine: Optional[CorrelationEngine] = None
    ):
        """Initialize dashboard manager."""
        self.ml_engine = ml_engine or MLEngine(enable_training=True)
        self.analyst_agent = analyst_agent
        self.playbook_engine = playbook_engine
        self.threat_feeds = threat_feeds
        self.correlation_engine = correlation_engine
        
        # In-memory storage for dashboard data
        self.recent_events: List[EventSummary] = []
        self.analysis_results: Dict[str, AnalysisResult] = {}
        self.active_websockets: List[WebSocket] = []
        
        # Statistics
        self.stats = {
            "total_events": 0,
            "events_last_24h": 0,
            "critical_events": 0,
            "high_events": 0,
            "anomalies_detected": 0,
            "threats_predicted": 0,
            "playbooks_executed": 0,
            "analysis_times": [],
            "threat_feed_hits": 0
        }
        
        logger.info("Dashboard manager initialized")
    
    async def add_event(self, event: SecurityEvent) -> EventSummary:
        """Add new event to dashboard."""
        # Create event summary
        summary = EventSummary(
            event_id=event.event_id,
            timestamp=event.timestamp,
            severity=event.severity.value,
            category=event.category.value,
            title=event.title,
            source_system=event.source_system,
            status="pending"
        )
        
        # Update statistics
        self.stats["total_events"] += 1
        if (datetime.utcnow() - event.timestamp).total_seconds() < 86400:
            self.stats["events_last_24h"] += 1
        
        if event.severity == Severity.CRITICAL:
            self.stats["critical_events"] += 1
        elif event.severity == Severity.HIGH:
            self.stats["high_events"] += 1
        
        # Run ML analysis
        if self.ml_engine:
            anomaly = self.ml_engine.detect_anomaly(event, None)
            prediction = self.ml_engine.predict_threat(event, None)

            summary.ml_anomaly_score = anomaly.anomaly_score
            summary.ml_threat_level = prediction.predicted_threat_level.value

            if anomaly.is_anomaly:
                self.stats["anomalies_detected"] += 1
            if prediction.predicted_threat_level.value in ["CRITICAL", "HIGH"]:
                self.stats["threats_predicted"] += 1
        
        # Add to recent events (keep last 100)
        self.recent_events.insert(0, summary)
        if len(self.recent_events) > 100:
            self.recent_events.pop()
        
        # Broadcast to websockets
        await self.broadcast_event(summary)
        
        logger.info(f"Event added to dashboard: {event.event_id}")
        return summary
    
    async def broadcast_event(self, event: EventSummary):
        """Broadcast event to all connected websockets."""
        message = {
            "type": "new_event",
            "data": event.dict()
        }
        
        disconnected = []
        for ws in self.active_websockets:
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send to websocket: {e}")
                disconnected.append(ws)
        
        # Remove disconnected websockets
        for ws in disconnected:
            self.active_websockets.remove(ws)
    
    async def broadcast_stats(self):
        """Broadcast updated statistics to all websockets."""
        stats = self.get_stats()
        message = {
            "type": "stats_update",
            "data": stats.dict()
        }
        
        for ws in self.active_websockets:
            try:
                await ws.send_json(message)
            except Exception:
                pass
    
    def get_stats(self) -> DashboardStats:
        """Get current dashboard statistics."""
        avg_time = (
            sum(self.stats["analysis_times"]) / len(self.stats["analysis_times"])
            if self.stats["analysis_times"] else 0.0
        )
        
        ml_stats = self.ml_engine.get_statistics() if self.ml_engine else {}
        ml_accuracy = (
            1.0 - ml_stats.get("anomaly_rate", 0.0)
            if ml_stats.get("total_predictions", 0) > 0 else 0.0
        )
        
        return DashboardStats(
            total_events=self.stats["total_events"],
            events_last_24h=self.stats["events_last_24h"],
            critical_events=self.stats["critical_events"],
            high_events=self.stats["high_events"],
            anomalies_detected=self.stats["anomalies_detected"],
            threats_predicted=self.stats["threats_predicted"],
            playbooks_executed=self.stats["playbooks_executed"],
            avg_analysis_time=avg_time,
            ml_accuracy=ml_accuracy,
            threat_feed_hits=self.stats["threat_feed_hits"]
        )
    
    def get_recent_events(self, limit: int = 50) -> List[EventSummary]:
        """Get recent events for dashboard display."""
        return self.recent_events[:limit]
    
    def get_severity_distribution(self) -> Dict[str, int]:
        """Get severity distribution for charts."""
        distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for event in self.recent_events:
            if event.severity in distribution:
                distribution[event.severity] += 1
        
        return distribution
    
    def get_timeline_data(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get timeline data for charts."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # Group events by hour
        timeline = {}
        for event in self.recent_events:
            if event.timestamp >= cutoff:
                hour_key = event.timestamp.replace(minute=0, second=0, microsecond=0)
                if hour_key not in timeline:
                    timeline[hour_key] = {
                        "timestamp": hour_key.isoformat(),
                        "count": 0,
                        "critical": 0,
                        "high": 0,
                        "anomalies": 0
                    }
                
                timeline[hour_key]["count"] += 1
                if event.severity == "CRITICAL":
                    timeline[hour_key]["critical"] += 1
                elif event.severity == "HIGH":
                    timeline[hour_key]["high"] += 1
                
                if event.ml_anomaly_score and event.ml_anomaly_score > 0.7:
                    timeline[hour_key]["anomalies"] += 1
        
        return sorted(timeline.values(), key=lambda x: x["timestamp"])
    
    def get_ml_insights(self) -> Dict[str, Any]:
        """Get ML engine insights for dashboard."""
        if not self.ml_engine:
            return {}
        
        stats = self.ml_engine.get_statistics()
        
        return {
            "total_predictions": stats.get("total_predictions", 0),
            "anomalies_detected": stats.get("anomalies_detected", 0),
            "threats_predicted": stats.get("threats_predicted", 0),
            "anomaly_rate": stats.get("anomaly_rate", 0.0),
            "threat_rate": stats.get("threat_rate", 0.0),
            "training_samples": stats.get("training_samples", 0)
        }
    
    async def register_websocket(self, websocket: WebSocket):
        """Register new websocket connection."""
        await websocket.accept()
        self.active_websockets.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_websockets)}")
        
        # Send initial data
        await websocket.send_json({
            "type": "initial_data",
            "data": {
                "stats": self.get_stats().dict(),
                "recent_events": [e.dict() for e in self.get_recent_events(20)]
            }
        })
    
    async def unregister_websocket(self, websocket: WebSocket):
        """Unregister websocket connection."""
        if websocket in self.active_websockets:
            self.active_websockets.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_websockets)}")


# Global dashboard manager instance
dashboard_manager: Optional[DashboardManager] = None


def get_dashboard_manager() -> DashboardManager:
    """Get or create dashboard manager instance."""
    global dashboard_manager
    if dashboard_manager is None:
        dashboard_manager = DashboardManager()
    return dashboard_manager

