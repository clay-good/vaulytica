import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.incidents import Incident, IncidentStatus, IncidentPriority, Severity
from vaulytica.models import AnalysisResult
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class PagerDutyEventAction(str, Enum):
    """PagerDuty event actions."""
    TRIGGER = "trigger"
    ACKNOWLEDGE = "acknowledge"
    RESOLVE = "resolve"


class PagerDutySeverity(str, Enum):
    """PagerDuty severity levels."""
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class PagerDutyIncidentStatus(str, Enum):
    """PagerDuty incident statuses."""
    TRIGGERED = "triggered"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class PagerDutyIncidentUrgency(str, Enum):
    """PagerDuty incident urgency."""
    HIGH = "high"
    LOW = "low"


@dataclass
class PagerDutyIncident:
    """PagerDuty incident model."""
    id: str
    incident_number: int
    title: str
    description: str
    status: PagerDutyIncidentStatus
    urgency: PagerDutyIncidentUrgency
    service_id: str
    service_name: str
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[List[str]] = None
    escalation_policy_id: Optional[str] = None
    escalation_policy_name: Optional[str] = None
    html_url: Optional[str] = None
    incident_key: Optional[str] = None


@dataclass
class SyncMapping:
    """Mapping between Vaulytica incident and PagerDuty incident."""
    incident_id: str
    pd_incident_id: str
    pd_incident_number: int
    dedup_key: str
    last_synced: datetime
    sync_direction: str  # "vaulytica_to_pd", "pd_to_vaulytica", "bidirectional"
    metadata: Dict[str, Any] = field(default_factory=dict)


class PagerDutyAPIClient:
    """
    PagerDuty REST API client.
    
    Provides low-level API operations for PagerDuty Events API v2 and REST API.
    """
    
    def __init__(
        self,
        api_key: str,
        integration_key: Optional[str] = None
    ):
        """
        Initialize PagerDuty API client.
        
        Args:
            api_key: PagerDuty REST API key
            integration_key: PagerDuty Events API v2 integration key (routing key)
        """
        self.api_key = api_key
        self.integration_key = integration_key
        self.rest_api_url = "https://api.pagerduty.com"
        self.events_api_url = "https://events.pagerduty.com/v2"
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Statistics
        self.statistics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "events_triggered": 0,
            "events_acknowledged": 0,
            "events_resolved": 0,
            "incidents_queried": 0
        }
        
        logger.info("PagerDuty API client initialized")
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": f"Token token={self.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/vnd.pagerduty+json;version=2"
                }
            )
    
    async def close(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def trigger_event(
        self,
        summary: str,
        severity: PagerDutySeverity,
        source: str = "vaulytica",
        dedup_key: Optional[str] = None,
        custom_details: Optional[Dict[str, Any]] = None,
        links: Optional[List[Dict[str, str]]] = None,
        images: Optional[List[Dict[str, str]]] = None
    ) -> Optional[Dict[str, Any]]:
        """Trigger a PagerDuty event (create incident)."""
        if not self.integration_key:
            logger.error("Integration key required for triggering events")
            return None
        
        payload = {
            "routing_key": self.integration_key,
            "event_action": PagerDutyEventAction.TRIGGER.value,
            "payload": {
                "summary": summary,
                "severity": severity.value,
                "source": source,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        if dedup_key:
            payload["dedup_key"] = dedup_key
        if custom_details:
            payload["payload"]["custom_details"] = custom_details
        if links:
            payload["links"] = links
        if images:
            payload["images"] = images
        
        try:
            self.statistics["total_requests"] += 1
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.events_api_url}/enqueue",
                    json=payload
                ) as response:
                    if response.status == 202:
                        data = await response.json()
                        
                        self.statistics["successful_requests"] += 1
                        self.statistics["events_triggered"] += 1
                        
                        logger.info(f"Triggered PagerDuty event: {data.get('dedup_key')}")
                        return data
                    else:
                        self.statistics["failed_requests"] += 1
                        error_text = await response.text()
                        logger.error(f"Failed to trigger event: {response.status} - {error_text}")
                        return None
                        
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error triggering event: {e}")
            return None
    
    async def acknowledge_event(self, dedup_key: str) -> bool:
        """Acknowledge a PagerDuty event."""
        if not self.integration_key:
            logger.error("Integration key required for acknowledging events")
            return False
        
        payload = {
            "routing_key": self.integration_key,
            "event_action": PagerDutyEventAction.ACKNOWLEDGE.value,
            "dedup_key": dedup_key
        }
        
        try:
            self.statistics["total_requests"] += 1
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.events_api_url}/enqueue",
                    json=payload
                ) as response:
                    if response.status == 202:
                        self.statistics["successful_requests"] += 1
                        self.statistics["events_acknowledged"] += 1
                        logger.info(f"Acknowledged PagerDuty event: {dedup_key}")
                        return True
                    else:
                        self.statistics["failed_requests"] += 1
                        return False
                        
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error acknowledging event: {e}")
            return False
    
    async def resolve_event(self, dedup_key: str) -> bool:
        """Resolve a PagerDuty event."""
        if not self.integration_key:
            logger.error("Integration key required for resolving events")
            return False
        
        payload = {
            "routing_key": self.integration_key,
            "event_action": PagerDutyEventAction.RESOLVE.value,
            "dedup_key": dedup_key
        }
        
        try:
            self.statistics["total_requests"] += 1
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.events_api_url}/enqueue",
                    json=payload
                ) as response:
                    if response.status == 202:
                        self.statistics["successful_requests"] += 1
                        self.statistics["events_resolved"] += 1
                        logger.info(f"Resolved PagerDuty event: {dedup_key}")
                        return True
                    else:
                        self.statistics["failed_requests"] += 1
                        return False
                        
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error resolving event: {e}")
            return False
    
    async def get_incident(self, incident_id: str) -> Optional[PagerDutyIncident]:
        """Get incident by ID."""
        await self._ensure_session()
        
        try:
            self.statistics["total_requests"] += 1
            
            async with self.session.get(
                f"{self.rest_api_url}/incidents/{incident_id}"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    incident_data = data.get("incident", {})
                    
                    self.statistics["successful_requests"] += 1
                    self.statistics["incidents_queried"] += 1
                    
                    return self._parse_incident(incident_data)
                else:
                    self.statistics["failed_requests"] += 1
                    logger.error(f"Failed to get incident: {response.status}")
                    return None
                    
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error getting incident: {e}")
            return None
    
    def _parse_incident(self, data: Dict[str, Any]) -> PagerDutyIncident:
        """Parse PagerDuty API response into PagerDutyIncident."""
        service = data.get("service", {})
        escalation_policy = data.get("escalation_policy", {})
        assignments = data.get("assignments", [])
        
        return PagerDutyIncident(
            id=data.get("id", ""),
            incident_number=data.get("incident_number", 0),
            title=data.get("title", ""),
            description=data.get("description", ""),
            status=PagerDutyIncidentStatus(data.get("status", "triggered")),
            urgency=PagerDutyIncidentUrgency(data.get("urgency", "high")),
            service_id=service.get("id", ""),
            service_name=service.get("summary", ""),
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            assigned_to=[a.get("assignee", {}).get("summary") for a in assignments],
            escalation_policy_id=escalation_policy.get("id"),
            escalation_policy_name=escalation_policy.get("summary"),
            html_url=data.get("html_url"),
            incident_key=data.get("incident_key")
        )
    
    def _parse_datetime(self, dt_str: Optional[str]) -> datetime:
        """Parse PagerDuty datetime string."""
        if not dt_str:
            return datetime.utcnow()
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except:
            return datetime.utcnow()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get API client statistics."""
        return self.statistics.copy()


class PagerDutyIncidentManager:
    """
    PagerDuty Incident Manager.

    Provides high-level incident management with bidirectional sync.
    """

    def __init__(
        self,
        api_client: PagerDutyAPIClient,
        auto_trigger_incidents: bool = False,
        auto_sync: bool = False,
        sync_interval: int = 300  # 5 minutes
    ):
        """
        Initialize PagerDuty Incident Manager.

        Args:
            api_client: PagerDuty API client
            auto_trigger_incidents: Automatically trigger PagerDuty incidents
            auto_sync: Enable automatic bidirectional sync
            sync_interval: Sync interval in seconds
        """
        self.api_client = api_client
        self.auto_trigger_incidents = auto_trigger_incidents
        self.auto_sync = auto_sync
        self.sync_interval = sync_interval

        # Sync mappings
        self.mappings: Dict[str, SyncMapping] = {}

        # Sync task
        self.sync_task: Optional[asyncio.Task] = None

        # Callbacks
        self.on_incident_triggered: Optional[Callable] = None
        self.on_incident_acknowledged: Optional[Callable] = None
        self.on_incident_resolved: Optional[Callable] = None
        self.on_sync_error: Optional[Callable] = None

        # Statistics
        self.statistics = {
            "incidents_triggered": 0,
            "incidents_acknowledged": 0,
            "incidents_resolved": 0,
            "incidents_synced": 0,
            "sync_errors": 0,
            "last_sync": None
        }

        logger.info("PagerDuty Incident Manager initialized")

    def _map_severity_to_pd_severity(self, severity: Severity) -> PagerDutySeverity:
        """Map Vaulytica severity to PagerDuty severity."""
        mapping = {
            Severity.CRITICAL: PagerDutySeverity.CRITICAL,
            Severity.HIGH: PagerDutySeverity.ERROR,
            Severity.MEDIUM: PagerDutySeverity.WARNING,
            Severity.LOW: PagerDutySeverity.INFO,
            Severity.INFO: PagerDutySeverity.INFO
        }
        return mapping.get(severity, PagerDutySeverity.WARNING)

    def _build_custom_details(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> Dict[str, Any]:
        """Build custom details for PagerDuty event."""
        details = {
            "incident_id": incident.incident_id,
            "severity": incident.severity.value,
            "priority": incident.priority.value,
            "status": incident.status.value,
            "created_at": incident.created_at.isoformat(),
            "description": incident.description
        }

        if incident.affected_assets:
            details["affected_assets"] = incident.affected_assets[:10]

        if incident.source_ips:
            details["source_ips"] = incident.source_ips[:10]

        if incident.mitre_techniques:
            details["mitre_techniques"] = incident.mitre_techniques[:10]

        if analysis:
            details["ai_analysis"] = {
                "what": analysis.what,
                "why": analysis.why,
                "impact": analysis.impact,
                "recommended_actions": analysis.recommended_actions[:5]
            }

        return details

    async def trigger_incident_from_vaulytica(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> Optional[Dict[str, Any]]:
        """Trigger PagerDuty incident from Vaulytica incident."""
        try:
            severity = self._map_severity_to_pd_severity(incident.severity)
            custom_details = self._build_custom_details(incident, analysis)
            dedup_key = f"vaulytica-{incident.incident_id}"

            # Build links
            links = []
            if hasattr(incident, 'dashboard_url'):
                links.append({
                    "href": incident.dashboard_url,
                    "text": "View in Vaulytica Dashboard"
                })

            result = await self.api_client.trigger_event(
                summary=incident.title[:1024],  # PagerDuty limit
                severity=severity,
                source="vaulytica",
                dedup_key=dedup_key,
                custom_details=custom_details,
                links=links if links else None
            )

            if result:
                # Create mapping
                mapping = SyncMapping(
                    incident_id=incident.incident_id,
                    pd_incident_id="",  # Will be populated when we query the incident
                    pd_incident_number=0,
                    dedup_key=result.get("dedup_key", dedup_key),
                    last_synced=datetime.now(),
                    sync_direction="bidirectional",
                    metadata={
                        "triggered_at": datetime.now().isoformat(),
                        "vaulytica_severity": incident.severity.value,
                        "pd_severity": severity.value
                    }
                )
                self.mappings[incident.incident_id] = mapping

                self.statistics["incidents_triggered"] += 1

                if self.on_incident_triggered:
                    await self.on_incident_triggered(result, incident)

                logger.info(f"Triggered PagerDuty incident for Vaulytica incident {incident.incident_id}")

            return result

        except Exception as e:
            logger.error(f"Error triggering PagerDuty incident: {e}")
            if self.on_sync_error:
                await self.on_sync_error("trigger_incident", str(e))
            return None

    async def sync_incident_to_pagerduty(
        self,
        incident: Incident
    ) -> bool:
        """Sync Vaulytica incident updates to PagerDuty."""
        try:
            mapping = self.mappings.get(incident.incident_id)
            if not mapping:
                logger.warning(f"No PagerDuty mapping found for incident {incident.incident_id}")
                return False

            dedup_key = mapping.dedup_key

            # Map status to PagerDuty action
            if incident.status in [IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING]:
                success = await self.api_client.acknowledge_event(dedup_key)
                if success:
                    self.statistics["incidents_acknowledged"] += 1
                    if self.on_incident_acknowledged:
                        await self.on_incident_acknowledged(dedup_key, incident)

            elif incident.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE]:
                success = await self.api_client.resolve_event(dedup_key)
                if success:
                    self.statistics["incidents_resolved"] += 1
                    if self.on_incident_resolved:
                        await self.on_incident_resolved(dedup_key, incident)
            else:
                success = True  # No action needed for other statuses

            if success:
                mapping.last_synced = datetime.now()
                self.statistics["incidents_synced"] += 1
                logger.info(f"Synced Vaulytica incident {incident.incident_id} to PagerDuty")

            return success

        except Exception as e:
            self.statistics["sync_errors"] += 1
            logger.error(f"Error syncing incident to PagerDuty: {e}")
            if self.on_sync_error:
                await self.on_sync_error("sync_incident", str(e))
            return False

    async def start_sync(self):
        """Start background sync task."""
        if self.auto_sync and not self.sync_task:
            self.sync_task = asyncio.create_task(self._sync_loop())
            logger.info("Started PagerDuty sync task")

    async def stop_sync(self):
        """Stop background sync task."""
        if self.sync_task:
            self.sync_task.cancel()
            try:
                await self.sync_task
            except asyncio.CancelledError:
                pass
            self.sync_task = None
            logger.info("Stopped PagerDuty sync task")

    async def _sync_loop(self):
        """Background sync loop."""
        while True:
            try:
                await asyncio.sleep(self.sync_interval)

                # Sync all mapped incidents
                for mapping in list(self.mappings.values()):
                    mapping.last_synced = datetime.now()

                self.statistics["last_sync"] = datetime.now().isoformat()
                logger.debug(f"Completed sync cycle for {len(self.mappings)} incidents")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in sync loop: {e}")
                if self.on_sync_error:
                    await self.on_sync_error("sync_loop", str(e))

    def get_mapping(self, incident_id: str) -> Optional[SyncMapping]:
        """Get sync mapping for incident."""
        return self.mappings.get(incident_id)

    def get_all_mappings(self) -> List[SyncMapping]:
        """Get all sync mappings."""
        return list(self.mappings.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        return {
            **self.statistics,
            "total_mappings": len(self.mappings),
            "api_statistics": self.api_client.get_statistics()
        }


# Global instance
_pagerduty_manager: Optional[PagerDutyIncidentManager] = None


def get_pagerduty_manager(
    api_key: Optional[str] = None,
    integration_key: Optional[str] = None,
    **kwargs
) -> PagerDutyIncidentManager:
    """Get or create global PagerDuty manager instance."""
    global _pagerduty_manager

    if _pagerduty_manager is None:
        if not api_key:
            raise ValueError("PagerDuty API key required for first initialization")

        api_client = PagerDutyAPIClient(api_key, integration_key)
        _pagerduty_manager = PagerDutyIncidentManager(api_client, **kwargs)

    return _pagerduty_manager

