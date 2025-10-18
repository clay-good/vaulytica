import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from base64 import b64encode

from vaulytica.incidents import Incident, IncidentStatus, IncidentPriority, Severity
from vaulytica.models import AnalysisResult
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class ServiceNowIncidentState(str, Enum):
    """ServiceNow incident states."""
    NEW = "1"
    IN_PROGRESS = "2"
    ON_HOLD = "3"
    RESOLVED = "6"
    CLOSED = "7"
    CANCELLED = "8"


class ServiceNowPriority(str, Enum):
    """ServiceNow priority levels."""
    P1_CRITICAL = "1"
    P2_HIGH = "2"
    P3_MODERATE = "3"
    P4_LOW = "4"
    P5_PLANNING = "5"


class ServiceNowImpact(str, Enum):
    """ServiceNow impact levels."""
    HIGH = "1"
    MEDIUM = "2"
    LOW = "3"


class ServiceNowUrgency(str, Enum):
    """ServiceNow urgency levels."""
    HIGH = "1"
    MEDIUM = "2"
    LOW = "3"


@dataclass
class ServiceNowIncident:
    """ServiceNow incident model."""
    sys_id: str
    number: str
    short_description: str
    description: str
    state: ServiceNowIncidentState
    priority: ServiceNowPriority
    impact: ServiceNowImpact
    urgency: ServiceNowUrgency
    category: str
    subcategory: Optional[str] = None
    assigned_to: Optional[str] = None
    assignment_group: Optional[str] = None
    caller_id: Optional[str] = None
    opened_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    work_notes: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    cmdb_ci: Optional[str] = None  # Configuration Item
    business_service: Optional[str] = None
    correlation_id: Optional[str] = None
    additional_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SyncMapping:
    """Mapping between Vaulytica incident and ServiceNow incident."""
    incident_id: str
    snow_sys_id: str
    snow_number: str
    last_synced: datetime
    sync_direction: str  # "vaulytica_to_snow", "snow_to_vaulytica", "bidirectional"
    metadata: Dict[str, Any] = field(default_factory=dict)


class ServiceNowAPIClient:
    """
    ServiceNow REST API client.
    
    Provides low-level API operations for ServiceNow Table API.
    """
    
    def __init__(
        self,
        instance: str,
        username: str,
        password: str,
        api_version: str = "v2"
    ):
        """
        Initialize ServiceNow API client.
        
        Args:
            instance: ServiceNow instance name (e.g., 'dev12345')
            username: ServiceNow username
            password: ServiceNow password
            api_version: API version (default: v2)
        """
        self.instance = instance
        self.base_url = f"https://{instance}.service-now.com/api/now/{api_version}"
        self.username = username
        self.password = password
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Statistics
        self.statistics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "incidents_created": 0,
            "incidents_updated": 0,
            "incidents_queried": 0
        }
        
        logger.info(f"ServiceNow API client initialized for instance: {instance}")
    
    def _get_auth_header(self) -> str:
        """Generate Basic Auth header."""
        credentials = f"{self.username}:{self.password}"
        encoded = b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": self._get_auth_header(),
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            )
    
    async def close(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def create_incident(
        self,
        short_description: str,
        description: str,
        priority: ServiceNowPriority,
        impact: ServiceNowImpact,
        urgency: ServiceNowUrgency,
        category: str = "Security",
        assignment_group: Optional[str] = None,
        caller_id: Optional[str] = None,
        **kwargs
    ) -> Optional[ServiceNowIncident]:
        """Create a new ServiceNow incident."""
        await self._ensure_session()
        
        payload = {
            "short_description": short_description,
            "description": description,
            "priority": priority.value,
            "impact": impact.value,
            "urgency": urgency.value,
            "category": category
        }
        
        if assignment_group:
            payload["assignment_group"] = assignment_group
        if caller_id:
            payload["caller_id"] = caller_id
        
        # Add any additional fields
        payload.update(kwargs)
        
        try:
            self.statistics["total_requests"] += 1
            
            async with self.session.post(
                f"{self.base_url}/table/incident",
                json=payload
            ) as response:
                if response.status == 201:
                    data = await response.json()
                    result = data.get("result", {})
                    
                    self.statistics["successful_requests"] += 1
                    self.statistics["incidents_created"] += 1
                    
                    incident = self._parse_incident(result)
                    logger.info(f"Created ServiceNow incident: {incident.number}")
                    return incident
                else:
                    self.statistics["failed_requests"] += 1
                    error_text = await response.text()
                    logger.error(f"Failed to create incident: {response.status} - {error_text}")
                    return None
                    
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error creating incident: {e}")
            return None
    
    async def get_incident(self, sys_id: str) -> Optional[ServiceNowIncident]:
        """Get incident by sys_id."""
        await self._ensure_session()
        
        try:
            self.statistics["total_requests"] += 1
            
            async with self.session.get(
                f"{self.base_url}/table/incident/{sys_id}"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    result = data.get("result", {})
                    
                    self.statistics["successful_requests"] += 1
                    self.statistics["incidents_queried"] += 1
                    
                    return self._parse_incident(result)
                else:
                    self.statistics["failed_requests"] += 1
                    logger.error(f"Failed to get incident: {response.status}")
                    return None
                    
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error getting incident: {e}")
            return None
    
    def _parse_incident(self, data: Dict[str, Any]) -> ServiceNowIncident:
        """Parse ServiceNow API response into ServiceNowIncident."""
        return ServiceNowIncident(
            sys_id=data.get("sys_id", ""),
            number=data.get("number", ""),
            short_description=data.get("short_description", ""),
            description=data.get("description", ""),
            state=ServiceNowIncidentState(data.get("state", "1")),
            priority=ServiceNowPriority(data.get("priority", "3")),
            impact=ServiceNowImpact(data.get("impact", "3")),
            urgency=ServiceNowUrgency(data.get("urgency", "3")),
            category=data.get("category", ""),
            subcategory=data.get("subcategory"),
            assigned_to=data.get("assigned_to", {}).get("value") if isinstance(data.get("assigned_to"), dict) else data.get("assigned_to"),
            assignment_group=data.get("assignment_group", {}).get("value") if isinstance(data.get("assignment_group"), dict) else data.get("assignment_group"),
            caller_id=data.get("caller_id", {}).get("value") if isinstance(data.get("caller_id"), dict) else data.get("caller_id"),
            opened_at=self._parse_datetime(data.get("opened_at")),
            resolved_at=self._parse_datetime(data.get("resolved_at")),
            closed_at=self._parse_datetime(data.get("closed_at")),
            cmdb_ci=data.get("cmdb_ci", {}).get("value") if isinstance(data.get("cmdb_ci"), dict) else data.get("cmdb_ci"),
            business_service=data.get("business_service", {}).get("value") if isinstance(data.get("business_service"), dict) else data.get("business_service"),
            correlation_id=data.get("correlation_id"),
            additional_fields={k: v for k, v in data.items() if k not in [
                "sys_id", "number", "short_description", "description", "state",
                "priority", "impact", "urgency", "category", "subcategory",
                "assigned_to", "assignment_group", "caller_id", "opened_at",
                "resolved_at", "closed_at", "cmdb_ci", "business_service", "correlation_id"
            ]}
        )
    
    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse ServiceNow datetime string."""
        if not dt_str:
            return None
        try:
            return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except:
            return None

    async def update_incident(
        self,
        sys_id: str,
        **fields
    ) -> Optional[ServiceNowIncident]:
        """Update an existing ServiceNow incident."""
        await self._ensure_session()

        try:
            self.statistics["total_requests"] += 1

            async with self.session.patch(
                f"{self.base_url}/table/incident/{sys_id}",
                json=fields
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    result = data.get("result", {})

                    self.statistics["successful_requests"] += 1
                    self.statistics["incidents_updated"] += 1

                    incident = self._parse_incident(result)
                    logger.info(f"Updated ServiceNow incident: {incident.number}")
                    return incident
                else:
                    self.statistics["failed_requests"] += 1
                    error_text = await response.text()
                    logger.error(f"Failed to update incident: {response.status} - {error_text}")
                    return None

        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error updating incident: {e}")
            return None

    async def list_incidents(
        self,
        state: Optional[ServiceNowIncidentState] = None,
        priority: Optional[ServiceNowPriority] = None,
        assignment_group: Optional[str] = None,
        limit: int = 100
    ) -> List[ServiceNowIncident]:
        """List ServiceNow incidents with filters."""
        await self._ensure_session()

        params = {"sysparm_limit": limit}
        query_parts = []

        if state:
            query_parts.append(f"state={state.value}")
        if priority:
            query_parts.append(f"priority={priority.value}")
        if assignment_group:
            query_parts.append(f"assignment_group={assignment_group}")

        if query_parts:
            params["sysparm_query"] = "^".join(query_parts)

        try:
            self.statistics["total_requests"] += 1

            async with self.session.get(
                f"{self.base_url}/table/incident",
                params=params
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    results = data.get("result", [])

                    self.statistics["successful_requests"] += 1
                    self.statistics["incidents_queried"] += len(results)

                    incidents = [self._parse_incident(r) for r in results]
                    logger.info(f"Retrieved {len(incidents)} ServiceNow incidents")
                    return incidents
                else:
                    self.statistics["failed_requests"] += 1
                    logger.error(f"Failed to list incidents: {response.status}")
                    return []

        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error listing incidents: {e}")
            return []

    async def add_work_note(self, sys_id: str, note: str) -> bool:
        """Add a work note to an incident."""
        return await self.update_incident(sys_id, work_notes=note) is not None

    async def add_comment(self, sys_id: str, comment: str) -> bool:
        """Add a comment to an incident."""
        return await self.update_incident(sys_id, comments=comment) is not None

    async def resolve_incident(
        self,
        sys_id: str,
        resolution_notes: str,
        resolution_code: str = "Solved (Permanently)"
    ) -> Optional[ServiceNowIncident]:
        """Resolve a ServiceNow incident."""
        return await self.update_incident(
            sys_id,
            state=ServiceNowIncidentState.RESOLVED.value,
            close_notes=resolution_notes,
            close_code=resolution_code
        )

    async def close_incident(
        self,
        sys_id: str,
        close_notes: str,
        close_code: str = "Solved (Permanently)"
    ) -> Optional[ServiceNowIncident]:
        """Close a ServiceNow incident."""
        return await self.update_incident(
            sys_id,
            state=ServiceNowIncidentState.CLOSED.value,
            close_notes=close_notes,
            close_code=close_code
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get API client statistics."""
        return self.statistics.copy()


class ServiceNowIncidentManager:
    """
    ServiceNow Incident Manager.

    Provides high-level incident management with bidirectional sync.
    """

    def __init__(
        self,
        api_client: ServiceNowAPIClient,
        auto_create_incidents: bool = False,
        auto_sync: bool = False,
        sync_interval: int = 300,  # 5 minutes
        assignment_group: Optional[str] = None,
        caller_id: Optional[str] = None
    ):
        """
        Initialize ServiceNow Incident Manager.

        Args:
            api_client: ServiceNow API client
            auto_create_incidents: Automatically create ServiceNow incidents
            auto_sync: Enable automatic bidirectional sync
            sync_interval: Sync interval in seconds
            assignment_group: Default assignment group
            caller_id: Default caller ID
        """
        self.api_client = api_client
        self.auto_create_incidents = auto_create_incidents
        self.auto_sync = auto_sync
        self.sync_interval = sync_interval
        self.assignment_group = assignment_group
        self.caller_id = caller_id

        # Sync mappings
        self.mappings: Dict[str, SyncMapping] = {}

        # Sync task
        self.sync_task: Optional[asyncio.Task] = None

        # Callbacks
        self.on_incident_created: Optional[Callable] = None
        self.on_incident_updated: Optional[Callable] = None
        self.on_sync_error: Optional[Callable] = None

        # Statistics
        self.statistics = {
            "incidents_created": 0,
            "incidents_updated": 0,
            "incidents_synced": 0,
            "sync_errors": 0,
            "last_sync": None
        }

        logger.info("ServiceNow Incident Manager initialized")

    def _map_severity_to_priority(self, severity: Severity) -> ServiceNowPriority:
        """Map Vaulytica severity to ServiceNow priority."""
        mapping = {
            Severity.CRITICAL: ServiceNowPriority.P1_CRITICAL,
            Severity.HIGH: ServiceNowPriority.P2_HIGH,
            Severity.MEDIUM: ServiceNowPriority.P3_MODERATE,
            Severity.LOW: ServiceNowPriority.P4_LOW,
            Severity.INFO: ServiceNowPriority.P5_PLANNING
        }
        return mapping.get(severity, ServiceNowPriority.P3_MODERATE)

    def _map_severity_to_impact(self, severity: Severity) -> ServiceNowImpact:
        """Map Vaulytica severity to ServiceNow impact."""
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            return ServiceNowImpact.HIGH
        elif severity == Severity.MEDIUM:
            return ServiceNowImpact.MEDIUM
        else:
            return ServiceNowImpact.LOW

    def _map_severity_to_urgency(self, severity: Severity) -> ServiceNowUrgency:
        """Map Vaulytica severity to ServiceNow urgency."""
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            return ServiceNowUrgency.HIGH
        elif severity == Severity.MEDIUM:
            return ServiceNowUrgency.MEDIUM
        else:
            return ServiceNowUrgency.LOW

    def _build_incident_description(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> str:
        """Build ServiceNow incident description from Vaulytica incident."""
        lines = [
            f"Vaulytica Incident ID: {incident.incident_id}",
            f"Severity: {incident.severity.value}",
            f"Priority: {incident.priority.value}",
            f"Status: {incident.status.value}",
            f"Created: {incident.created_at.isoformat()}",
            "",
            "Description:",
            incident.description or "No description available",
        ]

        if incident.affected_assets:
            lines.extend([
                "",
                "Affected Assets:",
                *[f"- {asset}" for asset in incident.affected_assets[:10]]
            ])

        if incident.source_ips:
            lines.extend([
                "",
                "Source IPs:",
                *[f"- {ip}" for ip in incident.source_ips[:10]]
            ])

        if incident.mitre_techniques:
            lines.extend([
                "",
                "MITRE ATT&CK Techniques:",
                *[f"- {technique}" for technique in incident.mitre_techniques[:10]]
            ])

        if analysis:
            lines.extend([
                "",
                "AI Analysis:",
                f"What: {analysis.what}",
                f"Why: {analysis.why}",
                f"Impact: {analysis.impact}",
                "",
                "Recommended Actions:",
                *[f"{i+1}. {action}" for i, action in enumerate(analysis.recommended_actions[:5])]
            ])

        return "\n".join(lines)

    async def create_incident_from_vaulytica(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> Optional[ServiceNowIncident]:
        """Create ServiceNow incident from Vaulytica incident."""
        try:
            priority = self._map_severity_to_priority(incident.severity)
            impact = self._map_severity_to_impact(incident.severity)
            urgency = self._map_severity_to_urgency(incident.severity)

            description = self._build_incident_description(incident, analysis)

            snow_incident = await self.api_client.create_incident(
                short_description=incident.title[:160],  # ServiceNow limit
                description=description,
                priority=priority,
                impact=impact,
                urgency=urgency,
                category="Security",
                assignment_group=self.assignment_group,
                caller_id=self.caller_id,
                correlation_id=incident.incident_id
            )

            if snow_incident:
                # Create mapping
                mapping = SyncMapping(
                    incident_id=incident.incident_id,
                    snow_sys_id=snow_incident.sys_id,
                    snow_number=snow_incident.number,
                    last_synced=datetime.now(),
                    sync_direction="bidirectional",
                    metadata={
                        "created_at": datetime.now().isoformat(),
                        "vaulytica_severity": incident.severity.value,
                        "snow_priority": priority.value
                    }
                )
                self.mappings[incident.incident_id] = mapping

                self.statistics["incidents_created"] += 1

                if self.on_incident_created:
                    await self.on_incident_created(snow_incident, incident)

                logger.info(f"Created ServiceNow incident {snow_incident.number} for Vaulytica incident {incident.incident_id}")

            return snow_incident

        except Exception as e:
            logger.error(f"Error creating ServiceNow incident: {e}")
            if self.on_sync_error:
                await self.on_sync_error("create_incident", str(e))
            return None

    async def sync_incident_to_servicenow(
        self,
        incident: Incident,
        sys_id: str
    ) -> Optional[ServiceNowIncident]:
        """Sync Vaulytica incident updates to ServiceNow."""
        try:
            # Map status
            state_mapping = {
                IncidentStatus.NEW: ServiceNowIncidentState.NEW,
                IncidentStatus.ACKNOWLEDGED: ServiceNowIncidentState.IN_PROGRESS,
                IncidentStatus.INVESTIGATING: ServiceNowIncidentState.IN_PROGRESS,
                IncidentStatus.CONTAINED: ServiceNowIncidentState.IN_PROGRESS,
                IncidentStatus.RESOLVED: ServiceNowIncidentState.RESOLVED,
                IncidentStatus.CLOSED: ServiceNowIncidentState.CLOSED,
                IncidentStatus.FALSE_POSITIVE: ServiceNowIncidentState.CANCELLED
            }

            state = state_mapping.get(incident.status, ServiceNowIncidentState.IN_PROGRESS)
            priority = self._map_severity_to_priority(incident.severity)

            fields = {
                "state": state.value,
                "priority": priority.value
            }

            if incident.assigned_to:
                fields["assigned_to"] = incident.assigned_to

            snow_incident = await self.api_client.update_incident(sys_id, **fields)

            if snow_incident:
                # Update mapping
                if incident.incident_id in self.mappings:
                    self.mappings[incident.incident_id].last_synced = datetime.now()

                self.statistics["incidents_synced"] += 1

                if self.on_incident_updated:
                    await self.on_incident_updated(snow_incident, incident)

                logger.info(f"Synced Vaulytica incident {incident.incident_id} to ServiceNow {snow_incident.number}")

            return snow_incident

        except Exception as e:
            self.statistics["sync_errors"] += 1
            logger.error(f"Error syncing incident to ServiceNow: {e}")
            if self.on_sync_error:
                await self.on_sync_error("sync_incident", str(e))
            return None

    async def start_sync(self):
        """Start background sync task."""
        if self.auto_sync and not self.sync_task:
            self.sync_task = asyncio.create_task(self._sync_loop())
            logger.info("Started ServiceNow sync task")

    async def stop_sync(self):
        """Stop background sync task."""
        if self.sync_task:
            self.sync_task.cancel()
            try:
                await self.sync_task
            except asyncio.CancelledError:
                pass
            self.sync_task = None
            logger.info("Stopped ServiceNow sync task")

    async def _sync_loop(self):
        """Background sync loop."""
        while True:
            try:
                await asyncio.sleep(self.sync_interval)

                # Sync all mapped incidents
                for mapping in list(self.mappings.values()):
                    # In production, fetch incident from incident manager
                    # For now, just update last_sync time
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
_servicenow_manager: Optional[ServiceNowIncidentManager] = None


def get_servicenow_manager(
    instance: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    **kwargs
) -> ServiceNowIncidentManager:
    """Get or create global ServiceNow manager instance."""
    global _servicenow_manager

    if _servicenow_manager is None:
        if not all([instance, username, password]):
            raise ValueError("ServiceNow credentials required for first initialization")

        api_client = ServiceNowAPIClient(instance, username, password)
        _servicenow_manager = ServiceNowIncidentManager(api_client, **kwargs)

    return _servicenow_manager

