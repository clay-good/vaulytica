import asyncio
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from urllib.parse import urljoin
import aiohttp

from vaulytica.logger import get_logger
from vaulytica.models import SecurityEvent, Severity, AnalysisResult
from vaulytica.incidents import Incident, IncidentStatus

logger = get_logger(__name__)


class DatadogCaseStatus(str, Enum):
    """Datadog case status values."""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class DatadogCasePriority(str, Enum):
    """Datadog case priority values."""
    P1 = "P1"  # Critical
    P2 = "P2"  # High
    P3 = "P3"  # Medium
    P4 = "P4"  # Low
    P5 = "P5"  # Informational


class DatadogCaseType(str, Enum):
    """Datadog case types."""
    SECURITY_INCIDENT = "SECURITY_INCIDENT"
    VULNERABILITY = "VULNERABILITY"
    COMPLIANCE = "COMPLIANCE"
    INVESTIGATION = "INVESTIGATION"
    OTHER = "OTHER"


@dataclass
class DatadogCase:
    """Datadog case representation."""
    case_id: str
    title: str
    description: str
    status: DatadogCaseStatus
    priority: DatadogCasePriority
    case_type: DatadogCaseType
    created_at: datetime
    updated_at: datetime
    assignee: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority.value,
            "case_type": self.case_type.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "assignee": self.assignee,
            "tags": self.tags,
            "attributes": self.attributes,
            "timeline": self.timeline
        }


@dataclass
class SyncMapping:
    """Mapping between Vaulytica incident and Datadog case."""
    incident_id: str
    case_id: str
    last_synced: datetime
    sync_direction: str  # "vaulytica_to_datadog", "datadog_to_vaulytica", "bidirectional"
    metadata: Dict[str, Any] = field(default_factory=dict)


class DatadogAPIClient:
    """Datadog API client with rate limiting and error handling."""
    
    def __init__(
        self,
        api_key: str,
        app_key: str,
        site: str = "datadoghq.com",
        timeout: int = 30,
        max_retries: int = 3
    ):
        """Initialize Datadog API client.
        
        Args:
            api_key: Datadog API key
            app_key: Datadog application key
            site: Datadog site (datadoghq.com, datadoghq.eu, etc.)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
        """
        self.api_key = api_key
        self.app_key = app_key
        self.base_url = f"https://api.{site}"
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Rate limiting
        self._rate_limit_remaining = 1000
        self._rate_limit_reset = datetime.now()
        self._request_semaphore = asyncio.Semaphore(10)  # Max 10 concurrent requests
        
        # Statistics
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.rate_limited_requests = 0
        
        logger.info(f"Datadog API client initialized for site: {site}")
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make HTTP request to Datadog API with rate limiting and retries."""
        url = urljoin(self.base_url, endpoint)
        headers = {
            "DD-API-KEY": self.api_key,
            "DD-APPLICATION-KEY": self.app_key,
            "Content-Type": "application/json"
        }
        
        async with self._request_semaphore:
            for attempt in range(self.max_retries):
                try:
                    # Check rate limit
                    if self._rate_limit_remaining <= 10 and datetime.now() < self._rate_limit_reset:
                        wait_time = (self._rate_limit_reset - datetime.now()).total_seconds()
                        logger.warning(f"Rate limit approaching, waiting {wait_time:.1f}s")
                        await asyncio.sleep(wait_time)
                    
                    self.total_requests += 1
                    
                    async with aiohttp.ClientSession() as session:
                        async with session.request(
                            method,
                            url,
                            headers=headers,
                            json=data,
                            params=params,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:
                            # Update rate limit info
                            if "X-RateLimit-Remaining" in response.headers:
                                self._rate_limit_remaining = int(response.headers["X-RateLimit-Remaining"])
                            if "X-RateLimit-Reset" in response.headers:
                                self._rate_limit_reset = datetime.fromtimestamp(
                                    int(response.headers["X-RateLimit-Reset"])
                                )
                            
                            if response.status == 429:  # Rate limited
                                self.rate_limited_requests += 1
                                retry_after = int(response.headers.get("Retry-After", 60))
                                logger.warning(f"Rate limited, retrying after {retry_after}s")
                                await asyncio.sleep(retry_after)
                                continue
                            
                            response.raise_for_status()
                            self.successful_requests += 1
                            return await response.json()
                
                except aiohttp.ClientError as e:
                    self.failed_requests += 1
                    if attempt == self.max_retries - 1:
                        logger.error(f"Request failed after {self.max_retries} attempts: {e}")
                        raise
                    logger.warning(f"Request failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        raise Exception("Request failed after all retries")
    
    async def get_case(self, case_id: str) -> Optional[DatadogCase]:
        """Get case by ID."""
        try:
            response = await self._make_request("GET", f"/api/v2/cases/{case_id}")
            return self._parse_case(response["data"])
        except Exception as e:
            logger.error(f"Failed to get case {case_id}: {e}")
            return None
    
    async def list_cases(
        self,
        status: Optional[DatadogCaseStatus] = None,
        priority: Optional[DatadogCasePriority] = None,
        limit: int = 100
    ) -> List[DatadogCase]:
        """List cases with optional filters."""
        params = {"page[size]": limit}
        if status:
            params["filter[status]"] = status.value
        if priority:
            params["filter[priority]"] = priority.value
        
        try:
            response = await self._make_request("GET", "/api/v2/cases", params=params)
            return [self._parse_case(case_data) for case_data in response.get("data", [])]
        except Exception as e:
            logger.error(f"Failed to list cases: {e}")
            return []
    
    async def create_case(
        self,
        title: str,
        description: str,
        priority: DatadogCasePriority,
        case_type: DatadogCaseType,
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None
    ) -> Optional[DatadogCase]:
        """Create new case."""
        data = {
            "data": {
                "type": "case",
                "attributes": {
                    "title": title,
                    "description": description,
                    "priority": priority.value,
                    "type": case_type.value,
                    "tags": tags or [],
                    **( attributes or {})
                }
            }
        }
        
        try:
            response = await self._make_request("POST", "/api/v2/cases", data=data)
            case = self._parse_case(response["data"])
            logger.info(f"Created Datadog case: {case.case_id}")
            return case
        except Exception as e:
            logger.error(f"Failed to create case: {e}")
            return None
    
    async def update_case(
        self,
        case_id: str,
        status: Optional[DatadogCaseStatus] = None,
        priority: Optional[DatadogCasePriority] = None,
        assignee: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Optional[DatadogCase]:
        """Update existing case."""
        attributes = {}
        if status:
            attributes["status"] = status.value
        if priority:
            attributes["priority"] = priority.value
        if assignee:
            attributes["assignee"] = assignee
        if tags is not None:
            attributes["tags"] = tags
        
        data = {
            "data": {
                "type": "case",
                "id": case_id,
                "attributes": attributes
            }
        }
        
        try:
            response = await self._make_request("PATCH", f"/api/v2/cases/{case_id}", data=data)
            case = self._parse_case(response["data"])
            logger.info(f"Updated Datadog case: {case_id}")
            return case
        except Exception as e:
            logger.error(f"Failed to update case {case_id}: {e}")
            return None

    async def add_timeline_event(
        self,
        case_id: str,
        event_type: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Add timeline event to case."""
        data = {
            "data": {
                "type": "case_timeline_event",
                "attributes": {
                    "event_type": event_type,
                    "message": message,
                    "metadata": metadata or {}
                }
            }
        }

        try:
            await self._make_request("POST", f"/api/v2/cases/{case_id}/timeline", data=data)
            logger.info(f"Added timeline event to case {case_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add timeline event: {e}")
            return False

    async def close_case(self, case_id: str, resolution: str) -> Optional[DatadogCase]:
        """Close case with resolution."""
        return await self.update_case(
            case_id,
            status=DatadogCaseStatus.CLOSED
        )

    def _parse_case(self, case_data: Dict[str, Any]) -> DatadogCase:
        """Parse case data from API response."""
        attrs = case_data.get("attributes", {})
        return DatadogCase(
            case_id=case_data["id"],
            title=attrs.get("title", ""),
            description=attrs.get("description", ""),
            status=DatadogCaseStatus(attrs.get("status", "OPEN")),
            priority=DatadogCasePriority(attrs.get("priority", "P3")),
            case_type=DatadogCaseType(attrs.get("type", "OTHER")),
            created_at=datetime.fromisoformat(attrs.get("created_at", datetime.now().isoformat())),
            updated_at=datetime.fromisoformat(attrs.get("updated_at", datetime.now().isoformat())),
            assignee=attrs.get("assignee"),
            tags=attrs.get("tags", []),
            attributes=attrs.get("attributes", {}),
            timeline=attrs.get("timeline", [])
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get API client statistics."""
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "rate_limited_requests": self.rate_limited_requests,
            "success_rate": self.successful_requests / self.total_requests if self.total_requests > 0 else 0,
            "rate_limit_remaining": self._rate_limit_remaining,
            "rate_limit_reset": self._rate_limit_reset.isoformat()
        }


class DatadogCaseManager:
    """Manages bidirectional synchronization between Vaulytica and Datadog cases."""

    def __init__(
        self,
        api_client: DatadogAPIClient,
        sync_interval: int = 300,  # 5 minutes
        auto_create_cases: bool = True,
        auto_sync: bool = True
    ):
        """Initialize case manager.

        Args:
            api_client: Datadog API client
            sync_interval: Sync interval in seconds
            auto_create_cases: Automatically create Datadog cases for new incidents
            auto_sync: Enable automatic bidirectional sync
        """
        self.api_client = api_client
        self.sync_interval = sync_interval
        self.auto_create_cases = auto_create_cases
        self.auto_sync = auto_sync

        # Sync mappings
        self.mappings: Dict[str, SyncMapping] = {}  # incident_id -> mapping
        self.case_to_incident: Dict[str, str] = {}  # case_id -> incident_id

        # Sync callbacks
        self.on_case_created: List[Callable] = []
        self.on_case_updated: List[Callable] = []
        self.on_sync_error: List[Callable] = []

        # Statistics
        self.total_syncs = 0
        self.successful_syncs = 0
        self.failed_syncs = 0
        self.cases_created = 0
        self.cases_updated = 0

        # Background sync task
        self._sync_task: Optional[asyncio.Task] = None

        logger.info("Datadog case manager initialized")

    async def start_sync(self):
        """Start background sync task."""
        if self._sync_task is None or self._sync_task.done():
            self._sync_task = asyncio.create_task(self._sync_loop())
            logger.info("Started background sync task")

    async def stop_sync(self):
        """Stop background sync task."""
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped background sync task")

    async def _sync_loop(self):
        """Background sync loop."""
        while True:
            try:
                await asyncio.sleep(self.sync_interval)
                await self.sync_all()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sync loop error: {e}")

    async def create_case_from_incident(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> Optional[DatadogCase]:
        """Create Datadog case from Vaulytica incident."""
        try:
            # Map severity to priority
            priority = self._map_severity_to_priority(incident.severity)

            # Determine case type
            case_type = self._map_category_to_type(incident.category)

            # Build description
            description = self._build_case_description(incident, analysis)

            # Build tags
            tags = [
                f"vaulytica:incident:{incident.incident_id}",
                f"severity:{incident.severity.value}",
                f"category:{incident.category.value}",
                f"source:{incident.source_system}"
            ]

            # Create case
            case = await self.api_client.create_case(
                title=incident.title,
                description=description,
                priority=priority,
                case_type=case_type,
                tags=tags,
                attributes={
                    "vaulytica_incident_id": incident.incident_id,
                    "vaulytica_priority": incident.priority.value
                }
            )

            if case:
                # Create mapping
                mapping = SyncMapping(
                    incident_id=incident.incident_id,
                    case_id=case.case_id,
                    last_synced=datetime.now(),
                    sync_direction="bidirectional",
                    metadata={"created_by": "vaulytica"}
                )
                self.mappings[incident.incident_id] = mapping
                self.case_to_incident[case.case_id] = incident.incident_id

                self.cases_created += 1

                # Trigger callbacks
                for callback in self.on_case_created:
                    try:
                        await callback(case, incident)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                logger.info(f"Created Datadog case {case.case_id} for incident {incident.incident_id}")

            return case

        except Exception as e:
            logger.error(f"Failed to create case from incident: {e}")
            for callback in self.on_sync_error:
                try:
                    await callback("create_case", incident, e)
                except:
                    pass
            return None

    async def sync_incident_to_case(
        self,
        incident: Incident,
        case_id: str
    ) -> bool:
        """Sync Vaulytica incident updates to Datadog case."""
        try:
            # Map status
            status = self._map_incident_status_to_case_status(incident.status)

            # Map priority
            priority = self._map_severity_to_priority(incident.severity)

            # Update case
            case = await self.api_client.update_case(
                case_id,
                status=status,
                priority=priority
            )

            if case:
                # Update mapping
                if incident.incident_id in self.mappings:
                    self.mappings[incident.incident_id].last_synced = datetime.now()

                self.cases_updated += 1
                self.successful_syncs += 1

                logger.info(f"Synced incident {incident.incident_id} to case {case_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to sync incident to case: {e}")
            self.failed_syncs += 1
            return False

    async def sync_case_to_incident(
        self,
        case: DatadogCase,
        incident: Incident
    ) -> bool:
        """Sync Datadog case updates to Vaulytica incident."""
        try:
            # Map status
            incident_status = self._map_case_status_to_incident_status(case.status)

            # Update incident (this would integrate with incident manager)
            # For now, just log the sync
            logger.info(f"Would sync case {case.case_id} to incident {incident.incident_id}")
            logger.info(f"  Status: {case.status} -> {incident_status}")
            logger.info(f"  Priority: {case.priority}")

            # Update mapping
            if incident.incident_id in self.mappings:
                self.mappings[incident.incident_id].last_synced = datetime.now()

            self.successful_syncs += 1
            return True

        except Exception as e:
            logger.error(f"Failed to sync case to incident: {e}")
            self.failed_syncs += 1
            return False

    async def sync_all(self):
        """Sync all mapped incidents and cases."""
        if not self.auto_sync:
            return

        logger.info(f"Starting sync for {len(self.mappings)} mappings")

        for incident_id, mapping in list(self.mappings.items()):
            try:
                # Get case from Datadog
                case = await self.api_client.get_case(mapping.case_id)
                if not case:
                    logger.warning(f"Case {mapping.case_id} not found")
                    continue

                # Check if sync is needed (case updated since last sync)
                if case.updated_at > mapping.last_synced:
                    logger.info(f"Case {case.case_id} updated, syncing...")
                    # Would sync to incident here
                    mapping.last_synced = datetime.now()

                self.total_syncs += 1

            except Exception as e:
                logger.error(f"Failed to sync mapping {incident_id}: {e}")

        logger.info("Sync completed")

    def _map_severity_to_priority(self, severity: Severity) -> DatadogCasePriority:
        """Map Vaulytica severity to Datadog priority."""
        mapping = {
            Severity.CRITICAL: DatadogCasePriority.P1,
            Severity.HIGH: DatadogCasePriority.P2,
            Severity.MEDIUM: DatadogCasePriority.P3,
            Severity.LOW: DatadogCasePriority.P4,
            Severity.INFO: DatadogCasePriority.P5
        }
        return mapping.get(severity, DatadogCasePriority.P3)

    def _map_category_to_type(self, category: str) -> DatadogCaseType:
        """Map event category to case type."""
        category_lower = str(category).lower()
        if "vulnerability" in category_lower:
            return DatadogCaseType.VULNERABILITY
        elif "compliance" in category_lower or "policy" in category_lower:
            return DatadogCaseType.COMPLIANCE
        elif "investigation" in category_lower or "reconnaissance" in category_lower:
            return DatadogCaseType.INVESTIGATION
        else:
            return DatadogCaseType.SECURITY_INCIDENT

    def _map_incident_status_to_case_status(self, status: IncidentStatus) -> DatadogCaseStatus:
        """Map incident status to case status."""
        mapping = {
            IncidentStatus.NEW: DatadogCaseStatus.OPEN,
            IncidentStatus.INVESTIGATING: DatadogCaseStatus.IN_PROGRESS,
            IncidentStatus.CONTAINED: DatadogCaseStatus.IN_PROGRESS,
            IncidentStatus.RESOLVED: DatadogCaseStatus.CLOSED,
            IncidentStatus.CLOSED: DatadogCaseStatus.CLOSED,
            IncidentStatus.FALSE_POSITIVE: DatadogCaseStatus.CLOSED
        }
        return mapping.get(status, DatadogCaseStatus.OPEN)

    def _map_case_status_to_incident_status(self, status: DatadogCaseStatus) -> IncidentStatus:
        """Map case status to incident status."""
        mapping = {
            DatadogCaseStatus.OPEN: IncidentStatus.NEW,
            DatadogCaseStatus.IN_PROGRESS: IncidentStatus.INVESTIGATING,
            DatadogCaseStatus.CLOSED: IncidentStatus.RESOLVED,
            DatadogCaseStatus.ARCHIVED: IncidentStatus.CLOSED
        }
        return mapping.get(status, IncidentStatus.NEW)

    def _build_case_description(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> str:
        """Build case description from incident and analysis."""
        lines = [
            f"**Incident ID:** {incident.incident_id}",
            f"**Severity:** {incident.severity.value}",
            f"**Priority:** {incident.priority.value}",
            f"**Status:** {incident.status.value}",
            f"**Created:** {incident.created_at.isoformat()}",
            "",
            "## Description",
            incident.description or "No description available",
        ]

        if incident.affected_assets:
            lines.extend([
                "",
                "## Affected Assets",
                *[f"- {asset}" for asset in incident.affected_assets[:10]]
            ])

        if incident.source_ips:
            lines.extend([
                "",
                "## Source IPs",
                *[f"- {ip}" for ip in incident.source_ips[:10]]
            ])

        if incident.mitre_techniques:
            lines.extend([
                "",
                "## MITRE ATT&CK Techniques",
                *[f"- {technique}" for technique in incident.mitre_techniques[:10]]
            ])

        if analysis:
            lines.extend([
                "",
                "## AI Analysis",
                f"**What:** {analysis.what}",
                f"**Why:** {analysis.why}",
                f"**Impact:** {analysis.impact}",
                "",
                "**Recommended Actions:**",
                *[f"{i+1}. {action}" for i, action in enumerate(analysis.recommended_actions[:5])]
            ])

        if incident.tags:
            lines.extend([
                "",
                "## Tags",
                ", ".join(incident.tags)
            ])

        return "\n".join(lines)

    def get_mapping(self, incident_id: str) -> Optional[SyncMapping]:
        """Get sync mapping for incident."""
        return self.mappings.get(incident_id)

    def get_case_id(self, incident_id: str) -> Optional[str]:
        """Get Datadog case ID for incident."""
        mapping = self.mappings.get(incident_id)
        return mapping.case_id if mapping else None

    def get_incident_id(self, case_id: str) -> Optional[str]:
        """Get incident ID for Datadog case."""
        return self.case_to_incident.get(case_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get case manager statistics."""
        return {
            "total_mappings": len(self.mappings),
            "total_syncs": self.total_syncs,
            "successful_syncs": self.successful_syncs,
            "failed_syncs": self.failed_syncs,
            "cases_created": self.cases_created,
            "cases_updated": self.cases_updated,
            "sync_success_rate": self.successful_syncs / self.total_syncs if self.total_syncs > 0 else 0,
            "auto_create_cases": self.auto_create_cases,
            "auto_sync": self.auto_sync,
            "sync_interval": self.sync_interval
        }


# Global instance
_datadog_case_manager: Optional[DatadogCaseManager] = None


def get_datadog_case_manager(
    api_key: Optional[str] = None,
    app_key: Optional[str] = None,
    site: str = "datadoghq.com",
    **kwargs
) -> DatadogCaseManager:
    """Get or create global Datadog case manager instance."""
    global _datadog_case_manager

    if _datadog_case_manager is None:
        if not api_key or not app_key:
            raise ValueError("Datadog API key and app key required for first initialization")

        api_client = DatadogAPIClient(api_key, app_key, site)
        _datadog_case_manager = DatadogCaseManager(api_client, **kwargs)

    return _datadog_case_manager


async def create_datadog_case_for_incident(
    incident: Incident,
    analysis: Optional[AnalysisResult] = None,
    api_key: Optional[str] = None,
    app_key: Optional[str] = None
) -> Optional[DatadogCase]:
    """Helper function to create Datadog case for incident."""
    try:
        manager = get_datadog_case_manager(api_key, app_key)
        return await manager.create_case_from_incident(incident, analysis)
    except Exception as e:
        logger.error(f"Failed to create Datadog case: {e}")
        return None

