"""
Unified Ticketing Manager for Vaulytica.

Provides a unified interface for managing tickets across multiple platforms:
- ServiceNow incident management
- Jira issue tracking
- PagerDuty alerting
- Datadog case management

Supports:
- Multi-platform ticket creation
- Bidirectional synchronization
- Unified status mapping
- Cross-platform correlation
- Ticket lifecycle management
- Bulk operations
- Statistics and reporting

Author: Vaulytica Team
Version: 0.21.0
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.incidents import Incident, IncidentStatus, get_incident_manager
from vaulytica.models import AnalysisResult
from vaulytica.logger import get_logger

# Import integration managers
try:
    from vaulytica.servicenow_integration import (
        ServiceNowIncidentManager,
        get_servicenow_manager
    )
    SERVICENOW_AVAILABLE = True
except ImportError:
    SERVICENOW_AVAILABLE = False

try:
    from vaulytica.jira_integration import (
        JiraIssueManager,
        get_jira_manager
    )
    JIRA_AVAILABLE = True
except ImportError:
    JIRA_AVAILABLE = False

try:
    from vaulytica.pagerduty_integration import (
        PagerDutyIncidentManager,
        get_pagerduty_manager
    )
    PAGERDUTY_AVAILABLE = True
except ImportError:
    PAGERDUTY_AVAILABLE = False

try:
    from vaulytica.datadog_integration import (
        DatadogCaseManager,
        get_datadog_case_manager
    )
    DATADOG_AVAILABLE = True
except ImportError:
    DATADOG_AVAILABLE = False

logger = get_logger(__name__)


class TicketingPlatform(str, Enum):
    """Supported ticketing platforms."""
    SERVICENOW = "servicenow"
    JIRA = "jira"
    PAGERDUTY = "pagerduty"
    DATADOG = "datadog"


@dataclass
class UnifiedTicket:
    """Unified ticket representation across platforms."""
    vaulytica_incident_id: str
    platform: TicketingPlatform
    ticket_id: str
    ticket_number: str
    title: str
    status: str
    priority: str
    created_at: datetime
    updated_at: datetime
    url: Optional[str] = None
    assignee: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TicketingConfig:
    """Configuration for ticketing platforms."""
    enabled_platforms: Set[TicketingPlatform] = field(default_factory=set)
    auto_create: bool = False
    auto_sync: bool = False
    sync_interval: int = 300  # 5 minutes

    # Platform-specific configs
    servicenow_config: Optional[Dict[str, Any]] = None
    jira_config: Optional[Dict[str, Any]] = None
    pagerduty_config: Optional[Dict[str, Any]] = None
    datadog_config: Optional[Dict[str, Any]] = None


class UnifiedTicketingManager:
    """
    Unified Ticketing Manager.

    Orchestrates ticket management across multiple platforms with:
    - Multi-platform ticket creation
    - Bidirectional synchronization
    - Unified status tracking
    - Cross-platform correlation
    """

    def __init__(self, config: TicketingConfig):
        """
        Initialize Unified Ticketing Manager.

        Args:
            config: Ticketing configuration
        """
        self.config = config

        # Platform managers
        self.servicenow_manager: Optional[ServiceNowIncidentManager] = None
        self.jira_manager: Optional[JiraIssueManager] = None
        self.pagerduty_manager: Optional[PagerDutyIncidentManager] = None
        self.datadog_manager: Optional[DatadogCaseManager] = None

        # Initialize enabled platforms
        self._initialize_platforms()

        # Unified ticket tracking
        self.tickets: Dict[str, List[UnifiedTicket]] = {}  # incident_id -> tickets

        # Statistics
        self.statistics = {
            "total_tickets_created": 0,
            "total_tickets_synced": 0,
            "tickets_by_platform": {
                platform.value: 0 for platform in TicketingPlatform
            },
            "sync_errors": 0,
            "last_sync": None
        }

        logger.info(f"Unified Ticketing Manager initialized with platforms: {[p.value for p in config.enabled_platforms]}")

    def _initialize_platforms(self):
        """Initialize enabled platform managers."""
        platform_initializers = {
            TicketingPlatform.SERVICENOW: self._init_servicenow,
            TicketingPlatform.JIRA: self._init_jira,
            TicketingPlatform.PAGERDUTY: self._init_pagerduty,
            TicketingPlatform.DATADOG: self._init_datadog
        }

        for platform in self.config.enabled_platforms:
            initializer = platform_initializers.get(platform)
            if initializer:
                initializer()

    def _init_servicenow(self):
        """Initialize ServiceNow platform."""
        if SERVICENOW_AVAILABLE and self.config.servicenow_config:
            try:
                self.servicenow_manager = get_servicenow_manager(**self.config.servicenow_config)
                logger.info("ServiceNow integration enabled")
            except Exception as e:
                logger.error(f"Failed to initialize ServiceNow: {e}")

    def _init_jira(self):
        """Initialize Jira platform."""
        if JIRA_AVAILABLE and self.config.jira_config:
            try:
                self.jira_manager = get_jira_manager(**self.config.jira_config)
                logger.info("Jira integration enabled")
            except Exception as e:
                logger.error(f"Failed to initialize Jira: {e}")

    def _init_pagerduty(self):
        """Initialize PagerDuty platform."""
        if PAGERDUTY_AVAILABLE and self.config.pagerduty_config:
            try:
                self.pagerduty_manager = get_pagerduty_manager(**self.config.pagerduty_config)
                logger.info("PagerDuty integration enabled")
            except Exception as e:
                logger.error(f"Failed to initialize PagerDuty: {e}")

    def _init_datadog(self):
        """Initialize Datadog platform."""
        if DATADOG_AVAILABLE and self.config.datadog_config:
            try:
                self.datadog_manager = get_datadog_case_manager(**self.config.datadog_config)
                logger.info("Datadog integration enabled")
            except Exception as e:
                logger.error(f"Failed to initialize Datadog: {e}")

    async def create_tickets_for_incident(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None,
        platforms: Optional[List[TicketingPlatform]] = None
    ) -> List[UnifiedTicket]:
        """
        Create tickets across multiple platforms for an incident.

        Args:
            incident: Vaulytica incident
            analysis: Optional AI analysis result
            platforms: Specific platforms to create tickets on (default: all enabled)

        Returns:
            List of created unified tickets
        """
        if platforms is None:
            platforms = list(self.config.enabled_platforms)

        tickets = []
        tasks = []

        # ServiceNow
        if TicketingPlatform.SERVICENOW in platforms and self.servicenow_manager:
            tasks.append(self._create_servicenow_ticket(incident, analysis))

        # Jira
        if TicketingPlatform.JIRA in platforms and self.jira_manager:
            tasks.append(self._create_jira_ticket(incident, analysis))

        # PagerDuty
        if TicketingPlatform.PAGERDUTY in platforms and self.pagerduty_manager:
            tasks.append(self._create_pagerduty_ticket(incident, analysis))

        # Datadog
        if TicketingPlatform.DATADOG in platforms and self.datadog_manager:
            tasks.append(self._create_datadog_ticket(incident, analysis))

        # Execute all ticket creations in parallel
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, UnifiedTicket):
                    tickets.append(result)
                    self.statistics["total_tickets_created"] += 1
                    self.statistics["tickets_by_platform"][result.platform.value] += 1
                elif isinstance(result, Exception):
                    logger.error(f"Error creating ticket: {result}")
                    self.statistics["sync_errors"] += 1

        # Store tickets
        if tickets:
            if incident.incident_id not in self.tickets:
                self.tickets[incident.incident_id] = []
            self.tickets[incident.incident_id].extend(tickets)

            logger.info(f"Created {len(tickets)} tickets for incident {incident.incident_id}")

        return tickets

    async def _create_servicenow_ticket(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult]
    ) -> Optional[UnifiedTicket]:
        """Create ServiceNow ticket."""
        try:
            snow_incident = await self.servicenow_manager.create_incident_from_vaulytica(incident, analysis)
            if snow_incident:
                return UnifiedTicket(
                    vaulytica_incident_id=incident.incident_id,
                    platform=TicketingPlatform.SERVICENOW,
                    ticket_id=snow_incident.sys_id,
                    ticket_number=snow_incident.number,
                    title=snow_incident.short_description,
                    status=snow_incident.state.value,
                    priority=snow_incident.priority.value,
                    created_at=snow_incident.opened_at or datetime.now(),
                    updated_at=datetime.now(),
                    url=f"https://{self.servicenow_manager.api_client.instance}.service-now.com/nav_to.do?uri=incident.do?sys_id={snow_incident.sys_id}",
                    assignee=snow_incident.assigned_to,
                    metadata={"snow_incident": snow_incident}
                )
        except Exception as e:
            logger.error(f"Error creating ServiceNow ticket: {e}")
            raise
        return None

    async def _create_jira_ticket(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult]
    ) -> Optional[UnifiedTicket]:
        """Create Jira ticket."""
        try:
            jira_issue = await self.jira_manager.create_issue_from_vaulytica(incident, analysis)
            if jira_issue:
                return UnifiedTicket(
                    vaulytica_incident_id=incident.incident_id,
                    platform=TicketingPlatform.JIRA,
                    ticket_id=jira_issue.id,
                    ticket_number=jira_issue.key,
                    title=jira_issue.summary,
                    status=jira_issue.status,
                    priority=jira_issue.priority,
                    created_at=jira_issue.created or datetime.now(),
                    updated_at=jira_issue.updated or datetime.now(),
                    url=f"{self.jira_manager.api_client.base_url}/browse/{jira_issue.key}",
                    assignee=jira_issue.assignee,
                    metadata={"jira_issue": jira_issue}
                )
        except Exception as e:
            logger.error(f"Error creating Jira ticket: {e}")
            raise
        return None

    async def _create_pagerduty_ticket(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult]
    ) -> Optional[UnifiedTicket]:
        """Create PagerDuty ticket."""
        try:
            pd_result = await self.pagerduty_manager.trigger_incident_from_vaulytica(incident, analysis)
            if pd_result:
                dedup_key = pd_result.get("dedup_key", "")
                return UnifiedTicket(
                    vaulytica_incident_id=incident.incident_id,
                    platform=TicketingPlatform.PAGERDUTY,
                    ticket_id=dedup_key,
                    ticket_number=dedup_key,
                    title=incident.title,
                    status="triggered",
                    priority=incident.severity.value,
                    created_at=datetime.now(),
                    updated_at=datetime.now(),
                    url=None,  # Will be populated when incident is queried
                    metadata={"pd_result": pd_result}
                )
        except Exception as e:
            logger.error(f"Error creating PagerDuty ticket: {e}")
            raise
        return None

    async def _create_datadog_ticket(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult]
    ) -> Optional[UnifiedTicket]:
        """Create Datadog ticket."""
        try:
            dd_case = await self.datadog_manager.create_case_from_incident(incident, analysis)
            if dd_case:
                return UnifiedTicket(
                    vaulytica_incident_id=incident.incident_id,
                    platform=TicketingPlatform.DATADOG,
                    ticket_id=dd_case.case_id,
                    ticket_number=dd_case.case_id,
                    title=dd_case.title,
                    status=dd_case.status.value,
                    priority=dd_case.priority.value,
                    created_at=dd_case.created_at,
                    updated_at=dd_case.updated_at,
                    url=f"https://example.com",
                    assignee=dd_case.assignee,
                    metadata={"dd_case": dd_case}
                )
        except Exception as e:
            logger.error(f"Error creating Datadog ticket: {e}")
            raise
        return None

    async def sync_incident_to_all_platforms(
        self,
        incident: Incident
    ) -> Dict[TicketingPlatform, bool]:
        """
        Sync incident updates to all platforms with existing tickets.

        Args:
            incident: Updated Vaulytica incident

        Returns:
            Dictionary of platform -> success status
        """
        results = {}

        tickets = self.tickets.get(incident.incident_id, [])
        if not tickets:
            logger.warning(f"No tickets found for incident {incident.incident_id}")
            return results

        tasks = []
        platforms = []

        for ticket in tickets:
            if ticket.platform == TicketingPlatform.SERVICENOW and self.servicenow_manager:
                tasks.append(self.servicenow_manager.sync_incident_to_servicenow(incident, ticket.ticket_id))
                platforms.append(TicketingPlatform.SERVICENOW)

            elif ticket.platform == TicketingPlatform.JIRA and self.jira_manager:
                tasks.append(self.jira_manager.sync_incident_to_jira(incident, ticket.ticket_number))
                platforms.append(TicketingPlatform.JIRA)

            elif ticket.platform == TicketingPlatform.PAGERDUTY and self.pagerduty_manager:
                tasks.append(self.pagerduty_manager.sync_incident_to_pagerduty(incident))
                platforms.append(TicketingPlatform.PAGERDUTY)

            elif ticket.platform == TicketingPlatform.DATADOG and self.datadog_manager:
                tasks.append(self.datadog_manager.sync_incident_to_case(incident, ticket.ticket_id))
                platforms.append(TicketingPlatform.DATADOG)

        if tasks:
            sync_results = await asyncio.gather(*tasks, return_exceptions=True)

            for platform, result in zip(platforms, sync_results):
                if isinstance(result, Exception):
                    results[platform] = False
                    logger.error(f"Error syncing to {platform.value}: {result}")
                    self.statistics["sync_errors"] += 1
                else:
                    results[platform] = bool(result)
                    if result:
                        self.statistics["total_tickets_synced"] += 1

            self.statistics["last_sync"] = datetime.now().isoformat()
            logger.info(f"Synced incident {incident.incident_id} to {len(results)} platforms")

        return results

    def get_tickets_for_incident(self, incident_id: str) -> List[UnifiedTicket]:
        """Get all tickets for an incident."""
        return self.tickets.get(incident_id, [])

    def get_tickets_by_platform(self, platform: TicketingPlatform) -> List[UnifiedTicket]:
        """Get all tickets for a specific platform."""
        all_tickets = []
        for tickets in self.tickets.values():
            all_tickets.extend([t for t in tickets if t.platform == platform])
        return all_tickets

    def get_all_tickets(self) -> List[UnifiedTicket]:
        """Get all tickets across all platforms."""
        all_tickets = []
        for tickets in self.tickets.values():
            all_tickets.extend(tickets)
        return all_tickets

    def get_statistics(self) -> Dict[str, Any]:
        """Get unified ticketing statistics."""
        stats = {
            **self.statistics,
            "total_incidents_with_tickets": len(self.tickets),
            "total_tickets": sum(len(tickets) for tickets in self.tickets.values()),
            "enabled_platforms": [p.value for p in self.config.enabled_platforms],
            "platform_statistics": {}
        }

        # Add platform-specific statistics
        if self.servicenow_manager:
            stats["platform_statistics"]["servicenow"] = self.servicenow_manager.get_statistics()
        if self.jira_manager:
            stats["platform_statistics"]["jira"] = self.jira_manager.get_statistics()
        if self.pagerduty_manager:
            stats["platform_statistics"]["pagerduty"] = self.pagerduty_manager.get_statistics()
        if self.datadog_manager:
            stats["platform_statistics"]["datadog"] = self.datadog_manager.get_statistics()

        return stats

    async def start_all_sync_tasks(self):
        """Start background sync tasks for all platforms."""
        if self.servicenow_manager:
            await self.servicenow_manager.start_sync()
        if self.jira_manager and hasattr(self.jira_manager, 'start_sync'):
            await self.jira_manager.start_sync()
        if self.pagerduty_manager:
            await self.pagerduty_manager.start_sync()
        if self.datadog_manager:
            await self.datadog_manager.start_sync()

        logger.info("Started all platform sync tasks")

    async def stop_all_sync_tasks(self):
        """Stop background sync tasks for all platforms."""
        if self.servicenow_manager:
            await self.servicenow_manager.stop_sync()
        if self.jira_manager and hasattr(self.jira_manager, 'stop_sync'):
            await self.jira_manager.stop_sync()
        if self.pagerduty_manager:
            await self.pagerduty_manager.stop_sync()
        if self.datadog_manager:
            await self.datadog_manager.stop_sync()

        logger.info("Stopped all platform sync tasks")

    async def close_all_connections(self):
        """Close all platform API connections."""
        if self.servicenow_manager:
            await self.servicenow_manager.api_client.close()
        if self.jira_manager:
            await self.jira_manager.api_client.close()
        if self.pagerduty_manager:
            await self.pagerduty_manager.api_client.close()
        if self.datadog_manager:
            await self.datadog_manager.api_client.close()

        logger.info("Closed all platform connections")


# Global instance
_unified_ticketing_manager: Optional[UnifiedTicketingManager] = None


def get_unified_ticketing_manager(config: Optional[TicketingConfig] = None) -> UnifiedTicketingManager:
    """Get or create global unified ticketing manager instance."""
    global _unified_ticketing_manager

    if _unified_ticketing_manager is None:
        if config is None:
            raise ValueError("TicketingConfig required for first initialization")

        _unified_ticketing_manager = UnifiedTicketingManager(config)

    return _unified_ticketing_manager


def create_ticketing_config_from_env() -> TicketingConfig:
    """Create ticketing configuration from environment variables."""
    import os

    config = TicketingConfig()

    # ServiceNow
    if os.getenv("SNOW_INSTANCE") and os.getenv("SNOW_USERNAME") and os.getenv("SNOW_PASSWORD"):
        config.enabled_platforms.add(TicketingPlatform.SERVICENOW)
        config.servicenow_config = {
            "instance": os.getenv("SNOW_INSTANCE"),
            "username": os.getenv("SNOW_USERNAME"),
            "password": os.getenv("SNOW_PASSWORD"),
            "auto_create_incidents": os.getenv("SNOW_AUTO_CREATE", "false").lower() == "true",
            "auto_sync": os.getenv("SNOW_AUTO_SYNC", "false").lower() == "true"
        }

    # Jira
    if os.getenv("JIRA_URL") and os.getenv("JIRA_USERNAME") and os.getenv("JIRA_API_TOKEN") and os.getenv("JIRA_PROJECT_KEY"):
        config.enabled_platforms.add(TicketingPlatform.JIRA)
        config.jira_config = {
            "base_url": os.getenv("JIRA_URL"),
            "username": os.getenv("JIRA_USERNAME"),
            "api_token": os.getenv("JIRA_API_TOKEN"),
            "project_key": os.getenv("JIRA_PROJECT_KEY"),
            "auto_create_issues": os.getenv("JIRA_AUTO_CREATE", "false").lower() == "true",
            "auto_sync": os.getenv("JIRA_AUTO_SYNC", "false").lower() == "true"
        }

    # PagerDuty
    if os.getenv("PD_API_KEY"):
        config.enabled_platforms.add(TicketingPlatform.PAGERDUTY)
        config.pagerduty_config = {
            "api_key": os.getenv("PD_API_KEY"),
            "integration_key": os.getenv("PD_INTEGRATION_KEY"),
            "auto_trigger_incidents": os.getenv("PD_AUTO_TRIGGER", "false").lower() == "true",
            "auto_sync": os.getenv("PD_AUTO_SYNC", "false").lower() == "true"
        }

    # Datadog
    if os.getenv("DD_API_KEY") and os.getenv("DD_APP_KEY"):
        config.enabled_platforms.add(TicketingPlatform.DATADOG)
        config.datadog_config = {
            "api_key": os.getenv("DD_API_KEY"),
            "app_key": os.getenv("DD_APP_KEY"),
            "site": os.getenv("DD_SITE", "datadoghq.com"),
            "auto_create_cases": os.getenv("DD_AUTO_CREATE", "false").lower() == "true",
            "auto_sync": os.getenv("DD_AUTO_SYNC", "false").lower() == "true"
        }

    # Global settings
    config.auto_create = os.getenv("TICKETING_AUTO_CREATE", "false").lower() == "true"
    config.auto_sync = os.getenv("TICKETING_AUTO_SYNC", "false").lower() == "true"
    config.sync_interval = int(os.getenv("TICKETING_SYNC_INTERVAL", "300"))

    return config
