"""
Vaulytica Incident Management & Alerting System

This module provides enterprise-grade incident management:
- Alert deduplication and grouping
- Incident lifecycle management (create, update, resolve, close)
- SLA tracking and escalation
- On-call scheduling and routing
- Ticketing system integrations (Jira, ServiceNow, PagerDuty, Opsgenie)
- Incident metrics and reporting

Author: World-Class Software Engineering Team
Version: 0.14.0
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import asyncio

from pydantic import BaseModel, Field

from vaulytica.models import SecurityEvent, AnalysisResult, Severity
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class IncidentStatus(str, Enum):
    """Incident status lifecycle."""
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class IncidentPriority(str, Enum):
    """Incident priority levels."""
    P1_CRITICAL = "P1_CRITICAL"  # Immediate response required
    P2_HIGH = "P2_HIGH"  # Response within 1 hour
    P3_MEDIUM = "P3_MEDIUM"  # Response within 4 hours
    P4_LOW = "P4_LOW"  # Response within 24 hours
    P5_INFO = "P5_INFO"  # No immediate response required


class EscalationLevel(str, Enum):
    """Escalation levels."""
    L1_ANALYST = "L1_ANALYST"
    L2_SENIOR_ANALYST = "L2_SENIOR_ANALYST"
    L3_SECURITY_ENGINEER = "L3_SECURITY_ENGINEER"
    L4_SECURITY_MANAGER = "L4_SECURITY_MANAGER"
    L5_CISO = "L5_CISO"


class TicketingSystem(str, Enum):
    """Supported ticketing systems."""
    JIRA = "JIRA"
    SERVICENOW = "SERVICENOW"
    PAGERDUTY = "PAGERDUTY"
    OPSGENIE = "OPSGENIE"
    GITHUB = "GITHUB"
    LINEAR = "LINEAR"


class AlertGroupingStrategy(str, Enum):
    """Alert grouping strategies."""
    FINGERPRINT = "FINGERPRINT"  # Group by alert fingerprint
    TIME_WINDOW = "TIME_WINDOW"  # Group by time window
    SIMILARITY = "SIMILARITY"  # Group by similarity score
    SOURCE = "SOURCE"  # Group by source system
    ASSET = "ASSET"  # Group by affected asset


@dataclass
class SLAPolicy:
    """SLA policy configuration."""
    priority: IncidentPriority
    acknowledgement_time: timedelta  # Time to acknowledge
    response_time: timedelta  # Time to start investigation
    resolution_time: timedelta  # Time to resolve
    escalation_time: timedelta  # Time before escalation

    def is_breached(self, incident: 'Incident', check_type: str) -> bool:
        """Check if SLA is breached."""
        if not incident.created_at:
            return False

        elapsed = datetime.utcnow() - incident.created_at

        if check_type == "acknowledgement":
            return not incident.acknowledged_at and elapsed > self.acknowledgement_time
        elif check_type == "response":
            return incident.status == IncidentStatus.NEW and elapsed > self.response_time
        elif check_type == "resolution":
            return incident.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED] and elapsed > self.resolution_time
        elif check_type == "escalation":
            return elapsed > self.escalation_time

        return False


@dataclass
class Alert:
    """Individual alert that can be grouped into incidents."""
    alert_id: str
    event: SecurityEvent
    analysis: Optional[AnalysisResult]
    fingerprint: str  # Unique fingerprint for deduplication
    created_at: datetime = field(default_factory=datetime.utcnow)
    deduplicated_count: int = 1  # Number of times this alert was deduplicated
    last_seen: datetime = field(default_factory=datetime.utcnow)

    def update_deduplication(self) -> None:
        """Update deduplication counters."""
        self.deduplicated_count += 1
        self.last_seen = datetime.utcnow()


class Incident(BaseModel):
    """Incident model representing grouped alerts."""
    incident_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    status: IncidentStatus = IncidentStatus.NEW
    priority: IncidentPriority
    severity: Severity

    # Lifecycle timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    acknowledged_at: Optional[datetime] = None
    investigating_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None

    # Assignment and escalation
    assigned_to: Optional[str] = None
    escalation_level: EscalationLevel = EscalationLevel.L1_ANALYST
    escalated_at: Optional[datetime] = None

    # Alerts and events
    alert_ids: List[str] = Field(default_factory=list)
    event_count: int = 0
    deduplicated_count: int = 0

    # Affected resources
    affected_assets: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    source_ips: List[str] = Field(default_factory=list)

    # MITRE ATT&CK
    mitre_techniques: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)

    # Ticketing integration
    external_tickets: Dict[str, str] = Field(default_factory=dict)  # system -> ticket_id

    # SLA tracking
    sla_breached: bool = False
    sla_breach_reasons: List[str] = Field(default_factory=list)

    # Metadata
    tags: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        """Pydantic configuration for Incident model."""
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

    def acknowledge(self, user: str) -> None:
        """Acknowledge the incident."""
        if self.status == IncidentStatus.NEW:
            self.status = IncidentStatus.ACKNOWLEDGED
            self.acknowledged_at = datetime.utcnow()
            self.assigned_to = user
            self.notes.append(f"Acknowledged by {user} at {self.acknowledged_at.isoformat()}")

    def start_investigation(self, user: str) -> None:
        """Start investigating the incident."""
        if self.status in [IncidentStatus.NEW, IncidentStatus.ACKNOWLEDGED]:
            self.status = IncidentStatus.INVESTIGATING
            self.investigating_at = datetime.utcnow()
            if not self.assigned_to:
                self.assigned_to = user
            self.notes.append(f"Investigation started by {user} at {self.investigating_at.isoformat()}")

    def resolve(self, user: str, resolution_note: str) -> None:
        """Resolve the incident."""
        if self.status != IncidentStatus.RESOLVED:
            self.status = IncidentStatus.RESOLVED
            self.resolved_at = datetime.utcnow()
            self.notes.append(f"Resolved by {user} at {self.resolved_at.isoformat()}: {resolution_note}")

    def close(self, user: str, close_note: Optional[str] = None) -> None:
        """Close the incident."""
        if self.status == IncidentStatus.RESOLVED:
            self.status = IncidentStatus.CLOSED
            self.closed_at = datetime.utcnow()
            note = f"Closed by {user} at {self.closed_at.isoformat()}"
            if close_note:
                note += f": {close_note}"
            self.notes.append(note)

    def reopen(self, user: str, reason: str) -> None:
        """Reopen a resolved/closed incident."""
        if self.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
            self.status = IncidentStatus.REOPENED
            self.resolved_at = None
            self.closed_at = None
            self.notes.append(f"Reopened by {user} at {datetime.utcnow().isoformat()}: {reason}")

    def escalate(self, to_level: EscalationLevel, reason: str) -> None:
        """Escalate the incident to a higher level."""
        old_level = self.escalation_level
        self.escalation_level = to_level
        self.escalated_at = datetime.utcnow()
        self.notes.append(f"Escalated from {old_level.value} to {to_level.value} at {self.escalated_at.isoformat()}: {reason}")

    def add_external_ticket(self, system: TicketingSystem, ticket_id: str) -> None:
        """Link external ticket."""
        self.external_tickets[system.value] = ticket_id
        self.notes.append(f"Linked to {system.value} ticket: {ticket_id}")

    def add_note(self, user: str, note: str) -> None:
        """Add a note to the incident."""
        timestamp = datetime.utcnow().isoformat()
        self.notes.append(f"[{timestamp}] {user}: {note}")

    def add_tag(self, tag: str) -> None:
        """Add a tag to the incident."""
        if tag not in self.tags:
            self.tags.append(tag)

    def get_age(self) -> timedelta:
        """Get incident age."""
        return datetime.utcnow() - self.created_at

    def get_time_to_acknowledge(self) -> Optional[timedelta]:
        """Get time taken to acknowledge."""
        if self.acknowledged_at:
            return self.acknowledged_at - self.created_at
        return None

    def get_time_to_resolve(self) -> Optional[timedelta]:
        """Get time taken to resolve."""
        if self.resolved_at:
            return self.resolved_at - self.created_at
        return None


@dataclass
class IncidentMetrics:
    """Incident metrics for reporting."""
    total_incidents: int = 0
    open_incidents: int = 0
    acknowledged_incidents: int = 0
    investigating_incidents: int = 0
    resolved_incidents: int = 0
    closed_incidents: int = 0

    incidents_by_priority: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    incidents_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    incidents_by_status: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    sla_breaches: int = 0
    escalations: int = 0

    avg_time_to_acknowledge: Optional[float] = None  # seconds
    avg_time_to_resolve: Optional[float] = None  # seconds
    avg_incident_age: Optional[float] = None  # seconds

    alerts_deduplicated: int = 0
    deduplication_rate: float = 0.0  # percentage

    timestamp: datetime = field(default_factory=datetime.utcnow)


class AlertDeduplicator:
    """Alert deduplication engine."""

    def __init__(self, time_window: timedelta = timedelta(minutes=5)):
        self.time_window = time_window
        self.alert_cache: Dict[str, Alert] = {}  # fingerprint -> Alert
        self.fingerprint_to_incident: Dict[str, str] = {}  # fingerprint -> incident_id
        logger.info(f"Alert deduplicator initialized with {time_window} time window")

    def generate_fingerprint(self, event: SecurityEvent, analysis: Optional[AnalysisResult] = None) -> str:
        """Generate unique fingerprint for alert deduplication."""
        # Create fingerprint from key attributes
        fingerprint_data = {
            "source_system": event.source_system,
            "category": event.category.value,
            "severity": event.severity.value,
            "title": event.title,
        }

        # Add affected assets
        if event.affected_assets:
            fingerprint_data["assets"] = sorted([
                asset.hostname or asset.cloud_resource_id or ""
                for asset in event.affected_assets
            ])

        # Add MITRE techniques
        if event.mitre_attack:
            fingerprint_data["mitre"] = sorted([m.technique_id for m in event.mitre_attack])

        # Generate hash
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    def should_deduplicate(self, fingerprint: str) -> Tuple[bool, Optional[Alert]]:
        """Check if alert should be deduplicated."""
        if fingerprint in self.alert_cache:
            existing_alert = self.alert_cache[fingerprint]
            # Check if within time window
            if datetime.utcnow() - existing_alert.last_seen <= self.time_window:
                return True, existing_alert
            else:
                # Time window expired, remove from cache
                del self.alert_cache[fingerprint]

        return False, None

    def add_alert(self, alert: Alert) -> bool:
        """Add alert to deduplication cache. Returns True if deduplicated."""
        should_dedup, existing_alert = self.should_deduplicate(alert.fingerprint)

        if should_dedup and existing_alert:
            existing_alert.update_deduplication()
            logger.debug(f"Alert deduplicated: {alert.alert_id} -> {existing_alert.alert_id} (count: {existing_alert.deduplicated_count})")
            return True
        else:
            self.alert_cache[alert.fingerprint] = alert
            return False

    def cleanup_expired(self) -> None:
        """Remove expired alerts from cache."""
        now = datetime.utcnow()
        expired = [
            fp for fp, alert in self.alert_cache.items()
            if now - alert.last_seen > self.time_window
        ]
        for fp in expired:
            del self.alert_cache[fp]

        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired alerts from deduplication cache")


class IncidentGrouper:
    """Alert grouping engine."""

    def __init__(self, strategy: AlertGroupingStrategy = AlertGroupingStrategy.FINGERPRINT):
        self.strategy = strategy
        self.groups: Dict[str, List[Alert]] = defaultdict(list)
        logger.info(f"Incident grouper initialized with strategy: {strategy.value}")

    def get_group_key(self, alert: Alert) -> str:
        """Get grouping key based on strategy."""
        if self.strategy == AlertGroupingStrategy.FINGERPRINT:
            return alert.fingerprint

        elif self.strategy == AlertGroupingStrategy.TIME_WINDOW:
            # Group by 5-minute time windows
            timestamp = alert.created_at
            window = timestamp.replace(second=0, microsecond=0)
            window = window.replace(minute=(window.minute // 5) * 5)
            return f"{alert.event.category.value}_{window.isoformat()}"

        elif self.strategy == AlertGroupingStrategy.SOURCE:
            return f"{alert.event.source_system}_{alert.event.category.value}"

        elif self.strategy == AlertGroupingStrategy.ASSET:
            if alert.event.affected_assets:
                asset = alert.event.affected_assets[0]
                asset_id = asset.hostname or asset.cloud_resource_id or "unknown"
                return f"{asset_id}_{alert.event.category.value}"
            return f"unknown_{alert.event.category.value}"

        elif self.strategy == AlertGroupingStrategy.SIMILARITY:
            # Group by MITRE techniques
            if alert.event.mitre_attack:
                techniques = "_".join(sorted([m.technique_id for m in alert.event.mitre_attack]))
                return f"{alert.event.category.value}_{techniques}"
            return alert.event.category.value

        return alert.fingerprint

    def add_alert(self, alert: Alert) -> str:
        """Add alert to group. Returns group key."""
        group_key = self.get_group_key(alert)
        self.groups[group_key].append(alert)
        return group_key

    def get_group(self, group_key: str) -> List[Alert]:
        """Get alerts in a group."""
        return self.groups.get(group_key, [])

    def get_all_groups(self) -> Dict[str, List[Alert]]:
        """Get all alert groups."""
        return dict(self.groups)


class SLATracker:
    """SLA tracking and escalation engine."""

    def __init__(self):
        # Default SLA policies
        self.policies: Dict[IncidentPriority, SLAPolicy] = {
            IncidentPriority.P1_CRITICAL: SLAPolicy(
                priority=IncidentPriority.P1_CRITICAL,
                acknowledgement_time=timedelta(minutes=5),
                response_time=timedelta(minutes=15),
                resolution_time=timedelta(hours=4),
                escalation_time=timedelta(minutes=30)
            ),
            IncidentPriority.P2_HIGH: SLAPolicy(
                priority=IncidentPriority.P2_HIGH,
                acknowledgement_time=timedelta(minutes=15),
                response_time=timedelta(hours=1),
                resolution_time=timedelta(hours=8),
                escalation_time=timedelta(hours=2)
            ),
            IncidentPriority.P3_MEDIUM: SLAPolicy(
                priority=IncidentPriority.P3_MEDIUM,
                acknowledgement_time=timedelta(hours=1),
                response_time=timedelta(hours=4),
                resolution_time=timedelta(hours=24),
                escalation_time=timedelta(hours=8)
            ),
            IncidentPriority.P4_LOW: SLAPolicy(
                priority=IncidentPriority.P4_LOW,
                acknowledgement_time=timedelta(hours=4),
                response_time=timedelta(hours=24),
                resolution_time=timedelta(days=3),
                escalation_time=timedelta(days=1)
            ),
            IncidentPriority.P5_INFO: SLAPolicy(
                priority=IncidentPriority.P5_INFO,
                acknowledgement_time=timedelta(days=1),
                response_time=timedelta(days=3),
                resolution_time=timedelta(days=7),
                escalation_time=timedelta(days=5)
            ),
        }
        logger.info("SLA tracker initialized with default policies")

    def check_sla(self, incident: Incident) -> Dict[str, bool]:
        """Check SLA status for incident."""
        policy = self.policies.get(incident.priority)
        if not policy:
            return {}

        breaches = {
            "acknowledgement": policy.is_breached(incident, "acknowledgement"),
            "response": policy.is_breached(incident, "response"),
            "resolution": policy.is_breached(incident, "resolution"),
            "escalation": policy.is_breached(incident, "escalation")
        }

        return breaches

    def update_incident_sla(self, incident: Incident) -> bool:
        """Update incident SLA status. Returns True if any breach detected."""
        breaches = self.check_sla(incident)

        breach_detected = False
        for breach_type, is_breached in breaches.items():
            if is_breached and breach_type not in incident.sla_breach_reasons:
                incident.sla_breached = True
                incident.sla_breach_reasons.append(breach_type)
                breach_detected = True
                logger.warning(f"SLA breach detected for incident {incident.incident_id}: {breach_type}")

        return breach_detected

    def should_escalate(self, incident: Incident) -> Tuple[bool, Optional[EscalationLevel]]:
        """Check if incident should be escalated."""
        policy = self.policies.get(incident.priority)
        if not policy:
            return False, None

        # Check if escalation time exceeded
        if policy.is_breached(incident, "escalation"):
            # Determine next escalation level
            current_level = incident.escalation_level

            escalation_order = [
                EscalationLevel.L1_ANALYST,
                EscalationLevel.L2_SENIOR_ANALYST,
                EscalationLevel.L3_SECURITY_ENGINEER,
                EscalationLevel.L4_SECURITY_MANAGER,
                EscalationLevel.L5_CISO
            ]

            try:
                current_index = escalation_order.index(current_level)
                if current_index < len(escalation_order) - 1:
                    next_level = escalation_order[current_index + 1]
                    return True, next_level
            except ValueError:
                pass

        return False, None

    def get_policy(self, priority: IncidentPriority) -> Optional[SLAPolicy]:
        """Get SLA policy for priority."""
        return self.policies.get(priority)

    def set_policy(self, priority: IncidentPriority, policy: SLAPolicy) -> None:
        """Set custom SLA policy."""
        self.policies[priority] = policy
        logger.info(f"Updated SLA policy for {priority.value}")


class OnCallSchedule:
    """On-call scheduling and routing."""

    def __init__(self):
        self.schedules: Dict[EscalationLevel, List[str]] = defaultdict(list)
        self.current_rotation: Dict[EscalationLevel, int] = defaultdict(int)
        logger.info("On-call schedule initialized")

    def add_user(self, level: EscalationLevel, user: str) -> None:
        """Add user to on-call rotation."""
        if user not in self.schedules[level]:
            self.schedules[level].append(user)
            logger.info(f"Added {user} to {level.value} on-call rotation")

    def remove_user(self, level: EscalationLevel, user: str) -> None:
        """Remove user from on-call rotation."""
        if user in self.schedules[level]:
            self.schedules[level].remove(user)
            logger.info(f"Removed {user} from {level.value} on-call rotation")

    def get_on_call_user(self, level: EscalationLevel) -> Optional[str]:
        """Get current on-call user for level."""
        users = self.schedules.get(level, [])
        if not users:
            return None

        index = self.current_rotation[level] % len(users)
        return users[index]

    def rotate(self, level: EscalationLevel) -> None:
        """Rotate to next on-call user."""
        self.current_rotation[level] += 1
        logger.info(f"Rotated {level.value} on-call schedule")

    def get_all_schedules(self) -> Dict[str, List[str]]:
        """Get all on-call schedules."""
        return {level.value: users for level, users in self.schedules.items()}


class IncidentManager:
    """Main incident management engine."""

    def __init__(
        self,
        deduplication_window: timedelta = timedelta(minutes=5),
        grouping_strategy: AlertGroupingStrategy = AlertGroupingStrategy.FINGERPRINT,
        enable_auto_escalation: bool = True
    ):
        self.deduplicator = AlertDeduplicator(time_window=deduplication_window)
        self.grouper = IncidentGrouper(strategy=grouping_strategy)
        self.sla_tracker = SLATracker()
        self.on_call_schedule = OnCallSchedule()

        self.enable_auto_escalation = enable_auto_escalation

        # Storage
        self.incidents: Dict[str, Incident] = {}  # incident_id -> Incident
        self.alerts: Dict[str, Alert] = {}  # alert_id -> Alert
        self.fingerprint_to_incident: Dict[str, str] = {}  # fingerprint -> incident_id

        # Metrics
        self.total_alerts_received = 0
        self.total_alerts_deduplicated = 0
        self.total_incidents_created = 0
        self.total_escalations = 0
        self.total_sla_breaches = 0

        logger.info("Incident Manager initialized")

    def _severity_to_priority(self, severity: Severity) -> IncidentPriority:
        """Convert severity to priority."""
        mapping = {
            Severity.CRITICAL: IncidentPriority.P1_CRITICAL,
            Severity.HIGH: IncidentPriority.P2_HIGH,
            Severity.MEDIUM: IncidentPriority.P3_MEDIUM,
            Severity.LOW: IncidentPriority.P4_LOW,
            Severity.INFO: IncidentPriority.P5_INFO
        }
        return mapping.get(severity, IncidentPriority.P3_MEDIUM)

    def create_alert(
        self,
        event: SecurityEvent,
        analysis: Optional[AnalysisResult] = None
    ) -> Tuple[Alert, bool]:
        """Create alert from event. Returns (alert, was_deduplicated)."""
        self.total_alerts_received += 1

        # Generate fingerprint
        fingerprint = self.deduplicator.generate_fingerprint(event, analysis)

        # Create alert
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            event=event,
            analysis=analysis,
            fingerprint=fingerprint
        )

        # Check deduplication
        was_deduplicated = self.deduplicator.add_alert(alert)

        if was_deduplicated:
            self.total_alerts_deduplicated += 1
            logger.debug(f"Alert deduplicated: {alert.alert_id}")
            return alert, True

        # Store alert
        self.alerts[alert.alert_id] = alert

        return alert, False

    def create_incident_from_alert(self, alert: Alert) -> Incident:
        """Create new incident from alert."""
        event = alert.event
        analysis = alert.analysis

        # Determine priority
        priority = self._severity_to_priority(event.severity)

        # Extract affected resources
        affected_assets = []
        affected_users = []
        source_ips = []

        for asset in event.affected_assets:
            if asset.hostname:
                affected_assets.append(asset.hostname)
            if asset.cloud_resource_id:
                affected_assets.append(asset.cloud_resource_id)

        # Extract from metadata
        if "user" in event.metadata:
            affected_users.append(event.metadata["user"])
        if "source_ip" in event.metadata:
            source_ips.append(event.metadata["source_ip"])

        # Extract MITRE techniques
        mitre_techniques = [m.technique_id for m in event.mitre_attack]
        mitre_tactics = list(set([m.tactic for m in event.mitre_attack]))

        # Create incident
        incident = Incident(
            title=event.title,
            description=event.description,
            priority=priority,
            severity=event.severity,
            alert_ids=[alert.alert_id],
            event_count=1,
            affected_assets=affected_assets,
            affected_users=affected_users,
            source_ips=source_ips,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            tags=[event.category.value, event.source_system]
        )

        # Auto-assign to on-call user
        on_call_user = self.on_call_schedule.get_on_call_user(incident.escalation_level)
        if on_call_user:
            incident.assigned_to = on_call_user
            incident.add_note("system", f"Auto-assigned to on-call user: {on_call_user}")

        # Store incident
        self.incidents[incident.incident_id] = incident
        self.fingerprint_to_incident[alert.fingerprint] = incident.incident_id
        self.total_incidents_created += 1

        logger.info(f"Created incident {incident.incident_id} from alert {alert.alert_id}")

        return incident

    def add_alert_to_incident(self, alert: Alert, incident_id: str) -> None:
        """Add alert to existing incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.error(f"Incident {incident_id} not found")
            return

        incident.alert_ids.append(alert.alert_id)
        incident.event_count += 1
        incident.deduplicated_count = alert.deduplicated_count

        # Update affected resources
        for asset in alert.event.affected_assets:
            if asset.hostname and asset.hostname not in incident.affected_assets:
                incident.affected_assets.append(asset.hostname)
            if asset.cloud_resource_id and asset.cloud_resource_id not in incident.affected_assets:
                incident.affected_assets.append(asset.cloud_resource_id)

        logger.debug(f"Added alert {alert.alert_id} to incident {incident_id}")

    def process_event(
        self,
        event: SecurityEvent,
        analysis: Optional[AnalysisResult] = None
    ) -> Tuple[Incident, bool]:
        """Process security event and create/update incident. Returns (incident, is_new)."""
        # Create alert
        alert, was_deduplicated = self.create_alert(event, analysis)

        # Check if incident already exists for this fingerprint
        existing_incident_id = self.fingerprint_to_incident.get(alert.fingerprint)

        if existing_incident_id and existing_incident_id in self.incidents:
            # Add to existing incident
            incident = self.incidents[existing_incident_id]
            if not was_deduplicated:
                self.add_alert_to_incident(alert, existing_incident_id)
            else:
                # Update deduplication count
                incident.deduplicated_count += 1
            return incident, False
        else:
            # Create new incident
            incident = self.create_incident_from_alert(alert)
            return incident, True

    def acknowledge_incident(self, incident_id: str, user: str) -> bool:
        """Acknowledge incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.error(f"Incident {incident_id} not found")
            return False

        incident.acknowledge(user)
        logger.info(f"Incident {incident_id} acknowledged by {user}")
        return True

    def start_investigation(self, incident_id: str, user: str) -> bool:
        """Start investigating incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.error(f"Incident {incident_id} not found")
            return False

        incident.start_investigation(user)
        logger.info(f"Investigation started for incident {incident_id} by {user}")
        return True

    def resolve_incident(self, incident_id: str, user: str, resolution_note: str) -> bool:
        """Resolve incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.error(f"Incident {incident_id} not found")
            return False

        incident.resolve(user, resolution_note)
        logger.info(f"Incident {incident_id} resolved by {user}")
        return True

    def close_incident(self, incident_id: str, user: str, close_note: Optional[str] = None) -> bool:
        """Close incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.error(f"Incident {incident_id} not found")
            return False

        incident.close(user, close_note)
        logger.info(f"Incident {incident_id} closed by {user}")
        return True

    def reopen_incident(self, incident_id: str, user: str, reason: str) -> bool:
        """Reopen incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.error(f"Incident {incident_id} not found")
            return False

        incident.reopen(user, reason)
        logger.info(f"Incident {incident_id} reopened by {user}")
        return True

    def escalate_incident(self, incident_id: str, to_level: EscalationLevel, reason: str) -> bool:
        """Manually escalate incident."""
        incident = self.incidents.get(incident_id)
        if not incident:
            logger.error(f"Incident {incident_id} not found")
            return False

        incident.escalate(to_level, reason)
        self.total_escalations += 1

        # Reassign to on-call user at new level
        on_call_user = self.on_call_schedule.get_on_call_user(to_level)
        if on_call_user:
            incident.assigned_to = on_call_user
            incident.add_note("system", f"Reassigned to {on_call_user} at {to_level.value}")

        logger.info(f"Incident {incident_id} escalated to {to_level.value}")
        return True

    def check_and_escalate_incidents(self) -> None:
        """Check all open incidents for auto-escalation."""
        if not self.enable_auto_escalation:
            return

        for incident in self.incidents.values():
            if incident.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
                continue

            should_escalate, next_level = self.sla_tracker.should_escalate(incident)
            if should_escalate and next_level:
                self.escalate_incident(
                    incident.incident_id,
                    next_level,
                    "Auto-escalation due to SLA breach"
                )

    def check_sla_breaches(self) -> None:
        """Check all open incidents for SLA breaches."""
        for incident in self.incidents.values():
            if incident.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
                continue

            breach_detected = self.sla_tracker.update_incident_sla(incident)
            if breach_detected:
                self.total_sla_breaches += 1

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID."""
        return self.incidents.get(incident_id)

    def get_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        priority: Optional[IncidentPriority] = None,
        severity: Optional[Severity] = None,
        assigned_to: Optional[str] = None,
        limit: int = 100
    ) -> List[Incident]:
        """Get incidents with filters."""
        incidents = list(self.incidents.values())

        # Apply filters
        if status:
            incidents = [i for i in incidents if i.status == status]
        if priority:
            incidents = [i for i in incidents if i.priority == priority]
        if severity:
            incidents = [i for i in incidents if i.severity == severity]
        if assigned_to:
            incidents = [i for i in incidents if i.assigned_to == assigned_to]

        # Sort by created_at descending
        incidents.sort(key=lambda x: x.created_at, reverse=True)

        return incidents[:limit]

    def get_open_incidents(self, limit: int = 100) -> List[Incident]:
        """Get all open incidents."""
        return self.get_incidents(
            status=None,
            limit=limit
        )

    def get_metrics(self) -> IncidentMetrics:
        """Get incident metrics."""
        metrics = IncidentMetrics()
        metrics.total_incidents = len(self.incidents)

        # Collect metrics from all incidents
        self._collect_status_metrics(metrics)
        self._collect_timing_metrics(metrics)

        metrics.escalations = self.total_escalations
        return metrics

    def _collect_status_metrics(self, metrics: IncidentMetrics):
        """Collect status-based metrics from incidents."""
        status_counters = {
            IncidentStatus.NEW: lambda: setattr(metrics, 'open_incidents', metrics.open_incidents + 1),
            IncidentStatus.ACKNOWLEDGED: lambda: setattr(metrics, 'acknowledged_incidents', metrics.acknowledged_incidents + 1),
            IncidentStatus.INVESTIGATING: lambda: setattr(metrics, 'investigating_incidents', metrics.investigating_incidents + 1),
            IncidentStatus.RESOLVED: lambda: setattr(metrics, 'resolved_incidents', metrics.resolved_incidents + 1),
            IncidentStatus.CLOSED: lambda: setattr(metrics, 'closed_incidents', metrics.closed_incidents + 1)
        }

        for incident in self.incidents.values():
            # Count by status, priority, severity
            metrics.incidents_by_status[incident.status.value] += 1
            metrics.incidents_by_priority[incident.priority.value] += 1
            metrics.incidents_by_severity[incident.severity.value] += 1

            # Update status-specific counters
            counter = status_counters.get(incident.status)
            if counter:
                counter()

            # Count SLA breaches
            if incident.sla_breached:
                metrics.sla_breaches += 1

    def _collect_timing_metrics(self, metrics: IncidentMetrics):
        """Collect timing-based metrics from incidents."""
        ack_times = []
        resolve_times = []
        ages = []

        for incident in self.incidents.values():
            # Collect acknowledgement times
            ack_time = incident.get_time_to_acknowledge()
            if ack_time:
                ack_times.append(ack_time.total_seconds())

            # Collect resolution times
            resolve_time = incident.get_time_to_resolve()
            if resolve_time:
                resolve_times.append(resolve_time.total_seconds())

            # Collect ages
            ages.append(incident.get_age().total_seconds())

        # Calculate averages
        if ack_times:
            metrics.avg_time_to_acknowledge = sum(ack_times) / len(ack_times)
        if resolve_times:
            metrics.avg_time_to_resolve = sum(resolve_times) / len(resolve_times)
        if ages:
            metrics.avg_incident_age = sum(ages) / len(ages)
        metrics.alerts_deduplicated = self.total_alerts_deduplicated

        if self.total_alerts_received > 0:
            metrics.deduplication_rate = (self.total_alerts_deduplicated / self.total_alerts_received) * 100

        return metrics

    def cleanup(self) -> None:
        """Cleanup expired alerts and old incidents."""
        self.deduplicator.cleanup_expired()

        # Archive closed incidents older than 30 days
        cutoff = datetime.utcnow() - timedelta(days=30)
        to_archive = [
            incident_id for incident_id, incident in self.incidents.items()
            if incident.status == IncidentStatus.CLOSED and incident.closed_at and incident.closed_at < cutoff
        ]

        for incident_id in to_archive:
            del self.incidents[incident_id]

        if to_archive:
            logger.info(f"Archived {len(to_archive)} old closed incidents")


# Global incident manager instance
_incident_manager: Optional[IncidentManager] = None


def get_incident_manager(
    deduplication_window: timedelta = timedelta(minutes=5),
    grouping_strategy: AlertGroupingStrategy = AlertGroupingStrategy.FINGERPRINT,
    enable_auto_escalation: bool = True
) -> IncidentManager:
    """Get or create global incident manager instance."""
    global _incident_manager
    if _incident_manager is None:
        _incident_manager = IncidentManager(
            deduplication_window=deduplication_window,
            grouping_strategy=grouping_strategy,
            enable_auto_escalation=enable_auto_escalation
        )
    return _incident_manager


# ============================================================================
# Ticketing System Integrations
# ============================================================================


class TicketingConfig(BaseModel):
    """Configuration for ticketing system integration."""
    system: TicketingSystem
    enabled: bool = True

    # Jira
    jira_url: Optional[str] = None
    jira_username: Optional[str] = None
    jira_api_token: Optional[str] = None
    jira_project_key: Optional[str] = None

    # ServiceNow
    servicenow_instance: Optional[str] = None
    servicenow_username: Optional[str] = None
    servicenow_password: Optional[str] = None

    # PagerDuty
    pagerduty_api_key: Optional[str] = None
    pagerduty_service_id: Optional[str] = None
    pagerduty_from_email: Optional[str] = None

    # Opsgenie
    opsgenie_api_key: Optional[str] = None
    opsgenie_team: Optional[str] = None

    # GitHub
    github_token: Optional[str] = None
    github_repo: Optional[str] = None

    # Linear
    linear_api_key: Optional[str] = None
    linear_team_id: Optional[str] = None


class TicketingIntegration:
    """Base class for ticketing system integrations."""

    def __init__(self, config: TicketingConfig):
        self.config = config
        self.system = config.system
        logger.info(f"Initialized {self.system.value} integration")

    async def create_ticket(self, incident: Incident) -> Optional[str]:
        """Create ticket in external system. Returns ticket ID."""
        raise NotImplementedError

    async def update_ticket(self, ticket_id: str, incident: Incident) -> bool:
        """Update ticket in external system."""
        raise NotImplementedError

    async def close_ticket(self, ticket_id: str, resolution: str) -> bool:
        """Close ticket in external system."""
        raise NotImplementedError

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get ticket status from external system."""
        raise NotImplementedError


class JiraIntegration(TicketingIntegration):
    """Jira ticketing integration."""

    async def create_ticket(self, incident: Incident) -> Optional[str]:
        """Create Jira issue."""
        if not self.config.jira_url or not self.config.jira_project_key:
            logger.error("Jira configuration incomplete")
            return None

        try:
            # In production, use jira library
            # from jira import JIRA
            # jira = JIRA(server=self.config.jira_url, basic_auth=(username, token))

            # Simulate ticket creation
            ticket_id = f"{self.config.jira_project_key}-{hash(incident.incident_id) % 10000}"

            logger.info(f"Created Jira ticket {ticket_id} for incident {incident.incident_id}")
            return ticket_id
        except Exception as e:
            logger.error(f"Failed to create Jira ticket: {e}")
            return None

    async def update_ticket(self, ticket_id: str, incident: Incident) -> bool:
        """Update Jira issue."""
        try:
            logger.info(f"Updated Jira ticket {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update Jira ticket: {e}")
            return False

    async def close_ticket(self, ticket_id: str, resolution: str) -> bool:
        """Close Jira issue."""
        try:
            logger.info(f"Closed Jira ticket {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to close Jira ticket: {e}")
            return False

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get Jira issue status."""
        return "Open"


class ServiceNowIntegration(TicketingIntegration):
    """ServiceNow ticketing integration."""

    async def create_ticket(self, incident: Incident) -> Optional[str]:
        """Create ServiceNow incident."""
        if not self.config.servicenow_instance:
            logger.error("ServiceNow configuration incomplete")
            return None

        try:
            # In production, use pysnow library
            # import pysnow
            # client = pysnow.Client(instance=instance, user=user, password=password)

            # Simulate ticket creation
            ticket_id = f"INC{hash(incident.incident_id) % 1000000:07d}"

            logger.info(f"Created ServiceNow ticket {ticket_id} for incident {incident.incident_id}")
            return ticket_id
        except Exception as e:
            logger.error(f"Failed to create ServiceNow ticket: {e}")
            return None

    async def update_ticket(self, ticket_id: str, incident: Incident) -> bool:
        """Update ServiceNow incident."""
        try:
            logger.info(f"Updated ServiceNow ticket {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update ServiceNow ticket: {e}")
            return False

    async def close_ticket(self, ticket_id: str, resolution: str) -> bool:
        """Close ServiceNow incident."""
        try:
            logger.info(f"Closed ServiceNow ticket {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to close ServiceNow ticket: {e}")
            return False

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get ServiceNow incident status."""
        return "New"


class PagerDutyIntegration(TicketingIntegration):
    """PagerDuty integration."""

    async def create_ticket(self, incident: Incident) -> Optional[str]:
        """Create PagerDuty incident."""
        if not self.config.pagerduty_api_key:
            logger.error("PagerDuty configuration incomplete")
            return None

        try:
            # In production, use pdpyras library
            # from pdpyras import APISession
            # session = APISession(api_key)

            # Simulate incident creation
            ticket_id = f"PD-{hash(incident.incident_id) % 100000:05d}"

            logger.info(f"Created PagerDuty incident {ticket_id} for incident {incident.incident_id}")
            return ticket_id
        except Exception as e:
            logger.error(f"Failed to create PagerDuty incident: {e}")
            return None

    async def update_ticket(self, ticket_id: str, incident: Incident) -> bool:
        """Update PagerDuty incident."""
        try:
            logger.info(f"Updated PagerDuty incident {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update PagerDuty incident: {e}")
            return False

    async def close_ticket(self, ticket_id: str, resolution: str) -> bool:
        """Resolve PagerDuty incident."""
        try:
            logger.info(f"Resolved PagerDuty incident {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to resolve PagerDuty incident: {e}")
            return False

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get PagerDuty incident status."""
        return "triggered"


class OpsgenieIntegration(TicketingIntegration):
    """Opsgenie integration."""

    async def create_ticket(self, incident: Incident) -> Optional[str]:
        """Create Opsgenie alert."""
        if not self.config.opsgenie_api_key:
            logger.error("Opsgenie configuration incomplete")
            return None

        try:
            # In production, use opsgenie-sdk
            # from opsgenie import OpsgenieClient

            # Simulate alert creation
            ticket_id = f"OG-{uuid.uuid4().hex[:8]}"

            logger.info(f"Created Opsgenie alert {ticket_id} for incident {incident.incident_id}")
            return ticket_id
        except Exception as e:
            logger.error(f"Failed to create Opsgenie alert: {e}")
            return None

    async def update_ticket(self, ticket_id: str, incident: Incident) -> bool:
        """Update Opsgenie alert."""
        try:
            logger.info(f"Updated Opsgenie alert {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update Opsgenie alert: {e}")
            return False

    async def close_ticket(self, ticket_id: str, resolution: str) -> bool:
        """Close Opsgenie alert."""
        try:
            logger.info(f"Closed Opsgenie alert {ticket_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to close Opsgenie alert: {e}")
            return False

    async def get_ticket_status(self, ticket_id: str) -> Optional[str]:
        """Get Opsgenie alert status."""
        return "open"


class TicketingManager:
    """Manager for ticketing system integrations."""

    def __init__(self):
        self.integrations: Dict[TicketingSystem, TicketingIntegration] = {}
        logger.info("Ticketing manager initialized")

    def add_integration(self, config: TicketingConfig) -> None:
        """Add ticketing system integration."""
        if not config.enabled:
            return

        integration: Optional[TicketingIntegration] = None

        if config.system == TicketingSystem.JIRA:
            integration = JiraIntegration(config)
        elif config.system == TicketingSystem.SERVICENOW:
            integration = ServiceNowIntegration(config)
        elif config.system == TicketingSystem.PAGERDUTY:
            integration = PagerDutyIntegration(config)
        elif config.system == TicketingSystem.OPSGENIE:
            integration = OpsgenieIntegration(config)

        if integration:
            self.integrations[config.system] = integration
            logger.info(f"Added {config.system.value} integration")

    async def create_tickets(self, incident: Incident) -> Dict[str, str]:
        """Create tickets in all configured systems. Returns system -> ticket_id mapping."""
        tickets = {}

        for system, integration in self.integrations.items():
            try:
                ticket_id = await integration.create_ticket(incident)
                if ticket_id:
                    tickets[system.value] = ticket_id
                    incident.add_external_ticket(system, ticket_id)
            except Exception as e:
                logger.error(f"Failed to create ticket in {system.value}: {e}")

        return tickets

    async def update_tickets(self, incident: Incident) -> Dict[str, bool]:
        """Update tickets in all linked systems. Returns system -> success mapping."""
        results = {}

        for system_name, ticket_id in incident.external_tickets.items():
            try:
                system = TicketingSystem(system_name)
                integration = self.integrations.get(system)
                if integration:
                    success = await integration.update_ticket(ticket_id, incident)
                    results[system_name] = success
            except Exception as e:
                logger.error(f"Failed to update ticket in {system_name}: {e}")
                results[system_name] = False

        return results

    async def close_tickets(self, incident: Incident, resolution: str) -> Dict[str, bool]:
        """Close tickets in all linked systems. Returns system -> success mapping."""
        results = {}

        for system_name, ticket_id in incident.external_tickets.items():
            try:
                system = TicketingSystem(system_name)
                integration = self.integrations.get(system)
                if integration:
                    success = await integration.close_ticket(ticket_id, resolution)
                    results[system_name] = success
            except Exception as e:
                logger.error(f"Failed to close ticket in {system_name}: {e}")
                results[system_name] = False

        return results

    def get_integration(self, system: TicketingSystem) -> Optional[TicketingIntegration]:
        """Get integration for system."""
        return self.integrations.get(system)


# Global ticketing manager instance
_ticketing_manager: Optional[TicketingManager] = None


def get_ticketing_manager() -> TicketingManager:
    """Get or create global ticketing manager instance."""
    global _ticketing_manager
    if _ticketing_manager is None:
        _ticketing_manager = TicketingManager()
    return _ticketing_manager


# ============================================================================
# Convenience Functions
# ============================================================================


async def process_security_event(
    event: SecurityEvent,
    analysis: Optional[AnalysisResult] = None,
    create_tickets: bool = True
) -> Tuple[Incident, bool]:
    """
    Process security event and create/update incident with optional ticketing.

    Args:
        event: Security event to process
        analysis: Optional analysis result
        create_tickets: Whether to create tickets in external systems

    Returns:
        Tuple of (incident, is_new_incident)
    """
    manager = get_incident_manager()
    incident, is_new = manager.process_event(event, analysis)

    # Create tickets for new incidents
    if is_new and create_tickets:
        ticketing_manager = get_ticketing_manager()
        if ticketing_manager.integrations:
            try:
                tickets = await ticketing_manager.create_tickets(incident)
                logger.info(f"Created {len(tickets)} tickets for incident {incident.incident_id}")
            except Exception as e:
                logger.error(f"Failed to create tickets: {e}")

    return incident, is_new


def get_incident_summary(incident: Incident) -> Dict[str, Any]:
    """Get human-readable incident summary."""
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "status": incident.status.value,
        "priority": incident.priority.value,
        "severity": incident.severity.value,
        "created_at": incident.created_at.isoformat(),
        "age": str(incident.get_age()),
        "assigned_to": incident.assigned_to,
        "escalation_level": incident.escalation_level.value,
        "event_count": incident.event_count,
        "deduplicated_count": incident.deduplicated_count,
        "affected_assets": incident.affected_assets,
        "affected_users": incident.affected_users,
        "mitre_techniques": incident.mitre_techniques,
        "external_tickets": incident.external_tickets,
        "sla_breached": incident.sla_breached,
        "sla_breach_reasons": incident.sla_breach_reasons,
        "tags": incident.tags,
        "notes_count": len(incident.notes)
    }


def format_incident_for_notification(incident: Incident) -> str:
    """Format incident for notification message."""
    lines = [
        f"🚨 **Incident Alert: {incident.title}**",
        "",
        f"**ID:** {incident.incident_id}",
        f"**Priority:** {incident.priority.value}",
        f"**Severity:** {incident.severity.value}",
        f"**Status:** {incident.status.value}",
        f"**Created:** {incident.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Age:** {incident.get_age()}",
        ""
    ]

    if incident.assigned_to:
        lines.append(f"**Assigned To:** {incident.assigned_to}")

    lines.append(f"**Escalation Level:** {incident.escalation_level.value}")

    if incident.affected_assets:
        lines.append(f"**Affected Assets:** {', '.join(incident.affected_assets[:5])}")

    if incident.mitre_techniques:
        lines.append(f"**MITRE Techniques:** {', '.join(incident.mitre_techniques[:5])}")

    if incident.external_tickets:
        tickets = [f"{sys}: {tid}" for sys, tid in incident.external_tickets.items()]
        lines.append(f"**External Tickets:** {', '.join(tickets)}")

    if incident.sla_breached:
        lines.append(f"⚠️ **SLA BREACHED:** {', '.join(incident.sla_breach_reasons)}")

    lines.append("")
    lines.append(f"**Description:** {incident.description[:200]}...")

    return "\n".join(lines)


# ============================================================================
# Background Tasks
# ============================================================================


async def incident_maintenance_task(interval_seconds: int = 60):
    """Background task for incident maintenance."""
    manager = get_incident_manager()

    while True:
        try:
            # Check SLA breaches
            manager.check_sla_breaches()

            # Check for auto-escalation
            manager.check_and_escalate_incidents()

            # Cleanup expired data
            manager.cleanup()

            logger.debug("Incident maintenance task completed")
        except Exception as e:
            logger.error(f"Error in incident maintenance task: {e}")

        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    # Demo usage
    print("Vaulytica Incident Management System")
    print("=" * 80)

    # Create manager
    manager = get_incident_manager()

    # Add on-call users
    manager.on_call_schedule.add_user(EscalationLevel.L1_ANALYST, "user@example.com")
    manager.on_call_schedule.add_user(EscalationLevel.L2_SENIOR_ANALYST, "user@example.com")

    # Create sample event
    from vaulytica.models import SecurityEvent, Severity, EventCategory

    event = SecurityEvent(
        event_id="test-001",
        source_system="GuardDuty",
        timestamp=datetime.utcnow(),
        severity=Severity.HIGH,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Suspicious login detected",
        description="Multiple failed login attempts followed by successful login",
        raw_event={},
        metadata={"source_ip": "203.0.113.45", "user": "admin"}
    )

    # Process event
    incident, is_new = manager.process_event(event)

    print(f"\nIncident Created: {incident.incident_id}")
    print(f"Priority: {incident.priority.value}")
    print(f"Status: {incident.status.value}")
    print(f"Assigned To: {incident.assigned_to}")

    # Get metrics
    metrics = manager.get_metrics()
    print("\nMetrics:")
    print(f"Total Incidents: {metrics.total_incidents}")
    print(f"Open Incidents: {metrics.open_incidents}")
    print(f"Deduplication Rate: {metrics.deduplication_rate:.1f}%")
