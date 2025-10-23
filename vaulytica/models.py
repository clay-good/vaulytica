"""Data models for security events and analysis."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalized severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventCategory(str, Enum):
    """Security event categories."""
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    MALWARE = "MALWARE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    VULNERABILITY = "VULNERABILITY"
    RECONNAISSANCE = "RECONNAISSANCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    UNKNOWN = "UNKNOWN"


# Alias for backward compatibility
EventType = EventCategory


class AssetInfo(BaseModel):
    """Information about affected assets."""
    hostname: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    cloud_resource_id: Optional[str] = None
    environment: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class TechnicalIndicator(BaseModel):
    """Technical indicators from security events."""
    indicator_type: str
    value: str
    context: Optional[str] = None


class MitreAttack(BaseModel):
    """MITRE ATT&CK framework mapping."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0)


class SecurityEvent(BaseModel):
    """Normalized security event model."""

    event_id: str = Field(description="Unique event identifier")
    source_system: str = Field(description="Source system (e.g., GuardDuty, GCP SCC)")
    timestamp: datetime = Field(description="Event timestamp")
    severity: Severity = Field(description="Normalized severity")
    category: EventCategory = Field(description="Event category")
    title: str = Field(description="Event title/summary")
    description: str = Field(description="Detailed description")

    affected_assets: List[AssetInfo] = Field(default_factory=list)
    technical_indicators: List[TechnicalIndicator] = Field(default_factory=list)
    mitre_attack: List[MitreAttack] = Field(default_factory=list)

    raw_event: Dict[str, Any] = Field(description="Original raw event data")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)


class FiveW1H(BaseModel):
    """5W1H quick summary framework for rapid incident understanding."""

    who: str = Field(description="Who is involved (attacker, victim, accounts)")
    what: str = Field(description="What happened (attack type, actions taken)")
    when: str = Field(description="When did it occur (timeline, duration)")
    where: str = Field(description="Where did it happen (systems, locations, networks)")
    why: str = Field(description="Why it happened (motivation, objectives)")
    how: str = Field(description="How was it executed (techniques, tools, methods)")


class ThreatActorProfile(BaseModel):
    """Threat actor attribution profile."""
    actor_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    origin: Optional[str] = None
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    ttps_matched: List[str] = Field(default_factory=list)


class BehavioralInsight(BaseModel):
    """Behavioral analysis insight."""
    insight_type: str
    description: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)


class AttackGraphNode(BaseModel):
    """Node in attack graph visualization."""
    node_id: str
    node_type: str  # initial_access, execution, persistence, etc.
    technique_id: Optional[str] = None
    description: str
    timestamp: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)


class AnalysisResult(BaseModel):
    """Result of security analysis."""

    event_id: str
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)

    five_w1h: FiveW1H
    executive_summary: str
    risk_score: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(ge=0.0, le=1.0)

    attack_chain: List[str] = Field(default_factory=list)
    mitre_techniques: List[MitreAttack] = Field(default_factory=list)

    immediate_actions: List[str] = Field(default_factory=list)
    short_term_recommendations: List[str] = Field(default_factory=list)
    long_term_recommendations: List[str] = Field(default_factory=list)

    related_incidents: List[str] = Field(default_factory=list)
    investigation_queries: List[str] = Field(default_factory=list)

    # Enhanced fields
    threat_actors: List[ThreatActorProfile] = Field(default_factory=list)
    behavioral_insights: List[BehavioralInsight] = Field(default_factory=list)
    attack_graph: List[AttackGraphNode] = Field(default_factory=list)
    anomaly_score: float = Field(default=0.0, ge=0.0, le=10.0)
    ioc_enrichments: Dict[str, Any] = Field(default_factory=dict)

    # Cross-platform investigation queries (new)
    investigation_queries_by_platform: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)

    # URLScan.io results (new)
    urlscan_results: Dict[str, Any] = Field(default_factory=dict)

    # WHOIS results (new)
    whois_results: Dict[str, Any] = Field(default_factory=dict)

    raw_llm_response: str
    tokens_used: int = 0
    processing_time_seconds: float = 0.0

    # Correlation fields (populated by correlation engine)
    correlated_event_ids: List[str] = Field(default_factory=list)
    cluster_id: Optional[str] = None
    campaign_id: Optional[str] = None


class CorrelationSummary(BaseModel):
    """Summary of event correlations."""
    event_id: str
    total_correlations: int
    correlation_types: Dict[str, int] = Field(default_factory=dict)
    correlated_events: List[str] = Field(default_factory=list)
    cluster_id: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_name: Optional[str] = None
    is_part_of_campaign: bool = False
