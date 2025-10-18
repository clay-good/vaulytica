import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict
import hashlib
import json

from vaulytica.models import SecurityEvent, Severity, EventCategory
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class HuntStatus(str, Enum):
    """Hunt campaign status."""
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class HuntType(str, Enum):
    """Types of threat hunts."""
    HYPOTHESIS_DRIVEN = "HYPOTHESIS_DRIVEN"  # Based on threat intelligence
    IOC_BASED = "IOC_BASED"  # Search for specific IOCs
    BEHAVIORAL = "BEHAVIORAL"  # Anomaly and behavior-based
    CROWN_JEWEL = "CROWN_JEWEL"  # Protect critical assets
    THREAT_ACTOR = "THREAT_ACTOR"  # Hunt for specific APT/actor
    TECHNIQUE_BASED = "TECHNIQUE_BASED"  # MITRE ATT&CK technique hunting


class QueryType(str, Enum):
    """Types of hunt queries."""
    SIEM = "SIEM"  # SIEM query (Splunk, ELK, etc.)
    EDR = "EDR"  # EDR query (CrowdStrike, Carbon Black, etc.)
    NETWORK = "NETWORK"  # Network traffic query
    CLOUD = "CLOUD"  # Cloud logs query
    ENDPOINT = "ENDPOINT"  # Endpoint logs query
    CUSTOM = "CUSTOM"  # Custom data source


class FindingSeverity(str, Enum):
    """Severity of hunt findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class HuntQuery:
    """Represents a threat hunting query."""
    query_id: str
    query_type: QueryType
    query_string: str
    description: str
    data_sources: List[str]
    expected_results: str
    false_positive_rate: float = 0.0
    execution_time_estimate: int = 60  # seconds
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_id": self.query_id,
            "query_type": self.query_type.value,
            "query_string": self.query_string,
            "description": self.description,
            "data_sources": self.data_sources,
            "expected_results": self.expected_results,
            "false_positive_rate": self.false_positive_rate,
            "execution_time_estimate": self.execution_time_estimate,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class HuntFinding:
    """Represents a finding from threat hunting."""
    finding_id: str
    hunt_id: str
    query_id: str
    severity: FindingSeverity
    title: str
    description: str
    indicators: List[str]
    affected_assets: List[str]
    mitre_techniques: List[str]
    confidence_score: float  # 0.0-1.0
    false_positive_likelihood: float  # 0.0-1.0
    raw_data: Dict[str, Any]
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    validated: bool = False
    escalated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "hunt_id": self.hunt_id,
            "query_id": self.query_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "indicators": self.indicators,
            "affected_assets": self.affected_assets,
            "mitre_techniques": self.mitre_techniques,
            "confidence_score": self.confidence_score,
            "false_positive_likelihood": self.false_positive_likelihood,
            "discovered_at": self.discovered_at.isoformat(),
            "validated": self.validated,
            "escalated": self.escalated
        }


@dataclass
class HuntCampaign:
    """Represents a threat hunting campaign."""
    hunt_id: str
    name: str
    description: str
    hunt_type: HuntType
    hypothesis: str
    queries: List[HuntQuery]
    findings: List[HuntFinding] = field(default_factory=list)
    status: HuntStatus = HuntStatus.DRAFT
    priority: int = 3  # 1-5, 1 is highest
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "name": self.name,
            "description": self.description,
            "hunt_type": self.hunt_type.value,
            "hypothesis": self.hypothesis,
            "status": self.status.value,
            "priority": self.priority,
            "assigned_to": self.assigned_to,
            "tags": self.tags,
            "mitre_techniques": self.mitre_techniques,
            "threat_actors": self.threat_actors,
            "queries_count": len(self.queries),
            "findings_count": len(self.findings),
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


class ThreatHuntingEngine:
    """
    Advanced Threat Hunting Engine.
    
    Provides hypothesis-driven threat hunting with automated query generation,
    IOC pivoting, behavioral analysis, and hunt campaign management.
    """
    
    def __init__(self):
        self.campaigns: Dict[str, HuntCampaign] = {}
        self.findings: Dict[str, HuntFinding] = {}
        self.query_templates: Dict[str, List[HuntQuery]] = self._initialize_templates()
        self.statistics = {
            "total_campaigns": 0,
            "active_campaigns": 0,
            "total_findings": 0,
            "validated_findings": 0,
            "escalated_findings": 0,
            "queries_executed": 0,
            "avg_execution_time": 0.0
        }
        logger.info("Threat Hunting Engine initialized")
    
    def _initialize_templates(self) -> Dict[str, List[HuntQuery]]:
        """Initialize hunt query templates for common scenarios."""
        templates = {
            "lateral_movement": [
                HuntQuery(
                    query_id="lm_001",
                    query_type=QueryType.SIEM,
                    query_string='EventID=4624 AND LogonType=3 AND NOT (SourceIP IN known_admin_ips)',
                    description="Detect unusual network logons indicating lateral movement",
                    data_sources=["Windows Security Logs", "Active Directory"],
                    expected_results="Network logons from unexpected sources",
                    false_positive_rate=0.15
                ),
                HuntQuery(
                    query_id="lm_002",
                    query_type=QueryType.EDR,
                    query_string='process_name IN (psexec.exe, wmic.exe, powershell.exe) AND network_connection=true',
                    description="Detect remote execution tools used for lateral movement",
                    data_sources=["EDR", "Process Logs"],
                    expected_results="Remote execution tool usage",
                    false_positive_rate=0.10
                )
            ],
            "data_exfiltration": [
                HuntQuery(
                    query_id="de_001",
                    query_type=QueryType.NETWORK,
                    query_string='bytes_out > 100MB AND dest_port IN (443, 80, 22) AND NOT dest_ip IN known_cloud_ips',
                    description="Detect large data transfers to unknown destinations",
                    data_sources=["Network Traffic", "Firewall Logs"],
                    expected_results="Unusual large outbound transfers",
                    false_positive_rate=0.20
                ),
                HuntQuery(
                    query_id="de_002",
                    query_type=QueryType.CLOUD,
                    query_string='action=download AND object_size > 50MB AND user NOT IN approved_users',
                    description="Detect bulk downloads from cloud storage",
                    data_sources=["Cloud Storage Logs", "S3/GCS Logs"],
                    expected_results="Unauthorized bulk downloads",
                    false_positive_rate=0.12
                )
            ],
            "privilege_escalation": [
                HuntQuery(
                    query_id="pe_001",
                    query_type=QueryType.SIEM,
                    query_string='EventID IN (4672, 4728, 4732) AND user NOT IN known_admins',
                    description="Detect privilege escalation attempts",
                    data_sources=["Windows Security Logs"],
                    expected_results="Unexpected privilege grants",
                    false_positive_rate=0.08
                )
            ],
            "persistence": [
                HuntQuery(
                    query_id="ps_001",
                    query_type=QueryType.ENDPOINT,
                    query_string='registry_path CONTAINS "\\Run" OR scheduled_task_created=true',
                    description="Detect persistence mechanisms",
                    data_sources=["Registry Logs", "Scheduled Tasks"],
                    expected_results="New persistence mechanisms",
                    false_positive_rate=0.18
                )
            ],
            "c2_communication": [
                HuntQuery(
                    query_id="c2_001",
                    query_type=QueryType.NETWORK,
                    query_string='dns_query MATCHES "^[a-f0-9]{32,}\\." OR beacon_interval < 60',
                    description="Detect C2 beaconing patterns",
                    data_sources=["DNS Logs", "Network Traffic"],
                    expected_results="C2 communication patterns",
                    false_positive_rate=0.10
                )
            ]
        }
        return templates
    
    async def create_campaign(
        self,
        name: str,
        description: str,
        hunt_type: HuntType,
        hypothesis: str,
        queries: Optional[List[HuntQuery]] = None,
        priority: int = 3,
        assigned_to: Optional[str] = None,
        tags: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        threat_actors: Optional[List[str]] = None
    ) -> HuntCampaign:
        """Create a new threat hunting campaign."""
        hunt_id = f"HUNT-{datetime.utcnow().strftime('%Y%m%d')}-{len(self.campaigns) + 1:04d}"
        
        campaign = HuntCampaign(
            hunt_id=hunt_id,
            name=name,
            description=description,
            hunt_type=hunt_type,
            hypothesis=hypothesis,
            queries=queries or [],
            priority=priority,
            assigned_to=assigned_to,
            tags=tags or [],
            mitre_techniques=mitre_techniques or [],
            threat_actors=threat_actors or []
        )
        
        self.campaigns[hunt_id] = campaign
        self.statistics["total_campaigns"] += 1
        
        logger.info(f"Created hunt campaign: {hunt_id} - {name}")
        return campaign

    async def start_campaign(self, hunt_id: str) -> HuntCampaign:
        """Start a hunt campaign."""
        if hunt_id not in self.campaigns:
            raise ValueError(f"Hunt campaign {hunt_id} not found")

        campaign = self.campaigns[hunt_id]
        campaign.status = HuntStatus.ACTIVE
        campaign.started_at = datetime.utcnow()
        self.statistics["active_campaigns"] += 1

        logger.info(f"Started hunt campaign: {hunt_id}")
        return campaign

    async def execute_query(
        self,
        hunt_id: str,
        query: HuntQuery,
        simulate: bool = True
    ) -> List[HuntFinding]:
        """
        Execute a hunt query and return findings.

        In production, this would connect to actual SIEM/EDR/data sources.
        For now, we simulate query execution.
        """
        if hunt_id not in self.campaigns:
            raise ValueError(f"Hunt campaign {hunt_id} not found")

        campaign = self.campaigns[hunt_id]
        findings = []

        # Simulate query execution
        if simulate:
            await asyncio.sleep(0.1)  # Simulate query time

            # Generate simulated findings based on query type
            num_findings = 0
            if query.false_positive_rate < 0.1:
                num_findings = 2  # Low FP rate = more reliable findings
            elif query.false_positive_rate < 0.2:
                num_findings = 1

            for i in range(num_findings):
                finding = HuntFinding(
                    finding_id=f"{hunt_id}-F{len(campaign.findings) + i + 1:03d}",
                    hunt_id=hunt_id,
                    query_id=query.query_id,
                    severity=FindingSeverity.HIGH if i == 0 else FindingSeverity.MEDIUM,
                    title=f"Suspicious activity detected: {query.description}",
                    description=f"Query '{query.query_id}' detected potential threat activity",
                    indicators=[f"indicator_{i+1}", f"ioc_{i+1}"],
                    affected_assets=[f"asset_{i+1}"],
                    mitre_techniques=campaign.mitre_techniques[:2] if campaign.mitre_techniques else [],
                    confidence_score=0.85 - (i * 0.1),
                    false_positive_likelihood=query.false_positive_rate,
                    raw_data={"query": query.query_string, "results": f"simulated_result_{i+1}"}
                )
                findings.append(finding)
                campaign.findings.append(finding)
                self.findings[finding.finding_id] = finding

        self.statistics["queries_executed"] += 1
        self.statistics["total_findings"] += len(findings)

        logger.info(f"Executed query {query.query_id} for hunt {hunt_id}: {len(findings)} findings")
        return findings

    async def execute_campaign(self, hunt_id: str, simulate: bool = True) -> Dict[str, Any]:
        """Execute all queries in a hunt campaign."""
        if hunt_id not in self.campaigns:
            raise ValueError(f"Hunt campaign {hunt_id} not found")

        campaign = self.campaigns[hunt_id]

        if campaign.status != HuntStatus.ACTIVE:
            await self.start_campaign(hunt_id)

        all_findings = []
        execution_times = []

        for query in campaign.queries:
            start_time = datetime.utcnow()
            findings = await self.execute_query(hunt_id, query, simulate=simulate)
            execution_time = (datetime.utcnow() - start_time).total_seconds()

            all_findings.extend(findings)
            execution_times.append(execution_time)

        avg_execution_time = sum(execution_times) / len(execution_times) if execution_times else 0

        result = {
            "hunt_id": hunt_id,
            "queries_executed": len(campaign.queries),
            "total_findings": len(all_findings),
            "avg_execution_time": avg_execution_time,
            "findings_by_severity": self._count_by_severity(all_findings)
        }

        logger.info(f"Executed campaign {hunt_id}: {len(all_findings)} findings")
        return result

    def _count_by_severity(self, findings: List[HuntFinding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = defaultdict(int)
        for finding in findings:
            counts[finding.severity.value] += 1
        return dict(counts)

    async def validate_finding(self, finding_id: str, is_valid: bool, notes: str = "") -> HuntFinding:
        """Validate a hunt finding (true positive vs false positive)."""
        if finding_id not in self.findings:
            raise ValueError(f"Finding {finding_id} not found")

        finding = self.findings[finding_id]
        finding.validated = True

        if is_valid:
            self.statistics["validated_findings"] += 1
            logger.info(f"Finding {finding_id} validated as TRUE POSITIVE")
        else:
            logger.info(f"Finding {finding_id} validated as FALSE POSITIVE")

        return finding

    async def escalate_finding(self, finding_id: str, escalation_notes: str = "") -> HuntFinding:
        """Escalate a finding to incident response."""
        if finding_id not in self.findings:
            raise ValueError(f"Finding {finding_id} not found")

        finding = self.findings[finding_id]
        finding.escalated = True
        self.statistics["escalated_findings"] += 1

        logger.info(f"Finding {finding_id} escalated to incident response")
        return finding

    async def complete_campaign(self, hunt_id: str, summary: str = "") -> HuntCampaign:
        """Complete a hunt campaign."""
        if hunt_id not in self.campaigns:
            raise ValueError(f"Hunt campaign {hunt_id} not found")

        campaign = self.campaigns[hunt_id]
        campaign.status = HuntStatus.COMPLETED
        campaign.completed_at = datetime.utcnow()

        if campaign.status == HuntStatus.ACTIVE:
            self.statistics["active_campaigns"] -= 1

        logger.info(f"Completed hunt campaign: {hunt_id}")
        return campaign

    async def generate_hunt_from_ioc(
        self,
        ioc: str,
        ioc_type: str,
        name: Optional[str] = None
    ) -> HuntCampaign:
        """Generate a hunt campaign from an IOC."""
        hunt_name = name or f"IOC Hunt: {ioc_type} - {ioc[:20]}"

        # Generate queries based on IOC type
        queries = []
        if ioc_type == "ip":
            queries.append(HuntQuery(
                query_id=f"ioc_ip_{hashlib.md5(ioc.encode()).hexdigest()[:8]}",
                query_type=QueryType.NETWORK,
                query_string=f'src_ip="{ioc}" OR dest_ip="{ioc}"',
                description=f"Search for IP address {ioc} in network traffic",
                data_sources=["Network Traffic", "Firewall Logs"],
                expected_results=f"Connections involving {ioc}",
                false_positive_rate=0.05
            ))
        elif ioc_type == "domain":
            queries.append(HuntQuery(
                query_id=f"ioc_domain_{hashlib.md5(ioc.encode()).hexdigest()[:8]}",
                query_type=QueryType.NETWORK,
                query_string=f'dns_query="{ioc}" OR http_host="{ioc}"',
                description=f"Search for domain {ioc} in DNS and HTTP logs",
                data_sources=["DNS Logs", "Proxy Logs"],
                expected_results=f"DNS queries or HTTP requests to {ioc}",
                false_positive_rate=0.03
            ))
        elif ioc_type == "hash":
            queries.append(HuntQuery(
                query_id=f"ioc_hash_{hashlib.md5(ioc.encode()).hexdigest()[:8]}",
                query_type=QueryType.EDR,
                query_string=f'file_hash="{ioc}"',
                description=f"Search for file hash {ioc} on endpoints",
                data_sources=["EDR", "File Integrity Monitoring"],
                expected_results=f"Files matching hash {ioc}",
                false_positive_rate=0.01
            ))

        campaign = await self.create_campaign(
            name=hunt_name,
            description=f"Automated hunt for IOC: {ioc}",
            hunt_type=HuntType.IOC_BASED,
            hypothesis=f"IOC {ioc} ({ioc_type}) may be present in environment",
            queries=queries,
            priority=2,
            tags=["ioc", ioc_type, "automated"]
        )

        logger.info(f"Generated IOC hunt campaign: {campaign.hunt_id}")
        return campaign

    async def generate_hunt_from_technique(
        self,
        technique_id: str,
        technique_name: str
    ) -> HuntCampaign:
        """Generate a hunt campaign for a MITRE ATT&CK technique."""
        # Map common techniques to query templates
        technique_map = {
            "T1021": "lateral_movement",  # Remote Services
            "T1048": "data_exfiltration",  # Exfiltration Over Alternative Protocol
            "T1078": "privilege_escalation",  # Valid Accounts
            "T1547": "persistence",  # Boot or Logon Autostart Execution
            "T1071": "c2_communication"  # Application Layer Protocol
        }

        template_key = technique_map.get(technique_id.split(".")[0], "lateral_movement")
        queries = self.query_templates.get(template_key, [])

        campaign = await self.create_campaign(
            name=f"Technique Hunt: {technique_name}",
            description=f"Hunt for MITRE ATT&CK technique {technique_id}",
            hunt_type=HuntType.TECHNIQUE_BASED,
            hypothesis=f"Adversaries may be using {technique_name} ({technique_id})",
            queries=queries,
            priority=2,
            mitre_techniques=[technique_id],
            tags=["mitre", "technique", technique_id]
        )

        logger.info(f"Generated technique hunt campaign: {campaign.hunt_id}")
        return campaign

    def get_campaign(self, hunt_id: str) -> Optional[HuntCampaign]:
        """Get a hunt campaign by ID."""
        return self.campaigns.get(hunt_id)

    def list_campaigns(
        self,
        status: Optional[HuntStatus] = None,
        hunt_type: Optional[HuntType] = None,
        limit: int = 100
    ) -> List[HuntCampaign]:
        """List hunt campaigns with optional filtering."""
        campaigns = list(self.campaigns.values())

        if status:
            campaigns = [c for c in campaigns if c.status == status]
        if hunt_type:
            campaigns = [c for c in campaigns if c.hunt_type == hunt_type]

        # Sort by priority (1 is highest) then by created_at
        campaigns.sort(key=lambda c: (c.priority, c.created_at), reverse=True)

        return campaigns[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat hunting statistics."""
        return {
            **self.statistics,
            "campaigns_by_status": self._count_campaigns_by_status(),
            "campaigns_by_type": self._count_campaigns_by_type(),
            "findings_by_severity": self._count_all_findings_by_severity()
        }

    def _count_campaigns_by_status(self) -> Dict[str, int]:
        """Count campaigns by status."""
        counts = defaultdict(int)
        for campaign in self.campaigns.values():
            counts[campaign.status.value] += 1
        return dict(counts)

    def _count_campaigns_by_type(self) -> Dict[str, int]:
        """Count campaigns by type."""
        counts = defaultdict(int)
        for campaign in self.campaigns.values():
            counts[campaign.hunt_type.value] += 1
        return dict(counts)

    def _count_all_findings_by_severity(self) -> Dict[str, int]:
        """Count all findings by severity."""
        counts = defaultdict(int)
        for finding in self.findings.values():
            counts[finding.severity.value] += 1
        return dict(counts)


# Global instance
_threat_hunting_engine: Optional[ThreatHuntingEngine] = None


def get_threat_hunting_engine() -> ThreatHuntingEngine:
    """Get the global threat hunting engine instance."""
    global _threat_hunting_engine
    if _threat_hunting_engine is None:
        _threat_hunting_engine = ThreatHuntingEngine()
    return _threat_hunting_engine

