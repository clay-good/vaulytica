import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import statistics

from vaulytica.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Data Models
# ============================================================================

class AssetType(str, Enum):
    """Asset types for attack surface management."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    CLOUD_RESOURCE = "cloud_resource"
    MOBILE_APP = "mobile_app"
    CERTIFICATE = "certificate"
    EMAIL_SERVER = "email_server"
    DNS_RECORD = "dns_record"
    NETWORK_SERVICE = "network_service"
    THIRD_PARTY_SERVICE = "third_party_service"


class ExposureLevel(str, Enum):
    """Exposure level classification."""
    CRITICAL = "critical"  # Publicly exposed with critical vulnerabilities
    HIGH = "high"  # Publicly exposed with high-risk services
    MEDIUM = "medium"  # Publicly exposed with standard services
    LOW = "low"  # Limited exposure or well-protected
    MINIMAL = "minimal"  # Internal only or properly secured


class ThreatCategory(str, Enum):
    """STRIDE threat categories."""
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class DataSourceType(str, Enum):
    """Security data lake source types."""
    SIEM = "siem"
    EDR = "edr"
    FIREWALL = "firewall"
    IDS_IPS = "ids_ips"
    CLOUD_LOGS = "cloud_logs"
    APPLICATION_LOGS = "application_logs"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY_SCAN = "vulnerability_scan"
    COMPLIANCE_AUDIT = "compliance_audit"
    USER_BEHAVIOR = "user_behavior"


@dataclass
class DiscoveredAsset:
    """Discovered asset in attack surface."""
    asset_id: str
    asset_type: AssetType
    name: str
    description: str
    discovered_at: datetime
    last_seen: datetime

    # Asset details
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)

    # Exposure information
    is_public: bool = False
    exposure_level: ExposureLevel = ExposureLevel.MINIMAL
    exposure_score: float = 0.0  # 0-10 scale

    # Vulnerability information
    vulnerabilities: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    misconfigurations: List[str] = field(default_factory=list)

    # Ownership and classification
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    is_shadow_it: bool = False
    is_approved: bool = True

    # Risk information
    risk_score: float = 0.0  # 0-10 scale
    criticality: str = "medium"

    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSurfaceReport:
    """Attack surface analysis report."""
    report_id: str
    organization_id: str
    generated_at: datetime

    # Asset summary
    total_assets: int
    assets_by_type: Dict[AssetType, int]
    public_assets: int
    shadow_it_assets: int

    # Exposure summary
    critical_exposures: int
    high_exposures: int
    medium_exposures: int
    low_exposures: int
    average_exposure_score: float

    # Vulnerability summary
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    unique_cves: int

    # Risk summary
    overall_risk_score: float  # 0-10 scale
    high_risk_assets: List[DiscoveredAsset]

    # Recommendations
    recommendations: List[str]
    quick_wins: List[str]

    # Trends
    asset_growth_rate: float  # Percentage
    exposure_trend: str  # "improving", "stable", "declining"


@dataclass
class ThreatModel:
    """Threat model for a system or component."""
    model_id: str
    name: str
    description: str
    created_at: datetime
    updated_at: datetime

    # System information
    system_name: str
    system_type: str
    components: List[str]
    data_flows: List[Dict[str, str]]
    trust_boundaries: List[str]

    # Threats
    threats: List['Threat']
    total_threats: int
    critical_threats: int
    high_threats: int

    # Risk assessment
    overall_risk_score: float  # 0-10 scale
    residual_risk_score: float  # After mitigations

    # Mitigations
    mitigations: List[str]
    mitigation_coverage: float  # Percentage

    # Metadata
    owner: str
    reviewers: List[str]
    last_reviewed: datetime
    next_review: datetime


@dataclass
class Threat:
    """Individual threat in threat model."""
    threat_id: str
    category: ThreatCategory
    title: str
    description: str

    # STRIDE analysis
    affected_component: str
    attack_vector: str
    prerequisites: List[str]

    # Risk assessment
    likelihood: float  # 0-1 scale
    impact: float  # 0-1 scale
    risk_score: float  # likelihood * impact * 10

    # Mitigations
    existing_controls: List[str]
    recommended_controls: List[str]
    mitigation_status: str  # "none", "partial", "complete"

    # References
    cwe_ids: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class SecurityDataRecord:
    """Record in security data lake."""
    record_id: str
    source_type: DataSourceType
    source_name: str
    timestamp: datetime
    ingested_at: datetime

    # Normalized fields
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None

    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # Enrichment
    enriched_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    # Retention
    retention_days: int = 90
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(days=90))


@dataclass
class SecurityMetric:
    """Security metric for KPI tracking."""
    metric_id: str
    name: str
    description: str
    category: str  # "vulnerability", "incident", "compliance", "posture", etc.

    # Current value
    current_value: float
    previous_value: float
    target_value: float

    # Trend
    trend: str  # "improving", "stable", "declining"
    change_percentage: float

    # Time period
    period_start: datetime
    period_end: datetime

    # Metadata
    unit: str  # "count", "percentage", "score", "days", etc.
    is_higher_better: bool = True
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None


@dataclass
class IncidentSimulation:
    """Incident simulation scenario."""
    simulation_id: str
    name: str
    description: str
    scenario_type: str  # "ransomware", "data_breach", "ddos", "insider_threat", etc.

    # Scenario details
    initial_conditions: Dict[str, Any]
    timeline: List[Dict[str, Any]]
    expected_actions: List[str]
    success_criteria: List[str]

    # Execution
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # "pending", "running", "completed", "failed"

    # Results
    actions_taken: List[str] = field(default_factory=list)
    response_time_minutes: Optional[float] = None
    success_rate: Optional[float] = None  # 0-1 scale

    # Participants
    participants: List[str] = field(default_factory=list)
    facilitator: Optional[str] = None

    # Lessons learned
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# ============================================================================
# Attack Surface Discovery Engine
# ============================================================================

class AttackSurfaceDiscoveryEngine:
    """
    Attack Surface Discovery Engine.

    Discovers and maps external attack surface including domains, subdomains,
    IP addresses, services, and shadow IT assets.
    """

    def __init__(self):
        """Initialize attack surface discovery engine."""
        self.assets: Dict[str, DiscoveredAsset] = {}
        self.scan_history: List[Dict[str, Any]] = []

        self.statistics = {
            'total_scans': 0,
            'assets_discovered': 0,
            'shadow_it_detected': 0,
            'critical_exposures': 0,
            'vulnerabilities_found': 0,
        }

        logger.info("Attack Surface Discovery Engine initialized")

    async def discover_assets(
        self,
        organization_id: str,
        domains: List[str],
        scan_depth: str = "standard"  # "quick", "standard", "deep"
    ) -> List[DiscoveredAsset]:
        """
        Discover assets for organization.

        Args:
            organization_id: Organization identifier
            domains: List of root domains to scan
            scan_depth: Scan depth level

        Returns:
            List of discovered assets
        """
        logger.info(f"Starting asset discovery for {organization_id} with {len(domains)} domains")

        discovered = []

        for domain in domains:
            # Discover subdomains
            subdomains = await self._discover_subdomains(domain, scan_depth)
            discovered.extend(subdomains)

            # Discover IP addresses
            ip_assets = await self._discover_ip_addresses(domain)
            discovered.extend(ip_assets)

            # Discover web applications
            web_apps = await self._discover_web_applications(domain)
            discovered.extend(web_apps)

            # Discover API endpoints
            apis = await self._discover_api_endpoints(domain)
            discovered.extend(apis)

            # Discover cloud resources
            cloud_resources = await self._discover_cloud_resources(domain)
            discovered.extend(cloud_resources)

        # Detect shadow IT
        await self._detect_shadow_it(discovered, organization_id)

        # Calculate exposure scores
        for asset in discovered:
            asset.exposure_score = await self._calculate_exposure_score(asset)
            asset.risk_score = await self._calculate_risk_score(asset)

        # Store assets
        for asset in discovered:
            self.assets[asset.asset_id] = asset

        self.statistics['total_scans'] += 1
        self.statistics['assets_discovered'] += len(discovered)
        self.statistics['shadow_it_detected'] += sum(1 for a in discovered if a.is_shadow_it)
        self.statistics['critical_exposures'] += sum(1 for a in discovered if a.exposure_level == ExposureLevel.CRITICAL)

        logger.info(f"Discovered {len(discovered)} assets for {organization_id}")

        return discovered

    async def _discover_subdomains(self, domain: str, scan_depth: str) -> List[DiscoveredAsset]:
        """Discover subdomains for a domain."""
        # Simulated subdomain discovery
        common_subdomains = [
            "www", "api", "app", "dev", "staging", "test", "admin", "portal",
            "mail", "smtp", "ftp", "vpn", "remote", "dashboard", "cdn", "static"
        ]

        if scan_depth == "deep":
            common_subdomains.extend(["internal", "legacy", "old", "backup", "db", "mysql", "postgres"])

        discovered = []
        for subdomain in common_subdomains[:8 if scan_depth == "quick" else 12 if scan_depth == "standard" else 16]:
            asset_id = hashlib.sha256(f"{subdomain}.{domain}".encode()).hexdigest()[:16]
            asset = DiscoveredAsset(
                asset_id=asset_id,
                asset_type=AssetType.SUBDOMAIN,
                name=f"{subdomain}.{domain}",
                description=f"Subdomain of {domain}",
                discovered_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                domains=[f"{subdomain}.{domain}"],
                is_public=True,
                services=["HTTP", "HTTPS"] if subdomain in ["www", "api", "app"] else ["HTTPS"],
                ports=[80, 443] if subdomain in ["www", "api", "app"] else [443],
                technologies=["Nginx", "TLS 1.3"] if subdomain in ["www", "api"] else ["Apache"],
            )
            discovered.append(asset)

        return discovered

    async def _discover_ip_addresses(self, domain: str) -> List[DiscoveredAsset]:
        """Discover IP addresses for a domain."""
        # Simulated IP discovery
        discovered = []

        # Simulate 2-3 IP addresses per domain
        for i in range(2):
            asset_id = hashlib.sha256(f"ip_{domain}_{i}".encode()).hexdigest()[:16]
            ip = f"203.0.113.{10 + i}"  # TEST-NET-3 range

            asset = DiscoveredAsset(
                asset_id=asset_id,
                asset_type=AssetType.IP_ADDRESS,
                name=ip,
                description=f"IP address for {domain}",
                discovered_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                ip_addresses=[ip],
                domains=[domain],
                is_public=True,
                ports=[22, 80, 443, 3306] if i == 0 else [80, 443],
                services=["SSH", "HTTP", "HTTPS", "MySQL"] if i == 0 else ["HTTP", "HTTPS"],
            )
            discovered.append(asset)

        return discovered

    async def _discover_web_applications(self, domain: str) -> List[DiscoveredAsset]:
        """Discover web applications."""
        # Simulated web app discovery
        web_apps = ["main_app", "customer_portal", "admin_panel"]
        discovered = []

        for app in web_apps[:2]:  # Discover 2 web apps
            asset_id = hashlib.sha256(f"webapp_{domain}_{app}".encode()).hexdigest()[:16]

            asset = DiscoveredAsset(
                asset_id=asset_id,
                asset_type=AssetType.WEB_APPLICATION,
                name=f"{app.replace('_', ' ').title()} - {domain}",
                description=f"Web application hosted on {domain}",
                discovered_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                domains=[domain],
                is_public=True,
                technologies=["React", "Node.js", "PostgreSQL", "Redis"],
                services=["HTTPS"],
                ports=[443],
            )
            discovered.append(asset)

        return discovered

    async def _discover_api_endpoints(self, domain: str) -> List[DiscoveredAsset]:
        """Discover API endpoints."""
        # Simulated API discovery
        apis = ["/api/v1/users", "/api/v1/auth", "/api/v1/data", "/api/v2/analytics"]
        discovered = []

        for api in apis[:3]:  # Discover 3 APIs
            asset_id = hashlib.sha256(f"api_{domain}_{api}".encode()).hexdigest()[:16]

            asset = DiscoveredAsset(
                asset_id=asset_id,
                asset_type=AssetType.API_ENDPOINT,
                name=f"{domain}{api}",
                description=f"API endpoint on {domain}",
                discovered_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                domains=[domain],
                is_public=True,
                technologies=["REST API", "JSON", "OAuth 2.0"],
                services=["HTTPS"],
                ports=[443],
            )
            discovered.append(asset)

        return discovered

    async def _discover_cloud_resources(self, domain: str) -> List[DiscoveredAsset]:
        """Discover cloud resources."""
        # Simulated cloud resource discovery
        cloud_types = ["S3 Bucket", "Azure Blob", "GCS Bucket"]
        discovered = []

        for i, cloud_type in enumerate(cloud_types[:2]):  # Discover 2 cloud resources
            asset_id = hashlib.sha256(f"cloud_{domain}_{i}".encode()).hexdigest()[:16]

            asset = DiscoveredAsset(
                asset_id=asset_id,
                asset_type=AssetType.CLOUD_RESOURCE,
                name=f"{domain.replace('.', '-')}-{cloud_type.lower().replace(' ', '-')}-{i}",
                description=f"{cloud_type} for {domain}",
                discovered_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                domains=[domain],
                is_public=i == 0,  # First one is public
                technologies=[cloud_type, "Cloud Storage"],
                services=["HTTPS"],
                ports=[443],
            )
            discovered.append(asset)

        return discovered

    async def _detect_shadow_it(self, assets: List[DiscoveredAsset], organization_id: str) -> None:
        """Detect shadow IT assets."""
        # Simulated shadow IT detection
        # Mark assets with certain patterns as shadow IT
        shadow_it_indicators = ["dev", "test", "staging", "legacy", "old", "backup"]

        for asset in assets:
            if any(indicator in asset.name.lower() for indicator in shadow_it_indicators):
                if hash(asset.asset_id) % 3 == 0:  # 33% chance
                    asset.is_shadow_it = True
                    asset.is_approved = False

    async def _calculate_exposure_score(self, asset: DiscoveredAsset) -> float:
        """Calculate exposure score for asset (0-10 scale)."""
        score = 0.0

        # Base score for public assets
        if asset.is_public:
            score += 3.0

        # Add score for risky ports
        risky_ports = {22: 1.5, 3306: 2.0, 5432: 2.0, 27017: 2.0, 6379: 1.5}
        for port in asset.ports:
            score += risky_ports.get(port, 0.0)

        # Add score for vulnerabilities
        score += len(asset.vulnerabilities) * 0.5
        score += len(asset.cve_ids) * 1.0

        # Add score for misconfigurations
        score += len(asset.misconfigurations) * 0.8

        # Add score for shadow IT
        if asset.is_shadow_it:
            score += 2.0

        # Classify exposure level
        if score >= 8.0:
            asset.exposure_level = ExposureLevel.CRITICAL
        elif score >= 6.0:
            asset.exposure_level = ExposureLevel.HIGH
        elif score >= 4.0:
            asset.exposure_level = ExposureLevel.MEDIUM
        elif score >= 2.0:
            asset.exposure_level = ExposureLevel.LOW
        else:
            asset.exposure_level = ExposureLevel.MINIMAL

        return min(score, 10.0)

    async def _calculate_risk_score(self, asset: DiscoveredAsset) -> float:
        """Calculate overall risk score for asset (0-10 scale)."""
        # Risk = Exposure * Criticality * Vulnerability
        exposure_factor = asset.exposure_score / 10.0

        criticality_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}
        criticality_factor = criticality_map.get(asset.criticality, 0.5)

        vulnerability_factor = min((len(asset.vulnerabilities) + len(asset.cve_ids)) / 10.0, 1.0)

        risk_score = (exposure_factor + criticality_factor + vulnerability_factor) / 3.0 * 10.0

        return min(risk_score, 10.0)

    async def generate_attack_surface_report(
        self,
        organization_id: str
    ) -> AttackSurfaceReport:
        """Generate comprehensive attack surface report."""
        logger.info(f"Generating attack surface report for {organization_id}")

        org_assets = [a for a in self.assets.values()]

        # Asset summary
        assets_by_type = defaultdict(int)
        for asset in org_assets:
            assets_by_type[asset.asset_type] += 1

        public_assets = sum(1 for a in org_assets if a.is_public)
        shadow_it_assets = sum(1 for a in org_assets if a.is_shadow_it)

        # Exposure summary
        critical_exposures = sum(1 for a in org_assets if a.exposure_level == ExposureLevel.CRITICAL)
        high_exposures = sum(1 for a in org_assets if a.exposure_level == ExposureLevel.HIGH)
        medium_exposures = sum(1 for a in org_assets if a.exposure_level == ExposureLevel.MEDIUM)
        low_exposures = sum(1 for a in org_assets if a.exposure_level == ExposureLevel.LOW)

        avg_exposure = statistics.mean([a.exposure_score for a in org_assets]) if org_assets else 0.0

        # Vulnerability summary
        total_vulns = sum(len(a.vulnerabilities) + len(a.cve_ids) for a in org_assets)
        unique_cves = len(set(cve for a in org_assets for cve in a.cve_ids))

        # Risk summary
        overall_risk = statistics.mean([a.risk_score for a in org_assets]) if org_assets else 0.0
        high_risk_assets = sorted([a for a in org_assets if a.risk_score >= 7.0], key=lambda x: x.risk_score, reverse=True)[:10]

        # Generate recommendations
        recommendations = []
        if shadow_it_assets > 0:
            recommendations.append(f"Review and remediate {shadow_it_assets} shadow IT assets")
        if critical_exposures > 0:
            recommendations.append(f"Immediately address {critical_exposures} critical exposures")
        if unique_cves > 0:
            recommendations.append(f"Patch {unique_cves} unique CVEs across attack surface")

        quick_wins = []
        if any(22 in a.ports for a in org_assets if a.is_public):
            quick_wins.append("Disable SSH on public-facing assets or use VPN")
        if any(3306 in a.ports or 5432 in a.ports for a in org_assets if a.is_public):
            quick_wins.append("Move databases behind firewall or use private networking")

        report = AttackSurfaceReport(
            report_id=hashlib.sha256(f"{organization_id}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16],
            organization_id=organization_id,
            generated_at=datetime.utcnow(),
            total_assets=len(org_assets),
            assets_by_type=dict(assets_by_type),
            public_assets=public_assets,
            shadow_it_assets=shadow_it_assets,
            critical_exposures=critical_exposures,
            high_exposures=high_exposures,
            medium_exposures=medium_exposures,
            low_exposures=low_exposures,
            average_exposure_score=avg_exposure,
            total_vulnerabilities=total_vulns,
            critical_vulnerabilities=sum(1 for a in org_assets if a.exposure_level == ExposureLevel.CRITICAL),
            high_vulnerabilities=sum(1 for a in org_assets if a.exposure_level == ExposureLevel.HIGH),
            unique_cves=unique_cves,
            overall_risk_score=overall_risk,
            high_risk_assets=high_risk_assets,
            recommendations=recommendations,
            quick_wins=quick_wins,
            asset_growth_rate=5.2,  # Simulated
            exposure_trend="stable"
        )

        logger.info(f"Generated attack surface report: {len(org_assets)} assets, {critical_exposures} critical exposures")

        return report

    def get_statistics(self) -> Dict[str, Any]:
        """Get discovery engine statistics."""
        return self.statistics.copy()



# ============================================================================
# Security Data Lake
# ============================================================================

class SecurityDataLake:
    """
    Security Data Lake.

    Centralized repository for all security data with advanced query capabilities,
    data normalization, retention management, and analytics.
    """

    def __init__(self):
        """Initialize security data lake."""
        self.records: Dict[str, SecurityDataRecord] = {}
        self.indices: Dict[str, List[str]] = defaultdict(list)  # Index by field

        self.statistics = {
            'total_records': 0,
            'records_by_source': defaultdict(int),
            'data_volume_gb': 0.0,
            'queries_executed': 0,
            'avg_query_time_ms': 0.0,
        }

        logger.info("Security Data Lake initialized")

    async def ingest_data(
        self,
        source_type: DataSourceType,
        source_name: str,
        records: List[Dict[str, Any]],
        retention_days: int = 90
    ) -> List[str]:
        """
        Ingest security data into data lake.

        Args:
            source_type: Type of data source
            source_name: Name of data source
            records: List of raw records
            retention_days: Data retention period

        Returns:
            List of record IDs
        """
        logger.info(f"Ingesting {len(records)} records from {source_name}")

        record_ids = []

        for raw_record in records:
            # Normalize record
            normalized = await self._normalize_record(source_type, raw_record)

            # Create data record
            record_id = hashlib.sha256(f"{source_name}_{datetime.utcnow().isoformat()}_{hash(str(raw_record))}".encode()).hexdigest()[:16]

            data_record = SecurityDataRecord(
                record_id=record_id,
                source_type=source_type,
                source_name=source_name,
                timestamp=normalized.get('timestamp', datetime.utcnow()),
                ingested_at=datetime.utcnow(),
                event_type=normalized.get('event_type', 'unknown'),
                severity=normalized.get('severity', 'info'),
                source_ip=normalized.get('source_ip'),
                destination_ip=normalized.get('destination_ip'),
                user=normalized.get('user'),
                action=normalized.get('action'),
                result=normalized.get('result'),
                raw_data=raw_record,
                retention_days=retention_days,
                expires_at=datetime.utcnow() + timedelta(days=retention_days)
            )

            # Store record
            self.records[record_id] = data_record
            record_ids.append(record_id)

            # Update indices
            self._update_indices(data_record)

        self.statistics['total_records'] += len(records)
        self.statistics['records_by_source'][source_name] += len(records)
        self.statistics['data_volume_gb'] += len(str(records)) / (1024 ** 3)  # Rough estimate

        logger.info(f"Ingested {len(records)} records, total: {self.statistics['total_records']}")

        return record_ids

    async def _normalize_record(self, source_type: DataSourceType, raw_record: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize raw record to common schema."""
        normalized = {}

        # Source-specific normalization
        if source_type == DataSourceType.SIEM:
            normalized['event_type'] = raw_record.get('event_type', raw_record.get('type', 'unknown'))
            normalized['severity'] = raw_record.get('severity', 'info')
            normalized['source_ip'] = raw_record.get('src_ip', raw_record.get('source_ip'))
            normalized['destination_ip'] = raw_record.get('dst_ip', raw_record.get('dest_ip'))
            normalized['user'] = raw_record.get('user', raw_record.get('username'))
            normalized['action'] = raw_record.get('action')
            normalized['result'] = raw_record.get('result', raw_record.get('status'))

        elif source_type == DataSourceType.FIREWALL:
            normalized['event_type'] = 'network_traffic'
            normalized['severity'] = 'info' if raw_record.get('action') == 'allow' else 'warning'
            normalized['source_ip'] = raw_record.get('src_ip')
            normalized['destination_ip'] = raw_record.get('dst_ip')
            normalized['action'] = raw_record.get('action')
            normalized['result'] = raw_record.get('action')

        elif source_type == DataSourceType.EDR:
            normalized['event_type'] = raw_record.get('event_type', 'endpoint_event')
            normalized['severity'] = raw_record.get('severity', 'info')
            normalized['user'] = raw_record.get('user')
            normalized['action'] = raw_record.get('action')
            normalized['result'] = raw_record.get('result')

        # Add timestamp
        if 'timestamp' in raw_record:
            if isinstance(raw_record['timestamp'], str):
                try:
                    normalized['timestamp'] = datetime.fromisoformat(raw_record['timestamp'].replace('Z', '+00:00'))
                except:
                    normalized['timestamp'] = datetime.utcnow()
            else:
                normalized['timestamp'] = raw_record['timestamp']
        else:
            normalized['timestamp'] = datetime.utcnow()

        return normalized

    def _update_indices(self, record: SecurityDataRecord) -> None:
        """Update search indices."""
        if record.source_ip:
            self.indices[f"source_ip:{record.source_ip}"].append(record.record_id)
        if record.destination_ip:
            self.indices[f"destination_ip:{record.destination_ip}"].append(record.record_id)
        if record.user:
            self.indices[f"user:{record.user}"].append(record.record_id)
        if record.event_type:
            self.indices[f"event_type:{record.event_type}"].append(record.record_id)
        if record.severity:
            self.indices[f"severity:{record.severity}"].append(record.record_id)

    async def query_data(
        self,
        filters: Dict[str, Any],
        limit: int = 100,
        offset: int = 0
    ) -> List[SecurityDataRecord]:
        """
        Query security data lake.

        Args:
            filters: Query filters (e.g., {'source_ip': '1.2.3.4', 'severity': 'high'})
            limit: Maximum number of results
            offset: Result offset for pagination

        Returns:
            List of matching records
        """
        import time
        start_time = time.time()

        logger.info(f"Querying data lake with filters: {filters}")

        # Get candidate record IDs from indices
        candidate_ids = None

        for field, value in filters.items():
            index_key = f"{field}:{value}"
            if index_key in self.indices:
                field_ids = set(self.indices[index_key])
                if candidate_ids is None:
                    candidate_ids = field_ids
                else:
                    candidate_ids = candidate_ids.intersection(field_ids)

        # If no index matches, scan all records
        if candidate_ids is None:
            candidate_ids = set(self.records.keys())

        # Filter records
        results = []
        for record_id in candidate_ids:
            if record_id in self.records:
                record = self.records[record_id]
                if self._matches_filters(record, filters):
                    results.append(record)

        # Sort by timestamp (newest first)
        results.sort(key=lambda x: x.timestamp, reverse=True)

        # Apply pagination
        paginated_results = results[offset:offset + limit]

        query_time = (time.time() - start_time) * 1000  # Convert to ms
        self.statistics['queries_executed'] += 1
        self.statistics['avg_query_time_ms'] = (
            (self.statistics['avg_query_time_ms'] * (self.statistics['queries_executed'] - 1) + query_time) /
            self.statistics['queries_executed']
        )

        logger.info(f"Query returned {len(paginated_results)} results in {query_time:.2f}ms")

        return paginated_results

    def _matches_filters(self, record: SecurityDataRecord, filters: Dict[str, Any]) -> bool:
        """Check if record matches all filters."""
        for field, value in filters.items():
            record_value = getattr(record, field, None)
            if record_value != value:
                return False
        return True

    async def cleanup_expired_data(self) -> int:
        """Remove expired data based on retention policy."""
        logger.info("Cleaning up expired data")

        now = datetime.utcnow()
        expired_ids = [
            record_id for record_id, record in self.records.items()
            if record.expires_at < now
        ]

        for record_id in expired_ids:
            del self.records[record_id]

        logger.info(f"Removed {len(expired_ids)} expired records")

        return len(expired_ids)

    def get_statistics(self) -> Dict[str, Any]:
        """Get data lake statistics."""
        return {
            'total_records': self.statistics['total_records'],
            'records_by_source': dict(self.statistics['records_by_source']),
            'data_volume_gb': round(self.statistics['data_volume_gb'], 2),
            'queries_executed': self.statistics['queries_executed'],
            'avg_query_time_ms': round(self.statistics['avg_query_time_ms'], 2),
            'active_records': len(self.records),
        }


# ============================================================================
# Threat Modeling Engine
# ============================================================================

class ThreatModelingEngine:
    """
    Threat Modeling Engine.

    STRIDE-based threat modeling with attack tree generation,
    threat scenario simulation, and risk quantification.
    """

    def __init__(self):
        """Initialize threat modeling engine."""
        self.models: Dict[str, ThreatModel] = {}
        self.threat_library: Dict[ThreatCategory, List[Dict[str, Any]]] = self._initialize_threat_library()

        self.statistics = {
            'models_created': 0,
            'threats_identified': 0,
            'mitigations_recommended': 0,
            'models_reviewed': 0,
        }

        logger.info("Threat Modeling Engine initialized")

    def _initialize_threat_library(self) -> Dict[ThreatCategory, List[Dict[str, Any]]]:
        """Initialize threat library with common threats."""
        return {
            ThreatCategory.SPOOFING: [
                {'title': 'Credential Theft', 'cwe': ['CWE-287'], 'mitre': ['T1078']},
                {'title': 'Session Hijacking', 'cwe': ['CWE-384'], 'mitre': ['T1185']},
                {'title': 'Man-in-the-Middle', 'cwe': ['CWE-300'], 'mitre': ['T1557']},
            ],
            ThreatCategory.TAMPERING: [
                {'title': 'Data Manipulation', 'cwe': ['CWE-20'], 'mitre': ['T1565']},
                {'title': 'Code Injection', 'cwe': ['CWE-94'], 'mitre': ['T1055']},
                {'title': 'Configuration Tampering', 'cwe': ['CWE-732'], 'mitre': ['T1562']},
            ],
            ThreatCategory.REPUDIATION: [
                {'title': 'Log Tampering', 'cwe': ['CWE-117'], 'mitre': ['T1070']},
                {'title': 'Audit Trail Deletion', 'cwe': ['CWE-778'], 'mitre': ['T1070.001']},
            ],
            ThreatCategory.INFORMATION_DISCLOSURE: [
                {'title': 'Data Leakage', 'cwe': ['CWE-200'], 'mitre': ['T1567']},
                {'title': 'Sensitive Data Exposure', 'cwe': ['CWE-311'], 'mitre': ['T1005']},
                {'title': 'Directory Traversal', 'cwe': ['CWE-22'], 'mitre': ['T1083']},
            ],
            ThreatCategory.DENIAL_OF_SERVICE: [
                {'title': 'Resource Exhaustion', 'cwe': ['CWE-400'], 'mitre': ['T1499']},
                {'title': 'Application Crash', 'cwe': ['CWE-404'], 'mitre': ['T1499.004']},
            ],
            ThreatCategory.ELEVATION_OF_PRIVILEGE: [
                {'title': 'Privilege Escalation', 'cwe': ['CWE-269'], 'mitre': ['T1068']},
                {'title': 'Unauthorized Access', 'cwe': ['CWE-284'], 'mitre': ['T1078']},
            ],
        }

    async def create_threat_model(
        self,
        system_name: str,
        system_type: str,
        components: List[str],
        data_flows: List[Dict[str, str]],
        trust_boundaries: List[str],
        owner: str
    ) -> ThreatModel:
        """
        Create threat model for a system.

        Args:
            system_name: Name of system
            system_type: Type of system (web_app, api, mobile_app, etc.)
            components: List of system components
            data_flows: List of data flows between components
            trust_boundaries: List of trust boundaries
            owner: Model owner

        Returns:
            Created threat model
        """
        logger.info(f"Creating threat model for {system_name}")

        model_id = hashlib.sha256(f"{system_name}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]

        # Identify threats using STRIDE
        threats = await self._identify_threats(system_type, components, data_flows, trust_boundaries)

        # Calculate risk scores
        overall_risk = statistics.mean([t.risk_score for t in threats]) if threats else 0.0

        # Generate mitigations
        mitigations = await self._generate_mitigations(threats)
        mitigation_coverage = len([t for t in threats if t.mitigation_status != "none"]) / len(threats) if threats else 0.0

        # Calculate residual risk (after mitigations)
        residual_risk = overall_risk * (1 - mitigation_coverage * 0.7)  # Mitigations reduce risk by up to 70%

        model = ThreatModel(
            model_id=model_id,
            name=f"Threat Model: {system_name}",
            description=f"STRIDE-based threat model for {system_name}",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            system_name=system_name,
            system_type=system_type,
            components=components,
            data_flows=data_flows,
            trust_boundaries=trust_boundaries,
            threats=threats,
            total_threats=len(threats),
            critical_threats=sum(1 for t in threats if t.risk_score >= 8.0),
            high_threats=sum(1 for t in threats if 6.0 <= t.risk_score < 8.0),
            overall_risk_score=overall_risk,
            residual_risk_score=residual_risk,
            mitigations=mitigations,
            mitigation_coverage=mitigation_coverage,
            owner=owner,
            reviewers=[],
            last_reviewed=datetime.utcnow(),
            next_review=datetime.utcnow() + timedelta(days=90)
        )

        self.models[model_id] = model
        self.statistics['models_created'] += 1
        self.statistics['threats_identified'] += len(threats)
        self.statistics['mitigations_recommended'] += len(mitigations)

        logger.info(f"Created threat model with {len(threats)} threats, overall risk: {overall_risk:.2f}")

        return model

    async def _identify_threats(
        self,
        system_type: str,
        components: List[str],
        data_flows: List[Dict[str, str]],
        trust_boundaries: List[str]
    ) -> List[Threat]:
        """Identify threats using STRIDE methodology."""
        threats = []

        # Analyze each STRIDE category
        for category, threat_templates in self.threat_library.items():
            for template in threat_templates:
                # Determine if threat applies to this system
                if await self._threat_applies(category, system_type, components):
                    threat_id = hashlib.sha256(f"{category}_{template['title']}_{system_type}".encode()).hexdigest()[:16]

                    # Calculate likelihood and impact
                    likelihood = await self._calculate_likelihood(category, system_type, components)
                    impact = await self._calculate_impact(category, system_type)

                    threat = Threat(
                        threat_id=threat_id,
                        category=category,
                        title=template['title'],
                        description=f"{template['title']} threat in {system_type}",
                        affected_component=components[hash(threat_id) % len(components)] if components else "Unknown",
                        attack_vector=self._get_attack_vector(category),
                        prerequisites=self._get_prerequisites(category),
                        likelihood=likelihood,
                        impact=impact,
                        risk_score=likelihood * impact * 10,
                        existing_controls=[],
                        recommended_controls=self._get_recommended_controls(category),
                        mitigation_status="none",
                        cwe_ids=template.get('cwe', []),
                        mitre_techniques=template.get('mitre', []),
                        references=[]
                    )
                    threats.append(threat)

        return threats

    async def _threat_applies(self, category: ThreatCategory, system_type: str, components: List[str]) -> bool:
        """Determine if threat category applies to system."""
        # All STRIDE categories apply to web apps and APIs
        if system_type in ["web_app", "api", "mobile_app"]:
            return True

        # Specific logic for other system types
        if system_type == "database":
            return category in [ThreatCategory.TAMPERING, ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.ELEVATION_OF_PRIVILEGE]

        return True

    async def _calculate_likelihood(self, category: ThreatCategory, system_type: str, components: List[str]) -> float:
        """Calculate threat likelihood (0-1 scale)."""
        base_likelihood = {
            ThreatCategory.SPOOFING: 0.6,
            ThreatCategory.TAMPERING: 0.5,
            ThreatCategory.REPUDIATION: 0.3,
            ThreatCategory.INFORMATION_DISCLOSURE: 0.7,
            ThreatCategory.DENIAL_OF_SERVICE: 0.4,
            ThreatCategory.ELEVATION_OF_PRIVILEGE: 0.5,
        }

        likelihood = base_likelihood.get(category, 0.5)

        # Adjust based on system type
        if system_type in ["web_app", "api"] and category == ThreatCategory.INFORMATION_DISCLOSURE:
            likelihood += 0.1

        return min(likelihood, 1.0)

    async def _calculate_impact(self, category: ThreatCategory, system_type: str) -> float:
        """Calculate threat impact (0-1 scale)."""
        base_impact = {
            ThreatCategory.SPOOFING: 0.7,
            ThreatCategory.TAMPERING: 0.8,
            ThreatCategory.REPUDIATION: 0.5,
            ThreatCategory.INFORMATION_DISCLOSURE: 0.9,
            ThreatCategory.DENIAL_OF_SERVICE: 0.6,
            ThreatCategory.ELEVATION_OF_PRIVILEGE: 0.9,
        }

        return base_impact.get(category, 0.7)

    def _get_attack_vector(self, category: ThreatCategory) -> str:
        """Get attack vector for threat category."""
        vectors = {
            ThreatCategory.SPOOFING: "Network/Application",
            ThreatCategory.TAMPERING: "Application/Data",
            ThreatCategory.REPUDIATION: "Application/Logs",
            ThreatCategory.INFORMATION_DISCLOSURE: "Network/Application/Data",
            ThreatCategory.DENIAL_OF_SERVICE: "Network/Application",
            ThreatCategory.ELEVATION_OF_PRIVILEGE: "Application/System",
        }
        return vectors.get(category, "Unknown")

    def _get_prerequisites(self, category: ThreatCategory) -> List[str]:
        """Get prerequisites for threat category."""
        prereqs = {
            ThreatCategory.SPOOFING: ["Network access", "Valid credentials or session"],
            ThreatCategory.TAMPERING: ["Application access", "Insufficient input validation"],
            ThreatCategory.REPUDIATION: ["Application access", "Weak audit logging"],
            ThreatCategory.INFORMATION_DISCLOSURE: ["Network/Application access", "Insufficient access controls"],
            ThreatCategory.DENIAL_OF_SERVICE: ["Network access", "Resource-intensive operations"],
            ThreatCategory.ELEVATION_OF_PRIVILEGE: ["User access", "Vulnerable privilege management"],
        }
        return prereqs.get(category, [])

    def _get_recommended_controls(self, category: ThreatCategory) -> List[str]:
        """Get recommended controls for threat category."""
        controls = {
            ThreatCategory.SPOOFING: ["Multi-factor authentication", "Strong session management", "Certificate pinning"],
            ThreatCategory.TAMPERING: ["Input validation", "Integrity checks", "Code signing"],
            ThreatCategory.REPUDIATION: ["Comprehensive audit logging", "Log integrity protection", "Non-repudiation mechanisms"],
            ThreatCategory.INFORMATION_DISCLOSURE: ["Encryption at rest and in transit", "Access controls", "Data classification"],
            ThreatCategory.DENIAL_OF_SERVICE: ["Rate limiting", "Resource quotas", "DDoS protection"],
            ThreatCategory.ELEVATION_OF_PRIVILEGE: ["Principle of least privilege", "Role-based access control", "Regular privilege audits"],
        }
        return controls.get(category, [])

    async def _generate_mitigations(self, threats: List[Threat]) -> List[str]:
        """Generate mitigation recommendations."""
        mitigations = set()
        for threat in threats:
            mitigations.update(threat.recommended_controls)
        return sorted(list(mitigations))

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat modeling engine statistics."""
        return self.statistics.copy()



# ============================================================================
# Security Metrics & KPI Dashboard
# ============================================================================

class SecurityMetricsDashboard:
    """
    Security Metrics & KPI Dashboard.

    Tracks security metrics, KPIs, and generates executive dashboards
    with trend analysis and automated reporting.
    """

    def __init__(self):
        """Initialize security metrics dashboard."""
        self.metrics: Dict[str, SecurityMetric] = {}
        self.metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=90))  # 90 days

        self.statistics = {
            'metrics_tracked': 0,
            'dashboards_generated': 0,
            'reports_created': 0,
        }

        logger.info("Security Metrics Dashboard initialized")

    async def track_metric(
        self,
        name: str,
        category: str,
        current_value: float,
        target_value: float,
        unit: str = "count",
        is_higher_better: bool = True
    ) -> SecurityMetric:
        """Track a security metric."""
        metric_id = hashlib.sha256(f"{name}_{category}".encode()).hexdigest()[:16]

        # Get previous value
        previous_value = 0.0
        if metric_id in self.metrics:
            previous_value = self.metrics[metric_id].current_value

        # Calculate trend
        change_percentage = ((current_value - previous_value) / previous_value * 100) if previous_value != 0 else 0.0

        if is_higher_better:
            trend = "improving" if change_percentage > 5 else "declining" if change_percentage < -5 else "stable"
        else:
            trend = "improving" if change_percentage < -5 else "declining" if change_percentage > 5 else "stable"

        metric = SecurityMetric(
            metric_id=metric_id,
            name=name,
            description=f"{category} metric: {name}",
            category=category,
            current_value=current_value,
            previous_value=previous_value,
            target_value=target_value,
            trend=trend,
            change_percentage=change_percentage,
            period_start=datetime.utcnow() - timedelta(days=30),
            period_end=datetime.utcnow(),
            unit=unit,
            is_higher_better=is_higher_better
        )

        self.metrics[metric_id] = metric
        self.metric_history[metric_id].append({
            'timestamp': datetime.utcnow(),
            'value': current_value
        })

        self.statistics['metrics_tracked'] += 1

        return metric

    async def generate_executive_dashboard(self, organization_id: str) -> Dict[str, Any]:
        """Generate executive security dashboard."""
        logger.info(f"Generating executive dashboard for {organization_id}")

        # Group metrics by category
        metrics_by_category = defaultdict(list)
        for metric in self.metrics.values():
            metrics_by_category[metric.category].append(metric)

        # Calculate category summaries
        category_summaries = {}
        for category, metrics in metrics_by_category.items():
            improving = sum(1 for m in metrics if m.trend == "improving")
            declining = sum(1 for m in metrics if m.trend == "declining")
            stable = sum(1 for m in metrics if m.trend == "stable")

            category_summaries[category] = {
                'total_metrics': len(metrics),
                'improving': improving,
                'declining': declining,
                'stable': stable,
                'health_score': (improving * 100 + stable * 50) / len(metrics) if metrics else 0
            }

        # Overall health score
        overall_health = statistics.mean([s['health_score'] for s in category_summaries.values()]) if category_summaries else 0

        # Top improving and declining metrics
        all_metrics = list(self.metrics.values())
        top_improving = sorted([m for m in all_metrics if m.trend == "improving"], key=lambda x: abs(x.change_percentage), reverse=True)[:5]
        top_declining = sorted([m for m in all_metrics if m.trend == "declining"], key=lambda x: abs(x.change_percentage), reverse=True)[:5]

        dashboard = {
            'organization_id': organization_id,
            'generated_at': datetime.utcnow().isoformat(),
            'overall_health_score': round(overall_health, 2),
            'total_metrics': len(all_metrics),
            'category_summaries': category_summaries,
            'top_improving_metrics': [{'name': m.name, 'change': f"+{m.change_percentage:.1f}%"} for m in top_improving],
            'top_declining_metrics': [{'name': m.name, 'change': f"{m.change_percentage:.1f}%"} for m in top_declining],
            'metrics_by_category': {cat: len(metrics) for cat, metrics in metrics_by_category.items()}
        }

        self.statistics['dashboards_generated'] += 1

        logger.info(f"Generated dashboard with {len(all_metrics)} metrics, health score: {overall_health:.2f}")

        return dashboard

    def get_statistics(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        return self.statistics.copy()


# ============================================================================
# Incident Simulation & Tabletop Exercise Platform
# ============================================================================

class IncidentSimulationPlatform:
    """
    Incident Simulation & Tabletop Exercise Platform.

    Creates incident simulation scenarios, automates tabletop exercises,
    assesses team readiness, and provides training modules.
    """

    def __init__(self):
        """Initialize incident simulation platform."""
        self.simulations: Dict[str, IncidentSimulation] = {}
        self.scenario_templates: Dict[str, Dict[str, Any]] = self._initialize_scenarios()

        self.statistics = {
            'simulations_run': 0,
            'participants_trained': set(),
            'avg_response_time_minutes': 0.0,
            'avg_success_rate': 0.0,
        }

        logger.info("Incident Simulation Platform initialized")

    def _initialize_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Initialize scenario templates."""
        return {
            'ransomware': {
                'name': 'Ransomware Attack Simulation',
                'description': 'Simulated ransomware attack with encryption and ransom demand',
                'timeline': [
                    {'time': 0, 'event': 'Initial infection via phishing email'},
                    {'time': 5, 'event': 'Lateral movement to file servers'},
                    {'time': 15, 'event': 'File encryption begins'},
                    {'time': 30, 'event': 'Ransom note displayed'},
                ],
                'expected_actions': [
                    'Isolate infected systems',
                    'Activate incident response team',
                    'Assess backup integrity',
                    'Notify stakeholders',
                    'Engage law enforcement',
                ],
                'success_criteria': [
                    'Response time < 30 minutes',
                    'All infected systems isolated',
                    'Backups verified and restored',
                    'No ransom paid',
                ]
            },
            'data_breach': {
                'name': 'Data Breach Simulation',
                'description': 'Simulated data breach with exfiltration of sensitive data',
                'timeline': [
                    {'time': 0, 'event': 'Unauthorized access detected'},
                    {'time': 10, 'event': 'Data exfiltration in progress'},
                    {'time': 20, 'event': 'Exfiltration complete'},
                    {'time': 30, 'event': 'Data posted on dark web'},
                ],
                'expected_actions': [
                    'Block exfiltration channels',
                    'Identify compromised accounts',
                    'Assess data sensitivity',
                    'Notify affected parties',
                    'Engage legal and PR teams',
                ],
                'success_criteria': [
                    'Exfiltration stopped within 15 minutes',
                    'All compromised accounts identified',
                    'Notification plan executed',
                    'Regulatory compliance maintained',
                ]
            },
            'ddos': {
                'name': 'DDoS Attack Simulation',
                'description': 'Simulated distributed denial of service attack',
                'timeline': [
                    {'time': 0, 'event': 'Traffic spike detected'},
                    {'time': 5, 'event': 'Services degraded'},
                    {'time': 10, 'event': 'Services unavailable'},
                ],
                'expected_actions': [
                    'Activate DDoS mitigation',
                    'Scale infrastructure',
                    'Block malicious IPs',
                    'Communicate with customers',
                ],
                'success_criteria': [
                    'Mitigation activated within 10 minutes',
                    'Service restored within 30 minutes',
                    'Customer communication sent',
                ]
            },
        }

    async def create_simulation(
        self,
        scenario_type: str,
        participants: List[str],
        facilitator: str
    ) -> IncidentSimulation:
        """Create incident simulation."""
        logger.info(f"Creating {scenario_type} simulation with {len(participants)} participants")

        if scenario_type not in self.scenario_templates:
            raise ValueError(f"Unknown scenario type: {scenario_type}")

        template = self.scenario_templates[scenario_type]
        simulation_id = hashlib.sha256(f"{scenario_type}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]

        simulation = IncidentSimulation(
            simulation_id=simulation_id,
            name=template['name'],
            description=template['description'],
            scenario_type=scenario_type,
            initial_conditions={'scenario': scenario_type, 'participants': len(participants)},
            timeline=template['timeline'],
            expected_actions=template['expected_actions'],
            success_criteria=template['success_criteria'],
            participants=participants,
            facilitator=facilitator
        )

        self.simulations[simulation_id] = simulation

        logger.info(f"Created simulation {simulation_id}")

        return simulation

    async def run_simulation(self, simulation_id: str) -> IncidentSimulation:
        """Run incident simulation."""
        if simulation_id not in self.simulations:
            raise ValueError(f"Simulation not found: {simulation_id}")

        simulation = self.simulations[simulation_id]

        logger.info(f"Running simulation {simulation_id}")

        simulation.status = "running"
        simulation.started_at = datetime.utcnow()

        # Simulate execution (in real implementation, this would be interactive)
        await asyncio.sleep(0.1)  # Simulate time

        # Simulate actions taken
        simulation.actions_taken = simulation.expected_actions[:3]  # Simulate 3 out of expected actions

        # Calculate response time (simulated)
        simulation.response_time_minutes = 25.0 + (hash(simulation_id) % 20)  # 25-45 minutes

        # Calculate success rate
        actions_completed = len(simulation.actions_taken) / len(simulation.expected_actions)
        criteria_met = 0.7  # Simulated
        simulation.success_rate = (actions_completed + criteria_met) / 2

        simulation.completed_at = datetime.utcnow()
        simulation.status = "completed"

        # Generate lessons learned
        simulation.strengths = [
            "Quick initial response",
            "Good communication between teams",
        ]
        simulation.weaknesses = [
            "Delayed backup verification",
            "Incomplete stakeholder notification",
        ]
        simulation.recommendations = [
            "Improve backup testing procedures",
            "Update stakeholder contact list",
            "Conduct more frequent drills",
        ]

        # Update statistics
        self.statistics['simulations_run'] += 1
        self.statistics['participants_trained'].update(simulation.participants)
        self.statistics['avg_response_time_minutes'] = (
            (self.statistics['avg_response_time_minutes'] * (self.statistics['simulations_run'] - 1) +
             simulation.response_time_minutes) / self.statistics['simulations_run']
        )
        self.statistics['avg_success_rate'] = (
            (self.statistics['avg_success_rate'] * (self.statistics['simulations_run'] - 1) +
             simulation.success_rate) / self.statistics['simulations_run']
        )

        logger.info(f"Completed simulation {simulation_id}, success rate: {simulation.success_rate:.2%}")

        return simulation

    def get_statistics(self) -> Dict[str, Any]:
        """Get simulation platform statistics."""
        return {
            'simulations_run': self.statistics['simulations_run'],
            'participants_trained': len(self.statistics['participants_trained']),
            'avg_response_time_minutes': round(self.statistics['avg_response_time_minutes'], 2),
            'avg_success_rate': round(self.statistics['avg_success_rate'], 2),
        }


# ============================================================================
# Attack Surface Management Orchestrator
# ============================================================================

class AttackSurfaceManagementOrchestrator:
    """
    Attack Surface Management Orchestrator.

    Unified orchestration layer for all attack surface management,
    security data lake, threat modeling, metrics, and simulation operations.
    """

    def __init__(self):
        """Initialize ASM orchestrator."""
        self.discovery_engine = AttackSurfaceDiscoveryEngine()
        self.data_lake = SecurityDataLake()
        self.threat_modeling = ThreatModelingEngine()
        self.metrics_dashboard = SecurityMetricsDashboard()
        self.simulation_platform = IncidentSimulationPlatform()

        logger.info("Attack Surface Management Orchestrator initialized")

    async def perform_comprehensive_assessment(
        self,
        organization_id: str,
        domains: List[str],
        system_name: str,
        system_type: str,
        components: List[str]
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security assessment.

        Includes:
        1. Attack surface discovery
        2. Threat modeling
        3. Security metrics tracking
        4. Executive dashboard generation

        Args:
            organization_id: Organization identifier
            domains: List of domains to scan
            system_name: System name for threat modeling
            system_type: System type (web_app, api, etc.)
            components: System components

        Returns:
            Comprehensive assessment results
        """
        logger.info(f"Starting comprehensive assessment for {organization_id}")

        start_time = datetime.utcnow()

        # 1. Discover attack surface
        discovered_assets = await self.discovery_engine.discover_assets(
            organization_id=organization_id,
            domains=domains,
            scan_depth="standard"
        )

        # 2. Generate attack surface report
        attack_surface_report = await self.discovery_engine.generate_attack_surface_report(organization_id)

        # 3. Create threat model
        threat_model = await self.threat_modeling.create_threat_model(
            system_name=system_name,
            system_type=system_type,
            components=components,
            data_flows=[],
            trust_boundaries=["Internet", "DMZ", "Internal Network"],
            owner="Security Team"
        )

        # 4. Track security metrics
        await self.metrics_dashboard.track_metric(
            name="Attack Surface Size",
            category="attack_surface",
            current_value=float(len(discovered_assets)),
            target_value=50.0,
            unit="count",
            is_higher_better=False
        )

        await self.metrics_dashboard.track_metric(
            name="Critical Exposures",
            category="attack_surface",
            current_value=float(attack_surface_report.critical_exposures),
            target_value=0.0,
            unit="count",
            is_higher_better=False
        )

        await self.metrics_dashboard.track_metric(
            name="Threat Model Coverage",
            category="threat_modeling",
            current_value=threat_model.mitigation_coverage * 100,
            target_value=90.0,
            unit="percentage",
            is_higher_better=True
        )

        # 5. Generate executive dashboard
        executive_dashboard = await self.metrics_dashboard.generate_executive_dashboard(organization_id)

        duration = (datetime.utcnow() - start_time).total_seconds()

        result = {
            'organization_id': organization_id,
            'assessment_date': datetime.utcnow().isoformat(),
            'duration_seconds': duration,

            # Attack Surface
            'attack_surface': {
                'total_assets': len(discovered_assets),
                'public_assets': attack_surface_report.public_assets,
                'shadow_it_assets': attack_surface_report.shadow_it_assets,
                'critical_exposures': attack_surface_report.critical_exposures,
                'overall_risk_score': attack_surface_report.overall_risk_score,
                'recommendations': attack_surface_report.recommendations,
                'quick_wins': attack_surface_report.quick_wins,
            },

            # Threat Model
            'threat_model': {
                'model_id': threat_model.model_id,
                'total_threats': threat_model.total_threats,
                'critical_threats': threat_model.critical_threats,
                'high_threats': threat_model.high_threats,
                'overall_risk_score': threat_model.overall_risk_score,
                'residual_risk_score': threat_model.residual_risk_score,
                'mitigation_coverage': threat_model.mitigation_coverage,
                'top_threats': [
                    {'title': t.title, 'category': t.category, 'risk_score': t.risk_score}
                    for t in sorted(threat_model.threats, key=lambda x: x.risk_score, reverse=True)[:5]
                ],
            },

            # Executive Dashboard
            'executive_dashboard': executive_dashboard,

            # Summary
            'summary': {
                'overall_health': self._calculate_overall_health(
                    attack_surface_report.overall_risk_score,
                    threat_model.residual_risk_score,
                    executive_dashboard['overall_health_score']
                ),
                'top_priorities': self._generate_top_priorities(
                    attack_surface_report,
                    threat_model
                ),
            },

            # Statistics
            'statistics': {
                'discovery_engine': self.discovery_engine.get_statistics(),
                'data_lake': self.data_lake.get_statistics(),
                'threat_modeling': self.threat_modeling.get_statistics(),
                'metrics_dashboard': self.metrics_dashboard.get_statistics(),
                'simulation_platform': self.simulation_platform.get_statistics(),
            }
        }

        logger.info(f"Completed comprehensive assessment in {duration:.2f}s")

        return result

    def _calculate_overall_health(
        self,
        attack_surface_risk: float,
        threat_model_risk: float,
        metrics_health: float
    ) -> str:
        """Calculate overall security health."""
        # Invert risk scores (lower risk = better health)
        attack_surface_health = (10 - attack_surface_risk) * 10
        threat_model_health = (10 - threat_model_risk) * 10

        overall = (attack_surface_health + threat_model_health + metrics_health) / 3

        if overall >= 80:
            return "EXCELLENT"
        elif overall >= 65:
            return "GOOD"
        elif overall >= 50:
            return "FAIR"
        elif overall >= 35:
            return "POOR"
        else:
            return "CRITICAL"

    def _generate_top_priorities(
        self,
        attack_surface_report: AttackSurfaceReport,
        threat_model: ThreatModel
    ) -> List[str]:
        """Generate top security priorities."""
        priorities = []

        if attack_surface_report.critical_exposures > 0:
            priorities.append(f"Address {attack_surface_report.critical_exposures} critical attack surface exposures")

        if attack_surface_report.shadow_it_assets > 0:
            priorities.append(f"Review and remediate {attack_surface_report.shadow_it_assets} shadow IT assets")

        if threat_model.critical_threats > 0:
            priorities.append(f"Mitigate {threat_model.critical_threats} critical threats in threat model")

        if threat_model.mitigation_coverage < 0.7:
            priorities.append(f"Improve threat mitigation coverage from {threat_model.mitigation_coverage:.0%} to 70%+")

        if attack_surface_report.unique_cves > 0:
            priorities.append(f"Patch {attack_surface_report.unique_cves} unique CVEs across attack surface")

        return priorities[:5]  # Top 5 priorities


# ============================================================================
# Global Accessor Functions
# ============================================================================

_asm_orchestrator: Optional[AttackSurfaceManagementOrchestrator] = None


def get_asm_orchestrator() -> AttackSurfaceManagementOrchestrator:
    """Get global ASM orchestrator instance."""
    global _asm_orchestrator
    if _asm_orchestrator is None:
        _asm_orchestrator = AttackSurfaceManagementOrchestrator()
    return _asm_orchestrator


def get_attack_surface_discovery() -> AttackSurfaceDiscoveryEngine:
    """Get attack surface discovery engine."""
    return get_asm_orchestrator().discovery_engine


def get_security_data_lake() -> SecurityDataLake:
    """Get security data lake."""
    return get_asm_orchestrator().data_lake


def get_threat_modeling_engine() -> ThreatModelingEngine:
    """Get threat modeling engine."""
    return get_asm_orchestrator().threat_modeling


def get_security_metrics_dashboard() -> SecurityMetricsDashboard:
    """Get security metrics dashboard."""
    return get_asm_orchestrator().metrics_dashboard


def get_incident_simulation_platform() -> IncidentSimulationPlatform:
    """Get incident simulation platform."""
    return get_asm_orchestrator().simulation_platform
