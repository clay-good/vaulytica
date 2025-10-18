import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json

from vaulytica.logger import get_logger

logger = get_logger(__name__)


class CloudProvider(str, Enum):
    """Supported cloud providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


class ResourceType(str, Enum):
    """Cloud resource types."""
    # Compute
    VM_INSTANCE = "vm_instance"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    
    # Storage
    STORAGE_BUCKET = "storage_bucket"
    DATABASE = "database"
    VOLUME = "volume"
    
    # Network
    VPC = "vpc"
    SUBNET = "subnet"
    SECURITY_GROUP = "security_group"
    LOAD_BALANCER = "load_balancer"
    
    # Identity
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_POLICY = "iam_policy"
    
    # Other
    KMS_KEY = "kms_key"
    SECRET = "secret"
    LOG_GROUP = "log_group"


class ComplianceFramework(str, Enum):
    """Compliance frameworks."""
    CIS_AWS = "cis_aws"
    CIS_AZURE = "cis_azure"
    CIS_GCP = "cis_gcp"
    CIS_KUBERNETES = "cis_kubernetes"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Finding status."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"


@dataclass
class CloudResource:
    """Cloud resource representation."""
    resource_id: str
    resource_type: ResourceType
    provider: CloudProvider
    region: str
    name: str
    tags: Dict[str, str] = field(default_factory=dict)
    configuration: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_config_hash(self) -> str:
        """Get hash of resource configuration."""
        config_str = json.dumps(self.configuration, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()


@dataclass
class ComplianceCheck:
    """Compliance check definition."""
    check_id: str
    framework: ComplianceFramework
    title: str
    description: str
    severity: Severity
    resource_types: List[ResourceType]
    check_function: str  # Name of function to execute
    remediation: str
    references: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """Security finding."""
    finding_id: str
    resource: CloudResource
    check: ComplianceCheck
    status: FindingStatus
    severity: Severity
    title: str
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    suppressed_reason: Optional[str] = None


@dataclass
class Vulnerability:
    """Vulnerability information."""
    cve_id: str
    title: str
    description: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    affected_resources: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False


@dataclass
class ConfigurationBaseline:
    """Configuration baseline for drift detection."""
    baseline_id: str
    resource_type: ResourceType
    provider: CloudProvider
    configuration: Dict[str, Any]
    config_hash: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    approved_by: Optional[str] = None


@dataclass
class DriftDetection:
    """Configuration drift detection result."""
    resource: CloudResource
    baseline: ConfigurationBaseline
    drifted: bool
    drift_details: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)


class CloudResourceScanner:
    """
    Multi-cloud resource scanner.
    
    Scans cloud resources across AWS, Azure, GCP, and Kubernetes.
    """
    
    def __init__(self):
        """Initialize cloud resource scanner."""
        self.resources: Dict[str, CloudResource] = {}
        self.scan_history: List[Dict[str, Any]] = []
        
        self.statistics = {
            "total_scans": 0,
            "resources_discovered": 0,
            "resources_by_provider": {p.value: 0 for p in CloudProvider},
            "resources_by_type": {t.value: 0 for t in ResourceType},
            "last_scan": None
        }
        
        logger.info("Cloud Resource Scanner initialized")
    
    async def scan_aws_resources(
        self,
        region: str = "us-east-1",
        resource_types: Optional[List[ResourceType]] = None
    ) -> List[CloudResource]:
        """
        Scan AWS resources.
        
        Args:
            region: AWS region to scan
            resource_types: Specific resource types to scan
        
        Returns:
            List of discovered resources
        """
        logger.info(f"Scanning AWS resources in {region}")
        
        resources = []
        
        # Mock AWS resource discovery
        # In production, use boto3 to scan actual AWS resources
        mock_resources = [
            CloudResource(
                resource_id="i-1234567890abcdef0",
                resource_type=ResourceType.VM_INSTANCE,
                provider=CloudProvider.AWS,
                region=region,
                name="web-server-01",
                tags={"Environment": "production", "Application": "web"},
                configuration={
                    "instance_type": "t3.medium",
                    "public_ip": "54.123.45.67",
                    "security_groups": ["sg-12345678"],
                    "iam_role": "web-server-role",
                    "monitoring_enabled": False,
                    "encrypted": False
                }
            ),
            CloudResource(
                resource_id="sg-12345678",
                resource_type=ResourceType.SECURITY_GROUP,
                provider=CloudProvider.AWS,
                region=region,
                name="web-sg",
                configuration={
                    "ingress_rules": [
                        {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "port": 80, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"}
                    ],
                    "egress_rules": [
                        {"protocol": "-1", "port": -1, "cidr": "0.0.0.0/0"}
                    ]
                }
            ),
            CloudResource(
                resource_id="bucket-prod-data-12345",
                resource_type=ResourceType.STORAGE_BUCKET,
                provider=CloudProvider.AWS,
                region=region,
                name="prod-data-bucket",
                configuration={
                    "public_access_block": False,
                    "versioning_enabled": False,
                    "encryption": None,
                    "logging_enabled": False,
                    "acl": "public-read"
                }
            )
        ]
        
        for resource in mock_resources:
            if resource_types is None or resource.resource_type in resource_types:
                resources.append(resource)
                self.resources[resource.resource_id] = resource
                self.statistics["resources_by_provider"][CloudProvider.AWS.value] += 1
                self.statistics["resources_by_type"][resource.resource_type.value] += 1
        
        self.statistics["resources_discovered"] += len(resources)
        logger.info(f"Discovered {len(resources)} AWS resources")
        
        return resources
    
    async def scan_azure_resources(
        self,
        subscription_id: str,
        resource_types: Optional[List[ResourceType]] = None
    ) -> List[CloudResource]:
        """Scan Azure resources."""
        logger.info(f"Scanning Azure resources in subscription {subscription_id}")
        
        # Mock Azure scanning
        resources = []
        self.statistics["resources_discovered"] += len(resources)
        
        return resources
    
    async def scan_gcp_resources(
        self,
        project_id: str,
        resource_types: Optional[List[ResourceType]] = None
    ) -> List[CloudResource]:
        """Scan GCP resources."""
        logger.info(f"Scanning GCP resources in project {project_id}")
        
        # Mock GCP scanning
        resources = []
        self.statistics["resources_discovered"] += len(resources)
        
        return resources
    
    async def scan_all_providers(self) -> Dict[CloudProvider, List[CloudResource]]:
        """Scan all cloud providers."""
        results = {}
        
        # Scan AWS
        aws_resources = await self.scan_aws_resources()
        results[CloudProvider.AWS] = aws_resources
        
        self.statistics["total_scans"] += 1
        self.statistics["last_scan"] = datetime.utcnow().isoformat()
        
        return results
    
    def get_resource(self, resource_id: str) -> Optional[CloudResource]:
        """Get resource by ID."""
        return self.resources.get(resource_id)
    
    def get_resources_by_type(self, resource_type: ResourceType) -> List[CloudResource]:
        """Get all resources of a specific type."""
        return [r for r in self.resources.values() if r.resource_type == resource_type]
    
    def get_resources_by_provider(self, provider: CloudProvider) -> List[CloudResource]:
        """Get all resources from a specific provider."""
        return [r for r in self.resources.values() if r.provider == provider]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return self.statistics


# Global instance
_cloud_scanner: Optional[CloudResourceScanner] = None


def get_cloud_scanner() -> CloudResourceScanner:
    """Get or create global cloud scanner instance."""
    global _cloud_scanner

    if _cloud_scanner is None:
        _cloud_scanner = CloudResourceScanner()

    return _cloud_scanner


class ComplianceEngine:
    """
    Compliance checking engine.

    Performs automated compliance checks against multiple frameworks.
    """

    def __init__(self):
        """Initialize compliance engine."""
        self.checks: Dict[str, ComplianceCheck] = {}
        self.findings: Dict[str, Finding] = {}

        self.statistics = {
            "total_checks_run": 0,
            "findings_by_severity": {s.value: 0 for s in Severity},
            "findings_by_framework": {f.value: 0 for f in ComplianceFramework},
            "compliance_scores": {},
            "last_assessment": None
        }

        # Initialize compliance checks
        self._initialize_checks()

        logger.info(f"Compliance Engine initialized with {len(self.checks)} checks")

    def _initialize_checks(self):
        """Initialize compliance checks."""
        # CIS AWS Checks
        self.checks["cis-aws-2.1"] = ComplianceCheck(
            check_id="cis-aws-2.1",
            framework=ComplianceFramework.CIS_AWS,
            title="Ensure CloudTrail is enabled in all regions",
            description="AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you.",
            severity=Severity.HIGH,
            resource_types=[ResourceType.LOG_GROUP],
            check_function="check_cloudtrail_enabled",
            remediation="Enable CloudTrail in all regions with multi-region trail",
            references=["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"]
        )

        self.checks["cis-aws-2.3"] = ComplianceCheck(
            check_id="cis-aws-2.3",
            framework=ComplianceFramework.CIS_AWS,
            title="Ensure S3 bucket access logging is enabled",
            description="S3 Bucket Access Logging generates a log that contains access records for each request made to your S3 bucket.",
            severity=Severity.MEDIUM,
            resource_types=[ResourceType.STORAGE_BUCKET],
            check_function="check_s3_logging",
            remediation="Enable access logging on all S3 buckets",
            references=["https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html"]
        )

        self.checks["cis-aws-2.7"] = ComplianceCheck(
            check_id="cis-aws-2.7",
            framework=ComplianceFramework.CIS_AWS,
            title="Ensure S3 buckets are encrypted at rest",
            description="Amazon S3 default encryption provides a way to set the default encryption behavior for an S3 bucket.",
            severity=Severity.HIGH,
            resource_types=[ResourceType.STORAGE_BUCKET],
            check_function="check_s3_encryption",
            remediation="Enable default encryption on all S3 buckets",
            references=["https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html"]
        )

        self.checks["cis-aws-4.1"] = ComplianceCheck(
            check_id="cis-aws-4.1",
            framework=ComplianceFramework.CIS_AWS,
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
            description="Security groups provide stateful filtering of ingress/egress network traffic to AWS resources.",
            severity=Severity.CRITICAL,
            resource_types=[ResourceType.SECURITY_GROUP],
            check_function="check_sg_ssh_open",
            remediation="Restrict SSH access to specific IP ranges",
            references=["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"]
        )

        self.checks["cis-aws-4.2"] = ComplianceCheck(
            check_id="cis-aws-4.2",
            framework=ComplianceFramework.CIS_AWS,
            title="Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
            description="Security groups should not allow unrestricted RDP access from the internet.",
            severity=Severity.CRITICAL,
            resource_types=[ResourceType.SECURITY_GROUP],
            check_function="check_sg_rdp_open",
            remediation="Restrict RDP access to specific IP ranges",
            references=["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"]
        )

        # PCI-DSS Checks
        self.checks["pci-dss-2.2"] = ComplianceCheck(
            check_id="pci-dss-2.2",
            framework=ComplianceFramework.PCI_DSS,
            title="Ensure encryption is enabled for data at rest",
            description="All cardholder data must be encrypted at rest.",
            severity=Severity.CRITICAL,
            resource_types=[ResourceType.STORAGE_BUCKET, ResourceType.DATABASE, ResourceType.VOLUME],
            check_function="check_encryption_at_rest",
            remediation="Enable encryption for all data storage resources",
            references=["https://www.pcisecuritystandards.org/"]
        )

        # HIPAA Checks
        self.checks["hipaa-164.312"] = ComplianceCheck(
            check_id="hipaa-164.312",
            framework=ComplianceFramework.HIPAA,
            title="Ensure encryption and decryption of ePHI",
            description="Implement a mechanism to encrypt and decrypt electronic protected health information.",
            severity=Severity.CRITICAL,
            resource_types=[ResourceType.STORAGE_BUCKET, ResourceType.DATABASE],
            check_function="check_encryption_at_rest",
            remediation="Enable encryption for all resources containing ePHI",
            references=["https://www.hhs.gov/hipaa/"]
        )

    async def run_check(self, check: ComplianceCheck, resource: CloudResource) -> Optional[Finding]:
        """
        Run a compliance check on a resource.

        Args:
            check: Compliance check to run
            resource: Resource to check

        Returns:
            Finding if check fails, None if passes
        """
        # Execute check function
        check_result = await self._execute_check(check.check_function, resource)

        self.statistics["total_checks_run"] += 1

        if not check_result["passed"]:
            # Create finding
            finding = Finding(
                finding_id=f"{check.check_id}-{resource.resource_id}",
                resource=resource,
                check=check,
                status=FindingStatus.OPEN,
                severity=check.severity,
                title=check.title,
                description=check.description,
                remediation=check.remediation,
                evidence=check_result.get("evidence", {}),
                risk_score=self._calculate_risk_score(check.severity, resource)
            )

            self.findings[finding.finding_id] = finding
            self.statistics["findings_by_severity"][check.severity.value] += 1
            self.statistics["findings_by_framework"][check.framework.value] += 1

            logger.warning(f"Finding: {finding.title} on {resource.resource_id}")
            return finding

        return None

    async def _execute_check(self, check_function: str, resource: CloudResource) -> Dict[str, Any]:
        """Execute a check function."""
        # Map check functions to implementations
        check_functions = {
            "check_s3_logging": self._check_s3_logging,
            "check_s3_encryption": self._check_s3_encryption,
            "check_sg_ssh_open": self._check_sg_ssh_open,
            "check_sg_rdp_open": self._check_sg_rdp_open,
            "check_encryption_at_rest": self._check_encryption_at_rest,
            "check_cloudtrail_enabled": self._check_cloudtrail_enabled
        }

        func = check_functions.get(check_function)
        if func:
            return await func(resource)

        return {"passed": True}

    async def _check_s3_logging(self, resource: CloudResource) -> Dict[str, Any]:
        """Check if S3 bucket has logging enabled."""
        if resource.resource_type != ResourceType.STORAGE_BUCKET:
            return {"passed": True}

        logging_enabled = resource.configuration.get("logging_enabled", False)

        return {
            "passed": logging_enabled,
            "evidence": {
                "logging_enabled": logging_enabled,
                "bucket_name": resource.name
            }
        }

    async def _check_s3_encryption(self, resource: CloudResource) -> Dict[str, Any]:
        """Check if S3 bucket has encryption enabled."""
        if resource.resource_type != ResourceType.STORAGE_BUCKET:
            return {"passed": True}

        encryption = resource.configuration.get("encryption")

        return {
            "passed": encryption is not None,
            "evidence": {
                "encryption": encryption,
                "bucket_name": resource.name
            }
        }

    async def _check_sg_ssh_open(self, resource: CloudResource) -> Dict[str, Any]:
        """Check if security group allows SSH from 0.0.0.0/0."""
        if resource.resource_type != ResourceType.SECURITY_GROUP:
            return {"passed": True}

        ingress_rules = resource.configuration.get("ingress_rules", [])

        for rule in ingress_rules:
            if rule.get("port") == 22 and rule.get("cidr") == "0.0.0.0/0":
                return {
                    "passed": False,
                    "evidence": {
                        "rule": rule,
                        "security_group": resource.name
                    }
                }

        return {"passed": True}

    async def _check_sg_rdp_open(self, resource: CloudResource) -> Dict[str, Any]:
        """Check if security group allows RDP from 0.0.0.0/0."""
        if resource.resource_type != ResourceType.SECURITY_GROUP:
            return {"passed": True}

        ingress_rules = resource.configuration.get("ingress_rules", [])

        for rule in ingress_rules:
            if rule.get("port") == 3389 and rule.get("cidr") == "0.0.0.0/0":
                return {
                    "passed": False,
                    "evidence": {
                        "rule": rule,
                        "security_group": resource.name
                    }
                }

        return {"passed": True}

    async def _check_encryption_at_rest(self, resource: CloudResource) -> Dict[str, Any]:
        """Check if resource has encryption at rest enabled."""
        if resource.resource_type not in [ResourceType.STORAGE_BUCKET, ResourceType.DATABASE, ResourceType.VOLUME]:
            return {"passed": True}

        encrypted = resource.configuration.get("encrypted", False) or resource.configuration.get("encryption") is not None

        return {
            "passed": encrypted,
            "evidence": {
                "encrypted": encrypted,
                "resource_name": resource.name
            }
        }

    async def _check_cloudtrail_enabled(self, resource: CloudResource) -> Dict[str, Any]:
        """Check if CloudTrail is enabled."""
        # This would check actual CloudTrail configuration
        return {"passed": True}

    def _calculate_risk_score(self, severity: Severity, resource: CloudResource) -> float:
        """Calculate risk score for a finding."""
        base_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 1.0
        }

        score = base_scores.get(severity, 5.0)

        # Adjust based on resource exposure
        if resource.configuration.get("public_access_block") == False:
            score *= 1.5

        if resource.tags.get("Environment") == "production":
            score *= 1.3

        return min(score, 10.0)

    async def assess_compliance(
        self,
        resources: List[CloudResource],
        frameworks: Optional[List[ComplianceFramework]] = None
    ) -> Dict[str, Any]:
        """
        Assess compliance for resources.

        Args:
            resources: Resources to assess
            frameworks: Specific frameworks to check (default: all)

        Returns:
            Assessment results with findings and scores
        """
        logger.info(f"Assessing compliance for {len(resources)} resources")

        findings = []

        for resource in resources:
            # Find applicable checks
            applicable_checks = [
                check for check in self.checks.values()
                if resource.resource_type in check.resource_types
                and (frameworks is None or check.framework in frameworks)
            ]

            # Run checks
            for check in applicable_checks:
                finding = await self.run_check(check, resource)
                if finding:
                    findings.append(finding)

        # Calculate compliance scores
        compliance_scores = self._calculate_compliance_scores(findings, frameworks)

        self.statistics["compliance_scores"] = compliance_scores
        self.statistics["last_assessment"] = datetime.utcnow().isoformat()

        logger.info(f"Assessment complete: {len(findings)} findings")

        return {
            "findings": findings,
            "compliance_scores": compliance_scores,
            "total_checks": self.statistics["total_checks_run"],
            "resources_assessed": len(resources)
        }

    def _calculate_compliance_scores(
        self,
        findings: List[Finding],
        frameworks: Optional[List[ComplianceFramework]]
    ) -> Dict[str, float]:
        """Calculate compliance scores by framework."""
        scores = {}

        frameworks_to_score = frameworks or list(ComplianceFramework)

        for framework in frameworks_to_score:
            framework_checks = [c for c in self.checks.values() if c.framework == framework]
            framework_findings = [f for f in findings if f.check.framework == framework]

            if framework_checks:
                passed = len(framework_checks) - len(framework_findings)
                score = (passed / len(framework_checks)) * 100
                scores[framework.value] = round(score, 2)

        return scores

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID."""
        return self.findings.get(finding_id)

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings by severity."""
        return [f for f in self.findings.values() if f.severity == severity]

    def get_findings_by_resource(self, resource_id: str) -> List[Finding]:
        """Get findings for a specific resource."""
        return [f for f in self.findings.values() if f.resource.resource_id == resource_id]

    def get_statistics(self) -> Dict[str, Any]:
        """Get compliance engine statistics."""
        return self.statistics


# Global instance
_compliance_engine: Optional[ComplianceEngine] = None


def get_compliance_engine() -> ComplianceEngine:
    """Get or create global compliance engine instance."""
    global _compliance_engine

    if _compliance_engine is None:
        _compliance_engine = ComplianceEngine()

    return _compliance_engine


class DriftDetectionEngine:
    """
    Configuration drift detection engine.

    Detects configuration drift from approved baselines.
    """

    def __init__(self):
        """Initialize drift detection engine."""
        self.baselines: Dict[str, ConfigurationBaseline] = {}
        self.drift_detections: List[DriftDetection] = []

        self.statistics = {
            "total_baselines": 0,
            "total_drift_checks": 0,
            "resources_drifted": 0,
            "drift_by_type": {t.value: 0 for t in ResourceType},
            "last_check": None
        }

        logger.info("Drift Detection Engine initialized")

    def create_baseline(
        self,
        resource: CloudResource,
        approved_by: Optional[str] = None
    ) -> ConfigurationBaseline:
        """
        Create configuration baseline for a resource.

        Args:
            resource: Resource to baseline
            approved_by: User who approved the baseline

        Returns:
            Configuration baseline
        """
        baseline_id = f"baseline-{resource.resource_id}"
        config_hash = resource.get_config_hash()

        baseline = ConfigurationBaseline(
            baseline_id=baseline_id,
            resource_type=resource.resource_type,
            provider=resource.provider,
            configuration=resource.configuration.copy(),
            config_hash=config_hash,
            approved_by=approved_by
        )

        self.baselines[baseline_id] = baseline
        self.statistics["total_baselines"] += 1

        logger.info(f"Created baseline {baseline_id} for {resource.resource_id}")

        return baseline

    async def check_drift(self, resource: CloudResource) -> DriftDetection:
        """
        Check if resource has drifted from baseline.

        Args:
            resource: Resource to check

        Returns:
            Drift detection result
        """
        baseline_id = f"baseline-{resource.resource_id}"
        baseline = self.baselines.get(baseline_id)

        if not baseline:
            logger.warning(f"No baseline found for {resource.resource_id}")
            # Create baseline if it doesn't exist
            baseline = self.create_baseline(resource)

            return DriftDetection(
                resource=resource,
                baseline=baseline,
                drifted=False,
                drift_details={"message": "Baseline created"}
            )

        # Check for drift
        current_hash = resource.get_config_hash()
        drifted = current_hash != baseline.config_hash

        drift_details = {}
        if drifted:
            drift_details = self._analyze_drift(baseline.configuration, resource.configuration)

        detection = DriftDetection(
            resource=resource,
            baseline=baseline,
            drifted=drifted,
            drift_details=drift_details
        )

        self.drift_detections.append(detection)
        self.statistics["total_drift_checks"] += 1

        if drifted:
            self.statistics["resources_drifted"] += 1
            self.statistics["drift_by_type"][resource.resource_type.value] += 1
            logger.warning(f"Drift detected for {resource.resource_id}")

        self.statistics["last_check"] = datetime.utcnow().isoformat()

        return detection

    def _analyze_drift(
        self,
        baseline_config: Dict[str, Any],
        current_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze configuration drift details."""
        drift_details = {
            "added": {},
            "removed": {},
            "changed": {}
        }

        # Find added keys
        for key in current_config:
            if key not in baseline_config:
                drift_details["added"][key] = current_config[key]

        # Find removed keys
        for key in baseline_config:
            if key not in current_config:
                drift_details["removed"][key] = baseline_config[key]

        # Find changed values
        for key in baseline_config:
            if key in current_config and baseline_config[key] != current_config[key]:
                drift_details["changed"][key] = {
                    "baseline": baseline_config[key],
                    "current": current_config[key]
                }

        return drift_details

    async def check_all_resources(self, resources: List[CloudResource]) -> List[DriftDetection]:
        """Check drift for all resources."""
        logger.info(f"Checking drift for {len(resources)} resources")

        detections = []
        for resource in resources:
            detection = await self.check_drift(resource)
            detections.append(detection)

        drifted_count = sum(1 for d in detections if d.drifted)
        logger.info(f"Drift check complete: {drifted_count}/{len(resources)} resources drifted")

        return detections

    def get_drifted_resources(self) -> List[DriftDetection]:
        """Get all resources that have drifted."""
        return [d for d in self.drift_detections if d.drifted]

    def get_baseline(self, baseline_id: str) -> Optional[ConfigurationBaseline]:
        """Get baseline by ID."""
        return self.baselines.get(baseline_id)

    def update_baseline(self, resource: CloudResource, approved_by: str) -> ConfigurationBaseline:
        """Update baseline to current configuration."""
        baseline_id = f"baseline-{resource.resource_id}"

        # Create new baseline
        baseline = self.create_baseline(resource, approved_by)

        logger.info(f"Updated baseline {baseline_id}")

        return baseline

    def get_statistics(self) -> Dict[str, Any]:
        """Get drift detection statistics."""
        return self.statistics


# Global instance
_drift_engine: Optional[DriftDetectionEngine] = None


def get_drift_engine() -> DriftDetectionEngine:
    """Get or create global drift detection engine instance."""
    global _drift_engine

    if _drift_engine is None:
        _drift_engine = DriftDetectionEngine()

    return _drift_engine


class CSPMOrchestrator:
    """
    CSPM Orchestrator.

    Coordinates all CSPM operations: scanning, compliance, vulnerabilities, drift, remediation.
    """

    def __init__(self):
        """Initialize CSPM orchestrator."""
        self.scanner = get_cloud_scanner()
        self.compliance_engine = get_compliance_engine()
        self.drift_engine = get_drift_engine()

        logger.info("CSPM Orchestrator initialized")

    async def run_full_assessment(
        self,
        provider: CloudProvider = CloudProvider.AWS,
        frameworks: Optional[List[ComplianceFramework]] = None
    ) -> Dict[str, Any]:
        """
        Run full CSPM assessment.

        Args:
            provider: Cloud provider to assess
            frameworks: Compliance frameworks to check

        Returns:
            Complete assessment results
        """
        logger.info(f"Running full CSPM assessment for {provider.value}")

        # 1. Scan resources
        scan_results = await self.scanner.scan_all_providers()
        resources = scan_results.get(provider, [])

        logger.info(f"Scanned {len(resources)} resources")

        # 2. Run compliance checks
        compliance_results = await self.compliance_engine.assess_compliance(resources, frameworks)

        # 3. Check drift
        drift_results = await self.drift_engine.check_all_resources(resources)

        # 4. Compile results
        results = {
            "provider": provider.value,
            "timestamp": datetime.utcnow().isoformat(),
            "resources_scanned": len(resources),
            "compliance": {
                "findings": len(compliance_results["findings"]),
                "scores": compliance_results["compliance_scores"],
                "findings_by_severity": {
                    severity.value: len([f for f in compliance_results["findings"] if f.severity == severity])
                    for severity in Severity
                }
            },
            "drift": {
                "total_checks": len(drift_results),
                "drifted_resources": sum(1 for d in drift_results if d.drifted),
                "drift_rate": (sum(1 for d in drift_results if d.drifted) / len(drift_results) * 100) if drift_results else 0
            },
            "summary": {
                "critical_findings": len([f for f in compliance_results["findings"] if f.severity == Severity.CRITICAL]),
                "high_findings": len([f for f in compliance_results["findings"] if f.severity == Severity.HIGH]),
                "overall_score": sum(compliance_results["compliance_scores"].values()) / len(compliance_results["compliance_scores"]) if compliance_results["compliance_scores"] else 0
            }
        }

        logger.info(f"Assessment complete: {results['compliance']['findings']} findings, {results['drift']['drifted_resources']} drifted resources")

        return results

    def get_unified_statistics(self) -> Dict[str, Any]:
        """Get unified statistics from all engines."""
        return {
            "scanner": self.scanner.get_statistics(),
            "compliance": self.compliance_engine.get_statistics(),
            "drift": self.drift_engine.get_statistics()
        }


# Global instance
_cspm_orchestrator: Optional[CSPMOrchestrator] = None


def get_cspm_orchestrator() -> CSPMOrchestrator:
    """Get or create global CSPM orchestrator instance."""
    global _cspm_orchestrator

    if _cspm_orchestrator is None:
        _cspm_orchestrator = CSPMOrchestrator()

    return _cspm_orchestrator

