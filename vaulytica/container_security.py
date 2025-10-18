import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.cspm import Severity
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class ImageScanStatus(str, Enum):
    """Container image scan status."""
    PENDING = "pending"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class PackageManager(str, Enum):
    """Package managers for dependency scanning."""
    APK = "apk"  # Alpine
    APT = "apt"  # Debian/Ubuntu
    YUM = "yum"  # RHEL/CentOS
    DNF = "dnf"  # Fedora
    NPM = "npm"  # Node.js
    PIP = "pip"  # Python
    GEM = "gem"  # Ruby
    MAVEN = "maven"  # Java
    GO_MOD = "go_mod"  # Go


class K8sResourceType(str, Enum):
    """Kubernetes resource types."""
    POD = "pod"
    DEPLOYMENT = "deployment"
    STATEFULSET = "statefulset"
    DAEMONSET = "daemonset"
    SERVICE = "service"
    INGRESS = "ingress"
    CONFIGMAP = "configmap"
    SECRET = "secret"
    SERVICE_ACCOUNT = "service_account"
    ROLE = "role"
    CLUSTER_ROLE = "cluster_role"
    ROLE_BINDING = "role_binding"
    CLUSTER_ROLE_BINDING = "cluster_role_binding"
    NETWORK_POLICY = "network_policy"
    POD_SECURITY_POLICY = "pod_security_policy"
    NAMESPACE = "namespace"


class PodSecurityStandard(str, Enum):
    """Pod Security Standards levels."""
    PRIVILEGED = "privileged"  # Unrestricted
    BASELINE = "baseline"  # Minimally restrictive
    RESTRICTED = "restricted"  # Heavily restricted


@dataclass
class ContainerImage:
    """Container image information."""
    image_id: str
    repository: str
    tag: str
    digest: str
    size_bytes: int
    created_at: datetime
    layers: List[str] = field(default_factory=list)
    os: str = "linux"
    architecture: str = "amd64"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImageLayer:
    """Container image layer."""
    layer_id: str
    command: str
    size_bytes: int
    created_at: datetime
    packages: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class Package:
    """Software package in container."""
    name: str
    version: str
    package_manager: PackageManager
    source: str = ""
    license: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class ImageVulnerability:
    """Vulnerability found in container image."""
    cve_id: str
    package_name: str
    package_version: str
    fixed_version: Optional[str]
    severity: Severity
    cvss_score: float
    description: str
    layer_id: str
    exploit_available: bool = False
    fix_available: bool = False


@dataclass
class ImageScanResult:
    """Container image scan result."""
    scan_id: str
    image: ContainerImage
    status: ImageScanStatus
    vulnerabilities: List[ImageVulnerability] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)
    layers: List[ImageLayer] = field(default_factory=list)
    risk_score: float = 0.0
    scanned_at: datetime = field(default_factory=datetime.utcnow)
    scan_duration_ms: int = 0
    
    def get_vulnerability_count_by_severity(self) -> Dict[str, int]:
        """Get vulnerability counts by severity."""
        counts = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts


@dataclass
class K8sResource:
    """Kubernetes resource."""
    resource_id: str
    resource_type: K8sResourceType
    name: str
    namespace: str
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    spec: Dict[str, Any] = field(default_factory=dict)
    status: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None


@dataclass
class PodSecurityContext:
    """Pod security context analysis."""
    pod_name: str
    namespace: str
    runs_as_root: bool
    privileged: bool
    host_network: bool
    host_pid: bool
    host_ipc: bool
    capabilities_added: List[str] = field(default_factory=list)
    capabilities_dropped: List[str] = field(default_factory=list)
    read_only_root_filesystem: bool = False
    allow_privilege_escalation: bool = True
    security_standard: PodSecurityStandard = PodSecurityStandard.PRIVILEGED


@dataclass
class K8sSecurityFinding:
    """Kubernetes security finding."""
    finding_id: str
    resource: K8sResource
    severity: Severity
    title: str
    description: str
    remediation: str
    category: str  # rbac, network, pod_security, secrets, etc.
    cis_benchmark: Optional[str] = None
    risk_score: float = 0.0
    discovered_at: datetime = field(default_factory=datetime.utcnow)


class ContainerImageScanner:
    """
    Container image vulnerability scanner.
    
    Scans container images for vulnerabilities, packages, and misconfigurations.
    """
    
    def __init__(self):
        """Initialize container image scanner."""
        self.scan_results: Dict[str, ImageScanResult] = {}
        
        self.statistics = {
            "total_scans": 0,
            "images_scanned": 0,
            "vulnerabilities_found": 0,
            "vulnerabilities_by_severity": {s.value: 0 for s in Severity},
            "packages_scanned": 0,
            "last_scan": None
        }
        
        # Sample vulnerability database
        self._initialize_vulnerability_db()
        
        logger.info("Container Image Scanner initialized")
    
    def _initialize_vulnerability_db(self):
        """Initialize sample vulnerability database."""
        # Sample vulnerabilities for common packages
        self.vulnerability_db = {
            "openssl": [
                {
                    "cve_id": "CVE-2023-0286",
                    "affected_versions": ["< 3.0.8"],
                    "fixed_version": "3.0.8",
                    "severity": Severity.HIGH,
                    "cvss_score": 7.4,
                    "description": "X.400 address type confusion in X.509 GeneralName"
                }
            ],
            "curl": [
                {
                    "cve_id": "CVE-2023-27533",
                    "affected_versions": ["< 7.88.1"],
                    "fixed_version": "7.88.1",
                    "severity": Severity.MEDIUM,
                    "cvss_score": 5.9,
                    "description": "TELNET option IAC injection"
                }
            ],
            "nginx": [
                {
                    "cve_id": "CVE-2023-44487",
                    "affected_versions": ["< 1.25.2"],
                    "fixed_version": "1.25.2",
                    "severity": Severity.HIGH,
                    "cvss_score": 7.5,
                    "description": "HTTP/2 Rapid Reset Attack"
                }
            ],
            "python": [
                {
                    "cve_id": "CVE-2023-40217",
                    "affected_versions": ["< 3.11.5"],
                    "fixed_version": "3.11.5",
                    "severity": Severity.MEDIUM,
                    "cvss_score": 5.3,
                    "description": "TLS handshake bypass"
                }
            ]
        }
    
    async def scan_image(
        self,
        image_ref: str,
        registry: Optional[str] = None
    ) -> ImageScanResult:
        """
        Scan container image for vulnerabilities.
        
        Args:
            image_ref: Image reference (e.g., "nginx:1.21")
            registry: Container registry URL
        
        Returns:
            Image scan result
        """
        logger.info(f"Scanning container image: {image_ref}")
        
        start_time = datetime.utcnow()
        
        # Parse image reference
        parts = image_ref.split(":")
        repository = parts[0]
        tag = parts[1] if len(parts) > 1 else "latest"
        
        # Create mock image
        image = ContainerImage(
            image_id=hashlib.sha256(image_ref.encode()).hexdigest()[:12],
            repository=repository,
            tag=tag,
            digest=f"sha256:{hashlib.sha256(image_ref.encode()).hexdigest()}",
            size_bytes=150_000_000,  # 150 MB
            created_at=datetime.utcnow() - timedelta(days=30),
            layers=[f"layer-{i}" for i in range(5)],
            os="linux",
            architecture="amd64"
        )
        
        # Scan layers
        layers = await self._scan_layers(image)
        
        # Scan packages
        packages = await self._scan_packages(image)
        
        # Find vulnerabilities
        vulnerabilities = await self._find_vulnerabilities(packages, layers)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Create scan result
        scan_duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        
        scan_result = ImageScanResult(
            scan_id=f"scan-{image.image_id}-{int(datetime.utcnow().timestamp())}",
            image=image,
            status=ImageScanStatus.COMPLETED,
            vulnerabilities=vulnerabilities,
            packages=packages,
            layers=layers,
            risk_score=risk_score,
            scan_duration_ms=scan_duration
        )
        
        self.scan_results[scan_result.scan_id] = scan_result
        
        # Update statistics
        self.statistics["total_scans"] += 1
        self.statistics["images_scanned"] += 1
        self.statistics["vulnerabilities_found"] += len(vulnerabilities)
        self.statistics["packages_scanned"] += len(packages)
        for vuln in vulnerabilities:
            self.statistics["vulnerabilities_by_severity"][vuln.severity.value] += 1
        self.statistics["last_scan"] = datetime.utcnow().isoformat()
        
        logger.info(f"Scan complete: {len(vulnerabilities)} vulnerabilities found in {scan_duration}ms")
        
        return scan_result
    
    async def _scan_layers(self, image: ContainerImage) -> List[ImageLayer]:
        """Scan image layers."""
        layers = []
        
        for i, layer_id in enumerate(image.layers):
            layer = ImageLayer(
                layer_id=layer_id,
                command=f"RUN apt-get install package-{i}",
                size_bytes=30_000_000,
                created_at=image.created_at + timedelta(minutes=i)
            )
            layers.append(layer)
        
        return layers
    
    async def _scan_packages(self, image: ContainerImage) -> List[Package]:
        """Scan packages in image."""
        # Mock packages based on image name
        packages = []
        
        if "nginx" in image.repository.lower():
            packages.extend([
                Package("nginx", "1.21.0", PackageManager.APT, license="BSD-2-Clause"),
                Package("openssl", "1.1.1k", PackageManager.APT, license="Apache-2.0"),
                Package("curl", "7.74.0", PackageManager.APT, license="MIT")
            ])
        elif "python" in image.repository.lower():
            packages.extend([
                Package("python", "3.9.5", PackageManager.APT, license="PSF"),
                Package("pip", "21.1.1", PackageManager.PIP, license="MIT"),
                Package("requests", "2.25.1", PackageManager.PIP, license="Apache-2.0")
            ])
        else:
            # Generic packages
            packages.extend([
                Package("openssl", "1.1.1k", PackageManager.APT, license="Apache-2.0"),
                Package("curl", "7.74.0", PackageManager.APT, license="MIT")
            ])
        
        return packages
    
    async def _find_vulnerabilities(
        self,
        packages: List[Package],
        layers: List[ImageLayer]
    ) -> List[ImageVulnerability]:
        """Find vulnerabilities in packages."""
        vulnerabilities = []
        
        for package in packages:
            if package.name in self.vulnerability_db:
                for vuln_data in self.vulnerability_db[package.name]:
                    # Simple version check (in production, use proper version comparison)
                    vulnerabilities.append(ImageVulnerability(
                        cve_id=vuln_data["cve_id"],
                        package_name=package.name,
                        package_version=package.version,
                        fixed_version=vuln_data["fixed_version"],
                        severity=vuln_data["severity"],
                        cvss_score=vuln_data["cvss_score"],
                        description=vuln_data["description"],
                        layer_id=layers[0].layer_id if layers else "unknown",
                        fix_available=True
                    ))
        
        return vulnerabilities
    
    def _calculate_risk_score(self, vulnerabilities: List[ImageVulnerability]) -> float:
        """Calculate overall risk score for image."""
        if not vulnerabilities:
            return 0.0
        
        # Weight by severity
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 1.0
        }
        
        total_score = sum(severity_weights.get(v.severity, 5.0) for v in vulnerabilities)
        avg_score = total_score / len(vulnerabilities)
        
        # Adjust for exploit availability
        exploit_multiplier = 1.0
        if any(v.exploit_available for v in vulnerabilities):
            exploit_multiplier = 1.5
        
        return min(avg_score * exploit_multiplier, 10.0)
    
    def get_scan_result(self, scan_id: str) -> Optional[ImageScanResult]:
        """Get scan result by ID."""
        return self.scan_results.get(scan_id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return self.statistics


# Global instance
_container_scanner: Optional[ContainerImageScanner] = None


def get_container_scanner() -> ContainerImageScanner:
    """Get or create global container scanner instance."""
    global _container_scanner

    if _container_scanner is None:
        _container_scanner = ContainerImageScanner()

    return _container_scanner


class KubernetesSecurityScanner:
    """
    Kubernetes security scanner.

    Scans Kubernetes resources for security misconfigurations and compliance violations.
    """

    def __init__(self):
        """Initialize Kubernetes security scanner."""
        self.resources: Dict[str, K8sResource] = {}
        self.findings: Dict[str, K8sSecurityFinding] = {}

        self.statistics = {
            "total_scans": 0,
            "resources_scanned": 0,
            "findings_by_severity": {s.value: 0 for s in Severity},
            "findings_by_category": {},
            "last_scan": None
        }

        logger.info("Kubernetes Security Scanner initialized")

    async def scan_namespace(self, namespace: str = "default") -> List[K8sResource]:
        """
        Scan Kubernetes namespace for resources.

        Args:
            namespace: Namespace to scan

        Returns:
            List of discovered resources
        """
        logger.info(f"Scanning Kubernetes namespace: {namespace}")

        resources = []

        # Mock Kubernetes resources
        # In production, use kubernetes Python client

        # Pod with security issues
        pod = K8sResource(
            resource_id="pod-web-app-12345",
            resource_type=K8sResourceType.POD,
            name="web-app",
            namespace=namespace,
            labels={"app": "web", "tier": "frontend"},
            spec={
                "containers": [{
                    "name": "nginx",
                    "image": "nginx:1.21",
                    "securityContext": {
                        "runAsUser": 0,  # Running as root
                        "privileged": True,  # Privileged container
                        "capabilities": {
                            "add": ["NET_ADMIN", "SYS_ADMIN"]
                        }
                    }
                }],
                "hostNetwork": True,  # Using host network
                "hostPID": False,
                "hostIPC": False
            }
        )
        resources.append(pod)
        self.resources[pod.resource_id] = pod

        # Service with potential issues
        service = K8sResource(
            resource_id="svc-web-app-12345",
            resource_type=K8sResourceType.SERVICE,
            name="web-app-service",
            namespace=namespace,
            labels={"app": "web"},
            spec={
                "type": "LoadBalancer",  # Exposed to internet
                "ports": [{
                    "port": 80,
                    "targetPort": 80,
                    "protocol": "TCP"
                }],
                "selector": {"app": "web"}
            }
        )
        resources.append(service)
        self.resources[service.resource_id] = service

        # Deployment
        deployment = K8sResource(
            resource_id="deploy-web-app-12345",
            resource_type=K8sResourceType.DEPLOYMENT,
            name="web-app-deployment",
            namespace=namespace,
            labels={"app": "web"},
            spec={
                "replicas": 3,
                "selector": {"matchLabels": {"app": "web"}},
                "template": {
                    "metadata": {"labels": {"app": "web"}},
                    "spec": {
                        "containers": [{
                            "name": "nginx",
                            "image": "nginx:1.21"
                        }]
                    }
                }
            }
        )
        resources.append(deployment)
        self.resources[deployment.resource_id] = deployment

        # Secret (potential exposure)
        secret = K8sResource(
            resource_id="secret-db-creds-12345",
            resource_type=K8sResourceType.SECRET,
            name="db-credentials",
            namespace=namespace,
            labels={},
            spec={
                "type": "Opaque",
                "data": {
                    "username": "YWRtaW4=",  # base64 encoded
                    "password": "cGFzc3dvcmQxMjM="
                }
            }
        )
        resources.append(secret)
        self.resources[secret.resource_id] = secret

        self.statistics["total_scans"] += 1
        self.statistics["resources_scanned"] += len(resources)
        self.statistics["last_scan"] = datetime.utcnow().isoformat()

        logger.info(f"Discovered {len(resources)} Kubernetes resources")

        return resources

    async def analyze_pod_security(self, pod: K8sResource) -> PodSecurityContext:
        """
        Analyze pod security context.

        Args:
            pod: Pod resource to analyze

        Returns:
            Pod security context analysis
        """
        if pod.resource_type != K8sResourceType.POD:
            raise ValueError("Resource must be a Pod")

        containers = pod.spec.get("containers", [])
        if not containers:
            return PodSecurityContext(
                pod_name=pod.name,
                namespace=pod.namespace,
                runs_as_root=False,
                privileged=False,
                host_network=False,
                host_pid=False,
                host_ipc=False
            )

        # Analyze first container (in production, analyze all)
        container = containers[0]
        security_context = container.get("securityContext", {})

        runs_as_root = security_context.get("runAsUser", 0) == 0
        privileged = security_context.get("privileged", False)
        host_network = pod.spec.get("hostNetwork", False)
        host_pid = pod.spec.get("hostPID", False)
        host_ipc = pod.spec.get("hostIPC", False)

        capabilities = security_context.get("capabilities", {})
        capabilities_added = capabilities.get("add", [])
        capabilities_dropped = capabilities.get("drop", [])

        read_only_root = security_context.get("readOnlyRootFilesystem", False)
        allow_privilege_escalation = security_context.get("allowPrivilegeEscalation", True)

        # Determine security standard
        if privileged or host_network or host_pid or host_ipc:
            standard = PodSecurityStandard.PRIVILEGED
        elif runs_as_root or allow_privilege_escalation:
            standard = PodSecurityStandard.BASELINE
        else:
            standard = PodSecurityStandard.RESTRICTED

        return PodSecurityContext(
            pod_name=pod.name,
            namespace=pod.namespace,
            runs_as_root=runs_as_root,
            privileged=privileged,
            host_network=host_network,
            host_pid=host_pid,
            host_ipc=host_ipc,
            capabilities_added=capabilities_added,
            capabilities_dropped=capabilities_dropped,
            read_only_root_filesystem=read_only_root,
            allow_privilege_escalation=allow_privilege_escalation,
            security_standard=standard
        )

    async def check_cis_kubernetes_benchmark(
        self,
        resources: List[K8sResource]
    ) -> List[K8sSecurityFinding]:
        """
        Check CIS Kubernetes Benchmark compliance.

        Args:
            resources: Kubernetes resources to check

        Returns:
            List of security findings
        """
        logger.info(f"Running CIS Kubernetes Benchmark checks on {len(resources)} resources")

        findings = []

        for resource in resources:
            if resource.resource_type == K8sResourceType.POD:
                # Check pod security
                pod_findings = await self._check_pod_security(resource)
                findings.extend(pod_findings)

            elif resource.resource_type == K8sResourceType.SERVICE:
                # Check service exposure
                service_findings = await self._check_service_security(resource)
                findings.extend(service_findings)

            elif resource.resource_type == K8sResourceType.SECRET:
                # Check secret security
                secret_findings = await self._check_secret_security(resource)
                findings.extend(secret_findings)

        # Store findings
        for finding in findings:
            self.findings[finding.finding_id] = finding
            self.statistics["findings_by_severity"][finding.severity.value] += 1

            category = finding.category
            if category not in self.statistics["findings_by_category"]:
                self.statistics["findings_by_category"][category] = 0
            self.statistics["findings_by_category"][category] += 1

        logger.info(f"Found {len(findings)} security findings")

        return findings

    async def _check_pod_security(self, pod: K8sResource) -> List[K8sSecurityFinding]:
        """Check pod security configuration."""
        findings = []

        pod_security = await self.analyze_pod_security(pod)

        # CIS 5.2.1: Minimize the admission of privileged containers
        if pod_security.privileged:
            findings.append(K8sSecurityFinding(
                finding_id=f"cis-5.2.1-{pod.resource_id}",
                resource=pod,
                severity=Severity.CRITICAL,
                title="Privileged container detected",
                description=f"Pod '{pod.name}' is running a privileged container",
                remediation="Remove 'privileged: true' from container securityContext",
                category="pod_security",
                cis_benchmark="5.2.1",
                risk_score=10.0
            ))

        # CIS 5.2.2: Minimize the admission of containers wishing to share the host process ID namespace
        if pod_security.host_pid:
            findings.append(K8sSecurityFinding(
                finding_id=f"cis-5.2.2-{pod.resource_id}",
                resource=pod,
                severity=Severity.HIGH,
                title="Host PID namespace sharing detected",
                description=f"Pod '{pod.name}' is sharing the host PID namespace",
                remediation="Remove 'hostPID: true' from pod spec",
                category="pod_security",
                cis_benchmark="5.2.2",
                risk_score=8.0
            ))

        # CIS 5.2.3: Minimize the admission of containers wishing to share the host IPC namespace
        if pod_security.host_ipc:
            findings.append(K8sSecurityFinding(
                finding_id=f"cis-5.2.3-{pod.resource_id}",
                resource=pod,
                severity=Severity.HIGH,
                title="Host IPC namespace sharing detected",
                description=f"Pod '{pod.name}' is sharing the host IPC namespace",
                remediation="Remove 'hostIPC: true' from pod spec",
                category="pod_security",
                cis_benchmark="5.2.3",
                risk_score=8.0
            ))

        # CIS 5.2.4: Minimize the admission of containers wishing to share the host network namespace
        if pod_security.host_network:
            findings.append(K8sSecurityFinding(
                finding_id=f"cis-5.2.4-{pod.resource_id}",
                resource=pod,
                severity=Severity.HIGH,
                title="Host network namespace sharing detected",
                description=f"Pod '{pod.name}' is sharing the host network namespace",
                remediation="Remove 'hostNetwork: true' from pod spec",
                category="pod_security",
                cis_benchmark="5.2.4",
                risk_score=8.0
            ))

        # CIS 5.2.5: Minimize the admission of containers with allowPrivilegeEscalation
        if pod_security.allow_privilege_escalation:
            findings.append(K8sSecurityFinding(
                finding_id=f"cis-5.2.5-{pod.resource_id}",
                resource=pod,
                severity=Severity.MEDIUM,
                title="Privilege escalation allowed",
                description=f"Pod '{pod.name}' allows privilege escalation",
                remediation="Set 'allowPrivilegeEscalation: false' in container securityContext",
                category="pod_security",
                cis_benchmark="5.2.5",
                risk_score=6.0
            ))

        # CIS 5.2.6: Minimize the admission of root containers
        if pod_security.runs_as_root:
            findings.append(K8sSecurityFinding(
                finding_id=f"cis-5.2.6-{pod.resource_id}",
                resource=pod,
                severity=Severity.MEDIUM,
                title="Container running as root",
                description=f"Pod '{pod.name}' is running as root user (UID 0)",
                remediation="Set 'runAsUser' to non-zero value in container securityContext",
                category="pod_security",
                cis_benchmark="5.2.6",
                risk_score=6.0
            ))

        return findings

    async def _check_service_security(self, service: K8sResource) -> List[K8sSecurityFinding]:
        """Check service security configuration."""
        findings = []

        service_type = service.spec.get("type", "ClusterIP")

        # Check for LoadBalancer services (exposed to internet)
        if service_type == "LoadBalancer":
            findings.append(K8sSecurityFinding(
                finding_id=f"service-exposure-{service.resource_id}",
                resource=service,
                severity=Severity.MEDIUM,
                title="Service exposed via LoadBalancer",
                description=f"Service '{service.name}' is exposed to the internet via LoadBalancer",
                remediation="Consider using Ingress with authentication or changing to ClusterIP",
                category="network",
                risk_score=5.0
            ))

        return findings

    async def _check_secret_security(self, secret: K8sResource) -> List[K8sSecurityFinding]:
        """Check secret security configuration."""
        findings = []

        # Check if secret is properly encrypted at rest
        # In production, check etcd encryption configuration

        # Check for weak secret names
        if "password" in secret.name.lower() or "cred" in secret.name.lower():
            findings.append(K8sSecurityFinding(
                finding_id=f"secret-naming-{secret.resource_id}",
                resource=secret,
                severity=Severity.LOW,
                title="Secret with descriptive name",
                description=f"Secret '{secret.name}' has a descriptive name that reveals its purpose",
                remediation="Use generic secret names and document purpose in annotations",
                category="secrets",
                risk_score=2.0
            ))

        return findings

    def get_findings_by_severity(self, severity: Severity) -> List[K8sSecurityFinding]:
        """Get findings by severity."""
        return [f for f in self.findings.values() if f.severity == severity]

    def get_findings_by_category(self, category: str) -> List[K8sSecurityFinding]:
        """Get findings by category."""
        return [f for f in self.findings.values() if f.category == category]

    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return self.statistics


# Global instance
_k8s_scanner: Optional[KubernetesSecurityScanner] = None


def get_k8s_scanner() -> KubernetesSecurityScanner:
    """Get or create global Kubernetes scanner instance."""
    global _k8s_scanner

    if _k8s_scanner is None:
        _k8s_scanner = KubernetesSecurityScanner()

    return _k8s_scanner


@dataclass
class RuntimeEvent:
    """Runtime security event."""
    event_id: str
    container_id: str
    container_name: str
    event_type: str  # syscall, network, file, process
    timestamp: datetime
    severity: Severity
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False


@dataclass
class SBOMComponent:
    """Software Bill of Materials component."""
    name: str
    version: str
    type: str  # library, application, framework, os
    supplier: str = ""
    license: str = ""
    purl: str = ""  # Package URL
    cpe: str = ""  # Common Platform Enumeration
    hashes: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class SBOM:
    """Software Bill of Materials."""
    sbom_id: str
    image: ContainerImage
    format: str = "CycloneDX"  # or SPDX
    version: str = "1.4"
    components: List[SBOMComponent] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)
    tool: str = "Vaulytica Container Security"

    def to_json(self) -> str:
        """Export SBOM as JSON."""
        return json.dumps({
            "bomFormat": self.format,
            "specVersion": self.version,
            "serialNumber": f"urn:uuid:{self.sbom_id}",
            "version": 1,
            "metadata": {
                "timestamp": self.generated_at.isoformat(),
                "tools": [{"name": self.tool}],
                "component": {
                    "type": "container",
                    "name": self.image.repository,
                    "version": self.image.tag
                }
            },
            "components": [
                {
                    "type": comp.type,
                    "name": comp.name,
                    "version": comp.version,
                    "supplier": comp.supplier,
                    "licenses": [{"license": {"id": comp.license}}] if comp.license else [],
                    "purl": comp.purl,
                    "hashes": [{"alg": k, "content": v} for k, v in comp.hashes.items()]
                }
                for comp in self.components
            ]
        }, indent=2)


class RuntimeSecurityMonitor:
    """
    Runtime security monitor for containers.

    Monitors container runtime behavior for suspicious activity.
    """

    def __init__(self):
        """Initialize runtime security monitor."""
        self.events: List[RuntimeEvent] = []
        self.blocked_events: List[RuntimeEvent] = []

        self.statistics = {
            "total_events": 0,
            "events_by_type": {},
            "events_by_severity": {s.value: 0 for s in Severity},
            "blocked_events": 0,
            "containers_monitored": 0
        }

        logger.info("Runtime Security Monitor initialized")

    async def monitor_container(
        self,
        container_id: str,
        duration_seconds: int = 60
    ) -> List[RuntimeEvent]:
        """
        Monitor container runtime behavior.

        Args:
            container_id: Container ID to monitor
            duration_seconds: Monitoring duration

        Returns:
            List of runtime events detected
        """
        logger.info(f"Monitoring container {container_id} for {duration_seconds}s")

        events = []

        # Mock runtime events
        # In production, integrate with Falco, Sysdig, or eBPF

        # Suspicious syscall
        events.append(RuntimeEvent(
            event_id=f"evt-{int(datetime.utcnow().timestamp())}-1",
            container_id=container_id,
            container_name="web-app",
            event_type="syscall",
            timestamp=datetime.utcnow(),
            severity=Severity.HIGH,
            description="Suspicious syscall: ptrace detected",
            details={
                "syscall": "ptrace",
                "process": "/bin/bash",
                "pid": 1234
            },
            blocked=False
        ))

        # Suspicious network activity
        events.append(RuntimeEvent(
            event_id=f"evt-{int(datetime.utcnow().timestamp())}-2",
            container_id=container_id,
            container_name="web-app",
            event_type="network",
            timestamp=datetime.utcnow(),
            severity=Severity.MEDIUM,
            description="Outbound connection to suspicious IP",
            details={
                "destination_ip": "198.51.100.5",
                "destination_port": 4444,
                "protocol": "tcp"
            },
            blocked=False
        ))

        # Suspicious file access
        events.append(RuntimeEvent(
            event_id=f"evt-{int(datetime.utcnow().timestamp())}-3",
            container_id=container_id,
            container_name="web-app",
            event_type="file",
            timestamp=datetime.utcnow(),
            severity=Severity.MEDIUM,
            description="Sensitive file access detected",
            details={
                "file_path": "/etc/shadow",
                "operation": "read",
                "process": "/usr/bin/cat"
            },
            blocked=True
        ))

        # Store events
        self.events.extend(events)

        # Update statistics
        self.statistics["total_events"] += len(events)
        self.statistics["containers_monitored"] += 1

        for event in events:
            event_type = event.event_type
            if event_type not in self.statistics["events_by_type"]:
                self.statistics["events_by_type"][event_type] = 0
            self.statistics["events_by_type"][event_type] += 1

            self.statistics["events_by_severity"][event.severity.value] += 1

            if event.blocked:
                self.blocked_events.append(event)
                self.statistics["blocked_events"] += 1

        logger.info(f"Detected {len(events)} runtime events")

        return events

    def get_events_by_severity(self, severity: Severity) -> List[RuntimeEvent]:
        """Get events by severity."""
        return [e for e in self.events if e.severity == severity]

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitor statistics."""
        return self.statistics


class SupplyChainSecurity:
    """
    Supply chain security for containers.

    Generates SBOMs, scans dependencies, and verifies image provenance.
    """

    def __init__(self):
        """Initialize supply chain security."""
        self.sboms: Dict[str, SBOM] = {}

        self.statistics = {
            "sboms_generated": 0,
            "components_tracked": 0,
            "licenses_found": set()
        }

        logger.info("Supply Chain Security initialized")

    async def generate_sbom(self, image: ContainerImage) -> SBOM:
        """
        Generate Software Bill of Materials for image.

        Args:
            image: Container image

        Returns:
            SBOM for the image
        """
        logger.info(f"Generating SBOM for {image.repository}:{image.tag}")

        # Scan image for components
        scanner = get_container_scanner()
        scan_result = await scanner.scan_image(f"{image.repository}:{image.tag}")

        # Convert packages to SBOM components
        components = []
        for package in scan_result.packages:
            component = SBOMComponent(
                name=package.name,
                version=package.version,
                type="library",
                license=package.license,
                purl=f"pkg:{package.package_manager.value}/{package.name}@{package.version}",
                hashes={"sha256": hashlib.sha256(f"{package.name}{package.version}".encode()).hexdigest()}
            )
            components.append(component)

        # Create SBOM
        sbom = SBOM(
            sbom_id=hashlib.sha256(f"{image.image_id}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16],
            image=image,
            components=components
        )

        self.sboms[sbom.sbom_id] = sbom

        # Update statistics
        self.statistics["sboms_generated"] += 1
        self.statistics["components_tracked"] += len(components)
        for comp in components:
            if comp.license:
                self.statistics["licenses_found"].add(comp.license)

        logger.info(f"Generated SBOM with {len(components)} components")

        return sbom

    async def verify_image_signature(
        self,
        image: ContainerImage,
        public_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verify image signature and provenance.

        Args:
            image: Container image
            public_key: Public key for verification

        Returns:
            Verification result
        """
        logger.info(f"Verifying signature for {image.repository}:{image.tag}")

        # Mock signature verification
        # In production, use cosign or notary

        return {
            "verified": True,
            "signer": "build-system@example.com",
            "signed_at": (datetime.utcnow() - timedelta(days=1)).isoformat(),
            "provenance": {
                "builder": "GitHub Actions",
                "source_repo": "https://github.com/example/app",
                "commit_sha": "abc123def456"
            }
        }

    def get_sbom(self, sbom_id: str) -> Optional[SBOM]:
        """Get SBOM by ID."""
        return self.sboms.get(sbom_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get supply chain statistics."""
        stats = self.statistics.copy()
        stats["licenses_found"] = list(stats["licenses_found"])
        return stats


# Global instances
_runtime_monitor: Optional[RuntimeSecurityMonitor] = None
_supply_chain: Optional[SupplyChainSecurity] = None


def get_runtime_monitor() -> RuntimeSecurityMonitor:
    """Get or create global runtime monitor instance."""
    global _runtime_monitor

    if _runtime_monitor is None:
        _runtime_monitor = RuntimeSecurityMonitor()

    return _runtime_monitor


def get_supply_chain_security() -> SupplyChainSecurity:
    """Get or create global supply chain security instance."""
    global _supply_chain

    if _supply_chain is None:
        _supply_chain = SupplyChainSecurity()

    return _supply_chain


class ContainerSecurityOrchestrator:
    """
    Orchestrates all container security operations.

    Provides unified interface for container and Kubernetes security.
    """

    def __init__(self):
        """Initialize container security orchestrator."""
        self.image_scanner = get_container_scanner()
        self.k8s_scanner = get_k8s_scanner()
        self.runtime_monitor = get_runtime_monitor()
        self.supply_chain = get_supply_chain_security()

        logger.info("Container Security Orchestrator initialized")

    async def full_security_assessment(
        self,
        image_ref: str,
        namespace: str = "default",
        monitor_runtime: bool = True
    ) -> Dict[str, Any]:
        """
        Perform full security assessment.

        Args:
            image_ref: Container image reference
            namespace: Kubernetes namespace
            monitor_runtime: Whether to monitor runtime

        Returns:
            Complete security assessment
        """
        logger.info(f"Starting full security assessment for {image_ref}")

        start_time = datetime.utcnow()

        # Scan container image
        image_scan = await self.image_scanner.scan_image(image_ref)

        # Generate SBOM
        sbom = await self.supply_chain.generate_sbom(image_scan.image)

        # Verify image signature
        signature_verification = await self.supply_chain.verify_image_signature(image_scan.image)

        # Scan Kubernetes resources
        k8s_resources = await self.k8s_scanner.scan_namespace(namespace)
        k8s_findings = await self.k8s_scanner.check_cis_kubernetes_benchmark(k8s_resources)

        # Monitor runtime (if enabled)
        runtime_events = []
        if monitor_runtime:
            runtime_events = await self.runtime_monitor.monitor_container(
                image_scan.image.image_id,
                duration_seconds=10
            )

        duration = (datetime.utcnow() - start_time).total_seconds()

        assessment = {
            "assessment_id": f"assess-{int(datetime.utcnow().timestamp())}",
            "image": {
                "reference": image_ref,
                "scan_id": image_scan.scan_id,
                "vulnerabilities": len(image_scan.vulnerabilities),
                "vulnerabilities_by_severity": image_scan.get_vulnerability_count_by_severity(),
                "risk_score": image_scan.risk_score,
                "packages": len(image_scan.packages)
            },
            "sbom": {
                "sbom_id": sbom.sbom_id,
                "components": len(sbom.components),
                "format": sbom.format
            },
            "signature": signature_verification,
            "kubernetes": {
                "resources_scanned": len(k8s_resources),
                "findings": len(k8s_findings),
                "findings_by_severity": {
                    s.value: len([f for f in k8s_findings if f.severity == s])
                    for s in Severity
                }
            },
            "runtime": {
                "events": len(runtime_events),
                "events_by_severity": {
                    s.value: len([e for e in runtime_events if e.severity == s])
                    for s in Severity
                },
                "blocked_events": len([e for e in runtime_events if e.blocked])
            } if monitor_runtime else None,
            "overall_risk_score": self._calculate_overall_risk(
                image_scan,
                k8s_findings,
                runtime_events
            ),
            "duration_seconds": duration,
            "timestamp": datetime.utcnow().isoformat()
        }

        logger.info(f"Security assessment complete in {duration:.2f}s")

        return assessment

    def _calculate_overall_risk(
        self,
        image_scan: ImageScanResult,
        k8s_findings: List[K8sSecurityFinding],
        runtime_events: List[RuntimeEvent]
    ) -> float:
        """Calculate overall risk score."""
        # Weight different factors
        image_risk = image_scan.risk_score * 0.4

        k8s_risk = 0.0
        if k8s_findings:
            severity_weights = {
                Severity.CRITICAL: 10.0,
                Severity.HIGH: 7.5,
                Severity.MEDIUM: 5.0,
                Severity.LOW: 2.5,
                Severity.INFO: 1.0
            }
            k8s_risk = sum(severity_weights.get(f.severity, 5.0) for f in k8s_findings) / len(k8s_findings) * 0.4

        runtime_risk = 0.0
        if runtime_events:
            severity_weights = {
                Severity.CRITICAL: 10.0,
                Severity.HIGH: 7.5,
                Severity.MEDIUM: 5.0,
                Severity.LOW: 2.5,
                Severity.INFO: 1.0
            }
            runtime_risk = sum(severity_weights.get(e.severity, 5.0) for e in runtime_events) / len(runtime_events) * 0.2

        return min(image_risk + k8s_risk + runtime_risk, 10.0)

    def get_unified_statistics(self) -> Dict[str, Any]:
        """Get unified statistics from all components."""
        return {
            "image_scanner": self.image_scanner.get_statistics(),
            "k8s_scanner": self.k8s_scanner.get_statistics(),
            "runtime_monitor": self.runtime_monitor.get_statistics(),
            "supply_chain": self.supply_chain.get_statistics()
        }


# Global instance
_orchestrator: Optional[ContainerSecurityOrchestrator] = None


def get_container_security_orchestrator() -> ContainerSecurityOrchestrator:
    """Get or create global orchestrator instance."""
    global _orchestrator

    if _orchestrator is None:
        _orchestrator = ContainerSecurityOrchestrator()

    return _orchestrator

