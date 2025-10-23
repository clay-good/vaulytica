"""
Socket.dev Supply Chain Security Integration

Integrates with Socket.dev API for:
- Package vulnerability scanning
- Supply chain attack detection
- Dependency risk analysis
- License compliance checking
- Malware detection in dependencies
- Typosquatting detection

Supports: npm, PyPI, Go modules

Version: 1.0.0
Author: Vaulytica Team
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import httpx

from vaulytica.config import VaulyticaConfig, get_config
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class SocketEcosystem(str, Enum):
    """Package ecosystems supported by Socket"""
    NPM = "npm"
    PYPI = "pypi"
    GO = "go"


class SocketAlertType(str, Enum):
    """Socket alert types"""
    MALWARE = "malware"
    TYPOSQUAT = "typosquat"
    INSTALL_SCRIPTS = "install_scripts"
    OBFUSCATED_CODE = "obfuscated_code"
    NETWORK_ACCESS = "network_access"
    FILESYSTEM_ACCESS = "filesystem_access"
    SHELL_ACCESS = "shell_access"
    ENVIRONMENT_VARIABLES = "environment_variables"
    DEPRECATED = "deprecated"
    UNMAINTAINED = "unmaintained"
    VULNERABLE = "vulnerable"
    LICENSE_ISSUE = "license_issue"


class SocketSeverity(str, Enum):
    """Socket severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SocketAlert:
    """Socket security alert"""
    type: SocketAlertType
    severity: SocketSeverity
    title: str
    description: str
    suggestion: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SocketPackageScore:
    """Socket package quality and security score"""
    overall: float  # 0-100
    quality: float
    maintenance: float
    vulnerability: float
    license: float
    supply_chain: float


@dataclass
class SocketPackageAnalysis:
    """Socket package analysis result"""
    ecosystem: SocketEcosystem
    package_name: str
    version: str
    score: SocketPackageScore
    alerts: List[SocketAlert] = field(default_factory=list)
    dependencies_count: int = 0
    direct_vulnerabilities: int = 0
    transitive_vulnerabilities: int = 0
    license: Optional[str] = None
    author: Optional[str] = None
    published_at: Optional[datetime] = None
    downloads_last_month: int = 0
    is_deprecated: bool = False
    is_unmaintained: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SocketVulnerability:
    """Socket vulnerability finding"""
    id: str
    cve_id: Optional[str] = None
    severity: SocketSeverity = SocketSeverity.MEDIUM
    title: str = ""
    description: str = ""
    affected_versions: List[str] = field(default_factory=list)
    patched_versions: List[str] = field(default_factory=list)
    published_at: Optional[datetime] = None
    cvss_score: float = 0.0
    epss_score: float = 0.0
    exploit_available: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SocketDependency:
    """Package dependency"""
    name: str
    version: str
    ecosystem: SocketEcosystem
    is_direct: bool = True
    depth: int = 0
    parent: Optional[str] = None
    vulnerabilities: List[SocketVulnerability] = field(default_factory=list)
    alerts: List[SocketAlert] = field(default_factory=list)


class SocketAPIClient:
    """Socket.dev API client"""

    def __init__(
        self,
        api_key: str,
        timeout: int = 30
    ):
        """
        Initialize Socket API client.

        Args:
            api_key: Socket.dev API key
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = "https://example.com"

        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "packages_analyzed": 0,
            "vulnerabilities_found": 0,
            "alerts_found": 0
        }

        logger.info("Socket.dev API client initialized")

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Make API request"""
        try:
            self.stats["total_requests"] += 1

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            url = f"{self.base_url}/{endpoint}"

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=params)
                elif method == "POST":
                    response = await client.post(url, headers=headers, json=json_data)
                else:
                    raise ValueError(f"Unsupported method: {method}")

                if response.status_code == 200:
                    self.stats["successful_requests"] += 1
                    return response.json()
                else:
                    logger.error(f"Socket API error: {response.status_code} - {response.text}")
                    self.stats["failed_requests"] += 1
                    return None

        except Exception as e:
            logger.error(f"Socket API request error: {e}")
            self.stats["failed_requests"] += 1
            return None

    async def analyze_package(
        self,
        ecosystem: SocketEcosystem,
        package: str,
        version: str
    ) -> Optional[SocketPackageAnalysis]:
        """
        Analyze a package for security issues.

        Args:
            ecosystem: Package ecosystem (npm, pypi, go)
            package: Package name
            version: Package version

        Returns:
            SocketPackageAnalysis or None
        """
        endpoint = f"package/{ecosystem.value}/{package}/{version}"
        result = await self._make_request("GET", endpoint)

        if not result:
            return None

        # Parse score
        score_data = result.get("score", {})
        score = SocketPackageScore(
            overall=score_data.get("overall", 0.0),
            quality=score_data.get("quality", 0.0),
            maintenance=score_data.get("maintenance", 0.0),
            vulnerability=score_data.get("vulnerability", 0.0),
            license=score_data.get("license", 0.0),
            supply_chain=score_data.get("supplyChain", 0.0)
        )

        # Parse alerts
        alerts = []
        for alert_data in result.get("alerts", []):
            alert = SocketAlert(
                type=SocketAlertType(alert_data["type"]),
                severity=SocketSeverity(alert_data.get("severity", "medium")),
                title=alert_data.get("title", ""),
                description=alert_data.get("description", ""),
                suggestion=alert_data.get("suggestion", ""),
                metadata=alert_data
            )
            alerts.append(alert)

        analysis = SocketPackageAnalysis(
            ecosystem=ecosystem,
            package_name=package,
            version=version,
            score=score,
            alerts=alerts,
            dependencies_count=result.get("dependenciesCount", 0),
            direct_vulnerabilities=result.get("directVulnerabilities", 0),
            transitive_vulnerabilities=result.get("transitiveVulnerabilities", 0),
            license=result.get("license"),
            author=result.get("author"),
            published_at=self._parse_datetime(result.get("publishedAt")),
            downloads_last_month=result.get("downloadsLastMonth", 0),
            is_deprecated=result.get("deprecated", False),
            is_unmaintained=result.get("unmaintained", False),
            metadata=result
        )

        self.stats["packages_analyzed"] += 1
        self.stats["alerts_found"] += len(alerts)

        logger.info(f"Analyzed {ecosystem.value}/{package}@{version}: score={score.overall:.1f}, alerts={len(alerts)}")

        return analysis

    async def get_vulnerabilities(
        self,
        ecosystem: SocketEcosystem,
        package: str,
        version: Optional[str] = None
    ) -> List[SocketVulnerability]:
        """
        Get vulnerabilities for a package.

        Args:
            ecosystem: Package ecosystem
            package: Package name
            version: Optional specific version

        Returns:
            List of SocketVulnerability objects
        """
        if version:
            endpoint = f"package/{ecosystem.value}/{package}/{version}/vulnerabilities"
        else:
            endpoint = f"package/{ecosystem.value}/{package}/vulnerabilities"

        result = await self._make_request("GET", endpoint)

        if not result or "vulnerabilities" not in result:
            return []

        vulnerabilities = []
        for vuln_data in result["vulnerabilities"]:
            vuln = SocketVulnerability(
                id=vuln_data["id"],
                cve_id=vuln_data.get("cveId"),
                severity=SocketSeverity(vuln_data.get("severity", "medium")),
                title=vuln_data.get("title", ""),
                description=vuln_data.get("description", ""),
                affected_versions=vuln_data.get("affectedVersions", []),
                patched_versions=vuln_data.get("patchedVersions", []),
                published_at=self._parse_datetime(vuln_data.get("publishedAt")),
                cvss_score=vuln_data.get("cvssScore", 0.0),
                epss_score=vuln_data.get("epssScore", 0.0),
                exploit_available=vuln_data.get("exploitAvailable", False),
                metadata=vuln_data
            )
            vulnerabilities.append(vuln)

        self.stats["vulnerabilities_found"] += len(vulnerabilities)
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {ecosystem.value}/{package}")

        return vulnerabilities

    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string"""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except Exception:
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics"""
        return self.stats.copy()


class SocketDevIntegration:
    """High-level Socket.dev integration with caching"""

    def __init__(self, config: Optional[VaulyticaConfig] = None):
        """Initialize Socket.dev integration"""
        if config is None:
            config = get_config()

        self.config = config
        self.client = SocketAPIClient(api_key=config.socketdev_api_key)

        # Cache
        self.analysis_cache: Dict[str, SocketPackageAnalysis] = {}
        self.vulnerability_cache: Dict[str, List[SocketVulnerability]] = {}

        logger.info("Socket.dev integration initialized")

    async def analyze_npm_package(
        self,
        package: str,
        version: str,
        use_cache: bool = True
    ) -> Optional[SocketPackageAnalysis]:
        """Analyze npm package"""
        cache_key = f"npm:{package}:{version}"

        if use_cache and cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        analysis = await self.client.analyze_package(
            ecosystem=SocketEcosystem.NPM,
            package=package,
            version=version
        )

        if analysis:
            self.analysis_cache[cache_key] = analysis

        return analysis

    async def analyze_python_package(
        self,
        package: str,
        version: str,
        use_cache: bool = True
    ) -> Optional[SocketPackageAnalysis]:
        """Analyze Python package"""
        cache_key = f"pypi:{package}:{version}"

        if use_cache and cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        analysis = await self.client.analyze_package(
            ecosystem=SocketEcosystem.PYPI,
            package=package,
            version=version
        )

        if analysis:
            self.analysis_cache[cache_key] = analysis

        return analysis

    async def get_high_risk_packages(
        self,
        ecosystem: SocketEcosystem,
        packages: List[tuple[str, str]]  # [(name, version), ...]
    ) -> List[SocketPackageAnalysis]:
        """
        Analyze multiple packages and return high-risk ones.

        Args:
            ecosystem: Package ecosystem
            packages: List of (package_name, version) tuples

        Returns:
            List of high-risk package analyses (score < 70 or critical alerts)
        """
        high_risk = []

        for package_name, version in packages:
            analysis = await self.client.analyze_package(
                ecosystem=ecosystem,
                package=package_name,
                version=version
            )

            if not analysis:
                continue

            # Check if high risk
            is_high_risk = (
                analysis.score.overall < 70 or
                any(alert.severity in [SocketSeverity.CRITICAL, SocketSeverity.HIGH]
                    for alert in analysis.alerts) or
                analysis.direct_vulnerabilities > 0
            )

            if is_high_risk:
                high_risk.append(analysis)

        logger.info(f"Found {len(high_risk)} high-risk packages out of {len(packages)}")
        return high_risk

    async def check_for_malware(
        self,
        ecosystem: SocketEcosystem,
        package: str,
        version: str
    ) -> bool:
        """Check if package contains malware"""
        analysis = await self.client.analyze_package(
            ecosystem=ecosystem,
            package=package,
            version=version
        )

        if not analysis:
            return False

        # Check for malware alerts
        return any(
            alert.type == SocketAlertType.MALWARE
            for alert in analysis.alerts
        )

    async def check_for_typosquat(
        self,
        ecosystem: SocketEcosystem,
        package: str,
        version: str
    ) -> bool:
        """Check if package is a typosquat"""
        analysis = await self.client.analyze_package(
            ecosystem=ecosystem,
            package=package,
            version=version
        )

        if not analysis:
            return False

        # Check for typosquat alerts
        return any(
            alert.type == SocketAlertType.TYPOSQUAT
            for alert in analysis.alerts
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics"""
        stats = self.client.get_statistics()
        stats["cache_size"] = len(self.analysis_cache)
        return stats


# Global instance
_socketdev_integration: Optional[SocketDevIntegration] = None


def get_socketdev_integration(config: Optional[VaulyticaConfig] = None) -> SocketDevIntegration:
    """Get or create global Socket.dev integration instance"""
    global _socketdev_integration

    if _socketdev_integration is None:
        _socketdev_integration = SocketDevIntegration(config)

    return _socketdev_integration

