"""
Wiz Cloud Security Platform Integration

Integrates with Wiz.io API for:
- Vulnerability scanning and management
- Cloud Security Posture Management (CSPM)
- Asset discovery and inventory
- Compliance monitoring
- Kubernetes security
- Container image scanning

Wiz uses GraphQL API for all operations.

Version: 1.0.0
Author: Vaulytica Team
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import httpx

from vaulytica.config import VaulyticaConfig, get_config
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class WizSeverity(str, Enum):
    """Wiz severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class WizResourceType(str, Enum):
    """Wiz resource types"""
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"
    CONTAINER = "CONTAINER"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    KUBERNETES_POD = "KUBERNETES_POD"
    SERVERLESS_FUNCTION = "SERVERLESS_FUNCTION"
    DATABASE = "DATABASE"
    STORAGE = "STORAGE"
    NETWORK = "NETWORK"
    IAM_ROLE = "IAM_ROLE"
    IAM_USER = "IAM_USER"


class WizIssueStatus(str, Enum):
    """Wiz issue status"""
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"


@dataclass
class WizVulnerability:
    """Wiz vulnerability finding"""
    id: str
    name: str
    severity: WizSeverity
    cvss_score: float
    cve_id: Optional[str] = None
    description: str = ""
    remediation: str = ""
    affected_resources: List[str] = field(default_factory=list)
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    exploitability_score: float = 0.0
    has_exploit: bool = False
    epss_score: float = 0.0  # Exploit Prediction Scoring System
    first_detected: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    status: WizIssueStatus = WizIssueStatus.OPEN
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WizResource:
    """Wiz cloud resource"""
    id: str
    name: str
    type: WizResourceType
    cloud_provider: str  # AWS, Azure, GCP
    cloud_account_id: str
    region: str
    tags: Dict[str, str] = field(default_factory=dict)
    risk_score: float = 0.0
    vulnerabilities_count: int = 0
    misconfigurations_count: int = 0
    created_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WizIssue:
    """Wiz security issue"""
    id: str
    title: str
    severity: WizSeverity
    status: WizIssueStatus
    issue_type: str  # VULNERABILITY, MISCONFIGURATION, THREAT, etc.
    description: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    affected_resources: List[WizResource] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    assignee: Optional[str] = None
    projects: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class WizAPIClient:
    """Wiz GraphQL API client"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        region: str = "us17",
        timeout: int = 30
    ):
        """
        Initialize Wiz API client.

        Args:
            client_id: Wiz service account client ID
            client_secret: Wiz service account client secret
            region: Wiz region (us17, eu1, etc.)
            timeout: Request timeout in seconds
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = region
        self.timeout = timeout

        # API endpoints
        self.auth_url = f"https://example.com"
        self.api_url = f"https://example.com{region}.app.wiz.io/graphql"

        # Authentication
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None

        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "vulnerabilities_found": 0,
            "issues_found": 0,
            "resources_scanned": 0
        }

        logger.info(f"Wiz API client initialized (region: {region})")

    async def _authenticate(self) -> bool:
        """Authenticate with Wiz and get access token"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.auth_url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "audience": "wiz-api"
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    self.access_token = data["access_token"]
                    expires_in = data.get("expires_in", 3600)
                    self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in - 300)
                    logger.info("Wiz authentication successful")
                    return True
                else:
                    logger.error(f"Wiz authentication failed: {response.status_code} - {response.text}")
                    return False

        except Exception as e:
            logger.error(f"Wiz authentication error: {e}")
            return False

    async def _ensure_authenticated(self) -> bool:
        """Ensure we have a valid access token"""
        if not self.access_token or not self.token_expires_at:
            return await self._authenticate()

        if datetime.utcnow() >= self.token_expires_at:
            return await self._authenticate()

        return True

    async def _execute_query(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Execute GraphQL query"""
        if not await self._ensure_authenticated():
            return None

        try:
            self.stats["total_requests"] += 1

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "query": query,
                        "variables": variables or {}
                    }
                )

                if response.status_code == 200:
                    data = response.json()

                    if "errors" in data:
                        logger.error(f"Wiz GraphQL errors: {data['errors']}")
                        self.stats["failed_requests"] += 1
                        return None

                    self.stats["successful_requests"] += 1
                    return data.get("data")
                else:
                    logger.error(f"Wiz API error: {response.status_code} - {response.text}")
                    self.stats["failed_requests"] += 1
                    return None

        except Exception as e:
            logger.error(f"Wiz query execution error: {e}")
            self.stats["failed_requests"] += 1
            return None

    async def get_vulnerabilities(
        self,
        severity: Optional[List[WizSeverity]] = None,
        limit: int = 100,
        has_exploit: Optional[bool] = None
    ) -> List[WizVulnerability]:
        """
        Get vulnerabilities from Wiz.

        Args:
            severity: Filter by severity levels
            limit: Maximum number of results
            has_exploit: Filter by exploit availability

        Returns:
            List of WizVulnerability objects
        """
        # Build filter
        filters = []
        if severity:
            severity_values = [s.value for s in severity]
            filters.append(f'severity: {json.dumps(severity_values)}')
        if has_exploit is not None:
            filters.append(f'hasExploit: {str(has_exploit).lower()}')

        filter_str = ", ".join(filters) if filters else ""

        query = f"""
        query GetVulnerabilities {{
            vulnerabilities(
                first: {limit}
                {f'filterBy: {{{filter_str}}}' if filter_str else ''}
            ) {{
                nodes {{
                    id
                    name
                    severity
                    cvssScore
                    cveId
                    description
                    remediation
                    packageName
                    packageVersion
                    fixedVersion
                    exploitabilityScore
                    hasExploit
                    epssScore
                    firstDetectedAt
                    lastSeenAt
                    status
                    affectedResources {{
                        id
                        name
                    }}
                }}
            }}
        }}
        """

        result = await self._execute_query(query)
        if not result or "vulnerabilities" not in result:
            return []

        vulnerabilities = []
        for node in result["vulnerabilities"].get("nodes", []):
            vuln = WizVulnerability(
                id=node["id"],
                name=node["name"],
                severity=WizSeverity(node["severity"]),
                cvss_score=node.get("cvssScore", 0.0),
                cve_id=node.get("cveId"),
                description=node.get("description", ""),
                remediation=node.get("remediation", ""),
                package_name=node.get("packageName"),
                package_version=node.get("packageVersion"),
                fixed_version=node.get("fixedVersion"),
                exploitability_score=node.get("exploitabilityScore", 0.0),
                has_exploit=node.get("hasExploit", False),
                epss_score=node.get("epssScore", 0.0),
                first_detected=self._parse_datetime(node.get("firstDetectedAt")),
                last_seen=self._parse_datetime(node.get("lastSeenAt")),
                status=WizIssueStatus(node.get("status", "OPEN")),
                affected_resources=[r["id"] for r in node.get("affectedResources", [])],
                metadata=node
            )
            vulnerabilities.append(vuln)

        self.stats["vulnerabilities_found"] += len(vulnerabilities)
        logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities from Wiz")

        return vulnerabilities

    async def get_issues(
        self,
        severity: Optional[List[WizSeverity]] = None,
        status: Optional[List[WizIssueStatus]] = None,
        issue_type: Optional[str] = None,
        limit: int = 100
    ) -> List[WizIssue]:
        """
        Get security issues from Wiz.

        Args:
            severity: Filter by severity levels
            status: Filter by issue status
            issue_type: Filter by issue type (VULNERABILITY, MISCONFIGURATION, etc.)
            limit: Maximum number of results

        Returns:
            List of WizIssue objects
        """
        # Build filter
        filters = []
        if severity:
            severity_values = [s.value for s in severity]
            filters.append(f'severity: {json.dumps(severity_values)}')
        if status:
            status_values = [s.value for s in status]
            filters.append(f'status: {json.dumps(status_values)}')
        if issue_type:
            filters.append(f'type: "{issue_type}"')

        filter_str = ", ".join(filters) if filters else ""

        query = f"""
        query GetIssues {{
            issues(
                first: {limit}
                {f'filterBy: {{{filter_str}}}' if filter_str else ''}
            ) {{
                nodes {{
                    id
                    title
                    severity
                    status
                    type
                    description
                    remediationSteps
                    createdAt
                    updatedAt
                    resolvedAt
                    assignee {{
                        name
                    }}
                    projects {{
                        name
                    }}
                    affectedResources {{
                        id
                        name
                        type
                        cloudProvider
                        cloudAccountId
                        region
                        tags
                        riskScore
                    }}
                }}
            }}
        }}
        """

        result = await self._execute_query(query)
        if not result or "issues" not in result:
            return []

        issues = []
        for node in result["issues"].get("nodes", []):
            # Parse affected resources
            resources = []
            for res in node.get("affectedResources", []):
                resource = WizResource(
                    id=res["id"],
                    name=res["name"],
                    type=WizResourceType(res["type"]),
                    cloud_provider=res.get("cloudProvider", ""),
                    cloud_account_id=res.get("cloudAccountId", ""),
                    region=res.get("region", ""),
                    tags=res.get("tags", {}),
                    risk_score=res.get("riskScore", 0.0)
                )
                resources.append(resource)

            issue = WizIssue(
                id=node["id"],
                title=node["title"],
                severity=WizSeverity(node["severity"]),
                status=WizIssueStatus(node["status"]),
                issue_type=node["type"],
                description=node.get("description", ""),
                remediation_steps=node.get("remediationSteps", []),
                affected_resources=resources,
                created_at=self._parse_datetime(node.get("createdAt")),
                updated_at=self._parse_datetime(node.get("updatedAt")),
                resolved_at=self._parse_datetime(node.get("resolvedAt")),
                assignee=node.get("assignee", {}).get("name") if node.get("assignee") else None,
                projects=[p["name"] for p in node.get("projects", [])],
                metadata=node
            )
            issues.append(issue)

        self.stats["issues_found"] += len(issues)
        logger.info(f"Retrieved {len(issues)} issues from Wiz")

        return issues

    async def get_resources(
        self,
        resource_type: Optional[WizResourceType] = None,
        cloud_provider: Optional[str] = None,
        limit: int = 100
    ) -> List[WizResource]:
        """
        Get cloud resources from Wiz.

        Args:
            resource_type: Filter by resource type
            cloud_provider: Filter by cloud provider (AWS, Azure, GCP)
            limit: Maximum number of results

        Returns:
            List of WizResource objects
        """
        # Build filter
        filters = []
        if resource_type:
            filters.append(f'type: "{resource_type.value}"')
        if cloud_provider:
            filters.append(f'cloudProvider: "{cloud_provider}"')

        filter_str = ", ".join(filters) if filters else ""

        query = f"""
        query GetResources {{
            resources(
                first: {limit}
                {f'filterBy: {{{filter_str}}}' if filter_str else ''}
            ) {{
                nodes {{
                    id
                    name
                    type
                    cloudProvider
                    cloudAccountId
                    region
                    tags
                    riskScore
                    vulnerabilitiesCount
                    misconfigurationsCount
                    createdAt
                }}
            }}
        }}
        """

        result = await self._execute_query(query)
        if not result or "resources" not in result:
            return []

        resources = []
        for node in result["resources"].get("nodes", []):
            resource = WizResource(
                id=node["id"],
                name=node["name"],
                type=WizResourceType(node["type"]),
                cloud_provider=node.get("cloudProvider", ""),
                cloud_account_id=node.get("cloudAccountId", ""),
                region=node.get("region", ""),
                tags=node.get("tags", {}),
                risk_score=node.get("riskScore", 0.0),
                vulnerabilities_count=node.get("vulnerabilitiesCount", 0),
                misconfigurations_count=node.get("misconfigurationsCount", 0),
                created_at=self._parse_datetime(node.get("createdAt")),
                metadata=node
            )
            resources.append(resource)

        self.stats["resources_scanned"] += len(resources)
        logger.info(f"Retrieved {len(resources)} resources from Wiz")

        return resources

    async def update_issue_status(
        self,
        issue_id: str,
        status: WizIssueStatus,
        note: Optional[str] = None
    ) -> bool:
        """
        Update issue status in Wiz.

        Args:
            issue_id: Wiz issue ID
            status: New status
            note: Optional note

        Returns:
            True if successful
        """
        query = """
        mutation UpdateIssueStatus($issueId: ID!, $status: IssueStatus!, $note: String) {
            updateIssue(input: {
                id: $issueId
                status: $status
                note: $note
            }) {
                issue {
                    id
                    status
                }
            }
        }
        """

        variables = {
            "issueId": issue_id,
            "status": status.value,
            "note": note
        }

        result = await self._execute_query(query, variables)
        if result and "updateIssue" in result:
            logger.info(f"Updated Wiz issue {issue_id} to status {status.value}")
            return True

        return False

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


class WizIntegration:
    """High-level Wiz integration with caching and enrichment"""

    def __init__(self, config: Optional[VaulyticaConfig] = None):
        """Initialize Wiz integration"""
        if config is None:
            config = get_config()

        self.config = config
        self.client = WizAPIClient(
            client_id=config.wiz_client_id,
            client_secret=config.wiz_client_secret,
            region=config.wiz_region
        )

        # Cache
        self.vulnerability_cache: Dict[str, WizVulnerability] = {}
        self.issue_cache: Dict[str, WizIssue] = {}
        self.resource_cache: Dict[str, WizResource] = {}

        logger.info("Wiz integration initialized")

    async def get_critical_vulnerabilities(self) -> List[WizVulnerability]:
        """Get all critical and high severity vulnerabilities"""
        return await self.client.get_vulnerabilities(
            severity=[WizSeverity.CRITICAL, WizSeverity.HIGH],
            limit=500
        )

    async def get_exploitable_vulnerabilities(self) -> List[WizVulnerability]:
        """Get vulnerabilities with known exploits"""
        return await self.client.get_vulnerabilities(
            has_exploit=True,
            limit=500
        )

    async def get_open_issues(self) -> List[WizIssue]:
        """Get all open security issues"""
        return await self.client.get_issues(
            status=[WizIssueStatus.OPEN, WizIssueStatus.IN_PROGRESS],
            limit=500
        )

    async def resolve_issue(self, issue_id: str, note: str = "Resolved by Vaulytica") -> bool:
        """Mark issue as resolved"""
        return await self.client.update_issue_status(
            issue_id=issue_id,
            status=WizIssueStatus.RESOLVED,
            note=note
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics"""
        return self.client.get_statistics()


# Global instance
_wiz_integration: Optional[WizIntegration] = None


def get_wiz_integration(config: Optional[VaulyticaConfig] = None) -> WizIntegration:
    """Get or create global Wiz integration instance"""
    global _wiz_integration

    if _wiz_integration is None:
        _wiz_integration = WizIntegration(config)

    return _wiz_integration

