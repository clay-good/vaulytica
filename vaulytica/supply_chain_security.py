"""
Supply Chain Security, SBOM Management & Security GRC Platform (v0.28.0).

This module provides comprehensive supply chain security, software bill of materials (SBOM)
management, and security governance, risk & compliance (GRC) capabilities.

Features:
- Supply chain security scanning and vulnerability tracking
- SBOM generation and management (CycloneDX, SPDX)
- Security GRC platform with governance, risk, and compliance
- Policy-as-code engine with validation and enforcement
- Risk management system with assessment and treatment
"""

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class DependencyType(Enum):
    """Dependency type."""
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    DEV = "dev"
    PEER = "peer"
    OPTIONAL = "optional"


class LicenseType(Enum):
    """License type classification."""
    PERMISSIVE = "permissive"  # MIT, Apache, BSD
    COPYLEFT = "copyleft"  # GPL, LGPL, AGPL
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class SupplyChainThreat(Enum):
    """Supply chain threat types."""
    MALICIOUS_PACKAGE = "malicious_package"
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    COMPROMISED_MAINTAINER = "compromised_maintainer"
    BACKDOOR = "backdoor"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"


class SBOMFormat(Enum):
    """SBOM format standards."""
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    SWID = "swid"


class PolicyType(Enum):
    """Policy type."""
    SECURITY = "security"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    DATA_GOVERNANCE = "data_governance"


class PolicySeverity(Enum):
    """Policy violation severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskLevel(Enum):
    """Risk level classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class RiskStatus(Enum):
    """Risk status."""
    IDENTIFIED = "identified"
    ASSESSED = "assessed"
    TREATED = "treated"
    ACCEPTED = "accepted"
    MITIGATED = "mitigated"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


class ComplianceFramework(Enum):
    """Compliance frameworks."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_CSF = "nist_cs"
    CIS = "cis"
    COBIT = "cobit"


class ControlStatus(Enum):
    """Control implementation status."""
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class Severity(Enum):
    """Severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class Dependency:
    """Software dependency."""
    name: str
    version: str
    dependency_type: DependencyType
    ecosystem: str  # npm, pypi, maven, nuget, etc.
    license: str
    license_type: LicenseType
    vulnerabilities: List[str] = field(default_factory=list)
    transitive_dependencies: List[str] = field(default_factory=list)
    maintainers: List[str] = field(default_factory=list)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    download_count: int = 0
    risk_score: float = 0.0  # 0-10


@dataclass
class SupplyChainScanResult:
    """Supply chain security scan result."""
    scan_id: str
    project_name: str
    timestamp: datetime
    dependencies_scanned: int
    vulnerabilities_found: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    license_issues: int
    supply_chain_threats: List[SupplyChainThreat]
    risk_score: float  # 0-10
    recommendations: List[str]


@dataclass
class SBOMComponent:
    """SBOM component."""
    component_id: str
    name: str
    version: str
    type: str  # library, application, framework, etc.
    supplier: str
    license: str
    purl: str  # Package URL
    cpe: str  # Common Platform Enumeration
    hashes: Dict[str, str]  # algorithm: hash
    dependencies: List[str]
    vulnerabilities: List[str]


@dataclass
class SBOM:
    """Software Bill of Materials."""
    sbom_id: str
    format: SBOMFormat
    spec_version: str
    timestamp: datetime
    project_name: str
    project_version: str
    components: List[SBOMComponent]
    metadata: Dict[str, Any]


@dataclass
class Policy:
    """Security/compliance policy."""
    policy_id: str
    name: str
    description: str
    policy_type: PolicyType
    severity: PolicySeverity
    rules: List[Dict[str, Any]]
    enabled: bool
    created_at: datetime
    updated_at: datetime
    owner: str
    tags: List[str]


@dataclass
class PolicyViolation:
    """Policy violation."""
    violation_id: str
    policy_id: str
    resource_id: str
    resource_type: str
    severity: PolicySeverity
    description: str
    detected_at: datetime
    resolved_at: Optional[datetime]
    status: str  # open, resolved, accepted
    remediation: str


@dataclass
class Risk:
    """Security risk."""
    risk_id: str
    title: str
    description: str
    category: str
    risk_level: RiskLevel
    likelihood: float  # 0.0-1.0
    impact: float  # 0.0-1.0
    risk_score: float  # likelihood * impact * 10
    status: RiskStatus
    owner: str
    identified_at: datetime
    treatment_plan: str
    residual_risk: float
    controls: List[str]


@dataclass
class ComplianceControl:
    """Compliance control."""
    control_id: str
    framework: ComplianceFramework
    control_number: str
    title: str
    description: str
    status: ControlStatus
    evidence: List[str]
    last_assessed: datetime
    next_assessment: datetime
    owner: str
    automated: bool


@dataclass
class AuditLog:
    """Audit log entry."""
    log_id: str
    timestamp: datetime
    user: str
    action: str
    resource_type: str
    resource_id: str
    details: Dict[str, Any]
    ip_address: str
    result: str  # success, failure


# ============================================================================
# Supply Chain Security Scanner
# ============================================================================

class SupplyChainSecurityScanner:
    """Supply chain security scanner."""

    def __init__(self):
        self.dependencies: Dict[str, Dependency] = {}
        self.scan_results: List[SupplyChainScanResult] = []
        self.threat_patterns: Dict[str, List[str]] = {
            "typosquatting": ["similar_name", "common_typo"],
            "malicious": ["suspicious_code", "obfuscation", "network_calls"],
            "compromised": ["unusual_update", "maintainer_change"]
        }
        self.statistics = {
            "scans_performed": 0,
            "dependencies_analyzed": 0,
            "vulnerabilities_found": 0,
            "threats_detected": 0,
            "license_issues": 0
        }

    async def scan_dependencies(
        self,
        project_name: str,
        dependencies: List[Dict[str, Any]]
    ) -> SupplyChainScanResult:
        """Scan project dependencies for security issues."""
        logger.info(f"Scanning dependencies for project: {project_name}")

        scan_id = f"scan-{hashlib.md5(f'{project_name}{datetime.utcnow()}'.encode()).hexdigest()[:12]}"
        vulnerabilities = []
        license_issues = 0
        threats = []

        # Analyze each dependency
        for dep_data in dependencies:
            dep = Dependency(
                name=dep_data.get("name", "unknown"),
                version=dep_data.get("version", "0.0.0"),
                dependency_type=DependencyType(dep_data.get("type", "direct")),
                ecosystem=dep_data.get("ecosystem", "unknown"),
                license=dep_data.get("license", "unknown"),
                license_type=self._classify_license(dep_data.get("license", "unknown")),
                vulnerabilities=dep_data.get("vulnerabilities", []),
                transitive_dependencies=dep_data.get("transitive", [])
            )

            # Check for vulnerabilities
            if dep.vulnerabilities:
                vulnerabilities.extend(dep.vulnerabilities)
                self.statistics["vulnerabilities_found"] += len(dep.vulnerabilities)

            # Check license compliance
            if dep.license_type == LicenseType.UNKNOWN or dep.license_type == LicenseType.PROPRIETARY:
                license_issues += 1
                self.statistics["license_issues"] += 1

            # Detect supply chain threats
            detected_threats = await self._detect_threats(dep)
            threats.extend(detected_threats)

            self.dependencies[f"{dep.name}@{dep.version}"] = dep
            self.statistics["dependencies_analyzed"] += 1

        # Calculate severity counts
        critical_count = sum(1 for v in vulnerabilities if "critical" in v.lower())
        high_count = sum(1 for v in vulnerabilities if "high" in v.lower())
        medium_count = sum(1 for v in vulnerabilities if "medium" in v.lower())
        low_count = len(vulnerabilities) - critical_count - high_count - medium_count

        # Calculate risk score
        risk_score = min(10.0, (critical_count * 2.0 + high_count * 1.0 + medium_count * 0.5 + len(threats) * 1.5))

        result = SupplyChainScanResult(
            scan_id=scan_id,
            project_name=project_name,
            timestamp=datetime.utcnow(),
            dependencies_scanned=len(dependencies),
            vulnerabilities_found=len(vulnerabilities),
            critical_vulnerabilities=critical_count,
            high_vulnerabilities=high_count,
            medium_vulnerabilities=medium_count,
            low_vulnerabilities=low_count,
            license_issues=license_issues,
            supply_chain_threats=threats,
            risk_score=risk_score,
            recommendations=self._generate_recommendations(critical_count, high_count, threats)
        )

        self.scan_results.append(result)
        self.statistics["scans_performed"] += 1

        return result

    def _classify_license(self, license_name: str) -> LicenseType:
        """Classify license type."""
        license_lower = license_name.lower()

        permissive = ["mit", "apache", "bsd", "isc", "unlicense"]
        copyleft = ["gpl", "lgpl", "agpl", "mpl", "epl"]

        for perm in permissive:
            if perm in license_lower:
                return LicenseType.PERMISSIVE

        for copy in copyleft:
            if copy in license_lower:
                return LicenseType.COPYLEFT

        if "proprietary" in license_lower:
            return LicenseType.PROPRIETARY

        return LicenseType.UNKNOWN

    async def _detect_threats(self, dependency: Dependency) -> List[SupplyChainThreat]:
        """Detect supply chain threats."""
        threats = []

        # Detect typosquatting (simplified)
        if len(dependency.name) < 3 or any(char.isdigit() for char in dependency.name[-2:]):
            threats.append(SupplyChainThreat.TYPOSQUATTING)
            self.statistics["threats_detected"] += 1

        # Detect vulnerable dependencies
        if dependency.vulnerabilities:
            threats.append(SupplyChainThreat.VULNERABLE_DEPENDENCY)
            self.statistics["threats_detected"] += 1

        # Detect suspicious packages (low download count, recent creation)
        if dependency.download_count < 100:
            threats.append(SupplyChainThreat.MALICIOUS_PACKAGE)
            self.statistics["threats_detected"] += 1

        return threats

    def _generate_recommendations(
        self,
        critical: int,
        high: int,
        threats: List[SupplyChainThreat]
    ) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        if critical > 0:
            recommendations.append(f"Immediately update {critical} dependencies with critical vulnerabilities")

        if high > 0:
            recommendations.append(f"Update {high} dependencies with high severity vulnerabilities")

        if SupplyChainThreat.TYPOSQUATTING in threats:
            recommendations.append("Review dependencies for potential typosquatting attacks")

        if SupplyChainThreat.MALICIOUS_PACKAGE in threats:
            recommendations.append("Investigate suspicious packages with low download counts")

        recommendations.append("Enable automated dependency scanning in CI/CD pipeline")

        return recommendations

    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return self.statistics.copy()


# ============================================================================
# SBOM Management System
# ============================================================================

class SBOMManager:
    """Software Bill of Materials management system."""

    def __init__(self):
        self.sboms: Dict[str, SBOM] = {}
        self.components: Dict[str, SBOMComponent] = {}
        self.statistics = {
            "sboms_generated": 0,
            "components_tracked": 0,
            "vulnerabilities_correlated": 0,
            "license_violations": 0
        }

    async def generate_sbom(
        self,
        project_name: str,
        project_version: str,
        dependencies: List[Dependency],
        format: SBOMFormat = SBOMFormat.CYCLONEDX
    ) -> SBOM:
        """Generate SBOM from dependencies."""
        logger.info(f"Generating {format.value} SBOM for {project_name}")

        sbom_id = f"sbom-{hashlib.md5(f'{project_name}{project_version}'.encode()).hexdigest()[:12]}"
        components = []

        for dep in dependencies:
            component = SBOMComponent(
                component_id=f"comp-{hashlib.md5(f'{dep.name}{dep.version}'.encode()).hexdigest()[:12]}",
                name=dep.name,
                version=dep.version,
                type="library",
                supplier=dep.maintainers[0] if dep.maintainers else "unknown",
                license=dep.license,
                purl=f"pkg:{dep.ecosystem}/{dep.name}@{dep.version}",
                cpe=f"cpe:2.3:a:{dep.name}:{dep.version}",
                hashes={"sha256": hashlib.sha256(f"{dep.name}{dep.version}".encode()).hexdigest()},
                dependencies=dep.transitive_dependencies,
                vulnerabilities=dep.vulnerabilities
            )

            components.append(component)
            self.components[component.component_id] = component
            self.statistics["components_tracked"] += 1

        sbom = SBOM(
            sbom_id=sbom_id,
            format=format,
            spec_version="1.4" if format == SBOMFormat.CYCLONEDX else "2.3",
            timestamp=datetime.utcnow(),
            project_name=project_name,
            project_version=project_version,
            components=components,
            metadata={
                "tool": "Vaulytica v0.28.0",
                "component_count": len(components),
                "vulnerability_count": sum(len(c.vulnerabilities) for c in components)
            }
        )

        self.sboms[sbom_id] = sbom
        self.statistics["sboms_generated"] += 1

        return sbom

    async def export_sbom(self, sbom_id: str, format: str = "json") -> Dict[str, Any]:
        """Export SBOM in specified format."""
        if sbom_id not in self.sboms:
            raise ValueError(f"SBOM not found: {sbom_id}")

        sbom = self.sboms[sbom_id]

        if sbom.format == SBOMFormat.CYCLONEDX:
            return self._export_cyclonedx(sbom)
        elif sbom.format == SBOMFormat.SPDX:
            return self._export_spdx(sbom)
        else:
            raise ValueError(f"Unsupported SBOM format: {sbom.format}")

    def _export_cyclonedx(self, sbom: SBOM) -> Dict[str, Any]:
        """Export SBOM in CycloneDX format."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": sbom.spec_version,
            "serialNumber": f"urn:uuid:{sbom.sbom_id}",
            "version": 1,
            "metadata": {
                "timestamp": sbom.timestamp.isoformat(),
                "component": {
                    "name": sbom.project_name,
                    "version": sbom.project_version,
                    "type": "application"
                }
            },
            "components": [
                {
                    "type": comp.type,
                    "name": comp.name,
                    "version": comp.version,
                    "purl": comp.purl,
                    "licenses": [{"license": {"id": comp.license}}],
                    "hashes": [{"alg": alg, "content": hash_val} for alg, hash_val in comp.hashes.items()]
                }
                for comp in sbom.components
            ]
        }

    def _export_spdx(self, sbom: SBOM) -> Dict[str, Any]:
        """Export SBOM in SPDX format."""
        return {
            "spdxVersion": f"SPDX-{sbom.spec_version}",
            "dataLicense": "CC0-1.0",
            "SPDXID": f"SPDXRef-{sbom.sbom_id}",
            "name": sbom.project_name,
            "documentNamespace": f"https://example.com",
            "creationInfo": {
                "created": sbom.timestamp.isoformat(),
                "creators": ["Tool: Vaulytica-0.28.0"]
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-{comp.component_id}",
                    "name": comp.name,
                    "versionInfo": comp.version,
                    "licenseConcluded": comp.license,
                    "externalRefs": [{"referenceType": "purl", "referenceLocator": comp.purl}]
                }
                for comp in sbom.components
            ]
        }

    async def correlate_vulnerabilities(self, sbom_id: str) -> Dict[str, Any]:
        """Correlate SBOM components with known vulnerabilities."""
        if sbom_id not in self.sboms:
            raise ValueError(f"SBOM not found: {sbom_id}")

        sbom = self.sboms[sbom_id]
        vulnerable_components = []

        for component in sbom.components:
            if component.vulnerabilities:
                vulnerable_components.append({
                    "component": component.name,
                    "version": component.version,
                    "vulnerabilities": component.vulnerabilities,
                    "severity": "critical" if any("critical" in v.lower() for v in component.vulnerabilities) else "high"
                })
                self.statistics["vulnerabilities_correlated"] += len(component.vulnerabilities)

        return {
            "sbom_id": sbom_id,
            "total_components": len(sbom.components),
            "vulnerable_components": len(vulnerable_components),
            "total_vulnerabilities": sum(len(c["vulnerabilities"]) for c in vulnerable_components),
            "details": vulnerable_components
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get SBOM manager statistics."""
        return self.statistics.copy()


# ============================================================================
# Policy Engine
# ============================================================================

class PolicyEngine:
    """Policy-as-code engine."""

    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.violations: List[PolicyViolation] = []
        self.statistics = {
            "policies_created": 0,
            "policies_evaluated": 0,
            "violations_detected": 0,
            "violations_resolved": 0
        }

    async def create_policy(self, policy: Policy) -> Dict[str, Any]:
        """Create a new policy."""
        logger.info(f"Creating policy: {policy.name}")

        self.policies[policy.policy_id] = policy
        self.statistics["policies_created"] += 1

        return {
            "policy_id": policy.policy_id,
            "name": policy.name,
            "type": policy.policy_type.value,
            "severity": policy.severity.value,
            "enabled": policy.enabled,
            "rules": len(policy.rules)
        }

    async def evaluate_policy(
        self,
        policy_id: str,
        resource: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate policy against a resource."""
        if policy_id not in self.policies:
            raise ValueError(f"Policy not found: {policy_id}")

        policy = self.policies[policy_id]

        if not policy.enabled:
            return {"status": "skipped", "reason": "policy disabled"}

        violations = []

        # Evaluate each rule
        for rule in policy.rules:
            if not self._evaluate_rule(rule, resource):
                violation = PolicyViolation(
                    violation_id=f"viol-{uuid4().hex[:12]}",
                    policy_id=policy_id,
                    resource_id=resource.get("id", "unknown"),
                    resource_type=resource.get("type", "unknown"),
                    severity=policy.severity,
                    description=f"Policy violation: {rule.get('description', 'Rule failed')}",
                    detected_at=datetime.utcnow(),
                    resolved_at=None,
                    status="open",
                    remediation=rule.get("remediation", "Review and fix the violation")
                )
                violations.append(violation)
                self.violations.append(violation)
                self.statistics["violations_detected"] += 1

        self.statistics["policies_evaluated"] += 1

        return {
            "policy_id": policy_id,
            "resource_id": resource.get("id"),
            "compliant": len(violations) == 0,
            "violations": len(violations),
            "details": [
                {
                    "violation_id": v.violation_id,
                    "severity": v.severity.value,
                    "description": v.description,
                    "remediation": v.remediation
                }
                for v in violations
            ]
        }

    def _evaluate_rule(self, rule: Dict[str, Any], resource: Dict[str, Any]) -> bool:
        """Evaluate a single rule."""
        # Simplified rule evaluation
        field = rule.get("field")
        operator = rule.get("operator")
        value = rule.get("value")

        if field not in resource:
            return False

        resource_value = resource[field]

        if operator == "equals":
            return resource_value == value
        elif operator == "not_equals":
            return resource_value != value
        elif operator == "contains":
            return value in str(resource_value)
        elif operator == "greater_than":
            return float(resource_value) > float(value)
        elif operator == "less_than":
            return float(resource_value) < float(value)

        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        return self.statistics.copy()


# ============================================================================
# Risk Management System
# ============================================================================

class RiskManagementSystem:
    """Risk management system."""

    def __init__(self):
        self.risks: Dict[str, Risk] = {}
        self.statistics = {
            "risks_identified": 0,
            "risks_assessed": 0,
            "risks_mitigated": 0,
            "critical_risks": 0,
            "high_risks": 0
        }

    async def identify_risk(self, risk: Risk) -> Dict[str, Any]:
        """Identify a new risk."""
        logger.info(f"Identifying risk: {risk.title}")

        # Calculate risk score
        risk.risk_score = risk.likelihood * risk.impact * 10

        # Determine risk level
        if risk.risk_score >= 8.0:
            risk.risk_level = RiskLevel.CRITICAL
            self.statistics["critical_risks"] += 1
        elif risk.risk_score >= 6.0:
            risk.risk_level = RiskLevel.HIGH
            self.statistics["high_risks"] += 1
        elif risk.risk_score >= 4.0:
            risk.risk_level = RiskLevel.MEDIUM
        elif risk.risk_score >= 2.0:
            risk.risk_level = RiskLevel.LOW
        else:
            risk.risk_level = RiskLevel.NEGLIGIBLE

        self.risks[risk.risk_id] = risk
        self.statistics["risks_identified"] += 1

        return {
            "risk_id": risk.risk_id,
            "title": risk.title,
            "risk_level": risk.risk_level.value,
            "risk_score": risk.risk_score,
            "likelihood": risk.likelihood,
            "impact": risk.impact,
            "status": risk.status.value
        }

    async def assess_risk(self, risk_id: str) -> Dict[str, Any]:
        """Assess an identified risk."""
        if risk_id not in self.risks:
            raise ValueError(f"Risk not found: {risk_id}")

        risk = self.risks[risk_id]
        risk.status = RiskStatus.ASSESSED
        self.statistics["risks_assessed"] += 1

        # Generate treatment recommendations
        recommendations = []
        if risk.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("Immediate action required")
            recommendations.append("Assign dedicated resources for mitigation")
            recommendations.append("Implement compensating controls")
        elif risk.risk_level == RiskLevel.MEDIUM:
            recommendations.append("Plan mitigation within 30 days")
            recommendations.append("Monitor risk indicators")
        else:
            recommendations.append("Accept risk or implement low-cost controls")

        return {
            "risk_id": risk_id,
            "assessment_status": "completed",
            "risk_level": risk.risk_level.value,
            "risk_score": risk.risk_score,
            "recommendations": recommendations
        }

    async def treat_risk(
        self,
        risk_id: str,
        treatment_type: str,
        treatment_plan: str
    ) -> Dict[str, Any]:
        """Apply risk treatment."""
        if risk_id not in self.risks:
            raise ValueError(f"Risk not found: {risk_id}")

        risk = self.risks[risk_id]
        risk.treatment_plan = treatment_plan

        if treatment_type == "mitigate":
            risk.status = RiskStatus.MITIGATED
            risk.residual_risk = risk.risk_score * 0.3  # 70% reduction
            self.statistics["risks_mitigated"] += 1
        elif treatment_type == "accept":
            risk.status = RiskStatus.ACCEPTED
            risk.residual_risk = risk.risk_score
        elif treatment_type == "transfer":
            risk.status = RiskStatus.TRANSFERRED
            risk.residual_risk = risk.risk_score * 0.5  # 50% reduction

        return {
            "risk_id": risk_id,
            "treatment_type": treatment_type,
            "original_risk_score": risk.risk_score,
            "residual_risk": risk.residual_risk,
            "status": risk.status.value
        }

    async def generate_risk_report(self) -> Dict[str, Any]:
        """Generate comprehensive risk report."""
        total_risks = len(self.risks)

        risks_by_level = {
            "critical": sum(1 for r in self.risks.values() if r.risk_level == RiskLevel.CRITICAL),
            "high": sum(1 for r in self.risks.values() if r.risk_level == RiskLevel.HIGH),
            "medium": sum(1 for r in self.risks.values() if r.risk_level == RiskLevel.MEDIUM),
            "low": sum(1 for r in self.risks.values() if r.risk_level == RiskLevel.LOW),
            "negligible": sum(1 for r in self.risks.values() if r.risk_level == RiskLevel.NEGLIGIBLE)
        }

        risks_by_status = {
            "identified": sum(1 for r in self.risks.values() if r.status == RiskStatus.IDENTIFIED),
            "assessed": sum(1 for r in self.risks.values() if r.status == RiskStatus.ASSESSED),
            "treated": sum(1 for r in self.risks.values() if r.status == RiskStatus.TREATED),
            "mitigated": sum(1 for r in self.risks.values() if r.status == RiskStatus.MITIGATED),
            "accepted": sum(1 for r in self.risks.values() if r.status == RiskStatus.ACCEPTED)
        }

        # Calculate average risk score
        avg_risk_score = sum(r.risk_score for r in self.risks.values()) / total_risks if total_risks > 0 else 0

        # Top risks
        top_risks = sorted(self.risks.values(), key=lambda r: r.risk_score, reverse=True)[:5]

        return {
            "report_id": f"risk-report-{uuid4().hex[:12]}",
            "timestamp": datetime.utcnow().isoformat(),
            "total_risks": total_risks,
            "average_risk_score": round(avg_risk_score, 2),
            "risks_by_level": risks_by_level,
            "risks_by_status": risks_by_status,
            "top_risks": [
                {
                    "risk_id": r.risk_id,
                    "title": r.title,
                    "risk_level": r.risk_level.value,
                    "risk_score": r.risk_score,
                    "status": r.status.value
                }
                for r in top_risks
            ]
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get risk management statistics."""
        return self.statistics.copy()


# ============================================================================
# Security GRC Platform
# ============================================================================

class SecurityGRCPlatform:
    """Security Governance, Risk & Compliance platform."""

    def __init__(self):
        self.controls: Dict[str, ComplianceControl] = {}
        self.audit_logs: List[AuditLog] = []
        self.frameworks: Dict[ComplianceFramework, int] = {}
        self.statistics = {
            "controls_implemented": 0,
            "controls_assessed": 0,
            "frameworks_tracked": 0,
            "audit_logs_created": 0,
            "compliance_score": 0.0
        }

    async def implement_control(self, control: ComplianceControl) -> Dict[str, Any]:
        """Implement a compliance control."""
        logger.info(f"Implementing control: {control.control_number}")

        self.controls[control.control_id] = control

        if control.status == ControlStatus.IMPLEMENTED:
            self.statistics["controls_implemented"] += 1

        # Track framework
        if control.framework not in self.frameworks:
            self.frameworks[control.framework] = 0
            self.statistics["frameworks_tracked"] += 1
        self.frameworks[control.framework] += 1

        # Create audit log
        await self._create_audit_log(
            user="system",
            action="implement_control",
            resource_type="compliance_control",
            resource_id=control.control_id,
            details={"control_number": control.control_number, "framework": control.framework.value}
        )

        return {
            "control_id": control.control_id,
            "control_number": control.control_number,
            "framework": control.framework.value,
            "status": control.status.value,
            "automated": control.automated
        }

    async def assess_control(self, control_id: str) -> Dict[str, Any]:
        """Assess a compliance control."""
        if control_id not in self.controls:
            raise ValueError(f"Control not found: {control_id}")

        control = self.controls[control_id]
        control.last_assessed = datetime.utcnow()
        control.next_assessment = datetime.utcnow() + timedelta(days=90)
        self.statistics["controls_assessed"] += 1

        # Simulate assessment result
        assessment_result = {
            "control_id": control_id,
            "control_number": control.control_number,
            "status": control.status.value,
            "evidence_count": len(control.evidence),
            "last_assessed": control.last_assessed.isoformat(),
            "next_assessment": control.next_assessment.isoformat(),
            "findings": []
        }

        if control.status != ControlStatus.IMPLEMENTED:
            assessment_result["findings"].append({
                "severity": "high",
                "description": f"Control {control.control_number} is not fully implemented"
            })

        return assessment_result

    async def calculate_compliance_score(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Calculate compliance score for a framework."""
        framework_controls = [c for c in self.controls.values() if c.framework == framework]

        if not framework_controls:
            return {
                "framework": framework.value,
                "compliance_score": 0.0,
                "total_controls": 0,
                "implemented": 0,
                "partial": 0,
                "not_implemented": 0
            }

        implemented = sum(1 for c in framework_controls if c.status == ControlStatus.IMPLEMENTED)
        partial = sum(1 for c in framework_controls if c.status == ControlStatus.PARTIAL)
        not_implemented = sum(1 for c in framework_controls if c.status == ControlStatus.NOT_IMPLEMENTED)

        # Calculate score: implemented = 100%, partial = 50%, not_implemented = 0%
        score = ((implemented * 1.0 + partial * 0.5) / len(framework_controls)) * 100

        self.statistics["compliance_score"] = score

        return {
            "framework": framework.value,
            "compliance_score": round(score, 2),
            "total_controls": len(framework_controls),
            "implemented": implemented,
            "partial": partial,
            "not_implemented": not_implemented,
            "compliance_level": "high" if score >= 80 else "medium" if score >= 60 else "low"
        }

    async def _create_audit_log(
        self,
        user: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Dict[str, Any],
        ip_address: str = "127.0.0.1",
        result: str = "success"
    ) -> AuditLog:
        """Create an audit log entry."""
        log = AuditLog(
            log_id=f"audit-{uuid4().hex[:12]}",
            timestamp=datetime.utcnow(),
            user=user,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            result=result
        )

        self.audit_logs.append(log)
        self.statistics["audit_logs_created"] += 1

        return log

    async def get_audit_trail(
        self,
        resource_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get audit trail."""
        filtered_logs = self.audit_logs

        if resource_id:
            filtered_logs = [log for log in filtered_logs if log.resource_id == resource_id]

        if start_date:
            filtered_logs = [log for log in filtered_logs if log.timestamp >= start_date]

        if end_date:
            filtered_logs = [log for log in filtered_logs if log.timestamp <= end_date]

        return [
            {
                "log_id": log.log_id,
                "timestamp": log.timestamp.isoformat(),
                "user": log.user,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "result": log.result
            }
            for log in filtered_logs
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get GRC platform statistics."""
        return self.statistics.copy()


# ============================================================================
# Supply Chain & GRC Orchestrator
# ============================================================================

class SupplyChainGRCOrchestrator:
    """Unified orchestrator for supply chain security and GRC."""

    def __init__(self):
        self.scanner = SupplyChainSecurityScanner()
        self.sbom_manager = SBOMManager()
        self.policy_engine = PolicyEngine()
        self.risk_management = RiskManagementSystem()
        self.grc_platform = SecurityGRCPlatform()

    async def perform_comprehensive_assessment(
        self,
        project_name: str,
        project_version: str,
        dependencies: List[Dict[str, Any]],
        framework: ComplianceFramework = ComplianceFramework.SOC2
    ) -> Dict[str, Any]:
        """Perform comprehensive supply chain and GRC assessment."""
        logger.info(f"Performing comprehensive assessment for {project_name}")

        start_time = datetime.utcnow()

        # 1. Scan dependencies
        scan_result = await self.scanner.scan_dependencies(project_name, dependencies)

        # 2. Generate SBOM
        dep_objects = [
            Dependency(
                name=d.get("name", "unknown"),
                version=d.get("version", "0.0.0"),
                dependency_type=DependencyType(d.get("type", "direct")),
                ecosystem=d.get("ecosystem", "unknown"),
                license=d.get("license", "unknown"),
                license_type=self.scanner._classify_license(d.get("license", "unknown")),
                vulnerabilities=d.get("vulnerabilities", []),
                transitive_dependencies=d.get("transitive", [])
            )
            for d in dependencies
        ]
        sbom = await self.sbom_manager.generate_sbom(project_name, project_version, dep_objects)

        # 3. Correlate vulnerabilities
        vuln_correlation = await self.sbom_manager.correlate_vulnerabilities(sbom.sbom_id)

        # 4. Calculate compliance score
        compliance = await self.grc_platform.calculate_compliance_score(framework)

        # 5. Generate risk report
        risk_report = await self.risk_management.generate_risk_report()

        duration = (datetime.utcnow() - start_time).total_seconds()

        return {
            "assessment_id": f"assessment-{uuid4().hex[:12]}",
            "project_name": project_name,
            "project_version": project_version,
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "supply_chain_security": {
                "scan_id": scan_result.scan_id,
                "dependencies_scanned": scan_result.dependencies_scanned,
                "vulnerabilities_found": scan_result.vulnerabilities_found,
                "critical": scan_result.critical_vulnerabilities,
                "high": scan_result.high_vulnerabilities,
                "license_issues": scan_result.license_issues,
                "threats_detected": len(scan_result.supply_chain_threats),
                "risk_score": scan_result.risk_score
            },
            "sbom": {
                "sbom_id": sbom.sbom_id,
                "format": sbom.format.value,
                "components": len(sbom.components),
                "vulnerable_components": vuln_correlation["vulnerable_components"]
            },
            "compliance": compliance,
            "risk_management": {
                "total_risks": risk_report["total_risks"],
                "average_risk_score": risk_report["average_risk_score"],
                "critical_risks": risk_report["risks_by_level"]["critical"],
                "high_risks": risk_report["risks_by_level"]["high"]
            },
            "recommendations": scan_result.recommendations
        }

    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all modules."""
        return {
            "supply_chain_scanner": self.scanner.get_statistics(),
            "sbom_manager": self.sbom_manager.get_statistics(),
            "policy_engine": self.policy_engine.get_statistics(),
            "risk_management": self.risk_management.get_statistics(),
            "grc_platform": self.grc_platform.get_statistics()
        }


# ============================================================================
# Singleton Instances
# ============================================================================

_scanner_instance = None
_sbom_manager_instance = None
_policy_engine_instance = None
_risk_management_instance = None
_grc_platform_instance = None
_orchestrator_instance = None


def get_supply_chain_scanner() -> SupplyChainSecurityScanner:
    """Get supply chain scanner singleton."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = SupplyChainSecurityScanner()
    return _scanner_instance


def get_sbom_manager() -> SBOMManager:
    """Get SBOM manager singleton."""
    global _sbom_manager_instance
    if _sbom_manager_instance is None:
        _sbom_manager_instance = SBOMManager()
    return _sbom_manager_instance


def get_policy_engine() -> PolicyEngine:
    """Get policy engine singleton."""
    global _policy_engine_instance
    if _policy_engine_instance is None:
        _policy_engine_instance = PolicyEngine()
    return _policy_engine_instance


def get_risk_management() -> RiskManagementSystem:
    """Get risk management system singleton."""
    global _risk_management_instance
    if _risk_management_instance is None:
        _risk_management_instance = RiskManagementSystem()
    return _risk_management_instance


def get_grc_platform() -> SecurityGRCPlatform:
    """Get GRC platform singleton."""
    global _grc_platform_instance
    if _grc_platform_instance is None:
        _grc_platform_instance = SecurityGRCPlatform()
    return _grc_platform_instance


def get_supply_chain_grc_orchestrator() -> SupplyChainGRCOrchestrator:
    """Get supply chain & GRC orchestrator singleton."""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = SupplyChainGRCOrchestrator()
    return _orchestrator_instance
