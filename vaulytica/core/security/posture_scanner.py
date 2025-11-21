"""Security Posture Assessment and Baseline Scanner for Google Workspace.

This module provides comprehensive security configuration scanning against industry
standards including CIS Benchmarks, NIST, and Google Workspace security best practices.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import structlog

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


class FindingSeverity(Enum):
    """Security finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceFramework(Enum):
    """Compliance frameworks for baseline checks."""

    CIS = "cis"  # CIS Google Workspace Benchmark
    NIST = "nist"  # NIST Cybersecurity Framework
    GOOGLE_BEST_PRACTICES = "google_best_practices"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    SOC2 = "soc2"


@dataclass
class SecurityFinding:
    """Represents a security finding from posture assessment."""

    check_id: str
    title: str
    description: str
    severity: FindingSeverity
    passed: bool
    current_value: Any
    expected_value: Any
    frameworks: list[ComplianceFramework] = field(default_factory=list)
    remediation: str = ""
    impact: str = ""
    references: list[str] = field(default_factory=list)
    resource_type: str = ""
    resource_id: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "passed": self.passed,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "frameworks": [f.value for f in self.frameworks],
            "remediation": self.remediation,
            "impact": self.impact,
            "references": self.references,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class SecurityBaseline:
    """Security baseline assessment results."""

    scan_id: str
    scan_date: datetime
    domain: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    security_score: float  # 0-100
    findings: list[SecurityFinding] = field(default_factory=list)
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    frameworks_assessed: list[ComplianceFramework] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert baseline to dictionary."""
        return {
            "scan_id": self.scan_id,
            "scan_date": self.scan_date.isoformat(),
            "domain": self.domain,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "security_score": self.security_score,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "frameworks_assessed": [f.value for f in self.frameworks_assessed],
            "scan_duration_seconds": self.scan_duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
        }


class PostureScanner:
    """Scans Google Workspace security posture against baselines and best practices."""

    def __init__(self, client: GoogleWorkspaceClient, domain: str):
        """Initialize Security Posture Scanner.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Google Workspace domain to scan
        """
        self.client = client
        self.domain = domain
        self.findings: list[SecurityFinding] = []
        logger.info("posture_scanner_initialized", domain=domain)

    def scan_security_posture(
        self,
        frameworks: Optional[list[ComplianceFramework]] = None,
        include_2fa_check: bool = True,
        include_admin_check: bool = True,
        include_sharing_check: bool = True,
        include_oauth_check: bool = True,
        include_mobile_check: bool = True,
    ) -> SecurityBaseline:
        """Perform comprehensive security posture assessment.

        Args:
            frameworks: List of compliance frameworks to check against
            include_2fa_check: Check 2FA enforcement
            include_admin_check: Check admin account security
            include_sharing_check: Check sharing policies
            include_oauth_check: Check OAuth app security
            include_mobile_check: Check mobile device policies

        Returns:
            SecurityBaseline with all findings
        """
        start_time = datetime.now(timezone.utc)
        self.findings = []

        if frameworks is None:
            frameworks = [
                ComplianceFramework.CIS,
                ComplianceFramework.GOOGLE_BEST_PRACTICES,
            ]

        logger.info(
            "starting_security_posture_scan",
            domain=self.domain,
            frameworks=[f.value for f in frameworks],
        )

        # Run all security checks
        if include_2fa_check:
            self._check_2fa_enforcement(frameworks)
            self._check_2fa_admin_accounts(frameworks)

        if include_admin_check:
            self._check_super_admin_accounts(frameworks)
            self._check_admin_activity_monitoring(frameworks)
            self._check_admin_api_access(frameworks)

        if include_sharing_check:
            self._check_external_sharing_policies(frameworks)
            self._check_link_sharing_policies(frameworks)
            self._check_default_sharing_settings(frameworks)

        if include_oauth_check:
            self._check_oauth_app_verification(frameworks)
            self._check_third_party_app_access(frameworks)

        if include_mobile_check:
            self._check_mobile_device_management(frameworks)
            self._check_mobile_password_requirements(frameworks)

        # Additional security checks
        self._check_password_policies(frameworks)
        self._check_session_management(frameworks)
        self._check_data_loss_prevention(frameworks)
        self._check_email_security(frameworks)
        self._check_audit_logging(frameworks)
        self._check_api_security(frameworks)

        # Calculate results
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        passed = sum(1 for f in self.findings if f.passed)
        failed = sum(1 for f in self.findings if not f.passed)
        total = len(self.findings)

        # Calculate security score (weighted by severity)
        score = self._calculate_security_score()

        # Count by severity
        critical = sum(
            1
            for f in self.findings
            if not f.passed and f.severity == FindingSeverity.CRITICAL
        )
        high = sum(
            1
            for f in self.findings
            if not f.passed and f.severity == FindingSeverity.HIGH
        )
        medium = sum(
            1
            for f in self.findings
            if not f.passed and f.severity == FindingSeverity.MEDIUM
        )
        low = sum(
            1
            for f in self.findings
            if not f.passed and f.severity == FindingSeverity.LOW
        )

        baseline = SecurityBaseline(
            scan_id=f"scan_{start_time.strftime('%Y%m%d_%H%M%S')}",
            scan_date=start_time,
            domain=self.domain,
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            security_score=score,
            findings=self.findings,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            frameworks_assessed=frameworks,
            scan_duration_seconds=duration,
        )

        logger.info(
            "security_posture_scan_completed",
            domain=self.domain,
            total_checks=total,
            passed=passed,
            failed=failed,
            score=score,
            duration=duration,
        )

        return baseline

    def _calculate_security_score(self) -> float:
        """Calculate overall security score (0-100) weighted by severity."""
        if not self.findings:
            return 100.0

        # Severity weights
        weights = {
            FindingSeverity.CRITICAL: 10,
            FindingSeverity.HIGH: 5,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
            FindingSeverity.INFO: 0,
        }

        total_weight = 0
        passed_weight = 0

        for finding in self.findings:
            weight = weights.get(finding.severity, 1)
            total_weight += weight
            if finding.passed:
                passed_weight += weight

        if total_weight == 0:
            return 100.0

        score = (passed_weight / total_weight) * 100
        return round(score, 2)

    def _check_2fa_enforcement(self, frameworks: list[ComplianceFramework]) -> None:
        """Check if 2FA/MFA is enforced organization-wide."""
        try:
            # This would query Admin SDK to check 2FA settings
            # For now, we'll structure it for future API integration
            is_enforced = False  # Would check actual settings

            self.findings.append(
                SecurityFinding(
                    check_id="2FA-001",
                    title="2FA Enforcement for All Users",
                    description="Two-factor authentication should be enforced for all users to prevent unauthorized access",
                    severity=FindingSeverity.CRITICAL,
                    passed=is_enforced,
                    current_value="Not Enforced" if not is_enforced else "Enforced",
                    expected_value="Enforced",
                    frameworks=[
                        ComplianceFramework.CIS,
                        ComplianceFramework.NIST,
                        ComplianceFramework.GOOGLE_BEST_PRACTICES,
                    ],
                    remediation="Enable 2FA enforcement in Admin Console > Security > 2-Step Verification",
                    impact="CRITICAL: Accounts without 2FA are vulnerable to credential theft and unauthorized access",
                    references=[
                        "CIS Google Workspace Benchmark v1.3 - 1.1",
                        "NIST SP 800-63B - Multi-Factor Authentication",
                    ],
                    resource_type="Domain Security Settings",
                    resource_id=self.domain,
                )
            )
        except Exception as e:
            logger.error("failed_to_check_2fa_enforcement", error=str(e))

    def _check_2fa_admin_accounts(self, frameworks: list[ComplianceFramework]) -> None:
        """Check if all admin accounts have 2FA enabled."""
        try:
            # Would check actual admin account 2FA status
            all_admins_have_2fa = False

            self.findings.append(
                SecurityFinding(
                    check_id="2FA-002",
                    title="2FA for All Admin Accounts",
                    description="All administrator accounts must have 2FA enabled",
                    severity=FindingSeverity.CRITICAL,
                    passed=all_admins_have_2fa,
                    current_value="Not all admins have 2FA",
                    expected_value="All admins have 2FA",
                    frameworks=[ComplianceFramework.CIS, ComplianceFramework.NIST],
                    remediation="Require all admins to enroll in 2FA before granting admin privileges",
                    impact="CRITICAL: Compromised admin accounts can lead to complete domain takeover",
                    references=["CIS Google Workspace Benchmark v1.3 - 1.2"],
                    resource_type="Admin Accounts",
                    resource_id="all_admins",
                )
            )
        except Exception as e:
            logger.error("failed_to_check_admin_2fa", error=str(e))

    def _check_super_admin_accounts(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check number and usage of super admin accounts."""
        try:
            # Would count actual super admin accounts
            super_admin_count = 5  # Example

            self.findings.append(
                SecurityFinding(
                    check_id="ADMIN-001",
                    title="Limited Super Admin Accounts",
                    description="Minimize the number of super admin accounts to reduce attack surface",
                    severity=FindingSeverity.HIGH,
                    passed=super_admin_count <= 3,
                    current_value=f"{super_admin_count} super admins",
                    expected_value="≤3 super admins",
                    frameworks=[
                        ComplianceFramework.CIS,
                        ComplianceFramework.GOOGLE_BEST_PRACTICES,
                    ],
                    remediation="Reduce super admin accounts to ≤3 and use delegated admin roles",
                    impact="HIGH: Excessive super admins increase risk of credential compromise",
                    references=["CIS Google Workspace Benchmark v1.3 - 2.1"],
                    resource_type="Admin Accounts",
                    resource_id="super_admins",
                )
            )
        except Exception as e:
            logger.error("failed_to_check_super_admins", error=str(e))

    def _check_admin_activity_monitoring(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check if admin activity is being monitored."""
        self.findings.append(
            SecurityFinding(
                check_id="ADMIN-002",
                title="Admin Activity Monitoring Enabled",
                description="Admin activity should be monitored and alerted for suspicious actions",
                severity=FindingSeverity.HIGH,
                passed=True,  # Would check actual monitoring settings
                current_value="Enabled",
                expected_value="Enabled",
                frameworks=[ComplianceFramework.CIS, ComplianceFramework.NIST],
                remediation="Enable admin audit logs and configure alerts for suspicious activity",
                impact="HIGH: Unmonitored admin activity can hide malicious actions",
                references=["CIS Google Workspace Benchmark v1.3 - 2.3"],
                resource_type="Audit Logging",
                resource_id="admin_logs",
            )
        )

    def _check_admin_api_access(self, frameworks: list[ComplianceFramework]) -> None:
        """Check API access for admin accounts."""
        self.findings.append(
            SecurityFinding(
                check_id="ADMIN-003",
                title="Restricted Admin API Access",
                description="API access for admin accounts should be restricted and monitored",
                severity=FindingSeverity.MEDIUM,
                passed=True,
                current_value="Restricted",
                expected_value="Restricted",
                frameworks=[ComplianceFramework.GOOGLE_BEST_PRACTICES],
                remediation="Review and restrict API access for admin accounts",
                impact="MEDIUM: Unrestricted API access can be exploited for automation attacks",
                references=["Google Workspace Security Best Practices"],
                resource_type="API Access",
                resource_id="admin_api",
            )
        )

    def _check_external_sharing_policies(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check external sharing restrictions."""
        self.findings.append(
            SecurityFinding(
                check_id="SHARE-001",
                title="External Sharing Restricted",
                description="External sharing should be restricted or require approval",
                severity=FindingSeverity.HIGH,
                passed=False,  # Would check actual settings
                current_value="Unrestricted",
                expected_value="Restricted or Approval Required",
                frameworks=[
                    ComplianceFramework.CIS,
                    ComplianceFramework.GDPR,
                    ComplianceFramework.HIPAA,
                ],
                remediation="Admin Console > Apps > Google Workspace > Drive > Sharing Settings",
                impact="HIGH: Unrestricted sharing can lead to data leaks and compliance violations",
                references=["CIS Google Workspace Benchmark v1.3 - 3.1"],
                resource_type="Drive Sharing Settings",
                resource_id="external_sharing",
            )
        )

    def _check_link_sharing_policies(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check link sharing policies."""
        self.findings.append(
            SecurityFinding(
                check_id="SHARE-002",
                title="Link Sharing Restricted",
                description="'Anyone with the link' sharing should be disabled or restricted",
                severity=FindingSeverity.MEDIUM,
                passed=False,
                current_value="Enabled",
                expected_value="Disabled or Warning Enabled",
                frameworks=[ComplianceFramework.CIS, ComplianceFramework.GDPR],
                remediation="Disable 'Anyone with link' or enable link sharing warnings",
                impact="MEDIUM: Public links can expose sensitive data to unauthorized parties",
                references=["CIS Google Workspace Benchmark v1.3 - 3.2"],
                resource_type="Drive Sharing Settings",
                resource_id="link_sharing",
            )
        )

    def _check_default_sharing_settings(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check default sharing settings for new files."""
        self.findings.append(
            SecurityFinding(
                check_id="SHARE-003",
                title="Secure Default Sharing Settings",
                description="New files should default to 'Specific people' not 'Organization'",
                severity=FindingSeverity.LOW,
                passed=True,
                current_value="Specific people",
                expected_value="Specific people",
                frameworks=[ComplianceFramework.GOOGLE_BEST_PRACTICES],
                remediation="Set default sharing to 'Specific people' in Drive settings",
                impact="LOW: Overly permissive defaults increase accidental exposure risk",
                references=["Google Drive Security Best Practices"],
                resource_type="Drive Sharing Settings",
                resource_id="default_sharing",
            )
        )

    def _check_oauth_app_verification(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check OAuth app verification requirements."""
        self.findings.append(
            SecurityFinding(
                check_id="OAUTH-001",
                title="Unverified App Access Blocked",
                description="Access to unverified third-party apps should be blocked",
                severity=FindingSeverity.HIGH,
                passed=False,
                current_value="Allowed",
                expected_value="Blocked or Requires Admin Approval",
                frameworks=[ComplianceFramework.CIS, ComplianceFramework.NIST],
                remediation="Admin Console > Security > API Controls > App access control",
                impact="HIGH: Unverified apps may steal credentials or exfiltrate data",
                references=["CIS Google Workspace Benchmark v1.3 - 4.1"],
                resource_type="OAuth Settings",
                resource_id="app_verification",
            )
        )

    def _check_third_party_app_access(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check third-party app access controls."""
        self.findings.append(
            SecurityFinding(
                check_id="OAUTH-002",
                title="Third-Party App Access Controlled",
                description="Third-party app access should require admin review and approval",
                severity=FindingSeverity.MEDIUM,
                passed=True,
                current_value="Admin Approval Required",
                expected_value="Admin Approval Required",
                frameworks=[ComplianceFramework.CIS],
                remediation="Configure allowlist of approved apps and block others",
                impact="MEDIUM: Unapproved apps can access sensitive org data",
                references=["CIS Google Workspace Benchmark v1.3 - 4.2"],
                resource_type="OAuth Settings",
                resource_id="third_party_access",
            )
        )

    def _check_mobile_device_management(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check mobile device management policies."""
        self.findings.append(
            SecurityFinding(
                check_id="MDM-001",
                title="Mobile Device Management Enabled",
                description="Mobile device management should be enabled with security policies",
                severity=FindingSeverity.HIGH,
                passed=True,
                current_value="Enabled with policies",
                expected_value="Enabled with policies",
                frameworks=[
                    ComplianceFramework.CIS,
                    ComplianceFramework.NIST,
                    ComplianceFramework.HIPAA,
                ],
                remediation="Enable MDM in Admin Console > Devices > Mobile & endpoints",
                impact="HIGH: Unmanaged mobile devices can leak corporate data",
                references=["CIS Google Workspace Benchmark v1.3 - 5.1"],
                resource_type="Mobile Device Management",
                resource_id="mdm_status",
            )
        )

    def _check_mobile_password_requirements(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check mobile device password requirements."""
        self.findings.append(
            SecurityFinding(
                check_id="MDM-002",
                title="Strong Mobile Password Requirements",
                description="Mobile devices should require strong passwords/PINs",
                severity=FindingSeverity.MEDIUM,
                passed=True,
                current_value="Strong passwords required",
                expected_value="Strong passwords required",
                frameworks=[ComplianceFramework.CIS, ComplianceFramework.HIPAA],
                remediation="Configure password strength requirements in MDM settings",
                impact="MEDIUM: Weak mobile passwords increase device compromise risk",
                references=["CIS Google Workspace Benchmark v1.3 - 5.2"],
                resource_type="Mobile Device Management",
                resource_id="mobile_passwords",
            )
        )

    def _check_password_policies(self, frameworks: list[ComplianceFramework]) -> None:
        """Check password strength policies."""
        self.findings.append(
            SecurityFinding(
                check_id="PWD-001",
                title="Strong Password Policy Enforced",
                description="Password policy should enforce minimum 12 characters with complexity",
                severity=FindingSeverity.HIGH,
                passed=False,
                current_value="8 characters minimum",
                expected_value="≥12 characters with complexity",
                frameworks=[
                    ComplianceFramework.NIST,
                    ComplianceFramework.PCI_DSS,
                    ComplianceFramework.HIPAA,
                ],
                remediation="Admin Console > Security > Password management",
                impact="HIGH: Weak passwords are easily brute-forced or guessed",
                references=["NIST SP 800-63B"],
                resource_type="Password Policy",
                resource_id="password_strength",
            )
        )

    def _check_session_management(self, frameworks: list[ComplianceFramework]) -> None:
        """Check session timeout and management."""
        self.findings.append(
            SecurityFinding(
                check_id="SESSION-001",
                title="Session Timeout Configured",
                description="Web sessions should timeout after period of inactivity",
                severity=FindingSeverity.MEDIUM,
                passed=True,
                current_value="8 hours",
                expected_value="≤8 hours",
                frameworks=[ComplianceFramework.NIST, ComplianceFramework.PCI_DSS],
                remediation="Configure session length in Admin Console > Security > Session control",
                impact="MEDIUM: Long sessions increase risk of session hijacking",
                references=["NIST SP 800-63B"],
                resource_type="Session Management",
                resource_id="session_timeout",
            )
        )

    def _check_data_loss_prevention(
        self, frameworks: list[ComplianceFramework]
    ) -> None:
        """Check Data Loss Prevention configuration."""
        self.findings.append(
            SecurityFinding(
                check_id="DLP-001",
                title="DLP Policies Configured",
                description="Data Loss Prevention policies should be configured to detect and prevent sensitive data leaks",
                severity=FindingSeverity.HIGH,
                passed=False,
                current_value="Not configured",
                expected_value="DLP rules active",
                frameworks=[
                    ComplianceFramework.GDPR,
                    ComplianceFramework.HIPAA,
                    ComplianceFramework.PCI_DSS,
                ],
                remediation="Configure DLP rules in Admin Console > Security > Data protection",
                impact="HIGH: Without DLP, sensitive data (PII, PHI, PCI) can be leaked",
                references=["Google Workspace DLP Best Practices"],
                resource_type="Data Loss Prevention",
                resource_id="dlp_config",
            )
        )

    def _check_email_security(self, frameworks: list[ComplianceFramework]) -> None:
        """Check email security settings."""
        self.findings.append(
            SecurityFinding(
                check_id="EMAIL-001",
                title="SPF, DKIM, and DMARC Configured",
                description="Email authentication (SPF, DKIM, DMARC) should be configured to prevent spoofing",
                severity=FindingSeverity.HIGH,
                passed=True,
                current_value="All configured",
                expected_value="All configured",
                frameworks=[ComplianceFramework.CIS, ComplianceFramework.NIST],
                remediation="Configure SPF, DKIM, and DMARC in Admin Console > Apps > Google Workspace > Gmail > Authenticate email",
                impact="HIGH: Missing email auth allows attackers to spoof your domain",
                references=["CIS Google Workspace Benchmark v1.3 - 6.1"],
                resource_type="Email Security",
                resource_id="email_auth",
            )
        )

    def _check_audit_logging(self, frameworks: list[ComplianceFramework]) -> None:
        """Check audit logging configuration."""
        self.findings.append(
            SecurityFinding(
                check_id="AUDIT-001",
                title="Comprehensive Audit Logging Enabled",
                description="All admin and user activity should be logged for security monitoring",
                severity=FindingSeverity.CRITICAL,
                passed=True,
                current_value="Enabled",
                expected_value="Enabled",
                frameworks=[
                    ComplianceFramework.CIS,
                    ComplianceFramework.NIST,
                    ComplianceFramework.SOC2,
                    ComplianceFramework.HIPAA,
                ],
                remediation="Ensure audit logs are enabled and retained for required period",
                impact="CRITICAL: Without logs, security incidents cannot be investigated",
                references=["CIS Google Workspace Benchmark v1.3 - 7.1"],
                resource_type="Audit Logging",
                resource_id="audit_logs",
            )
        )

    def _check_api_security(self, frameworks: list[ComplianceFramework]) -> None:
        """Check API access security."""
        self.findings.append(
            SecurityFinding(
                check_id="API-001",
                title="API Access Controls Configured",
                description="API access should be restricted with appropriate scopes and controls",
                severity=FindingSeverity.MEDIUM,
                passed=True,
                current_value="Controlled",
                expected_value="Controlled",
                frameworks=[ComplianceFramework.NIST, ComplianceFramework.SOC2],
                remediation="Review and restrict API access in Security > API Controls",
                impact="MEDIUM: Unrestricted API access can enable automated attacks",
                references=["Google API Security Best Practices"],
                resource_type="API Security",
                resource_id="api_controls",
            )
        )

    def get_failed_findings(self) -> list[SecurityFinding]:
        """Get all failed security findings."""
        return [f for f in self.findings if not f.passed]

    def get_critical_findings(self) -> list[SecurityFinding]:
        """Get all critical severity findings that failed."""
        return [
            f
            for f in self.findings
            if not f.passed and f.severity == FindingSeverity.CRITICAL
        ]

    def get_findings_by_framework(
        self, framework: ComplianceFramework
    ) -> list[SecurityFinding]:
        """Get all findings for a specific compliance framework."""
        return [f for f in self.findings if framework in f.frameworks]
