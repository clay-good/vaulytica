"""Compliance reporting for GDPR, HIPAA, SOC 2."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

import structlog

from vaulytica.core.scanners.file_scanner import FileInfo
from vaulytica.core.scanners.user_scanner import UserInfo

logger = structlog.get_logger(__name__)


@dataclass
class ComplianceIssue:
    """Represents a compliance issue."""

    severity: str  # critical, high, medium, low
    category: str  # data_sharing, access_control, retention, etc.
    description: str
    recommendation: str
    affected_resource: str
    resource_type: str  # file, user, app


@dataclass
class GDPRReport:
    """GDPR compliance report."""

    report_time: datetime
    domain: str
    
    # Data sharing
    files_shared_outside_eu: int = 0
    files_with_pii_shared_externally: int = 0
    
    # Access controls
    users_without_2fa: int = 0
    inactive_users_with_data_access: int = 0
    
    # Data retention
    files_older_than_retention_period: int = 0
    
    issues: List[ComplianceIssue] = field(default_factory=list)
    
    def calculate_compliance_score(self) -> int:
        """Calculate GDPR compliance score (0-100)."""
        # Simple scoring: deduct points for issues
        score = 100
        
        for issue in self.issues:
            if issue.severity == "critical":
                score -= 10
            elif issue.severity == "high":
                score -= 5
            elif issue.severity == "medium":
                score -= 2
            elif issue.severity == "low":
                score -= 1
        
        return max(0, score)


@dataclass
class HIPAAReport:
    """HIPAA compliance report."""

    report_time: datetime
    domain: str
    
    # PHI exposure
    files_with_phi: int = 0
    files_with_phi_shared_externally: int = 0
    files_with_phi_publicly_shared: int = 0
    
    # Access controls
    users_without_2fa: int = 0
    admin_users_without_2fa: int = 0
    
    # Audit logging
    audit_logging_enabled: bool = True
    
    issues: List[ComplianceIssue] = field(default_factory=list)
    
    def calculate_compliance_score(self) -> int:
        """Calculate HIPAA compliance score (0-100)."""
        score = 100
        
        for issue in self.issues:
            if issue.severity == "critical":
                score -= 15
            elif issue.severity == "high":
                score -= 8
            elif issue.severity == "medium":
                score -= 3
            elif issue.severity == "low":
                score -= 1
        
        return max(0, score)


@dataclass
class SOC2Report:
    """SOC 2 compliance report."""

    report_time: datetime
    domain: str

    # Security
    files_publicly_shared: int = 0
    files_shared_externally: int = 0
    high_risk_oauth_apps: int = 0

    # Availability
    inactive_users: int = 0
    suspended_users: int = 0

    # Confidentiality
    files_with_sensitive_data: int = 0
    files_with_sensitive_data_shared: int = 0

    issues: List[ComplianceIssue] = field(default_factory=list)

    def calculate_compliance_score(self) -> int:
        """Calculate SOC 2 compliance score (0-100)."""
        score = 100

        for issue in self.issues:
            if issue.severity == "critical":
                score -= 12
            elif issue.severity == "high":
                score -= 6
            elif issue.severity == "medium":
                score -= 3
            elif issue.severity == "low":
                score -= 1

        return max(0, score)


@dataclass
class PCIDSSReport:
    """PCI-DSS compliance report for payment card data protection."""

    report_time: datetime
    domain: str

    # Cardholder data protection
    files_with_card_data: int = 0
    files_with_card_data_shared_externally: int = 0
    files_with_card_data_publicly_shared: int = 0

    # Access controls
    users_without_2fa: int = 0
    users_with_excessive_permissions: int = 0

    # Monitoring and logging
    audit_logging_enabled: bool = True

    # Network security
    files_shared_with_untrusted_domains: int = 0

    issues: List[ComplianceIssue] = field(default_factory=list)

    def calculate_compliance_score(self) -> int:
        """Calculate PCI-DSS compliance score (0-100)."""
        score = 100

        for issue in self.issues:
            if issue.severity == "critical":
                score -= 20  # PCI-DSS is strict
            elif issue.severity == "high":
                score -= 10
            elif issue.severity == "medium":
                score -= 4
            elif issue.severity == "low":
                score -= 1

        return max(0, score)


@dataclass
class FERPAReport:
    """FERPA compliance report for student data protection."""

    report_time: datetime
    domain: str

    # Student data protection
    files_with_student_data: int = 0
    files_with_student_data_shared_externally: int = 0
    files_with_student_data_publicly_shared: int = 0

    # Access controls
    users_without_2fa: int = 0
    inactive_users_with_student_data_access: int = 0

    # Data retention
    files_older_than_retention_period: int = 0

    # Disclosure tracking
    unauthorized_disclosures: int = 0

    issues: List[ComplianceIssue] = field(default_factory=list)

    def calculate_compliance_score(self) -> int:
        """Calculate FERPA compliance score (0-100)."""
        score = 100

        for issue in self.issues:
            if issue.severity == "critical":
                score -= 15
            elif issue.severity == "high":
                score -= 8
            elif issue.severity == "medium":
                score -= 3
            elif issue.severity == "low":
                score -= 1

        return max(0, score)


@dataclass
class FedRAMPReport:
    """FedRAMP compliance report for federal government security controls."""

    report_time: datetime
    domain: str
    impact_level: str = "Moderate"  # Low, Moderate, or High

    # Access Control (AC)
    users_without_2fa: int = 0
    users_with_excessive_permissions: int = 0
    inactive_accounts: int = 0

    # Audit and Accountability (AU)
    audit_logging_enabled: bool = True
    suspicious_activities_detected: int = 0

    # Identification and Authentication (IA)
    weak_authentication_methods: int = 0

    # System and Communications Protection (SC)
    files_shared_externally: int = 0
    files_publicly_shared: int = 0
    unencrypted_data_transfers: int = 0

    # System and Information Integrity (SI)
    files_with_sensitive_data_exposed: int = 0
    security_violations: int = 0

    issues: List[ComplianceIssue] = field(default_factory=list)

    def calculate_compliance_score(self) -> int:
        """Calculate FedRAMP compliance score (0-100)."""
        score = 100

        # FedRAMP High has stricter requirements
        multiplier = 1.5 if self.impact_level == "High" else 1.0

        for issue in self.issues:
            if issue.severity == "critical":
                score -= int(18 * multiplier)
            elif issue.severity == "high":
                score -= int(10 * multiplier)
            elif issue.severity == "medium":
                score -= int(4 * multiplier)
            elif issue.severity == "low":
                score -= int(1 * multiplier)

        return max(0, score)


class ComplianceReporter:
    """Generate compliance reports."""

    # EU countries for GDPR
    EU_COUNTRIES = [
        "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr",
        "de", "gr", "hu", "ie", "it", "lv", "lt", "lu", "mt", "nl",
        "pl", "pt", "ro", "sk", "si", "es", "se",
    ]

    def __init__(self, domain: str):
        """Initialize compliance reporter.

        Args:
            domain: Organization domain
        """
        self.domain = domain
        logger.info("compliance_reporter_initialized", domain=domain)

    def generate_gdpr_report(
        self,
        files: List[FileInfo],
        users: List[UserInfo],
    ) -> GDPRReport:
        """Generate GDPR compliance report.

        Args:
            files: List of FileInfo objects
            users: List of UserInfo objects

        Returns:
            GDPRReport
        """
        logger.info("generating_gdpr_report")

        report = GDPRReport(
            report_time=datetime.now(timezone.utc),
            domain=self.domain,
        )

        # Analyze files
        for file_info in files:
            # Check for external sharing
            if file_info.is_shared_externally:
                # Check if shared outside EU (simplified - would need geolocation)
                report.files_shared_outside_eu += 1

                # Check for PII
                if hasattr(file_info, "pii_result") and file_info.pii_result:
                    report.files_with_pii_shared_externally += 1

                    report.issues.append(ComplianceIssue(
                        severity="high",
                        category="data_sharing",
                        description=f"File with PII shared externally: {file_info.name}",
                        recommendation="Review and restrict external sharing of files containing PII",
                        affected_resource=file_info.id,
                        resource_type="file",
                    ))

        # Analyze users
        for user in users:
            if not user.two_factor_enabled:
                report.users_without_2fa += 1

                report.issues.append(ComplianceIssue(
                    severity="medium",
                    category="access_control",
                    description=f"User without 2FA: {user.email}",
                    recommendation="Enable 2-factor authentication for all users",
                    affected_resource=user.email,
                    resource_type="user",
                ))

            if user.is_inactive:
                report.inactive_users_with_data_access += 1

                report.issues.append(ComplianceIssue(
                    severity="medium",
                    category="access_control",
                    description=f"Inactive user with data access: {user.email}",
                    recommendation="Review and suspend inactive user accounts",
                    affected_resource=user.email,
                    resource_type="user",
                ))

        logger.info("gdpr_report_generated", issue_count=len(report.issues))
        return report

    def generate_hipaa_report(
        self,
        files: List[FileInfo],
        users: List[UserInfo],
    ) -> HIPAAReport:
        """Generate HIPAA compliance report.

        Args:
            files: List of FileInfo objects
            users: List of UserInfo objects

        Returns:
            HIPAAReport
        """
        logger.info("generating_hipaa_report")

        report = HIPAAReport(
            report_time=datetime.now(timezone.utc),
            domain=self.domain,
        )

        # Analyze files for PHI
        for file_info in files:
            if hasattr(file_info, "pii_result") and file_info.pii_result:
                report.files_with_phi += 1

                if file_info.is_public:
                    report.files_with_phi_publicly_shared += 1

                    report.issues.append(ComplianceIssue(
                        severity="critical",
                        category="phi_exposure",
                        description=f"File with PHI publicly shared: {file_info.name}",
                        recommendation="Immediately revoke public access to files containing PHI",
                        affected_resource=file_info.id,
                        resource_type="file",
                    ))

                elif file_info.is_shared_externally:
                    report.files_with_phi_shared_externally += 1

                    report.issues.append(ComplianceIssue(
                        severity="high",
                        category="phi_exposure",
                        description=f"File with PHI shared externally: {file_info.name}",
                        recommendation="Review and restrict external sharing of PHI",
                        affected_resource=file_info.id,
                        resource_type="file",
                    ))

        # Analyze users
        for user in users:
            if not user.two_factor_enabled:
                report.users_without_2fa += 1

                severity = "high" if user.is_admin else "medium"

                if user.is_admin:
                    report.admin_users_without_2fa += 1

                report.issues.append(ComplianceIssue(
                    severity=severity,
                    category="access_control",
                    description=f"User without 2FA: {user.email}",
                    recommendation="Enable 2-factor authentication for all users accessing PHI",
                    affected_resource=user.email,
                    resource_type="user",
                ))

        logger.info("hipaa_report_generated", issue_count=len(report.issues))
        return report

    def generate_soc2_report(
        self,
        files: List[FileInfo],
        users: List[UserInfo],
    ) -> SOC2Report:
        """Generate SOC 2 compliance report.

        Args:
            files: List of FileInfo objects
            users: List of UserInfo objects

        Returns:
            SOC2Report
        """
        logger.info("generating_soc2_report")

        report = SOC2Report(
            report_time=datetime.now(timezone.utc),
            domain=self.domain,
        )

        # Analyze files
        for file_info in files:
            if file_info.is_public:
                report.files_publicly_shared += 1

                report.issues.append(ComplianceIssue(
                    severity="high",
                    category="security",
                    description=f"File publicly shared: {file_info.name}",
                    recommendation="Review and restrict public file sharing",
                    affected_resource=file_info.id,
                    resource_type="file",
                ))

            if file_info.is_shared_externally:
                report.files_shared_externally += 1

        # Analyze users
        for user in users:
            if user.is_inactive:
                report.inactive_users += 1
            if user.is_suspended:
                report.suspended_users += 1

        logger.info("soc2_report_generated", issue_count=len(report.issues))
        return report

    def generate_pcidss_report(
        self,
        files: List[FileInfo],
        users: List[UserInfo],
    ) -> PCIDSSReport:
        """Generate PCI-DSS compliance report.

        Args:
            files: List of FileInfo objects
            users: List of UserInfo objects

        Returns:
            PCIDSSReport
        """
        logger.info("generating_pcidss_report")

        report = PCIDSSReport(
            report_time=datetime.now(timezone.utc),
            domain=self.domain,
        )

        # PII patterns that might indicate card data
        card_patterns = ["credit_card", "card_number", "cvv", "payment"]

        # Analyze files for cardholder data
        for file_info in files:
            if hasattr(file_info, "pii_result") and file_info.pii_result:
                # Check if PII includes credit card data
                has_card_data = any(
                    pattern in str(file_info.pii_result).lower()
                    for pattern in card_patterns
                )

                if has_card_data:
                    report.files_with_card_data += 1

                    if file_info.is_public:
                        report.files_with_card_data_publicly_shared += 1

                        report.issues.append(ComplianceIssue(
                            severity="critical",
                            category="cardholder_data_protection",
                            description=f"File with card data publicly shared: {file_info.name}",
                            recommendation="Immediately revoke public access to files containing cardholder data",
                            affected_resource=file_info.id,
                            resource_type="file",
                        ))

                    elif file_info.is_shared_externally:
                        report.files_with_card_data_shared_externally += 1

                        report.issues.append(ComplianceIssue(
                            severity="critical",
                            category="cardholder_data_protection",
                            description=f"File with card data shared externally: {file_info.name}",
                            recommendation="Restrict external sharing of cardholder data",
                            affected_resource=file_info.id,
                            resource_type="file",
                        ))

        # Analyze users
        for user in users:
            if not user.two_factor_enabled:
                report.users_without_2fa += 1

                report.issues.append(ComplianceIssue(
                    severity="high",
                    category="access_control",
                    description=f"User without 2FA: {user.email}",
                    recommendation="Enable 2-factor authentication for all users with access to cardholder data",
                    affected_resource=user.email,
                    resource_type="user",
                ))

        logger.info("pcidss_report_generated", issue_count=len(report.issues))
        return report

    def generate_ferpa_report(
        self,
        files: List[FileInfo],
        users: List[UserInfo],
    ) -> FERPAReport:
        """Generate FERPA compliance report.

        Args:
            files: List of FileInfo objects
            users: List of UserInfo objects

        Returns:
            FERPAReport
        """
        logger.info("generating_ferpa_report")

        report = FERPAReport(
            report_time=datetime.now(timezone.utc),
            domain=self.domain,
        )

        # Keywords that might indicate student data
        student_keywords = ["student", "grade", "transcript", "enrollment", "education"]

        # Analyze files for student data
        for file_info in files:
            # Check filename for student data indicators
            has_student_data = any(
                keyword in file_info.name.lower()
                for keyword in student_keywords
            )

            # Also check PII (student records often contain PII)
            if hasattr(file_info, "pii_result") and file_info.pii_result:
                has_student_data = True

            if has_student_data:
                report.files_with_student_data += 1

                if file_info.is_public:
                    report.files_with_student_data_publicly_shared += 1

                    report.issues.append(ComplianceIssue(
                        severity="critical",
                        category="student_data_protection",
                        description=f"File with student data publicly shared: {file_info.name}",
                        recommendation="Immediately revoke public access to files containing student data",
                        affected_resource=file_info.id,
                        resource_type="file",
                    ))

                elif file_info.is_shared_externally:
                    report.files_with_student_data_shared_externally += 1

                    report.issues.append(ComplianceIssue(
                        severity="high",
                        category="student_data_protection",
                        description=f"File with student data shared externally: {file_info.name}",
                        recommendation="Review and restrict external sharing of student data per FERPA requirements",
                        affected_resource=file_info.id,
                        resource_type="file",
                    ))

        # Analyze users
        for user in users:
            if not user.two_factor_enabled:
                report.users_without_2fa += 1

                report.issues.append(ComplianceIssue(
                    severity="medium",
                    category="access_control",
                    description=f"User without 2FA: {user.email}",
                    recommendation="Enable 2-factor authentication for all users with access to student data",
                    affected_resource=user.email,
                    resource_type="user",
                ))

            if user.is_inactive:
                report.inactive_users_with_student_data_access += 1

                report.issues.append(ComplianceIssue(
                    severity="medium",
                    category="access_control",
                    description=f"Inactive user with student data access: {user.email}",
                    recommendation="Review and suspend inactive user accounts per FERPA requirements",
                    affected_resource=user.email,
                    resource_type="user",
                ))

        logger.info("ferpa_report_generated", issue_count=len(report.issues))
        return report

    def generate_fedramp_report(
        self,
        files: List[FileInfo],
        users: List[UserInfo],
        impact_level: str = "Moderate",
    ) -> FedRAMPReport:
        """Generate FedRAMP compliance report.

        Args:
            files: List of FileInfo objects
            users: List of UserInfo objects
            impact_level: FedRAMP impact level (Low, Moderate, or High)

        Returns:
            FedRAMPReport
        """
        logger.info("generating_fedramp_report", impact_level=impact_level)

        report = FedRAMPReport(
            report_time=datetime.now(timezone.utc),
            domain=self.domain,
            impact_level=impact_level,
        )

        # Analyze files for security controls
        for file_info in files:
            if file_info.is_public:
                report.files_publicly_shared += 1

                report.issues.append(ComplianceIssue(
                    severity="critical",
                    category="system_communications_protection",
                    description=f"File publicly shared: {file_info.name}",
                    recommendation="FedRAMP requires strict access controls - revoke public access",
                    affected_resource=file_info.id,
                    resource_type="file",
                ))

            if file_info.is_shared_externally:
                report.files_shared_externally += 1

                report.issues.append(ComplianceIssue(
                    severity="high",
                    category="system_communications_protection",
                    description=f"File shared externally: {file_info.name}",
                    recommendation="Review external sharing against FedRAMP boundary protection requirements",
                    affected_resource=file_info.id,
                    resource_type="file",
                ))

            # Check for sensitive data exposure
            if hasattr(file_info, "pii_result") and file_info.pii_result:
                if file_info.is_shared_externally or file_info.is_public:
                    report.files_with_sensitive_data_exposed += 1

                    report.issues.append(ComplianceIssue(
                        severity="critical",
                        category="system_information_integrity",
                        description=f"Sensitive data exposed: {file_info.name}",
                        recommendation="Protect sensitive data per FedRAMP requirements",
                        affected_resource=file_info.id,
                        resource_type="file",
                    ))

        # Analyze users for access control and authentication
        for user in users:
            if not user.two_factor_enabled:
                report.users_without_2fa += 1
                report.weak_authentication_methods += 1

                severity = "critical" if impact_level == "High" else "high"

                report.issues.append(ComplianceIssue(
                    severity=severity,
                    category="identification_authentication",
                    description=f"User without 2FA: {user.email}",
                    recommendation="FedRAMP requires multi-factor authentication for all users",
                    affected_resource=user.email,
                    resource_type="user",
                ))

            if user.is_inactive:
                report.inactive_accounts += 1

                report.issues.append(ComplianceIssue(
                    severity="medium",
                    category="access_control",
                    description=f"Inactive account: {user.email}",
                    recommendation="FedRAMP requires timely removal of inactive accounts",
                    affected_resource=user.email,
                    resource_type="user",
                ))

            if user.is_admin:
                report.users_with_excessive_permissions += 1

                # Admins without 2FA are critical in FedRAMP
                if not user.two_factor_enabled:
                    report.issues.append(ComplianceIssue(
                        severity="critical",
                        category="access_control",
                        description=f"Admin without 2FA: {user.email}",
                        recommendation="FedRAMP requires MFA for all privileged users",
                        affected_resource=user.email,
                        resource_type="user",
                    ))

        logger.info("fedramp_report_generated", issue_count=len(report.issues))
        return report

