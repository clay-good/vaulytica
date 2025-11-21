"""Tests for Security Posture Scanner."""

import pytest
from unittest.mock import Mock

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.security.posture_scanner import (
    PostureScanner,
    SecurityFinding,
    SecurityBaseline,
    FindingSeverity,
    ComplianceFramework,
)


@pytest.fixture
def mock_client() -> Mock:
    """Create a mock GoogleWorkspaceClient."""
    client = Mock(spec=GoogleWorkspaceClient)
    return client


@pytest.fixture
def posture_scanner(mock_client: Mock) -> PostureScanner:
    """Create PostureScanner instance."""
    return PostureScanner(client=mock_client, domain="example.com")


class TestPostureScanner:
    """Test PostureScanner class."""

    def test_initialization(self, mock_client: Mock) -> None:
        """Test scanner initialization."""
        scanner = PostureScanner(client=mock_client, domain="example.com")
        assert scanner.domain == "example.com"
        assert scanner.client == mock_client
        assert len(scanner.findings) == 0

    def test_scan_security_posture_all_checks(
        self, posture_scanner: PostureScanner
    ) -> None:
        """Test full security posture scan."""
        baseline = posture_scanner.scan_security_posture()

        assert baseline.domain == "example.com"
        assert baseline.total_checks > 0
        assert baseline.security_score >= 0
        assert baseline.security_score <= 100
        assert len(baseline.findings) > 0
        assert baseline.scan_duration_seconds > 0

    def test_scan_with_specific_frameworks(
        self, posture_scanner: PostureScanner
    ) -> None:
        """Test scan with specific compliance frameworks."""
        frameworks = [ComplianceFramework.CIS, ComplianceFramework.NIST]
        baseline = posture_scanner.scan_security_posture(frameworks=frameworks)

        assert ComplianceFramework.CIS in baseline.frameworks_assessed
        assert ComplianceFramework.NIST in baseline.frameworks_assessed

    def test_scan_with_selective_checks(
        self, posture_scanner: PostureScanner
    ) -> None:
        """Test scan with selective checks enabled."""
        baseline = posture_scanner.scan_security_posture(
            include_2fa_check=True,
            include_admin_check=False,
            include_sharing_check=False,
            include_oauth_check=False,
            include_mobile_check=False,
        )

        # Should have fewer checks when some are disabled
        assert baseline.total_checks > 0
        # Should have 2FA-related findings
        two_fa_findings = [f for f in baseline.findings if f.check_id.startswith("2FA")]
        assert len(two_fa_findings) > 0

    def test_security_finding_creation(self) -> None:
        """Test SecurityFinding dataclass."""
        finding = SecurityFinding(
            check_id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=FindingSeverity.HIGH,
            passed=False,
            current_value="Bad",
            expected_value="Good",
            frameworks=[ComplianceFramework.CIS],
            remediation="Fix it",
            impact="HIGH impact",
            resource_type="Test Resource",
            resource_id="test_123",
        )

        assert finding.check_id == "TEST-001"
        assert finding.severity == FindingSeverity.HIGH
        assert not finding.passed
        assert ComplianceFramework.CIS in finding.frameworks

    def test_finding_to_dict(self) -> None:
        """Test SecurityFinding to_dict method."""
        finding = SecurityFinding(
            check_id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=FindingSeverity.CRITICAL,
            passed=True,
            current_value="Good",
            expected_value="Good",
        )

        finding_dict = finding.to_dict()

        assert finding_dict["check_id"] == "TEST-001"
        assert finding_dict["severity"] == "critical"
        assert finding_dict["passed"] is True
        assert "detected_at" in finding_dict

    def test_baseline_to_dict(self, posture_scanner: PostureScanner) -> None:
        """Test SecurityBaseline to_dict method."""
        baseline = posture_scanner.scan_security_posture()
        baseline_dict = baseline.to_dict()

        assert "scan_id" in baseline_dict
        assert "security_score" in baseline_dict
        assert "findings" in baseline_dict
        assert isinstance(baseline_dict["findings"], list)
        assert baseline_dict["domain"] == "example.com"

    def test_security_score_calculation(
        self, posture_scanner: PostureScanner
    ) -> None:
        """Test security score calculation."""
        baseline = posture_scanner.scan_security_posture()

        # Score should be 0-100
        assert 0 <= baseline.security_score <= 100

        # If all checks pass, score should be 100
        all_passed = all(f.passed for f in baseline.findings)
        if all_passed:
            assert baseline.security_score == 100.0

    def test_severity_counts(self, posture_scanner: PostureScanner) -> None:
        """Test severity counts in baseline."""
        baseline = posture_scanner.scan_security_posture()

        # Verify severity counts match actual findings
        critical_count = sum(
            1
            for f in baseline.findings
            if not f.passed and f.severity == FindingSeverity.CRITICAL
        )
        high_count = sum(
            1
            for f in baseline.findings
            if not f.passed and f.severity == FindingSeverity.HIGH
        )

        assert baseline.critical_findings == critical_count
        assert baseline.high_findings == high_count

    def test_get_failed_findings(self, posture_scanner: PostureScanner) -> None:
        """Test getting failed findings."""
        posture_scanner.scan_security_posture()
        failed = posture_scanner.get_failed_findings()

        assert isinstance(failed, list)
        assert all(not f.passed for f in failed)

    def test_get_critical_findings(self, posture_scanner: PostureScanner) -> None:
        """Test getting critical severity findings."""
        posture_scanner.scan_security_posture()
        critical = posture_scanner.get_critical_findings()

        assert isinstance(critical, list)
        assert all(not f.passed for f in critical)
        assert all(f.severity == FindingSeverity.CRITICAL for f in critical)

    def test_get_findings_by_framework(
        self, posture_scanner: PostureScanner
    ) -> None:
        """Test filtering findings by compliance framework."""
        posture_scanner.scan_security_posture()
        cis_findings = posture_scanner.get_findings_by_framework(ComplianceFramework.CIS)

        assert isinstance(cis_findings, list)
        assert all(ComplianceFramework.CIS in f.frameworks for f in cis_findings)

    def test_2fa_enforcement_check(self, posture_scanner: PostureScanner) -> None:
        """Test 2FA enforcement check."""
        baseline = posture_scanner.scan_security_posture()

        two_fa_findings = [
            f for f in baseline.findings if f.check_id.startswith("2FA")
        ]
        assert len(two_fa_findings) > 0

        # Should have critical 2FA enforcement check
        enforcement_check = next(
            (f for f in two_fa_findings if "Enforcement" in f.title), None
        )
        assert enforcement_check is not None
        assert enforcement_check.severity == FindingSeverity.CRITICAL

    def test_admin_checks(self, posture_scanner: PostureScanner) -> None:
        """Test admin account security checks."""
        baseline = posture_scanner.scan_security_posture()

        admin_findings = [
            f for f in baseline.findings if f.check_id.startswith("ADMIN")
        ]
        assert len(admin_findings) > 0

        # Should check super admin count
        super_admin_check = next(
            (f for f in admin_findings if "Super Admin" in f.title), None
        )
        assert super_admin_check is not None

    def test_sharing_checks(self, posture_scanner: PostureScanner) -> None:
        """Test external sharing security checks."""
        baseline = posture_scanner.scan_security_posture()

        sharing_findings = [
            f for f in baseline.findings if f.check_id.startswith("SHARE")
        ]
        assert len(sharing_findings) > 0

        # Should check external sharing
        external_sharing = next(
            (f for f in sharing_findings if "External Sharing" in f.title), None
        )
        assert external_sharing is not None
        assert external_sharing.severity in [
            FindingSeverity.HIGH,
            FindingSeverity.CRITICAL,
        ]

    def test_oauth_checks(self, posture_scanner: PostureScanner) -> None:
        """Test OAuth app security checks."""
        baseline = posture_scanner.scan_security_posture()

        oauth_findings = [
            f for f in baseline.findings if f.check_id.startswith("OAUTH")
        ]
        assert len(oauth_findings) > 0

        # Should check unverified app access
        unverified_check = next(
            (f for f in oauth_findings if "Unverified" in f.title), None
        )
        assert unverified_check is not None

    def test_mobile_checks(self, posture_scanner: PostureScanner) -> None:
        """Test mobile device management checks."""
        baseline = posture_scanner.scan_security_posture()

        mdm_findings = [f for f in baseline.findings if f.check_id.startswith("MDM")]
        assert len(mdm_findings) > 0

        # Should check MDM enablement
        mdm_enabled = next(
            (f for f in mdm_findings if "Management Enabled" in f.title), None
        )
        assert mdm_enabled is not None

    def test_password_policy_check(self, posture_scanner: PostureScanner) -> None:
        """Test password policy checks."""
        baseline = posture_scanner.scan_security_posture()

        pwd_findings = [f for f in baseline.findings if f.check_id.startswith("PWD")]
        assert len(pwd_findings) > 0

        # Password policy should be HIGH severity
        pwd_check = pwd_findings[0]
        assert pwd_check.severity == FindingSeverity.HIGH

    def test_dlp_check(self, posture_scanner: PostureScanner) -> None:
        """Test Data Loss Prevention checks."""
        baseline = posture_scanner.scan_security_posture()

        dlp_findings = [f for f in baseline.findings if f.check_id.startswith("DLP")]
        assert len(dlp_findings) > 0

        # DLP should be HIGH severity
        dlp_check = dlp_findings[0]
        assert dlp_check.severity == FindingSeverity.HIGH

    def test_email_security_check(self, posture_scanner: PostureScanner) -> None:
        """Test email security checks."""
        baseline = posture_scanner.scan_security_posture()

        email_findings = [
            f for f in baseline.findings if f.check_id.startswith("EMAIL")
        ]
        assert len(email_findings) > 0

        # Email auth should be checked
        email_auth = next(
            (f for f in email_findings if "DMARC" in f.description), None
        )
        assert email_auth is not None

    def test_audit_logging_check(self, posture_scanner: PostureScanner) -> None:
        """Test audit logging checks."""
        baseline = posture_scanner.scan_security_posture()

        audit_findings = [
            f for f in baseline.findings if f.check_id.startswith("AUDIT")
        ]
        assert len(audit_findings) > 0

        # Audit logging should be CRITICAL
        audit_check = audit_findings[0]
        assert audit_check.severity == FindingSeverity.CRITICAL

    def test_api_security_check(self, posture_scanner: PostureScanner) -> None:
        """Test API security checks."""
        baseline = posture_scanner.scan_security_posture()

        api_findings = [f for f in baseline.findings if f.check_id.startswith("API")]
        assert len(api_findings) > 0

    def test_remediation_provided(self, posture_scanner: PostureScanner) -> None:
        """Test that all failed findings have remediation guidance."""
        baseline = posture_scanner.scan_security_posture()
        failed = posture_scanner.get_failed_findings()

        for finding in failed:
            assert finding.remediation, f"Finding {finding.check_id} missing remediation"
            assert len(finding.remediation) > 10  # Non-trivial remediation

    def test_compliance_framework_coverage(
        self, posture_scanner: PostureScanner
    ) -> None:
        """Test that findings cover multiple compliance frameworks."""
        baseline = posture_scanner.scan_security_posture()

        frameworks_found = set()
        for finding in baseline.findings:
            frameworks_found.update(finding.frameworks)

        # Should cover at least CIS and NIST
        assert ComplianceFramework.CIS in frameworks_found
        assert ComplianceFramework.NIST in frameworks_found

    def test_scan_id_format(self, posture_scanner: PostureScanner) -> None:
        """Test scan ID format."""
        baseline = posture_scanner.scan_security_posture()

        assert baseline.scan_id.startswith("scan_")
        assert len(baseline.scan_id) > 10  # Should have timestamp

    def test_finding_severity_enum(self) -> None:
        """Test FindingSeverity enum."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_compliance_framework_enum(self) -> None:
        """Test ComplianceFramework enum."""
        assert ComplianceFramework.CIS.value == "cis"
        assert ComplianceFramework.NIST.value == "nist"
        assert ComplianceFramework.HIPAA.value == "hipaa"
        assert ComplianceFramework.GDPR.value == "gdpr"
        assert ComplianceFramework.SOC2.value == "soc2"

    def test_passed_vs_failed_counts(self, posture_scanner: PostureScanner) -> None:
        """Test that passed and failed counts sum to total."""
        baseline = posture_scanner.scan_security_posture()

        assert baseline.passed_checks + baseline.failed_checks == baseline.total_checks
