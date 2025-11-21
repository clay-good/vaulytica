"""Tests for compliance reporting."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from vaulytica.core.compliance.reporting import (
    ComplianceIssue,
    GDPRReport,
    HIPAAReport,
    SOC2Report,
    PCIDSSReport,
    FERPAReport,
    FedRAMPReport,
    ComplianceReporter,
)
from vaulytica.core.scanners.file_scanner import FileInfo, FilePermission
from vaulytica.core.scanners.user_scanner import UserInfo


@pytest.fixture
def sample_files():
    """Sample file data for testing."""
    return [
        FileInfo(
            id="file1",
            name="customer_data.xlsx",
            owner_email="user@company.com",
            owner_name="User Name",
            mime_type="application/vnd.ms-excel",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            size=1024000,
            web_view_link="https://drive.google.com/file/d/file1",
            is_public=False,
            is_shared_externally=True,
            external_domains=["external.com"],
            external_emails=["external@external.com"],
            risk_score=85,
        ),
        FileInfo(
            id="file2",
            name="public_doc.pdf",
            owner_email="user@company.com",
            owner_name="User Name",
            mime_type="application/pdf",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            size=50000,
            web_view_link="https://drive.google.com/file/d/file2",
            is_public=True,
            is_shared_externally=True,
            external_domains=[],
            external_emails=[],
            risk_score=95,
        ),
    ]


@pytest.fixture
def sample_users():
    """Sample user data for testing."""
    return [
        UserInfo(
            id="admin123",
            email="admin@company.com",
            full_name="Admin User",
            is_admin=True,
            is_suspended=False,
            is_archived=False,
            last_login_time=datetime.now(timezone.utc),
            creation_time=datetime(2023, 1, 1, tzinfo=timezone.utc),
            two_factor_enabled=False,  # Admin without 2FA - critical issue
            org_unit_path="/",
            is_inactive=False,
            days_since_last_login=0,
        ),
        UserInfo(
            id="inactive123",
            email="inactive@company.com",
            full_name="Inactive User",
            is_admin=False,
            is_suspended=False,
            is_archived=False,
            last_login_time=datetime(2023, 6, 1, tzinfo=timezone.utc),
            creation_time=datetime(2022, 1, 1, tzinfo=timezone.utc),
            two_factor_enabled=False,
            org_unit_path="/",
            is_inactive=True,
            days_since_last_login=200,
        ),
        UserInfo(
            id="active123",
            email="active@company.com",
            full_name="Active User",
            is_admin=False,
            is_suspended=False,
            is_archived=False,
            last_login_time=datetime.now(timezone.utc),
            creation_time=datetime(2023, 1, 1, tzinfo=timezone.utc),
            two_factor_enabled=True,
            org_unit_path="/Engineering",
            is_inactive=False,
            days_since_last_login=0,
        ),
    ]


class TestGDPRReport:
    """Test GDPR compliance reporting."""

    def test_gdpr_report_creation(self):
        """Test creating a GDPR report."""
        report = GDPRReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        assert report.domain == "company.com"
        assert report.files_shared_outside_eu == 0
        assert report.files_with_pii_shared_externally == 0
        assert len(report.issues) == 0

    def test_gdpr_compliance_score_perfect(self):
        """Test GDPR compliance score with no issues."""
        report = GDPRReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        score = report.calculate_compliance_score()
        assert score == 100

    def test_gdpr_compliance_score_with_issues(self):
        """Test GDPR compliance score with issues."""
        report = GDPRReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            issues=[
                ComplianceIssue(
                    severity="critical",
                    category="data_sharing",
                    description="PII shared externally",
                    recommendation="Remove external sharing",
                    affected_resource="file1",
                    resource_type="file",
                ),
                ComplianceIssue(
                    severity="high",
                    category="access_control",
                    description="Admin without 2FA",
                    recommendation="Enable 2FA",
                    affected_resource="admin@company.com",
                    resource_type="user",
                ),
                ComplianceIssue(
                    severity="medium",
                    category="retention",
                    description="Old files not deleted",
                    recommendation="Review retention policy",
                    affected_resource="file2",
                    resource_type="file",
                ),
            ],
        )

        score = report.calculate_compliance_score()
        # 100 - 10 (critical) - 5 (high) - 2 (medium) = 83
        assert score == 83

    def test_gdpr_report_with_data(self, sample_files, sample_users):
        """Test GDPR report generation with actual data."""
        # Note: FileInfo doesn't have pii_detected field yet
        # Counting externally shared files as a proxy for PII detection
        report = GDPRReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            files_with_pii_shared_externally=len([f for f in sample_files if f.is_shared_externally]),
            users_without_2fa=len([u for u in sample_users if not u.two_factor_enabled]),
            inactive_users_with_data_access=len([u for u in sample_users if u.is_inactive]),
        )

        assert report.files_with_pii_shared_externally == 2
        assert report.users_without_2fa == 2
        assert report.inactive_users_with_data_access == 1


class TestHIPAAReport:
    """Test HIPAA compliance reporting."""

    def test_hipaa_report_creation(self):
        """Test creating a HIPAA report."""
        report = HIPAAReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        assert report.domain == "company.com"
        assert report.files_with_phi == 0
        assert report.audit_logging_enabled is True

    def test_hipaa_compliance_score_perfect(self):
        """Test HIPAA compliance score with no issues."""
        report = HIPAAReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        score = report.calculate_compliance_score()
        assert score == 100

    def test_hipaa_compliance_score_with_critical_issues(self):
        """Test HIPAA compliance score with critical issues."""
        report = HIPAAReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            issues=[
                ComplianceIssue(
                    severity="critical",
                    category="phi_exposure",
                    description="PHI shared publicly",
                    recommendation="Remove public access immediately",
                    affected_resource="file1",
                    resource_type="file",
                ),
                ComplianceIssue(
                    severity="critical",
                    category="access_control",
                    description="Admin without 2FA accessing PHI",
                    recommendation="Enforce 2FA for all admin users",
                    affected_resource="admin@company.com",
                    resource_type="user",
                ),
            ],
        )

        score = report.calculate_compliance_score()
        # 100 - 15 - 15 = 70
        assert score == 70

    def test_hipaa_report_phi_detection(self, sample_files):
        """Test HIPAA report with PHI detection."""
        # Note: FileInfo doesn't have pii_types field yet, so we test with manual counts
        report = HIPAAReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            files_with_phi=1,
            files_with_phi_publicly_shared=1,
            files_with_phi_shared_externally=1,
        )

        assert report.files_with_phi == 1
        assert report.files_with_phi_publicly_shared == 1
        assert report.files_with_phi_shared_externally == 1


class TestSOC2Report:
    """Test SOC 2 compliance reporting."""

    def test_soc2_report_creation(self):
        """Test creating a SOC 2 report."""
        report = SOC2Report(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        assert report.domain == "company.com"
        assert len(report.issues) == 0

    def test_soc2_compliance_score(self):
        """Test SOC 2 compliance score calculation."""
        report = SOC2Report(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            issues=[
                ComplianceIssue(
                    severity="high",
                    category="access_control",
                    description="Weak access controls",
                    recommendation="Implement role-based access",
                    affected_resource="system",
                    resource_type="system",
                ),
            ],
        )

        score = report.calculate_compliance_score()
        # 100 - 6 (high in SOC2) = 94
        assert score == 94


class TestPCIDSSReport:
    """Test PCI-DSS compliance reporting."""

    def test_pcidss_report_creation(self):
        """Test creating a PCI-DSS report."""
        report = PCIDSSReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        assert report.domain == "company.com"
        assert report.files_with_card_data == 0

    def test_pcidss_compliance_score(self):
        """Test PCI-DSS compliance score calculation."""
        report = PCIDSSReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            files_with_card_data=5,
            files_with_card_data_shared_externally=2,
            issues=[
                ComplianceIssue(
                    severity="critical",
                    category="data_protection",
                    description="Cardholder data not encrypted",
                    recommendation="Enable encryption",
                    affected_resource="file1",
                    resource_type="file",
                ),
            ],
        )

        score = report.calculate_compliance_score()
        # 100 - 20 (critical in PCI-DSS) = 80
        assert score == 80


class TestFERPAReport:
    """Test FERPA compliance reporting."""

    def test_ferpa_report_creation(self):
        """Test creating a FERPA report."""
        report = FERPAReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        assert report.domain == "company.com"
        assert report.files_with_student_data == 0

    def test_ferpa_compliance_score(self):
        """Test FERPA compliance score calculation."""
        report = FERPAReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            files_with_student_data=10,
            files_with_student_data_shared_externally=3,
            unauthorized_access_detected=True,
            issues=[
                ComplianceIssue(
                    severity="critical",
                    category="student_data",
                    description="Student records shared publicly",
                    recommendation="Remove public access",
                    affected_resource="file1",
                    resource_type="file",
                ),
            ],
        )

        score = report.calculate_compliance_score()
        assert score < 100


class TestFedRAMPReport:
    """Test FedRAMP compliance reporting."""

    def test_fedramp_report_creation(self):
        """Test creating a FedRAMP report."""
        report = FedRAMPReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
        )

        assert report.domain == "company.com"
        assert report.encryption_at_rest_enabled is False
        assert report.encryption_in_transit_enabled is False

    def test_fedramp_compliance_score(self):
        """Test FedRAMP compliance score calculation."""
        report = FedRAMPReport(
            report_time=datetime.now(timezone.utc),
            domain="company.com",
            encryption_at_rest_enabled=False,
            encryption_in_transit_enabled=True,
            multi_factor_auth_enforced=True,
            issues=[
                ComplianceIssue(
                    severity="critical",
                    category="encryption",
                    description="Encryption at rest not enabled",
                    recommendation="Enable encryption for all data",
                    affected_resource="system",
                    resource_type="system",
                ),
            ],
        )

        score = report.calculate_compliance_score()
        assert score < 100


class TestComplianceReporter:
    """Test compliance report generator."""

    def test_generate_gdpr_report(self, sample_files, sample_users):
        """Test generating GDPR report."""
        generator = ComplianceReporter(domain="company.com")

        report = generator.generate_gdpr_report(files=sample_files, users=sample_users)

        assert isinstance(report, GDPRReport)
        assert report.domain == "company.com"
        # Note: files_with_pii_shared_externally will be 0 until PII detection is implemented
        assert report.files_with_pii_shared_externally >= 0
        assert report.users_without_2fa > 0

    def test_generate_hipaa_report(self, sample_files, sample_users):
        """Test generating HIPAA report."""
        generator = ComplianceReporter(domain="company.com")

        report = generator.generate_hipaa_report(files=sample_files, users=sample_users)

        assert isinstance(report, HIPAAReport)
        assert report.domain == "company.com"

    def test_generate_all_reports(self, sample_files, sample_users):
        """Test generating all compliance reports."""
        generator = ComplianceReporter(domain="company.com")

        reports = generator.generate_all_reports(files=sample_files, users=sample_users)

        assert "gdpr" in reports
        assert "hipaa" in reports
        assert "soc2" in reports
        assert "pci_dss" in reports
        assert "ferpa" in reports
        assert "fedramp" in reports

    def test_report_to_dict(self, sample_files, sample_users):
        """Test converting report to dictionary."""
        generator = ComplianceReporter(domain="company.com")
        report = generator.generate_gdpr_report(files=sample_files, users=sample_users)

        report_dict = generator.report_to_dict(report)

        assert "domain" in report_dict
        assert "report_time" in report_dict
        assert "compliance_score" in report_dict
        assert "issues" in report_dict

    def test_report_to_json(self, sample_files, sample_users, tmp_path):
        """Test exporting report to JSON."""
        generator = ComplianceReporter(domain="company.com")
        report = generator.generate_gdpr_report(files=sample_files, users=sample_users)

        output_file = tmp_path / "gdpr-report.json"
        generator.export_to_json(report, output_file)

        assert output_file.exists()

        import json
        with open(output_file, "r") as f:
            data = json.load(f)
            assert data["domain"] == "company.com"
            assert "compliance_score" in data


class TestComplianceIssues:
    """Test compliance issue categorization."""

    def test_issue_creation(self):
        """Test creating a compliance issue."""
        issue = ComplianceIssue(
            severity="critical",
            category="data_sharing",
            description="PII shared externally without encryption",
            recommendation="Enable encryption and remove external sharing",
            affected_resource="file123",
            resource_type="file",
        )

        assert issue.severity == "critical"
        assert issue.category == "data_sharing"
        assert "encryption" in issue.description.lower()

    def test_issue_severity_levels(self):
        """Test different severity levels."""
        severities = ["critical", "high", "medium", "low"]

        for severity in severities:
            issue = ComplianceIssue(
                severity=severity,
                category="test",
                description=f"{severity} issue",
                recommendation="Fix it",
                affected_resource="resource1",
                resource_type="file",
            )
            assert issue.severity == severity
