"""Integration tests for compliance API."""

import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import (
    ComplianceReport,
    ScheduledReport,
    Domain,
    ScanRun,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
    User,
    UserDomain,
)


class TestComplianceFrameworks:
    """Test compliance frameworks endpoint."""

    def test_get_frameworks(self, client: TestClient, superuser_headers):
        """Test getting list of supported compliance frameworks."""
        response = client.get("/api/compliance/frameworks", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 6  # gdpr, hipaa, soc2, pci-dss, ferpa, fedramp

        framework_ids = [f["id"] for f in data]
        assert "gdpr" in framework_ids
        assert "hipaa" in framework_ids
        assert "soc2" in framework_ids
        assert "pci-dss" in framework_ids

    def test_get_frameworks_unauthenticated(self, client: TestClient):
        """Test that frameworks endpoint requires authentication."""
        response = client.get("/api/compliance/frameworks")
        assert response.status_code == 401


class TestComplianceReports:
    """Test compliance report CRUD operations."""

    @pytest.fixture
    def compliance_report(self, db: Session, test_domain: Domain, test_superuser: User) -> ComplianceReport:
        """Create a test compliance report."""
        report = ComplianceReport(
            domain_id=test_domain.id,
            domain_name=test_domain.name,
            framework="gdpr",
            status="completed",
            compliance_score=75,
            total_checks=10,
            passed_checks=7,
            failed_checks=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=0,
            report_data={
                "framework": "gdpr",
                "issues": [
                    {
                        "check_id": "GDPR-1",
                        "title": "PII in Externally Shared Files",
                        "description": "Found 2 files with PII shared externally",
                        "severity": "critical",
                        "category": "Data Protection",
                        "remediation": "Review and restrict external sharing",
                    },
                    {
                        "check_id": "GDPR-3",
                        "title": "Two-Factor Authentication",
                        "description": "3 users without 2FA enabled",
                        "severity": "high",
                        "category": "Access Control",
                        "remediation": "Enforce 2FA for all users",
                    },
                ]
            },
            generated_by=test_superuser.id,
            generated_at=datetime.utcnow(),
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    def test_list_compliance_reports(
        self, client: TestClient, superuser_headers, compliance_report
    ):
        """Test listing compliance reports."""
        response = client.get("/api/compliance", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert len(data["items"]) >= 1

    def test_list_compliance_reports_filter_by_domain(
        self, client: TestClient, superuser_headers, compliance_report, test_domain
    ):
        """Test filtering compliance reports by domain."""
        response = client.get(
            f"/api/compliance?domain={test_domain.name}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for report in data["items"]:
            assert report["domain_name"] == test_domain.name

    def test_list_compliance_reports_filter_by_framework(
        self, client: TestClient, superuser_headers, compliance_report
    ):
        """Test filtering compliance reports by framework."""
        response = client.get(
            "/api/compliance?framework=gdpr",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for report in data["items"]:
            assert report["framework"] == "gdpr"

    def test_list_compliance_reports_invalid_framework(
        self, client: TestClient, superuser_headers
    ):
        """Test filtering with invalid framework returns error."""
        response = client.get(
            "/api/compliance?framework=invalid",
            headers=superuser_headers,
        )
        assert response.status_code == 400
        assert "Invalid framework" in response.json()["detail"]

    def test_get_compliance_report_detail(
        self, client: TestClient, superuser_headers, compliance_report
    ):
        """Test getting a specific compliance report."""
        response = client.get(
            f"/api/compliance/{compliance_report.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == compliance_report.id
        assert data["framework"] == "gdpr"
        assert data["compliance_score"] == 75
        assert "issues" in data
        assert len(data["issues"]) == 2

    def test_get_compliance_report_not_found(
        self, client: TestClient, superuser_headers
    ):
        """Test getting non-existent compliance report."""
        response = client.get(
            "/api/compliance/99999",
            headers=superuser_headers,
        )
        assert response.status_code == 404

    def test_delete_compliance_report(
        self, client: TestClient, superuser_headers, compliance_report
    ):
        """Test deleting a compliance report."""
        response = client.delete(
            f"/api/compliance/{compliance_report.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 204

        # Verify it's deleted
        response = client.get(
            f"/api/compliance/{compliance_report.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 404


class TestGenerateComplianceReport:
    """Test compliance report generation."""

    @pytest.fixture
    def scan_with_findings(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create a completed scan with various findings."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            total_items=50,
            issues_found=5,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Add security findings
        security_findings = [
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-2FA",
                title="2FA Not Enforced",
                severity="high",
                passed=False,
            ),
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-AUDIT",
                title="Audit Logging Enabled",
                severity="medium",
                passed=True,
            ),
        ]
        for f in security_findings:
            db.add(f)

        # Add file findings
        file_findings = [
            FileFinding(
                scan_run_id=scan.id,
                file_id="file1",
                file_name="sensitive.xlsx",
                owner_email="user@example.com",
                is_public=True,
                is_shared_externally=True,
                pii_detected=True,
                pii_types=["SSN"],
                risk_score=85,
            ),
        ]
        for f in file_findings:
            db.add(f)

        # Add user findings
        user_findings = [
            UserFinding(
                scan_run_id=scan.id,
                user_id="user1",
                email="user1@example.com",
                full_name="User One",
                is_admin=False,
                two_factor_enabled=False,
                is_inactive=True,
                days_since_last_login=120,
                risk_score=70,
            ),
        ]
        for f in user_findings:
            db.add(f)

        # Add OAuth findings
        oauth_findings = [
            OAuthFinding(
                scan_run_id=scan.id,
                client_id="app1",
                display_text="Risky App",
                is_verified=False,
                risk_score=75,
            ),
        ]
        for f in oauth_findings:
            db.add(f)

        db.commit()
        return scan

    def test_generate_gdpr_report(
        self, client: TestClient, superuser_headers, test_domain, scan_with_findings
    ):
        """Test generating a GDPR compliance report."""
        response = client.post(
            "/api/compliance",
            json={
                "domain_name": test_domain.name,
                "framework": "gdpr",
            },
            headers=superuser_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["framework"] == "gdpr"
        assert data["status"] == "completed"
        assert data["total_checks"] > 0
        assert "compliance_score" in data
        assert data["domain_name"] == test_domain.name

    def test_generate_hipaa_report(
        self, client: TestClient, superuser_headers, test_domain, scan_with_findings
    ):
        """Test generating a HIPAA compliance report."""
        response = client.post(
            "/api/compliance",
            json={
                "domain_name": test_domain.name,
                "framework": "hipaa",
            },
            headers=superuser_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["framework"] == "hipaa"
        assert data["total_checks"] >= 10

    def test_generate_soc2_report(
        self, client: TestClient, superuser_headers, test_domain, scan_with_findings
    ):
        """Test generating a SOC 2 compliance report."""
        response = client.post(
            "/api/compliance",
            json={
                "domain_name": test_domain.name,
                "framework": "soc2",
            },
            headers=superuser_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["framework"] == "soc2"
        assert data["total_checks"] >= 10

    def test_generate_report_invalid_framework(
        self, client: TestClient, superuser_headers, test_domain
    ):
        """Test generating report with invalid framework."""
        response = client.post(
            "/api/compliance",
            json={
                "domain_name": test_domain.name,
                "framework": "invalid-framework",
            },
            headers=superuser_headers,
        )
        assert response.status_code == 400

    def test_generate_report_domain_not_found(
        self, client: TestClient, superuser_headers
    ):
        """Test generating report for non-existent domain."""
        response = client.post(
            "/api/compliance",
            json={
                "domain_name": "nonexistent.com",
                "framework": "gdpr",
            },
            headers=superuser_headers,
        )
        assert response.status_code in [403, 404]

    def test_generate_report_with_scan_id(
        self, client: TestClient, superuser_headers, test_domain, scan_with_findings
    ):
        """Test generating report based on specific scan run."""
        response = client.post(
            "/api/compliance",
            json={
                "domain_name": test_domain.name,
                "framework": "pci-dss",
                "scan_run_id": scan_with_findings.id,
            },
            headers=superuser_headers,
        )
        assert response.status_code == 201


class TestScheduledReports:
    """Test scheduled report CRUD operations."""

    @pytest.fixture
    def editor_user(self, db: Session, test_domain: Domain) -> tuple:
        """Create a user with editor role on the test domain."""
        from backend.auth.security import get_password_hash, create_access_token

        user = User(
            email="editor@example.com",
            hashed_password=get_password_hash("editorpassword"),
            full_name="Editor User",
            is_active=True,
            is_superuser=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Give editor role on domain
        user_domain = UserDomain(
            user_id=user.id,
            domain=test_domain.name,
            role="editor",
        )
        db.add(user_domain)
        db.commit()

        token = create_access_token(
            data={"sub": user.email, "user_id": user.id}
        )
        headers = {"Authorization": f"Bearer {token}"}
        return user, headers

    @pytest.fixture
    def scheduled_report(self, db: Session, test_domain: Domain, test_superuser: User) -> ScheduledReport:
        """Create a test scheduled report."""
        schedule = ScheduledReport(
            name="Weekly GDPR Report",
            domain_id=test_domain.id,
            framework="gdpr",
            schedule_type="weekly",
            schedule_config={"day_of_week": 1, "hour": 9},
            recipients=["admin@example.com"],
            is_active=True,
            created_by=test_superuser.id,
            next_run=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()
        db.refresh(schedule)
        return schedule

    def test_list_scheduled_reports(
        self, client: TestClient, superuser_headers, scheduled_report
    ):
        """Test listing scheduled reports."""
        response = client.get("/api/compliance/schedules", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert len(data["items"]) >= 1

    def test_list_scheduled_reports_filter_active(
        self, client: TestClient, superuser_headers, scheduled_report
    ):
        """Test filtering scheduled reports by active status."""
        response = client.get(
            "/api/compliance/schedules?is_active=true",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for schedule in data["items"]:
            assert schedule["is_active"] is True

    def test_create_scheduled_report(
        self, client: TestClient, superuser_headers, test_domain
    ):
        """Test creating a scheduled report."""
        response = client.post(
            "/api/compliance/schedules",
            json={
                "name": "Daily SOC2 Report",
                "domain_name": test_domain.name,
                "framework": "soc2",
                "schedule_type": "daily",
                "schedule_config": {"hour": 6},
                "recipients": ["security@example.com"],
                "is_active": True,
            },
            headers=superuser_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Daily SOC2 Report"
        assert data["framework"] == "soc2"
        assert data["schedule_type"] == "daily"
        assert data["is_active"] is True
        assert data["next_run"] is not None

    def test_create_scheduled_report_as_editor(
        self, client: TestClient, editor_user, test_domain
    ):
        """Test that editor users can create scheduled reports."""
        _, headers = editor_user
        response = client.post(
            "/api/compliance/schedules",
            json={
                "name": "Monthly HIPAA Report",
                "domain_name": test_domain.name,
                "framework": "hipaa",
                "schedule_type": "monthly",
                "schedule_config": {"day": 1, "hour": 8},
                "is_active": True,
            },
            headers=headers,
        )
        assert response.status_code == 201

    def test_create_scheduled_report_invalid_framework(
        self, client: TestClient, superuser_headers, test_domain
    ):
        """Test creating scheduled report with invalid framework."""
        response = client.post(
            "/api/compliance/schedules",
            json={
                "name": "Invalid Report",
                "domain_name": test_domain.name,
                "framework": "invalid",
                "schedule_type": "daily",
            },
            headers=superuser_headers,
        )
        assert response.status_code == 400

    def test_create_scheduled_report_invalid_schedule_type(
        self, client: TestClient, superuser_headers, test_domain
    ):
        """Test creating scheduled report with invalid schedule type."""
        response = client.post(
            "/api/compliance/schedules",
            json={
                "name": "Invalid Schedule",
                "domain_name": test_domain.name,
                "framework": "gdpr",
                "schedule_type": "hourly",  # Invalid
            },
            headers=superuser_headers,
        )
        assert response.status_code == 400

    def test_get_scheduled_report(
        self, client: TestClient, superuser_headers, scheduled_report
    ):
        """Test getting a specific scheduled report."""
        response = client.get(
            f"/api/compliance/schedules/{scheduled_report.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == scheduled_report.id
        assert data["name"] == "Weekly GDPR Report"

    def test_get_scheduled_report_not_found(
        self, client: TestClient, superuser_headers
    ):
        """Test getting non-existent scheduled report."""
        response = client.get(
            "/api/compliance/schedules/99999",
            headers=superuser_headers,
        )
        assert response.status_code == 404

    def test_update_scheduled_report(
        self, client: TestClient, superuser_headers, scheduled_report
    ):
        """Test updating a scheduled report."""
        response = client.put(
            f"/api/compliance/schedules/{scheduled_report.id}",
            json={
                "name": "Updated Report Name",
                "schedule_type": "monthly",
                "schedule_config": {"day": 15, "hour": 10},
            },
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Report Name"
        assert data["schedule_type"] == "monthly"

    def test_toggle_scheduled_report(
        self, client: TestClient, superuser_headers, scheduled_report
    ):
        """Test toggling a scheduled report's active status."""
        # Initially active
        assert scheduled_report.is_active is True

        # Toggle to inactive
        response = client.post(
            f"/api/compliance/schedules/{scheduled_report.id}/toggle",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False

        # Toggle back to active
        response = client.post(
            f"/api/compliance/schedules/{scheduled_report.id}/toggle",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is True

    def test_delete_scheduled_report(
        self, client: TestClient, superuser_headers, scheduled_report
    ):
        """Test deleting a scheduled report."""
        response = client.delete(
            f"/api/compliance/schedules/{scheduled_report.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 204

        # Verify it's deleted
        response = client.get(
            f"/api/compliance/schedules/{scheduled_report.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 404


class TestComplianceReportsUnauthorized:
    """Test that compliance endpoints require proper authentication."""

    def test_list_reports_unauthorized(self, client: TestClient):
        """Test that listing reports requires authentication."""
        response = client.get("/api/compliance")
        assert response.status_code == 401

    def test_generate_report_unauthorized(self, client: TestClient):
        """Test that generating reports requires authentication."""
        response = client.post(
            "/api/compliance",
            json={"domain_name": "test.com", "framework": "gdpr"},
        )
        assert response.status_code == 401

    def test_list_schedules_unauthorized(self, client: TestClient):
        """Test that listing schedules requires authentication."""
        response = client.get("/api/compliance/schedules")
        assert response.status_code == 401


class TestComplianceReportsDomainAccess:
    """Test domain-based access control for compliance reports."""

    @pytest.fixture
    def viewer_user(self, db: Session, test_domain: Domain) -> tuple:
        """Create a user with viewer role on the test domain."""
        from backend.auth.security import get_password_hash, create_access_token

        user = User(
            email="viewer@example.com",
            hashed_password=get_password_hash("viewerpassword"),
            full_name="Viewer User",
            is_active=True,
            is_superuser=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Give viewer role on domain
        user_domain = UserDomain(
            user_id=user.id,
            domain=test_domain.name,
            role="viewer",
        )
        db.add(user_domain)
        db.commit()

        token = create_access_token(
            data={"sub": user.email, "user_id": user.id}
        )
        headers = {"Authorization": f"Bearer {token}"}
        return user, headers

    def test_viewer_cannot_create_scheduled_report(
        self, client: TestClient, viewer_user, test_domain
    ):
        """Test that viewer users cannot create scheduled reports."""
        _, headers = viewer_user
        response = client.post(
            "/api/compliance/schedules",
            json={
                "name": "Viewer Schedule",
                "domain_name": test_domain.name,
                "framework": "gdpr",
                "schedule_type": "daily",
            },
            headers=headers,
        )
        assert response.status_code == 403

    def test_viewer_can_list_reports(
        self, client: TestClient, viewer_user, db: Session, test_domain, test_superuser
    ):
        """Test that viewer users can list compliance reports for their domain."""
        # Create a report first
        report = ComplianceReport(
            domain_id=test_domain.id,
            domain_name=test_domain.name,
            framework="gdpr",
            status="completed",
            compliance_score=80,
            total_checks=10,
            passed_checks=8,
            failed_checks=2,
            generated_by=test_superuser.id,
            generated_at=datetime.utcnow(),
        )
        db.add(report)
        db.commit()

        _, headers = viewer_user
        response = client.get("/api/compliance", headers=headers)
        assert response.status_code == 200
        data = response.json()
        # Viewer should only see reports from their domain
        for r in data["items"]:
            assert r["domain_name"] == test_domain.name
