"""Integration tests for findings API."""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import (
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
    ScanRun,
    Domain,
    User,
    UserDomain,
)


class TestSecurityFindings:
    """Test security findings endpoints."""

    @pytest.fixture
    def security_findings(self, db: Session, test_scan_run: ScanRun) -> list:
        """Create test security findings."""
        findings = [
            SecurityFinding(
                scan_run_id=test_scan_run.id,
                check_id="SEC001",
                title="2FA Not Enforced",
                description="Two-factor authentication is not enforced for all users",
                severity="critical",
                passed=False,
                remediation="Enable 2FA enforcement in Admin Console",
                frameworks=["CIS", "SOC2"],
                detected_at=datetime.utcnow(),
            ),
            SecurityFinding(
                scan_run_id=test_scan_run.id,
                check_id="SEC002",
                title="Password Policy Weak",
                description="Password policy does not meet security standards",
                severity="high",
                passed=False,
                remediation="Strengthen password requirements",
                frameworks=["CIS"],
                detected_at=datetime.utcnow(),
            ),
            SecurityFinding(
                scan_run_id=test_scan_run.id,
                check_id="SEC003",
                title="Session Timeout Configured",
                description="Session timeout is properly configured",
                severity="info",
                passed=True,
                detected_at=datetime.utcnow(),
            ),
        ]
        for finding in findings:
            db.add(finding)
        db.commit()
        return findings

    def test_get_security_findings(
        self, client: TestClient, superuser_headers, security_findings
    ):
        """Test getting security findings."""
        response = client.get("/api/findings/security", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert len(data["items"]) >= 2  # At least the non-passed findings

    def test_get_security_findings_by_severity(
        self, client: TestClient, superuser_headers, security_findings
    ):
        """Test filtering security findings by severity."""
        response = client.get(
            "/api/findings/security",
            params={"severity": "critical"},
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for finding in data["items"]:
            assert finding["severity"] == "critical"

    def test_get_security_findings_summary(
        self, client: TestClient, superuser_headers, security_findings
    ):
        """Test getting security findings summary."""
        response = client.get("/api/findings/security/summary", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_findings" in data
        assert "by_severity" in data
        assert "passed" in data
        assert "failed" in data

    def test_update_finding_status(
        self, client: TestClient, superuser_headers, security_findings, db: Session
    ):
        """Test updating finding status."""
        finding = security_findings[0]
        response = client.patch(
            f"/api/findings/security/{finding.id}/status",
            json={"status": "acknowledged", "notes": "Acknowledged by admin"},
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "acknowledged"
        assert "updated_at" in data

    def test_update_finding_status_invalid(
        self, client: TestClient, superuser_headers, security_findings
    ):
        """Test updating finding with invalid status."""
        finding = security_findings[0]
        response = client.patch(
            f"/api/findings/security/{finding.id}/status",
            json={"status": "invalid_status"},
            headers=superuser_headers,
        )
        assert response.status_code == 400

    def test_get_single_finding(
        self, client: TestClient, superuser_headers, security_findings
    ):
        """Test getting a single security finding."""
        finding = security_findings[0]
        response = client.get(
            f"/api/findings/security/{finding.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == finding.id
        assert data["check_id"] == "SEC001"


class TestFileFindings:
    """Test file findings endpoints."""

    @pytest.fixture
    def file_findings(self, db: Session, test_scan_run: ScanRun) -> list:
        """Create test file findings."""
        findings = [
            FileFinding(
                scan_run_id=test_scan_run.id,
                file_id="file123",
                file_name="sensitive_data.xlsx",
                owner_email="user@example.com",
                mime_type="application/vnd.ms-excel",
                is_public=True,
                is_shared_externally=True,
                risk_score=85,
                pii_detected=True,
                pii_types=["SSN", "Email"],
                detected_at=datetime.utcnow(),
            ),
            FileFinding(
                scan_run_id=test_scan_run.id,
                file_id="file456",
                file_name="report.pdf",
                owner_email="user@example.com",
                mime_type="application/pdf",
                is_public=False,
                is_shared_externally=True,
                risk_score=60,
                pii_detected=False,
                detected_at=datetime.utcnow(),
            ),
        ]
        for finding in findings:
            db.add(finding)
        db.commit()
        return findings

    def test_get_high_risk_files(
        self, client: TestClient, superuser_headers, file_findings
    ):
        """Test getting high risk files."""
        response = client.get("/api/findings/files/high-risk", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        # Should only return files with risk_score >= 70
        for file in data["items"]:
            assert file["risk_score"] >= 70

    def test_get_public_files(
        self, client: TestClient, superuser_headers, file_findings
    ):
        """Test getting public files."""
        response = client.get("/api/findings/files/public", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        for file in data["items"]:
            assert file["is_public"] is True

    def test_get_files_with_pii(
        self, client: TestClient, superuser_headers, file_findings
    ):
        """Test getting files with PII."""
        response = client.get("/api/findings/files/pii", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        for file in data["items"]:
            assert file["pii_detected"] is True


class TestUserFindings:
    """Test user findings endpoints."""

    @pytest.fixture
    def user_findings(self, db: Session, test_scan_run: ScanRun) -> list:
        """Create test user findings."""
        findings = [
            UserFinding(
                scan_run_id=test_scan_run.id,
                user_id="user123",
                email="inactive@example.com",
                full_name="Inactive User",
                is_admin=False,
                is_suspended=False,
                last_login_time=datetime.utcnow() - timedelta(days=120),
                two_factor_enabled=False,
                is_inactive=True,
                days_since_last_login=120,
                risk_score=75,
                detected_at=datetime.utcnow(),
            ),
            UserFinding(
                scan_run_id=test_scan_run.id,
                user_id="user456",
                email="admin@example.com",
                full_name="Admin Without 2FA",
                is_admin=True,
                is_suspended=False,
                last_login_time=datetime.utcnow(),
                two_factor_enabled=False,
                is_inactive=False,
                days_since_last_login=0,
                risk_score=90,
                detected_at=datetime.utcnow(),
            ),
        ]
        for finding in findings:
            db.add(finding)
        db.commit()
        return findings

    def test_get_inactive_users(
        self, client: TestClient, superuser_headers, user_findings
    ):
        """Test getting inactive users."""
        response = client.get(
            "/api/findings/users/inactive",
            params={"min_days": 90},
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for user in data["items"]:
            assert user["days_since_last_login"] >= 90 or user["is_inactive"]

    def test_get_users_without_2fa(
        self, client: TestClient, superuser_headers, user_findings
    ):
        """Test getting users without 2FA."""
        response = client.get("/api/findings/users/no-2fa", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        for user in data["items"]:
            assert user["two_factor_enabled"] is False


class TestOAuthFindings:
    """Test OAuth findings endpoints."""

    @pytest.fixture
    def oauth_findings(self, db: Session, test_scan_run: ScanRun) -> list:
        """Create test OAuth findings."""
        findings = [
            OAuthFinding(
                scan_run_id=test_scan_run.id,
                client_id="client123",
                display_text="Suspicious App",
                scopes=["https://mail.google.com/", "https://www.googleapis.com/auth/drive"],
                user_count=5,
                risk_score=80,
                is_verified=False,
                is_google_app=False,
                is_internal=False,
                detected_at=datetime.utcnow(),
            ),
            OAuthFinding(
                scan_run_id=test_scan_run.id,
                client_id="client456",
                display_text="Verified App",
                scopes=["https://www.googleapis.com/auth/calendar.readonly"],
                user_count=10,
                risk_score=30,
                is_verified=True,
                is_google_app=False,
                is_internal=False,
                detected_at=datetime.utcnow(),
            ),
        ]
        for finding in findings:
            db.add(finding)
        db.commit()
        return findings

    def test_get_risky_oauth_apps(
        self, client: TestClient, superuser_headers, oauth_findings
    ):
        """Test getting risky OAuth apps."""
        response = client.get(
            "/api/findings/oauth/risky",
            params={"min_risk_score": 50},
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for app in data["items"]:
            assert app["risk_score"] >= 50


class TestFindingsExport:
    """Test findings export endpoints."""

    def test_export_security_findings_csv(
        self, client: TestClient, superuser_headers, db: Session, test_scan_run: ScanRun
    ):
        """Test exporting security findings as CSV."""
        # Create a finding first
        finding = SecurityFinding(
            scan_run_id=test_scan_run.id,
            check_id="SEC001",
            title="Test Finding",
            severity="high",
            passed=False,
            detected_at=datetime.utcnow(),
        )
        db.add(finding)
        db.commit()

        response = client.get(
            "/api/findings/export/security",
            params={"format": "csv"},
            headers=superuser_headers,
        )
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]

    def test_export_security_findings_json(
        self, client: TestClient, superuser_headers, db: Session, test_scan_run: ScanRun
    ):
        """Test exporting security findings as JSON."""
        finding = SecurityFinding(
            scan_run_id=test_scan_run.id,
            check_id="SEC002",
            title="Test Finding 2",
            severity="medium",
            passed=False,
            detected_at=datetime.utcnow(),
        )
        db.add(finding)
        db.commit()

        response = client.get(
            "/api/findings/export/security",
            params={"format": "json"},
            headers=superuser_headers,
        )
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]


class TestFindingsUnauthorized:
    """Test that findings endpoints require authentication."""

    def test_security_findings_unauthorized(self, client: TestClient):
        """Test that security findings require auth."""
        response = client.get("/api/findings/security")
        assert response.status_code == 401

    def test_file_findings_unauthorized(self, client: TestClient):
        """Test that file findings require auth."""
        response = client.get("/api/findings/files/high-risk")
        assert response.status_code == 401

    def test_user_findings_unauthorized(self, client: TestClient):
        """Test that user findings require auth."""
        response = client.get("/api/findings/users/inactive")
        assert response.status_code == 401

    def test_oauth_findings_unauthorized(self, client: TestClient):
        """Test that OAuth findings require auth."""
        response = client.get("/api/findings/oauth/risky")
        assert response.status_code == 401
