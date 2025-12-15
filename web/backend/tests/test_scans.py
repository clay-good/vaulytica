"""Tests for scans API."""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import ScanRun, SecurityFinding


class TestScansRoutes:
    """Test scans API routes."""

    def test_get_recent_scans_authenticated(
        self, client: TestClient, superuser_headers, test_scan_run
    ):
        """Test getting recent scans as authenticated user."""
        response = client.get("/api/scans/recent", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert data[0]["scan_type"] == "posture"

    def test_get_recent_scans_unauthenticated(self, client: TestClient):
        """Test getting recent scans without auth."""
        response = client.get("/api/scans/recent")
        assert response.status_code == 401

    def test_get_recent_scans_with_domain_filter(
        self, client: TestClient, superuser_headers, test_scan_run, test_domain
    ):
        """Test getting recent scans with domain filter."""
        response = client.get(
            f"/api/scans/recent?domain={test_domain.name}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert all(s["domain_name"] == test_domain.name for s in data)

    def test_get_recent_scans_with_type_filter(
        self, client: TestClient, superuser_headers, test_scan_run
    ):
        """Test getting recent scans with scan type filter."""
        response = client.get(
            "/api/scans/recent?scan_type=posture",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert all(s["scan_type"] == "posture" for s in data)

    def test_get_scan_stats(self, client: TestClient, superuser_headers, test_scan_run):
        """Test getting scan statistics."""
        response = client.get("/api/scans/stats", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "completed_scans" in data
        assert "success_rate" in data
        assert data["total_scans"] >= 1

    def test_get_scan_details(
        self, client: TestClient, superuser_headers, test_scan_run
    ):
        """Test getting scan details."""
        response = client.get(
            f"/api/scans/{test_scan_run.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_scan_run.id
        assert data["scan_type"] == "posture"
        assert data["status"] == "completed"

    def test_get_scan_details_not_found(
        self, client: TestClient, superuser_headers
    ):
        """Test getting non-existent scan."""
        response = client.get("/api/scans/99999", headers=superuser_headers)
        assert response.status_code == 404

    def test_get_scan_security_findings(
        self, client: TestClient, superuser_headers, db: Session, test_scan_run
    ):
        """Test getting security findings for a scan."""
        # Create test finding
        finding = SecurityFinding(
            scan_run_id=test_scan_run.id,
            check_id="SEC-001",
            title="Test Finding",
            severity="high",
            passed=False,
            description="Test description",
        )
        db.add(finding)
        db.commit()

        response = client.get(
            f"/api/scans/{test_scan_run.id}/findings/security",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert data[0]["check_id"] == "SEC-001"

    def test_get_scan_security_findings_filtered(
        self, client: TestClient, superuser_headers, db: Session, test_scan_run
    ):
        """Test getting security findings with filters."""
        # Create test findings
        finding1 = SecurityFinding(
            scan_run_id=test_scan_run.id,
            check_id="SEC-001",
            title="High Finding",
            severity="high",
            passed=False,
        )
        finding2 = SecurityFinding(
            scan_run_id=test_scan_run.id,
            check_id="SEC-002",
            title="Low Finding",
            severity="low",
            passed=True,
        )
        db.add_all([finding1, finding2])
        db.commit()

        # Filter by severity
        response = client.get(
            f"/api/scans/{test_scan_run.id}/findings/security?severity=high",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert all(f["severity"] == "high" for f in data)

        # Filter by passed
        response = client.get(
            f"/api/scans/{test_scan_run.id}/findings/security?passed=true",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert all(f["passed"] is True for f in data)


class TestDomainAccess:
    """Test domain-based access control for scans."""

    def test_regular_user_cannot_access_other_domain(
        self, client: TestClient, auth_headers, test_scan_run
    ):
        """Test that regular user cannot access scans from domains they don't have access to."""
        response = client.get(
            f"/api/scans/{test_scan_run.id}",
            headers=auth_headers,
        )
        assert response.status_code == 403

    def test_user_with_domain_access(
        self, client: TestClient, db: Session, user_with_domain, test_scan_run
    ):
        """Test that user with domain access can view scans."""
        from backend.auth.security import create_access_token

        token = create_access_token(
            data={"sub": user_with_domain.email, "user_id": user_with_domain.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get(
            f"/api/scans/{test_scan_run.id}",
            headers=headers,
        )
        assert response.status_code == 200
