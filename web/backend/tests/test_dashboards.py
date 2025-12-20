"""Tests for dashboard API endpoints."""

import pytest
from datetime import datetime, timedelta
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import (
    User,
    Domain,
    ScanRun,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
)
from backend.auth.security import create_access_token


class TestDashboardOverview:
    """Test dashboard overview endpoint."""

    def test_get_overview_empty(self, authenticated_client: TestClient):
        """Should return empty overview when no data exists."""
        response = authenticated_client.get("/api/v1/dashboard/overview")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["scan_stats"]["total_scans"] == 0
        assert data["scan_stats"]["completed_scans"] == 0
        assert data["recent_scans"] == []

    def test_get_overview_with_scans(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should return overview with scan data."""
        # Create completed scans
        for i in range(3):
            scan = ScanRun(
                scan_type="posture",
                domain_name=test_domain.name,
                status="completed",
                start_time=datetime.utcnow() - timedelta(days=i),
                end_time=datetime.utcnow() - timedelta(days=i) + timedelta(hours=1),
                issues_found=5 + i,
                high_risk_count=2,
                medium_risk_count=2,
                low_risk_count=1 + i,
            )
            db.add(scan)

        # Create a failed scan
        failed_scan = ScanRun(
            scan_type="files",
            domain_name=test_domain.name,
            status="failed",
            start_time=datetime.utcnow() - timedelta(hours=2),
            error_message="Test failure",
        )
        db.add(failed_scan)
        db.commit()

        response = authenticated_client.get("/api/v1/dashboard/overview")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        assert data["scan_stats"]["total_scans"] == 4
        assert data["scan_stats"]["completed_scans"] == 3
        assert data["scan_stats"]["failed_scans"] == 1
        assert data["scan_stats"]["success_rate"] == 75.0
        assert len(data["recent_scans"]) <= 5

    def test_overview_filters_by_domain(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should filter overview by domain parameter."""
        # Create scan for test domain
        scan = ScanRun(
            scan_type="users",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow(),
            issues_found=10,
        )
        db.add(scan)
        db.commit()

        response = authenticated_client.get(
            "/api/v1/dashboard/overview",
            params={"domain": test_domain.name},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["scan_stats"]["total_scans"] == 1

    def test_overview_respects_days_parameter(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should filter overview by days parameter."""
        # Create old scan (35 days ago)
        old_scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=35),
            issues_found=5,
        )
        # Create recent scan (5 days ago)
        recent_scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=5),
            issues_found=10,
        )
        db.add(old_scan)
        db.add(recent_scan)
        db.commit()

        # Default 30 days should only get recent scan
        response = authenticated_client.get("/api/v1/dashboard/overview")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["scan_stats"]["total_scans"] == 1

        # 60 days should get both
        response = authenticated_client.get(
            "/api/v1/dashboard/overview",
            params={"days": 60},
        )
        data = response.json()
        assert data["scan_stats"]["total_scans"] == 2

    def test_overview_includes_findings_counts(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should include findings counts in overview."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()

        # Add critical security finding
        finding = SecurityFinding(
            scan_run_id=scan.id,
            check_id="SEC-001",
            title="Critical Issue",
            severity="critical",
            passed=False,
            detected_at=datetime.utcnow(),
        )
        db.add(finding)

        # Add high-risk file
        file_finding = FileFinding(
            scan_run_id=scan.id,
            file_id="file123",
            file_name="sensitive.xlsx",
            risk_score=85,
            detected_at=datetime.utcnow(),
        )
        db.add(file_finding)

        # Add inactive user
        user_finding = UserFinding(
            scan_run_id=scan.id,
            user_id="user123",
            email="inactive@example.com",
            is_inactive=True,
            detected_at=datetime.utcnow(),
        )
        db.add(user_finding)
        db.commit()

        response = authenticated_client.get("/api/v1/dashboard/overview")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["critical_findings"] >= 1
        assert data["high_risk_files"] >= 1
        assert data["inactive_users"] >= 1


class TestDashboardTrends:
    """Test dashboard trends endpoint."""

    def test_get_trends(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should return scan trends data."""
        # Create scans over multiple days
        for i in range(7):
            scan = ScanRun(
                scan_type="posture",
                domain_name=test_domain.name,
                status="completed",
                start_time=datetime.utcnow() - timedelta(days=i),
                issues_found=10 - i,  # Decreasing issues
                high_risk_count=3,
                medium_risk_count=4,
                low_risk_count=3 - i if i < 3 else 0,
            )
            db.add(scan)
        db.commit()

        response = authenticated_client.get("/api/v1/dashboard/trends")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "daily_scans" in data or "scan_trend" in data
        assert "issues_trend" in data or "daily_issues" in data


class TestDashboardRiskDistribution:
    """Test risk distribution endpoint."""

    def test_get_risk_distribution(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should return risk distribution data."""
        scan = ScanRun(
            scan_type="files",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()

        # Add files with different risk scores
        risk_scores = [95, 85, 75, 60, 50, 40, 30, 20, 10]
        for score in risk_scores:
            file = FileFinding(
                scan_run_id=scan.id,
                file_id=f"file_{score}",
                file_name=f"file_{score}.doc",
                risk_score=score,
                detected_at=datetime.utcnow(),
            )
            db.add(file)
        db.commit()

        response = authenticated_client.get("/api/v1/dashboard/risk-distribution")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Should have distribution data
        assert isinstance(data, dict)


class TestDashboardTopIssues:
    """Test top issues endpoint."""

    def test_get_top_issues(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should return top security issues."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()

        # Add various severity findings
        severities = ["critical", "high", "high", "medium", "medium", "low"]
        for i, severity in enumerate(severities):
            finding = SecurityFinding(
                scan_run_id=scan.id,
                check_id=f"SEC-{i:03d}",
                title=f"Issue {i}",
                severity=severity,
                passed=False,
                detected_at=datetime.utcnow(),
            )
            db.add(finding)
        db.commit()

        response = authenticated_client.get("/api/v1/dashboard/top-issues")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        # Critical issues should come first
        if len(data) > 0 and "severity" in data[0]:
            assert data[0]["severity"] in ["critical", "high"]


class TestDashboardCaching:
    """Test dashboard caching behavior."""

    def test_dashboard_uses_cache(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should cache dashboard results."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow(),
            issues_found=5,
        )
        db.add(scan)
        db.commit()

        # First request
        response1 = authenticated_client.get("/api/v1/dashboard/overview")
        assert response1.status_code == status.HTTP_200_OK

        # Second request should use cache (same result)
        response2 = authenticated_client.get("/api/v1/dashboard/overview")
        assert response2.status_code == status.HTTP_200_OK

        # Both responses should be identical
        assert response1.json() == response2.json()


class TestDashboardAuthorization:
    """Test dashboard access control."""

    def test_unauthorized_domain_rejected(
        self, client: TestClient, db: Session, test_user: User
    ):
        """Should reject requests for unauthorized domains."""
        # Create another domain without user access
        other_domain = Domain(name="other.com", display_name="Other", is_active=True)
        db.add(other_domain)
        db.commit()

        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get(
            "/api/v1/dashboard/overview",
            headers=headers,
            params={"domain": "other.com"},
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_superuser_accesses_all_domains(
        self, client: TestClient, db: Session, test_superuser: User, test_domain: Domain
    ):
        """Superuser should access any domain's dashboard."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()

        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get(
            "/api/v1/dashboard/overview",
            headers=headers,
            params={"domain": test_domain.name},
        )
        assert response.status_code == status.HTTP_200_OK
