"""Integration tests for scan comparison API."""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import (
    ScanRun,
    Domain,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
    User,
    UserDomain,
)


class TestScanComparison:
    """Test scan comparison endpoint."""

    @pytest.fixture
    def old_posture_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create an older posture scan with findings."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow() - timedelta(days=7) + timedelta(hours=1),
            total_items=50,
            issues_found=3,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Add findings - some passing, some failing
        findings = [
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-001",
                title="2FA Not Enforced",
                severity="high",
                passed=False,  # Will be resolved in new scan
            ),
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-002",
                title="Password Policy Weak",
                severity="medium",
                passed=False,  # Will remain unresolved
            ),
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-003",
                title="Session Timeout OK",
                severity="low",
                passed=True,
            ),
        ]
        for f in findings:
            db.add(f)
        db.commit()
        return scan

    @pytest.fixture
    def new_posture_scan(self, db: Session, test_domain: Domain, old_posture_scan: ScanRun) -> ScanRun:
        """Create a newer posture scan with different findings."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
            end_time=datetime.utcnow() - timedelta(days=1) + timedelta(hours=1),
            total_items=50,
            issues_found=2,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Add findings - SEC-001 now passes (resolved), SEC-002 still fails, SEC-004 is new
        findings = [
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-001",
                title="2FA Not Enforced",
                severity="high",
                passed=True,  # Now resolved
            ),
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-002",
                title="Password Policy Weak",
                severity="medium",
                passed=False,  # Still failing
            ),
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-003",
                title="Session Timeout OK",
                severity="low",
                passed=True,
            ),
            SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-004",
                title="Admin Account No MFA",
                severity="critical",
                passed=False,  # New issue
            ),
        ]
        for f in findings:
            db.add(f)
        db.commit()
        return scan

    def test_compare_posture_scans(
        self, client: TestClient, superuser_headers, old_posture_scan, new_posture_scan
    ):
        """Test comparing two posture scans."""
        response = client.get(
            f"/api/scans/compare?scan_id_1={old_posture_scan.id}&scan_id_2={new_posture_scan.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # Check structure
        assert "old_scan" in data
        assert "new_scan" in data
        assert "new_issues" in data
        assert "resolved_issues" in data
        assert "unchanged_count" in data

        # Old scan should be the one from 7 days ago
        assert data["old_scan"]["id"] == old_posture_scan.id
        assert data["new_scan"]["id"] == new_posture_scan.id

        # Check issues - SEC-004 is new
        new_issue_ids = [i["check_id"] for i in data["new_issues"]]
        assert "SEC-004" in new_issue_ids

        # SEC-001 should be resolved
        resolved_ids = [i["check_id"] for i in data["resolved_issues"]]
        assert "SEC-001" in resolved_ids

    def test_compare_scans_reversed_order(
        self, client: TestClient, superuser_headers, old_posture_scan, new_posture_scan
    ):
        """Test that comparison works regardless of parameter order."""
        # Pass scans in reverse order (new first, old second)
        response = client.get(
            f"/api/scans/compare?scan_id_1={new_posture_scan.id}&scan_id_2={old_posture_scan.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # Should still correctly identify old vs new based on timestamps
        assert data["old_scan"]["id"] == old_posture_scan.id
        assert data["new_scan"]["id"] == new_posture_scan.id

    def test_compare_scans_not_found(
        self, client: TestClient, superuser_headers, old_posture_scan
    ):
        """Test comparing with non-existent scan."""
        response = client.get(
            f"/api/scans/compare?scan_id_1={old_posture_scan.id}&scan_id_2=99999",
            headers=superuser_headers,
        )
        assert response.status_code == 404


class TestScanComparisonDifferentDomains:
    """Test that comparison fails for scans from different domains."""

    @pytest.fixture
    def second_domain(self, db: Session) -> Domain:
        """Create a second test domain."""
        domain = Domain(
            name="other.com",
            display_name="Other Company",
            admin_email="admin@other.com",
            is_active=True,
        )
        db.add(domain)
        db.commit()
        db.refresh(domain)
        return domain

    @pytest.fixture
    def scan_from_domain_1(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create a scan from the first domain."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    @pytest.fixture
    def scan_from_domain_2(self, db: Session, second_domain: Domain) -> ScanRun:
        """Create a scan from the second domain."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=second_domain.name,
            domain_id=second_domain.id,
            status="completed",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    def test_cannot_compare_different_domains(
        self, client: TestClient, superuser_headers, scan_from_domain_1, scan_from_domain_2
    ):
        """Test that comparing scans from different domains fails."""
        response = client.get(
            f"/api/scans/compare?scan_id_1={scan_from_domain_1.id}&scan_id_2={scan_from_domain_2.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 400
        assert "same domain" in response.json()["detail"].lower()


class TestScanComparisonDifferentTypes:
    """Test that comparison fails for scans of different types."""

    @pytest.fixture
    def posture_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create a posture scan."""
        scan = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    @pytest.fixture
    def files_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create a files scan."""
        scan = ScanRun(
            scan_type="files",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    def test_cannot_compare_different_types(
        self, client: TestClient, superuser_headers, posture_scan, files_scan
    ):
        """Test that comparing scans of different types fails."""
        response = client.get(
            f"/api/scans/compare?scan_id_1={posture_scan.id}&scan_id_2={files_scan.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 400
        assert "same type" in response.json()["detail"].lower()


class TestFilesScanComparison:
    """Test comparing file scans."""

    @pytest.fixture
    def old_files_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create an older files scan."""
        scan = ScanRun(
            scan_type="files",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow() - timedelta(days=7),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        files = [
            FileFinding(
                scan_run_id=scan.id,
                file_id="file1",
                file_name="risky_file.xlsx",
                owner_email="user@example.com",
                risk_score=80,  # Will be fixed in new scan
                is_public=True,
            ),
            FileFinding(
                scan_run_id=scan.id,
                file_id="file2",
                file_name="safe_file.pdf",
                owner_email="user@example.com",
                risk_score=20,  # Still safe
                is_public=False,
            ),
        ]
        for f in files:
            db.add(f)
        db.commit()
        return scan

    @pytest.fixture
    def new_files_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create a newer files scan."""
        scan = ScanRun(
            scan_type="files",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
            end_time=datetime.utcnow() - timedelta(days=1),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        files = [
            FileFinding(
                scan_run_id=scan.id,
                file_id="file1",
                file_name="risky_file.xlsx",
                owner_email="user@example.com",
                risk_score=30,  # Fixed - risk reduced
                is_public=False,
            ),
            FileFinding(
                scan_run_id=scan.id,
                file_id="file2",
                file_name="safe_file.pdf",
                owner_email="user@example.com",
                risk_score=20,
                is_public=False,
            ),
            FileFinding(
                scan_run_id=scan.id,
                file_id="file3",
                file_name="new_risky.docx",
                owner_email="user@example.com",
                risk_score=75,  # New risky file
                is_public=True,
            ),
        ]
        for f in files:
            db.add(f)
        db.commit()
        return scan

    def test_compare_files_scans(
        self, client: TestClient, superuser_headers, old_files_scan, new_files_scan
    ):
        """Test comparing two files scans."""
        response = client.get(
            f"/api/scans/compare?scan_id_1={old_files_scan.id}&scan_id_2={new_files_scan.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # file1 was risky (80), now safe (30) - should be resolved
        resolved_files = [i["file_id"] for i in data["resolved_issues"]]
        assert "file1" in resolved_files

        # file3 is new and risky - should be new issue
        new_files = [i["file_id"] for i in data["new_issues"]]
        assert "file3" in new_files


class TestUsersScanComparison:
    """Test comparing user scans."""

    @pytest.fixture
    def old_users_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create an older users scan."""
        scan = ScanRun(
            scan_type="users",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow() - timedelta(days=7),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        users = [
            UserFinding(
                scan_run_id=scan.id,
                user_id="user1",
                email="user1@example.com",
                full_name="User One",
                two_factor_enabled=False,  # Will enable 2FA
                is_inactive=False,
            ),
            UserFinding(
                scan_run_id=scan.id,
                user_id="user2",
                email="user2@example.com",
                full_name="User Two",
                two_factor_enabled=True,
                is_inactive=False,
            ),
        ]
        for u in users:
            db.add(u)
        db.commit()
        return scan

    @pytest.fixture
    def new_users_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create a newer users scan."""
        scan = ScanRun(
            scan_type="users",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
            end_time=datetime.utcnow() - timedelta(days=1),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        users = [
            UserFinding(
                scan_run_id=scan.id,
                user_id="user1",
                email="user1@example.com",
                full_name="User One",
                two_factor_enabled=True,  # Fixed - enabled 2FA
                is_inactive=False,
            ),
            UserFinding(
                scan_run_id=scan.id,
                user_id="user2",
                email="user2@example.com",
                full_name="User Two",
                two_factor_enabled=True,
                is_inactive=True,  # Now inactive - new issue
            ),
        ]
        for u in users:
            db.add(u)
        db.commit()
        return scan

    def test_compare_users_scans(
        self, client: TestClient, superuser_headers, old_users_scan, new_users_scan
    ):
        """Test comparing two users scans."""
        response = client.get(
            f"/api/scans/compare?scan_id_1={old_users_scan.id}&scan_id_2={new_users_scan.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # user1 fixed 2FA - should be resolved
        resolved_emails = [i["email"] for i in data["resolved_issues"]]
        assert "user1@example.com" in resolved_emails

        # user2 is now inactive - should be new issue
        new_emails = [i["email"] for i in data["new_issues"]]
        assert "user2@example.com" in new_emails


class TestOAuthScanComparison:
    """Test comparing OAuth scans."""

    @pytest.fixture
    def old_oauth_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create an older OAuth scan."""
        scan = ScanRun(
            scan_type="oauth",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow() - timedelta(days=7),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        apps = [
            OAuthFinding(
                scan_run_id=scan.id,
                client_id="app1",
                display_text="Risky App",
                risk_score=80,  # Will be revoked
                is_verified=False,
            ),
            OAuthFinding(
                scan_run_id=scan.id,
                client_id="app2",
                display_text="Safe App",
                risk_score=20,
                is_verified=True,
            ),
        ]
        for a in apps:
            db.add(a)
        db.commit()
        return scan

    @pytest.fixture
    def new_oauth_scan(self, db: Session, test_domain: Domain) -> ScanRun:
        """Create a newer OAuth scan."""
        scan = ScanRun(
            scan_type="oauth",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
            end_time=datetime.utcnow() - timedelta(days=1),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        apps = [
            # app1 removed (revoked)
            OAuthFinding(
                scan_run_id=scan.id,
                client_id="app2",
                display_text="Safe App",
                risk_score=20,
                is_verified=True,
            ),
            OAuthFinding(
                scan_run_id=scan.id,
                client_id="app3",
                display_text="New Risky App",
                risk_score=70,  # New risky app
                is_verified=False,
            ),
        ]
        for a in apps:
            db.add(a)
        db.commit()
        return scan

    def test_compare_oauth_scans(
        self, client: TestClient, superuser_headers, old_oauth_scan, new_oauth_scan
    ):
        """Test comparing two OAuth scans."""
        response = client.get(
            f"/api/scans/compare?scan_id_1={old_oauth_scan.id}&scan_id_2={new_oauth_scan.id}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
        data = response.json()

        # app1 was risky and removed - should be resolved
        resolved_apps = [i["client_id"] for i in data["resolved_issues"]]
        assert "app1" in resolved_apps

        # app3 is new and risky - should be new issue
        new_apps = [i["client_id"] for i in data["new_issues"]]
        assert "app3" in new_apps


class TestScanComparisonAuth:
    """Test authentication and authorization for scan comparison."""

    def test_compare_unauthorized(self, client: TestClient, db: Session, test_domain: Domain):
        """Test that comparison requires authentication."""
        # Create two scans
        scan1 = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=7),
        )
        scan2 = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add_all([scan1, scan2])
        db.commit()

        response = client.get(
            f"/api/scans/compare?scan_id_1={scan1.id}&scan_id_2={scan2.id}"
        )
        assert response.status_code == 401

    def test_compare_requires_domain_access(
        self, client: TestClient, auth_headers, db: Session, test_domain: Domain
    ):
        """Test that regular users need domain access to compare scans."""
        # Create two scans
        scan1 = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=7),
        )
        scan2 = ScanRun(
            scan_type="posture",
            domain_name=test_domain.name,
            domain_id=test_domain.id,
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add_all([scan1, scan2])
        db.commit()

        # auth_headers is for a user without domain access
        response = client.get(
            f"/api/scans/compare?scan_id_1={scan1.id}&scan_id_2={scan2.id}",
            headers=auth_headers,
        )
        assert response.status_code == 403
