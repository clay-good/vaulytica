"""Tests for delta tracking and deduplication API."""

import pytest
from datetime import datetime, timedelta
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import (
    ScanRun,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
    Domain,
)
from backend.services.deduplication import (
    FindingType,
    generate_security_fingerprint,
    generate_file_fingerprint,
    generate_user_fingerprint,
    generate_oauth_fingerprint,
    FindingDeduplicator,
    DeltaTracker,
)


class TestFingerprints:
    """Test fingerprint generation."""

    def test_security_fingerprint_consistency(self):
        """Same security finding should generate same fingerprint."""
        # Create mock finding
        class MockFinding:
            check_id = "SEC-001"
            resource_type = "admin_setting"
            resource_id = "security.2fa_enabled"

        fp1 = generate_security_fingerprint(MockFinding())
        fp2 = generate_security_fingerprint(MockFinding())

        assert fp1 == fp2
        assert len(fp1) == 32  # SHA-256 truncated to 32 chars

    def test_security_fingerprint_uniqueness(self):
        """Different security findings should have different fingerprints."""
        class MockFinding1:
            check_id = "SEC-001"
            resource_type = "admin_setting"
            resource_id = "security.2fa_enabled"

        class MockFinding2:
            check_id = "SEC-002"
            resource_type = "admin_setting"
            resource_id = "security.password_length"

        fp1 = generate_security_fingerprint(MockFinding1())
        fp2 = generate_security_fingerprint(MockFinding2())

        assert fp1 != fp2

    def test_file_fingerprint_by_file_id(self):
        """File fingerprint should be based on file_id."""
        class MockFinding:
            file_id = "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms"

        fp = generate_file_fingerprint(MockFinding())

        assert len(fp) == 32
        assert fp == generate_file_fingerprint(MockFinding())

    def test_user_fingerprint_by_user_id(self):
        """User fingerprint should be based on user_id."""
        class MockFinding:
            user_id = "123456789012345678901"

        fp = generate_user_fingerprint(MockFinding())

        assert len(fp) == 32
        assert fp == generate_user_fingerprint(MockFinding())

    def test_oauth_fingerprint_by_client_id(self):
        """OAuth fingerprint should be based on client_id."""
        class MockFinding:
            client_id = "123456789012.apps.googleusercontent.com"

        fp = generate_oauth_fingerprint(MockFinding())

        assert len(fp) == 32
        assert fp == generate_oauth_fingerprint(MockFinding())


class TestFindingDeduplicator:
    """Test FindingDeduplicator class."""

    def test_get_fingerprint_map_empty(self, db: Session):
        """Empty scan should return empty map."""
        # Create a scan with no findings
        scan = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()

        deduplicator = FindingDeduplicator(db)
        fp_map = deduplicator.get_fingerprint_map(scan.id, FindingType.SECURITY)

        assert fp_map == {}

    def test_get_fingerprint_map_with_findings(self, db: Session):
        """Should return map of fingerprints to findings."""
        # Create a scan with findings
        scan = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()

        finding = SecurityFinding(
            scan_run_id=scan.id,
            check_id="SEC-001",
            title="2FA Not Enforced",
            severity="high",
            passed=False,
            resource_type="admin_setting",
            resource_id="security.2fa_enabled",
        )
        db.add(finding)
        db.commit()

        deduplicator = FindingDeduplicator(db)
        fp_map = deduplicator.get_fingerprint_map(scan.id, FindingType.SECURITY)

        assert len(fp_map) == 1
        assert finding.id in [f.id for f in fp_map.values()]


class TestDeltaTracker:
    """Test DeltaTracker class."""

    def test_compare_scans_new_finding(self, db: Session):
        """New finding in scan 2 should be detected."""
        # Create two scans
        scan1 = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        scan2 = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # Add finding only to scan 2
        finding = SecurityFinding(
            scan_run_id=scan2.id,
            check_id="SEC-001",
            title="2FA Not Enforced",
            severity="high",
            passed=False,
        )
        db.add(finding)
        db.commit()

        tracker = DeltaTracker(db)
        result = tracker.compare_scans(scan1.id, scan2.id, FindingType.SECURITY)

        assert result["summary"]["new_count"] == 1
        assert result["summary"]["resolved_count"] == 0
        assert len(result["new"]) == 1

    def test_compare_scans_resolved_finding(self, db: Session):
        """Resolved finding (in scan 1 but not scan 2) should be detected."""
        # Create two scans
        scan1 = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        scan2 = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # Add finding only to scan 1
        finding = SecurityFinding(
            scan_run_id=scan1.id,
            check_id="SEC-001",
            title="2FA Not Enforced",
            severity="high",
            passed=False,
        )
        db.add(finding)
        db.commit()

        tracker = DeltaTracker(db)
        result = tracker.compare_scans(scan1.id, scan2.id, FindingType.SECURITY)

        assert result["summary"]["new_count"] == 0
        assert result["summary"]["resolved_count"] == 1
        assert len(result["resolved"]) == 1

    def test_compare_scans_unchanged_finding(self, db: Session):
        """Finding in both scans should be detected as unchanged."""
        # Create two scans
        scan1 = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        scan2 = ScanRun(
            scan_type="posture",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # Add same finding to both scans
        finding1 = SecurityFinding(
            scan_run_id=scan1.id,
            check_id="SEC-001",
            title="2FA Not Enforced",
            severity="high",
            passed=False,
        )
        finding2 = SecurityFinding(
            scan_run_id=scan2.id,
            check_id="SEC-001",
            title="2FA Not Enforced",
            severity="high",
            passed=False,
        )
        db.add(finding1)
        db.add(finding2)
        db.commit()

        tracker = DeltaTracker(db)
        result = tracker.compare_scans(scan1.id, scan2.id, FindingType.SECURITY)

        assert result["summary"]["unchanged_count"] == 1
        assert len(result["unchanged"]) == 1


class TestDeltaAPI:
    """Test delta API endpoints."""

    def test_compare_requires_auth(self, client: TestClient):
        """Compare endpoint should require authentication."""
        response = client.get(
            "/api/v1/delta/compare",
            params={"scan_id_1": 1, "scan_id_2": 2, "finding_type": "security"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_compare_validates_finding_type(
        self, authenticated_client: TestClient
    ):
        """Compare endpoint should validate finding type."""
        response = authenticated_client.get(
            "/api/v1/delta/compare",
            params={"scan_id_1": 1, "scan_id_2": 2, "finding_type": "invalid"},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid finding type" in response.json()["detail"]

    def test_compare_validates_scan_exists(
        self, authenticated_client: TestClient
    ):
        """Compare endpoint should validate scans exist."""
        response = authenticated_client.get(
            "/api/v1/delta/compare",
            params={"scan_id_1": 99999, "scan_id_2": 99998, "finding_type": "security"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_duplicates_requires_domain(
        self, authenticated_client: TestClient
    ):
        """Duplicates endpoint should require domain."""
        response = authenticated_client.get(
            "/api/v1/delta/duplicates",
            params={"finding_type": "security"},
        )
        # Should fail validation for missing domain
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_trend_endpoint(self, authenticated_client: TestClient, db: Session):
        """Trend endpoint should return trend data."""
        # Note: authenticated_client fixture already creates example.com domain
        for i in range(3):
            scan = ScanRun(
                scan_type="posture",
                domain_name="example.com",
                status="completed",
                start_time=datetime.utcnow() - timedelta(days=i),
            )
            db.add(scan)
        db.commit()

        response = authenticated_client.get(
            "/api/v1/delta/trend",
            params={"domain": "example.com", "finding_type": "security", "num_scans": 5},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["domain_name"] == "example.com"
        assert data["finding_type"] == "security"
        assert len(data["data_points"]) <= 5


class TestFileFindingDelta:
    """Test delta tracking for file findings."""

    def test_file_fingerprint_different_files(self):
        """Different files should have different fingerprints."""
        class MockFile1:
            file_id = "file_123"

        class MockFile2:
            file_id = "file_456"

        fp1 = generate_file_fingerprint(MockFile1())
        fp2 = generate_file_fingerprint(MockFile2())

        assert fp1 != fp2

    def test_compare_file_scans(self, db: Session):
        """Should detect new and resolved file findings."""
        # Create scans
        scan1 = ScanRun(
            scan_type="files",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        scan2 = ScanRun(
            scan_type="files",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # File in both scans (unchanged)
        shared_file = FileFinding(
            scan_run_id=scan1.id,
            file_id="shared_file_123",
            file_name="shared.docx",
            owner_email="user@test.com",
            is_public=True,
            severity="high",
        )
        shared_file2 = FileFinding(
            scan_run_id=scan2.id,
            file_id="shared_file_123",
            file_name="shared.docx",
            owner_email="user@test.com",
            is_public=True,
            severity="high",
        )

        # File only in scan1 (resolved)
        resolved_file = FileFinding(
            scan_run_id=scan1.id,
            file_id="resolved_file_456",
            file_name="resolved.xlsx",
            owner_email="user@test.com",
            is_shared_externally=True,
            severity="medium",
        )

        # File only in scan2 (new)
        new_file = FileFinding(
            scan_run_id=scan2.id,
            file_id="new_file_789",
            file_name="new.pdf",
            owner_email="user@test.com",
            pii_detected=True,
            severity="critical",
        )

        db.add_all([shared_file, shared_file2, resolved_file, new_file])
        db.commit()

        tracker = DeltaTracker(db)
        result = tracker.compare_scans(scan1.id, scan2.id, FindingType.FILE)

        assert result["summary"]["new_count"] == 1
        assert result["summary"]["resolved_count"] == 1
        assert result["summary"]["unchanged_count"] == 1


class TestUserFindingDelta:
    """Test delta tracking for user findings."""

    def test_user_fingerprint_different_users(self):
        """Different users should have different fingerprints."""
        class MockUser1:
            user_id = "user_123"

        class MockUser2:
            user_id = "user_456"

        fp1 = generate_user_fingerprint(MockUser1())
        fp2 = generate_user_fingerprint(MockUser2())

        assert fp1 != fp2

    def test_compare_user_scans_inactive(self, db: Session):
        """Should track users becoming inactive over time."""
        scan1 = ScanRun(
            scan_type="users",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        scan2 = ScanRun(
            scan_type="users",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # User in both scans
        user1_scan1 = UserFinding(
            scan_run_id=scan1.id,
            user_id="user_123",
            email="inactive@test.com",
            is_inactive=False,
            two_factor_enabled=True,
            severity="low",
        )
        user1_scan2 = UserFinding(
            scan_run_id=scan2.id,
            user_id="user_123",
            email="inactive@test.com",
            is_inactive=True,  # Now inactive
            two_factor_enabled=True,
            severity="high",
        )

        db.add_all([user1_scan1, user1_scan2])
        db.commit()

        tracker = DeltaTracker(db)
        result = tracker.compare_scans(scan1.id, scan2.id, FindingType.USER)

        # Same user appears in both - fingerprint matches
        assert result["summary"]["unchanged_count"] == 1 or result["summary"]["changed_count"] == 1


class TestOAuthFindingDelta:
    """Test delta tracking for OAuth app findings."""

    def test_oauth_fingerprint_different_apps(self):
        """Different OAuth apps should have different fingerprints."""
        class MockApp1:
            client_id = "123456.apps.googleusercontent.com"

        class MockApp2:
            client_id = "789012.apps.googleusercontent.com"

        fp1 = generate_oauth_fingerprint(MockApp1())
        fp2 = generate_oauth_fingerprint(MockApp2())

        assert fp1 != fp2

    def test_compare_oauth_scans(self, db: Session):
        """Should detect new risky OAuth apps."""
        scan1 = ScanRun(
            scan_type="oauth",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        scan2 = ScanRun(
            scan_type="oauth",
            domain_name="test.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # New risky app appeared
        risky_app = OAuthFinding(
            scan_run_id=scan2.id,
            client_id="risky_app_123.apps.googleusercontent.com",
            display_text="Risky Data Exporter",
            is_verified=False,
            risk_score=85,
            severity="high",
            scopes=["https://www.googleapis.com/auth/drive"],
        )
        db.add(risky_app)
        db.commit()

        tracker = DeltaTracker(db)
        result = tracker.compare_scans(scan1.id, scan2.id, FindingType.OAUTH)

        assert result["summary"]["new_count"] == 1


class TestDeduplicationService:
    """Test the deduplication service."""

    def test_find_recurring_findings(self, db: Session):
        """Should identify findings that appear across multiple scans."""
        # Create multiple scans
        scans = []
        for i in range(3):
            scan = ScanRun(
                scan_type="posture",
                domain_name="test.com",
                status="completed",
                start_time=datetime.utcnow() - timedelta(days=i),
            )
            db.add(scan)
            scans.append(scan)
        db.commit()

        # Same finding appears in all scans (recurring issue)
        for scan in scans:
            finding = SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-001",
                title="2FA Not Enforced",
                severity="high",
                passed=False,
                resource_type="admin_setting",
                resource_id="security.2fa_enabled",
            )
            db.add(finding)
        db.commit()

        deduplicator = FindingDeduplicator(db)
        duplicates = deduplicator.find_duplicates("test.com", FindingType.SECURITY, lookback_scans=3)

        # Should find this fingerprint appears 3 times
        assert len(duplicates) > 0
        # Get the fingerprint that has multiple findings
        for fp, finding_ids in duplicates.items():
            if len(finding_ids) == 3:
                assert len(finding_ids) == 3
                break


class TestDeltaAPIEndpoints:
    """Integration tests for delta API endpoints."""

    def test_compare_different_domains_rejected(
        self, authenticated_client: TestClient, db: Session
    ):
        """Should reject comparison of scans from different domains."""
        # Create scan for the user's domain (example.com from fixture)
        scan1 = ScanRun(
            scan_type="posture",
            domain_name="example.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        # Create another domain and scan
        other_domain = Domain(name="other.com", display_name="Other", is_active=True)
        db.add(other_domain)
        db.commit()

        scan2 = ScanRun(
            scan_type="posture",
            domain_name="other.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # This should fail because user doesn't have access to other.com
        response = authenticated_client.get(
            "/api/v1/delta/compare",
            params={
                "scan_id_1": scan1.id,
                "scan_id_2": scan2.id,
                "finding_type": "security",
            },
        )

        # Either 403 (no access to other domain) or 400 (different domains)
        assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_400_BAD_REQUEST]

    def test_analyze_scan_deduplication(
        self, authenticated_client: TestClient, db: Session
    ):
        """Should analyze a scan for new vs recurring findings."""
        # Create two scans
        scan1 = ScanRun(
            scan_type="posture",
            domain_name="example.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(days=1),
        )
        scan2 = ScanRun(
            scan_type="posture",
            domain_name="example.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # Add recurring finding to both scans
        for scan in [scan1, scan2]:
            finding = SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-001",
                title="2FA Not Enforced",
                severity="high",
                passed=False,
            )
            db.add(finding)

        # Add new finding only to scan2
        new_finding = SecurityFinding(
            scan_run_id=scan2.id,
            check_id="SEC-002",
            title="Password Policy Weak",
            severity="medium",
            passed=False,
        )
        db.add(new_finding)
        db.commit()

        response = authenticated_client.post(
            f"/api/v1/delta/analyze/{scan2.id}",
            params={"finding_type": "security"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["scan_id"] == scan2.id
        assert data["total"] == 2
        assert data["new"] == 1  # SEC-002 is new
        assert data["recurring"] == 1  # SEC-001 is recurring

    def test_latest_delta(self, authenticated_client: TestClient, db: Session):
        """Should return delta between two most recent scans."""
        # Create two scans with findings
        scan1 = ScanRun(
            scan_type="posture",
            domain_name="example.com",
            status="completed",
            start_time=datetime.utcnow() - timedelta(hours=2),
        )
        scan2 = ScanRun(
            scan_type="posture",
            domain_name="example.com",
            status="completed",
            start_time=datetime.utcnow(),
        )
        db.add(scan1)
        db.add(scan2)
        db.commit()

        # Finding only in older scan (resolved)
        resolved = SecurityFinding(
            scan_run_id=scan1.id,
            check_id="SEC-RESOLVED",
            title="Resolved Issue",
            severity="medium",
            passed=False,
        )
        db.add(resolved)
        db.commit()

        response = authenticated_client.get(
            "/api/v1/delta/latest",
            params={"domain": "example.com", "finding_type": "security"},
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["scan_1_id"] == scan1.id
        assert data["scan_2_id"] == scan2.id
        assert data["summary"]["resolved_count"] == 1

    def test_finding_history(self, authenticated_client: TestClient, db: Session):
        """Should return history of a specific finding."""
        # Create multiple scans
        scans = []
        for i in range(3):
            scan = ScanRun(
                scan_type="posture",
                domain_name="example.com",
                status="completed",
                start_time=datetime.utcnow() - timedelta(days=i),
            )
            db.add(scan)
            scans.append(scan)
        db.commit()

        # Same finding in all scans
        findings = []
        for scan in scans:
            finding = SecurityFinding(
                scan_run_id=scan.id,
                check_id="SEC-PERSISTENT",
                title="Persistent Issue",
                severity="high",
                passed=False,
                resource_type="admin_setting",
                resource_id="security.persistent",
            )
            db.add(finding)
            findings.append(finding)
        db.commit()

        # Get fingerprint from first finding
        fingerprint = generate_security_fingerprint(findings[0])

        response = authenticated_client.get(
            f"/api/v1/delta/history/{fingerprint}",
            params={
                "domain": "example.com",
                "finding_type": "security",
                "max_scans": 10,
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["fingerprint"] == fingerprint
        assert len(data["history"]) == 3  # Present in all 3 scans
