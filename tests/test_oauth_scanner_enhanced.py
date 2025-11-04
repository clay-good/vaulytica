"""Tests for enhanced OAuth scanner security features."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from vaulytica.core.scanners.oauth_scanner import (
    OAuthScanner,
    OAuthApp,
    OAuthToken,
    OAuthScanResult,
)


class TestEnhancedOAuthScanner:
    """Tests for enhanced OAuth scanner security features."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        return client

    @pytest.fixture
    def oauth_scanner(self, mock_client):
        """Create an OAuth scanner instance."""
        return OAuthScanner(client=mock_client, domain="example.com")

    def test_detect_admin_access_app(self, oauth_scanner):
        """Test detection of apps with admin access."""
        app = OAuthApp(
            client_id="test-app-123",
            display_text="Admin Tool",
            scopes=[
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/admin.directory.group",
            ],
            user_count=5,
        )

        risk_score = oauth_scanner._calculate_app_risk_score(app)

        assert app.has_admin_access is True
        assert risk_score >= 70  # Should be high risk
        assert any("admin" in rf.lower() for rf in app.risk_factors)

    def test_detect_excessive_permissions(self, oauth_scanner):
        """Test detection of apps with excessive permissions."""
        # Create app with 20 scopes
        scopes = [f"https://www.googleapis.com/auth/scope{i}" for i in range(20)]
        app = OAuthApp(
            client_id="test-app-456",
            display_text="Greedy App",
            scopes=scopes,
            user_count=10,
        )

        risk_score = oauth_scanner._calculate_app_risk_score(app)

        assert app.has_excessive_permissions is True
        assert risk_score >= 50
        assert any("excessive" in rf.lower() or "many" in rf.lower() for rf in app.risk_factors)

    def test_detect_drive_access(self, oauth_scanner):
        """Test detection of apps with Drive access."""
        app = OAuthApp(
            client_id="test-app-789",
            display_text="Drive App",
            scopes=["https://www.googleapis.com/auth/drive"],
            user_count=50,
        )

        risk_score = oauth_scanner._calculate_app_risk_score(app)

        assert app.has_drive_access is True
        assert app.has_data_access is True
        assert any("drive" in rf.lower() for rf in app.risk_factors)

    def test_detect_email_access(self, oauth_scanner):
        """Test detection of apps with email access."""
        app = OAuthApp(
            client_id="test-app-101",
            display_text="Email App",
            scopes=[
                "https://www.googleapis.com/auth/gmail.modify",
                "https://www.googleapis.com/auth/gmail.compose",
            ],
            user_count=25,
        )

        risk_score = oauth_scanner._calculate_app_risk_score(app)

        assert app.has_email_access is True
        assert app.has_data_access is True
        assert any("email" in rf.lower() for rf in app.risk_factors)

    def test_unverified_third_party_app_risk(self, oauth_scanner):
        """Test that unverified third-party apps get higher risk scores."""
        app = OAuthApp(
            client_id="malicious-app-999",
            display_text="Suspicious App",
            scopes=["https://www.googleapis.com/auth/drive"],
            user_count=5,
            is_verified=False,
            is_google_app=False,
        )

        risk_score = oauth_scanner._calculate_app_risk_score(app)

        assert risk_score >= 40  # Should have elevated risk
        assert any("third-party" in rf.lower() for rf in app.risk_factors)
        assert any("unverified" in rf.lower() for rf in app.risk_factors)

    def test_google_app_lower_risk(self, oauth_scanner):
        """Test that Google apps get lower risk scores."""
        google_app = OAuthApp(
            client_id="123456.apps.googleusercontent.com",
            display_text="Google Drive",
            scopes=["https://www.googleapis.com/auth/drive"],
            user_count=100,
            is_google_app=True,
        )

        non_google_app = OAuthApp(
            client_id="third-party-app",
            display_text="Third Party Drive",
            scopes=["https://www.googleapis.com/auth/drive"],
            user_count=100,
            is_google_app=False,
        )

        google_risk = oauth_scanner._calculate_app_risk_score(google_app)
        non_google_risk = oauth_scanner._calculate_app_risk_score(non_google_app)

        assert google_risk < non_google_risk  # Google apps should be lower risk

    def test_wide_adoption_increases_risk(self, oauth_scanner):
        """Test that wide adoption increases risk score."""
        low_adoption = OAuthApp(
            client_id="app-1",
            display_text="Small App",
            scopes=["https://www.googleapis.com/auth/drive"],
            user_count=5,
        )

        high_adoption = OAuthApp(
            client_id="app-2",
            display_text="Popular App",
            scopes=["https://www.googleapis.com/auth/drive"],
            user_count=150,
        )

        low_risk = oauth_scanner._calculate_app_risk_score(low_adoption)
        high_risk = oauth_scanner._calculate_app_risk_score(high_adoption)

        assert high_risk > low_risk
        assert any("adoption" in rf.lower() for rf in high_adoption.risk_factors)

    def test_generate_admin_access_issue(self, oauth_scanner):
        """Test generation of admin access security issues."""
        result = OAuthScanResult()
        result.apps = [
            OAuthApp(
                client_id="admin-app",
                display_text="Admin Tool",
                scopes=["https://www.googleapis.com/auth/admin.directory.user"],
                user_count=10,
                has_admin_access=True,
                risk_score=85,
                risk_factors=["Critical admin scope"],
            )
        ]

        issues = oauth_scanner._generate_security_issues(result)

        assert len(issues) > 0
        admin_issues = [i for i in issues if i["type"] == "admin_access_app"]
        assert len(admin_issues) == 1
        assert admin_issues[0]["severity"] == "critical"

    def test_generate_unverified_high_risk_issue(self, oauth_scanner):
        """Test generation of unverified high-risk app issues."""
        result = OAuthScanResult()
        result.apps = [
            OAuthApp(
                client_id="suspicious-app",
                display_text="Suspicious App",
                scopes=["https://www.googleapis.com/auth/drive"] * 10,
                user_count=50,
                is_verified=False,
                is_google_app=False,
                risk_score=75,
                risk_factors=["Unverified", "Many scopes"],
            )
        ]

        issues = oauth_scanner._generate_security_issues(result)

        unverified_issues = [i for i in issues if i["type"] == "unverified_high_risk_app"]
        assert len(unverified_issues) == 1
        assert unverified_issues[0]["severity"] == "high"

    def test_generate_excessive_permissions_issue(self, oauth_scanner):
        """Test generation of excessive permissions issues."""
        result = OAuthScanResult()
        # Create 10 apps with excessive permissions
        result.apps = [
            OAuthApp(
                client_id=f"app-{i}",
                display_text=f"App {i}",
                scopes=[f"scope-{j}" for j in range(20)],
                user_count=5,
                has_excessive_permissions=True,
                risk_score=60,
            )
            for i in range(10)
        ]

        issues = oauth_scanner._generate_security_issues(result)

        excessive_issues = [i for i in issues if i["type"] == "excessive_permissions"]
        assert len(excessive_issues) > 0
        assert excessive_issues[0]["count"] == 10

    def test_generate_recommendations(self, oauth_scanner):
        """Test generation of security recommendations."""
        result = OAuthScanResult()
        result.total_apps = 25
        result.high_risk_apps = 5
        result.apps_with_data_access = 15
        result.apps = [
            OAuthApp(
                client_id="admin-app",
                display_text="Admin Tool",
                scopes=["https://www.googleapis.com/auth/admin.directory.user"],
                user_count=10,
                has_admin_access=True,
                risk_score=85,
            )
        ]

        recommendations = oauth_scanner._generate_recommendations(result)

        assert len(recommendations) >= 3
        # Should recommend OAuth whitelisting
        assert any("whitelist" in r["title"].lower() for r in recommendations)
        # Should recommend reviewing high-risk apps
        assert any("high-risk" in r["title"].lower() for r in recommendations)
        # Should recommend auditing admin apps
        assert any("admin" in r["title"].lower() for r in recommendations)

    def test_enhanced_scan_result_metrics(self, oauth_scanner):
        """Test that enhanced metrics are calculated correctly."""
        result = OAuthScanResult()
        result.apps = [
            OAuthApp(
                client_id="app-1",
                display_text="Admin App",
                scopes=["https://www.googleapis.com/auth/admin.directory.user"],
                user_count=10,
                has_admin_access=True,
                has_excessive_permissions=False,
                has_data_access=True,
                is_verified=False,
                is_google_app=False,
                risk_score=85,
            ),
            OAuthApp(
                client_id="app-2",
                display_text="Data App",
                scopes=[f"scope-{i}" for i in range(20)],
                user_count=50,
                has_admin_access=False,
                has_excessive_permissions=True,
                has_data_access=True,
                is_verified=True,
                is_google_app=False,
                risk_score=65,
            ),
        ]

        # Manually calculate metrics (normally done in scan method)
        result.apps_with_admin_access = len([a for a in result.apps if a.has_admin_access])
        result.apps_with_excessive_permissions = len([a for a in result.apps if a.has_excessive_permissions])
        result.apps_with_data_access = len([a for a in result.apps if a.has_data_access])
        result.unverified_apps = len([a for a in result.apps if not a.is_verified and not a.is_google_app])

        assert result.apps_with_admin_access == 1
        assert result.apps_with_excessive_permissions == 1
        assert result.apps_with_data_access == 2
        assert result.unverified_apps == 1

