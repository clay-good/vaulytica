"""Tests for Shadow IT Analyzer."""

import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json
import tempfile
from unittest.mock import Mock, MagicMock, patch

from vaulytica.core.analyzers.shadow_it_analyzer import (
    ShadowITAnalyzer,
    ShadowITFinding,
    ShadowITAnalysisResult,
    ShadowITRiskLevel,
    ShadowITCategory,
    AppApprovalStatus,
    ShadowITAnalyzerError,
)
from vaulytica.core.scanners.oauth_scanner import OAuthApp, OAuthScanResult
from vaulytica.core.auth.client import GoogleWorkspaceClient


@pytest.fixture
def mock_client() -> Mock:
    """Create a mock GoogleWorkspaceClient."""
    client = Mock(spec=GoogleWorkspaceClient)
    return client


@pytest.fixture
def sample_oauth_apps() -> list[OAuthApp]:
    """Create sample OAuth apps for testing."""
    return [
        # Shadow IT app with admin access
        OAuthApp(
            client_id="shadow-admin-app.com",
            display_text="Unauthorized Admin Tool",
            scopes=[
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/admin.directory.group",
            ],
            user_count=5,
            risk_score=95,
            is_verified=False,
            is_google_app=False,
            has_admin_access=True,
            has_excessive_permissions=False,
            has_data_access=False,
            risk_factors=["Critical admin scope"],
        ),
        # Shadow IT app with data access
        OAuthApp(
            client_id="shadow-data-app.com",
            display_text="Unauthorized File Syncer",
            scopes=[
                "https://www.googleapis.com/auth/drive",
                "https://www.googleapis.com/auth/gmail.readonly",
            ],
            user_count=25,
            risk_score=75,
            is_verified=False,
            is_google_app=False,
            has_admin_access=False,
            has_excessive_permissions=False,
            has_data_access=True,
            has_drive_access=True,
            has_email_access=True,
            risk_factors=["Full Drive access", "Email access"],
        ),
        # Approved third-party app
        OAuthApp(
            client_id="approved-app.com",
            display_text="Approved Collaboration Tool",
            scopes=["https://www.googleapis.com/auth/calendar"],
            user_count=100,
            risk_score=20,
            is_verified=True,
            is_google_app=False,
            has_admin_access=False,
            has_excessive_permissions=False,
            has_data_access=False,
        ),
        # Google app (auto-approved)
        OAuthApp(
            client_id="123456.apps.googleusercontent.com",
            display_text="Google Drive",
            scopes=["https://www.googleapis.com/auth/drive"],
            user_count=500,
            risk_score=10,
            is_verified=True,
            is_google_app=True,
            has_admin_access=False,
            has_excessive_permissions=False,
            has_data_access=True,
            has_drive_access=True,
        ),
        # Shadow IT with excessive permissions
        OAuthApp(
            client_id="excessive-app.com",
            display_text="Feature-Heavy App",
            scopes=[f"scope_{i}" for i in range(20)],  # 20 scopes
            user_count=3,
            risk_score=60,
            is_verified=False,
            is_google_app=False,
            has_admin_access=False,
            has_excessive_permissions=True,
            has_data_access=False,
            risk_factors=["Excessive permissions (20 scopes)"],
        ),
    ]


@pytest.fixture
def sample_oauth_result(sample_oauth_apps: list[OAuthApp]) -> OAuthScanResult:
    """Create sample OAuth scan result."""
    result = OAuthScanResult()
    result.apps = sample_oauth_apps
    result.total_apps = len(sample_oauth_apps)
    result.high_risk_apps = len([a for a in sample_oauth_apps if a.risk_score >= 75])
    return result


@pytest.fixture
def approval_list_file(tmp_path: Path) -> Path:
    """Create a temporary approval list file."""
    approval_data = {
        "approved_apps": [
            {
                "client_id": "approved-app.com",
                "app_name": "Approved Collaboration Tool",
                "approved_by": "security@example.com",
                "approved_at": "2024-01-01T00:00:00Z",
                "notes": "Approved for all teams",
            }
        ]
    }

    file_path = tmp_path / "approved-apps.json"
    with open(file_path, "w") as f:
        json.dump(approval_data, f)

    return file_path


class TestShadowITAnalyzer:
    """Test ShadowITAnalyzer class."""

    def test_initialization(self, mock_client: Mock) -> None:
        """Test analyzer initialization."""
        analyzer = ShadowITAnalyzer(
            client=mock_client,
            domain="example.com",
            stale_days=60,
        )

        assert analyzer.domain == "example.com"
        assert analyzer.stale_days == 60
        assert len(analyzer.approved_apps) == 0

    def test_initialization_with_approval_list(
        self, mock_client: Mock, approval_list_file: Path
    ) -> None:
        """Test analyzer initialization with approval list."""
        analyzer = ShadowITAnalyzer(
            client=mock_client,
            domain="example.com",
            approval_list_path=str(approval_list_file),
        )

        assert len(analyzer.approved_apps) == 1
        assert "approved-app.com" in analyzer.approved_apps
        assert analyzer.approved_apps["approved-app.com"].app_name == "Approved Collaboration Tool"

    def test_load_approval_list_not_found(self, mock_client: Mock) -> None:
        """Test loading non-existent approval list."""
        analyzer = ShadowITAnalyzer(
            client=mock_client,
            domain="example.com",
            approval_list_path="/nonexistent/file.json",
        )

        # Should not raise error, just log warning
        assert len(analyzer.approved_apps) == 0

    def test_add_approved_app(self, mock_client: Mock) -> None:
        """Test adding app to approval list."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        status = analyzer.add_approved_app(
            client_id="test-app.com",
            app_name="Test App",
            approved_by="admin@example.com",
            notes="Test approval",
        )

        assert status.client_id == "test-app.com"
        assert status.app_name == "Test App"
        assert status.is_approved is True
        assert status.approved_by == "admin@example.com"
        assert "test-app.com" in analyzer.approved_apps

    def test_classify_apps(
        self,
        mock_client: Mock,
        sample_oauth_apps: list[OAuthApp],
        approval_list_file: Path,
    ) -> None:
        """Test app classification into shadow IT and approved."""
        analyzer = ShadowITAnalyzer(
            client=mock_client,
            domain="example.com",
            approval_list_path=str(approval_list_file),
        )

        shadow_apps, approved_apps = analyzer._classify_apps(sample_oauth_apps)

        # Google app + approved-app.com = 2 approved
        assert len(approved_apps) == 2

        # 3 shadow IT apps
        assert len(shadow_apps) == 3

        # Verify shadow IT apps
        shadow_ids = {app.client_id for app in shadow_apps}
        assert "shadow-admin-app.com" in shadow_ids
        assert "shadow-data-app.com" in shadow_ids
        assert "excessive-app.com" in shadow_ids

    @patch("vaulytica.core.analyzers.shadow_it_analyzer.OAuthScanner")
    def test_analyze_basic(
        self,
        mock_oauth_scanner_class: Mock,
        mock_client: Mock,
        sample_oauth_result: OAuthScanResult,
    ) -> None:
        """Test basic Shadow IT analysis."""
        # Setup mock scanner
        mock_scanner = Mock()
        mock_scanner.scan_oauth_tokens.return_value = sample_oauth_result
        mock_oauth_scanner_class.return_value = mock_scanner

        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")
        result = analyzer.analyze(include_audit_logs=False)

        assert result.total_apps_analyzed == 5
        assert result.shadow_it_apps > 0
        assert result.approved_apps > 0
        assert len(result.findings) > 0
        assert result.executive_summary != ""
        assert len(result.remediation_playbook) > 0

    def test_analyze_app_risks_admin_access(
        self, mock_client: Mock, sample_oauth_apps: list[OAuthApp]
    ) -> None:
        """Test risk analysis for app with admin access."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        admin_app = sample_oauth_apps[0]  # shadow-admin-app.com
        oauth_result = OAuthScanResult(apps=[admin_app])

        findings = analyzer._analyze_app_risks(admin_app, oauth_result)

        # Should have: unauthorized app + admin access risk
        assert len(findings) >= 2

        # Check for admin access finding
        admin_findings = [
            f for f in findings if f.category == ShadowITCategory.ADMIN_ACCESS_RISK
        ]
        assert len(admin_findings) == 1
        assert admin_findings[0].risk_level == ShadowITRiskLevel.CRITICAL

    def test_analyze_app_risks_data_exfiltration(
        self, mock_client: Mock, sample_oauth_apps: list[OAuthApp]
    ) -> None:
        """Test risk analysis for app with data access."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        data_app = sample_oauth_apps[1]  # shadow-data-app.com
        oauth_result = OAuthScanResult(apps=[data_app])

        findings = analyzer._analyze_app_risks(data_app, oauth_result)

        # Check for data exfiltration finding
        data_findings = [
            f
            for f in findings
            if f.category == ShadowITCategory.DATA_EXFILTRATION_RISK
        ]
        assert len(data_findings) == 1
        assert data_findings[0].risk_level in [
            ShadowITRiskLevel.HIGH,
            ShadowITRiskLevel.MEDIUM,
        ]

    def test_analyze_app_risks_excessive_permissions(
        self, mock_client: Mock, sample_oauth_apps: list[OAuthApp]
    ) -> None:
        """Test risk analysis for app with excessive permissions."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        excessive_app = sample_oauth_apps[4]  # excessive-app.com
        oauth_result = OAuthScanResult(apps=[excessive_app])

        findings = analyzer._analyze_app_risks(excessive_app, oauth_result)

        # Check for excessive permissions finding
        excessive_findings = [
            f
            for f in findings
            if f.category == ShadowITCategory.EXCESSIVE_PERMISSIONS
        ]
        assert len(excessive_findings) == 1

    def test_detect_stale_grants(
        self, mock_client: Mock, sample_oauth_apps: list[OAuthApp]
    ) -> None:
        """Test stale grant detection."""
        analyzer = ShadowITAnalyzer(
            client=mock_client, domain="example.com", stale_days=90
        )

        shadow_apps = sample_oauth_apps[:2]  # First 2 shadow IT apps
        oauth_result = OAuthScanResult(apps=shadow_apps)

        findings = analyzer._detect_stale_grants(oauth_result, shadow_apps)

        # Should detect stale grants for shadow apps
        assert len(findings) > 0
        assert all(f.category == ShadowITCategory.STALE_GRANT for f in findings)

    def test_analyze_widespread_adoption(
        self, mock_client: Mock, sample_oauth_apps: list[OAuthApp]
    ) -> None:
        """Test widespread adoption analysis."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        # shadow-data-app.com has 25 users (above threshold of 20)
        widespread_app = sample_oauth_apps[1]
        findings = analyzer._analyze_widespread_adoption([widespread_app])

        assert len(findings) == 1
        assert findings[0].category == ShadowITCategory.WIDESPREAD_ADOPTION
        assert findings[0].user_count >= 20

    def test_determine_risk_level(self, mock_client: Mock) -> None:
        """Test risk level determination from score."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        assert analyzer._determine_risk_level(95) == ShadowITRiskLevel.CRITICAL
        assert analyzer._determine_risk_level(75) == ShadowITRiskLevel.HIGH
        assert analyzer._determine_risk_level(50) == ShadowITRiskLevel.MEDIUM
        assert analyzer._determine_risk_level(30) == ShadowITRiskLevel.LOW
        assert analyzer._determine_risk_level(10) == ShadowITRiskLevel.INFO

    def test_generate_unapproved_app_list(
        self, mock_client: Mock, sample_oauth_apps: list[OAuthApp]
    ) -> None:
        """Test unapproved app list generation."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        shadow_apps = sample_oauth_apps[:3]
        app_list = analyzer._generate_unapproved_app_list(shadow_apps)

        assert len(app_list) == 3
        assert all("app_name" in app for app in app_list)
        assert all("client_id" in app for app in app_list)
        assert all("risk_score" in app for app in app_list)

        # Should be sorted by risk score descending
        scores = [app["risk_score"] for app in app_list]
        assert scores == sorted(scores, reverse=True)

    def test_generate_remediation_playbook(self, mock_client: Mock) -> None:
        """Test remediation playbook generation."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        result = ShadowITAnalysisResult(
            critical_findings=2,
            high_findings=3,
            medium_findings=5,
            stale_grants=10,
            data_exfiltration_risks=2,
        )

        playbook = analyzer._generate_remediation_playbook(result)

        assert len(playbook) > 0
        assert all("priority" in item for item in playbook)
        assert all("title" in item for item in playbook)
        assert all("actions" in item for item in playbook)

        # Should have priority order
        priorities = [item["priority"] for item in playbook]
        assert priorities == sorted(priorities)

    def test_generate_executive_summary(self, mock_client: Mock) -> None:
        """Test executive summary generation."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        result = ShadowITAnalysisResult(
            total_apps_analyzed=100,
            shadow_it_apps=15,
            critical_findings=2,
            high_findings=5,
            medium_findings=8,
            stale_grants=10,
        )

        summary = analyzer._generate_executive_summary(result)

        assert "15 unauthorized" in summary or "15 " in summary
        assert "100 total" in summary or "100 " in summary
        assert len(summary) > 100  # Should be substantial

    def test_export_approval_template(self, mock_client: Mock, tmp_path: Path) -> None:
        """Test approval template export."""
        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")

        output_file = tmp_path / "template.json"
        analyzer.export_approval_template(str(output_file))

        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)

        assert "approved_apps" in data
        assert isinstance(data["approved_apps"], list)
        assert len(data["approved_apps"]) > 0

    @patch("vaulytica.core.analyzers.shadow_it_analyzer.OAuthScanner")
    def test_analyze_with_findings_categorization(
        self,
        mock_oauth_scanner_class: Mock,
        mock_client: Mock,
        sample_oauth_result: OAuthScanResult,
    ) -> None:
        """Test that findings are properly categorized by severity."""
        mock_scanner = Mock()
        mock_scanner.scan_oauth_tokens.return_value = sample_oauth_result
        mock_oauth_scanner_class.return_value = mock_scanner

        analyzer = ShadowITAnalyzer(client=mock_client, domain="example.com")
        result = analyzer.analyze(include_audit_logs=False)

        # Verify findings are categorized
        total_categorized = (
            result.critical_findings
            + result.high_findings
            + result.medium_findings
            + result.low_findings
        )

        assert total_categorized > 0
        assert result.critical_findings > 0  # Admin app should trigger critical

    def test_finding_dataclass(self) -> None:
        """Test ShadowITFinding dataclass."""
        finding = ShadowITFinding(
            category=ShadowITCategory.UNAUTHORIZED_APP,
            risk_level=ShadowITRiskLevel.HIGH,
            app_name="Test App",
            client_id="test.com",
            user_count=10,
            title="Test Finding",
            description="Test description",
            evidence=["Evidence 1", "Evidence 2"],
            remediation_steps=["Step 1", "Step 2"],
            risk_score=75,
            scopes=["scope1", "scope2"],
        )

        assert finding.category == ShadowITCategory.UNAUTHORIZED_APP
        assert finding.risk_level == ShadowITRiskLevel.HIGH
        assert finding.app_name == "Test App"
        assert len(finding.evidence) == 2
        assert len(finding.remediation_steps) == 2

    def test_app_approval_status_dataclass(self) -> None:
        """Test AppApprovalStatus dataclass."""
        now = datetime.now(timezone.utc)
        status = AppApprovalStatus(
            client_id="test.com",
            app_name="Test App",
            is_approved=True,
            approved_by="admin@example.com",
            approved_at=now,
            notes="Approved for testing",
        )

        assert status.client_id == "test.com"
        assert status.is_approved is True
        assert status.approved_by == "admin@example.com"
        assert status.approved_at == now

    def test_analysis_result_dataclass(self) -> None:
        """Test ShadowITAnalysisResult dataclass."""
        result = ShadowITAnalysisResult(
            total_apps_analyzed=50,
            shadow_it_apps=10,
            approved_apps=40,
        )

        assert result.total_apps_analyzed == 50
        assert result.shadow_it_apps == 10
        assert result.approved_apps == 40
        assert len(result.findings) == 0
        assert result.timestamp is not None
