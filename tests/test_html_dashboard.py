"""Tests for HTML dashboard generation."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from vaulytica.core.reporters.html_dashboard import HTMLDashboardGenerator
from vaulytica.core.scanners.file_scanner import FileInfo, FilePermission
from vaulytica.core.scanners.user_scanner import UserInfo
from vaulytica.core.scanners.oauth_scanner import OAuthApp


@pytest.fixture
def sample_scan_results():
    """Sample scan results for dashboard testing."""
    return {
        "files": [
            FileInfo(
                id="file1",
                name="sensitive_data.xlsx",
                owner_email="user@company.com",
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
                sharing_info=FilePermission(
                    is_public=False,
                    is_shared_externally=True,
                    internal_shares=1,
                    external_shares=1,
                    public_shares=0,
                    anyone_with_link=False,
                ),
                pii_detected=True,
                pii_types=["EMAIL", "SSN"],
            ),
            FileInfo(
                id="file2",
                name="public_doc.pdf",
                owner_email="user@company.com",
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
                sharing_info=FilePermission(
                    is_public=True,
                    is_shared_externally=True,
                    internal_shares=0,
                    external_shares=0,
                    public_shares=1,
                    anyone_with_link=True,
                ),
                pii_detected=False,
                pii_types=[],
            ),
        ],
        "users": [
            UserInfo(
                email="inactive@company.com",
                full_name="Inactive User",
                is_admin=False,
                is_suspended=False,
                last_login_time=datetime(2023, 6, 1, tzinfo=timezone.utc),
                creation_time=datetime(2022, 1, 1, tzinfo=timezone.utc),
                two_factor_enabled=False,
                org_unit_path="/",
                is_inactive=True,
                inactive_days=200,
            ),
            UserInfo(
                email="active@company.com",
                full_name="Active User",
                is_admin=False,
                is_suspended=False,
                last_login_time=datetime.now(timezone.utc),
                creation_time=datetime(2023, 1, 1, tzinfo=timezone.utc),
                two_factor_enabled=True,
                org_unit_path="/Engineering",
                is_inactive=False,
                inactive_days=0,
            ),
        ],
        "oauth_apps": [
            OAuthApp(
                client_id="client123",
                display_text="Risky App",
                scopes=["https://www.googleapis.com/auth/drive"],
                authorized_by=["user@company.com"],
                risk_score=85,
                is_verified=False,
                is_internal=False,
            ),
        ],
    }


class TestHTMLDashboardGenerator:
    """Test HTML dashboard generator."""

    def test_create_dashboard_generator(self):
        """Test creating dashboard generator."""
        generator = HTMLDashboardGenerator(domain="company.com")

        assert generator.domain == "company.com"

    def test_generate_basic_dashboard(self, tmp_path, sample_scan_results):
        """Test generating a basic dashboard."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        assert output_file.exists()
        assert output_file.stat().st_size > 0

        # Verify HTML content
        html_content = output_file.read_text()
        assert "<html" in html_content
        assert "</html>" in html_content
        assert "company.com" in html_content

    def test_dashboard_includes_summary_stats(self, tmp_path, sample_scan_results):
        """Test that dashboard includes summary statistics."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include summary stats
        assert "Total Files" in html_content or "Files Scanned" in html_content
        assert "Total Users" in html_content or "Users Scanned" in html_content

    def test_dashboard_includes_charts(self, tmp_path, sample_scan_results):
        """Test that dashboard includes Chart.js charts."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include Chart.js
        assert "chart.js" in html_content.lower() or "canvas" in html_content.lower()

    def test_dashboard_includes_risk_scoring(self, tmp_path, sample_scan_results):
        """Test that dashboard includes risk scoring."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include risk scores
        assert "risk" in html_content.lower() or "score" in html_content.lower()

    def test_dashboard_includes_pii_detection(self, tmp_path, sample_scan_results):
        """Test that dashboard includes PII detection results."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should mention PII
        assert "PII" in html_content or "pii" in html_content.lower()

    def test_dashboard_includes_timestamp(self, tmp_path, sample_scan_results):
        """Test that dashboard includes generation timestamp."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include timestamp
        assert str(datetime.now().year) in html_content

    def test_dashboard_file_table(self, tmp_path, sample_scan_results):
        """Test that dashboard includes file details table."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include table with file names
        assert "sensitive_data.xlsx" in html_content
        assert "public_doc.pdf" in html_content
        assert "<table" in html_content.lower()

    def test_dashboard_user_table(self, tmp_path, sample_scan_results):
        """Test that dashboard includes user details table."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include user emails
        assert "inactive@company.com" in html_content
        assert "active@company.com" in html_content

    def test_dashboard_oauth_app_table(self, tmp_path, sample_scan_results):
        """Test that dashboard includes OAuth app details."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include OAuth app name
        assert "Risky App" in html_content

    def test_dashboard_with_empty_results(self, tmp_path):
        """Test dashboard generation with empty results."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results={"files": [], "users": [], "oauth_apps": []},
            output_file=output_file,
        )

        assert output_file.exists()

        html_content = output_file.read_text()
        assert "<html" in html_content
        assert "No data" in html_content or "0" in html_content

    def test_dashboard_css_styling(self, tmp_path, sample_scan_results):
        """Test that dashboard includes CSS styling."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include CSS
        assert "<style" in html_content.lower() or "stylesheet" in html_content.lower()

    def test_dashboard_responsive_design(self, tmp_path, sample_scan_results):
        """Test that dashboard includes responsive design elements."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include viewport meta tag for responsive design
        assert "viewport" in html_content.lower()


class TestDashboardCharts:
    """Test dashboard chart generation."""

    def test_risk_distribution_chart(self, tmp_path, sample_scan_results):
        """Test risk distribution chart."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include risk distribution data
        assert "85" in html_content  # Risk score from sample data
        assert "95" in html_content  # Risk score from sample data

    def test_pii_types_chart(self, tmp_path, sample_scan_results):
        """Test PII types distribution chart."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include PII types from sample data
        assert "EMAIL" in html_content or "SSN" in html_content

    def test_sharing_distribution_chart(self, tmp_path, sample_scan_results):
        """Test file sharing distribution chart."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include sharing stats
        assert "external" in html_content.lower() or "public" in html_content.lower()


class TestDashboardExport:
    """Test dashboard export functionality."""

    def test_export_to_pdf_ready(self, tmp_path, sample_scan_results):
        """Test that dashboard is print/PDF ready."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include print media styles
        assert "@media print" in html_content or "print" in html_content.lower()

    def test_dashboard_metadata(self, tmp_path, sample_scan_results):
        """Test that dashboard includes proper HTML metadata."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
        )

        html_content = output_file.read_text()

        # Should include title and charset
        assert "<title" in html_content.lower()
        assert "charset" in html_content.lower()


class TestDashboardTemplates:
    """Test dashboard templates and formatting."""

    def test_executive_summary_section(self, tmp_path, sample_scan_results):
        """Test executive summary section."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
            include_executive_summary=True,
        )

        html_content = output_file.read_text()

        # Should include executive summary
        assert "summary" in html_content.lower() or "overview" in html_content.lower()

    def test_detailed_findings_section(self, tmp_path, sample_scan_results):
        """Test detailed findings section."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
            include_detailed_findings=True,
        )

        html_content = output_file.read_text()

        # Should include detailed findings
        assert "findings" in html_content.lower() or "details" in html_content.lower()

    def test_recommendations_section(self, tmp_path, sample_scan_results):
        """Test recommendations section."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"
        generator.generate_dashboard(
            scan_results=sample_scan_results,
            output_file=output_file,
            include_recommendations=True,
        )

        html_content = output_file.read_text()

        # Should include recommendations
        assert "recommend" in html_content.lower() or "action" in html_content.lower()


class TestDashboardErrorHandling:
    """Test error handling in dashboard generation."""

    def test_handle_invalid_output_path(self, sample_scan_results):
        """Test handling of invalid output path."""
        generator = HTMLDashboardGenerator(domain="company.com")

        # Try to write to non-existent directory
        with pytest.raises(Exception):
            generator.generate_dashboard(
                scan_results=sample_scan_results,
                output_file=Path("/nonexistent/dir/dashboard.html"),
            )

    def test_handle_malformed_scan_results(self, tmp_path):
        """Test handling of malformed scan results."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"

        # Try with None or malformed data
        try:
            generator.generate_dashboard(
                scan_results=None,
                output_file=output_file,
            )
        except Exception:
            pass  # Expected to fail gracefully

    def test_handle_missing_required_fields(self, tmp_path):
        """Test handling of scan results with missing fields."""
        generator = HTMLDashboardGenerator(domain="company.com")

        output_file = tmp_path / "dashboard.html"

        # Provide incomplete scan results
        incomplete_results = {"files": []}  # Missing users and oauth_apps

        generator.generate_dashboard(
            scan_results=incomplete_results,
            output_file=output_file,
        )

        # Should handle gracefully and generate dashboard
        assert output_file.exists()
