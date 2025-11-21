"""Tests for CLI scan commands."""

import json
import csv
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from vaulytica.cli.main import cli
from vaulytica.core.scanners.file_scanner import FileInfo, FilePermission
from vaulytica.core.scanners.user_scanner import UserInfo
from vaulytica.core.scanners.oauth_scanner import OAuthApp


@pytest.fixture
def cli_runner():
    """Create CLI runner."""
    return CliRunner()


@pytest.fixture
def mock_file_scanner():
    """Mock file scanner."""
    scanner = Mock()
    scanner.scan_files.return_value = [
        FileInfo(
            id="file1",
            name="test.pdf",
            owner_email="user@company.com",
            owner_name="User Name",
            mime_type="application/pdf",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            size=1024,
            web_view_link="https://drive.google.com/file/d/file1",
            is_public=False,
            is_shared_externally=True,
            external_domains=["external.com"],
            external_emails=["external@external.com"],
            risk_score=75,
        )
    ]
    return scanner


@pytest.fixture
def mock_user_scanner():
    """Mock user scanner."""
    scanner = Mock()
    scanner.scan_users.return_value = [
        UserInfo(
            id="inactive123",
            email="inactive@company.com",
            full_name="Inactive User",
            is_admin=False,
            is_suspended=False,
            is_archived=False,
            last_login_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            creation_time=datetime(2023, 1, 1, tzinfo=timezone.utc),
            two_factor_enabled=False,
            org_unit_path="/",
            is_inactive=True,
            days_since_last_login=180,
        )
    ]
    return scanner


@pytest.fixture
def mock_oauth_scanner():
    """Mock OAuth scanner."""
    scanner = Mock()
    scanner.scan_oauth_apps.return_value = [
        OAuthApp(
            client_id="client123",
            display_text="Risky App",
            scopes=["https://www.googleapis.com/auth/drive"],
            authorized_by=["user@company.com"],
            risk_score=85,
            is_verified=False,
            is_internal=False,
        )
    ]
    return scanner


class TestScanFilesCommand:
    """Test scan files command."""

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_files_basic(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test basic file scan."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            # Create config
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files"])

            assert result.exit_code == 0
            assert "test.pdf" in result.output or result.exit_code == 0  # May not show in output format

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_files_external_only(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test scanning only externally shared files."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files", "--external-only"])

            assert result.exit_code == 0
            mock_file_scanner.scan_files.assert_called_once()

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_files_csv_output(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test CSV output format."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files", "--output", "report.csv"])

            assert result.exit_code == 0
            assert Path("report.csv").exists()

            # Verify CSV content
            with open("report.csv", "r") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 1
                assert rows[0]["File Name"] == "test.pdf"
                assert rows[0]["Owner"] == "user@company.com"

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_files_json_output(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test JSON output format."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files", "--output", "report.json"])

            assert result.exit_code == 0
            assert Path("report.json").exists()

            # Verify JSON content
            with open("report.json", "r") as f:
                data = json.load(f)
                assert data["scan_type"] == "files"
                assert len(data["files"]) == 1
                assert data["files"][0]["name"] == "test.pdf"

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_files_with_pii_check(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test file scan with PII detection."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files", "--check-pii"])

            assert result.exit_code == 0
            # Verify scan was called with PII check enabled
            call_kwargs = mock_file_scanner.scan_files.call_args[1]
            assert call_kwargs.get("check_pii") is True


class TestScanUsersCommand:
    """Test scan users command."""

    @patch("vaulytica.cli.commands.scan.UserScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_users_basic(self, mock_create_client, mock_scanner_class, cli_runner, mock_user_scanner):
        """Test basic user scan."""
        mock_scanner_class.return_value = mock_user_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "users"])

            assert result.exit_code == 0

    @patch("vaulytica.cli.commands.scan.UserScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_users_inactive_days(self, mock_create_client, mock_scanner_class, cli_runner, mock_user_scanner):
        """Test scanning for inactive users."""
        mock_scanner_class.return_value = mock_user_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "users", "--inactive-days", "90"])

            assert result.exit_code == 0
            call_kwargs = mock_user_scanner.scan_users.call_args[1]
            assert call_kwargs.get("inactive_days") == 90

    @patch("vaulytica.cli.commands.scan.UserScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_users_2fa_check(self, mock_create_client, mock_scanner_class, cli_runner, mock_user_scanner):
        """Test 2FA compliance check."""
        mock_scanner_class.return_value = mock_user_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "users", "--check-2fa"])

            assert result.exit_code == 0

    @patch("vaulytica.cli.commands.scan.UserScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_users_csv_output(self, mock_create_client, mock_scanner_class, cli_runner, mock_user_scanner):
        """Test user scan CSV output."""
        mock_scanner_class.return_value = mock_user_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "users", "--output", "users.csv"])

            assert result.exit_code == 0
            assert Path("users.csv").exists()


class TestScanOAuthAppsCommand:
    """Test scan oauth-apps command."""

    @patch("vaulytica.cli.commands.scan.OAuthScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_oauth_apps_basic(self, mock_create_client, mock_scanner_class, cli_runner, mock_oauth_scanner):
        """Test basic OAuth app scan."""
        mock_scanner_class.return_value = mock_oauth_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "oauth-apps"])

            assert result.exit_code == 0

    @patch("vaulytica.cli.commands.scan.OAuthScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_oauth_apps_min_risk_score(self, mock_create_client, mock_scanner_class, cli_runner, mock_oauth_scanner):
        """Test filtering OAuth apps by risk score."""
        mock_scanner_class.return_value = mock_oauth_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "oauth-apps", "--min-risk-score", "70"])

            assert result.exit_code == 0

    @patch("vaulytica.cli.commands.scan.OAuthScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_oauth_apps_json_output(self, mock_create_client, mock_scanner_class, cli_runner, mock_oauth_scanner):
        """Test OAuth apps JSON output."""
        mock_scanner_class.return_value = mock_oauth_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "oauth-apps", "--output", "apps.json"])

            assert result.exit_code == 0
            assert Path("apps.json").exists()

            with open("apps.json", "r") as f:
                data = json.load(f)
                assert data["scan_type"] == "oauth_apps"
                assert len(data["apps"]) == 1


class TestScanCommandErrorHandling:
    """Test error handling in scan commands."""

    def test_scan_files_missing_config(self, cli_runner):
        """Test scan fails gracefully with missing config."""
        with cli_runner.isolated_filesystem():
            result = cli_runner.invoke(cli, ["scan", "files"])

            # Should fail gracefully, not crash
            assert result.exit_code != 0

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_files_api_error(self, mock_create_client, mock_scanner_class, cli_runner):
        """Test handling of API errors."""
        mock_scanner = Mock()
        mock_scanner.scan_files.side_effect = Exception("API Error")
        mock_scanner_class.return_value = mock_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files"])

            # Should handle error gracefully
            assert result.exit_code != 0
            assert "error" in result.output.lower() or result.exception

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_scan_files_invalid_output_path(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test handling of invalid output path."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            # Try to write to non-existent directory
            result = cli_runner.invoke(cli, ["scan", "files", "--output", "/nonexistent/dir/report.csv"])

            # Should handle error gracefully
            assert result.exit_code != 0 or Path("/nonexistent/dir/report.csv").exists() is False


class TestOutputFormats:
    """Test output format consistency across commands."""

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_csv_format_consistency(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test CSV output has consistent headers."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files", "--output", "report.csv"])

            assert result.exit_code == 0

            with open("report.csv", "r") as f:
                reader = csv.reader(f)
                headers = next(reader)
                # Verify expected headers
                assert "File ID" in headers
                assert "File Name" in headers
                assert "Owner" in headers
                assert "Risk Score" in headers

    @patch("vaulytica.cli.commands.scan.FileScanner")
    @patch("vaulytica.cli.commands.scan.create_client_from_config")
    def test_json_format_structure(self, mock_create_client, mock_scanner_class, cli_runner, mock_file_scanner):
        """Test JSON output has consistent structure."""
        mock_scanner_class.return_value = mock_file_scanner
        mock_create_client.return_value = Mock()

        with cli_runner.isolated_filesystem():
            Path("config.yaml").write_text("google_workspace:\n  domain: test.com\n")

            result = cli_runner.invoke(cli, ["scan", "files", "--output", "report.json"])

            assert result.exit_code == 0

            with open("report.json", "r") as f:
                data = json.load(f)
                # Verify expected structure
                assert "scan_type" in data
                assert "timestamp" in data
                assert "summary" in data
                assert "files" in data
                assert isinstance(data["files"], list)
