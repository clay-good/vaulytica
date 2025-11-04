"""Tests for CLI commands."""

import pytest
from click.testing import CliRunner
from pathlib import Path

from vaulytica.cli.main import cli


class TestCLI:
    """Tests for main CLI."""

    def test_cli_help(self):
        """Test CLI help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Vaulytica" in result.output
        assert "Google Workspace Security" in result.output

    def test_cli_version(self):
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        assert "Vaulytica" in result.output

    def test_cli_with_version_option(self):
        """Test --version option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "vaulytica" in result.output.lower()


class TestInitCommand:
    """Tests for init command."""

    def test_init_help(self):
        """Test init command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["init", "--help"])
        assert result.exit_code == 0
        assert "Initialize" in result.output

    def test_init_creates_config(self, tmp_path):
        """Test that init creates configuration file."""
        runner = CliRunner()

        # Mock user input
        with runner.isolated_filesystem(temp_dir=tmp_path):
            config_file = Path("config.yaml")
            result = runner.invoke(
                cli,
                ["--config", "config.yaml", "init", "--force"],
                input="example.com\nservice-account.json\nadmin@example.com\ny\nsmtp.gmail.com\n587\nalerts@example.com\nsecurity@example.com\n",
            )

            assert config_file.exists(), f"Config file not created. Output: {result.output}"
            assert result.exit_code == 0, f"Command failed with: {result.output}"


class TestScanCommand:
    """Tests for scan commands."""

    def test_scan_help(self):
        """Test scan command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan Google Workspace" in result.output

    def test_scan_files_help(self):
        """Test scan files command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "files", "--help"])
        assert result.exit_code == 0
        assert "Scan Google Drive files" in result.output

    def test_scan_users_help(self):
        """Test scan users command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "users", "--help"])
        assert result.exit_code == 0
        assert "inactive users" in result.output


class TestReportCommand:
    """Tests for report commands."""

    def test_report_help(self):
        """Test report command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--help"])
        assert result.exit_code == 0
        assert "Generate reports" in result.output

    def test_report_generate_help(self):
        """Test report generate command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "generate", "--help"])
        assert result.exit_code == 0
        assert "Generate a report" in result.output


class TestConfigCommand:
    """Tests for config command."""

    def test_config_help(self):
        """Test config command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "--help"])
        assert result.exit_code == 0
        assert "Show current configuration" in result.output

    def test_config_missing_file(self, tmp_path):
        """Test config command with missing file."""
        runner = CliRunner()
        config_file = tmp_path / "missing.yaml"

        result = runner.invoke(cli, ["--config", str(config_file), "config"])
        assert result.exit_code != 0
        assert "not found" in result.output


class TestTestCommand:
    """Tests for test command."""

    def test_test_help(self):
        """Test test command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["test", "--help"])
        assert result.exit_code == 0
        assert "Test Vaulytica" in result.output

