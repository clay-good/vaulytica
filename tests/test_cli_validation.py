"""CLI validation tests - test that commands can be invoked."""

import pytest
from click.testing import CliRunner
from unittest.mock import Mock, patch

from vaulytica.cli.main import cli


@pytest.fixture
def runner():
    """Create CLI test runner."""
    return CliRunner()


class TestCLICommands:
    """Test CLI commands can be invoked."""

    def test_cli_help(self, runner):
        """Test main CLI help."""
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'Vaulytica' in result.output or 'Usage' in result.output

    def test_cli_version(self, runner):
        """Test version command."""
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0

    def test_scan_help(self, runner):
        """Test scan command help."""
        result = runner.invoke(cli, ['scan', '--help'])
        assert result.exit_code == 0
        assert 'scan' in result.output.lower()

    def test_workflow_help(self, runner):
        """Test workflow command help."""
        result = runner.invoke(cli, ['workflow', '--help'])
        assert result.exit_code == 0
        assert 'workflow' in result.output.lower()

    def test_policy_help(self, runner):
        """Test policy command help."""
        result = runner.invoke(cli, ['policy', '--help'])
        assert result.exit_code == 0
        assert 'policy' in result.output.lower()

    def test_compliance_help(self, runner):
        """Test compliance command help."""
        result = runner.invoke(cli, ['compliance', '--help'])
        assert result.exit_code == 0
        assert 'compliance' in result.output.lower()

    def test_monitor_help(self, runner):
        """Test monitor command help."""
        result = runner.invoke(cli, ['monitor', '--help'])
        assert result.exit_code == 0
        assert 'monitor' in result.output.lower()

    def test_offboard_help(self, runner):
        """Test offboard command help."""
        result = runner.invoke(cli, ['offboard', '--help'])
        assert result.exit_code == 0
        assert 'offboard' in result.output.lower()

    def test_config_help(self, runner):
        """Test config command help."""
        result = runner.invoke(cli, ['config', '--help'])
        assert result.exit_code == 0
        assert 'config' in result.output.lower()

    def test_init_help(self, runner):
        """Test init command help."""
        result = runner.invoke(cli, ['init', '--help'])
        assert result.exit_code == 0
        assert 'init' in result.output.lower()


class TestWorkflowCommands:
    """Test workflow subcommands."""

    def test_workflow_external_pii_alert_help(self, runner):
        """Test external-pii-alert workflow help."""
        result = runner.invoke(cli, ['workflow', 'external-pii-alert', '--help'])
        assert result.exit_code == 0
        assert 'external' in result.output.lower() or 'pii' in result.output.lower()

    def test_workflow_gmail_external_pii_alert_help(self, runner):
        """Test gmail-external-pii-alert workflow help."""
        result = runner.invoke(cli, ['workflow', 'gmail-external-pii-alert', '--help'])
        assert result.exit_code == 0
        assert 'gmail' in result.output.lower() or 'external' in result.output.lower()


class TestScanCommands:
    """Test scan subcommands."""

    def test_scan_files_help(self, runner):
        """Test scan files help."""
        result = runner.invoke(cli, ['scan', 'files', '--help'])
        assert result.exit_code == 0
        assert 'files' in result.output.lower() or 'drive' in result.output.lower()

    def test_scan_gmail_help(self, runner):
        """Test scan gmail help."""
        result = runner.invoke(cli, ['scan', 'gmail', '--help'])
        assert result.exit_code == 0
        assert 'gmail' in result.output.lower() or 'email' in result.output.lower()

    def test_scan_users_help(self, runner):
        """Test scan users help."""
        result = runner.invoke(cli, ['scan', 'users', '--help'])
        assert result.exit_code == 0
        assert 'users' in result.output.lower()

    def test_scan_oauth_help(self, runner):
        """Test scan oauth-apps help."""
        result = runner.invoke(cli, ['scan', 'oauth-apps', '--help'])
        assert result.exit_code == 0
        assert 'oauth' in result.output.lower()

    def test_scan_shared_drives_help(self, runner):
        """Test scan shared-drives help."""
        result = runner.invoke(cli, ['scan', 'shared-drives', '--help'])
        assert result.exit_code == 0
        assert 'shared' in result.output.lower() or 'drive' in result.output.lower()


class TestPolicyCommands:
    """Test policy subcommands."""

    def test_policy_expire_help(self, runner):
        """Test policy expire help."""
        result = runner.invoke(cli, ['policy', 'expire', '--help'])
        assert result.exit_code == 0


class TestComplianceCommands:
    """Test compliance subcommands."""

    def test_compliance_report_help(self, runner):
        """Test compliance report help."""
        result = runner.invoke(cli, ['compliance', 'report', '--help'])
        assert result.exit_code == 0

    def test_compliance_gdpr_help(self, runner):
        """Test compliance gdpr help."""
        result = runner.invoke(cli, ['compliance', 'gdpr', '--help'])
        assert result.exit_code == 0

    def test_compliance_hipaa_help(self, runner):
        """Test compliance hipaa help."""
        result = runner.invoke(cli, ['compliance', 'hipaa', '--help'])
        assert result.exit_code == 0

    def test_compliance_soc2_help(self, runner):
        """Test compliance soc2 help."""
        result = runner.invoke(cli, ['compliance', 'soc2', '--help'])
        assert result.exit_code == 0


class TestMonitorCommands:
    """Test monitor subcommands."""

    def test_monitor_health_help(self, runner):
        """Test monitor health help."""
        result = runner.invoke(cli, ['monitor', 'health', '--help'])
        assert result.exit_code == 0

    def test_monitor_metrics_help(self, runner):
        """Test monitor metrics help."""
        result = runner.invoke(cli, ['monitor', 'metrics', '--help'])
        assert result.exit_code == 0

    def test_monitor_performance_help(self, runner):
        """Test monitor performance help."""
        result = runner.invoke(cli, ['monitor', 'performance', '--help'])
        assert result.exit_code == 0

    def test_monitor_system_help(self, runner):
        """Test monitor system help."""
        result = runner.invoke(cli, ['monitor', 'system', '--help'])
        assert result.exit_code == 0

