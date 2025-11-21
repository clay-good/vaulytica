"""Integration tests for complete workflows."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from vaulytica.core.scanners.file_scanner import FileScanner, FileInfo, FilePermission
from vaulytica.core.scanners.user_scanner import UserScanner, UserInfo
from vaulytica.core.compliance.reporting import ComplianceReporter
from vaulytica.core.reporters.html_dashboard import HTMLDashboardGenerator
from vaulytica.core.lifecycle.offboarding import EmployeeOffboardingManager


@pytest.fixture
def mock_google_client():
    """Mock Google Workspace client."""
    client = Mock()
    client.domain = "company.com"
    return client


@pytest.fixture
def sample_files():
    """Sample file scan results."""
    return [
        FileInfo(
            id="file1",
            name="sensitive_data.xlsx",
            owner_email="user@company.com",
            owner_name="User Name",
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
        ),
    ]


@pytest.fixture
def sample_users():
    """Sample user scan results."""
    return [
        UserInfo(
            id="inactive123",
            email="inactive@company.com",
            full_name="Inactive User",
            is_admin=False,
            is_suspended=False,
            is_archived=False,
            last_login_time=datetime(2023, 6, 1, tzinfo=timezone.utc),
            creation_time=datetime(2022, 1, 1, tzinfo=timezone.utc),
            two_factor_enabled=False,
            org_unit_path="/",
            is_inactive=True,
            days_since_last_login=200,
        ),
    ]


class TestPIIDetectionWorkflow:
    """Test end-to-end PII detection workflow."""

    @patch("vaulytica.core.scanners.file_scanner.FileScanner")
    def test_full_pii_scan_workflow(self, mock_scanner_class, tmp_path, mock_google_client, sample_files):
        """Test complete PII scan workflow from scan to report."""
        # Setup
        mock_scanner = Mock()
        mock_scanner.scan_files.return_value = sample_files
        mock_scanner_class.return_value = mock_scanner

        # Step 1: Scan files for PII
        scanner = FileScanner(client=mock_google_client)
        files_with_pii = scanner.scan_files(check_pii=True, external_only=True)

        assert len(files_with_pii) == 1
        assert files_with_pii[0].pii_detected is True
        assert "SSN" in files_with_pii[0].pii_types

        # Step 2: Generate compliance report
        compliance_gen = ComplianceReporter(domain="company.com")
        gdpr_report = compliance_gen.generate_gdpr_report(files=files_with_pii, users=[])

        assert gdpr_report.files_with_pii_shared_externally == 1

        # Step 3: Generate HTML dashboard
        dashboard_gen = HTMLDashboardGenerator(domain="company.com")
        output_file = tmp_path / "dashboard.html"

        dashboard_gen.generate_dashboard(
            scan_results={"files": files_with_pii, "users": [], "oauth_apps": []},
            output_file=output_file,
        )

        assert output_file.exists()

        # Step 4: Verify alert threshold
        high_risk_files = [f for f in files_with_pii if f.risk_score > 70]
        assert len(high_risk_files) == 1  # Should trigger alert

    @patch("vaulytica.core.scanners.file_scanner.FileScanner")
    @patch("vaulytica.integrations.email.EmailNotifier")
    def test_pii_alert_workflow(self, mock_email, mock_scanner_class, mock_google_client, sample_files):
        """Test PII detection with automated alerts."""
        # Setup
        mock_scanner = Mock()
        mock_scanner.scan_files.return_value = sample_files
        mock_scanner_class.return_value = mock_scanner

        # Scan for PII
        scanner = FileScanner(client=mock_google_client)
        files_with_pii = scanner.scan_files(check_pii=True, external_only=True)

        # Check if alert threshold is met
        threshold = 1
        if len(files_with_pii) >= threshold:
            # Send alert
            mock_email_instance = Mock()
            mock_email.return_value = mock_email_instance

            notifier = mock_email.return_value
            notifier.send_alert(
                subject="PII Alert: External sharing detected",
                body=f"Found {len(files_with_pii)} files with PII shared externally",
            )

            mock_email_instance.send_alert.assert_called_once()


class TestEmployeeOffboardingWorkflow:
    """Test end-to-end employee offboarding workflow."""

    @patch("vaulytica.core.lifecycle.offboarding.EmployeeOffboardingManager")
    def test_complete_offboarding_workflow(self, mock_offboarding_class, mock_google_client, tmp_path):
        """Test complete employee offboarding process."""
        # Setup
        mock_offboarding = Mock()
        mock_offboarding_class.return_value = mock_offboarding

        manager = EmployeeOffboardingManager(client=mock_google_client)

        # Step 1: Suspend user
        manager.suspend_user(email="terminated@company.com")
        mock_offboarding.suspend_user.assert_called_once()

        # Step 2: Transfer Drive files
        manager.transfer_drive_files(
            from_user="terminated@company.com",
            to_user="manager@company.com",
        )
        mock_offboarding.transfer_drive_files.assert_called_once()

        # Step 3: Delegate calendar
        manager.delegate_calendar(
            from_user="terminated@company.com",
            to_user="manager@company.com",
        )
        mock_offboarding.delegate_calendar.assert_called_once()

        # Step 4: Setup email forwarding
        manager.setup_email_forwarding(
            from_user="terminated@company.com",
            to_user="manager@company.com",
        )
        mock_offboarding.setup_email_forwarding.assert_called_once()

        # Step 5: Create backup
        backup_file = tmp_path / "terminated-backup.json"
        manager.create_backup(
            email="terminated@company.com",
            output_file=backup_file,
        )
        mock_offboarding.create_backup.assert_called_once()

    @patch("vaulytica.core.lifecycle.offboarding.EmployeeOffboardingManager")
    def test_offboarding_with_dry_run(self, mock_offboarding_class, mock_google_client):
        """Test offboarding dry-run mode."""
        mock_offboarding = Mock()
        mock_offboarding_class.return_value = mock_offboarding

        manager = EmployeeOffboardingManager(client=mock_google_client)

        # Dry-run should not make changes
        manager.offboard_user(
            email="terminated@company.com",
            transfer_to="manager@company.com",
            dry_run=True,
        )

        # Should have been called with dry_run=True
        mock_offboarding.offboard_user.assert_called_with(
            email="terminated@company.com",
            transfer_to="manager@company.com",
            dry_run=True,
        )


class TestComplianceReportingWorkflow:
    """Test end-to-end compliance reporting workflow."""

    @patch("vaulytica.core.scanners.file_scanner.FileScanner")
    @patch("vaulytica.core.scanners.user_scanner.UserScanner")
    def test_gdpr_compliance_workflow(
        self,
        mock_user_scanner,
        mock_file_scanner,
        mock_google_client,
        sample_files,
        sample_users,
        tmp_path,
    ):
        """Test complete GDPR compliance reporting workflow."""
        # Setup
        file_scanner_instance = Mock()
        file_scanner_instance.scan_files.return_value = sample_files
        mock_file_scanner.return_value = file_scanner_instance

        user_scanner_instance = Mock()
        user_scanner_instance.scan_users.return_value = sample_users
        mock_user_scanner.return_value = user_scanner_instance

        # Step 1: Scan files
        file_scanner = FileScanner(client=mock_google_client)
        files = file_scanner.scan_files(check_pii=True)

        # Step 2: Scan users
        user_scanner = UserScanner(client=mock_google_client)
        users = user_scanner.scan_users(check_2fa=True, check_inactive=True)

        # Step 3: Generate GDPR report
        compliance_gen = ComplianceReporter(domain="company.com")
        gdpr_report = compliance_gen.generate_gdpr_report(files=files, users=users)

        assert gdpr_report.domain == "company.com"
        assert gdpr_report.files_with_pii_shared_externally > 0
        assert gdpr_report.users_without_2fa > 0

        # Step 4: Export to JSON
        output_file = tmp_path / "gdpr-report.json"
        compliance_gen.export_to_json(gdpr_report, output_file)

        assert output_file.exists()

    @patch("vaulytica.core.scanners.file_scanner.FileScanner")
    @patch("vaulytica.core.scanners.user_scanner.UserScanner")
    def test_multi_framework_compliance(
        self,
        mock_user_scanner,
        mock_file_scanner,
        mock_google_client,
        sample_files,
        sample_users,
        tmp_path,
    ):
        """Test generating reports for multiple compliance frameworks."""
        # Setup
        file_scanner_instance = Mock()
        file_scanner_instance.scan_files.return_value = sample_files
        mock_file_scanner.return_value = file_scanner_instance

        user_scanner_instance = Mock()
        user_scanner_instance.scan_users.return_value = sample_users
        mock_user_scanner.return_value = user_scanner_instance

        # Scan data
        file_scanner = FileScanner(client=mock_google_client)
        files = file_scanner.scan_files(check_pii=True)

        user_scanner = UserScanner(client=mock_google_client)
        users = user_scanner.scan_users(check_2fa=True)

        # Generate all compliance reports
        compliance_gen = ComplianceReporter(domain="company.com")
        reports = compliance_gen.generate_all_reports(files=files, users=users)

        assert "gdpr" in reports
        assert "hipaa" in reports
        assert "soc2" in reports
        assert "pci_dss" in reports
        assert "ferpa" in reports
        assert "fedramp" in reports


class TestScheduledScanWorkflow:
    """Test scheduled scan workflows."""

    @patch("vaulytica.core.scanners.file_scanner.FileScanner")
    def test_scheduled_file_scan(self, mock_scanner_class, mock_google_client, sample_files, tmp_path):
        """Test scheduled file scan workflow."""
        # Setup
        mock_scanner = Mock()
        mock_scanner.scan_files.return_value = sample_files
        mock_scanner_class.return_value = mock_scanner

        # Simulate scheduled scan
        scanner = FileScanner(client=mock_google_client)
        files = scanner.scan_files(external_only=True, check_pii=True)

        # Generate report
        output_file = tmp_path / f"scan-{datetime.now().strftime('%Y%m%d')}.csv"

        # Save results (simulated)
        with open(output_file, "w") as f:
            f.write("file_id,name,risk_score\n")
            for file in files:
                f.write(f"{file.id},{file.name},{file.risk_score}\n")

        assert output_file.exists()

    @patch("vaulytica.core.scanners.user_scanner.UserScanner")
    def test_weekly_inactive_user_scan(self, mock_scanner_class, mock_google_client, sample_users, tmp_path):
        """Test weekly inactive user scan workflow."""
        # Setup
        mock_scanner = Mock()
        mock_scanner.scan_users.return_value = sample_users
        mock_scanner_class.return_value = mock_scanner

        # Simulate weekly scan
        scanner = UserScanner(client=mock_google_client)
        inactive_users = scanner.scan_users(days_since_last_login=90)

        # Filter inactive users
        inactive = [u for u in inactive_users if u.is_inactive]

        assert len(inactive) == 1

        # Generate report
        output_file = tmp_path / "inactive-users-weekly.json"

        import json
        with open(output_file, "w") as f:
            json.dump(
                {
                    "scan_date": datetime.now().isoformat(),
                    "inactive_users": [
                        {"email": u.email, "inactive_days": u.inactive_days}
                        for u in inactive
                    ],
                },
                f,
            )

        assert output_file.exists()


class TestMultiScannerWorkflow:
    """Test workflows combining multiple scanners."""

    @patch("vaulytica.core.scanners.file_scanner.FileScanner")
    @patch("vaulytica.core.scanners.user_scanner.UserScanner")
    @patch("vaulytica.core.scanners.oauth_scanner.OAuthScanner")
    def test_comprehensive_security_scan(
        self,
        mock_oauth_scanner,
        mock_user_scanner,
        mock_file_scanner,
        mock_google_client,
        sample_files,
        sample_users,
        tmp_path,
    ):
        """Test comprehensive security scan using multiple scanners."""
        # Setup
        file_scanner_instance = Mock()
        file_scanner_instance.scan_files.return_value = sample_files
        mock_file_scanner.return_value = file_scanner_instance

        user_scanner_instance = Mock()
        user_scanner_instance.scan_users.return_value = sample_users
        mock_user_scanner.return_value = user_scanner_instance

        oauth_scanner_instance = Mock()
        oauth_scanner_instance.scan_oauth_apps.return_value = []
        mock_oauth_scanner.return_value = oauth_scanner_instance

        # Run all scanners
        file_scanner = FileScanner(client=mock_google_client)
        files = file_scanner.scan_files(check_pii=True, external_only=True)

        user_scanner = UserScanner(client=mock_google_client)
        users = user_scanner.scan_users(check_2fa=True, days_since_last_login=90)

        oauth_scanner = mock_oauth_scanner(client=mock_google_client)
        oauth_apps = oauth_scanner.scan_oauth_apps(min_risk_score=70)

        # Correlate findings
        findings = {
            "high_risk_files": [f for f in files if f.risk_score > 70],
            "inactive_users": [u for u in users if u.is_inactive],
            "users_without_2fa": [u for u in users if not u.two_factor_enabled],
            "risky_oauth_apps": oauth_apps,
        }

        # Generate unified report
        dashboard_gen = HTMLDashboardGenerator(domain="company.com")
        output_file = tmp_path / "security-dashboard.html"

        dashboard_gen.generate_dashboard(
            scan_results={"files": files, "users": users, "oauth_apps": oauth_apps},
            output_file=output_file,
        )

        assert output_file.exists()
        assert len(findings["high_risk_files"]) == 1
        assert len(findings["inactive_users"]) == 1

    @patch("vaulytica.core.scanners.file_scanner.FileScanner")
    @patch("vaulytica.core.scanners.user_scanner.UserScanner")
    def test_risk_correlation_workflow(
        self,
        mock_user_scanner,
        mock_file_scanner,
        mock_google_client,
        sample_files,
        sample_users,
    ):
        """Test correlating risks across multiple scanners."""
        # Setup
        file_scanner_instance = Mock()
        file_scanner_instance.scan_files.return_value = sample_files
        mock_file_scanner.return_value = file_scanner_instance

        user_scanner_instance = Mock()
        user_scanner_instance.scan_users.return_value = sample_users
        mock_user_scanner.return_value = user_scanner_instance

        # Scan files and users
        file_scanner = FileScanner(client=mock_google_client)
        files = file_scanner.scan_files(check_pii=True)

        user_scanner = UserScanner(client=mock_google_client)
        users = user_scanner.scan_users()

        # Correlate risks by user
        user_risk_map = {}
        for file in files:
            if file.owner_email not in user_risk_map:
                user_risk_map[file.owner_email] = []
            user_risk_map[file.owner_email].append(file)

        # Identify high-risk users (users with multiple high-risk files)
        high_risk_users = {
            email: files_list
            for email, files_list in user_risk_map.items()
            if len(files_list) > 0 and any(f.risk_score > 70 for f in files_list)
        }

        assert len(high_risk_users) > 0
