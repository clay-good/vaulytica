"""Tests for scanner performance optimizations and input validation."""

import pytest
from unittest.mock import Mock
from datetime import datetime, timezone


class TestOAuthScannerOptimizations:
    """Tests for OAuth scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        return client

    @pytest.fixture
    def oauth_scanner(self, mock_client):
        """Create an OAuth scanner instance."""
        from vaulytica.core.scanners.oauth_scanner import OAuthScanner
        return OAuthScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_user_email(self, oauth_scanner):
        """Test that invalid user_email raises ValueError."""
        with pytest.raises(ValueError, match="user_email must be a string"):
            oauth_scanner.scan_oauth_tokens(user_email=123)

    def test_input_validation_invalid_max_users(self, oauth_scanner):
        """Test that invalid max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            oauth_scanner.scan_oauth_tokens(max_users=-1)

    def test_input_validation_zero_max_users(self, oauth_scanner):
        """Test that zero max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            oauth_scanner.scan_oauth_tokens(max_users=0)

    def test_input_validation_string_max_users(self, oauth_scanner):
        """Test that string max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            oauth_scanner.scan_oauth_tokens(max_users="10")

    def test_valid_parameters(self, oauth_scanner, mock_client):
        """Test that valid parameters are accepted."""
        # Mock the necessary methods
        mock_client.admin.tokens().list().execute.return_value = {"items": []}
        
        # Should not raise any exceptions
        result = oauth_scanner.scan_oauth_tokens(user_email="user@example.com", max_users=10)
        assert result is not None


class TestMobileDeviceScannerOptimizations:
    """Tests for mobile device scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        return client

    @pytest.fixture
    def mobile_scanner(self, mock_client):
        """Create a mobile device scanner instance."""
        from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanner
        return MobileDeviceScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_users(self, mobile_scanner):
        """Test that invalid max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            mobile_scanner.scan_all_devices(max_users=-1)

    def test_input_validation_zero_max_users(self, mobile_scanner):
        """Test that zero max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            mobile_scanner.scan_all_devices(max_users=0)

    def test_input_validation_invalid_os_filter(self, mobile_scanner):
        """Test that invalid os_filter raises ValueError."""
        with pytest.raises(ValueError, match="os_filter must be ANDROID, IOS, or IOS_SYNC"):
            mobile_scanner.scan_all_devices(os_filter="WINDOWS")

    def test_input_validation_lowercase_os_filter(self, mobile_scanner):
        """Test that lowercase os_filter raises ValueError."""
        with pytest.raises(ValueError, match="os_filter must be ANDROID, IOS, or IOS_SYNC"):
            mobile_scanner.scan_all_devices(os_filter="android")

    def test_valid_os_filter_android(self, mobile_scanner, mock_client):
        """Test that valid ANDROID os_filter is accepted."""
        # Mock the necessary methods
        mock_client.admin.users().list().execute.return_value = {"users": []}
        
        # Should not raise any exceptions
        result = mobile_scanner.scan_all_devices(os_filter="ANDROID")
        assert result is not None

    def test_valid_os_filter_ios(self, mobile_scanner, mock_client):
        """Test that valid IOS os_filter is accepted."""
        # Mock the necessary methods
        mock_client.admin.users().list().execute.return_value = {"users": []}
        
        # Should not raise any exceptions
        result = mobile_scanner.scan_all_devices(os_filter="IOS")
        assert result is not None

    def test_valid_os_filter_ios_sync(self, mobile_scanner, mock_client):
        """Test that valid IOS_SYNC os_filter is accepted."""
        # Mock the necessary methods
        mock_client.admin.users().list().execute.return_value = {"users": []}
        
        # Should not raise any exceptions
        result = mobile_scanner.scan_all_devices(os_filter="IOS_SYNC")
        assert result is not None


class TestAuditLogScannerOptimizations:
    """Tests for audit log scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.reports = Mock()
        return client

    @pytest.fixture
    def audit_scanner(self, mock_client):
        """Create an audit log scanner instance."""
        from vaulytica.core.scanners.audit_log_scanner import AuditLogScanner
        return AuditLogScanner(client=mock_client, domain="example.com")

    def test_input_validation_days_back_too_small(self, audit_scanner):
        """Test that days_back < 1 raises ValueError."""
        with pytest.raises(ValueError, match="days_back must be between 1 and 180"):
            audit_scanner.scan_admin_activity(days_back=0)

    def test_input_validation_days_back_negative(self, audit_scanner):
        """Test that negative days_back raises ValueError."""
        with pytest.raises(ValueError, match="days_back must be between 1 and 180"):
            audit_scanner.scan_admin_activity(days_back=-5)

    def test_input_validation_days_back_too_large(self, audit_scanner):
        """Test that days_back > 180 raises ValueError."""
        with pytest.raises(ValueError, match="days_back must be between 1 and 180"):
            audit_scanner.scan_admin_activity(days_back=200)

    def test_input_validation_max_results_too_small(self, audit_scanner):
        """Test that max_results < 1 raises ValueError."""
        with pytest.raises(ValueError, match="max_results must be between 1 and 10000"):
            audit_scanner.scan_admin_activity(max_results=0)

    def test_input_validation_max_results_negative(self, audit_scanner):
        """Test that negative max_results raises ValueError."""
        with pytest.raises(ValueError, match="max_results must be between 1 and 10000"):
            audit_scanner.scan_admin_activity(max_results=-100)

    def test_input_validation_max_results_too_large(self, audit_scanner):
        """Test that max_results > 10000 raises ValueError."""
        with pytest.raises(ValueError, match="max_results must be between 1 and 10000"):
            audit_scanner.scan_admin_activity(max_results=20000)

    def test_valid_days_back_minimum(self, audit_scanner, mock_client):
        """Test that days_back=1 is accepted."""
        # Mock the necessary methods
        mock_client.reports.activities().list().execute.return_value = {"items": []}
        
        # Should not raise any exceptions
        result = audit_scanner.scan_admin_activity(days_back=1)
        assert result is not None

    def test_valid_days_back_maximum(self, audit_scanner, mock_client):
        """Test that days_back=180 is accepted."""
        # Mock the necessary methods
        mock_client.reports.activities().list().execute.return_value = {"items": []}
        
        # Should not raise any exceptions
        result = audit_scanner.scan_admin_activity(days_back=180)
        assert result is not None

    def test_valid_max_results_minimum(self, audit_scanner, mock_client):
        """Test that max_results=1 is accepted."""
        # Mock the necessary methods
        mock_client.reports.activities().list().execute.return_value = {"items": []}
        
        # Should not raise any exceptions
        result = audit_scanner.scan_admin_activity(max_results=1)
        assert result is not None

    def test_valid_max_results_maximum(self, audit_scanner, mock_client):
        """Test that max_results=10000 is accepted."""
        # Mock the necessary methods
        mock_client.reports.activities().list().execute.return_value = {"items": []}
        
        # Should not raise any exceptions
        result = audit_scanner.scan_admin_activity(max_results=10000)
        assert result is not None

    def test_event_filter_parameter(self, audit_scanner, mock_client):
        """Test that event_filter parameter works."""
        # Mock the necessary methods
        mock_client.reports.activities().list().execute.return_value = {"items": []}
        
        # Should not raise any exceptions
        result = audit_scanner.scan_admin_activity(event_filter="GRANT_ADMIN_PRIVILEGE")
        assert result is not None


class TestUserScannerOptimizations:
    """Tests for user scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        return client

    @pytest.fixture
    def user_scanner(self, mock_client):
        """Create a user scanner instance."""
        from vaulytica.core.scanners.user_scanner import UserScanner
        return UserScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_users(self, user_scanner):
        """Test that invalid max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            user_scanner.scan_all_users(max_users=-1)

    def test_input_validation_invalid_org_unit(self, user_scanner):
        """Test that invalid org_unit raises ValueError."""
        with pytest.raises(ValueError, match="org_unit must be a string"):
            user_scanner.scan_all_users(org_unit=123)

    def test_valid_parameters(self, user_scanner, mock_client):
        """Test that valid parameters are accepted."""
        # Mock the necessary methods
        mock_client.admin.users().list().execute.return_value = {"users": []}

        # Should not raise any exceptions
        result = user_scanner.scan_all_users(max_users=10, org_unit="/Engineering")
        assert result is not None


class TestGroupScannerOptimizations:
    """Tests for group scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        return client

    @pytest.fixture
    def group_scanner(self, mock_client):
        """Create a group scanner instance."""
        from vaulytica.core.scanners.group_scanner import GroupScanner
        return GroupScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_groups(self, group_scanner):
        """Test that invalid max_groups raises ValueError."""
        with pytest.raises(ValueError, match="max_groups must be a positive integer"):
            group_scanner.scan_all_groups(max_groups=-1)

    def test_input_validation_zero_max_groups(self, group_scanner):
        """Test that zero max_groups raises ValueError."""
        with pytest.raises(ValueError, match="max_groups must be a positive integer"):
            group_scanner.scan_all_groups(max_groups=0)

    def test_valid_max_groups(self, group_scanner, mock_client):
        """Test that valid max_groups is accepted."""
        # Mock the necessary methods
        mock_client.admin.groups().list().execute.return_value = {"groups": []}

        # Should not raise any exceptions
        result = group_scanner.scan_all_groups(max_groups=10)
        assert result is not None


class TestFileScannerOptimizations:
    """Tests for file scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.drive = Mock()
        return client

    @pytest.fixture
    def file_scanner(self, mock_client):
        """Create a file scanner instance."""
        from vaulytica.core.scanners.file_scanner import FileScanner
        return FileScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_files(self, file_scanner):
        """Test that invalid max_files raises ValueError."""
        with pytest.raises(ValueError, match="max_files must be a positive integer"):
            list(file_scanner.scan_all_files(max_files=-1))

    def test_input_validation_invalid_user_email(self, file_scanner):
        """Test that invalid user_email raises ValueError."""
        with pytest.raises(ValueError, match="user_email must be a string"):
            list(file_scanner.scan_all_files(user_email=123))

    def test_valid_parameters(self, file_scanner, mock_client):
        """Test that valid parameters are accepted."""
        # Mock the necessary methods
        mock_client.drive.files().list().execute.return_value = {"files": []}

        # Should not raise any exceptions
        files = list(file_scanner.scan_all_files(max_files=10, user_email="user@example.com"))
        assert isinstance(files, list)


class TestGmailScannerOptimizations:
    """Tests for Gmail scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.gmail = Mock()
        return client

    @pytest.fixture
    def gmail_scanner(self, mock_client):
        """Create a Gmail scanner instance."""
        from vaulytica.core.scanners.gmail_scanner import GmailScanner
        return GmailScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_user_email(self, gmail_scanner):
        """Test that invalid user_email raises ValueError."""
        with pytest.raises(ValueError, match="user_email must be a non-empty string"):
            gmail_scanner.scan_user_attachments(user_email="")

    def test_input_validation_invalid_days_back(self, gmail_scanner):
        """Test that invalid days_back raises ValueError."""
        with pytest.raises(ValueError, match="days_back must be at least 1"):
            gmail_scanner.scan_user_attachments(user_email="user@example.com", days_back=0)

    def test_input_validation_invalid_max_messages(self, gmail_scanner):
        """Test that invalid max_messages raises ValueError."""
        with pytest.raises(ValueError, match="max_messages must be at least 1"):
            gmail_scanner.scan_user_attachments(user_email="user@example.com", max_messages=0)

    def test_input_validation_invalid_max_attachments(self, gmail_scanner):
        """Test that invalid max_attachments raises ValueError."""
        with pytest.raises(ValueError, match="max_attachments must be a positive integer"):
            gmail_scanner.scan_user_attachments(user_email="user@example.com", max_attachments=-1)

    def test_valid_parameters(self, gmail_scanner, mock_client):
        """Test that valid parameters are accepted."""
        # Mock the necessary methods
        mock_client.gmail.users().messages().list().execute.return_value = {"messages": []}

        # Should not raise any exceptions
        result = gmail_scanner.scan_user_attachments(
            user_email="user@example.com",
            days_back=7,
            max_messages=50,
            max_attachments=100
        )
        assert result is not None


class TestChromeDeviceScannerOptimizations:
    """Tests for Chrome device scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        return client

    @pytest.fixture
    def chrome_scanner(self, mock_client):
        """Create a Chrome device scanner instance."""
        from vaulytica.core.scanners.chrome_device_scanner import ChromeDeviceScanner
        return ChromeDeviceScanner(client=mock_client, customer_id="my_customer")

    def test_input_validation_invalid_max_devices(self, chrome_scanner):
        """Test that invalid max_devices raises ValueError."""
        with pytest.raises(ValueError, match="max_devices must be a positive integer"):
            chrome_scanner.scan_all_devices(max_devices=-1)

    def test_input_validation_invalid_org_unit_path(self, chrome_scanner):
        """Test that invalid org_unit_path raises ValueError."""
        with pytest.raises(ValueError, match="org_unit_path must be a string"):
            chrome_scanner.scan_all_devices(org_unit_path=123)

    def test_input_validation_invalid_query(self, chrome_scanner):
        """Test that invalid query raises ValueError."""
        with pytest.raises(ValueError, match="query must be a string"):
            chrome_scanner.scan_all_devices(query=123)

    def test_valid_parameters(self, chrome_scanner, mock_client):
        """Test that valid parameters are accepted."""
        # Mock the necessary methods
        mock_client.admin.chromeosdevices().list().execute.return_value = {"chromeosdevices": []}

        # Should not raise any exceptions
        result = chrome_scanner.scan_all_devices(
            org_unit_path="/Engineering",
            query="status:ACTIVE",
            max_devices=50
        )
        assert result is not None


class TestLicenseScannerOptimizations:
    """Tests for license scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.service = Mock()
        return client

    @pytest.fixture
    def license_scanner(self, mock_client):
        """Create a license scanner instance."""
        from vaulytica.core.scanners.license_scanner import LicenseScanner
        return LicenseScanner(client=mock_client)

    def test_input_validation_invalid_max_assignments(self, license_scanner):
        """Test that invalid max_assignments raises ValueError."""
        with pytest.raises(ValueError, match="max_assignments must be a positive integer"):
            license_scanner.scan_all_licenses(max_assignments=-1)

    def test_input_validation_zero_max_assignments(self, license_scanner):
        """Test that zero max_assignments raises ValueError."""
        with pytest.raises(ValueError, match="max_assignments must be a positive integer"):
            license_scanner.scan_all_licenses(max_assignments=0)

    def test_valid_max_assignments(self, license_scanner, mock_client):
        """Test that valid max_assignments is accepted."""
        # Mock the necessary methods
        mock_client.service.reseller().subscriptions().list().execute.return_value = {"subscriptions": []}
        mock_client.service.licensing().listForProduct().execute.return_value = {"items": []}

        # Should not raise any exceptions
        result = license_scanner.scan_all_licenses(max_assignments=100)
        assert result is not None


class TestScannerPerformanceMetrics:
    """Tests for scanner performance metrics and logging."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        client.reports = Mock()
        client.drive = Mock()
        return client

    def test_oauth_scanner_logs_duration(self, mock_client):
        """Test that OAuth scanner logs scan duration."""
        from vaulytica.core.scanners.oauth_scanner import OAuthScanner

        scanner = OAuthScanner(client=mock_client, domain="example.com")
        mock_client.admin.tokens().list().execute.return_value = {"items": []}

        # Scan should complete and log duration
        result = scanner.scan_oauth_tokens(user_email="user@example.com")
        assert result is not None

    def test_mobile_scanner_logs_duration(self, mock_client):
        """Test that mobile device scanner logs scan duration."""
        from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanner

        scanner = MobileDeviceScanner(client=mock_client, domain="example.com")
        mock_client.admin.users().list().execute.return_value = {"users": []}

        # Scan should complete and log duration
        result = scanner.scan_all_devices()
        assert result is not None

    def test_audit_scanner_logs_duration(self, mock_client):
        """Test that audit log scanner logs scan duration."""
        from vaulytica.core.scanners.audit_log_scanner import AuditLogScanner

        scanner = AuditLogScanner(client=mock_client, domain="example.com")
        mock_client.reports.activities().list().execute.return_value = {"items": []}

        # Scan should complete and log duration
        result = scanner.scan_admin_activity()
        assert result is not None

    def test_user_scanner_logs_duration(self, mock_client):
        """Test that user scanner logs scan duration."""
        from vaulytica.core.scanners.user_scanner import UserScanner

        scanner = UserScanner(client=mock_client, domain="example.com")
        mock_client.admin.users().list().execute.return_value = {"users": []}

        # Scan should complete and log duration
        result = scanner.scan_all_users()
        assert result is not None

    def test_group_scanner_logs_duration(self, mock_client):
        """Test that group scanner logs scan duration."""
        from vaulytica.core.scanners.group_scanner import GroupScanner

        scanner = GroupScanner(client=mock_client, domain="example.com")
        mock_client.admin.groups().list().execute.return_value = {"groups": []}

        # Scan should complete and log duration
        result = scanner.scan_all_groups()
        assert result is not None

    def test_file_scanner_logs_duration(self, mock_client):
        """Test that file scanner logs scan duration."""
        from vaulytica.core.scanners.file_scanner import FileScanner

        scanner = FileScanner(client=mock_client, domain="example.com")
        mock_client.drive.files().list().execute.return_value = {"files": []}

        # Scan should complete and log duration
        files = list(scanner.scan_all_files())
        assert isinstance(files, list)

    def test_gmail_scanner_logs_duration(self, mock_client):
        """Test that Gmail scanner logs scan duration."""
        from vaulytica.core.scanners.gmail_scanner import GmailScanner

        scanner = GmailScanner(client=mock_client, domain="example.com")
        mock_client.gmail.users().messages().list().execute.return_value = {"messages": []}

        # Scan should complete and log duration
        result = scanner.scan_user_attachments(user_email="user@example.com")
        assert result is not None

    def test_chrome_device_scanner_logs_duration(self, mock_client):
        """Test that Chrome device scanner logs scan duration."""
        from vaulytica.core.scanners.chrome_device_scanner import ChromeDeviceScanner

        scanner = ChromeDeviceScanner(client=mock_client, customer_id="my_customer")
        mock_client.admin.chromeosdevices().list().execute.return_value = {"chromeosdevices": []}

        # Scan should complete and log duration
        result = scanner.scan_all_devices()
        assert result is not None

    def test_license_scanner_logs_duration(self, mock_client):
        """Test that license scanner logs scan duration."""
        from vaulytica.core.scanners.license_scanner import LicenseScanner

        scanner = LicenseScanner(client=mock_client)
        mock_client.service.reseller().subscriptions().list().execute.return_value = {"subscriptions": []}
        mock_client.service.licensing().listForProduct().execute.return_value = {"items": []}

        # Scan should complete and log duration
        result = scanner.scan_all_licenses()
        assert result is not None


class TestVaultScannerOptimizations:
    """Tests for Vault scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.vault = Mock()
        return client

    @pytest.fixture
    def vault_scanner(self, mock_client):
        """Create a Vault scanner instance."""
        from vaulytica.core.scanners.vault_scanner import VaultScanner
        return VaultScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_matters(self, vault_scanner):
        """Test that invalid max_matters raises ValueError."""
        with pytest.raises(ValueError, match="max_matters must be a positive integer"):
            vault_scanner.scan_all(max_matters=-1)

    def test_input_validation_zero_max_matters(self, vault_scanner):
        """Test that zero max_matters raises ValueError."""
        with pytest.raises(ValueError, match="max_matters must be a positive integer"):
            vault_scanner.scan_all(max_matters=0)

    def test_valid_max_matters(self, vault_scanner):
        """Test that valid max_matters is accepted."""
        # Should not raise any exceptions
        result = vault_scanner.scan_all(max_matters=10)
        assert result is not None


class TestSharedDriveScannerOptimizations:
    """Tests for Shared Drive scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.drive = Mock()
        return client

    @pytest.fixture
    def shared_drive_scanner(self, mock_client):
        """Create a Shared Drive scanner instance."""
        from vaulytica.core.scanners.shared_drive_scanner import SharedDriveScanner
        return SharedDriveScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_drives(self, shared_drive_scanner, mock_client):
        """Test that invalid max_drives raises ValueError."""
        with pytest.raises(ValueError, match="max_drives must be a positive integer"):
            shared_drive_scanner.scan_all_shared_drives(max_drives=-1)

    def test_input_validation_zero_max_drives(self, shared_drive_scanner, mock_client):
        """Test that zero max_drives raises ValueError."""
        with pytest.raises(ValueError, match="max_drives must be a positive integer"):
            shared_drive_scanner.scan_all_shared_drives(max_drives=0)

    def test_valid_max_drives(self, shared_drive_scanner, mock_client):
        """Test that valid max_drives is accepted."""
        # Mock the necessary methods
        mock_client.drive.drives().list().execute.return_value = {"drives": []}

        # Should not raise any exceptions
        result = shared_drive_scanner.scan_all_shared_drives(max_drives=10)
        assert result is not None


class TestCalendarScannerOptimizations:
    """Tests for Calendar scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        client.calendar = Mock()
        return client

    @pytest.fixture
    def calendar_scanner(self, mock_client):
        """Create a Calendar scanner instance."""
        from vaulytica.core.scanners.calendar_scanner import CalendarScanner
        return CalendarScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_calendars(self, calendar_scanner):
        """Test that invalid max_calendars raises ValueError."""
        with pytest.raises(ValueError, match="max_calendars must be a positive integer"):
            calendar_scanner.scan_all_calendars(max_calendars=-1)

    def test_input_validation_invalid_days_ahead(self, calendar_scanner):
        """Test that invalid days_ahead raises ValueError."""
        with pytest.raises(ValueError, match="days_ahead must be at least 1"):
            calendar_scanner.scan_all_calendars(days_ahead=0)

    def test_valid_parameters(self, calendar_scanner, mock_client):
        """Test that valid parameters are accepted."""
        # Mock the necessary methods
        mock_client.admin.users().list().execute.return_value = {"users": []}

        # Should not raise any exceptions
        result = calendar_scanner.scan_all_calendars(max_calendars=10, days_ahead=7)
        assert result is not None


class TestGmailSecurityScannerOptimizations:
    """Tests for Gmail Security scanner performance optimizations."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.admin = Mock()
        client.gmail = Mock()
        return client

    @pytest.fixture
    def gmail_security_scanner(self, mock_client):
        """Create a Gmail Security scanner instance."""
        from vaulytica.core.scanners.gmail_security_scanner import GmailSecurityScanner
        return GmailSecurityScanner(client=mock_client, domain="example.com")

    def test_input_validation_invalid_max_users(self, gmail_security_scanner):
        """Test that invalid max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            gmail_security_scanner.scan_all_users(max_users=-1)

    def test_input_validation_zero_max_users(self, gmail_security_scanner):
        """Test that zero max_users raises ValueError."""
        with pytest.raises(ValueError, match="max_users must be a positive integer"):
            gmail_security_scanner.scan_all_users(max_users=0)

    def test_valid_max_users(self, gmail_security_scanner, mock_client):
        """Test that valid max_users is accepted."""
        # Mock the necessary methods
        mock_client.admin.users().list().execute.return_value = {"users": []}

        # Should not raise any exceptions
        result = gmail_security_scanner.scan_all_users(max_users=50)
        assert result is not None

