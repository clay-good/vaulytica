"""Tests for Chrome OS device scanner."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from vaulytica.core.scanners.chrome_device_scanner import (
    ChromeDevice,
    ChromeDeviceScanResult,
    ChromeDeviceScanner,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.service = Mock()
    return client


@pytest.fixture
def chrome_scanner(mock_client):
    """Create a ChromeDeviceScanner instance."""
    return ChromeDeviceScanner(client=mock_client, inactive_days=90)


@pytest.fixture
def sample_device_data():
    """Sample Chrome device data from API."""
    return {
        "deviceId": "device-123",
        "serialNumber": "ABC123XYZ",
        "assetId": "ASSET-001",
        "annotatedLocation": "Building A, Floor 2",
        "annotatedUser": "john.doe@company.com",
        "lastSync": "2024-10-25T10:30:00.000Z",
        "lastEnrollmentTime": "2024-01-15T08:00:00.000Z",
        "model": "HP Chromebook 14",
        "osVersion": "120.0.6099.315",
        "platformVersion": "15437.64.0",
        "firmwareVersion": "Google_Nami.10775.404.0",
        "status": "ACTIVE",
        "bootMode": "Verified",
        "recentUsers": [
            {"email": "john.doe@company.com", "type": "USER_TYPE_MANAGED"}
        ],
        "autoUpdateExpiration": "2025-06-30T00:00:00.000Z",
        "ethernetMacAddress": "00:1A:2B:3C:4D:5E",
        "macAddress": "00:1A:2B:3C:4D:5F",
        "orgUnitPath": "/Engineering",
    }


class TestChromeDevice:
    """Tests for ChromeDevice dataclass."""

    def test_chrome_device_creation(self, sample_device_data):
        """Test creating a ChromeDevice from API data."""
        device = ChromeDevice(
            device_id=sample_device_data["deviceId"],
            serial_number=sample_device_data["serialNumber"],
            model=sample_device_data["model"],
            status=sample_device_data["status"],
            os_version=sample_device_data["osVersion"],
            last_sync=datetime.fromisoformat(
                sample_device_data["lastSync"].replace("Z", "+00:00")
            ),
        )

        assert device.device_id == "device-123"
        assert device.serial_number == "ABC123XYZ"
        assert device.model == "HP Chromebook 14"
        assert device.status == "ACTIVE"

    def test_auto_update_expired(self):
        """Test auto-update expiration detection."""
        from datetime import timezone

        # Expired device
        expired_device = ChromeDevice(
            device_id="device-1",
            serial_number="ABC123",
            model="Old Chromebook",
            status="ACTIVE",
            os_version="100.0.0.0",
            last_sync=datetime.now(timezone.utc),
            auto_update_expiration=datetime.now(timezone.utc) - timedelta(days=30),
            is_auto_update_expired=True,
        )
        assert expired_device.is_auto_update_expired is True

        # Not expired device
        active_device = ChromeDevice(
            device_id="device-2",
            serial_number="XYZ789",
            model="New Chromebook",
            status="ACTIVE",
            os_version="120.0.0.0",
            last_sync=datetime.now(timezone.utc),
            auto_update_expiration=datetime.now(timezone.utc) + timedelta(days=365),
            is_auto_update_expired=False,
        )
        assert active_device.is_auto_update_expired is False


class TestChromeDeviceScanner:
    """Tests for ChromeDeviceScanner."""

    def test_scanner_initialization(self, chrome_scanner):
        """Test scanner initialization."""
        assert chrome_scanner.inactive_days == 90
        assert chrome_scanner.client is not None

    @patch("vaulytica.core.scanners.chrome_device_scanner.ChromeDeviceScanner._list_all_devices")
    def test_scan_all_devices(self, mock_list_devices, chrome_scanner, sample_device_data):
        """Test scanning all Chrome devices."""
        mock_list_devices.return_value = [sample_device_data]

        result = chrome_scanner.scan_all_devices()

        assert isinstance(result, ChromeDeviceScanResult)
        assert result.total_devices == 1
        assert result.active_devices == 1
        assert len(result.devices) == 1

    @patch("vaulytica.core.scanners.chrome_device_scanner.ChromeDeviceScanner._list_all_devices")
    def test_scan_with_org_unit_filter(self, mock_list_devices, chrome_scanner, sample_device_data):
        """Test scanning with organizational unit filter."""
        mock_list_devices.return_value = [sample_device_data]

        result = chrome_scanner.scan_all_devices(org_unit_path="/Engineering")

        # Check that the method was called with the correct arguments
        assert mock_list_devices.called
        assert result.total_devices == 1

    def test_parse_device(self, chrome_scanner, sample_device_data):
        """Test parsing device data from API."""
        device = chrome_scanner._parse_device(sample_device_data)

        assert device.device_id == "device-123"
        assert device.serial_number == "ABC123XYZ"
        assert device.model == "HP Chromebook 14"
        assert device.status == "ACTIVE"
        assert device.boot_mode == "Verified"
        assert device.annotated_user == "john.doe@company.com"

    def test_calculate_risk_score_auto_update_expired(self, chrome_scanner):
        """Test risk score calculation for expired auto-update."""
        from datetime import timezone

        device = ChromeDevice(
            device_id="device-1",
            serial_number="ABC123",
            model="Old Chromebook",
            status="ACTIVE",
            os_version="100.0.0.0",
            last_sync=datetime.now(timezone.utc),
            auto_update_expiration=datetime.now(timezone.utc) - timedelta(days=30),
            is_auto_update_expired=True,
        )

        risk_score = chrome_scanner._calculate_risk_score(device)

        assert risk_score >= 40  # Auto-update expired adds 40 points
        assert "Auto-update expired" in device.risk_factors

    def test_calculate_risk_score_developer_mode(self, chrome_scanner):
        """Test risk score calculation for developer mode."""
        from datetime import timezone

        device = ChromeDevice(
            device_id="device-1",
            serial_number="ABC123",
            model="Chromebook",
            status="ACTIVE",
            os_version="120.0.0.0",
            last_sync=datetime.now(timezone.utc),
            boot_mode="Dev",
        )

        risk_score = chrome_scanner._calculate_risk_score(device)

        assert risk_score >= 30  # Developer mode adds 30 points
        assert "Developer mode enabled" in device.risk_factors

    def test_calculate_risk_score_inactive_device(self, chrome_scanner):
        """Test risk score calculation for inactive device."""
        from datetime import timezone

        device = ChromeDevice(
            device_id="device-1",
            serial_number="ABC123",
            model="Chromebook",
            status="ACTIVE",
            os_version="120.0.0.0",
            last_sync=datetime.now(timezone.utc) - timedelta(days=120),  # 120 days ago
        )

        risk_score = chrome_scanner._calculate_risk_score(device)

        assert risk_score >= 10  # Inactive device adds 10 points
        assert "Inactive" in " ".join(device.risk_factors)

    def test_calculate_risk_score_disabled_device(self, chrome_scanner):
        """Test risk score calculation for disabled device."""
        from datetime import timezone

        device = ChromeDevice(
            device_id="device-1",
            serial_number="ABC123",
            model="Chromebook",
            status="DISABLED",
            os_version="120.0.0.0",
            last_sync=datetime.now(timezone.utc),
        )

        risk_score = chrome_scanner._calculate_risk_score(device)

        assert risk_score >= 20  # Disabled device adds 20 points
        assert "disabled" in " ".join(device.risk_factors).lower()

    def test_generate_issues(self, chrome_scanner):
        """Test issue generation for high-risk devices."""
        from datetime import timezone
        from vaulytica.core.scanners.chrome_device_scanner import ChromeDeviceScanResult

        device = ChromeDevice(
            device_id="device-1",
            serial_number="ABC123",
            model="Old Chromebook",
            status="ACTIVE",
            os_version="100.0.0.0",
            last_sync=datetime.now(timezone.utc),
            auto_update_expiration=datetime.now(timezone.utc) - timedelta(days=30),
            boot_mode="Dev",
            annotated_user="john.doe@company.com",
            risk_score=70,
            risk_factors=["Auto-update expired", "Developer mode enabled"],
            is_auto_update_expired=True,
        )

        # Create a scan result with the device
        result = ChromeDeviceScanResult(
            total_devices=1,
            active_devices=1,
            devices=[device],
            dev_mode_devices=1,
            auto_update_expired=1,
        )

        issues = chrome_scanner._generate_issues(result)

        assert len(issues) >= 2  # At least 2 issues
        assert any("Auto-update expired" in issue["description"] for issue in issues)
        assert any("developer mode" in issue["description"].lower() for issue in issues)

    @patch("vaulytica.core.scanners.chrome_device_scanner.ChromeDeviceScanner._list_all_devices")
    def test_scan_result_statistics(self, mock_list_devices, chrome_scanner):
        """Test scan result statistics calculation."""
        from datetime import timezone

        # Convert datetime to milliseconds timestamp (as Google API returns)
        now = datetime.now(timezone.utc)
        future_date = now + timedelta(days=365)
        past_date = now - timedelta(days=30)
        old_sync = now - timedelta(days=120)

        devices_data = [
            {
                "deviceId": "device-1",
                "serialNumber": "ABC123",
                "status": "ACTIVE",
                "bootMode": "Verified",
                "lastSync": now.isoformat(),
                "autoUpdateExpiration": str(int(future_date.timestamp() * 1000)),
            },
            {
                "deviceId": "device-2",
                "serialNumber": "XYZ789",
                "status": "ACTIVE",
                "bootMode": "Dev",
                "lastSync": now.isoformat(),
                "autoUpdateExpiration": str(int(past_date.timestamp() * 1000)),
            },
            {
                "deviceId": "device-3",
                "serialNumber": "DEF456",
                "status": "DISABLED",
                "bootMode": "Verified",
                "lastSync": old_sync.isoformat(),
                "autoUpdateExpiration": str(int(future_date.timestamp() * 1000)),
            },
        ]

        mock_list_devices.return_value = devices_data

        result = chrome_scanner.scan_all_devices()

        assert result.total_devices == 3
        assert result.active_devices == 2
        assert result.disabled_devices == 1
        assert result.dev_mode_devices >= 1
        assert result.auto_update_expired >= 1
        assert result.inactive_devices >= 1

