"""Tests for mobile device scanner."""

import pytest
from unittest.mock import Mock
from datetime import datetime, timedelta, timezone
from vaulytica.core.scanners.mobile_device_scanner import (
    MobileDeviceScanner,
    MobileDevice,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.admin = Mock()
    return client


@pytest.fixture
def mobile_device_scanner(mock_client):
    """Create a MobileDeviceScanner instance."""
    return MobileDeviceScanner(mock_client, "example.com", inactive_days=90)


class TestMobileDeviceScanner:
    """Tests for MobileDeviceScanner class."""

    def test_init(self, mobile_device_scanner):
        """Test scanner initialization."""
        assert mobile_device_scanner.domain == "example.com"
        assert mobile_device_scanner.inactive_days == 90

    def test_list_all_users(self, mobile_device_scanner, mock_client):
        """Test listing all users."""
        # Mock API response
        mock_client.admin.users().list().execute.return_value = {
            "users": [
                {"primaryEmail": "user1@example.com"},
                {"primaryEmail": "user2@example.com"},
            ]
        }

        users = mobile_device_scanner._list_all_users()

        assert len(users) == 2
        assert users[0]["primaryEmail"] == "user1@example.com"

    def test_scan_user_devices(self, mobile_device_scanner, mock_client):
        """Test scanning devices for a user."""
        # Mock API response
        mock_client.admin.mobiledevices().list().execute.return_value = {
            "mobiledevices": [
                {
                    "deviceId": "device1",
                    "resourceId": "res1",
                    "model": "iPhone 12",
                    "os": "IOS",
                    "status": "APPROVED",
                    "encryptionStatus": "ENCRYPTED",
                    "passwordStatus": "PASSWORD_SET",
                }
            ]
        }

        devices = mobile_device_scanner._scan_user_devices("user@example.com")

        assert len(devices) == 1
        assert devices[0].device_id == "device1"
        assert devices[0].model == "iPhone 12"

    def test_parse_device(self, mobile_device_scanner):
        """Test parsing a device from API response."""
        device_data = {
            "deviceId": "device1",
            "resourceId": "res1",
            "model": "Pixel 6",
            "os": "ANDROID",
            "osVersion": "12",
            "type": "ANDROID",
            "status": "APPROVED",
            "encryptionStatus": "ENCRYPTED",
            "passwordStatus": "PASSWORD_SET",
            "compromisedStatus": "NOT_COMPROMISED",
        }

        device = mobile_device_scanner._parse_device(device_data, "user@example.com")

        assert device.device_id == "device1"
        assert device.model == "Pixel 6"
        assert device.os == "ANDROID"
        assert device.is_encrypted is True
        assert device.is_password_protected is True
        assert device.is_compromised is False

    def test_calculate_device_risk_score_compromised(self, mobile_device_scanner):
        """Test risk score calculation for compromised device."""
        device = MobileDevice(
            device_id="device1",
            resource_id="res1",
            email="user@example.com",
            is_compromised=True,
            is_encrypted=True,
            is_password_protected=True,
            last_sync=datetime.now(timezone.utc) - timedelta(days=1),  # Recent sync
        )

        score = mobile_device_scanner._calculate_device_risk_score(device)

        assert score == 50  # Compromised = 50

    def test_calculate_device_risk_score_unencrypted(self, mobile_device_scanner):
        """Test risk score calculation for unencrypted device."""
        device = MobileDevice(
            device_id="device1",
            resource_id="res1",
            email="user@example.com",
            is_compromised=False,
            is_encrypted=False,
            is_password_protected=True,
            last_sync=datetime.now(timezone.utc) - timedelta(days=1),  # Recent sync
        )

        score = mobile_device_scanner._calculate_device_risk_score(device)

        assert score == 20  # Unencrypted = 20

    def test_calculate_device_risk_score_no_password(self, mobile_device_scanner):
        """Test risk score calculation for device without password."""
        device = MobileDevice(
            device_id="device1",
            resource_id="res1",
            email="user@example.com",
            is_compromised=False,
            is_encrypted=True,
            is_password_protected=False,
            last_sync=datetime.now(timezone.utc) - timedelta(days=1),  # Recent sync
        )

        score = mobile_device_scanner._calculate_device_risk_score(device)

        assert score == 15  # No password = 15

    def test_calculate_device_risk_score_combined(self, mobile_device_scanner):
        """Test risk score calculation with multiple issues."""
        device = MobileDevice(
            device_id="device1",
            resource_id="res1",
            email="user@example.com",
            is_compromised=True,
            is_encrypted=False,
            is_password_protected=False,
            status="BLOCKED",
            last_sync=datetime.now(timezone.utc) - timedelta(days=1),  # Recent sync
        )

        score = mobile_device_scanner._calculate_device_risk_score(device)

        assert score == 95  # 50 + 20 + 15 + 10 = 95

    def test_is_device_inactive(self, mobile_device_scanner):
        """Test checking if device is inactive."""
        # Device with recent sync
        device_active = MobileDevice(
            device_id="device1",
            resource_id="res1",
            email="user@example.com",
            last_sync=datetime.now(timezone.utc) - timedelta(days=30),
        )

        assert mobile_device_scanner._is_device_inactive(device_active) is False

        # Device with old sync
        device_inactive = MobileDevice(
            device_id="device2",
            resource_id="res2",
            email="user@example.com",
            last_sync=datetime.now(timezone.utc) - timedelta(days=100),
        )

        assert mobile_device_scanner._is_device_inactive(device_inactive) is True

    def test_generate_issues_compromised(self, mobile_device_scanner):
        """Test issue generation for compromised device."""
        from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanResult

        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="device1",
                resource_id="res1",
                email="user@example.com",
                model="iPhone 12",
                is_compromised=True,
                is_encrypted=True,
                is_password_protected=True,
                risk_score=50,
            )
        ]

        issues = mobile_device_scanner._generate_issues(result)

        compromised_issues = [i for i in issues if i["type"] == "compromised_device"]
        assert len(compromised_issues) == 1
        assert compromised_issues[0]["severity"] == "critical"

    def test_generate_issues_unencrypted(self, mobile_device_scanner):
        """Test issue generation for unencrypted device."""
        from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanResult

        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="device1",
                resource_id="res1",
                email="user@example.com",
                model="Pixel 6",
                is_compromised=False,
                is_encrypted=False,
                is_password_protected=True,
                risk_score=20,
            )
        ]

        issues = mobile_device_scanner._generate_issues(result)

        unencrypted_issues = [i for i in issues if i["type"] == "unencrypted_device"]
        assert len(unencrypted_issues) == 1
        assert unencrypted_issues[0]["severity"] == "high"

    def test_generate_issues_no_password(self, mobile_device_scanner):
        """Test issue generation for device without password."""
        from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanResult

        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="device1",
                resource_id="res1",
                email="user@example.com",
                model="Galaxy S21",
                is_compromised=False,
                is_encrypted=True,
                is_password_protected=False,
                risk_score=15,
            )
        ]

        issues = mobile_device_scanner._generate_issues(result)

        no_password_issues = [i for i in issues if i["type"] == "no_password_device"]
        assert len(no_password_issues) == 1
        assert no_password_issues[0]["severity"] == "medium"  # Updated: no_password_device is now classified as "medium" severity

    def test_generate_issues_inactive(self, mobile_device_scanner):
        """Test issue generation for inactive device."""
        from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanResult

        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="device1",
                resource_id="res1",
                email="user@example.com",
                model="iPhone 11",
                is_compromised=False,
                is_encrypted=True,
                is_password_protected=True,
                last_sync=datetime.now(timezone.utc) - timedelta(days=100),
            )
        ]

        issues = mobile_device_scanner._generate_issues(result)

        inactive_issues = [i for i in issues if i["type"] == "inactive_device"]
        assert len(inactive_issues) == 1
        assert inactive_issues[0]["severity"] == "low"  # Updated: inactive_device is now classified as "low" severity

    def test_calculate_statistics(self, mobile_device_scanner):
        """Test statistics calculation."""
        from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanResult

        result = MobileDeviceScanResult(
            total_devices=10,
            android_devices=6,
            ios_devices=4,
            approved_devices=8,
            blocked_devices=2,
            compromised_devices=1,
            unencrypted_devices=2,
            no_password_devices=1,
            inactive_devices=3,
        )
        result.issues = [{"type": "test"}] * 5

        stats = mobile_device_scanner._calculate_statistics(result)

        assert stats["total_devices"] == 10
        assert stats["android_devices"] == 6
        assert stats["ios_devices"] == 4
        assert stats["compromised_devices"] == 1
        assert stats["total_issues"] == 5

    def test_mobile_device_dataclass(self):
        """Test MobileDevice dataclass."""
        device = MobileDevice(
            device_id="device1",
            resource_id="res1",
            email="user@example.com",
            model="iPhone 13",
            os="IOS",
            status="APPROVED",
        )

        assert device.device_id == "device1"
        assert device.model == "iPhone 13"
        assert device.os == "IOS"
        assert device.risk_score == 0

