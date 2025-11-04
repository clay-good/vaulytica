"""Tests for enhanced mobile device scanner security features."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

from vaulytica.core.scanners.mobile_device_scanner import (
    MobileDeviceScanner,
    MobileDevice,
    MobileDeviceScanResult,
)


class TestEnhancedMobileDeviceScanner:
    """Tests for enhanced mobile device scanner security features."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        return client

    @pytest.fixture
    def mobile_scanner(self, mock_client):
        """Create a mobile device scanner instance."""
        return MobileDeviceScanner(client=mock_client, domain="example.com", inactive_days=90)

    def test_detect_developer_mode(self, mobile_scanner):
        """Test detection of developer mode on Android devices."""
        device = MobileDevice(
            device_id="dev-123",
            resource_id="res-123",
            email="user@example.com",
            model="Pixel 7",
            os="ANDROID",
            os_version="13.0",
            has_developer_mode=True,
        )

        risk_score = mobile_scanner._calculate_device_risk_score(device)

        assert risk_score >= 25
        assert any("developer mode" in rf.lower() for rf in device.risk_factors)

    def test_detect_usb_debugging(self, mobile_scanner):
        """Test detection of USB debugging on Android devices."""
        device = MobileDevice(
            device_id="usb-123",
            resource_id="res-123",
            email="user@example.com",
            model="Samsung Galaxy",
            os="ANDROID",
            os_version="12.0",
            has_usb_debugging=True,
        )

        risk_score = mobile_scanner._calculate_device_risk_score(device)

        assert risk_score >= 20
        assert any("usb debugging" in rf.lower() for rf in device.risk_factors)

    def test_detect_unknown_sources(self, mobile_scanner):
        """Test detection of unknown sources enabled on Android."""
        device = MobileDevice(
            device_id="unk-123",
            resource_id="res-123",
            email="user@example.com",
            model="OnePlus 9",
            os="ANDROID",
            os_version="11.0",
            has_unknown_sources=True,
        )

        risk_score = mobile_scanner._calculate_device_risk_score(device)

        assert risk_score >= 20
        assert any("unknown sources" in rf.lower() for rf in device.risk_factors)

    def test_detect_outdated_android_os(self, mobile_scanner):
        """Test detection of outdated Android OS."""
        assert mobile_scanner._is_os_outdated("ANDROID", "10.0") is True
        assert mobile_scanner._is_os_outdated("ANDROID", "9.0") is True
        assert mobile_scanner._is_os_outdated("ANDROID", "11.0") is False
        assert mobile_scanner._is_os_outdated("ANDROID", "13.0") is False

    def test_detect_outdated_ios(self, mobile_scanner):
        """Test detection of outdated iOS."""
        assert mobile_scanner._is_os_outdated("IOS", "15.0") is True
        assert mobile_scanner._is_os_outdated("IOS", "14.0") is True
        assert mobile_scanner._is_os_outdated("IOS", "16.0") is False
        assert mobile_scanner._is_os_outdated("IOS", "17.0") is False

    def test_outdated_os_increases_risk(self, mobile_scanner):
        """Test that outdated OS increases risk score."""
        device = MobileDevice(
            device_id="old-123",
            resource_id="res-123",
            email="user@example.com",
            model="iPhone 8",
            os="IOS",
            os_version="14.0",
            has_outdated_os=True,
        )

        risk_score = mobile_scanner._calculate_device_risk_score(device)

        assert risk_score >= 15
        assert any("outdated" in rf.lower() for rf in device.risk_factors)

    def test_non_compliant_device(self, mobile_scanner):
        """Test detection of non-compliant devices."""
        device = MobileDevice(
            device_id="nc-123",
            resource_id="res-123",
            email="user@example.com",
            model="Pixel 6",
            os="ANDROID",
            os_version="12.0",
            compliance_state="NON_COMPLIANT",
        )

        risk_score = mobile_scanner._calculate_device_risk_score(device)

        assert risk_score >= 15
        assert any("non-compliant" in rf.lower() for rf in device.risk_factors)

    def test_supervised_ios_reduces_risk(self, mobile_scanner):
        """Test that supervised iOS devices have lower risk."""
        supervised = MobileDevice(
            device_id="sup-123",
            resource_id="res-123",
            email="user@example.com",
            model="iPhone 13",
            os="IOS",
            os_version="16.0",
            is_supervised=True,
            is_encrypted=False,  # Add some risk
        )

        unsupervised = MobileDevice(
            device_id="unsup-123",
            resource_id="res-123",
            email="user@example.com",
            model="iPhone 13",
            os="IOS",
            os_version="16.0",
            is_supervised=False,
            is_encrypted=False,  # Same risk
        )

        supervised_risk = mobile_scanner._calculate_device_risk_score(supervised)
        unsupervised_risk = mobile_scanner._calculate_device_risk_score(unsupervised)

        assert supervised_risk < unsupervised_risk

    def test_compromised_device_critical_risk(self, mobile_scanner):
        """Test that compromised devices get critical risk score."""
        device = MobileDevice(
            device_id="comp-123",
            resource_id="res-123",
            email="user@example.com",
            model="Rooted Device",
            os="ANDROID",
            os_version="12.0",
            is_compromised=True,
        )

        risk_score = mobile_scanner._calculate_device_risk_score(device)

        assert risk_score >= 50
        assert any("compromised" in rf.lower() or "rooted" in rf.lower() or "jailbroken" in rf.lower() for rf in device.risk_factors)

    def test_multiple_risk_factors_compound(self, mobile_scanner):
        """Test that multiple risk factors compound."""
        device = MobileDevice(
            device_id="multi-123",
            resource_id="res-123",
            email="user@example.com",
            model="Risky Device",
            os="ANDROID",
            os_version="10.0",
            has_developer_mode=True,
            has_usb_debugging=True,
            has_unknown_sources=True,
            is_encrypted=False,
            is_password_protected=False,
            has_outdated_os=True,
        )

        risk_score = mobile_scanner._calculate_device_risk_score(device)

        assert risk_score >= 80  # Should be very high risk
        assert len(device.risk_factors) >= 5

    def test_generate_developer_mode_issue(self, mobile_scanner):
        """Test generation of developer mode security issue."""
        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="dev-123",
                resource_id="res-123",
                email="user@example.com",
                model="Pixel 7",
                os="ANDROID",
                os_version="13.0",
                has_developer_mode=True,
                risk_score=75,
            )
        ]

        issues = mobile_scanner._generate_issues(result)

        dev_issues = [i for i in issues if i["type"] == "developer_mode_enabled"]
        assert len(dev_issues) == 1
        assert dev_issues[0]["severity"] == "high"

    def test_generate_usb_debugging_issue(self, mobile_scanner):
        """Test generation of USB debugging security issue."""
        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="usb-123",
                resource_id="res-123",
                email="user@example.com",
                model="Samsung",
                os="ANDROID",
                os_version="12.0",
                has_usb_debugging=True,
                risk_score=70,
            )
        ]

        issues = mobile_scanner._generate_issues(result)

        usb_issues = [i for i in issues if i["type"] == "usb_debugging_enabled"]
        assert len(usb_issues) == 1
        assert usb_issues[0]["severity"] == "high"

    def test_generate_unknown_sources_issue(self, mobile_scanner):
        """Test generation of unknown sources security issue."""
        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="unk-123",
                resource_id="res-123",
                email="user@example.com",
                model="OnePlus",
                os="ANDROID",
                os_version="11.0",
                has_unknown_sources=True,
                risk_score=65,
            )
        ]

        issues = mobile_scanner._generate_issues(result)

        unk_issues = [i for i in issues if i["type"] == "unknown_sources_enabled"]
        assert len(unk_issues) == 1
        assert unk_issues[0]["severity"] == "high"

    def test_generate_outdated_os_issue(self, mobile_scanner):
        """Test generation of outdated OS security issue."""
        result = MobileDeviceScanResult()
        result.devices = [
            MobileDevice(
                device_id="old-123",
                resource_id="res-123",
                email="user@example.com",
                model="iPhone 8",
                os="IOS",
                os_version="14.0",
                has_outdated_os=True,
                risk_score=60,
            )
        ]

        issues = mobile_scanner._generate_issues(result)

        old_issues = [i for i in issues if i["type"] == "outdated_os"]
        assert len(old_issues) == 1
        assert old_issues[0]["severity"] == "medium"

    def test_generate_recommendations(self, mobile_scanner):
        """Test generation of security recommendations."""
        result = MobileDeviceScanResult()
        result.total_devices = 50
        result.high_risk_devices = 10
        result.compromised_devices = 2
        result.unencrypted_devices = 8
        result.developer_mode_devices = 5
        result.outdated_os_devices = 15
        result.inactive_devices = 25

        recommendations = mobile_scanner._generate_recommendations(result)

        assert len(recommendations) >= 4
        # Should recommend MDM
        assert any("management" in r["title"].lower() for r in recommendations)
        # Should recommend blocking compromised devices
        assert any("compromised" in r["title"].lower() for r in recommendations)
        # Should recommend enforcing encryption
        assert any("encryption" in r["title"].lower() for r in recommendations)
        # Should recommend disabling developer mode
        assert any("developer" in r["title"].lower() for r in recommendations)

    def test_enhanced_statistics(self, mobile_scanner):
        """Test that enhanced statistics are calculated correctly."""
        result = MobileDeviceScanResult()
        result.total_devices = 100
        result.outdated_os_devices = 20
        result.developer_mode_devices = 5
        result.usb_debugging_devices = 3
        result.unknown_sources_devices = 4
        result.non_compliant_devices = 10
        result.high_risk_devices = 15

        stats = mobile_scanner._calculate_statistics(result)

        assert stats["total_devices"] == 100
        assert stats["outdated_os_devices"] == 20
        assert stats["developer_mode_devices"] == 5
        assert stats["usb_debugging_devices"] == 3
        assert stats["unknown_sources_devices"] == 4
        assert stats["non_compliant_devices"] == 10
        assert stats["high_risk_devices"] == 15

