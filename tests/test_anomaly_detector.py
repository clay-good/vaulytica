"""Tests for anomaly detector."""

import pytest
from datetime import datetime, timedelta, timezone
from vaulytica.core.detectors.anomaly_detector import (
    AnomalyDetector,
    Anomaly,
)
from vaulytica.core.scanners.audit_log_scanner import AuditEvent


@pytest.fixture
def anomaly_detector():
    """Create an AnomalyDetector instance."""
    return AnomalyDetector("example.com")


class TestAnomalyDetector:
    """Tests for AnomalyDetector class."""

    def test_init(self, anomaly_detector):
        """Test detector initialization."""
        assert anomaly_detector.domain == "example.com"

    def test_detect_unusual_login_location(self, anomaly_detector):
        """Test detecting unusual login locations."""
        # Create events from multiple countries
        events = [
            AuditEvent(
                event_id="1",
                event_type="login",
                event_name="login_success",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"login_country": "US"},
            ),
            AuditEvent(
                event_id="2",
                event_type="login",
                event_name="login_success",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"login_country": "CN"},
            ),
            AuditEvent(
                event_id="3",
                event_type="login",
                event_name="login_success",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"login_country": "RU"},
            ),
        ]

        anomalies = anomaly_detector._detect_unusual_login_location(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "unusual_login_location"
        assert anomalies[0].severity == "high"
        assert "3 different countries" in anomalies[0].description

    def test_detect_unusual_access_time(self, anomaly_detector):
        """Test detecting unusual access times."""
        # Create events outside business hours
        events = []
        base_time = datetime.now(timezone.utc).replace(hour=2, minute=0)  # 2 AM

        for i in range(25):  # 25 after-hours events (medium severity)
            events.append(
                AuditEvent(
                    event_id=str(i),
                    event_type="admin",
                    event_name="VIEW_USER",
                    actor_email="user@example.com",
                    timestamp=base_time + timedelta(minutes=i),
                )
            )

        anomalies = anomaly_detector._detect_unusual_access_time(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "unusual_access_time"
        assert anomalies[0].severity == "medium"
        assert "25 events outside business hours" in anomalies[0].description

    def test_detect_unusual_access_time_low_severity(self, anomaly_detector):
        """Test detecting unusual access times with low severity."""
        # Create events outside business hours
        events = []
        base_time = datetime.now(timezone.utc).replace(hour=2, minute=0)  # 2 AM

        for i in range(10):  # 10 after-hours events (low severity)
            events.append(
                AuditEvent(
                    event_id=str(i),
                    event_type="admin",
                    event_name="VIEW_USER",
                    actor_email="user@example.com",
                    timestamp=base_time + timedelta(minutes=i),
                )
            )

        anomalies = anomaly_detector._detect_unusual_access_time(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "unusual_access_time"
        assert anomalies[0].severity == "low"
        assert "10 events outside business hours" in anomalies[0].description

    def test_detect_mass_file_download(self, anomaly_detector):
        """Test detecting mass file downloads."""
        # Create many download events
        events = []

        for i in range(60):  # 60 downloads
            events.append(
                AuditEvent(
                    event_id=str(i),
                    event_type="drive",
                    event_name="download",
                    actor_email="user@example.com",
                    timestamp=datetime.now(timezone.utc),
                )
            )

        anomalies = anomaly_detector._detect_mass_file_download(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "mass_file_download"
        assert anomalies[0].severity == "high"
        assert "60 files" in anomalies[0].description

    def test_detect_mass_file_download_critical(self, anomaly_detector):
        """Test detecting critical mass file downloads."""
        # Create many download events (over 100)
        events = []

        for i in range(150):  # 150 downloads
            events.append(
                AuditEvent(
                    event_id=str(i),
                    event_type="drive",
                    event_name="download",
                    actor_email="user@example.com",
                    timestamp=datetime.now(timezone.utc),
                )
            )

        anomalies = anomaly_detector._detect_mass_file_download(events)

        assert len(anomalies) == 1
        assert anomalies[0].severity == "critical"  # Over 100 downloads

    def test_detect_privilege_escalation_grant_admin(self, anomaly_detector):
        """Test detecting privilege escalation (grant admin)."""
        events = [
            AuditEvent(
                event_id="1",
                event_type="admin",
                event_name="GRANT_ADMIN_PRIVILEGE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={
                    "USER_EMAIL": "newadmin@example.com",
                    "PRIVILEGE_NAME": "SUPER_ADMIN",
                },
            )
        ]

        anomalies = anomaly_detector._detect_privilege_escalation(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "privilege_escalation"
        assert anomalies[0].severity == "critical"
        assert "Admin privilege granted" in anomalies[0].description

    def test_detect_privilege_escalation_assign_role(self, anomaly_detector):
        """Test detecting privilege escalation (assign role)."""
        events = [
            AuditEvent(
                event_id="1",
                event_type="admin",
                event_name="ASSIGN_ROLE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={
                    "USER_EMAIL": "user@example.com",
                    "ROLE_NAME": "USER_MANAGEMENT_ADMIN",
                },
            )
        ]

        anomalies = anomaly_detector._detect_privilege_escalation(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "privilege_escalation"
        assert anomalies[0].severity == "high"
        assert "Role" in anomalies[0].description

    def test_detect_suspicious_api_usage_sensitive_scopes(self, anomaly_detector):
        """Test detecting suspicious API usage with sensitive scopes."""
        events = [
            AuditEvent(
                event_id="1",
                event_type="token",
                event_name="authorize",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={
                    "app_name": "Suspicious App",
                    "scope": "https://www.googleapis.com/auth/admin.directory.user",
                },
            )
        ]

        anomalies = anomaly_detector._detect_suspicious_api_usage(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "suspicious_api_usage"
        assert anomalies[0].severity == "high"
        assert "sensitive scopes" in anomalies[0].description

    def test_detect_suspicious_api_usage_high_volume(self, anomaly_detector):
        """Test detecting suspicious API usage (high volume)."""
        # Create many token events
        events = []

        for i in range(150):  # 150 API calls
            events.append(
                AuditEvent(
                    event_id=str(i),
                    event_type="token",
                    event_name="api_call",
                    actor_email="user@example.com",
                    timestamp=datetime.now(timezone.utc),
                )
            )

        anomalies = anomaly_detector._detect_suspicious_api_usage(events)

        assert len(anomalies) == 1
        assert anomalies[0].anomaly_type == "suspicious_api_usage"
        assert anomalies[0].severity == "medium"
        assert "150 API calls" in anomalies[0].description

    def test_detect_anomalies_combined(self, anomaly_detector):
        """Test detecting multiple types of anomalies."""
        events = [
            # Unusual login location
            AuditEvent(
                event_id="1",
                event_type="login",
                event_name="login_success",
                actor_email="user1@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"login_country": "US"},
            ),
            AuditEvent(
                event_id="2",
                event_type="login",
                event_name="login_success",
                actor_email="user1@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"login_country": "CN"},
            ),
            AuditEvent(
                event_id="3",
                event_type="login",
                event_name="login_success",
                actor_email="user1@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"login_country": "RU"},
            ),
            # Privilege escalation
            AuditEvent(
                event_id="4",
                event_type="admin",
                event_name="GRANT_ADMIN_PRIVILEGE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"USER_EMAIL": "newadmin@example.com"},
            ),
        ]

        result = anomaly_detector.detect_anomalies(events)

        assert result.total_anomalies == 2
        assert result.critical_anomalies == 1  # Privilege escalation
        assert result.high_anomalies == 1  # Unusual login location

    def test_detect_anomalies_statistics(self, anomaly_detector):
        """Test anomaly detection statistics."""
        events = [
            # Critical anomaly
            AuditEvent(
                event_id="1",
                event_type="admin",
                event_name="GRANT_ADMIN_PRIVILEGE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"USER_EMAIL": "newadmin@example.com"},
            ),
        ]

        result = anomaly_detector.detect_anomalies(events)

        assert result.statistics["total_anomalies"] == 1
        assert result.statistics["critical"] == 1
        assert result.statistics["high"] == 0
        assert result.statistics["medium"] == 0
        assert result.statistics["low"] == 0

    def test_detect_anomalies_all_severity_levels(self, anomaly_detector):
        """Test anomaly detection with all severity levels."""
        events = []
        base_time = datetime.now(timezone.utc)

        # Critical: Mass file download (>100)
        for i in range(150):
            events.append(
                AuditEvent(
                    event_id=f"download_{i}",
                    event_type="drive",
                    event_name="download",
                    actor_email="user1@example.com",
                    timestamp=base_time,
                )
            )

        # High: Unusual login location
        events.extend([
            AuditEvent(
                event_id="login_1",
                event_type="login",
                event_name="login_success",
                actor_email="user2@example.com",
                timestamp=base_time,
                parameters={"login_country": "US"},
            ),
            AuditEvent(
                event_id="login_2",
                event_type="login",
                event_name="login_success",
                actor_email="user2@example.com",
                timestamp=base_time,
                parameters={"login_country": "CN"},
            ),
            AuditEvent(
                event_id="login_3",
                event_type="login",
                event_name="login_success",
                actor_email="user2@example.com",
                timestamp=base_time,
                parameters={"login_country": "RU"},
            ),
        ])

        # Medium: Unusual access time
        after_hours_time = base_time.replace(hour=2, minute=0)
        for i in range(25):
            events.append(
                AuditEvent(
                    event_id=f"after_hours_{i}",
                    event_type="admin",
                    event_name="VIEW_USER",
                    actor_email="user3@example.com",
                    timestamp=after_hours_time + timedelta(minutes=i),
                )
            )

        # Low: Unusual access time (fewer events)
        for i in range(10):
            events.append(
                AuditEvent(
                    event_id=f"low_after_hours_{i}",
                    event_type="admin",
                    event_name="VIEW_USER",
                    actor_email="user4@example.com",
                    timestamp=after_hours_time + timedelta(minutes=i),
                )
            )

        result = anomaly_detector.detect_anomalies(events)

        # Should have all four severity levels
        assert result.total_anomalies >= 4
        assert result.critical_anomalies >= 1  # Mass download
        assert result.high_anomalies >= 1  # Unusual location
        assert result.medium_anomalies >= 1  # After hours (25 events)
        assert result.low_anomalies >= 1  # After hours (10 events)

        # Verify statistics match counts
        assert result.statistics["critical"] == result.critical_anomalies
        assert result.statistics["high"] == result.high_anomalies
        assert result.statistics["medium"] == result.medium_anomalies
        assert result.statistics["low"] == result.low_anomalies

    def test_empty_events_list(self, anomaly_detector):
        """Test anomaly detection with empty events list."""
        result = anomaly_detector.detect_anomalies([])

        assert result.total_anomalies == 0
        assert result.critical_anomalies == 0
        assert result.high_anomalies == 0
        assert result.medium_anomalies == 0
        assert result.low_anomalies == 0
        assert len(result.anomalies) == 0

