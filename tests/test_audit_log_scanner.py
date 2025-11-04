"""Tests for audit log scanner."""

import pytest
from unittest.mock import Mock
from datetime import datetime, timedelta, timezone
from vaulytica.core.scanners.audit_log_scanner import (
    AuditLogScanner,
    AuditEvent,
    AuditLogScanResult,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.reports = Mock()
    return client


@pytest.fixture
def audit_log_scanner(mock_client):
    """Create an AuditLogScanner instance."""
    return AuditLogScanner(mock_client, "example.com")


class TestAuditLogScanner:
    """Tests for AuditLogScanner class."""

    def test_init(self, audit_log_scanner):
        """Test scanner initialization."""
        assert audit_log_scanner.domain == "example.com"
        assert audit_log_scanner.client is not None

    def test_parse_audit_event(self, audit_log_scanner):
        """Test parsing an audit event."""
        item = {
            "id": {
                "uniqueQualifier": "event123",
                "time": "2024-01-15T10:30:00Z",
            },
            "actor": {"email": "admin@example.com"},
            "ipAddress": "192.168.1.1",
            "events": [
                {
                    "name": "CREATE_USER",
                    "parameters": [
                        {"name": "USER_EMAIL", "value": "newuser@example.com"},
                    ],
                }
            ],
        }

        event = audit_log_scanner._parse_audit_event(item, "admin")

        assert event.event_id == "event123"
        assert event.event_type == "admin"
        assert event.event_name == "CREATE_USER"
        assert event.actor_email == "admin@example.com"
        assert event.ip_address == "192.168.1.1"
        assert event.parameters["USER_EMAIL"] == "newuser@example.com"

    def test_detect_suspicious_admin_activity(self, audit_log_scanner):
        """Test detecting suspicious admin activity."""
        events = [
            AuditEvent(
                event_id="1",
                event_type="admin",
                event_name="CREATE_USER",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
            ),
            AuditEvent(
                event_id="2",
                event_type="admin",
                event_name="DELETE_USER",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
            ),
            AuditEvent(
                event_id="3",
                event_type="admin",
                event_name="GRANT_ADMIN_PRIVILEGE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
            ),
        ]

        suspicious = audit_log_scanner._detect_suspicious_admin_activity(events)

        assert len(suspicious) == 2  # DELETE_USER and GRANT_ADMIN_PRIVILEGE
        assert suspicious[0].event_name == "DELETE_USER"
        assert suspicious[0].severity == "high"  # Updated: DELETE_USER is now classified as "high" severity
        assert suspicious[1].event_name == "GRANT_ADMIN_PRIVILEGE"

    def test_detect_suspicious_login_activity(self, audit_log_scanner):
        """Test detecting suspicious login activity."""
        events = [
            AuditEvent(
                event_id="1",
                event_type="login",
                event_name="login_success",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
            ),
            AuditEvent(
                event_id="2",
                event_type="login",
                event_name="login_failure",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
            ),
            AuditEvent(
                event_id="3",
                event_type="login",
                event_name="suspicious_login",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
            ),
        ]

        suspicious = audit_log_scanner._detect_suspicious_login_activity(events)

        assert len(suspicious) == 2  # login_failure and suspicious_login
        assert suspicious[0].event_name == "login_failure"
        assert suspicious[0].severity == "warning"

    def test_detect_suspicious_drive_activity_public_sharing(self, audit_log_scanner):
        """Test detecting suspicious drive activity (public sharing)."""
        events = [
            AuditEvent(
                event_id="1",
                event_type="drive",
                event_name="change_document_access_scope",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"visibility": "public"},
            ),
            AuditEvent(
                event_id="2",
                event_type="drive",
                event_name="download",
                actor_email="user@example.com",
                timestamp=datetime.now(timezone.utc),
            ),
        ]

        suspicious = audit_log_scanner._detect_suspicious_drive_activity(events)

        assert len(suspicious) == 2
        assert suspicious[0].severity == "critical"  # Public sharing
        assert suspicious[1].severity == "info"  # Download

    def test_fetch_audit_logs(self, audit_log_scanner, mock_client):
        """Test fetching audit logs."""
        # Mock API response
        mock_client.reports.activities().list().execute.return_value = {
            "items": [
                {
                    "id": {
                        "uniqueQualifier": "event1",
                        "time": "2024-01-15T10:00:00Z",
                    },
                    "actor": {"email": "admin@example.com"},
                    "ipAddress": "192.168.1.1",
                    "events": [
                        {
                            "name": "CREATE_USER",
                            "parameters": [],
                        }
                    ],
                }
            ]
        }

        start_time = datetime.now(timezone.utc) - timedelta(days=7)
        events = audit_log_scanner._fetch_audit_logs("admin", start_time, 1000)

        assert len(events) == 1
        assert events[0].event_type == "admin"
        assert events[0].event_name == "CREATE_USER"

    def test_scan_admin_activity(self, audit_log_scanner, mock_client):
        """Test scanning admin activity."""
        # Mock API response
        mock_client.reports.activities().list().execute.return_value = {
            "items": [
                {
                    "id": {
                        "uniqueQualifier": "event1",
                        "time": "2024-01-15T10:00:00Z",
                    },
                    "actor": {"email": "admin@example.com"},
                    "ipAddress": "192.168.1.1",
                    "events": [
                        {
                            "name": "DELETE_USER",
                            "parameters": [],
                        }
                    ],
                }
            ]
        }

        result = audit_log_scanner.scan_admin_activity(days_back=7, max_results=1000)

        assert result.admin_events == 1
        assert result.total_events == 1
        assert len(result.suspicious_events) == 1  # DELETE_USER is suspicious

    def test_scan_login_activity(self, audit_log_scanner, mock_client):
        """Test scanning login activity."""
        # Mock API response
        mock_client.reports.activities().list().execute.return_value = {
            "items": [
                {
                    "id": {
                        "uniqueQualifier": "event1",
                        "time": "2024-01-15T10:00:00Z",
                    },
                    "actor": {"email": "user@example.com"},
                    "ipAddress": "192.168.1.1",
                    "events": [
                        {
                            "name": "login_failure",
                            "parameters": [],
                        }
                    ],
                }
            ]
        }

        result = audit_log_scanner.scan_login_activity(days_back=7, max_results=1000)

        assert result.login_events == 1
        assert result.total_events == 1
        assert len(result.suspicious_events) == 1  # login_failure is suspicious

    def test_scan_drive_activity(self, audit_log_scanner, mock_client):
        """Test scanning drive activity."""
        # Mock API response
        mock_client.reports.activities().list().execute.return_value = {
            "items": [
                {
                    "id": {
                        "uniqueQualifier": "event1",
                        "time": "2024-01-15T10:00:00Z",
                    },
                    "actor": {"email": "user@example.com"},
                    "ipAddress": "192.168.1.1",
                    "events": [
                        {
                            "name": "download",
                            "parameters": [],
                        }
                    ],
                }
            ]
        }

        result = audit_log_scanner.scan_drive_activity(days_back=7, max_results=1000)

        assert result.drive_events == 1
        assert result.total_events == 1

    def test_scan_token_activity(self, audit_log_scanner, mock_client):
        """Test scanning token activity."""
        # Mock API response
        mock_client.reports.activities().list().execute.return_value = {
            "items": [
                {
                    "id": {
                        "uniqueQualifier": "event1",
                        "time": "2024-01-15T10:00:00Z",
                    },
                    "actor": {"email": "user@example.com"},
                    "ipAddress": "192.168.1.1",
                    "events": [
                        {
                            "name": "authorize",
                            "parameters": [],
                        }
                    ],
                }
            ]
        }

        result = audit_log_scanner.scan_token_activity(days_back=7, max_results=1000)

        assert result.token_events == 1
        assert result.total_events == 1

