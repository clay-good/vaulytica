"""Tests for enhanced audit log scanner admin activity monitoring."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, MagicMock

from vaulytica.core.scanners.audit_log_scanner import (
    AuditLogScanner,
    AuditEvent,
    AuditLogScanResult,
)


class TestEnhancedAuditLogScanner:
    """Tests for enhanced audit log scanner security features."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        client.reports = Mock()
        client.reports.activities = Mock()
        return client

    @pytest.fixture
    def audit_scanner(self, mock_client):
        """Create an audit log scanner instance."""
        return AuditLogScanner(client=mock_client, domain="example.com")

    def test_detect_privilege_escalation(self, audit_scanner):
        """Test detection of privilege escalation events."""
        events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="GRANT_ADMIN_PRIVILEGE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"USER_EMAIL": "user@example.com"},
            )
        ]

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        assert len(suspicious) == 1
        assert suspicious[0].is_privilege_escalation is True
        assert suspicious[0].severity == "critical"
        assert suspicious[0].risk_score >= 85

    def test_detect_bulk_delete_users(self, audit_scanner):
        """Test detection of bulk user deletion."""
        base_time = datetime.now(timezone.utc)
        events = []
        
        # Create 6 DELETE_USER events within 5 minutes
        for i in range(6):
            events.append(
                AuditEvent(
                    event_id=f"evt-{i}",
                    event_type="admin",
                    event_name="DELETE_USER",
                    actor_email="admin@example.com",
                    timestamp=base_time + timedelta(minutes=i),
                    parameters={"USER_EMAIL": f"user{i}@example.com"},
                )
            )

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        # Should detect bulk action
        bulk_events = [e for e in suspicious if e.is_bulk_action]
        assert len(bulk_events) >= 1
        assert any(e.severity == "critical" for e in bulk_events)

    def test_detect_bulk_suspend_users(self, audit_scanner):
        """Test detection of bulk user suspension."""
        base_time = datetime.now(timezone.utc)
        events = []
        
        # Create 5 SUSPEND_USER events within 8 minutes
        for i in range(5):
            events.append(
                AuditEvent(
                    event_id=f"evt-{i}",
                    event_type="admin",
                    event_name="SUSPEND_USER",
                    actor_email="admin@example.com",
                    timestamp=base_time + timedelta(minutes=i * 1.5),
                    parameters={"USER_EMAIL": f"user{i}@example.com"},
                )
            )

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        # Should detect bulk action
        bulk_events = [e for e in suspicious if e.is_bulk_action]
        assert len(bulk_events) >= 1

    def test_detect_after_hours_admin_activity(self, audit_scanner):
        """Test detection of after-hours admin activity."""
        # Create event at 2 AM (after hours)
        after_hours_time = datetime.now(timezone.utc).replace(hour=2, minute=0, second=0)
        events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="CHANGE_APPLICATION_SETTING",
                actor_email="admin@example.com",
                timestamp=after_hours_time,
            )
        ]

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        assert len(suspicious) == 1
        assert suspicious[0].is_after_hours is True
        assert suspicious[0].severity in ["high", "warning"]

    def test_detect_assign_role(self, audit_scanner):
        """Test detection of role assignment (privilege escalation)."""
        events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="ASSIGN_ROLE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"USER_EMAIL": "user@example.com", "ROLE_NAME": "Super Admin"},
            )
        ]

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        assert len(suspicious) == 1
        assert suspicious[0].is_privilege_escalation is True
        assert suspicious[0].severity == "critical"

    def test_detect_create_role(self, audit_scanner):
        """Test detection of custom role creation."""
        events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="CREATE_ROLE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"ROLE_NAME": "Custom Admin Role"},
            )
        ]

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        assert len(suspicious) == 1
        assert suspicious[0].is_privilege_escalation is True

    def test_detect_password_change(self, audit_scanner):
        """Test detection of password changes."""
        events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="CHANGE_PASSWORD",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"USER_EMAIL": "user@example.com"},
            )
        ]

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        assert len(suspicious) == 1
        assert suspicious[0].severity in ["high", "critical"]

    def test_detect_sensitive_config_change(self, audit_scanner):
        """Test detection of sensitive configuration changes."""
        events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="TOGGLE_SERVICE_ENABLED",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc).replace(hour=14),  # During business hours
                parameters={"SERVICE_NAME": "Drive"},
            )
        ]

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        assert len(suspicious) == 1
        assert suspicious[0].severity == "warning"
        assert suspicious[0].risk_score >= 40

    def test_after_hours_increases_severity(self, audit_scanner):
        """Test that after-hours activity increases severity."""
        # Same event, different times
        business_hours_time = datetime.now(timezone.utc).replace(hour=14, minute=0)
        after_hours_time = datetime.now(timezone.utc).replace(hour=22, minute=0)

        business_event = AuditEvent(
            event_id="evt-1",
            event_type="admin",
            event_name="CHANGE_APPLICATION_SETTING",
            actor_email="admin@example.com",
            timestamp=business_hours_time,
        )

        after_hours_event = AuditEvent(
            event_id="evt-2",
            event_type="admin",
            event_name="CHANGE_APPLICATION_SETTING",
            actor_email="admin@example.com",
            timestamp=after_hours_time,
        )

        business_suspicious = audit_scanner._detect_suspicious_admin_activity([business_event])
        after_hours_suspicious = audit_scanner._detect_suspicious_admin_activity([after_hours_event])

        # After hours should have higher risk
        assert after_hours_suspicious[0].risk_score > business_suspicious[0].risk_score
        assert after_hours_suspicious[0].is_after_hours is True

    def test_generate_privilege_escalation_issue(self, audit_scanner):
        """Test generation of privilege escalation security issue."""
        result = AuditLogScanResult()
        result.events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="GRANT_ADMIN_PRIVILEGE",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                is_privilege_escalation=True,
                target_user="user@example.com",
                risk_score=90,
                risk_factors=["Privilege escalation: granting admin rights"],
            )
        ]
        result.privilege_escalation_events = 1

        issues = audit_scanner._generate_admin_issues(result)

        priv_esc_issues = [i for i in issues if i["type"] == "privilege_escalation"]
        assert len(priv_esc_issues) == 1
        assert priv_esc_issues[0]["severity"] == "critical"
        assert priv_esc_issues[0]["actor"] == "admin@example.com"
        assert priv_esc_issues[0]["target_user"] == "user@example.com"

    def test_generate_bulk_action_issue(self, audit_scanner):
        """Test generation of bulk action security issue."""
        result = AuditLogScanResult()
        base_time = datetime.now(timezone.utc)
        
        # Create multiple bulk action events
        for i in range(5):
            result.events.append(
                AuditEvent(
                    event_id=f"evt-{i}",
                    event_type="admin",
                    event_name="DELETE_USER",
                    actor_email="admin@example.com",
                    timestamp=base_time + timedelta(minutes=i),
                    is_bulk_action=True,
                    risk_score=85,
                )
            )
        result.bulk_action_events = 5

        issues = audit_scanner._generate_admin_issues(result)

        bulk_issues = [i for i in issues if i["type"] == "bulk_destructive_action"]
        assert len(bulk_issues) >= 1
        assert bulk_issues[0]["severity"] == "critical"
        assert bulk_issues[0]["event_count"] == 5

    def test_generate_after_hours_issue(self, audit_scanner):
        """Test generation of after-hours admin activity issue."""
        result = AuditLogScanResult()
        after_hours_time = datetime.now(timezone.utc).replace(hour=22)
        
        # Create 15 after-hours high-risk events
        for i in range(15):
            result.events.append(
                AuditEvent(
                    event_id=f"evt-{i}",
                    event_type="admin",
                    event_name="CHANGE_APPLICATION_SETTING",
                    actor_email="admin@example.com",
                    timestamp=after_hours_time + timedelta(minutes=i),
                    is_after_hours=True,
                    severity="high",
                    risk_score=65,
                )
            )
        result.after_hours_admin_events = 15

        issues = audit_scanner._generate_admin_issues(result)

        after_hours_issues = [i for i in issues if i["type"] == "after_hours_admin_activity"]
        assert len(after_hours_issues) == 1
        assert after_hours_issues[0]["severity"] == "high"
        assert after_hours_issues[0]["event_count"] == 15

    def test_generate_recommendations(self, audit_scanner):
        """Test generation of security recommendations."""
        result = AuditLogScanResult()
        result.admin_events = 150
        result.high_risk_events = 10
        result.privilege_escalation_events = 3
        result.after_hours_admin_events = 8

        recommendations = audit_scanner._generate_admin_recommendations(result)

        assert len(recommendations) >= 4
        # Should recommend enabling alerts
        assert any("alert" in r["title"].lower() for r in recommendations)
        # Should recommend reviewing privilege escalations
        assert any("privilege" in r["title"].lower() for r in recommendations)
        # Should recommend time-based access controls
        assert any("time-based" in r["title"].lower() or "after hours" in r["description"].lower() for r in recommendations)
        # Should recommend 2FA
        assert any("2-step" in r["title"].lower() or "2fa" in r["title"].lower() for r in recommendations)

    def test_target_user_extraction(self, audit_scanner):
        """Test extraction of target user from event parameters."""
        events = [
            AuditEvent(
                event_id="evt-1",
                event_type="admin",
                event_name="DELETE_USER",
                actor_email="admin@example.com",
                timestamp=datetime.now(timezone.utc),
                parameters={"USER_EMAIL": "target@example.com"},
            )
        ]

        suspicious = audit_scanner._detect_suspicious_admin_activity(events)

        assert suspicious[0].target_user == "target@example.com"

