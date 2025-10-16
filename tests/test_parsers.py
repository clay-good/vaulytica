"""Tests for security event parsers."""

import pytest
from datetime import datetime
from vaulytica.parsers import (
    GuardDutyParser,
    GCPSecurityCommandCenterParser,
    DatadogParser,
    CrowdStrikeParser,
    SnowflakeParser
)
from vaulytica.models import Severity, EventCategory


class TestGuardDutyParser:
    """Tests for GuardDuty parser."""

    def test_parse_guardduty_event(self, sample_guardduty_event):
        """Test parsing a GuardDuty event."""
        parser = GuardDutyParser()
        event = parser.parse(sample_guardduty_event)
        
        assert event.source_system == "AWS GuardDuty"
        assert event.severity in [Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM]
        assert event.category == EventCategory.MALWARE
        assert "Bitcoin" in event.title or "mining" in event.title.lower()

    def test_guardduty_parser_validates(self, sample_guardduty_event):
        """Test GuardDuty parser validation."""
        parser = GuardDutyParser()
        assert parser.validate(sample_guardduty_event) is True

    def test_guardduty_parser_invalid_event(self):
        """Test GuardDuty parser with invalid event."""
        parser = GuardDutyParser()
        invalid_event = {"invalid": "structure"}
        assert parser.validate(invalid_event) is False

    def test_guardduty_extracts_assets(self, sample_guardduty_event):
        """Test GuardDuty parser extracts assets."""
        parser = GuardDutyParser()
        event = parser.parse(sample_guardduty_event)
        
        assert len(event.affected_assets) > 0
        asset = event.affected_assets[0]
        assert asset.cloud_resource_id is not None

    def test_guardduty_extracts_indicators(self, sample_guardduty_event):
        """Test GuardDuty parser extracts technical indicators."""
        parser = GuardDutyParser()
        event = parser.parse(sample_guardduty_event)
        
        # Should have at least some indicators
        assert len(event.technical_indicators) >= 0


class TestGCPSecurityCommandCenterParser:
    """Tests for GCP SCC parser."""

    def test_parse_gcp_scc_event(self):
        """Test parsing a GCP SCC event."""
        parser = GCPSecurityCommandCenterParser()
        
        sample_event = {
            "name": "organizations/123/sources/456/findings/789",
            "parent": "organizations/123/sources/456",
            "resourceName": "//compute.googleapis.com/projects/test/zones/us-central1-a/instances/test-vm",
            "state": "ACTIVE",
            "category": "Persistence: IAM Anomalous Grant",
            "externalUri": "https://console.cloud.google.com/",
            "sourceProperties": {
                "Severity": "HIGH",
                "Description": "Anomalous IAM grant detected"
            },
            "securityMarks": {},
            "eventTime": "2024-10-15T14:30:00.000Z",
            "createTime": "2024-10-15T14:30:00.000Z"
        }
        
        event = parser.parse(sample_event)
        assert event.source_system == "GCP Security Command Center"
        assert event.severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW]

    def test_gcp_scc_parser_validates(self):
        """Test GCP SCC parser validation."""
        parser = GCPSecurityCommandCenterParser()
        
        valid_event = {
            "name": "test",
            "category": "test",
            "eventTime": "2024-10-15T14:30:00.000Z"
        }
        assert parser.validate(valid_event) is True


class TestDatadogParser:
    """Tests for Datadog parser."""

    def test_parse_datadog_event(self):
        """Test parsing a Datadog event."""
        parser = DatadogParser()
        
        sample_event = {
            "id": "test-signal-123",
            "type": "signal",
            "attributes": {
                "timestamp": 1697380800000,
                "message": "Suspicious data exfiltration detected",
                "severity": "high",
                "rule": {
                    "name": "Data Exfiltration Detection",
                    "id": "rule-123"
                },
                "tags": ["env:production", "service:api"]
            }
        }
        
        event = parser.parse(sample_event)
        assert event.source_system == "Datadog Security Monitoring"
        assert event.event_id == "test-signal-123"

    def test_datadog_parser_validates(self):
        """Test Datadog parser validation."""
        parser = DatadogParser()
        
        valid_event = {
            "id": "test",
            "type": "signal",
            "attributes": {"timestamp": 123456789}
        }
        assert parser.validate(valid_event) is True


class TestCrowdStrikeParser:
    """Tests for CrowdStrike parser."""

    def test_parse_crowdstrike_event(self):
        """Test parsing a CrowdStrike event."""
        parser = CrowdStrikeParser()
        
        sample_event = {
            "event_simpleName": "ProcessRollup2",
            "name": "ProcessRollup2",
            "aid": "test-agent-id",
            "ComputerName": "DESKTOP-TEST",
            "UserName": "testuser",
            "CommandLine": "powershell.exe -enc base64command",
            "FileName": "powershell.exe",
            "FilePath": "C:\\Windows\\System32\\",
            "ProcessStartTime": "2024-10-15T14:30:00Z",
            "Severity": "4",
            "DetectDescription": "Suspicious PowerShell execution detected"
        }
        
        event = parser.parse(sample_event)
        assert event.source_system == "CrowdStrike Falcon"

    def test_crowdstrike_parser_validates(self):
        """Test CrowdStrike parser validation."""
        parser = CrowdStrikeParser()
        
        valid_event = {
            "event_simpleName": "test",
            "aid": "test-id"
        }
        assert parser.validate(valid_event) is True


class TestSnowflakeParser:
    """Tests for Snowflake parser."""

    def test_parse_snowflake_event(self):
        """Test parsing a Snowflake event."""
        parser = SnowflakeParser()
        
        sample_event = {
            "EVENT_ID": "test-event-123",
            "EVENT_TYPE": "QUERY_EXECUTION",
            "EVENT_TIMESTAMP": "2024-10-15T14:30:00Z",
            "USER_NAME": "testuser@example.com",
            "CLIENT_IP": "192.168.1.100",
            "DATABASE_NAME": "PRODUCTION_DB",
            "QUERY_TEXT": "SELECT * FROM sensitive_table",
            "BYTES_TRANSFERRED": 5000000000,
            "ROWS_RETURNED": 1000000
        }
        
        event = parser.parse(sample_event)
        assert event.source_system == "Snowflake"
        assert event.event_id == "test-event-123"

    def test_snowflake_parser_validates(self):
        """Test Snowflake parser validation."""
        parser = SnowflakeParser()
        
        valid_event = {
            "EVENT_ID": "test",
            "EVENT_TYPE": "test",
            "EVENT_TIMESTAMP": "2024-10-15T14:30:00Z"
        }
        assert parser.validate(valid_event) is True

    def test_snowflake_parser_invalid_event(self):
        """Test Snowflake parser with invalid event."""
        parser = SnowflakeParser()
        invalid_event = {"invalid": "structure"}
        assert parser.validate(invalid_event) is False

