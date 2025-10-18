import pytest
from datetime import datetime
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo,
    TechnicalIndicator, MitreAttack, AnalysisResult, FiveW1H
)


class TestSecurityEvent:
    """Tests for SecurityEvent model."""

    def test_create_security_event(self, sample_security_event):
        """Test creating a security event."""
        assert sample_security_event.event_id == "test-event-001"
        assert sample_security_event.source_system == "GuardDuty"
        assert sample_security_event.severity == Severity.HIGH
        assert sample_security_event.category == EventCategory.MALWARE

    def test_security_event_serialization(self, sample_security_event):
        """Test security event can be serialized to JSON."""
        json_data = sample_security_event.model_dump_json()
        assert json_data is not None
        assert "test-event-001" in json_data

    def test_security_event_with_assets(self, sample_security_event):
        """Test security event with affected assets."""
        assert len(sample_security_event.affected_assets) == 1
        asset = sample_security_event.affected_assets[0]
        assert asset.hostname == "web-server-01"
        assert "10.0.1.100" in asset.ip_addresses

    def test_security_event_with_indicators(self, sample_security_event):
        """Test security event with technical indicators."""
        assert len(sample_security_event.technical_indicators) == 1
        indicator = sample_security_event.technical_indicators[0]
        assert indicator.indicator_type == "ip_address"
        assert indicator.value == "198.51.100.42"

    def test_security_event_with_mitre(self, sample_security_event):
        """Test security event with MITRE ATT&CK mapping."""
        assert len(sample_security_event.mitre_attack) == 1
        mitre = sample_security_event.mitre_attack[0]
        assert mitre.technique_id == "T1496"
        assert mitre.technique_name == "Resource Hijacking"


class TestAnalysisResult:
    """Tests for AnalysisResult model."""

    def test_create_analysis_result(self, sample_analysis_result):
        """Test creating an analysis result."""
        assert sample_analysis_result.event_id == "test-event-001"
        assert sample_analysis_result.risk_score == 8.5
        assert sample_analysis_result.confidence == 0.92

    def test_analysis_result_five_w1h(self, sample_analysis_result):
        """Test 5W1H summary in analysis result."""
        five_w1h = sample_analysis_result.five_w1h
        assert "attacker" in five_w1h.who.lower()
        assert "mining" in five_w1h.what.lower()
        assert five_w1h.when is not None
        assert "EC2" in five_w1h.where
        assert "gain" in five_w1h.why.lower()
        assert "malware" in five_w1h.how.lower()

    def test_analysis_result_recommendations(self, sample_analysis_result):
        """Test recommendations in analysis result."""
        assert len(sample_analysis_result.immediate_actions) > 0
        assert len(sample_analysis_result.short_term_recommendations) > 0
        assert len(sample_analysis_result.long_term_recommendations) > 0

    def test_analysis_result_attack_chain(self, sample_analysis_result):
        """Test attack chain in analysis result."""
        assert len(sample_analysis_result.attack_chain) > 0
        assert "Initial Access" in sample_analysis_result.attack_chain

    def test_analysis_result_serialization(self, sample_analysis_result):
        """Test analysis result can be serialized to JSON."""
        json_data = sample_analysis_result.model_dump_json()
        assert json_data is not None
        assert "test-event-001" in json_data


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"


class TestEventCategory:
    """Tests for EventCategory enum."""

    def test_event_category_values(self):
        """Test event category enum values."""
        assert EventCategory.MALWARE.value == "MALWARE"
        assert EventCategory.UNAUTHORIZED_ACCESS.value == "UNAUTHORIZED_ACCESS"
        assert EventCategory.DATA_EXFILTRATION.value == "DATA_EXFILTRATION"
        assert EventCategory.PRIVILEGE_ESCALATION.value == "PRIVILEGE_ESCALATION"


class TestAssetInfo:
    """Tests for AssetInfo model."""

    def test_create_asset_info(self):
        """Test creating asset info."""
        asset = AssetInfo(
            hostname="test-server",
            ip_addresses=["10.0.0.1"],
            cloud_resource_id="i-12345",
            environment="production",
            tags={"team": "security"}
        )
        assert asset.hostname == "test-server"
        assert len(asset.ip_addresses) == 1
        assert asset.tags["team"] == "security"


class TestTechnicalIndicator:
    """Tests for TechnicalIndicator model."""

    def test_create_technical_indicator(self):
        """Test creating technical indicator."""
        indicator = TechnicalIndicator(
            indicator_type="ip_address",
            value="192.168.1.1",
            context="Suspicious IP"
        )
        assert indicator.indicator_type == "ip_address"
        assert indicator.value == "192.168.1.1"


class TestMitreAttack:
    """Tests for MitreAttack model."""

    def test_create_mitre_attack(self):
        """Test creating MITRE ATT&CK mapping."""
        mitre = MitreAttack(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            confidence=0.85
        )
        assert mitre.technique_id == "T1059"
        assert mitre.tactic == "Execution"
        assert mitre.confidence == 0.85


class TestFiveW1H:
    """Tests for FiveW1H model."""

    def test_create_five_w1h(self):
        """Test creating 5W1H summary."""
        five_w1h = FiveW1H(
            who="Attacker from IP 1.2.3.4",
            what="Brute force attack",
            when="2024-10-15 14:30 UTC",
            where="SSH server on port 22",
            why="Unauthorized access attempt",
            how="Dictionary attack using common passwords"
        )
        assert "Attacker" in five_w1h.who
        assert "Brute force" in five_w1h.what
        assert "2024" in five_w1h.when
        assert "SSH" in five_w1h.where
        assert "access" in five_w1h.why
        assert "Dictionary" in five_w1h.how

