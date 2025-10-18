import pytest
import json
from pathlib import Path
from datetime import datetime
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo, 
    TechnicalIndicator, MitreAttack, AnalysisResult, FiveW1H
)
from vaulytica.config import VaulyticaConfig


@pytest.fixture
def mock_config(tmp_path):
    """Create a mock configuration for testing."""
    return VaulyticaConfig(
        anthropic_api_key="test-key-12345",
        model_name="claude-3-haiku-20240307",
        max_tokens=4000,
        temperature=0.0,
        chroma_db_path=tmp_path / "chroma_db",
        output_dir=tmp_path / "outputs",
        enable_rag=True,
        enable_cache=True,
        max_historical_incidents=5,
        batch_max_workers=2
    )


@pytest.fixture
def sample_security_event():
    """Create a sample security event for testing."""
    return SecurityEvent(
        event_id="test-event-001",
        source_system="GuardDuty",
        timestamp=datetime.utcnow(),
        severity=Severity.HIGH,
        category=EventCategory.MALWARE,
        title="Cryptocurrency Mining Activity Detected",
        description="EC2 instance i-1234567890abcdef0 is communicating with known mining pool",
        affected_assets=[
            AssetInfo(
                hostname="web-server-01",
                ip_addresses=["10.0.1.100", "54.123.45.67"],
                cloud_resource_id="i-1234567890abcdef0",
                environment="production"
            )
        ],
        technical_indicators=[
            TechnicalIndicator(
                indicator_type="ip_address",
                value="198.51.100.42",
                context="Mining pool IP"
            )
        ],
        mitre_attack=[
            MitreAttack(
                technique_id="T1496",
                technique_name="Resource Hijacking",
                tactic="Impact",
                confidence=0.9
            )
        ],
        raw_event={"detail": {"type": "CryptoCurrency:EC2/BitcoinTool.B!DNS"}},
        confidence_score=0.95
    )


@pytest.fixture
def sample_analysis_result():
    """Create a sample analysis result for testing."""
    return AnalysisResult(
        event_id="test-event-001",
        five_w1h=FiveW1H(
            who="Unknown attacker targeting EC2 instance",
            what="Cryptocurrency mining malware detected",
            when="2024-10-15 14:30:00 UTC",
            where="EC2 instance i-1234567890abcdef0 in us-east-1",
            why="Financial gain through unauthorized resource usage",
            how="Malware communicating with mining pool via DNS queries"
        ),
        executive_summary="High-severity cryptocurrency mining detected on production EC2 instance.",
        risk_score=8.5,
        confidence=0.92,
        attack_chain=[
            "Initial Access",
            "Execution",
            "Resource Hijacking",
            "Command and Control"
        ],
        mitre_techniques=[
            MitreAttack(
                technique_id="T1496",
                technique_name="Resource Hijacking",
                tactic="Impact",
                confidence=0.9
            )
        ],
        immediate_actions=[
            "Isolate affected EC2 instance immediately",
            "Terminate mining process",
            "Capture memory dump for forensics"
        ],
        short_term_recommendations=[
            "Scan all EC2 instances for similar indicators",
            "Review IAM permissions and access logs"
        ],
        long_term_recommendations=[
            "Implement runtime security monitoring",
            "Deploy EDR solution on all instances"
        ],
        investigation_queries=[
            "SELECT * FROM cloudtrail WHERE resource_id = 'i-1234567890abcdef0'"
        ]
    )


@pytest.fixture
def sample_guardduty_event():
    """Load sample GuardDuty event from test data."""
    test_file = Path(__file__).parent.parent / "test_data" / "guardduty_crypto_mining.json"
    if test_file.exists():
        with open(test_file) as f:
            return json.load(f)
    return {
        "detail": {
            "schemaVersion": "2.0",
            "accountId": "123456789012",
            "region": "us-east-1",
            "partition": "aws",
            "id": "test-finding-id",
            "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/test/finding/test",
            "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-1234567890abcdef0",
                    "instanceType": "t2.micro"
                }
            },
            "service": {
                "serviceName": "guardduty",
                "detectorId": "test-detector",
                "action": {
                    "actionType": "DNS_REQUEST",
                    "dnsRequestAction": {
                        "domain": "mining-pool.example.com"
                    }
                },
                "eventFirstSeen": "2024-10-15T14:30:00Z",
                "eventLastSeen": "2024-10-15T14:35:00Z",
                "count": 42
            },
            "severity": 8.0,
            "title": "Bitcoin mining activity detected",
            "description": "EC2 instance is querying a domain name associated with Bitcoin mining activity."
        }
    }


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary output directory."""
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    return output_dir

