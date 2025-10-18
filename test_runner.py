#!/usr/bin/env python3
"""
Comprehensive Test Runner for Vaulytica
Executes all tests and reports results
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

print("="*80)
print("VAULYTICA v0.17.0 - COMPREHENSIVE TEST EXECUTION")
print("="*80)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print()

# Track results
results = {
    "passed": [],
    "failed": [],
    "errors": []
}

def test(name, func):
    """Execute a test and record result"""
    try:
        func()
        results["passed"].append(name)
        print(f"✅ {name}")
        return True
    except Exception as e:
        results["failed"].append(name)
        results["errors"].append(f"{name}: {str(e)}")
        print(f"❌ {name}")
        print(f"   Error: {str(e)}")
        return False

# ============================================================================
# TEST 1: Core Imports
# ============================================================================
print("\n" + "="*80)
print("TEST 1: Core Module Imports")
print("="*80 + "\n")

def test_models_import():
    from vaulytica.models import SecurityEvent, Severity, EventCategory
    assert SecurityEvent is not None
    assert Severity is not None
    assert EventCategory is not None

def test_config_import():
    from vaulytica.config import VaulyticaConfig, load_config
    assert VaulyticaConfig is not None
    assert load_config is not None

def test_logger_import():
    from vaulytica.logger import get_logger
    logger = get_logger(__name__)
    assert logger is not None

def test_validators_import():
    from vaulytica.validators import validate_event
    assert validate_event is not None

test("Import models", test_models_import)
test("Import config", test_config_import)
test("Import logger", test_logger_import)
test("Import validators", test_validators_import)

# ============================================================================
# TEST 2: Parser Imports
# ============================================================================
print("\n" + "="*80)
print("TEST 2: Parser Imports")
print("="*80 + "\n")

def test_guardduty_parser():
    from vaulytica.parsers.guardduty import GuardDutyParser
    parser = GuardDutyParser()
    assert parser is not None

def test_gcp_parser():
    from vaulytica.parsers.gcp_scc import GCPSCCParser
    parser = GCPSCCParser()
    assert parser is not None

def test_snowflake_parser():
    from vaulytica.parsers.snowflake import SnowflakeParser
    parser = SnowflakeParser()
    assert parser is not None

def test_datadog_parser():
    from vaulytica.parsers.datadog import DatadogParser
    parser = DatadogParser()
    assert parser is not None

def test_crowdstrike_parser():
    from vaulytica.parsers.crowdstrike import CrowdStrikeParser
    parser = CrowdStrikeParser()
    assert parser is not None

test("GuardDuty parser", test_guardduty_parser)
test("GCP SCC parser", test_gcp_parser)
test("Snowflake parser", test_snowflake_parser)
test("Datadog parser", test_datadog_parser)
test("CrowdStrike parser", test_crowdstrike_parser)

# ============================================================================
# TEST 3: Parser Functionality with Real Data
# ============================================================================
print("\n" + "="*80)
print("TEST 3: Parser Functionality with Real Data")
print("="*80 + "\n")

def test_guardduty_parse():
    from vaulytica.parsers.guardduty import GuardDutyParser
    parser = GuardDutyParser()
    with open('test_data/guardduty_ssh_bruteforce.json') as f:
        data = json.load(f)
    event = parser.parse(data)
    assert event.event_id is not None
    assert event.severity is not None
    assert event.category is not None

def test_gcp_parse():
    from vaulytica.parsers.gcp_scc import GCPSCCParser
    parser = GCPSCCParser()
    with open('test_data/gcp_scc_privilege_escalation.json') as f:
        data = json.load(f)
    event = parser.parse(data)
    assert event.event_id is not None
    assert event.severity is not None

def test_snowflake_parse():
    from vaulytica.parsers.snowflake import SnowflakeParser
    parser = SnowflakeParser()
    with open('test_data/snowflake_data_exfiltration.json') as f:
        data = json.load(f)
    event = parser.parse(data)
    assert event.event_id is not None
    assert event.severity is not None

test("Parse GuardDuty event", test_guardduty_parse)
test("Parse GCP SCC event", test_gcp_parse)
test("Parse Snowflake event", test_snowflake_parse)

# ============================================================================
# TEST 4: Model Creation
# ============================================================================
print("\n" + "="*80)
print("TEST 4: Model Creation")
print("="*80 + "\n")

def test_create_security_event():
    from vaulytica.models import SecurityEvent, Severity, EventCategory
    event = SecurityEvent(
        event_id="test-001",
        timestamp=datetime.utcnow(),
        source="test",
        severity=Severity.HIGH,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        description="Test event",
        raw_event={}
    )
    assert event.event_id == "test-001"
    assert event.severity == Severity.HIGH

def test_create_config():
    from vaulytica.config import VaulyticaConfig
    config = VaulyticaConfig(
        anthropic_api_key="sk-ant-test-key",
        model_name="claude-3-haiku-20240307"
    )
    assert config.anthropic_api_key == "sk-ant-test-key"
    assert config.model_name == "claude-3-haiku-20240307"

test("Create SecurityEvent", test_create_security_event)
test("Create VaulyticaConfig", test_create_config)

# ============================================================================
# TEST 5: Advanced Module Imports
# ============================================================================
print("\n" + "="*80)
print("TEST 5: Advanced Module Imports")
print("="*80 + "\n")

def test_ml_engine_import():
    from vaulytica.ml_engine import MLEngine
    assert MLEngine is not None

def test_streaming_import():
    from vaulytica.streaming import StreamingAnalytics
    assert StreamingAnalytics is not None

def test_forensics_import():
    from vaulytica.forensics import ForensicsEngine
    assert ForensicsEngine is not None

def test_incidents_import():
    from vaulytica.incidents import IncidentManager
    assert IncidentManager is not None

def test_ai_soc_import():
    from vaulytica.ai_soc_analytics import AISOCAnalytics
    assert AISOCAnalytics is not None

test("ML Engine import", test_ml_engine_import)
test("Streaming Analytics import", test_streaming_import)
test("Forensics Engine import", test_forensics_import)
test("Incident Manager import", test_incidents_import)
test("AI SOC Analytics import", test_ai_soc_import)

# ============================================================================
# TEST 6: File Structure
# ============================================================================
print("\n" + "="*80)
print("TEST 6: File Structure")
print("="*80 + "\n")

required_files = [
    "vaulytica/__init__.py",
    "vaulytica/models.py",
    "vaulytica/config.py",
    "vaulytica/api.py",
    "requirements.txt",
    "setup.py",
    "Dockerfile",
    "docker-compose.yml"
]

for file_path in required_files:
    def check_file(fp=file_path):
        assert Path(fp).exists(), f"File not found: {fp}"
    test(f"File exists: {file_path}", check_file)

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "="*80)
print("FINAL RESULTS")
print("="*80)

total = len(results["passed"]) + len(results["failed"])
passed = len(results["passed"])
failed = len(results["failed"])

print(f"\nTotal Tests: {total}")
print(f"✅ Passed: {passed}")
print(f"❌ Failed: {failed}")
print(f"Success Rate: {(passed/total*100):.1f}%")

if results["errors"]:
    print(f"\n🐛 Errors Found ({len(results['errors'])}):")
    for i, error in enumerate(results["errors"], 1):
        print(f"  {i}. {error}")

print("\n" + "="*80)
print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*80)

sys.exit(0 if failed == 0 else 1)

