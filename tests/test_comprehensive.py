#!/usr/bin/env python3
"""
Comprehensive System Testing Suite
Tests all major components of Vaulytica
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("="*80)
print("VAULYTICA v0.17.0 - COMPREHENSIVE SYSTEM TEST")
print("="*80)
print()

# Track results
tests_passed = 0
tests_failed = 0
issues_found = []


def test_section(name):
    """Print test section header"""
    print(f"\n{'='*80}")
    print(f"TESTING: {name}")
    print(f"{'='*80}\n")


def test_result(test_name, passed, error=None):
    """Record test result"""
    global tests_passed, tests_failed, issues_found
    if passed:
        print(f"✅ {test_name}")
        tests_passed += 1
    else:
        print(f"❌ {test_name}")
        if error:
            print(f"   Error: {error}")
            issues_found.append(f"{test_name}: {error}")
        tests_failed += 1


# ============================================================================
# Test 1: Core Module Imports
# ============================================================================
test_section("Core Module Imports")

try:
    from vaulytica.models import SecurityEvent, Severity, EventCategory
    test_result("Import models", True)
except Exception as e:
    test_result("Import models", False, str(e))

try:
    from vaulytica.config import load_config
    test_result("Import config", True)
except Exception as e:
    test_result("Import config", False, str(e))

try:
    from vaulytica.logger import get_logger
    test_result("Import logger", True)
except Exception as e:
    test_result("Import logger", False, str(e))

try:
    from vaulytica.validators import validate_event
    test_result("Import validators", True)
except Exception as e:
    test_result("Import validators", False, str(e))


# ============================================================================
# Test 2: Parser Imports
# ============================================================================
test_section("Parser Imports")

try:
    from vaulytica.parsers.guardduty import GuardDutyParser
    test_result("Import GuardDuty parser", True)
except Exception as e:
    test_result("Import GuardDuty parser", False, str(e))

try:
    from vaulytica.parsers import GCPSCCParser
    test_result("Import GCP SCC parser", True)
except Exception as e:
    test_result("Import GCP SCC parser", False, str(e))

try:
    from vaulytica.parsers.snowflake import SnowflakeParser
    test_result("Import Snowflake parser", True)
except Exception as e:
    test_result("Import Snowflake parser", False, str(e))

try:
    from vaulytica.parsers.datadog import DatadogParser
    test_result("Import Datadog parser", True)
except Exception as e:
    test_result("Import Datadog parser", False, str(e))

try:
    from vaulytica.parsers.crowdstrike import CrowdStrikeParser
    test_result("Import CrowdStrike parser", True)
except Exception as e:
    test_result("Import CrowdStrike parser", False, str(e))


# ============================================================================
# Test 3: Advanced Module Imports
# ============================================================================
test_section("Advanced Module Imports")

try:
    from vaulytica.ml_engine import MLEngine
    test_result("Import ML Engine", True)
except Exception as e:
    test_result("Import ML Engine", False, str(e))

try:
    from vaulytica.advanced_ml import AdvancedMLEngine
    test_result("Import Advanced ML Engine", True)
except Exception as e:
    test_result("Import Advanced ML Engine", False, str(e))

try:
    from vaulytica.streaming import StreamingAnalytics
    test_result("Import Streaming Analytics", True)
except Exception as e:
    test_result("Import Streaming Analytics", False, str(e))

try:
    from vaulytica.forensics import ForensicsEngine
    test_result("Import Forensics Engine", True)
except Exception as e:
    test_result("Import Forensics Engine", False, str(e))

try:
    from vaulytica.incidents import IncidentManager
    test_result("Import Incident Manager", True)
except Exception as e:
    test_result("Import Incident Manager", False, str(e))

try:
    from vaulytica.ai_soc_analytics import AISOCAnalytics
    test_result("Import AI SOC Analytics", True)
except Exception as e:
    test_result("Import AI SOC Analytics", False, str(e))

try:
    from vaulytica.visualizations import VisualizationEngine
    test_result("Import Visualization Engine", True)
except Exception as e:
    test_result("Import Visualization Engine", False, str(e))


# ============================================================================
# Test 4: API Import
# ============================================================================
test_section("API Import")

try:
    from vaulytica.api import app
    test_result("Import FastAPI app", True)
    
    # Check routes
    route_count = len(app.routes)
    if route_count > 100:
        test_result(f"API routes registered ({route_count} routes)", True)
    else:
        test_result(f"API routes registered ({route_count} routes)", False, "Expected >100 routes")
except Exception as e:
    test_result("Import FastAPI app", False, str(e))


# ============================================================================
# Test 5: Model Creation
# ============================================================================
test_section("Model Creation")

try:
    from vaulytica.models import SecurityEvent, Severity, EventCategory
    from datetime import datetime

    event = SecurityEvent(
        event_id="test-001",
        source_system="test",
        timestamp=datetime.utcnow(),
        severity=Severity.HIGH,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Test Security Event",
        description="Test event",
        raw_event={}
    )
    test_result("Create SecurityEvent", True)
except Exception as e:
    test_result("Create SecurityEvent", False, str(e))


# ============================================================================
# Test 6: Configuration Loading
# ============================================================================
test_section("Configuration Loading")

try:
    from vaulytica.config import VaulyticaConfig
    
    config = VaulyticaConfig(
        anthropic_api_key="sk-ant-test-key",
        model_name="claude-3-haiku-20240307"
    )
    test_result("Create configuration", True)
except Exception as e:
    test_result("Create configuration", False, str(e))


# ============================================================================
# Test 7: File Structure
# ============================================================================
test_section("File Structure")

required_files = [
    "vaulytica/__init__.py",
    "vaulytica/models.py",
    "vaulytica/config.py",
    "vaulytica/logger.py",
    "vaulytica/api.py",
    "vaulytica/cli.py",
    "vaulytica/ml_engine.py",
    "vaulytica/advanced_ml.py",
    "vaulytica/streaming.py",
    "vaulytica/forensics.py",
    "vaulytica/incidents.py",
    "vaulytica/ai_soc_analytics.py",
    "requirements.txt",
    "setup.py",
    "README.md",
    "Dockerfile",
    "docker-compose.yml",
]

base_path = Path(__file__).parent.parent
for file_path in required_files:
    full_path = base_path / file_path
    if full_path.exists():
        test_result(f"File exists: {file_path}", True)
    else:
        test_result(f"File exists: {file_path}", False, "File not found")


# ============================================================================
# Final Summary
# ============================================================================
print("\n" + "="*80)
print("FINAL RESULTS")
print("="*80)
print(f"Total Tests: {tests_passed + tests_failed}")
print(f"✅ Passed: {tests_passed}")
print(f"❌ Failed: {tests_failed}")
print(f"Success Rate: {(tests_passed/(tests_passed+tests_failed)*100):.1f}%")

if issues_found:
    print(f"\n🐛 Issues Found ({len(issues_found)}):")
    for i, issue in enumerate(issues_found, 1):
        print(f"  {i}. {issue}")

print("="*80)

# Only exit if run directly
if __name__ == "__main__":
    sys.exit(0 if tests_failed == 0 else 1)
