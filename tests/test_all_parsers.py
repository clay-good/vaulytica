#!/usr/bin/env python3

import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.parsers.guardduty import GuardDutyParser
from vaulytica.parsers.gcp_scc import GCPSCCParser
from vaulytica.parsers.snowflake import SnowflakeParser
from vaulytica.parsers.datadog import DatadogParser
from vaulytica.parsers.crowdstrike import CrowdStrikeParser


def load_test_data(filename):
    """Load test data from file"""
    test_data_path = Path(__file__).parent.parent / "test_data" / filename
    with open(test_data_path, 'r') as f:
        return json.load(f)


def test_guardduty_parser():
    """Test GuardDuty parser with multiple test files"""
    print("\n" + "="*80)
    print("TESTING GUARDDUTY PARSER")
    print("="*80)
    
    parser = GuardDutyParser()
    test_files = [
        "guardduty_ssh_bruteforce.json",
        "guardduty_backdoor_c2.json",
        "guardduty_crypto_mining.json",
        "guardduty_cryptojacking_advanced.json",
        "guardduty_ransomware.json"
    ]
    
    passed = 0
    failed = 0
    
    for test_file in test_files:
        try:
            print(f"\n📄 Testing: {test_file}")
            data = load_test_data(test_file)
            event = parser.parse(data)
            
            # Validate required fields
            assert event.event_id, "Missing event_id"
            assert event.timestamp, "Missing timestamp"
            assert event.severity, "Missing severity"
            assert event.category, "Missing category"
            assert event.description, "Missing description"
            
            print(f"   ✅ PASSED")
            print(f"   Event ID: {event.event_id}")
            print(f"   Severity: {event.severity}")
            print(f"   Category: {event.category}")
            print(f"   Description: {event.description[:80]}...")
            passed += 1
            
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            failed += 1
    
    print(f"\n📊 GuardDuty Results: {passed} passed, {failed} failed")
    return passed, failed


def test_gcp_scc_parser():
    """Test GCP SCC parser"""
    print("\n" + "="*80)
    print("TESTING GCP SCC PARSER")
    print("="*80)
    
    parser = GCPSCCParser()
    test_files = ["gcp_scc_privilege_escalation.json"]
    
    passed = 0
    failed = 0
    
    for test_file in test_files:
        try:
            print(f"\n📄 Testing: {test_file}")
            data = load_test_data(test_file)
            event = parser.parse(data)
            
            # Validate required fields
            assert event.event_id, "Missing event_id"
            assert event.timestamp, "Missing timestamp"
            assert event.severity, "Missing severity"
            assert event.category, "Missing category"
            assert event.description, "Missing description"
            
            print(f"   ✅ PASSED")
            print(f"   Event ID: {event.event_id}")
            print(f"   Severity: {event.severity}")
            print(f"   Category: {event.category}")
            print(f"   Description: {event.description[:80]}...")
            passed += 1
            
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            failed += 1
    
    print(f"\n📊 GCP SCC Results: {passed} passed, {failed} failed")
    return passed, failed


def test_snowflake_parser():
    """Test Snowflake parser"""
    print("\n" + "="*80)
    print("TESTING SNOWFLAKE PARSER")
    print("="*80)
    
    parser = SnowflakeParser()
    test_files = [
        "snowflake_data_exfiltration.json",
        "snowflake_privilege_escalation.json",
        "snowflake_unauthorized_access.json"
    ]
    
    passed = 0
    failed = 0
    
    for test_file in test_files:
        try:
            print(f"\n📄 Testing: {test_file}")
            data = load_test_data(test_file)
            event = parser.parse(data)
            
            # Validate required fields
            assert event.event_id, "Missing event_id"
            assert event.timestamp, "Missing timestamp"
            assert event.severity, "Missing severity"
            assert event.category, "Missing category"
            assert event.description, "Missing description"
            
            print(f"   ✅ PASSED")
            print(f"   Event ID: {event.event_id}")
            print(f"   Severity: {event.severity}")
            print(f"   Category: {event.category}")
            print(f"   Description: {event.description[:80]}...")
            passed += 1
            
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            failed += 1
    
    print(f"\n📊 Snowflake Results: {passed} passed, {failed} failed")
    return passed, failed


def test_datadog_parser():
    """Test Datadog parser"""
    print("\n" + "="*80)
    print("TESTING DATADOG PARSER")
    print("="*80)
    
    parser = DatadogParser()
    test_files = ["datadog_data_exfiltration.json"]
    
    passed = 0
    failed = 0
    
    for test_file in test_files:
        try:
            print(f"\n📄 Testing: {test_file}")
            data = load_test_data(test_file)
            event = parser.parse(data)
            
            # Validate required fields
            assert event.event_id, "Missing event_id"
            assert event.timestamp, "Missing timestamp"
            assert event.severity, "Missing severity"
            assert event.category, "Missing category"
            assert event.description, "Missing description"
            
            print(f"   ✅ PASSED")
            print(f"   Event ID: {event.event_id}")
            print(f"   Severity: {event.severity}")
            print(f"   Category: {event.category}")
            print(f"   Description: {event.description[:80]}...")
            passed += 1
            
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            failed += 1
    
    print(f"\n📊 Datadog Results: {passed} passed, {failed} failed")
    return passed, failed


def test_crowdstrike_parser():
    """Test CrowdStrike parser"""
    print("\n" + "="*80)
    print("TESTING CROWDSTRIKE PARSER")
    print("="*80)
    
    parser = CrowdStrikeParser()
    test_files = ["crowdstrike_insider_threat.json"]
    
    passed = 0
    failed = 0
    
    for test_file in test_files:
        try:
            print(f"\n📄 Testing: {test_file}")
            data = load_test_data(test_file)
            event = parser.parse(data)
            
            # Validate required fields
            assert event.event_id, "Missing event_id"
            assert event.timestamp, "Missing timestamp"
            assert event.severity, "Missing severity"
            assert event.category, "Missing category"
            assert event.description, "Missing description"
            
            print(f"   ✅ PASSED")
            print(f"   Event ID: {event.event_id}")
            print(f"   Severity: {event.severity}")
            print(f"   Category: {event.category}")
            print(f"   Description: {event.description[:80]}...")
            passed += 1
            
        except Exception as e:
            print(f"   ❌ FAILED: {e}")
            failed += 1
    
    print(f"\n📊 CrowdStrike Results: {passed} passed, {failed} failed")
    return passed, failed


def main():
    """Run all parser tests"""
    print("="*80)
    print("VAULYTICA COMPREHENSIVE PARSER TESTING")
    print("="*80)
    
    total_passed = 0
    total_failed = 0
    
    # Test all parsers
    p, f = test_guardduty_parser()
    total_passed += p
    total_failed += f
    
    p, f = test_gcp_scc_parser()
    total_passed += p
    total_failed += f
    
    p, f = test_snowflake_parser()
    total_passed += p
    total_failed += f
    
    p, f = test_datadog_parser()
    total_passed += p
    total_failed += f
    
    p, f = test_crowdstrike_parser()
    total_passed += p
    total_failed += f
    
    # Final summary
    print("\n" + "="*80)
    print("FINAL RESULTS")
    print("="*80)
    print(f"Total Tests: {total_passed + total_failed}")
    print(f"✅ Passed: {total_passed}")
    print(f"❌ Failed: {total_failed}")
    print(f"Success Rate: {(total_passed/(total_passed+total_failed)*100):.1f}%")
    print("="*80)
    
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

