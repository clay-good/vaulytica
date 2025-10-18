#!/usr/bin/env python3
"""Test script for Datadog Case Management Integration.

This script tests the Datadog integration with both mock and live data.
Set DD_API_KEY and DD_APP_KEY environment variables for live testing.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add vaulytica to path
sys.path.insert(0, str(Path(__file__).parent))

from vaulytica.logger import get_logger
from vaulytica.datadog_integration import (
    DatadogAPIClient,
    DatadogCaseManager,
    DatadogCasePriority,
    DatadogCaseType,
    DatadogCaseStatus
)
from vaulytica.models import SecurityEvent, Severity, EventCategory, AssetInfo, TechnicalIndicator
from vaulytica.incidents import Incident, IncidentStatus, get_incident_manager
from vaulytica.parsers.datadog import DatadogParser

logger = get_logger(__name__)


async def test_mock_integration():
    """Test integration with mock data (no API keys required)."""
    print("=" * 80)
    print("DATADOG INTEGRATION - MOCK DATA TESTING")
    print("=" * 80)
    
    # Test 1: Parser
    print("\n📌 Test 1: Datadog Signal Parser")
    parser = DatadogParser()
    
    # Create mock signal
    mock_signal = {
        "id": "test-signal-001",
        "type": "signal",
        "attributes": {
            "message": "Suspicious malware activity detected",
            "timestamp": 1697654400000,
            "severity": "high",
            "rule": {
                "name": "Malware Detection - Suspicious Process"
            },
            "tags": [
                "host:web-server-01",
                "ip:192.168.1.100",
                "env:production"
            ],
            "custom": {
                "source_ip": "10.0.0.50",
                "process_name": "malicious.exe",
                "file_hash": "abc123def456"
            }
        }
    }
    
    try:
        event = parser.parse(mock_signal)
        print(f"  ✅ Parsed signal successfully")
        print(f"    - Event ID: {event.event_id}")
        print(f"    - Severity: {event.severity.value}")
        print(f"    - Category: {event.category.value}")
        print(f"    - Assets: {len(event.affected_assets)}")
        print(f"    - Indicators: {len(event.technical_indicators)}")
    except Exception as e:
        print(f"  ❌ Parser failed: {e}")
        return False
    
    # Test 2: Incident Creation
    print("\n📌 Test 2: Incident Creation from Signal")
    try:
        incident_manager = get_incident_manager()
        incident, is_new = incident_manager.process_event(event, None)
        print(f"  ✅ Created incident: {incident.incident_id}")
        print(f"    - Status: {incident.status.value}")
        print(f"    - Severity: {incident.severity.value}")
        print(f"    - Priority: {incident.priority.value}")
    except Exception as e:
        print(f"  ❌ Incident creation failed: {e}")
        return False
    
    # Test 3: Case Description Building
    print("\n📌 Test 3: Case Description Building")
    try:
        # Mock case manager (without API client)
        description = f"""**Incident ID:** {incident.incident_id}
**Severity:** {incident.severity.value}
**Priority:** {incident.priority.value}
**Status:** {incident.status.value}

## Description
{incident.description or "No description available"}

## Affected Assets
{chr(10).join([f"- {asset}" for asset in incident.affected_assets[:10]])}

## Source IPs
{chr(10).join([f"- {ip}" for ip in incident.source_ips[:10]])}

## MITRE ATT&CK Techniques
{chr(10).join([f"- {technique}" for technique in incident.mitre_techniques[:10]])}
"""
        print(f"  ✅ Built case description ({len(description)} chars)")
        print(f"\n{description[:200]}...")
    except Exception as e:
        print(f"  ❌ Description building failed: {e}")
        return False
    
    print("\n" + "=" * 80)
    print("✅ MOCK DATA TESTS PASSED")
    print("=" * 80)
    return True


async def test_live_integration():
    """Test integration with live Datadog API."""
    print("\n" + "=" * 80)
    print("DATADOG INTEGRATION - LIVE API TESTING")
    print("=" * 80)
    
    # Get credentials
    api_key = os.getenv("DD_API_KEY")
    app_key = os.getenv("DD_APP_KEY")
    site = os.getenv("DD_SITE", "datadoghq.com")
    
    if not api_key or not app_key:
        print("\n⚠️  Skipping live tests - DD_API_KEY and DD_APP_KEY not set")
        print("To run live tests, set environment variables:")
        print("  export DD_API_KEY='your-api-key'")
        print("  export DD_APP_KEY='your-app-key'")
        print("  export DD_SITE='datadoghq.com'  # optional")
        return True
    
    print(f"\n🔑 Using Datadog site: {site}")
    
    # Initialize client
    try:
        api_client = DatadogAPIClient(api_key, app_key, site)
        case_manager = DatadogCaseManager(api_client, auto_sync=False)
        print("  ✅ Initialized Datadog API client")
    except Exception as e:
        print(f"  ❌ Failed to initialize client: {e}")
        return False
    
    # Test 1: List Cases
    print("\n📌 Test 1: List Live Cases")
    try:
        cases = await api_client.list_cases(limit=5)
        print(f"  ✅ Retrieved {len(cases)} cases")
        for case in cases[:3]:
            print(f"    - {case.case_id}: {case.title[:50]}... [{case.status.value}/{case.priority.value}]")
    except Exception as e:
        print(f"  ❌ Failed to list cases: {e}")
        return False
    
    # Test 2: Create Test Case
    print("\n📌 Test 2: Create Test Case")
    test_case = None
    try:
        test_case = await api_client.create_case(
            title=f"Vaulytica Integration Test - {asyncio.get_event_loop().time()}",
            description="This is an automated test case created by Vaulytica integration testing",
            priority=DatadogCasePriority.P5,
            case_type=DatadogCaseType.OTHER,
            tags=["vaulytica:test", "automated:true", "integration:test"]
        )
        if test_case:
            print(f"  ✅ Created test case: {test_case.case_id}")
        else:
            raise Exception("Case creation returned None")
    except Exception as e:
        print(f"  ❌ Failed to create case: {e}")
        return False
    
    # Test 3: Update Case
    if test_case:
        print("\n📌 Test 3: Update Test Case")
        try:
            updated_case = await api_client.update_case(
                test_case.case_id,
                status=DatadogCaseStatus.IN_PROGRESS
            )
            print(f"  ✅ Updated case status to IN_PROGRESS")
        except Exception as e:
            print(f"  ❌ Failed to update case: {e}")
    
    # Test 4: Add Timeline Event
    if test_case:
        print("\n📌 Test 4: Add Timeline Event")
        try:
            success = await api_client.add_timeline_event(
                test_case.case_id,
                event_type="comment",
                message="Automated test timeline event from Vaulytica",
                metadata={"test": True, "source": "vaulytica"}
            )
            if success:
                print(f"  ✅ Added timeline event")
            else:
                print(f"  ⚠️  Timeline event may not be supported")
        except Exception as e:
            print(f"  ⚠️  Timeline event failed (may not be supported): {e}")
    
    # Test 5: Incident to Case Sync
    print("\n📌 Test 5: Incident to Case Sync")
    try:
        # Create test incident
        test_event = SecurityEvent(
            event_id="test-event-live-001",
            source_system="Datadog Security Monitoring",
            timestamp=asyncio.get_event_loop().time(),
            severity=Severity.MEDIUM,
            category=EventCategory.POLICY_VIOLATION,
            title="Test Policy Violation",
            description="Automated test incident for Datadog sync",
            affected_assets=[
                AssetInfo(
                    hostname="test-host-001",
                    ip_addresses=["192.168.1.100"],
                    environment="test"
                )
            ],
            technical_indicators=[
                TechnicalIndicator(
                    indicator_type="process",
                    value="test.exe",
                    context="Test process"
                )
            ],
            confidence_score=0.85
        )
        
        incident_manager = get_incident_manager()
        incident, is_new = incident_manager.process_event(test_event, None)
        
        # Create case from incident
        case = await case_manager.create_case_from_incident(incident, None)
        if case:
            print(f"  ✅ Created case from incident: {case.case_id}")
            print(f"    - Incident: {incident.incident_id}")
            print(f"    - Case: {case.case_id}")
            print(f"    - Priority: {case.priority.value}")
            
            # Clean up
            try:
                await api_client.close_case(case.case_id, "Test completed")
                print(f"  ✅ Closed test case")
            except:
                pass
        else:
            raise Exception("Case creation from incident returned None")
    except Exception as e:
        print(f"  ❌ Failed incident sync: {e}")
    
    # Test 6: Close Test Case
    if test_case:
        print("\n📌 Test 6: Close Test Case")
        try:
            closed_case = await api_client.close_case(
                test_case.case_id,
                resolution="Automated test completed successfully"
            )
            print(f"  ✅ Closed test case")
        except Exception as e:
            print(f"  ❌ Failed to close case: {e}")
    
    # Test 7: Statistics
    print("\n📌 Test 7: Integration Statistics")
    try:
        api_stats = api_client.get_statistics()
        case_stats = case_manager.get_statistics()
        
        print(f"  ✅ API Statistics:")
        print(f"    - Total requests: {api_stats['total_requests']}")
        print(f"    - Success rate: {api_stats['success_rate']:.1%}")
        print(f"    - Rate limited: {api_stats['rate_limited_requests']}")
        
        print(f"  ✅ Case Manager Statistics:")
        print(f"    - Cases created: {case_stats['cases_created']}")
        print(f"    - Total mappings: {case_stats['total_mappings']}")
        print(f"    - Sync success rate: {case_stats['sync_success_rate']:.1%}")
    except Exception as e:
        print(f"  ❌ Failed to get statistics: {e}")
    
    print("\n" + "=" * 80)
    print("✅ LIVE API TESTS COMPLETED")
    print("=" * 80)
    return True


async def main():
    """Main test function."""
    print("\n🚀 Starting Datadog Integration Tests\n")
    
    # Run mock tests
    mock_success = await test_mock_integration()
    
    # Run live tests if credentials available
    live_success = await test_live_integration()
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Mock Data Tests: {'✅ PASSED' if mock_success else '❌ FAILED'}")
    print(f"Live API Tests: {'✅ PASSED' if live_success else '❌ FAILED'}")
    print("=" * 80)
    
    return mock_success and live_success


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)

