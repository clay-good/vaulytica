"""
Comprehensive test suite for Vaulytica v0.21.0 Multi-Platform Ticketing Integration.

Tests all ticketing integrations:
- ServiceNow
- Jira
- PagerDuty
- Unified Ticketing Manager

Author: Vaulytica Team
Version: 0.21.0
"""

import asyncio
import os
from datetime import datetime
from typing import Dict, Any

# Test configuration
TEST_CONFIG = {
    "servicenow": {
        "enabled": bool(os.getenv("SNOW_INSTANCE")),
        "instance": os.getenv("SNOW_INSTANCE", "dev12345"),
        "username": os.getenv("SNOW_USERNAME", "admin"),
        "password": os.getenv("SNOW_PASSWORD", "password")
    },
    "jira": {
        "enabled": bool(os.getenv("JIRA_URL")),
        "base_url": os.getenv("JIRA_URL", "https://mycompany.atlassian.net"),
        "username": os.getenv("JIRA_USERNAME", "admin@mycompany.com"),
        "api_token": os.getenv("JIRA_API_TOKEN", "api_token"),
        "project_key": os.getenv("JIRA_PROJECT_KEY", "SEC")
    },
    "pagerduty": {
        "enabled": bool(os.getenv("PD_API_KEY")),
        "api_key": os.getenv("PD_API_KEY", "api_key"),
        "integration_key": os.getenv("PD_INTEGRATION_KEY", "integration_key")
    }
}


class TicketingTestSuite:
    """Comprehensive test suite for ticketing integrations."""
    
    def __init__(self):
        self.results = {
            "servicenow": [],
            "jira": [],
            "pagerduty": [],
            "unified": []
        }
        self.test_incident = None
    
    def log_test(self, platform: str, test_name: str, passed: bool, message: str = ""):
        """Log test result."""
        status = "✅ PASS" if passed else "❌ FAIL"
        result = {
            "test": test_name,
            "passed": passed,
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
        self.results[platform].append(result)
        print(f"{status} [{platform.upper()}] {test_name}: {message}")
    
    def create_test_incident(self):
        """Create a test incident."""
        from vaulytica.incidents import Incident, IncidentPriority, IncidentStatus
        from vaulytica.models import Severity

        self.test_incident = Incident(
            title="Test Security Incident - Multi-Platform Ticketing",
            description="This is a test incident for validating multi-platform ticketing integration",
            priority=IncidentPriority.P2_HIGH,
            severity=Severity.HIGH,
            affected_assets=["server-01", "server-02"],
            source_ips=["192.168.1.100", "10.0.0.50"],
            mitre_techniques=["T1190", "T1078"],
            tags=["test", "ticketing", "v0.21.0"]
        )
        print(f"\n📋 Created test incident: {self.test_incident.incident_id}")
        return self.test_incident
    
    async def test_servicenow_integration(self):
        """Test ServiceNow integration."""
        print("\n" + "="*80)
        print("🔧 TESTING SERVICENOW INTEGRATION")
        print("="*80)
        
        if not TEST_CONFIG["servicenow"]["enabled"]:
            self.log_test("servicenow", "Integration", False, "ServiceNow credentials not configured")
            return
        
        try:
            from vaulytica.servicenow_integration import (
                ServiceNowAPIClient,
                ServiceNowIncidentManager,
                ServiceNowPriority,
                ServiceNowImpact,
                ServiceNowUrgency
            )
            
            # Test 1: API Client Initialization
            try:
                client = ServiceNowAPIClient(
                    instance=TEST_CONFIG["servicenow"]["instance"],
                    username=TEST_CONFIG["servicenow"]["username"],
                    password=TEST_CONFIG["servicenow"]["password"]
                )
                self.log_test("servicenow", "API Client Init", True, "Client initialized successfully")
            except Exception as e:
                self.log_test("servicenow", "API Client Init", False, str(e))
                return
            
            # Test 2: Create Incident (Mock)
            try:
                manager = ServiceNowIncidentManager(
                    api_client=client,
                    auto_create_incidents=False,
                    auto_sync=False
                )
                
                # Test mapping functions
                priority = manager._map_severity_to_priority(self.test_incident.severity)
                self.log_test("servicenow", "Severity Mapping", 
                            priority == ServiceNowPriority.P2, 
                            f"HIGH → {priority.value}")
                
                # Test description building
                description = manager._build_incident_description(self.test_incident)
                has_required_fields = all([
                    self.test_incident.incident_id in description,
                    "Severity: HIGH" in description,
                    "Affected Assets:" in description
                ])
                self.log_test("servicenow", "Description Building", 
                            has_required_fields, 
                            f"Generated {len(description)} chars")
                
                self.log_test("servicenow", "Manager Init", True, "Manager initialized successfully")
            except Exception as e:
                self.log_test("servicenow", "Manager Init", False, str(e))
            
            # Test 3: Statistics
            try:
                stats = manager.get_statistics()
                self.log_test("servicenow", "Statistics", True, 
                            f"Incidents created: {stats['incidents_created']}")
            except Exception as e:
                self.log_test("servicenow", "Statistics", False, str(e))
            
            # Close client
            await client.close()
            
        except Exception as e:
            self.log_test("servicenow", "Integration", False, f"Error: {e}")
    
    async def test_jira_integration(self):
        """Test Jira integration."""
        print("\n" + "="*80)
        print("📋 TESTING JIRA INTEGRATION")
        print("="*80)
        
        if not TEST_CONFIG["jira"]["enabled"]:
            self.log_test("jira", "Integration", False, "Jira credentials not configured")
            return
        
        try:
            from vaulytica.jira_integration import (
                JiraAPIClient,
                JiraIssueManager,
                JiraPriority
            )
            
            # Test 1: API Client Initialization
            try:
                client = JiraAPIClient(
                    base_url=TEST_CONFIG["jira"]["base_url"],
                    username=TEST_CONFIG["jira"]["username"],
                    api_token=TEST_CONFIG["jira"]["api_token"]
                )
                self.log_test("jira", "API Client Init", True, "Client initialized successfully")
            except Exception as e:
                self.log_test("jira", "API Client Init", False, str(e))
                return
            
            # Test 2: Issue Manager
            try:
                manager = JiraIssueManager(
                    api_client=client,
                    project_key=TEST_CONFIG["jira"]["project_key"],
                    auto_create_issues=False,
                    auto_sync=False
                )
                
                # Test mapping functions
                priority = manager._map_severity_to_priority(self.test_incident.severity)
                self.log_test("jira", "Severity Mapping", 
                            priority == JiraPriority.HIGH, 
                            f"HIGH → {priority.value}")
                
                # Test description building
                description = manager._build_issue_description(self.test_incident)
                has_required_fields = all([
                    "h2. Vaulytica Incident" in description,
                    self.test_incident.incident_id in description,
                    "h2. Affected Assets" in description
                ])
                self.log_test("jira", "Description Building", 
                            has_required_fields, 
                            f"Generated {len(description)} chars with wiki markup")
                
                self.log_test("jira", "Manager Init", True, "Manager initialized successfully")
            except Exception as e:
                self.log_test("jira", "Manager Init", False, str(e))
            
            # Test 3: Statistics
            try:
                stats = manager.get_statistics()
                self.log_test("jira", "Statistics", True, 
                            f"Issues created: {stats['issues_created']}")
            except Exception as e:
                self.log_test("jira", "Statistics", False, str(e))
            
            # Close client
            await client.close()
            
        except Exception as e:
            self.log_test("jira", "Integration", False, f"Error: {e}")
    
    async def test_pagerduty_integration(self):
        """Test PagerDuty integration."""
        print("\n" + "="*80)
        print("🚨 TESTING PAGERDUTY INTEGRATION")
        print("="*80)
        
        if not TEST_CONFIG["pagerduty"]["enabled"]:
            self.log_test("pagerduty", "Integration", False, "PagerDuty credentials not configured")
            return
        
        try:
            from vaulytica.pagerduty_integration import (
                PagerDutyAPIClient,
                PagerDutyIncidentManager,
                PagerDutySeverity
            )
            
            # Test 1: API Client Initialization
            try:
                client = PagerDutyAPIClient(
                    api_key=TEST_CONFIG["pagerduty"]["api_key"],
                    integration_key=TEST_CONFIG["pagerduty"]["integration_key"]
                )
                self.log_test("pagerduty", "API Client Init", True, "Client initialized successfully")
            except Exception as e:
                self.log_test("pagerduty", "API Client Init", False, str(e))
                return
            
            # Test 2: Incident Manager
            try:
                manager = PagerDutyIncidentManager(
                    api_client=client,
                    auto_trigger_incidents=False,
                    auto_sync=False
                )
                
                # Test mapping functions
                severity = manager._map_severity_to_pd_severity(self.test_incident.severity)
                self.log_test("pagerduty", "Severity Mapping", 
                            severity == PagerDutySeverity.ERROR, 
                            f"HIGH → {severity.value}")
                
                # Test custom details building
                details = manager._build_custom_details(self.test_incident)
                has_required_fields = all([
                    "incident_id" in details,
                    "severity" in details,
                    "affected_assets" in details
                ])
                self.log_test("pagerduty", "Custom Details Building", 
                            has_required_fields, 
                            f"Generated {len(details)} fields")
                
                self.log_test("pagerduty", "Manager Init", True, "Manager initialized successfully")
            except Exception as e:
                self.log_test("pagerduty", "Manager Init", False, str(e))
            
            # Test 3: Statistics
            try:
                stats = manager.get_statistics()
                self.log_test("pagerduty", "Statistics", True, 
                            f"Incidents triggered: {stats['incidents_triggered']}")
            except Exception as e:
                self.log_test("pagerduty", "Statistics", False, str(e))
            
            # Close client
            await client.close()
            
        except Exception as e:
            self.log_test("pagerduty", "Integration", False, f"Error: {e}")
    
    async def test_unified_ticketing(self):
        """Test unified ticketing manager."""
        print("\n" + "="*80)
        print("🎯 TESTING UNIFIED TICKETING MANAGER")
        print("="*80)
        
        try:
            from vaulytica.ticketing import (
                UnifiedTicketingManager,
                TicketingConfig,
                TicketingPlatform,
                create_ticketing_config_from_env
            )
            
            # Test 1: Configuration from Environment
            try:
                config = create_ticketing_config_from_env()
                enabled_count = len(config.enabled_platforms)
                self.log_test("unified", "Config from Env", True, 
                            f"Detected {enabled_count} enabled platforms")
            except Exception as e:
                self.log_test("unified", "Config from Env", False, str(e))
                return
            
            # Test 2: Manager Initialization
            try:
                manager = UnifiedTicketingManager(config)
                self.log_test("unified", "Manager Init", True, 
                            f"Initialized with {len(config.enabled_platforms)} platforms")
            except Exception as e:
                self.log_test("unified", "Manager Init", False, str(e))
                return
            
            # Test 3: Statistics
            try:
                stats = manager.get_statistics()
                self.log_test("unified", "Statistics", True, 
                            f"Total tickets: {stats['total_tickets']}")
            except Exception as e:
                self.log_test("unified", "Statistics", False, str(e))
            
            # Test 4: Ticket Tracking
            try:
                all_tickets = manager.get_all_tickets()
                self.log_test("unified", "Ticket Tracking", True, 
                            f"Tracking {len(all_tickets)} tickets")
            except Exception as e:
                self.log_test("unified", "Ticket Tracking", False, str(e))
            
        except Exception as e:
            self.log_test("unified", "Integration", False, f"Error: {e}")
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "="*80)
        print("📊 TEST SUMMARY")
        print("="*80)
        
        total_tests = 0
        passed_tests = 0
        
        for platform, results in self.results.items():
            if results:
                platform_passed = sum(1 for r in results if r["passed"])
                platform_total = len(results)
                total_tests += platform_total
                passed_tests += platform_passed
                
                status = "✅" if platform_passed == platform_total else "⚠️"
                print(f"\n{status} {platform.upper()}: {platform_passed}/{platform_total} tests passed")
                
                for result in results:
                    status_icon = "✅" if result["passed"] else "❌"
                    print(f"  {status_icon} {result['test']}: {result['message']}")
        
        print("\n" + "="*80)
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        print(f"OVERALL: {passed_tests}/{total_tests} tests passed ({success_rate:.1f}%)")
        print("="*80)
        
        if success_rate == 100:
            print("\n🎉 ALL TESTS PASSED! Vaulytica v0.21.0 is ready for production!")
        elif success_rate >= 80:
            print("\n✅ Most tests passed. Review failures before deployment.")
        else:
            print("\n⚠️  Multiple test failures. Review and fix before deployment.")
    
    async def run_all_tests(self):
        """Run all tests."""
        print("="*80)
        print("🚀 VAULYTICA v0.21.0 - MULTI-PLATFORM TICKETING INTEGRATION TEST SUITE")
        print("="*80)
        
        # Create test incident
        self.create_test_incident()
        
        # Run tests
        await self.test_servicenow_integration()
        await self.test_jira_integration()
        await self.test_pagerduty_integration()
        await self.test_unified_ticketing()
        
        # Print summary
        self.print_summary()


async def main():
    """Main test function."""
    suite = TicketingTestSuite()
    await suite.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())

