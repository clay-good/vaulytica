import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path

from vaulytica.logger import get_logger
from vaulytica.datadog_integration import (
    DatadogAPIClient,
    DatadogCaseManager,
    DatadogCase,
    DatadogCaseStatus,
    DatadogCasePriority,
    DatadogCaseType
)
from vaulytica.models import SecurityEvent, Severity, EventCategory
from vaulytica.incidents import Incident, IncidentStatus, get_incident_manager
from vaulytica.parsers.datadog import DatadogParser

logger = get_logger(__name__)


@dataclass
class TestResult:
    """Test result data."""
    test_name: str
    passed: bool
    duration: float
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "passed": self.passed,
            "duration": self.duration,
            "message": self.message,
            "details": self.details,
            "error": self.error
        }


@dataclass
class TestSuite:
    """Test suite results."""
    name: str
    results: List[TestResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    @property
    def total_tests(self) -> int:
        """Total number of tests."""
        return len(self.results)
    
    @property
    def passed_tests(self) -> int:
        """Number of passed tests."""
        return sum(1 for r in self.results if r.passed)
    
    @property
    def failed_tests(self) -> int:
        """Number of failed tests."""
        return sum(1 for r in self.results if not r.passed)
    
    @property
    def success_rate(self) -> float:
        """Test success rate."""
        return self.passed_tests / self.total_tests if self.total_tests > 0 else 0.0
    
    @property
    def total_duration(self) -> float:
        """Total test duration."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return sum(r.duration for r in self.results)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "success_rate": self.success_rate,
            "total_duration": self.total_duration,
            "results": [r.to_dict() for r in self.results]
        }


class DatadogLiveTester:
    """Comprehensive live testing for Datadog integration."""
    
    def __init__(
        self,
        api_key: str,
        app_key: str,
        site: str = "datadoghq.com",
        test_data_dir: Optional[Path] = None
    ):
        """Initialize live tester.
        
        Args:
            api_key: Datadog API key
            app_key: Datadog application key
            site: Datadog site
            test_data_dir: Directory containing test data files
        """
        self.api_key = api_key
        self.app_key = app_key
        self.site = site
        self.test_data_dir = test_data_dir or Path("test_data")
        
        # Initialize components
        self.api_client = DatadogAPIClient(api_key, app_key, site)
        self.case_manager = DatadogCaseManager(self.api_client, auto_sync=False)
        self.parser = DatadogParser()
        
        # Test suites
        self.suites: List[TestSuite] = []
        
        logger.info("Datadog live tester initialized")
    
    async def run_all_tests(self) -> TestSuite:
        """Run all test suites."""
        suite = TestSuite(name="Datadog Integration - Full Test Suite")
        suite.start_time = datetime.now()
        
        logger.info("=" * 80)
        logger.info("DATADOG INTEGRATION - LIVE TESTING")
        logger.info("=" * 80)
        
        # Run test suites
        await self._test_api_client(suite)
        await self._test_case_management(suite)
        await self._test_live_cases(suite)
        await self._test_signal_parsing(suite)
        await self._test_incident_sync(suite)
        await self._test_workflow_automation(suite)
        
        suite.end_time = datetime.now()
        self.suites.append(suite)
        
        # Print summary
        self._print_summary(suite)
        
        return suite
    
    async def _test_api_client(self, suite: TestSuite):
        """Test Datadog API client."""
        logger.info("\n📌 Testing Datadog API Client")
        
        # Test 1: API connectivity
        start = datetime.now()
        try:
            cases = await self.api_client.list_cases(limit=1)
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="API Connectivity",
                passed=True,
                duration=duration,
                message="Successfully connected to Datadog API",
                details={"cases_found": len(cases)}
            ))
            logger.info(f"  ✅ API Connectivity - {duration:.2f}s")
        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="API Connectivity",
                passed=False,
                duration=duration,
                message="Failed to connect to Datadog API",
                error=str(e)
            ))
            logger.error(f"  ❌ API Connectivity - {e}")
        
        # Test 2: Rate limiting
        start = datetime.now()
        try:
            # Make multiple requests
            tasks = [self.api_client.list_cases(limit=1) for _ in range(5)]
            await asyncio.gather(*tasks)
            duration = (datetime.now() - start).total_seconds()
            
            stats = self.api_client.get_statistics()
            suite.results.append(TestResult(
                test_name="Rate Limiting",
                passed=stats["rate_limited_requests"] == 0,
                duration=duration,
                message="Rate limiting handled correctly",
                details=stats
            ))
            logger.info(f"  ✅ Rate Limiting - {duration:.2f}s")
        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="Rate Limiting",
                passed=False,
                duration=duration,
                message="Rate limiting test failed",
                error=str(e)
            ))
            logger.error(f"  ❌ Rate Limiting - {e}")
    
    async def _test_case_management(self, suite: TestSuite):
        """Test case management operations."""
        logger.info("\n📌 Testing Case Management")
        
        # Test 1: Create case
        start = datetime.now()
        test_case = None
        try:
            test_case = await self.api_client.create_case(
                title=f"Vaulytica Test Case - {datetime.now().isoformat()}",
                description="This is a test case created by Vaulytica automated testing",
                priority=DatadogCasePriority.P4,
                case_type=DatadogCaseType.OTHER,
                tags=["vaulytica:test", "automated:true"]
            )
            duration = (datetime.now() - start).total_seconds()
            
            if test_case:
                suite.results.append(TestResult(
                    test_name="Create Case",
                    passed=True,
                    duration=duration,
                    message=f"Successfully created test case {test_case.case_id}",
                    details={"case_id": test_case.case_id}
                ))
                logger.info(f"  ✅ Create Case - {duration:.2f}s (ID: {test_case.case_id})")
            else:
                raise Exception("Case creation returned None")
        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="Create Case",
                passed=False,
                duration=duration,
                message="Failed to create test case",
                error=str(e)
            ))
            logger.error(f"  ❌ Create Case - {e}")
        
        # Test 2: Update case
        if test_case:
            start = datetime.now()
            try:
                updated_case = await self.api_client.update_case(
                    test_case.case_id,
                    status=DatadogCaseStatus.IN_PROGRESS,
                    tags=["vaulytica:test", "automated:true", "updated:true"]
                )
                duration = (datetime.now() - start).total_seconds()
                
                suite.results.append(TestResult(
                    test_name="Update Case",
                    passed=updated_case is not None,
                    duration=duration,
                    message="Successfully updated test case",
                    details={"case_id": test_case.case_id}
                ))
                logger.info(f"  ✅ Update Case - {duration:.2f}s")
            except Exception as e:
                duration = (datetime.now() - start).total_seconds()
                suite.results.append(TestResult(
                    test_name="Update Case",
                    passed=False,
                    duration=duration,
                    message="Failed to update test case",
                    error=str(e)
                ))
                logger.error(f"  ❌ Update Case - {e}")
        
        # Test 3: Add timeline event
        if test_case:
            start = datetime.now()
            try:
                success = await self.api_client.add_timeline_event(
                    test_case.case_id,
                    event_type="comment",
                    message="Automated test timeline event",
                    metadata={"test": True, "timestamp": datetime.now().isoformat()}
                )
                duration = (datetime.now() - start).total_seconds()
                
                suite.results.append(TestResult(
                    test_name="Add Timeline Event",
                    passed=success,
                    duration=duration,
                    message="Successfully added timeline event"
                ))
                logger.info(f"  ✅ Add Timeline Event - {duration:.2f}s")
            except Exception as e:
                duration = (datetime.now() - start).total_seconds()
                suite.results.append(TestResult(
                    test_name="Add Timeline Event",
                    passed=False,
                    duration=duration,
                    message="Failed to add timeline event",
                    error=str(e)
                ))
                logger.error(f"  ❌ Add Timeline Event - {e}")
        
        # Test 4: Close case
        if test_case:
            start = datetime.now()
            try:
                closed_case = await self.api_client.close_case(
                    test_case.case_id,
                    resolution="Test completed successfully"
                )
                duration = (datetime.now() - start).total_seconds()
                
                suite.results.append(TestResult(
                    test_name="Close Case",
                    passed=closed_case is not None,
                    duration=duration,
                    message="Successfully closed test case"
                ))
                logger.info(f"  ✅ Close Case - {duration:.2f}s")
            except Exception as e:
                duration = (datetime.now() - start).total_seconds()
                suite.results.append(TestResult(
                    test_name="Close Case",
                    passed=False,
                    duration=duration,
                    message="Failed to close test case",
                    error=str(e)
                ))
                logger.error(f"  ❌ Close Case - {e}")

    async def _test_live_cases(self, suite: TestSuite):
        """Test with live Datadog cases."""
        logger.info("\n📌 Testing with Live Datadog Cases")

        # Test 1: List live cases
        start = datetime.now()
        try:
            cases = await self.api_client.list_cases(limit=10)
            duration = (datetime.now() - start).total_seconds()

            suite.results.append(TestResult(
                test_name="List Live Cases",
                passed=True,
                duration=duration,
                message=f"Successfully retrieved {len(cases)} live cases",
                details={
                    "total_cases": len(cases),
                    "statuses": {status.value: sum(1 for c in cases if c.status == status)
                                for status in DatadogCaseStatus},
                    "priorities": {priority.value: sum(1 for c in cases if c.priority == priority)
                                  for priority in DatadogCasePriority}
                }
            ))
            logger.info(f"  ✅ List Live Cases - {duration:.2f}s ({len(cases)} cases)")

            # Log case details
            for case in cases[:3]:
                logger.info(f"    - {case.case_id}: {case.title} [{case.status.value}/{case.priority.value}]")

        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="List Live Cases",
                passed=False,
                duration=duration,
                message="Failed to retrieve live cases",
                error=str(e)
            ))
            logger.error(f"  ❌ List Live Cases - {e}")

    async def _test_signal_parsing(self, suite: TestSuite):
        """Test Datadog signal parsing."""
        logger.info("\n📌 Testing Signal Parsing")

        # Load test signals
        test_files = list(self.test_data_dir.glob("datadog_*.json"))

        if not test_files:
            logger.warning("  ⚠️  No test signal files found")
            return

        for test_file in test_files:
            start = datetime.now()
            try:
                with open(test_file) as f:
                    signal_data = json.load(f)

                # Parse signal
                event = self.parser.parse(signal_data)
                duration = (datetime.now() - start).total_seconds()

                suite.results.append(TestResult(
                    test_name=f"Parse Signal - {test_file.name}",
                    passed=True,
                    duration=duration,
                    message=f"Successfully parsed signal from {test_file.name}",
                    details={
                        "event_id": event.event_id,
                        "severity": event.severity.value,
                        "category": event.category.value,
                        "assets": len(event.affected_assets),
                        "indicators": len(event.technical_indicators)
                    }
                ))
                logger.info(f"  ✅ Parse Signal - {test_file.name} - {duration:.2f}s")

            except Exception as e:
                duration = (datetime.now() - start).total_seconds()
                suite.results.append(TestResult(
                    test_name=f"Parse Signal - {test_file.name}",
                    passed=False,
                    duration=duration,
                    message=f"Failed to parse signal from {test_file.name}",
                    error=str(e)
                ))
                logger.error(f"  ❌ Parse Signal - {test_file.name} - {e}")

    async def _test_incident_sync(self, suite: TestSuite):
        """Test incident synchronization."""
        logger.info("\n📌 Testing Incident Synchronization")

        # Create test incident
        from vaulytica.models import AssetInfo, TechnicalIndicator

        test_event = SecurityEvent(
            event_id="test-event-001",
            source_system="Datadog Security Monitoring",
            timestamp=datetime.now(),
            severity=Severity.HIGH,
            category=EventCategory.MALWARE,
            title="Test Malware Detection",
            description="Automated test for incident sync",
            affected_assets=[
                AssetInfo(
                    hostname="test-host-001",
                    ip_addresses=["192.168.1.100"],
                    environment="test"
                )
            ],
            technical_indicators=[
                TechnicalIndicator(
                    indicator_type="file_hash",
                    value="abc123def456",
                    context="Test malware hash"
                )
            ],
            confidence_score=0.95
        )

        # Create incident
        incident_manager = get_incident_manager()
        incident, is_new = incident_manager.process_event(test_event, None)

        # Test 1: Create case from incident
        start = datetime.now()
        try:
            case = await self.case_manager.create_case_from_incident(incident, None)
            duration = (datetime.now() - start).total_seconds()

            if case:
                suite.results.append(TestResult(
                    test_name="Create Case from Incident",
                    passed=True,
                    duration=duration,
                    message=f"Successfully created case {case.case_id} from incident {incident.incident_id}",
                    details={
                        "incident_id": incident.incident_id,
                        "case_id": case.case_id,
                        "priority": case.priority.value
                    }
                ))
                logger.info(f"  ✅ Create Case from Incident - {duration:.2f}s")

                # Test 2: Sync incident to case
                start = datetime.now()
                try:
                    # Update incident status
                    incident.status = IncidentStatus.INVESTIGATING

                    # Sync to case
                    success = await self.case_manager.sync_incident_to_case(incident, case.case_id)
                    duration = (datetime.now() - start).total_seconds()

                    suite.results.append(TestResult(
                        test_name="Sync Incident to Case",
                        passed=success,
                        duration=duration,
                        message="Successfully synced incident updates to case"
                    ))
                    logger.info(f"  ✅ Sync Incident to Case - {duration:.2f}s")

                except Exception as e:
                    duration = (datetime.now() - start).total_seconds()
                    suite.results.append(TestResult(
                        test_name="Sync Incident to Case",
                        passed=False,
                        duration=duration,
                        message="Failed to sync incident to case",
                        error=str(e)
                    ))
                    logger.error(f"  ❌ Sync Incident to Case - {e}")

                # Clean up: close test case
                try:
                    await self.api_client.close_case(case.case_id, "Test completed")
                except:
                    pass
            else:
                raise Exception("Case creation returned None")

        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="Create Case from Incident",
                passed=False,
                duration=duration,
                message="Failed to create case from incident",
                error=str(e)
            ))
            logger.error(f"  ❌ Create Case from Incident - {e}")

    async def _test_workflow_automation(self, suite: TestSuite):
        """Test workflow automation."""
        logger.info("\n📌 Testing Workflow Automation")

        # Test 1: Case manager statistics
        start = datetime.now()
        try:
            stats = self.case_manager.get_statistics()
            duration = (datetime.now() - start).total_seconds()

            suite.results.append(TestResult(
                test_name="Case Manager Statistics",
                passed=True,
                duration=duration,
                message="Successfully retrieved case manager statistics",
                details=stats
            ))
            logger.info(f"  ✅ Case Manager Statistics - {duration:.2f}s")
            logger.info(f"    - Total mappings: {stats['total_mappings']}")
            logger.info(f"    - Cases created: {stats['cases_created']}")
            logger.info(f"    - Sync success rate: {stats['sync_success_rate']:.2%}")

        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="Case Manager Statistics",
                passed=False,
                duration=duration,
                message="Failed to retrieve statistics",
                error=str(e)
            ))
            logger.error(f"  ❌ Case Manager Statistics - {e}")

        # Test 2: API client statistics
        start = datetime.now()
        try:
            stats = self.api_client.get_statistics()
            duration = (datetime.now() - start).total_seconds()

            suite.results.append(TestResult(
                test_name="API Client Statistics",
                passed=True,
                duration=duration,
                message="Successfully retrieved API client statistics",
                details=stats
            ))
            logger.info(f"  ✅ API Client Statistics - {duration:.2f}s")
            logger.info(f"    - Total requests: {stats['total_requests']}")
            logger.info(f"    - Success rate: {stats['success_rate']:.2%}")
            logger.info(f"    - Rate limited: {stats['rate_limited_requests']}")

        except Exception as e:
            duration = (datetime.now() - start).total_seconds()
            suite.results.append(TestResult(
                test_name="API Client Statistics",
                passed=False,
                duration=duration,
                message="Failed to retrieve API statistics",
                error=str(e)
            ))
            logger.error(f"  ❌ API Client Statistics - {e}")

    def _print_summary(self, suite: TestSuite):
        """Print test summary."""
        logger.info("\n" + "=" * 80)
        logger.info("TEST SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total Tests: {suite.total_tests}")
        logger.info(f"Passed: {suite.passed_tests} ✅")
        logger.info(f"Failed: {suite.failed_tests} ❌")
        logger.info(f"Success Rate: {suite.success_rate:.1%}")
        logger.info(f"Total Duration: {suite.total_duration:.2f}s")
        logger.info("=" * 80)

        if suite.failed_tests > 0:
            logger.info("\nFailed Tests:")
            for result in suite.results:
                if not result.passed:
                    logger.info(f"  ❌ {result.test_name}: {result.error}")

    def save_results(self, output_file: Path):
        """Save test results to file."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "suites": [suite.to_dict() for suite in self.suites]
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        logger.info(f"Test results saved to {output_file}")


async def run_live_tests(
    api_key: Optional[str] = None,
    app_key: Optional[str] = None,
    site: str = "datadoghq.com",
    output_file: Optional[Path] = None
) -> TestSuite:
    """Run live Datadog integration tests.

    Args:
        api_key: Datadog API key (or set DD_API_KEY env var)
        app_key: Datadog app key (or set DD_APP_KEY env var)
        site: Datadog site
        output_file: Optional output file for results

    Returns:
        Test suite with results
    """
    # Get credentials from environment if not provided
    api_key = api_key or os.getenv("DD_API_KEY")
    app_key = app_key or os.getenv("DD_APP_KEY")

    if not api_key or not app_key:
        raise ValueError(
            "Datadog credentials required. "
            "Provide api_key/app_key or set DD_API_KEY/DD_APP_KEY environment variables"
        )

    # Run tests
    tester = DatadogLiveTester(api_key, app_key, site)
    suite = await tester.run_all_tests()

    # Save results
    if output_file:
        tester.save_results(output_file)

    return suite

