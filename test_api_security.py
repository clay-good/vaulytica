"""
Comprehensive tests for API Security & Application Security Testing (v0.26.0).

Tests all components:
- API Security Scanner
- Application Security Tester
- API Threat Protection
- Security Automation
- Vulnerability Reporter
- API Security Orchestrator
"""

import asyncio
import sys
from datetime import datetime


def test_api_security_scanner():
    """Test API security scanner."""
    print("\n" + "="*80)
    print("TEST 1: API Security Scanner")
    print("="*80)
    
    from vaulytica.api_security import get_api_scanner, APIEndpoint, APIMethod, AuthType
    
    scanner = get_api_scanner()
    
    # Create test endpoints
    endpoints = [
        APIEndpoint(
            endpoint_id="ep-001",
            path="/api/users/{id}",
            method=APIMethod.GET,
            auth_type=AuthType.NONE,
            parameters=["id", "user_id"],
            requires_auth=False
        ),
        APIEndpoint(
            endpoint_id="ep-002",
            path="/api/login",
            method=APIMethod.POST,
            auth_type=AuthType.BASIC,
            parameters=["username", "password"],
            requires_auth=True
        ),
        APIEndpoint(
            endpoint_id="ep-003",
            path="/api/data",
            method=APIMethod.GET,
            auth_type=AuthType.JWT,
            parameters=["query", "filter"],
            requires_auth=True,
            rate_limit=None
        )
    ]
    
    # Scan endpoints
    async def scan_all():
        all_vulns = []
        for endpoint in endpoints:
            vulns = await scanner.scan_endpoint(endpoint)
            all_vulns.extend(vulns)
            print(f"\n✓ Scanned {endpoint.method.value} {endpoint.path}")
            print(f"  Vulnerabilities found: {len(vulns)}")
            for vuln in vulns:
                print(f"  - {vuln.vulnerability_type.value}: {vuln.description}")
                print(f"    Severity: {vuln.severity.value}, CVSS: {vuln.cvss_score}")
        return all_vulns
    
    vulnerabilities = asyncio.run(scan_all())
    
    # Get statistics
    stats = scanner.get_statistics()
    
    print(f"\n📊 Scanner Statistics:")
    print(f"  Endpoints scanned: {stats['endpoints_scanned']}")
    print(f"  Vulnerabilities found: {stats['vulnerabilities_found']}")
    print(f"  Tests executed: {stats['tests_executed']}")
    print(f"  By severity: {stats['by_severity']}")
    
    assert stats['endpoints_scanned'] == 3, "Should scan 3 endpoints"
    assert stats['vulnerabilities_found'] > 0, "Should find vulnerabilities"
    
    print("\n✅ API Security Scanner test PASSED!")
    return True


def test_application_security_tester():
    """Test application security tester."""
    print("\n" + "="*80)
    print("TEST 2: Application Security Tester")
    print("="*80)
    
    from vaulytica.api_security import get_app_tester
    
    tester = get_app_tester()
    
    target = "https://example.com/api/users"
    parameters = ["id", "query", "comment", "url"]
    
    async def run_tests():
        # Test SQL injection
        print("\n🔍 Testing SQL Injection...")
        sql_vulns = await tester.test_sql_injection(target, ["id", "query"])
        print(f"  SQL injection vulnerabilities: {len(sql_vulns)}")
        
        # Test XSS
        print("\n🔍 Testing XSS...")
        xss_vulns = await tester.test_xss(target, ["comment", "message"])
        print(f"  XSS vulnerabilities: {len(xss_vulns)}")
        
        # Test CSRF
        print("\n🔍 Testing CSRF...")
        csrf_vulns = await tester.test_csrf(target)
        print(f"  CSRF vulnerabilities: {len(csrf_vulns)}")
        
        # Test SSRF
        print("\n🔍 Testing SSRF...")
        ssrf_vulns = await tester.test_ssrf(target, ["url", "callback"])
        print(f"  SSRF vulnerabilities: {len(ssrf_vulns)}")
        
        return sql_vulns + xss_vulns + csrf_vulns + ssrf_vulns
    
    vulnerabilities = asyncio.run(run_tests())
    
    # Get statistics
    stats = tester.get_statistics()
    
    print(f"\n📊 Tester Statistics:")
    print(f"  Tests executed: {stats['tests_executed']}")
    print(f"  Tests passed: {stats['tests_passed']}")
    print(f"  Tests failed: {stats['tests_failed']}")
    print(f"  Vulnerabilities found: {stats['vulnerabilities_found']}")
    
    assert stats['tests_executed'] > 0, "Should execute tests"
    assert stats['vulnerabilities_found'] > 0, "Should find vulnerabilities"
    
    print("\n✅ Application Security Tester test PASSED!")
    return True


def test_api_threat_protection():
    """Test API threat protection."""
    print("\n" + "="*80)
    print("TEST 3: API Threat Protection")
    print("="*80)
    
    from vaulytica.api_security import get_threat_protection
    
    protection = get_threat_protection()
    
    async def analyze_requests():
        threats = []
        
        # Test bot detection
        print("\n🔍 Testing Bot Detection...")
        threat = await protection.analyze_request(
            source_ip="192.168.1.100",
            endpoint="/api/data",
            method="GET",
            user_agent="python-requests/2.28.0",
            headers={}
        )
        if threat:
            threats.append(threat)
            print(f"  ✓ Bot detected: {threat.description}")
        
        # Test credential stuffing
        print("\n🔍 Testing Credential Stuffing Detection...")
        for i in range(15):
            threat = await protection.analyze_request(
                source_ip="10.0.0.50",
                endpoint="/api/login",
                method="POST",
                user_agent="Mozilla/5.0",
                headers={}
            )
            if threat:
                threats.append(threat)
                print(f"  ✓ Credential stuffing detected: {threat.description}")
                break
        
        # Test API abuse
        print("\n🔍 Testing API Abuse Detection...")
        for i in range(105):
            threat = await protection.analyze_request(
                source_ip="172.16.0.10",
                endpoint="/api/search",
                method="GET",
                user_agent="Mozilla/5.0",
                headers={}
            )
            if threat:
                threats.append(threat)
                print(f"  ✓ API abuse detected: {threat.description}")
                break
        
        return threats
    
    threats = asyncio.run(analyze_requests())
    
    # Get statistics
    stats = protection.get_statistics()
    
    print(f"\n📊 Threat Protection Statistics:")
    print(f"  Requests analyzed: {stats['requests_analyzed']}")
    print(f"  Threats detected: {stats['threats_detected']}")
    print(f"  By type: {stats['by_type']}")
    
    assert stats['requests_analyzed'] > 0, "Should analyze requests"
    assert stats['threats_detected'] > 0, "Should detect threats"
    
    print("\n✅ API Threat Protection test PASSED!")
    return True


def test_security_automation():
    """Test security automation."""
    print("\n" + "="*80)
    print("TEST 4: Security Automation")
    print("="*80)
    
    from vaulytica.api_security import get_security_automation
    
    automation = get_security_automation()
    
    async def run_automation():
        # Schedule scan
        print("\n🔍 Scheduling Security Scan...")
        scan = await automation.schedule_scan(
            target="https://example.com",
            scan_type="api",
            frequency="daily"
        )
        print(f"  ✓ Scheduled scan: {scan['scan_id']}")
        print(f"    Type: {scan['scan_type']}, Frequency: {scan['frequency']}")
        
        # Execute scan
        print("\n🔍 Executing Security Scan...")
        report = await automation.execute_scan(
            target="https://example.com/api",
            scan_type="app"
        )
        print(f"  ✓ Scan completed: {report.report_id}")
        print(f"    Vulnerabilities: {len(report.vulnerabilities)}")
        print(f"    Critical: {report.critical_count}, High: {report.high_count}")
        print(f"    Risk score: {report.overall_risk_score:.2f}")
        
        return report
    
    report = asyncio.run(run_automation())
    
    # Get statistics
    stats = automation.get_statistics()
    
    print(f"\n📊 Automation Statistics:")
    print(f"  Scans executed: {stats['scans_executed']}")
    print(f"  Vulnerabilities found: {stats['vulnerabilities_found']}")
    
    assert stats['scans_executed'] > 0, "Should execute scans"
    assert len(report.vulnerabilities) > 0, "Should find vulnerabilities"
    
    print("\n✅ Security Automation test PASSED!")
    return True


def test_vulnerability_reporter():
    """Test vulnerability reporter."""
    print("\n" + "="*80)
    print("TEST 5: Vulnerability Reporter")
    print("="*80)
    
    from vaulytica.api_security import (
        get_vulnerability_reporter,
        get_api_scanner,
        APIEndpoint,
        APIMethod,
        AuthType
    )
    
    reporter = get_vulnerability_reporter()
    scanner = get_api_scanner()
    
    async def generate_report():
        # Scan endpoint to get vulnerabilities
        endpoint = APIEndpoint(
            endpoint_id="ep-test",
            path="/api/admin",
            method=APIMethod.POST,
            auth_type=AuthType.NONE,
            parameters=["id", "query"],
            requires_auth=False
        )
        
        vulns = await scanner.scan_endpoint(endpoint)
        
        # Generate report
        print("\n📝 Generating Vulnerability Report...")
        report = await reporter.generate_report("https://example.com", vulns)
        
        print(f"  ✓ Report generated: {report.report_id}")
        print(f"    Target: {report.scan_target}")
        print(f"    Total vulnerabilities: {len(report.vulnerabilities)}")
        print(f"    Critical: {report.critical_count}")
        print(f"    High: {report.high_count}")
        print(f"    Medium: {report.medium_count}")
        print(f"    Low: {report.low_count}")
        print(f"    Overall risk score: {report.overall_risk_score:.2f}")
        
        # Export report
        print("\n📤 Exporting Report...")
        json_report = reporter.export_report(report, format="json")
        print(f"  ✓ Exported as JSON ({len(json_report)} bytes)")
        
        return report
    
    report = asyncio.run(generate_report())
    
    # Get statistics
    stats = reporter.get_statistics()
    
    print(f"\n📊 Reporter Statistics:")
    print(f"  Reports generated: {stats['reports_generated']}")
    print(f"  Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"  Critical vulnerabilities: {stats['critical_vulnerabilities']}")
    
    assert stats['reports_generated'] > 0, "Should generate reports"
    
    print("\n✅ Vulnerability Reporter test PASSED!")
    return True


def test_full_assessment():
    """Test full API security assessment."""
    print("\n" + "="*80)
    print("TEST 6: Full API Security Assessment")
    print("="*80)
    
    from vaulytica.api_security import (
        get_api_security_orchestrator,
        APIEndpoint,
        APIMethod,
        AuthType
    )
    
    orchestrator = get_api_security_orchestrator()
    
    # Create test endpoints
    endpoints = [
        APIEndpoint(
            endpoint_id="ep-full-001",
            path="/api/users",
            method=APIMethod.GET,
            auth_type=AuthType.JWT,
            parameters=["id"],
            requires_auth=True
        ),
        APIEndpoint(
            endpoint_id="ep-full-002",
            path="/api/data",
            method=APIMethod.POST,
            auth_type=AuthType.NONE,
            parameters=["query", "filter"],
            requires_auth=False
        )
    ]
    
    test_parameters = ["id", "query", "comment", "url"]
    
    async def run_assessment():
        print("\n🔍 Running Full API Security Assessment...")
        results = await orchestrator.perform_full_assessment(
            target="https://example.com",
            endpoints=endpoints,
            test_parameters=test_parameters
        )
        
        print(f"\n✓ Assessment completed: {results['assessment_id']}")
        print(f"  Duration: {results['duration_seconds']:.2f}s")
        
        print(f"\n📊 API Security:")
        print(f"  Endpoints scanned: {results['api_security']['endpoints_scanned']}")
        print(f"  Vulnerabilities: {results['api_security']['vulnerabilities_found']}")
        print(f"  By severity: {results['api_security']['by_severity']}")
        
        print(f"\n📊 Application Security:")
        print(f"  Tests executed: {results['application_security']['tests_executed']}")
        print(f"  Vulnerabilities: {results['application_security']['vulnerabilities_found']}")
        print(f"  By type: {results['application_security']['by_type']}")
        
        print(f"\n📊 Overall Report:")
        print(f"  Total vulnerabilities: {results['report']['total_vulnerabilities']}")
        print(f"  Critical: {results['report']['critical_count']}")
        print(f"  High: {results['report']['high_count']}")
        print(f"  Medium: {results['report']['medium_count']}")
        print(f"  Low: {results['report']['low_count']}")
        print(f"  Risk score: {results['report']['overall_risk_score']:.2f}")
        print(f"  Risk level: {results['report']['risk_level']}")
        
        return results
    
    results = asyncio.run(run_assessment())
    
    assert results['api_security']['endpoints_scanned'] == 2, "Should scan 2 endpoints"
    assert results['report']['total_vulnerabilities'] > 0, "Should find vulnerabilities"
    
    print("\n✅ Full API Security Assessment test PASSED!")
    return True


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("🚀 VAULYTICA v0.26.0 - API SECURITY & AST TEST SUITE")
    print("="*80)
    
    tests = [
        ("API Security Scanner", test_api_security_scanner),
        ("Application Security Tester", test_application_security_tester),
        ("API Threat Protection", test_api_threat_protection),
        ("Security Automation", test_security_automation),
        ("Vulnerability Reporter", test_vulnerability_reporter),
        ("Full Assessment", test_full_assessment)
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ {name} test FAILED: {e}")
            results.append((name, False))
    
    # Print summary
    print("\n" + "="*80)
    print("📊 TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {name}")
    
    print(f"\nResults: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED!")
        print("🎉 Vaulytica v0.26.0 API Security & AST is PRODUCTION READY! 🚀")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

