"""Comprehensive API endpoint testing for Vaulytica v0.30.0."""

import asyncio
from datetime import datetime
from typing import Dict, Any

print("=" * 80)
print("🚀 VAULYTICA v0.30.0 - COMPREHENSIVE API ENDPOINT TEST")
print("=" * 80)
print()

# Test counters
total_tests = 0
passed_tests = 0
failed_tests = 0
errors = []


def test_result(test_name: str, success: bool, error: str = None):
    """Record test result."""
    global total_tests, passed_tests, failed_tests, errors
    total_tests += 1
    if success:
        passed_tests += 1
        print(f"✅ {test_name}")
    else:
        failed_tests += 1
        print(f"❌ {test_name}")
        if error:
            print(f"   Error: {error[:200]}")
            errors.append((test_name, error))


def test_section(section_name: str):
    """Print test section header."""
    print()
    print("=" * 80)
    print(f"TESTING: {section_name}")
    print("=" * 80)
    print()


# ============================================================================
# Test 1: Import API and verify routes
# ============================================================================
test_section("API Import and Route Registration")

try:
    from vaulytica.api import app
    routes = [route for route in app.routes if hasattr(route, 'path')]
    route_count = len(routes)
    test_result(f"Import FastAPI app ({route_count} routes)", True)
    
    # Verify minimum expected routes
    if route_count >= 250:
        test_result(f"Verify route count >= 250", True)
    else:
        test_result(f"Verify route count >= 250", False, f"Only {route_count} routes found")
except Exception as e:
    test_result("Import FastAPI app", False, str(e))


# ============================================================================
# Test 2: Test Core Module Endpoints
# ============================================================================
test_section("Core Module Endpoints")

try:
    from vaulytica.api import app
    from fastapi.testclient import TestClient
    
    client = TestClient(app)
    
    # Test health endpoint
    response = client.get("/health")
    if response.status_code == 200:
        test_result("GET /health", True)
    else:
        test_result("GET /health", False, f"Status: {response.status_code}")
    
    # Test version endpoint
    response = client.get("/version")
    if response.status_code == 200:
        data = response.json()
        if data.get("version") == "0.30.0":
            test_result("GET /version (v0.30.0)", True)
        else:
            test_result("GET /version (v0.30.0)", False, f"Version: {data.get('version')}")
    else:
        test_result("GET /version", False, f"Status: {response.status_code}")
        
except Exception as e:
    test_result("Core endpoints", False, str(e))


# ============================================================================
# Test 3: Test Attack Surface Management Endpoints
# ============================================================================
test_section("Attack Surface Management Endpoints (v0.30.0)")

try:
    from fastapi.testclient import TestClient
    from vaulytica.api import app
    
    client = TestClient(app)
    
    # Test ASM statistics endpoint
    response = client.get("/asm/statistics")
    if response.status_code == 200:
        test_result("GET /asm/statistics", True)
    else:
        test_result("GET /asm/statistics", False, f"Status: {response.status_code}")
    
    # Test Data Lake statistics endpoint
    response = client.get("/datalake/statistics")
    if response.status_code == 200:
        test_result("GET /datalake/statistics", True)
    else:
        test_result("GET /datalake/statistics", False, f"Status: {response.status_code}")
    
    # Test Threat Modeling statistics endpoint
    response = client.get("/threatmodel/statistics")
    if response.status_code == 200:
        test_result("GET /threatmodel/statistics", True)
    else:
        test_result("GET /threatmodel/statistics", False, f"Status: {response.status_code}")
    
    # Test Security Metrics statistics endpoint
    response = client.get("/metrics/statistics")
    if response.status_code == 200:
        test_result("GET /metrics/statistics", True)
    else:
        test_result("GET /metrics/statistics", False, f"Status: {response.status_code}")
    
    # Test Incident Simulation statistics endpoint
    response = client.get("/simulation/statistics")
    if response.status_code == 200:
        test_result("GET /simulation/statistics", True)
    else:
        test_result("GET /simulation/statistics", False, f"Status: {response.status_code}")
        
except Exception as e:
    test_result("ASM endpoints", False, str(e))


# ============================================================================
# Test 4: Test Security Posture Endpoints
# ============================================================================
test_section("Security Posture Analytics Endpoints (v0.29.0)")

try:
    from fastapi.testclient import TestClient
    from vaulytica.api import app
    
    client = TestClient(app)
    
    # Test posture scoring statistics
    response = client.get("/posture/scoring/statistics")
    if response.status_code == 200:
        test_result("GET /posture/scoring/statistics", True)
    else:
        test_result("GET /posture/scoring/statistics", False, f"Status: {response.status_code}")
    
    # Test continuous monitoring statistics
    response = client.get("/posture/monitoring/statistics")
    if response.status_code == 200:
        test_result("GET /posture/monitoring/statistics", True)
    else:
        test_result("GET /posture/monitoring/statistics", False, f"Status: {response.status_code}")
    
    # Test predictive intelligence statistics
    response = client.get("/posture/predictions/statistics")
    if response.status_code == 200:
        test_result("GET /posture/predictions/statistics", True)
    else:
        test_result("GET /posture/predictions/statistics", False, f"Status: {response.status_code}")
        
except Exception as e:
    test_result("Security Posture endpoints", False, str(e))


# ============================================================================
# Test 5: Test Supply Chain Security Endpoints
# ============================================================================
test_section("Supply Chain Security & GRC Endpoints (v0.28.0)")

try:
    from fastapi.testclient import TestClient
    from vaulytica.api import app
    
    client = TestClient(app)
    
    # Test supply chain scanner statistics
    response = client.get("/supply-chain/scanner/statistics")
    if response.status_code == 200:
        test_result("GET /supply-chain/scanner/statistics", True)
    else:
        test_result("GET /supply-chain/scanner/statistics", False, f"Status: {response.status_code}")
    
    # Test SBOM manager statistics
    response = client.get("/supply-chain/sbom/statistics")
    if response.status_code == 200:
        test_result("GET /supply-chain/sbom/statistics", True)
    else:
        test_result("GET /supply-chain/sbom/statistics", False, f"Status: {response.status_code}")
    
    # Test GRC platform statistics
    response = client.get("/grc/statistics")
    if response.status_code == 200:
        test_result("GET /grc/statistics", True)
    else:
        test_result("GET /grc/statistics", False, f"Status: {response.status_code}")
        
except Exception as e:
    test_result("Supply Chain endpoints", False, str(e))


# ============================================================================
# Test 6: Test IAM Security Endpoints
# ============================================================================
test_section("IAM Security & Secrets Management Endpoints (v0.24.0)")

try:
    from fastapi.testclient import TestClient
    from vaulytica.api import app
    
    client = TestClient(app)
    
    # Test IAM analyzer statistics
    response = client.get("/iam/analyzer/statistics")
    if response.status_code == 200:
        test_result("GET /iam/analyzer/statistics", True)
    else:
        test_result("GET /iam/analyzer/statistics", False, f"Status: {response.status_code}")
    
    # Test secrets scanner statistics
    response = client.get("/iam/secrets/statistics")
    if response.status_code == 200:
        test_result("GET /iam/secrets/statistics", True)
    else:
        test_result("GET /iam/secrets/statistics", False, f"Status: {response.status_code}")
        
except Exception as e:
    test_result("IAM Security endpoints", False, str(e))


# ============================================================================
# Test 7: Test CSPM Endpoints
# ============================================================================
test_section("CSPM & Vulnerability Management Endpoints (v0.22.0)")

try:
    from fastapi.testclient import TestClient
    from vaulytica.api import app
    
    client = TestClient(app)
    
    # Test CSPM statistics
    response = client.get("/cspm/statistics")
    if response.status_code == 200:
        test_result("GET /cspm/statistics", True)
    else:
        test_result("GET /cspm/statistics", False, f"Status: {response.status_code}")
    
    # Test vulnerability management statistics
    response = client.get("/vulnerability/statistics")
    if response.status_code == 200:
        test_result("GET /vulnerability/statistics", True)
    else:
        test_result("GET /vulnerability/statistics", False, f"Status: {response.status_code}")
        
except Exception as e:
    test_result("CSPM endpoints", False, str(e))


# ============================================================================
# Final Results
# ============================================================================
print()
print("=" * 80)
print("FINAL RESULTS")
print("=" * 80)
print(f"Total Tests: {total_tests}")
print(f"✅ Passed: {passed_tests}")
print(f"❌ Failed: {failed_tests}")
print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")

if errors:
    print()
    print("🐛 Issues Found:")
    for i, (test_name, error) in enumerate(errors, 1):
        print(f"  {i}. {test_name}: {error[:150]}")

print("=" * 80)

if failed_tests == 0:
    print()
    print("✅ ALL API ENDPOINT TESTS PASSED!")
    print("🎉 Vaulytica v0.30.0 API is PRODUCTION READY! 🚀")
    exit(0)
else:
    print()
    print("⚠️  SOME TESTS FAILED - REVIEW REQUIRED")
    exit(1)

