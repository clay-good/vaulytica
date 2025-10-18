#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from vaulytica.api import app

# Create test client
client = TestClient(app)


def test_root_endpoint():
    """Test root endpoint."""
    print("\n1. Testing GET / (root)...")
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Vaulytica API"
    assert data["version"] == "0.17.0"
    assert "endpoints" in data
    print("   ✓ Root endpoint working")


def test_health_endpoints():
    """Test health check endpoints."""
    print("\n2. Testing health endpoints...")
    
    # Test /health
    response = client.get("/health")
    assert response.status_code in [200, 503]  # May be 503 if not fully initialized
    data = response.json()
    assert "status" in data
    assert "version" in data
    print("   ✓ /health endpoint working")
    
    # Test /ready
    response = client.get("/ready")
    assert response.status_code in [200, 503]
    data = response.json()
    assert "ready" in data
    print("   ✓ /ready endpoint working")
    
    # Test /live
    response = client.get("/live")
    assert response.status_code == 200
    data = response.json()
    assert data["alive"] == True
    print("   ✓ /live endpoint working")


def test_metrics_endpoint():
    """Test metrics endpoint."""
    print("\n3. Testing GET /metrics...")
    response = client.get("/metrics")
    assert response.status_code == 200
    # Metrics should be in Prometheus format (plain text)
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    print("   ✓ Metrics endpoint working")


def test_analyze_endpoint_validation():
    """Test analyze endpoint input validation."""
    print("\n4. Testing POST /analyze validation...")
    
    # Test missing required fields
    response = client.post("/analyze", json={})
    assert response.status_code == 422  # Validation error
    print("   ✓ Validation working for missing fields")
    
    # Test invalid source
    response = client.post("/analyze", json={
        "source": "invalid_source",
        "event_data": {}
    })
    assert response.status_code == 422
    print("   ✓ Validation working for invalid source")


def test_correlation_stats():
    """Test correlation stats endpoint."""
    print("\n5. Testing GET /correlation/stats...")
    response = client.get("/correlation/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "total_correlations" in data
    print("   ✓ Correlation stats endpoint working")


def test_playbooks_list():
    """Test playbooks list endpoint."""
    print("\n6. Testing GET /playbooks...")
    response = client.get("/playbooks")
    assert response.status_code == 200
    data = response.json()
    assert "playbooks" in data
    assert isinstance(data["playbooks"], list)
    print("   ✓ Playbooks list endpoint working")


def test_threat_feeds_stats():
    """Test threat feeds stats endpoint."""
    print("\n7. Testing GET /threat-feeds/stats...")
    response = client.get("/threat-feeds/stats")
    assert response.status_code == 200
    data = response.json()
    assert "feeds" in data
    print("   ✓ Threat feeds stats endpoint working")


def test_incidents_list():
    """Test incidents list endpoint."""
    print("\n8. Testing GET /incidents...")
    response = client.get("/incidents")
    assert response.status_code == 200
    data = response.json()
    assert "incidents" in data
    assert "total" in data
    print("   ✓ Incidents list endpoint working")


def test_visualizations_list():
    """Test visualizations list endpoint."""
    print("\n9. Testing GET /visualizations...")
    response = client.get("/visualizations")
    assert response.status_code == 200
    data = response.json()
    assert "available_visualizations" in data
    print("   ✓ Visualizations list endpoint working")


def test_ai_soc_endpoints():
    """Test AI SOC analytics endpoints."""
    print("\n10. Testing AI SOC endpoints...")
    
    # Test risk scoring stats
    response = client.get("/ai-soc/risk-scores/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scores" in data
    print("   ✓ Risk scores stats endpoint working")
    
    # Test triage stats
    response = client.get("/ai-soc/triage/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_triaged" in data
    print("   ✓ Triage stats endpoint working")


def test_streaming_endpoints():
    """Test streaming analytics endpoints."""
    print("\n11. Testing streaming endpoints...")
    
    # Test stream stats
    response = client.get("/streaming/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_events_processed" in data
    print("   ✓ Streaming stats endpoint working")
    
    # Test patterns list
    response = client.get("/streaming/patterns")
    assert response.status_code == 200
    data = response.json()
    assert "patterns" in data
    print("   ✓ Streaming patterns endpoint working")


def test_forensics_endpoints():
    """Test forensics endpoints."""
    print("\n12. Testing forensics endpoints...")
    
    # Test evidence list
    response = client.get("/forensics/evidence")
    assert response.status_code == 200
    data = response.json()
    assert "evidence" in data
    print("   ✓ Evidence list endpoint working")
    
    # Test investigations list
    response = client.get("/forensics/investigations")
    assert response.status_code == 200
    data = response.json()
    assert "investigations" in data
    print("   ✓ Investigations list endpoint working")


def test_error_handling():
    """Test error handling."""
    print("\n13. Testing error handling...")
    
    # Test 404
    response = client.get("/nonexistent-endpoint")
    assert response.status_code == 404
    print("   ✓ 404 handling working")
    
    # Test invalid JSON
    response = client.post(
        "/analyze",
        data="invalid json",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    print("   ✓ Invalid JSON handling working")


def test_rate_limiting():
    """Test rate limiting (if enabled)."""
    print("\n14. Testing rate limiting...")
    
    # Make multiple requests quickly
    responses = []
    for i in range(5):
        response = client.get("/health")
        responses.append(response.status_code)
    
    # All should succeed (rate limit is 100/60s)
    assert all(code in [200, 503] for code in responses)
    print("   ✓ Rate limiting configured (not triggered with 5 requests)")


def run_all_tests():
    """Run all tests."""
    print("=" * 80)
    print("VAULYTICA API ENDPOINT TESTS")
    print("=" * 80)
    
    tests = [
        test_root_endpoint,
        test_health_endpoints,
        test_metrics_endpoint,
        test_analyze_endpoint_validation,
        test_correlation_stats,
        test_playbooks_list,
        test_threat_feeds_stats,
        test_incidents_list,
        test_visualizations_list,
        test_ai_soc_endpoints,
        test_streaming_endpoints,
        test_forensics_endpoints,
        test_error_handling,
        test_rate_limiting,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"   ✗ Test failed: {e}")
            failed += 1
        except Exception as e:
            print(f"   ✗ Test error: {e}")
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 80)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

