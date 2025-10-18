"""
Comprehensive test suite for Container Security & Kubernetes Security Posture Management.

Tests all container security features including:
- Container image scanning
- Kubernetes resource scanning
- CIS Kubernetes Benchmark checks
- Runtime security monitoring
- SBOM generation
- Image signature verification
- Full security assessment

Author: Vaulytica Team
Version: 0.23.0
"""

import asyncio
import sys
from datetime import datetime
from typing import Dict, Any


def print_header(title: str):
    """Print test section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_result(test_name: str, passed: bool, details: str = ""):
    """Print test result."""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"\n{status} - {test_name}")
    if details:
        print(f"  {details}")


async def test_container_image_scanner():
    """Test container image vulnerability scanner."""
    print_header("TEST 1: Container Image Scanner")
    
    try:
        from vaulytica.container_security import get_container_scanner
        
        scanner = get_container_scanner()
        
        # Scan nginx image
        scan_result = await scanner.scan_image("nginx:1.21")
        
        # Verify scan result
        assert scan_result.scan_id is not None, "Scan ID should be set"
        assert scan_result.image.repository == "nginx", "Repository should be nginx"
        assert scan_result.image.tag == "1.21", "Tag should be 1.21"
        assert len(scan_result.vulnerabilities) > 0, "Should find vulnerabilities"
        assert len(scan_result.packages) > 0, "Should find packages"
        assert len(scan_result.layers) > 0, "Should find layers"
        assert scan_result.risk_score > 0, "Risk score should be calculated"
        
        # Check vulnerability counts
        vuln_counts = scan_result.get_vulnerability_count_by_severity()
        
        # Get statistics
        stats = scanner.get_statistics()
        assert stats["total_scans"] > 0, "Should track scans"
        assert stats["images_scanned"] > 0, "Should track images"
        assert stats["vulnerabilities_found"] > 0, "Should track vulnerabilities"
        
        details = (
            f"Scanned: {scan_result.image.repository}:{scan_result.image.tag}\n"
            f"  Vulnerabilities: {len(scan_result.vulnerabilities)}\n"
            f"  Packages: {len(scan_result.packages)}\n"
            f"  Layers: {len(scan_result.layers)}\n"
            f"  Risk Score: {scan_result.risk_score:.1f}/10.0\n"
            f"  Scan Duration: {scan_result.scan_duration_ms}ms"
        )
        
        print_result("Container Image Scanner", True, details)
        return True
        
    except Exception as e:
        print_result("Container Image Scanner", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_kubernetes_scanner():
    """Test Kubernetes security scanner."""
    print_header("TEST 2: Kubernetes Security Scanner")
    
    try:
        from vaulytica.container_security import get_k8s_scanner
        
        scanner = get_k8s_scanner()
        
        # Scan namespace
        resources = await scanner.scan_namespace("default")
        
        # Verify resources
        assert len(resources) > 0, "Should discover resources"
        
        # Check resource types
        resource_types = set(r.resource_type.value for r in resources)
        
        # Get statistics
        stats = scanner.get_statistics()
        assert stats["total_scans"] > 0, "Should track scans"
        assert stats["resources_scanned"] > 0, "Should track resources"
        
        details = (
            f"Namespace: default\n"
            f"  Resources: {len(resources)}\n"
            f"  Resource Types: {', '.join(resource_types)}"
        )
        
        print_result("Kubernetes Security Scanner", True, details)
        return True
        
    except Exception as e:
        print_result("Kubernetes Security Scanner", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_cis_kubernetes_benchmark():
    """Test CIS Kubernetes Benchmark checks."""
    print_header("TEST 3: CIS Kubernetes Benchmark")
    
    try:
        from vaulytica.container_security import get_k8s_scanner
        
        scanner = get_k8s_scanner()
        
        # Scan namespace
        resources = await scanner.scan_namespace("default")
        
        # Run CIS checks
        findings = await scanner.check_cis_kubernetes_benchmark(resources)
        
        # Verify findings
        assert len(findings) > 0, "Should find security issues"
        
        # Check finding categories
        categories = set(f.category for f in findings)
        
        # Check severity distribution
        severity_counts = {}
        for finding in findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Get statistics
        stats = scanner.get_statistics()
        
        details = (
            f"Resources Checked: {len(resources)}\n"
            f"  Findings: {len(findings)}\n"
            f"  Categories: {', '.join(categories)}\n"
            f"  By Severity: {severity_counts}"
        )
        
        print_result("CIS Kubernetes Benchmark", True, details)
        return True
        
    except Exception as e:
        print_result("CIS Kubernetes Benchmark", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_pod_security_analysis():
    """Test pod security context analysis."""
    print_header("TEST 4: Pod Security Analysis")
    
    try:
        from vaulytica.container_security import get_k8s_scanner
        
        scanner = get_k8s_scanner()
        
        # Scan namespace
        resources = await scanner.scan_namespace("default")
        
        # Find a pod
        pod = next((r for r in resources if r.resource_type.value == "pod"), None)
        assert pod is not None, "Should find a pod"
        
        # Analyze pod security
        pod_security = await scanner.analyze_pod_security(pod)
        
        # Verify analysis
        assert pod_security.pod_name == pod.name, "Pod name should match"
        assert pod_security.namespace == pod.namespace, "Namespace should match"
        
        details = (
            f"Pod: {pod_security.pod_name}\n"
            f"  Runs as Root: {pod_security.runs_as_root}\n"
            f"  Privileged: {pod_security.privileged}\n"
            f"  Host Network: {pod_security.host_network}\n"
            f"  Security Standard: {pod_security.security_standard.value}"
        )
        
        print_result("Pod Security Analysis", True, details)
        return True
        
    except Exception as e:
        print_result("Pod Security Analysis", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_runtime_security_monitor():
    """Test runtime security monitoring."""
    print_header("TEST 5: Runtime Security Monitor")
    
    try:
        from vaulytica.container_security import get_runtime_monitor
        
        monitor = get_runtime_monitor()
        
        # Monitor container
        events = await monitor.monitor_container("container-12345", duration_seconds=10)
        
        # Verify events
        assert len(events) > 0, "Should detect runtime events"
        
        # Check event types
        event_types = set(e.event_type for e in events)
        
        # Check blocked events
        blocked_events = [e for e in events if e.blocked]
        
        # Get statistics
        stats = monitor.get_statistics()
        assert stats["total_events"] > 0, "Should track events"
        
        details = (
            f"Container: container-12345\n"
            f"  Events: {len(events)}\n"
            f"  Event Types: {', '.join(event_types)}\n"
            f"  Blocked: {len(blocked_events)}"
        )
        
        print_result("Runtime Security Monitor", True, details)
        return True
        
    except Exception as e:
        print_result("Runtime Security Monitor", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_sbom_generation():
    """Test SBOM generation."""
    print_header("TEST 6: SBOM Generation")
    
    try:
        from vaulytica.container_security import get_supply_chain_security, get_container_scanner
        
        # Scan image first
        scanner = get_container_scanner()
        scan_result = await scanner.scan_image("python:3.9")
        
        # Generate SBOM
        supply_chain = get_supply_chain_security()
        sbom = await supply_chain.generate_sbom(scan_result.image)
        
        # Verify SBOM
        assert sbom.sbom_id is not None, "SBOM ID should be set"
        assert sbom.format == "CycloneDX", "Format should be CycloneDX"
        assert len(sbom.components) > 0, "Should have components"
        
        # Export to JSON
        sbom_json = sbom.to_json()
        assert len(sbom_json) > 0, "Should export to JSON"
        
        # Get statistics
        stats = supply_chain.get_statistics()
        assert stats["sboms_generated"] > 0, "Should track SBOMs"
        
        details = (
            f"Image: {sbom.image.repository}:{sbom.image.tag}\n"
            f"  SBOM ID: {sbom.sbom_id}\n"
            f"  Format: {sbom.format} {sbom.version}\n"
            f"  Components: {len(sbom.components)}\n"
            f"  JSON Size: {len(sbom_json)} bytes"
        )
        
        print_result("SBOM Generation", True, details)
        return True
        
    except Exception as e:
        print_result("SBOM Generation", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_image_signature_verification():
    """Test image signature verification."""
    print_header("TEST 7: Image Signature Verification")
    
    try:
        from vaulytica.container_security import get_supply_chain_security, get_container_scanner
        
        # Scan image first
        scanner = get_container_scanner()
        scan_result = await scanner.scan_image("nginx:latest")
        
        # Verify signature
        supply_chain = get_supply_chain_security()
        verification = await supply_chain.verify_image_signature(scan_result.image)
        
        # Verify result
        assert "verified" in verification, "Should have verification status"
        assert "signer" in verification, "Should have signer info"
        assert "provenance" in verification, "Should have provenance info"
        
        details = (
            f"Image: {scan_result.image.repository}:{scan_result.image.tag}\n"
            f"  Verified: {verification['verified']}\n"
            f"  Signer: {verification['signer']}\n"
            f"  Builder: {verification['provenance']['builder']}"
        )
        
        print_result("Image Signature Verification", True, details)
        return True
        
    except Exception as e:
        print_result("Image Signature Verification", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_full_security_assessment():
    """Test full security assessment orchestrator."""
    print_header("TEST 8: Full Security Assessment")
    
    try:
        from vaulytica.container_security import get_container_security_orchestrator
        
        orchestrator = get_container_security_orchestrator()
        
        # Run full assessment
        assessment = await orchestrator.full_security_assessment(
            "nginx:1.21",
            namespace="default",
            monitor_runtime=True
        )
        
        # Verify assessment
        assert "assessment_id" in assessment, "Should have assessment ID"
        assert "image" in assessment, "Should have image results"
        assert "sbom" in assessment, "Should have SBOM results"
        assert "signature" in assessment, "Should have signature results"
        assert "kubernetes" in assessment, "Should have K8s results"
        assert "runtime" in assessment, "Should have runtime results"
        assert "overall_risk_score" in assessment, "Should have overall risk score"
        
        # Get unified statistics
        stats = orchestrator.get_unified_statistics()
        assert "image_scanner" in stats, "Should have image scanner stats"
        assert "k8s_scanner" in stats, "Should have K8s scanner stats"
        assert "runtime_monitor" in stats, "Should have runtime monitor stats"
        assert "supply_chain" in stats, "Should have supply chain stats"
        
        details = (
            f"Assessment ID: {assessment['assessment_id']}\n"
            f"  Image Vulnerabilities: {assessment['image']['vulnerabilities']}\n"
            f"  SBOM Components: {assessment['sbom']['components']}\n"
            f"  K8s Findings: {assessment['kubernetes']['findings']}\n"
            f"  Runtime Events: {assessment['runtime']['events']}\n"
            f"  Overall Risk Score: {assessment['overall_risk_score']:.1f}/10.0\n"
            f"  Duration: {assessment['duration_seconds']:.2f}s"
        )
        
        print_result("Full Security Assessment", True, details)
        return True
        
    except Exception as e:
        print_result("Full Security Assessment", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("  VAULYTICA v0.23.0 - CONTAINER SECURITY TEST SUITE")
    print("=" * 80)
    print(f"\nStarting tests at {datetime.utcnow().isoformat()}")
    
    # Run all tests
    results = []
    
    results.append(await test_container_image_scanner())
    results.append(await test_kubernetes_scanner())
    results.append(await test_cis_kubernetes_benchmark())
    results.append(await test_pod_security_analysis())
    results.append(await test_runtime_security_monitor())
    results.append(await test_sbom_generation())
    results.append(await test_image_signature_verification())
    results.append(await test_full_security_assessment())
    
    # Print summary
    print("\n" + "=" * 80)
    print("  TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(results)
    total = len(results)
    percentage = (passed / total * 100) if total > 0 else 0
    
    print(f"\nResults: {passed}/{total} tests passed ({percentage:.1f}%)")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n❌ {total - passed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

