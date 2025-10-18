"""
Comprehensive CSPM Integration Tests.

Tests all CSPM features:
- Cloud resource scanning
- Compliance checking
- Vulnerability scanning
- Drift detection
- Remediation planning

Author: Vaulytica Team
Version: 0.22.0
"""

import asyncio
import sys
from datetime import datetime

# Test imports
try:
    from vaulytica.cspm import (
        get_cloud_scanner,
        get_compliance_engine,
        get_drift_engine,
        get_cspm_orchestrator,
        CloudProvider,
        ComplianceFramework,
        Severity
    )
    from vaulytica.vulnerability_management import get_vulnerability_scanner
    from vaulytica.remediation import get_remediation_engine
    print("✅ All CSPM imports successful")
except Exception as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


async def test_cloud_scanner():
    """Test cloud resource scanner."""
    print("\n" + "="*80)
    print("TEST 1: Cloud Resource Scanner")
    print("="*80)
    
    try:
        scanner = get_cloud_scanner()
        
        # Scan AWS resources
        print("\n📡 Scanning AWS resources...")
        aws_resources = await scanner.scan_aws_resources("us-east-1")
        print(f"✅ Discovered {len(aws_resources)} AWS resources")
        
        for resource in aws_resources:
            print(f"  - {resource.resource_type.value}: {resource.name} ({resource.resource_id})")
        
        # Get statistics
        stats = scanner.get_statistics()
        print(f"\n📊 Scanner Statistics:")
        print(f"  - Resources discovered: {stats['resources_discovered']}")
        print(f"  - Resources by provider: {stats['resources_by_provider']}")
        print(f"  - Resources by type: {stats['resources_by_type']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Cloud scanner test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_compliance_engine():
    """Test compliance checking engine."""
    print("\n" + "="*80)
    print("TEST 2: Compliance Engine")
    print("="*80)
    
    try:
        scanner = get_cloud_scanner()
        compliance_engine = get_compliance_engine()
        
        # Get resources
        resources = list(scanner.resources.values())
        print(f"\n🔍 Running compliance checks on {len(resources)} resources...")
        
        # Run compliance assessment
        results = await compliance_engine.assess_compliance(
            resources,
            frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.PCI_DSS]
        )
        
        print(f"✅ Compliance assessment complete")
        print(f"  - Total checks run: {results['total_checks']}")
        print(f"  - Findings: {len(results['findings'])}")
        print(f"  - Compliance scores: {results['compliance_scores']}")
        
        # Show findings by severity
        print(f"\n📋 Findings by Severity:")
        for severity in Severity:
            findings = compliance_engine.get_findings_by_severity(severity)
            if findings:
                print(f"  - {severity.value.upper()}: {len(findings)}")
                for finding in findings[:2]:  # Show first 2
                    print(f"    • {finding.title}")
                    print(f"      Resource: {finding.resource.name}")
                    print(f"      Risk Score: {finding.risk_score:.1f}")
        
        return True
        
    except Exception as e:
        print(f"❌ Compliance engine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_vulnerability_scanner():
    """Test vulnerability scanner."""
    print("\n" + "="*80)
    print("TEST 3: Vulnerability Scanner")
    print("="*80)
    
    try:
        scanner = get_cloud_scanner()
        vuln_scanner = get_vulnerability_scanner()
        
        # Get resources
        resources = list(scanner.resources.values())
        print(f"\n🔍 Scanning {len(resources)} resources for vulnerabilities...")
        
        # Scan for vulnerabilities
        assessments = await vuln_scanner.scan_all_resources(resources)
        
        print(f"✅ Vulnerability scan complete")
        print(f"  - Resources scanned: {len(assessments)}")
        
        # Show assessments
        print(f"\n🐛 Vulnerability Assessments:")
        for assessment in assessments:
            if assessment.vulnerabilities:
                print(f"  - {assessment.resource.name}:")
                print(f"    Risk Score: {assessment.risk_score:.1f}")
                print(f"    Priority: {assessment.priority.value}")
                print(f"    Vulnerabilities: {len(assessment.vulnerabilities)}")
                for vuln in assessment.vulnerabilities:
                    print(f"      • {vuln.cve_id}: {vuln.title}")
                    print(f"        CVSS: {vuln.cvss_v3_score} | Exploit: {vuln.exploit_available}")
        
        # Get statistics
        stats = vuln_scanner.get_statistics()
        print(f"\n📊 Scanner Statistics:")
        print(f"  - Total scans: {stats['total_scans']}")
        print(f"  - Vulnerabilities found: {stats['vulnerabilities_found']}")
        print(f"  - By severity: {stats['vulnerabilities_by_severity']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Vulnerability scanner test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_drift_detection():
    """Test drift detection engine."""
    print("\n" + "="*80)
    print("TEST 4: Drift Detection")
    print("="*80)
    
    try:
        scanner = get_cloud_scanner()
        drift_engine = get_drift_engine()
        
        # Get resources
        resources = list(scanner.resources.values())
        print(f"\n🔍 Checking drift for {len(resources)} resources...")
        
        # Check drift
        detections = await drift_engine.check_all_resources(resources)
        
        drifted = [d for d in detections if d.drifted]
        
        print(f"✅ Drift detection complete")
        print(f"  - Total resources: {len(resources)}")
        print(f"  - Drifted resources: {len(drifted)}")
        print(f"  - Drift rate: {(len(drifted) / len(resources) * 100):.1f}%")
        
        # Show drifted resources
        if drifted:
            print(f"\n⚠️  Drifted Resources:")
            for detection in drifted:
                print(f"  - {detection.resource.name}:")
                print(f"    Type: {detection.resource.resource_type.value}")
                print(f"    Drift details: {detection.drift_details}")
        
        # Get statistics
        stats = drift_engine.get_statistics()
        print(f"\n📊 Drift Statistics:")
        print(f"  - Total baselines: {stats['total_baselines']}")
        print(f"  - Total checks: {stats['total_drift_checks']}")
        print(f"  - Resources drifted: {stats['resources_drifted']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Drift detection test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_remediation_engine():
    """Test remediation engine."""
    print("\n" + "="*80)
    print("TEST 5: Remediation Engine")
    print("="*80)
    
    try:
        scanner = get_cloud_scanner()
        compliance_engine = get_compliance_engine()
        remediation_engine = get_remediation_engine()
        
        # Get a finding
        findings = list(compliance_engine.findings.values())
        if not findings:
            print("⚠️  No findings available for remediation test")
            return True
        
        finding = findings[0]
        resource = finding.resource
        
        print(f"\n🔧 Creating remediation plan for finding:")
        print(f"  - Finding: {finding.title}")
        print(f"  - Resource: {resource.name}")
        print(f"  - Severity: {finding.severity.value}")
        
        # Create remediation plan
        plan = await remediation_engine.create_remediation_plan(
            resource=resource,
            finding=finding
        )
        
        print(f"\n✅ Remediation plan created: {plan.plan_id}")
        print(f"  - Title: {plan.title}")
        print(f"  - Type: {plan.remediation_type.value}")
        print(f"  - Estimated effort: {plan.estimated_effort}")
        print(f"  - Risk of change: {plan.risk_of_change}")
        print(f"  - Requires downtime: {plan.requires_downtime}")
        print(f"  - Requires approval: {plan.requires_approval}")
        
        print(f"\n📝 Remediation Steps:")
        for step in plan.steps:
            print(f"  {step}")
        
        if plan.iac_template:
            print(f"\n🏗️  IaC Template ({plan.iac_format.value}):")
            print(plan.iac_template[:200] + "..." if len(plan.iac_template) > 200 else plan.iac_template)
        
        # Approve plan first
        print(f"\n✅ Approving plan...")
        remediation_engine.approve_plan(plan.plan_id, "test_user")

        # Execute plan (dry run)
        print(f"\n🚀 Executing plan (dry run)...")
        result = await remediation_engine.execute_plan(plan.plan_id, dry_run=True)
        
        print(f"✅ Plan execution complete")
        print(f"  - Status: {result['status']}")
        print(f"  - Dry run: {result['dry_run']}")
        print(f"  - Message: {result['message']}")
        
        # Get statistics
        stats = remediation_engine.get_statistics()
        print(f"\n📊 Remediation Statistics:")
        print(f"  - Total plans created: {stats['total_plans_created']}")
        print(f"  - Plans executed: {stats['plans_executed']}")
        print(f"  - Plans successful: {stats['plans_successful']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Remediation engine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_cspm_orchestrator():
    """Test CSPM orchestrator."""
    print("\n" + "="*80)
    print("TEST 6: CSPM Orchestrator (Full Assessment)")
    print("="*80)
    
    try:
        orchestrator = get_cspm_orchestrator()
        
        print(f"\n🎯 Running full CSPM assessment...")
        
        # Run full assessment
        results = await orchestrator.run_full_assessment(
            provider=CloudProvider.AWS,
            frameworks=[ComplianceFramework.CIS_AWS, ComplianceFramework.PCI_DSS]
        )
        
        print(f"\n✅ Full assessment complete!")
        print(f"\n📊 Assessment Results:")
        print(f"  Provider: {results['provider']}")
        print(f"  Timestamp: {results['timestamp']}")
        print(f"  Resources scanned: {results['resources_scanned']}")
        
        print(f"\n🔒 Compliance:")
        print(f"  - Total findings: {results['compliance']['findings']}")
        print(f"  - Compliance scores: {results['compliance']['scores']}")
        print(f"  - Findings by severity:")
        for severity, count in results['compliance']['findings_by_severity'].items():
            if count > 0:
                print(f"    • {severity}: {count}")
        
        print(f"\n🔄 Drift:")
        print(f"  - Total checks: {results['drift']['total_checks']}")
        print(f"  - Drifted resources: {results['drift']['drifted_resources']}")
        print(f"  - Drift rate: {results['drift']['drift_rate']:.1f}%")
        
        print(f"\n📈 Summary:")
        print(f"  - Critical findings: {results['summary']['critical_findings']}")
        print(f"  - High findings: {results['summary']['high_findings']}")
        print(f"  - Overall score: {results['summary']['overall_score']:.1f}%")
        
        # Get unified statistics
        stats = orchestrator.get_unified_statistics()
        print(f"\n📊 Unified Statistics:")
        print(f"  - Scanner: {stats['scanner']['resources_discovered']} resources")
        print(f"  - Compliance: {stats['compliance']['total_checks_run']} checks")
        print(f"  - Drift: {stats['drift']['total_drift_checks']} checks")
        
        return True
        
    except Exception as e:
        print(f"❌ CSPM orchestrator test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests."""
    print("="*80)
    print("🧪 VAULYTICA v0.22.0 - CSPM INTEGRATION TESTS")
    print("="*80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("Cloud Scanner", test_cloud_scanner),
        ("Compliance Engine", test_compliance_engine),
        ("Vulnerability Scanner", test_vulnerability_scanner),
        ("Drift Detection", test_drift_detection),
        ("Remediation Engine", test_remediation_engine),
        ("CSPM Orchestrator", test_cspm_orchestrator)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*80)
    print("📊 TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\n{'='*80}")
    print(f"Results: {passed}/{total} tests passed ({(passed/total*100):.1f}%)")
    print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! CSPM v0.22.0 is ready!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review.")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

