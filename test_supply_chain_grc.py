"""
Comprehensive tests for Supply Chain Security, SBOM Management & Security GRC (v0.28.0).

Tests all components:
- Supply Chain Security Scanner
- SBOM Management System
- Policy Engine
- Risk Management System
- Security GRC Platform
- Supply Chain & GRC Orchestrator
"""

import asyncio
import sys
from datetime import datetime


def test_supply_chain_scanner():
    """Test supply chain security scanner."""
    print("\n" + "="*80)
    print("TEST 1: Supply Chain Security Scanner")
    print("="*80)
    
    from vaulytica.supply_chain_security import get_supply_chain_scanner
    
    scanner = get_supply_chain_scanner()
    
    async def run_scanner_tests():
        # Scan dependencies
        print("\n🔍 Scanning Dependencies...")
        dependencies = [
            {
                "name": "express",
                "version": "4.18.2",
                "type": "direct",
                "ecosystem": "npm",
                "license": "MIT",
                "vulnerabilities": ["CVE-2024-12345 (critical)", "CVE-2024-12346 (high)"]
            },
            {
                "name": "lodash",
                "version": "4.17.21",
                "type": "direct",
                "ecosystem": "npm",
                "license": "MIT",
                "vulnerabilities": []
            },
            {
                "name": "axios",
                "version": "1.6.0",
                "type": "direct",
                "ecosystem": "npm",
                "license": "MIT",
                "vulnerabilities": ["CVE-2024-12347 (medium)"]
            },
            {
                "name": "unknown-package",
                "version": "0.0.1",
                "type": "direct",
                "ecosystem": "npm",
                "license": "unknown",
                "vulnerabilities": []
            }
        ]
        
        result = await scanner.scan_dependencies("my-api-project", dependencies)
        
        print(f"  ✓ Scan completed: {result.scan_id}")
        print(f"    Dependencies scanned: {result.dependencies_scanned}")
        print(f"    Vulnerabilities found: {result.vulnerabilities_found}")
        print(f"    Critical: {result.critical_vulnerabilities}")
        print(f"    High: {result.high_vulnerabilities}")
        print(f"    Medium: {result.medium_vulnerabilities}")
        print(f"    Low: {result.low_vulnerabilities}")
        print(f"    License issues: {result.license_issues}")
        print(f"    Supply chain threats: {len(result.supply_chain_threats)}")
        print(f"    Risk score: {result.risk_score:.1f}/10")
        print(f"    Recommendations: {len(result.recommendations)}")
        
        for rec in result.recommendations:
            print(f"      - {rec}")
        
        return result
    
    results = asyncio.run(run_scanner_tests())
    
    # Get statistics
    stats = scanner.get_statistics()
    
    print(f"\n📊 Scanner Statistics:")
    print(f"  Scans performed: {stats['scans_performed']}")
    print(f"  Dependencies analyzed: {stats['dependencies_analyzed']}")
    print(f"  Vulnerabilities found: {stats['vulnerabilities_found']}")
    print(f"  Threats detected: {stats['threats_detected']}")
    print(f"  License issues: {stats['license_issues']}")
    
    assert stats['scans_performed'] == 1, "Should perform 1 scan"
    assert stats['dependencies_analyzed'] == 4, "Should analyze 4 dependencies"
    
    print("\n✅ Supply Chain Security Scanner test PASSED!")
    return True


def test_sbom_manager():
    """Test SBOM management system."""
    print("\n" + "="*80)
    print("TEST 2: SBOM Management System")
    print("="*80)
    
    from vaulytica.supply_chain_security import (
        get_sbom_manager,
        Dependency,
        DependencyType,
        LicenseType,
        SBOMFormat
    )
    
    manager = get_sbom_manager()
    
    async def run_sbom_tests():
        # Generate SBOM
        print("\n📦 Generating SBOM...")
        
        dependencies = [
            Dependency(
                name="express",
                version="4.18.2",
                dependency_type=DependencyType.DIRECT,
                ecosystem="npm",
                license="MIT",
                license_type=LicenseType.PERMISSIVE,
                vulnerabilities=["CVE-2024-12345"]
            ),
            Dependency(
                name="lodash",
                version="4.17.21",
                dependency_type=DependencyType.DIRECT,
                ecosystem="npm",
                license="MIT",
                license_type=LicenseType.PERMISSIVE,
                vulnerabilities=[]
            ),
            Dependency(
                name="axios",
                version="1.6.0",
                dependency_type=DependencyType.DIRECT,
                ecosystem="npm",
                license="MIT",
                license_type=LicenseType.PERMISSIVE,
                vulnerabilities=["CVE-2024-12347"]
            )
        ]
        
        sbom = await manager.generate_sbom(
            project_name="my-api-project",
            project_version="1.0.0",
            dependencies=dependencies,
            format=SBOMFormat.CYCLONEDX
        )
        
        print(f"  ✓ SBOM generated: {sbom.sbom_id}")
        print(f"    Format: {sbom.format.value}")
        print(f"    Spec version: {sbom.spec_version}")
        print(f"    Components: {len(sbom.components)}")
        print(f"    Project: {sbom.project_name} v{sbom.project_version}")
        
        # Export SBOM
        print("\n📤 Exporting SBOM...")
        exported = await manager.export_sbom(sbom.sbom_id)
        print(f"  ✓ SBOM exported in {exported['bomFormat']} format")
        print(f"    Components: {len(exported['components'])}")
        
        # Correlate vulnerabilities
        print("\n🔗 Correlating Vulnerabilities...")
        correlation = await manager.correlate_vulnerabilities(sbom.sbom_id)
        print(f"  ✓ Correlation completed")
        print(f"    Total components: {correlation['total_components']}")
        print(f"    Vulnerable components: {correlation['vulnerable_components']}")
        print(f"    Total vulnerabilities: {correlation['total_vulnerabilities']}")
        
        return sbom
    
    results = asyncio.run(run_sbom_tests())
    
    # Get statistics
    stats = manager.get_statistics()
    
    print(f"\n📊 SBOM Manager Statistics:")
    print(f"  SBOMs generated: {stats['sboms_generated']}")
    print(f"  Components tracked: {stats['components_tracked']}")
    print(f"  Vulnerabilities correlated: {stats['vulnerabilities_correlated']}")
    
    assert stats['sboms_generated'] == 1, "Should generate 1 SBOM"
    assert stats['components_tracked'] == 3, "Should track 3 components"
    
    print("\n✅ SBOM Management System test PASSED!")
    return True


def test_policy_engine():
    """Test policy engine."""
    print("\n" + "="*80)
    print("TEST 3: Policy Engine")
    print("="*80)
    
    from vaulytica.supply_chain_security import (
        get_policy_engine,
        Policy,
        PolicyType,
        PolicySeverity
    )
    
    engine = get_policy_engine()
    
    async def run_policy_tests():
        # Create policy
        print("\n📋 Creating Security Policy...")
        
        policy = Policy(
            policy_id="policy-001",
            name="Vulnerability Threshold Policy",
            description="Enforce maximum vulnerability thresholds",
            policy_type=PolicyType.SECURITY,
            severity=PolicySeverity.HIGH,
            rules=[
                {
                    "field": "critical_vulnerabilities",
                    "operator": "less_than",
                    "value": 1,
                    "description": "No critical vulnerabilities allowed",
                    "remediation": "Fix all critical vulnerabilities immediately"
                },
                {
                    "field": "high_vulnerabilities",
                    "operator": "less_than",
                    "value": 5,
                    "description": "Maximum 5 high vulnerabilities allowed",
                    "remediation": "Reduce high vulnerabilities to acceptable level"
                }
            ],
            enabled=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            owner="security-team",
            tags=["vulnerability", "security"]
        )
        
        result = await engine.create_policy(policy)
        print(f"  ✓ Policy created: {result['policy_id']}")
        print(f"    Name: {result['name']}")
        print(f"    Type: {result['type']}")
        print(f"    Severity: {result['severity']}")
        print(f"    Rules: {result['rules']}")
        
        # Evaluate policy
        print("\n✅ Evaluating Policy...")
        
        # Test with compliant resource
        compliant_resource = {
            "id": "resource-001",
            "type": "application",
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 2
        }
        
        evaluation1 = await engine.evaluate_policy("policy-001", compliant_resource)
        print(f"  ✓ Evaluation 1 (compliant): {evaluation1['compliant']}")
        print(f"    Violations: {evaluation1['violations']}")
        
        # Test with non-compliant resource
        non_compliant_resource = {
            "id": "resource-002",
            "type": "application",
            "critical_vulnerabilities": 2,
            "high_vulnerabilities": 8
        }
        
        evaluation2 = await engine.evaluate_policy("policy-001", non_compliant_resource)
        print(f"  ✓ Evaluation 2 (non-compliant): {evaluation2['compliant']}")
        print(f"    Violations: {evaluation2['violations']}")
        
        for violation in evaluation2['details']:
            print(f"      - {violation['severity']}: {violation['description']}")
        
        return evaluation2
    
    results = asyncio.run(run_policy_tests())
    
    # Get statistics
    stats = engine.get_statistics()
    
    print(f"\n📊 Policy Engine Statistics:")
    print(f"  Policies created: {stats['policies_created']}")
    print(f"  Policies evaluated: {stats['policies_evaluated']}")
    print(f"  Violations detected: {stats['violations_detected']}")
    
    assert stats['policies_created'] == 1, "Should create 1 policy"
    assert stats['policies_evaluated'] == 2, "Should evaluate 2 times"
    
    print("\n✅ Policy Engine test PASSED!")
    return True


def test_risk_management():
    """Test risk management system."""
    print("\n" + "="*80)
    print("TEST 4: Risk Management System")
    print("="*80)
    
    from vaulytica.supply_chain_security import (
        get_risk_management,
        Risk,
        RiskLevel,
        RiskStatus
    )
    
    risk_mgmt = get_risk_management()
    
    async def run_risk_tests():
        # Identify risks
        print("\n🎯 Identifying Risks...")
        
        risks = [
            Risk(
                risk_id="risk-001",
                title="Critical Vulnerability in Production",
                description="CVE-2024-12345 found in production API",
                category="vulnerability",
                risk_level=RiskLevel.CRITICAL,
                likelihood=0.9,
                impact=0.9,
                risk_score=0.0,
                status=RiskStatus.IDENTIFIED,
                owner="security-team",
                identified_at=datetime.utcnow(),
                treatment_plan="",
                residual_risk=0.0,
                controls=[]
            ),
            Risk(
                risk_id="risk-002",
                title="Outdated Dependencies",
                description="Multiple dependencies are outdated",
                category="maintenance",
                risk_level=RiskLevel.MEDIUM,
                likelihood=0.6,
                impact=0.5,
                risk_score=0.0,
                status=RiskStatus.IDENTIFIED,
                owner="dev-team",
                identified_at=datetime.utcnow(),
                treatment_plan="",
                residual_risk=0.0,
                controls=[]
            )
        ]
        
        for risk in risks:
            result = await risk_mgmt.identify_risk(risk)
            print(f"  ✓ Risk identified: {result['risk_id']}")
            print(f"    Title: {result['title']}")
            print(f"    Risk level: {result['risk_level']}")
            print(f"    Risk score: {result['risk_score']:.2f}/10")
        
        # Assess risk
        print("\n📊 Assessing Risk...")
        assessment = await risk_mgmt.assess_risk("risk-001")
        print(f"  ✓ Assessment completed: {assessment['risk_id']}")
        print(f"    Risk level: {assessment['risk_level']}")
        print(f"    Recommendations: {len(assessment['recommendations'])}")
        for rec in assessment['recommendations']:
            print(f"      - {rec}")
        
        # Treat risk
        print("\n🛡️ Treating Risk...")
        treatment = await risk_mgmt.treat_risk(
            risk_id="risk-001",
            treatment_type="mitigate",
            treatment_plan="Apply security patch and deploy to production"
        )
        print(f"  ✓ Treatment applied: {treatment['risk_id']}")
        print(f"    Treatment type: {treatment['treatment_type']}")
        print(f"    Original risk score: {treatment['original_risk_score']:.2f}")
        print(f"    Residual risk: {treatment['residual_risk']:.2f}")
        
        # Generate risk report
        print("\n📝 Generating Risk Report...")
        report = await risk_mgmt.generate_risk_report()
        print(f"  ✓ Report generated: {report['report_id']}")
        print(f"    Total risks: {report['total_risks']}")
        print(f"    Average risk score: {report['average_risk_score']}")
        print(f"    Risks by level: {report['risks_by_level']}")
        print(f"    Risks by status: {report['risks_by_status']}")
        
        return report
    
    results = asyncio.run(run_risk_tests())
    
    # Get statistics
    stats = risk_mgmt.get_statistics()
    
    print(f"\n📊 Risk Management Statistics:")
    print(f"  Risks identified: {stats['risks_identified']}")
    print(f"  Risks assessed: {stats['risks_assessed']}")
    print(f"  Risks mitigated: {stats['risks_mitigated']}")
    print(f"  Critical risks: {stats['critical_risks']}")
    print(f"  High risks: {stats['high_risks']}")
    
    assert stats['risks_identified'] == 2, "Should identify 2 risks"
    assert stats['risks_assessed'] == 1, "Should assess 1 risk"
    assert stats['risks_mitigated'] == 1, "Should mitigate 1 risk"
    
    print("\n✅ Risk Management System test PASSED!")
    return True


def test_grc_platform():
    """Test security GRC platform."""
    print("\n" + "="*80)
    print("TEST 5: Security GRC Platform")
    print("="*80)
    
    from vaulytica.supply_chain_security import (
        get_grc_platform,
        ComplianceControl,
        ComplianceFramework,
        ControlStatus
    )
    from datetime import timedelta
    
    grc = get_grc_platform()
    
    async def run_grc_tests():
        # Implement controls
        print("\n🔒 Implementing Compliance Controls...")
        
        controls = [
            ComplianceControl(
                control_id="ctrl-001",
                framework=ComplianceFramework.SOC2,
                control_number="CC6.1",
                title="Logical and Physical Access Controls",
                description="Implement access controls to protect information assets",
                status=ControlStatus.IMPLEMENTED,
                evidence=["access_control_policy.pdf", "audit_log.csv"],
                last_assessed=datetime.utcnow(),
                next_assessment=datetime.utcnow() + timedelta(days=90),
                owner="security-team",
                automated=True
            ),
            ComplianceControl(
                control_id="ctrl-002",
                framework=ComplianceFramework.SOC2,
                control_number="CC7.2",
                title="System Monitoring",
                description="Monitor system components and detect anomalies",
                status=ControlStatus.IMPLEMENTED,
                evidence=["monitoring_dashboard.png"],
                last_assessed=datetime.utcnow(),
                next_assessment=datetime.utcnow() + timedelta(days=90),
                owner="ops-team",
                automated=True
            ),
            ComplianceControl(
                control_id="ctrl-003",
                framework=ComplianceFramework.SOC2,
                control_number="CC8.1",
                title="Change Management",
                description="Manage changes to system components",
                status=ControlStatus.PARTIAL,
                evidence=[],
                last_assessed=datetime.utcnow(),
                next_assessment=datetime.utcnow() + timedelta(days=90),
                owner="dev-team",
                automated=False
            )
        ]
        
        for control in controls:
            result = await grc.implement_control(control)
            print(f"  ✓ Control implemented: {result['control_number']}")
            print(f"    Framework: {result['framework']}")
            print(f"    Status: {result['status']}")
            print(f"    Automated: {result['automated']}")
        
        # Assess control
        print("\n📋 Assessing Control...")
        assessment = await grc.assess_control("ctrl-001")
        print(f"  ✓ Assessment completed: {assessment['control_number']}")
        print(f"    Status: {assessment['status']}")
        print(f"    Evidence count: {assessment['evidence_count']}")
        print(f"    Findings: {len(assessment['findings'])}")
        
        # Calculate compliance score
        print("\n📊 Calculating Compliance Score...")
        score = await grc.calculate_compliance_score(ComplianceFramework.SOC2)
        print(f"  ✓ Compliance score calculated")
        print(f"    Framework: {score['framework']}")
        print(f"    Compliance score: {score['compliance_score']:.1f}%")
        print(f"    Total controls: {score['total_controls']}")
        print(f"    Implemented: {score['implemented']}")
        print(f"    Partial: {score['partial']}")
        print(f"    Not implemented: {score['not_implemented']}")
        print(f"    Compliance level: {score['compliance_level']}")
        
        # Get audit trail
        print("\n📜 Retrieving Audit Trail...")
        trail = await grc.get_audit_trail()
        print(f"  ✓ Audit trail retrieved: {len(trail)} entries")
        
        for entry in trail[:3]:  # Show first 3
            print(f"    - {entry['timestamp']}: {entry['action']} on {entry['resource_type']}")
        
        return score
    
    results = asyncio.run(run_grc_tests())
    
    # Get statistics
    stats = grc.get_statistics()
    
    print(f"\n📊 GRC Platform Statistics:")
    print(f"  Controls implemented: {stats['controls_implemented']}")
    print(f"  Controls assessed: {stats['controls_assessed']}")
    print(f"  Frameworks tracked: {stats['frameworks_tracked']}")
    print(f"  Audit logs created: {stats['audit_logs_created']}")
    print(f"  Compliance score: {stats['compliance_score']:.1f}%")
    
    assert stats['controls_implemented'] == 2, "Should implement 2 controls"
    assert stats['controls_assessed'] == 1, "Should assess 1 control"
    
    print("\n✅ Security GRC Platform test PASSED!")
    return True


def test_comprehensive_assessment():
    """Test comprehensive supply chain and GRC assessment."""
    print("\n" + "="*80)
    print("TEST 6: Comprehensive Supply Chain & GRC Assessment")
    print("="*80)
    
    from vaulytica.supply_chain_security import (
        get_supply_chain_grc_orchestrator,
        ComplianceFramework
    )
    
    orchestrator = get_supply_chain_grc_orchestrator()
    
    async def run_assessment():
        print("\n🔍 Running Comprehensive Assessment...")
        
        dependencies = [
            {
                "name": "express",
                "version": "4.18.2",
                "type": "direct",
                "ecosystem": "npm",
                "license": "MIT",
                "vulnerabilities": ["CVE-2024-12345 (critical)"]
            },
            {
                "name": "lodash",
                "version": "4.17.21",
                "type": "direct",
                "ecosystem": "npm",
                "license": "MIT",
                "vulnerabilities": []
            }
        ]
        
        result = await orchestrator.perform_comprehensive_assessment(
            project_name="my-api-project",
            project_version="1.0.0",
            dependencies=dependencies,
            framework=ComplianceFramework.SOC2
        )
        
        print(f"\n✓ Assessment completed: {result['assessment_id']}")
        print(f"  Duration: {result['duration_seconds']:.2f}s")
        
        print(f"\n📦 Supply Chain Security:")
        print(f"  Dependencies scanned: {result['supply_chain_security']['dependencies_scanned']}")
        print(f"  Vulnerabilities found: {result['supply_chain_security']['vulnerabilities_found']}")
        print(f"  Critical: {result['supply_chain_security']['critical']}")
        print(f"  High: {result['supply_chain_security']['high']}")
        print(f"  License issues: {result['supply_chain_security']['license_issues']}")
        print(f"  Risk score: {result['supply_chain_security']['risk_score']:.1f}/10")
        
        print(f"\n📋 SBOM:")
        print(f"  SBOM ID: {result['sbom']['sbom_id']}")
        print(f"  Format: {result['sbom']['format']}")
        print(f"  Components: {result['sbom']['components']}")
        print(f"  Vulnerable components: {result['sbom']['vulnerable_components']}")
        
        print(f"\n✅ Compliance:")
        print(f"  Framework: {result['compliance']['framework']}")
        print(f"  Compliance score: {result['compliance']['compliance_score']:.1f}%")
        if 'compliance_level' in result['compliance']:
            print(f"  Compliance level: {result['compliance']['compliance_level']}")
        
        print(f"\n🎯 Risk Management:")
        print(f"  Total risks: {result['risk_management']['total_risks']}")
        print(f"  Average risk score: {result['risk_management']['average_risk_score']}")
        print(f"  Critical risks: {result['risk_management']['critical_risks']}")
        print(f"  High risks: {result['risk_management']['high_risks']}")
        
        print(f"\n💡 Recommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
        
        # Get comprehensive statistics
        print("\n📊 Comprehensive Statistics:")
        stats = orchestrator.get_comprehensive_statistics()
        
        for module, module_stats in stats.items():
            print(f"\n  {module}:")
            for key, value in module_stats.items():
                print(f"    {key}: {value}")
        
        return result
    
    results = asyncio.run(run_assessment())
    
    assert results['supply_chain_security']['dependencies_scanned'] == 2, "Should scan 2 dependencies"
    assert results['sbom']['components'] == 2, "Should have 2 components"
    
    print("\n✅ Comprehensive Assessment test PASSED!")
    return True


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("🚀 VAULYTICA v0.28.0 - SUPPLY CHAIN SECURITY & GRC TEST SUITE")
    print("="*80)
    
    tests = [
        ("Supply Chain Security Scanner", test_supply_chain_scanner),
        ("SBOM Management System", test_sbom_manager),
        ("Policy Engine", test_policy_engine),
        ("Risk Management System", test_risk_management),
        ("Security GRC Platform", test_grc_platform),
        ("Comprehensive Assessment", test_comprehensive_assessment)
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
        print("🎉 Vaulytica v0.28.0 Supply Chain Security & GRC is PRODUCTION READY! 🚀")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

