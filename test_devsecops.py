"""
Comprehensive tests for DevSecOps Integration & Security Orchestration (v0.27.0).

Tests all components:
- DevSecOps Pipeline Integration
- Security Orchestration Hub
- Advanced Threat Intelligence Platform
- Security Metrics & KPIs Dashboard
- Automated Penetration Testing
- DevSecOps Orchestrator
"""

import asyncio
import sys
from datetime import datetime


def test_devsecops_pipeline():
    """Test DevSecOps pipeline integration."""
    print("\n" + "="*80)
    print("TEST 1: DevSecOps Pipeline Integration")
    print("="*80)
    
    from vaulytica.devsecops import (
        get_devsecops_pipeline,
        PipelineConfig,
        PipelineType,
        SecurityGateType
    )
    
    pipeline = get_devsecops_pipeline()
    
    async def run_pipeline_tests():
        # Configure pipeline
        print("\n🔧 Configuring DevSecOps Pipeline...")
        config = PipelineConfig(
            pipeline_id="pipeline-001",
            name="Production API Pipeline",
            pipeline_type=PipelineType.GITHUB_ACTIONS,
            repository="https://github.com/example/api",
            branch="main",
            security_gates=[
                SecurityGateType.SAST,
                SecurityGateType.DAST,
                SecurityGateType.SCA,
                SecurityGateType.SECRETS_SCAN,
                SecurityGateType.CONTAINER_SCAN
            ],
            fail_on_critical=True,
            fail_on_high=False
        )
        
        result = await pipeline.configure_pipeline(config)
        print(f"  ✓ Pipeline configured: {result['pipeline_id']}")
        print(f"    Security gates: {len(result['security_gates'])}")
        
        # Execute security gates
        print("\n🔍 Executing Security Gates...")
        gate_results = await pipeline.execute_security_gates(
            pipeline_id="pipeline-001",
            commit_sha="abc123def456",
            artifacts={"image": "api:latest", "code": "/src"}
        )
        
        print(f"  ✓ Gates executed: {len(gate_results['gates'])}")
        print(f"    Overall status: {gate_results['overall_status']}")
        print(f"    Should fail build: {gate_results['should_fail_build']}")
        
        for gate in gate_results['gates']:
            print(f"    - {gate['type']}: {gate['status']} ({gate['findings']} findings)")
        
        return gate_results
    
    results = asyncio.run(run_pipeline_tests())
    
    # Get statistics
    stats = pipeline.get_statistics()
    
    print(f"\n📊 Pipeline Statistics:")
    print(f"  Pipelines configured: {stats['pipelines_configured']}")
    print(f"  Gates executed: {stats['gates_executed']}")
    print(f"  Gates passed: {stats['gates_passed']}")
    print(f"  Gates failed: {stats['gates_failed']}")
    print(f"  Vulnerabilities blocked: {stats['vulnerabilities_blocked']}")
    
    assert stats['pipelines_configured'] == 1, "Should configure 1 pipeline"
    assert stats['gates_executed'] == 5, "Should execute 5 gates"
    
    print("\n✅ DevSecOps Pipeline test PASSED!")
    return True


def test_security_orchestration():
    """Test security orchestration hub."""
    print("\n" + "="*80)
    print("TEST 2: Security Orchestration Hub")
    print("="*80)
    
    from vaulytica.devsecops import (
        get_orchestration_hub,
        OrchestrationWorkflow,
        OrchestrationAction
    )
    
    hub = get_orchestration_hub()
    
    async def run_orchestration_tests():
        # Create workflow
        print("\n🔧 Creating Orchestration Workflow...")
        workflow = OrchestrationWorkflow(
            workflow_id="workflow-001",
            name="Critical Vulnerability Response",
            description="Automated response to critical vulnerabilities",
            trigger_conditions=["vulnerability.severity == critical"],
            actions=[
                OrchestrationAction.SCAN,
                OrchestrationAction.ALERT,
                OrchestrationAction.TICKET,
                OrchestrationAction.REMEDIATE,
                OrchestrationAction.NOTIFY
            ],
            priority=10
        )
        
        result = await hub.create_workflow(workflow)
        print(f"  ✓ Workflow created: {result['workflow_id']}")
        print(f"    Actions: {len(result['actions'])}")
        print(f"    Priority: {result['priority']}")
        
        # Execute workflow
        print("\n🚀 Executing Workflow...")
        execution = await hub.execute_workflow(
            workflow_id="workflow-001",
            context={
                "vulnerability_id": "CVE-2024-12345",
                "severity": "critical",
                "target": "api.example.com",
                "ip_address": "192.168.1.100"
            }
        )
        
        print(f"  ✓ Workflow executed: {execution['workflow_id']}")
        print(f"    Duration: {execution['duration_seconds']:.2f}s")
        print(f"    Actions performed: {len(execution['actions'])}")
        
        for action in execution['actions']:
            print(f"    - {action['action']}: {action['status']}")
        
        return execution
    
    results = asyncio.run(run_orchestration_tests())
    
    # Get statistics
    stats = hub.get_statistics()
    
    print(f"\n📊 Orchestration Statistics:")
    print(f"  Workflows created: {stats['workflows_created']}")
    print(f"  Workflows executed: {stats['workflows_executed']}")
    print(f"  Actions performed: {stats['actions_performed']}")
    print(f"  Incidents auto-resolved: {stats['incidents_auto_resolved']}")
    
    assert stats['workflows_created'] == 1, "Should create 1 workflow"
    assert stats['workflows_executed'] == 1, "Should execute 1 workflow"
    assert stats['actions_performed'] == 5, "Should perform 5 actions"
    
    print("\n✅ Security Orchestration test PASSED!")
    return True


def test_threat_intelligence():
    """Test advanced threat intelligence platform."""
    print("\n" + "="*80)
    print("TEST 3: Advanced Threat Intelligence Platform")
    print("="*80)
    
    from vaulytica.devsecops import (
        get_threat_intelligence,
        ThreatIntelIndicator,
        ThreatIntelSource,
        Severity
    )
    
    intel = get_threat_intelligence()
    
    async def run_threat_intel_tests():
        # Ingest indicators
        print("\n📥 Ingesting Threat Intelligence Indicators...")
        
        indicators = [
            ThreatIntelIndicator(
                indicator_id="ind-001",
                indicator_type="ip",
                value="192.168.1.100",
                sources=[ThreatIntelSource.VIRUSTOTAL, ThreatIntelSource.ABUSE_IPDB],
                confidence_score=0.95,
                severity=Severity.CRITICAL,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                tags=["malware", "botnet", "c2"]
            ),
            ThreatIntelIndicator(
                indicator_id="ind-002",
                indicator_type="domain",
                value="malicious.example.com",
                sources=[ThreatIntelSource.ALIENVAULT_OTX],
                confidence_score=0.85,
                severity=Severity.HIGH,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                tags=["phishing", "malware"]
            ),
            ThreatIntelIndicator(
                indicator_id="ind-003",
                indicator_type="hash",
                value="abc123def456",
                sources=[ThreatIntelSource.VIRUSTOTAL, ThreatIntelSource.MITRE_ATTCK],
                confidence_score=0.90,
                severity=Severity.CRITICAL,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                tags=["malware", "ransomware"]
            )
        ]
        
        for indicator in indicators:
            result = await intel.ingest_indicator(indicator)
            print(f"  ✓ Ingested {indicator.indicator_type}: {indicator.value}")
            print(f"    Confidence: {result['confidence_score']:.2f}, Sources: {len(result['sources'])}")
        
        # Correlate indicators
        print("\n🔗 Correlating Indicators...")
        correlation = await intel.correlate_indicators(["ind-001", "ind-002", "ind-003"])
        print(f"  ✓ Correlation completed")
        print(f"    Indicators analyzed: {correlation['indicators_analyzed']}")
        print(f"    Correlations found: {correlation['correlations_found']}")
        
        for corr in correlation['correlations'][:3]:  # Show first 3
            print(f"    - {corr['correlation_type']}: confidence {corr['confidence']:.2f}")
        
        # Enrich indicator
        print("\n🔍 Enriching Indicator...")
        enrichment = await intel.enrich_indicator("ind-001")
        print(f"  ✓ Enrichment completed for {enrichment['indicator_id']}")
        print(f"    Geolocation: {enrichment['enriched_data']['geolocation']['country']}")
        print(f"    Reputation score: {enrichment['enriched_data']['reputation']['score']}")
        print(f"    Related campaigns: {len(enrichment['enriched_data']['related_campaigns'])}")
        
        return correlation
    
    results = asyncio.run(run_threat_intel_tests())
    
    # Get statistics
    stats = intel.get_statistics()
    
    print(f"\n📊 Threat Intelligence Statistics:")
    print(f"  Indicators collected: {stats['indicators_collected']}")
    print(f"  Sources integrated: {stats['sources_integrated']}")
    print(f"  Correlations found: {stats['correlations_found']}")
    print(f"  High confidence indicators: {stats['high_confidence_indicators']}")
    
    assert stats['indicators_collected'] == 3, "Should collect 3 indicators"
    assert stats['correlations_found'] > 0, "Should find correlations"
    
    print("\n✅ Advanced Threat Intelligence test PASSED!")
    return True


def test_security_metrics():
    """Test security metrics dashboard."""
    print("\n" + "="*80)
    print("TEST 4: Security Metrics & KPIs Dashboard")
    print("="*80)
    
    from vaulytica.devsecops import get_metrics_dashboard
    
    dashboard = get_metrics_dashboard()
    
    async def run_metrics_tests():
        # Collect metrics
        print("\n📊 Collecting Security Metrics...")
        metrics = await dashboard.collect_metrics()
        
        print(f"  ✓ Metrics collected: {metrics.metric_id}")
        print(f"    Security posture score: {metrics.security_posture_score:.1f}/100")
        print(f"    Compliance score: {metrics.compliance_score:.1f}/100")
        print(f"    Total vulnerabilities: {metrics.vulnerabilities_total}")
        print(f"    By severity: {metrics.vulnerabilities_by_severity}")
        print(f"    MTTD: {metrics.mean_time_to_detect:.1f}h")
        print(f"    MTTR: {metrics.mean_time_to_respond:.1f}h")
        print(f"    MTTR (remediate): {metrics.mean_time_to_remediate:.1f}h")
        
        # Generate executive report
        print("\n📝 Generating Executive Report...")
        report = await dashboard.generate_executive_report()
        
        print(f"  ✓ Report generated: {report['report_id']}")
        print(f"    Security posture: {report['summary']['security_posture_score']:.1f}")
        print(f"    Compliance: {report['summary']['compliance_score']:.1f}")
        print(f"    Trend: {report['summary']['trend']}")
        print(f"    Risk level: {report['summary']['risk_level']}")
        print(f"    Total incidents: {report['incident_response']['total_incidents']}")
        print(f"    Resolution rate: {report['incident_response']['resolution_rate']}")
        print(f"    Recommendations: {len(report['recommendations'])}")
        
        for rec in report['recommendations']:
            print(f"      - {rec}")
        
        return report
    
    results = asyncio.run(run_metrics_tests())
    
    # Get statistics
    stats = dashboard.get_statistics()
    
    print(f"\n📊 Dashboard Statistics:")
    print(f"  Metrics collected: {stats['metrics_collected']}")
    print(f"  Average posture score: {stats['average_posture_score']:.1f}")
    print(f"  Average compliance score: {stats['average_compliance_score']:.1f}")
    print(f"  Trend: {stats['trend']}")
    
    assert stats['metrics_collected'] > 0, "Should collect metrics"
    
    print("\n✅ Security Metrics Dashboard test PASSED!")
    return True


def test_automated_pentesting():
    """Test automated penetration testing."""
    print("\n" + "="*80)
    print("TEST 5: Automated Penetration Testing")
    print("="*80)
    
    from vaulytica.devsecops import get_automated_pentesting, PentestType
    
    pentesting = get_automated_pentesting()
    
    async def run_pentest_tests():
        # Execute different types of pentests
        test_types = [
            (PentestType.NETWORK, "10.0.0.0/24"),
            (PentestType.WEB_APPLICATION, "https://api.example.com"),
            (PentestType.API, "https://api.example.com/v1")
        ]
        
        results = []
        
        for test_type, target in test_types:
            print(f"\n🔍 Executing {test_type.value} Pentest...")
            result = await pentesting.execute_pentest(test_type, target, {})
            results.append(result)
            
            print(f"  ✓ Test completed: {result.test_id}")
            print(f"    Target: {result.target}")
            print(f"    Vulnerabilities found: {result.vulnerabilities_found}")
            print(f"    Critical: {len(result.critical_findings)}")
            print(f"    High: {len(result.high_findings)}")
            print(f"    Medium: {len(result.medium_findings)}")
            print(f"    Low: {len(result.low_findings)}")
            print(f"    Risk score: {result.risk_score:.1f}/10")
            print(f"    Duration: {result.duration_seconds:.2f}s")
            print(f"    Recommendations: {len(result.recommendations)}")
        
        return results
    
    results = asyncio.run(run_pentest_tests())
    
    # Get statistics
    stats = pentesting.get_statistics()
    
    print(f"\n📊 Pentesting Statistics:")
    print(f"  Tests executed: {stats['tests_executed']}")
    print(f"  Vulnerabilities found: {stats['vulnerabilities_found']}")
    print(f"  Critical findings: {stats['critical_findings']}")
    print(f"  High findings: {stats['high_findings']}")
    
    assert stats['tests_executed'] == 3, "Should execute 3 pentests"
    assert stats['vulnerabilities_found'] > 0, "Should find vulnerabilities"
    
    print("\n✅ Automated Penetration Testing test PASSED!")
    return True


def test_full_assessment():
    """Test full security assessment."""
    print("\n" + "="*80)
    print("TEST 6: Full Security Assessment")
    print("="*80)
    
    from vaulytica.devsecops import get_devsecops_orchestrator
    
    orchestrator = get_devsecops_orchestrator()
    
    async def run_assessment():
        print("\n🔍 Running Full Security Assessment...")
        results = await orchestrator.perform_full_security_assessment(
            target="https://api.example.com",
            assessment_type="comprehensive"
        )
        
        print(f"\n✓ Assessment completed: {results['assessment_id']}")
        print(f"  Duration: {results['duration_seconds']:.2f}s")
        
        print(f"\n📊 Security Metrics:")
        print(f"  Posture score: {results['security_metrics']['posture_score']:.1f}")
        print(f"  Compliance score: {results['security_metrics']['compliance_score']:.1f}")
        print(f"  Total vulnerabilities: {results['security_metrics']['vulnerabilities_total']}")
        print(f"  By severity: {results['security_metrics']['by_severity']}")
        
        print(f"\n🔍 Penetration Testing:")
        print(f"  Tests executed: {results['penetration_testing']['tests_executed']}")
        print(f"  Total vulnerabilities: {results['penetration_testing']['total_vulnerabilities']}")
        print(f"  Critical findings: {results['penetration_testing']['critical_findings']}")
        print(f"  High findings: {results['penetration_testing']['high_findings']}")
        
        print(f"\n📝 Executive Report:")
        print(f"  Risk level: {results['overall_risk_level']}")
        print(f"  Recommendations: {len(results['executive_report']['recommendations'])}")
        
        # Get comprehensive statistics
        print("\n📊 Comprehensive Statistics:")
        stats = orchestrator.get_comprehensive_statistics()
        
        for module, module_stats in stats.items():
            print(f"\n  {module}:")
            for key, value in module_stats.items():
                print(f"    {key}: {value}")
        
        return results
    
    results = asyncio.run(run_assessment())
    
    assert results['penetration_testing']['tests_executed'] == 3, "Should execute 3 pentests"
    assert results['overall_risk_level'] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "Should have valid risk level"
    
    print("\n✅ Full Security Assessment test PASSED!")
    return True


def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("🚀 VAULYTICA v0.27.0 - DEVSECOPS & ORCHESTRATION TEST SUITE")
    print("="*80)
    
    tests = [
        ("DevSecOps Pipeline Integration", test_devsecops_pipeline),
        ("Security Orchestration Hub", test_security_orchestration),
        ("Advanced Threat Intelligence", test_threat_intelligence),
        ("Security Metrics Dashboard", test_security_metrics),
        ("Automated Penetration Testing", test_automated_pentesting),
        ("Full Security Assessment", test_full_assessment)
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
        print("🎉 Vaulytica v0.27.0 DevSecOps & Orchestration is PRODUCTION READY! 🚀")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

