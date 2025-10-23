#!/usr/bin/env python3
"""
Vaulytica Forensics Engine Demo

Demonstrates comprehensive digital forensics and investigation capabilities:
1. Evidence Collection - Automated collection from multiple sources
2. Chain of Custody - Cryptographic integrity verification
3. Evidence Analysis - Automated analysis with findings
4. Investigation Workflows - Guided investigation with templates
5. Forensic Reporting - Comprehensive report generation
6. Integration with Security Events - Create investigations from events

Author: World-Class Software Engineering Team
Version: 0.17.0
"""

import asyncio
from datetime import datetime, timedelta
from vaulytica.forensics import (
    ForensicsEngine, get_forensics_engine,
    EvidenceType, EvidenceSource, CollectionMethod,
    InvestigationType, AnalysisType,
    Severity
)
from vaulytica.models import SecurityEvent, EventCategory


def print_section(title: str):
    """Print section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


async def demo_evidence_collection():
    """Demo 1: Evidence Collection"""
    print_section("DEMO 1: Evidence Collection")
    
    forensics = get_forensics_engine()
    
    print("Collecting evidence from multiple sources...\n")
    
    # Collect system logs
    evidence1 = await forensics.evidence_collector.collect_evidence(
        evidence_type=EvidenceType.SYSTEM_LOGS,
        source=EvidenceSource.ENDPOINT,
        source_system="web-server-01",
        collected_by="forensics_agent",
        collection_method=CollectionMethod.AGENT_BASED,
        source_ip="10.0.1.50",
        source_hostname="web-server-01.internal",
        data={
            "timestamp": datetime.now().isoformat(),
            "logs": [
                "2024-01-15 10:30:00 - Failed login attempt from 192.168.1.100",
                "2024-01-15 10:30:05 - Failed login attempt from 192.168.1.100",
                "2024-01-15 10:30:10 - Failed login attempt from 192.168.1.100",
                "2024-01-15 10:30:15 - Successful login from 192.168.1.100",
                "2024-01-15 10:31:00 - Unauthorized file access attempt"
            ]
        },
        tags=["brute_force", "unauthorized_access"]
    )
    
    print(f"✓ Collected System Logs: {evidence1.evidence_id}")
    print(f"  Source: {evidence1.source_system}")
    print(f"  Size: {evidence1.data_size} bytes")
    print(f"  SHA-256: {evidence1.hash_sha256[:32]}...")
    print(f"  Chain of Custody Entries: {len(evidence1.chain_of_custody)}")
    print()
    
    # Collect network capture
    evidence2 = await forensics.evidence_collector.collect_evidence(
        evidence_type=EvidenceType.NETWORK_CAPTURE,
        source=EvidenceSource.NETWORK_DEVICE,
        source_system="firewall-01",
        collected_by="forensics_agent",
        collection_method=CollectionMethod.REMOTE_COLLECTION,
        data={
            "timestamp": datetime.now().isoformat(),
            "connections": [
                {"src": "10.0.1.50", "dst": "203.0.113.50", "port": 443, "protocol": "HTTPS"},
                {"src": "10.0.1.50", "dst": "198.51.100.25", "port": 22, "protocol": "SSH"}
            ]
        },
        tags=["network_traffic", "outbound_connections"]
    )
    
    print(f"✓ Collected Network Capture: {evidence2.evidence_id}")
    print(f"  Source: {evidence2.source_system}")
    print(f"  Size: {evidence2.data_size} bytes")
    print()
    
    # Collect memory dump
    evidence3 = await forensics.evidence_collector.collect_evidence(
        evidence_type=EvidenceType.MEMORY_DUMP,
        source=EvidenceSource.ENDPOINT,
        source_system="workstation-42",
        collected_by="forensics_agent",
        collection_method=CollectionMethod.LIVE_COLLECTION,
        data={
            "timestamp": datetime.now().isoformat(),
            "processes": [
                {"pid": 1234, "name": "suspicious.exe", "memory": "50MB"},
                {"pid": 5678, "name": "malware.dll", "memory": "25MB"}
            ]
        },
        tags=["memory_analysis", "malware"]
    )
    
    print(f"✓ Collected Memory Dump: {evidence3.evidence_id}")
    print(f"  Source: {evidence3.source_system}")
    print(f"  Size: {evidence3.data_size} bytes")
    print()
    
    # Get statistics
    stats = forensics.evidence_collector.get_statistics()
    print(f"Collection Statistics:")
    print(f"  Total Collected: {stats['total_collected']}")
    print(f"  Total Size: {stats['total_size_mb']} MB")
    print(f"  By Type: {stats['collections_by_type']}")
    
    return [evidence1, evidence2, evidence3]


async def demo_chain_of_custody(evidence_list):
    """Demo 2: Chain of Custody"""
    print_section("DEMO 2: Chain of Custody & Integrity Verification")
    
    forensics = get_forensics_engine()
    evidence = evidence_list[0]
    
    print(f"Evidence: {evidence.evidence_id}\n")
    
    # Add custody entries
    print("Adding chain of custody entries...\n")
    
    forensics.evidence_collector.add_custody_entry(
        evidence_id=evidence.evidence_id,
        action="transferred",
        actor="forensics_analyst_1",
        location="forensics_lab",
        purpose="Transfer to forensics lab for analysis"
    )
    
    forensics.evidence_collector.add_custody_entry(
        evidence_id=evidence.evidence_id,
        action="accessed",
        actor="forensics_analyst_2",
        location="forensics_lab",
        purpose="Initial review and triage"
    )
    
    # Display chain of custody
    updated_evidence = forensics.evidence_collector.get_evidence(evidence.evidence_id)
    print(f"Chain of Custody ({len(updated_evidence.chain_of_custody)} entries):")
    for i, entry in enumerate(updated_evidence.chain_of_custody, 1):
        print(f"  {i}. {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"     Action: {entry.action}")
        print(f"     Actor: {entry.actor}")
        print(f"     Location: {entry.location}")
        print(f"     Purpose: {entry.purpose}")
        if entry.hash_after:
            print(f"     Hash: {entry.hash_after[:32]}...")
        print()
    
    # Verify integrity
    print("Verifying evidence integrity...")
    is_valid, message = forensics.evidence_collector.verify_integrity(evidence.evidence_id)
    print(f"  Result: {'✓ VALID' if is_valid else '✗ INVALID'}")
    print(f"  Message: {message}")


async def demo_evidence_analysis(evidence_list):
    """Demo 3: Evidence Analysis"""
    print_section("DEMO 3: Evidence Analysis")
    
    forensics = get_forensics_engine()
    
    print("Analyzing collected evidence...\n")
    
    # Analyze system logs
    print("1. Log Analysis")
    result1 = await forensics.evidence_analyzer.analyze_evidence(
        evidence_id=evidence_list[0].evidence_id,
        analysis_type=AnalysisType.LOG_ANALYSIS,
        analyzed_by="forensics_analyst_1",
        analysis_tool="log_analyzer_v2"
    )
    
    print(f"   Evidence: {result1.evidence_id}")
    print(f"   Analysis Type: {result1.analysis_type.value}")
    print(f"   Confidence: {result1.confidence:.2%}")
    print(f"   Severity: {result1.severity.value}")
    print(f"   Findings: {len(result1.findings)}")
    for finding in result1.findings:
        print(f"     - {finding['type']}: {finding['description']}")
    print(f"   Indicators: {', '.join(result1.indicators)}")
    print()
    
    # Analyze network traffic
    print("2. Network Analysis")
    result2 = await forensics.evidence_analyzer.analyze_evidence(
        evidence_id=evidence_list[1].evidence_id,
        analysis_type=AnalysisType.NETWORK_ANALYSIS,
        analyzed_by="forensics_analyst_1"
    )
    
    print(f"   Evidence: {result2.evidence_id}")
    print(f"   Findings: {len(result2.findings)}")
    for finding in result2.findings:
        print(f"     - {finding['type']}: {finding['description']}")
    print()
    
    # Analyze memory dump
    print("3. File Analysis (Memory)")
    result3 = await forensics.evidence_analyzer.analyze_evidence(
        evidence_id=evidence_list[2].evidence_id,
        analysis_type=AnalysisType.FILE_ANALYSIS,
        analyzed_by="forensics_analyst_2"
    )
    
    print(f"   Evidence: {result3.evidence_id}")
    print(f"   Findings: {len(result3.findings)}")
    for finding in result3.findings:
        print(f"     - {finding['type']}: {finding['description']}")
    print()
    
    # Get statistics
    stats = forensics.evidence_analyzer.get_statistics()
    print(f"Analysis Statistics:")
    print(f"  Total Analyzed: {stats['total_analyzed']}")
    print(f"  Total Findings: {stats['total_findings']}")
    print(f"  Avg Findings/Analysis: {stats['avg_findings_per_analysis']}")


async def demo_investigation_workflow():
    """Demo 4: Investigation Workflow"""
    print_section("DEMO 4: Investigation Workflow")
    
    forensics = get_forensics_engine()
    
    print("Creating investigation with template...\n")
    
    # Create investigation
    investigation = forensics.investigation_manager.create_investigation(
        investigation_type=InvestigationType.SECURITY_INCIDENT,
        title="Unauthorized Access Investigation",
        description="Investigation of unauthorized access attempt on web-server-01",
        severity=Severity.HIGH,
        lead_investigator="John Doe",
        use_template=True
    )
    
    print(f"✓ Investigation Created: {investigation.investigation_id}")
    print(f"  Title: {investigation.title}")
    print(f"  Type: {investigation.investigation_type.value}")
    print(f"  Severity: {investigation.severity.value}")
    print(f"  Lead: {investigation.lead_investigator}")
    print(f"  Tasks: {len(investigation.tasks)}")
    print()
    
    # Display tasks
    print("Investigation Tasks:")
    for i, task in enumerate(investigation.tasks, 1):
        print(f"  {i}. {task.task_name} (Priority: {task.priority})")
        print(f"     Status: {task.status}")
        print(f"     Type: {task.task_type}")
        if task.required_evidence:
            print(f"     Required Evidence: {', '.join(task.required_evidence)}")
    print()
    
    # Link evidence
    print("Linking evidence to investigation...")
    evidence_list = forensics.evidence_collector.list_evidence()
    for evidence in evidence_list[:3]:
        forensics.investigation_manager.add_evidence_to_investigation(
            investigation.investigation_id,
            evidence.evidence_id
        )
    print(f"✓ Linked {len(evidence_list[:3])} evidence items")
    print()
    
    # Update task status
    print("Updating task status...")
    task = investigation.tasks[0]
    forensics.investigation_manager.update_task_status(
        investigation_id=investigation.investigation_id,
        task_id=task.task_id,
        status="completed",
        findings="Initial triage completed. High severity incident confirmed.",
        assigned_to="John Doe"
    )
    print(f"✓ Task '{task.task_name}' marked as completed")
    print()
    
    # Get statistics
    stats = forensics.investigation_manager.get_statistics()
    print(f"Investigation Statistics:")
    print(f"  Total Investigations: {stats['total_investigations']}")
    print(f"  Active: {stats['active_investigations']}")
    print(f"  By Type: {stats['investigations_by_type']}")
    
    return investigation


async def demo_forensic_report(investigation):
    """Demo 5: Forensic Report Generation"""
    print_section("DEMO 5: Forensic Report Generation")
    
    forensics = get_forensics_engine()
    
    print("Generating comprehensive forensic report...\n")
    
    # Update investigation with findings
    investigation.findings = {
        "Attack Vector": "Brute force authentication attack followed by unauthorized file access",
        "Compromised Systems": "web-server-01 (10.0.1.50)",
        "Attack Timeline": "2024-01-15 10:30:00 - 10:31:00 UTC"
    }
    investigation.indicators_of_compromise = [
        "IP Address: 192.168.1.100",
        "Failed login attempts: 3",
        "Unauthorized file access attempt",
        "Suspicious outbound connections"
    ]
    investigation.root_cause = "Weak password policy allowed successful brute force attack"
    investigation.impact_assessment = "Potential unauthorized access to sensitive files. No confirmed data exfiltration."
    investigation.recommendations = [
        "Implement multi-factor authentication",
        "Enforce strong password policy",
        "Deploy intrusion detection system",
        "Conduct security awareness training",
        "Review and update access controls"
    ]
    
    # Generate report
    report = forensics.report_generator.generate_report(
        investigation_id=investigation.investigation_id,
        format="markdown"
    )
    
    # Display report (first 50 lines)
    print("Forensic Report Preview:")
    print("-" * 80)
    lines = report.split('\n')
    for line in lines[:50]:
        print(line)
    if len(lines) > 50:
        print(f"\n... ({len(lines) - 50} more lines)")
    print("-" * 80)


async def demo_event_integration():
    """Demo 6: Integration with Security Events"""
    print_section("DEMO 6: Integration with Security Events")
    
    forensics = get_forensics_engine()
    
    print("Creating investigation from security event...\n")
    
    # Create security event
    event = SecurityEvent(
        event_id="evt_malware_001",
        source_system="endpoint_protection",
        title="Malware Detected on Workstation",
        description="Ransomware detected on workstation-42",
        severity=Severity.CRITICAL,
        category=EventCategory.MALWARE,
        timestamp=datetime.now(),
        raw_event={
            "malware_family": "ransomware",
            "file_path": "C:\\Users\\user\\Downloads\\malicious.exe",
            "hash": "abc123def456"
        }
    )
    
    print(f"Security Event: {event.event_id}")
    print(f"  Title: {event.title}")
    print(f"  Severity: {event.severity.value}")
    print(f"  Category: {event.category.value}")
    print()
    
    # Create investigation from event
    investigation = await forensics.create_investigation_from_event(
        event=event,
        lead_investigator="Jane Smith"
    )
    
    print(f"✓ Investigation Created: {investigation.investigation_id}")
    print(f"  Type: {investigation.investigation_type.value}")
    print(f"  Tasks: {len(investigation.tasks)}")
    print(f"  Evidence Items: {len(investigation.evidence_items)}")
    print()
    
    print("Investigation Tasks:")
    for i, task in enumerate(investigation.tasks[:5], 1):
        print(f"  {i}. {task.task_name}")


async def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  VAULYTICA FORENSICS ENGINE - COMPREHENSIVE DEMO")
    print("=" * 80)
    
    # Demo 1: Evidence Collection
    evidence_list = await demo_evidence_collection()
    
    # Demo 2: Chain of Custody
    await demo_chain_of_custody(evidence_list)
    
    # Demo 3: Evidence Analysis
    await demo_evidence_analysis(evidence_list)
    
    # Demo 4: Investigation Workflow
    investigation = await demo_investigation_workflow()
    
    # Demo 5: Forensic Report
    await demo_forensic_report(investigation)
    
    # Demo 6: Event Integration
    await demo_event_integration()
    
    # Final Summary
    print_section("DEMO COMPLETE - SUMMARY")
    
    forensics = get_forensics_engine()
    metrics = forensics.get_comprehensive_metrics()
    
    print("Forensics Engine Metrics:")
    print(f"\nEvidence Collection:")
    print(f"  Total Collected: {metrics['evidence_collector']['total_collected']}")
    print(f"  Total Size: {metrics['evidence_collector']['total_size_mb']} MB")
    print(f"  Stored Evidence: {metrics['evidence_collector']['stored_evidence']}")
    
    print(f"\nEvidence Analysis:")
    print(f"  Total Analyzed: {metrics['evidence_analyzer']['total_analyzed']}")
    print(f"  Total Findings: {metrics['evidence_analyzer']['total_findings']}")
    
    print(f"\nInvestigations:")
    print(f"  Total: {metrics['investigation_manager']['total_investigations']}")
    print(f"  Active: {metrics['investigation_manager']['active_investigations']}")
    
    print("\n" + "=" * 80)
    print("✅ ALL DEMOS COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print("\nForensics Engine Features Demonstrated:")
    print("  ✓ Automated evidence collection from multiple sources")
    print("  ✓ Cryptographic chain of custody with integrity verification")
    print("  ✓ Automated evidence analysis with findings extraction")
    print("  ✓ Guided investigation workflows with templates")
    print("  ✓ Comprehensive forensic report generation")
    print("  ✓ Integration with security event management")
    print("\n")


if __name__ == "__main__":
    asyncio.run(main())

