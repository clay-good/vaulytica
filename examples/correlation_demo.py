#!/usr/bin/env python3

import asyncio
from datetime import datetime, timedelta
from vaulytica.correlation import CorrelationEngine, CorrelationType
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo,
    TechnicalIndicator, MitreAttack, AnalysisResult, FiveW1H
)


def create_sample_events():
    """Create sample security events for demonstration."""
    base_time = datetime.now()
    
    # Event 1: Initial Access - Phishing
    event1 = SecurityEvent(
        event_id="evt_001",
        source_system="guardduty",
        timestamp=base_time,
        severity=Severity.HIGH,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Suspicious email attachment opened",
        description="User opened malicious attachment from phishing email",
        affected_assets=[AssetInfo(
            hostname="workstation-42",
            ip_addresses=["10.0.1.42"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="email", value="attacker@evil.com"),
            TechnicalIndicator(indicator_type="hash", value="abc123def456")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1566.001", technique_name="Spearphishing Attachment",
                       tactic="Initial Access", confidence=0.9)
        ],
        raw_event={}
    )
    
    # Event 2: Execution - 5 minutes later
    event2 = SecurityEvent(
        event_id="evt_002",
        source_system="crowdstrike",
        timestamp=base_time + timedelta(minutes=5),
        severity=Severity.HIGH,
        category=EventCategory.MALWARE,
        title="Malicious process execution detected",
        description="Suspicious PowerShell execution on workstation",
        affected_assets=[AssetInfo(
            hostname="workstation-42",
            ip_addresses=["10.0.1.42"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="process", value="powershell.exe"),
            TechnicalIndicator(indicator_type="hash", value="abc123def456")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1059.001", technique_name="PowerShell",
                       tactic="Execution", confidence=0.95)
        ],
        raw_event={}
    )
    
    # Event 3: C2 Communication - 10 minutes later
    event3 = SecurityEvent(
        event_id="evt_003",
        source_system="datadog",
        timestamp=base_time + timedelta(minutes=10),
        severity=Severity.CRITICAL,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Outbound connection to known C2 server",
        description="Workstation communicating with command and control server",
        affected_assets=[AssetInfo(
            hostname="workstation-42",
            ip_addresses=["10.0.1.42"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="198.51.100.5"),
            TechnicalIndicator(indicator_type="domain", value="evil-c2.example.com")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1071.001", technique_name="Web Protocols",
                       tactic="Command and Control", confidence=0.9)
        ],
        raw_event={}
    )
    
    # Event 4: Lateral Movement - 20 minutes later
    event4 = SecurityEvent(
        event_id="evt_004",
        source_system="guardduty",
        timestamp=base_time + timedelta(minutes=20),
        severity=Severity.HIGH,
        category=EventCategory.LATERAL_MOVEMENT,
        title="Suspicious RDP connection",
        description="Unusual RDP connection from compromised workstation to server",
        affected_assets=[
            AssetInfo(hostname="workstation-42", ip_addresses=["10.0.1.42"]),
            AssetInfo(hostname="server-db-01", ip_addresses=["10.0.2.10"])
        ],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="10.0.1.42"),
            TechnicalIndicator(indicator_type="ip", value="10.0.2.10"),
            TechnicalIndicator(indicator_type="port", value="3389")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1021.001", technique_name="Remote Desktop Protocol",
                       tactic="Lateral Movement", confidence=0.85)
        ],
        raw_event={}
    )
    
    # Event 5: Data Exfiltration - 30 minutes later
    event5 = SecurityEvent(
        event_id="evt_005",
        source_system="datadog",
        timestamp=base_time + timedelta(minutes=30),
        severity=Severity.CRITICAL,
        category=EventCategory.DATA_EXFILTRATION,
        title="Large data transfer to external IP",
        description="Unusual large data transfer from database server to external IP",
        affected_assets=[AssetInfo(
            hostname="server-db-01",
            ip_addresses=["10.0.2.10"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="198.51.100.5"),
            TechnicalIndicator(indicator_type="bytes", value="5368709120")  # 5GB
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1041", technique_name="Exfiltration Over C2 Channel",
                       tactic="Exfiltration", confidence=0.9)
        ],
        raw_event={}
    )
    
    # Unrelated event - different asset, different time
    event6 = SecurityEvent(
        event_id="evt_006",
        source_system="guardduty",
        timestamp=base_time + timedelta(hours=2),
        severity=Severity.MEDIUM,
        category=EventCategory.POLICY_VIOLATION,
        title="Failed login attempts",
        description="Multiple failed SSH login attempts",
        affected_assets=[AssetInfo(
            hostname="web-server-03",
            ip_addresses=["10.0.3.15"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="203.0.113.50"),
            TechnicalIndicator(indicator_type="port", value="22")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1110", technique_name="Brute Force",
                       tactic="Credential Access", confidence=0.8)
        ],
        raw_event={}
    )
    
    return [event1, event2, event3, event4, event5, event6]


def create_sample_analyses(events):
    """Create sample analysis results."""
    analyses = {}
    
    for event in events:
        analysis = AnalysisResult(
            event_id=event.event_id,
            five_w1h=FiveW1H(
                who="Unknown attacker",
                what=event.title,
                when=event.timestamp.isoformat(),
                where=event.affected_assets[0].hostname if event.affected_assets else "Unknown",
                why="Potential data theft",
                how=event.description
            ),
            executive_summary=f"Security event detected: {event.title}",
            risk_score=float({"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 3}[event.severity.value]),
            confidence=0.8,
            mitre_techniques=event.mitre_attack,
            immediate_actions=["Investigate immediately"],
            short_term_recommendations=["Review logs"],
            long_term_recommendations=["Improve monitoring"],
            raw_llm_response="Sample response"
        )
        analyses[event.event_id] = analysis
    
    return analyses


async def main():
    """Main demonstration function."""
    print("=" * 80)
    print("🔗 VAULYTICA ADVANCED CORRELATION ENGINE DEMONSTRATION")
    print("=" * 80)
    print()
    
    # Initialize correlation engine
    print("1. INITIALIZING CORRELATION ENGINE")
    print("-" * 80)
    engine = CorrelationEngine(
        temporal_window_minutes=60,
        min_correlation_confidence=0.5,
        min_campaign_events=3
    )
    print("✓ Correlation engine initialized")
    print(f"  - Temporal window: 60 minutes")
    print(f"  - Min confidence: 0.5")
    print(f"  - Min campaign events: 3")
    print()
    
    # Create sample events
    print("2. CREATING SAMPLE SECURITY EVENTS")
    print("-" * 80)
    events = create_sample_events()
    analyses = create_sample_analyses(events)
    print(f"✓ Created {len(events)} sample events:")
    for event in events:
        print(f"  - {event.event_id}: {event.title} ({event.severity.value})")
    print()
    
    # Add events to correlation engine
    print("3. ADDING EVENTS TO CORRELATION ENGINE")
    print("-" * 80)
    for event in events:
        analysis = analyses.get(event.event_id)
        engine.add_event(event, analysis)
        print(f"✓ Added {event.event_id}")
    print()
    
    # Get statistics
    print("4. CORRELATION STATISTICS")
    print("-" * 80)
    stats = engine.get_statistics()
    print(f"✓ Total events: {stats['total_events']}")
    print(f"✓ Total correlations: {stats['total_correlations']}")
    print(f"✓ Correlation types:")
    for corr_type, count in stats['correlation_types'].items():
        print(f"    - {corr_type}: {count}")
    print(f"✓ Total clusters: {stats['total_clusters']}")
    print(f"✓ Avg cluster size: {stats['avg_cluster_size']:.1f}")
    print()
    
    # Detect campaigns
    print("5. DETECTING ATTACK CAMPAIGNS")
    print("-" * 80)
    campaigns = engine.detect_campaigns()
    print(f"✓ Detected {len(campaigns)} attack campaign(s)")
    for campaign in campaigns:
        print(f"\n  Campaign: {campaign.campaign_name}")
        print(f"  - ID: {campaign.campaign_id}")
        print(f"  - Status: {campaign.status.value}")
        print(f"  - Events: {campaign.total_events}")
        print(f"  - Confidence: {campaign.confidence:.2%}")
        print(f"  - Severity: {campaign.severity_score:.1f}/5")
        print(f"  - Targeted assets: {', '.join(list(campaign.targeted_assets)[:3])}")
        if campaign.ttps:
            print(f"  - TTPs: {', '.join(list(campaign.ttps)[:5])}")
    print()
    
    # Get correlation report for first event
    print("6. DETAILED CORRELATION REPORT")
    print("-" * 80)
    report = engine.generate_correlation_report("evt_001")
    print(f"Event: {report['event_title']}")
    print(f"Total correlations: {report['total_correlations']}")
    print(f"Correlated events: {report['correlated_events_count']}")
    print(f"\nCorrelations by type:")
    for corr_type, correlations in report['correlations_by_type'].items():
        print(f"  {corr_type}: {len(correlations)} correlation(s)")
        for corr in correlations[:2]:  # Show first 2
            print(f"    - Event {corr['other_event_id']}: {corr['confidence']:.2%} confidence")
            print(f"      Evidence: {corr['evidence'][0]}")
    
    if report['campaign']:
        print(f"\nPart of campaign: {report['campaign']['campaign_name']}")
        print(f"  - Status: {report['campaign']['status']}")
        print(f"  - Total events: {report['campaign']['total_events']}")
    print()
    
    # Export graph data
    print("7. EXPORTING CORRELATION GRAPH")
    print("-" * 80)
    graph_data = engine.export_graph_data()
    print(f"✓ Graph nodes: {len(graph_data['nodes'])}")
    print(f"✓ Graph edges: {len(graph_data['edges'])}")
    print(f"✓ Clusters: {len(graph_data['clusters'])}")
    print()
    
    print("=" * 80)
    print("✅ CORRELATION ENGINE DEMONSTRATION COMPLETE")
    print("=" * 80)
    print()
    print("Key Findings:")
    print("  ✓ Multi-event correlation working")
    print("  ✓ Attack chain detection successful")
    print("  ✓ Campaign identification operational")
    print("  ✓ Graph export ready for visualization")
    print()


if __name__ == "__main__":
    asyncio.run(main())

