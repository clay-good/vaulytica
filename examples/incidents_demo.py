#!/usr/bin/env python3
"""
Demonstration of Vaulytica's Incident Management & Alerting System.

This script demonstrates:
- Alert deduplication
- Incident creation and lifecycle management
- SLA tracking and escalation
- On-call scheduling
- Ticketing system integration
- Incident metrics and reporting
"""

import asyncio
from datetime import datetime, timedelta
from vaulytica.incidents import (
    get_incident_manager, get_ticketing_manager,
    IncidentStatus, IncidentPriority, EscalationLevel,
    TicketingSystem, TicketingConfig,
    get_incident_summary, format_incident_for_notification
)
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo,
    TechnicalIndicator, MitreAttack
)


def create_sample_events():
    """Create sample security events for demonstration."""
    base_time = datetime.utcnow()
    events = []
    
    # Event 1: Brute force attack
    events.append(SecurityEvent(
        event_id="evt-001",
        source_system="GuardDuty",
        timestamp=base_time,
        severity=Severity.HIGH,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Brute force SSH attack detected",
        description="Multiple failed SSH login attempts from suspicious IP",
        affected_assets=[AssetInfo(
            hostname="web-server-01",
            ip_addresses=["10.0.1.100"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="203.0.113.45"),
            TechnicalIndicator(indicator_type="port", value="22")
        ],
        mitre_attack=[
            MitreAttack(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                confidence=0.9
            )
        ],
        raw_event={},
        metadata={"source_ip": "203.0.113.45", "user": "root", "attempts": 50}
    ))
    
    # Event 2: Same brute force (should be deduplicated)
    events.append(SecurityEvent(
        event_id="evt-002",
        source_system="GuardDuty",
        timestamp=base_time + timedelta(minutes=2),
        severity=Severity.HIGH,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Brute force SSH attack detected",
        description="Multiple failed SSH login attempts from suspicious IP",
        affected_assets=[AssetInfo(
            hostname="web-server-01",
            ip_addresses=["10.0.1.100"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="203.0.113.45"),
            TechnicalIndicator(indicator_type="port", value="22")
        ],
        mitre_attack=[
            MitreAttack(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                confidence=0.9
            )
        ],
        raw_event={},
        metadata={"source_ip": "203.0.113.45", "user": "root", "attempts": 75}
    ))
    
    # Event 3: Data exfiltration
    events.append(SecurityEvent(
        event_id="evt-003",
        source_system="Datadog",
        timestamp=base_time + timedelta(minutes=10),
        severity=Severity.CRITICAL,
        category=EventCategory.DATA_EXFILTRATION,
        title="Large data transfer to external IP",
        description="Unusual outbound data transfer detected",
        affected_assets=[AssetInfo(
            hostname="db-server-01",
            ip_addresses=["10.0.2.50"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="198.51.100.10"),
            TechnicalIndicator(indicator_type="bytes_transferred", value="5GB")
        ],
        mitre_attack=[
            MitreAttack(
                technique_id="T1048",
                technique_name="Exfiltration Over Alternative Protocol",
                tactic="Exfiltration",
                confidence=0.85
            )
        ],
        raw_event={},
        metadata={"destination_ip": "198.51.100.10", "bytes": 5368709120}
    ))
    
    # Event 4: Malware detection
    events.append(SecurityEvent(
        event_id="evt-004",
        source_system="CrowdStrike",
        timestamp=base_time + timedelta(minutes=15),
        severity=Severity.CRITICAL,
        category=EventCategory.MALWARE,
        title="Ransomware detected",
        description="Ransomware behavior detected on endpoint",
        affected_assets=[AssetInfo(
            hostname="laptop-user123",
            ip_addresses=["10.0.3.75"],
            environment="corporate"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="file_hash", value="a1b2c3d4e5f6..."),
            TechnicalIndicator(indicator_type="process", value="malware.exe")
        ],
        mitre_attack=[
            MitreAttack(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactic="Impact",
                confidence=0.95
            )
        ],
        raw_event={},
        metadata={"user": "user123", "file_path": "C:\\temp\\malware.exe"}
    ))
    
    # Event 5: Privilege escalation
    events.append(SecurityEvent(
        event_id="evt-005",
        source_system="Snowflake",
        timestamp=base_time + timedelta(minutes=20),
        severity=Severity.HIGH,
        category=EventCategory.PRIVILEGE_ESCALATION,
        title="Unauthorized privilege escalation",
        description="User gained admin privileges without approval",
        affected_assets=[AssetInfo(
            hostname="snowflake-prod",
            cloud_resource_id="account-12345",
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="user", value="user@example.com"),
            TechnicalIndicator(indicator_type="role", value="ACCOUNTADMIN")
        ],
        mitre_attack=[
            MitreAttack(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Privilege Escalation",
                confidence=0.8
            )
        ],
        raw_event={},
        metadata={"user": "user@example.com", "role": "ACCOUNTADMIN"}
    ))
    
    return events


async def demo_incident_lifecycle():
    """Demonstrate incident lifecycle management."""
    print("\n" + "=" * 80)
    print("DEMO 1: Incident Lifecycle Management")
    print("=" * 80)
    
    manager = get_incident_manager()
    
    # Setup on-call schedule
    manager.on_call_schedule.add_user(EscalationLevel.L1_ANALYST, "user@example.com")
    manager.on_call_schedule.add_user(EscalationLevel.L2_SENIOR_ANALYST, "user@example.com")
    manager.on_call_schedule.add_user(EscalationLevel.L3_SECURITY_ENGINEER, "user@example.com")
    
    print("\n✓ On-call schedule configured")
    print(f"  L1 Analyst: user@example.com")
    print(f"  L2 Senior Analyst: user@example.com")
    print(f"  L3 Security Engineer: user@example.com")
    
    # Create sample events
    events = create_sample_events()
    
    # Process events
    print(f"\n✓ Processing {len(events)} security events...")
    incidents = []
    for event in events:
        incident, is_new = manager.process_event(event)
        if is_new:
            incidents.append(incident)
            print(f"  • Created incident {incident.incident_id[:8]}... - {incident.title}")
        else:
            print(f"  • Added to existing incident {incident.incident_id[:8]}... (deduplicated)")
    
    print(f"\n✓ Created {len(incidents)} unique incidents")
    
    # Demonstrate lifecycle
    if incidents:
        incident = incidents[0]
        print(f"\n✓ Demonstrating lifecycle for incident: {incident.incident_id[:8]}...")
        
        # Acknowledge
        manager.acknowledge_incident(incident.incident_id, "user@example.com")
        print(f"  1. Acknowledged by user@example.com")
        print(f"     Status: {incident.status.value}")
        
        # Start investigation
        manager.start_investigation(incident.incident_id, "user@example.com")
        print(f"  2. Investigation started")
        print(f"     Status: {incident.status.value}")
        
        # Add note
        incident.add_note("user@example.com", "Investigating source IP 203.0.113.45")
        print(f"  3. Added investigation note")
        
        # Resolve
        manager.resolve_incident(
            incident.incident_id,
            "user@example.com",
            "Blocked source IP and reset user password"
        )
        print(f"  4. Resolved")
        print(f"     Status: {incident.status.value}")
        print(f"     Time to resolve: {incident.get_time_to_resolve()}")
        
        # Close
        manager.close_incident(incident.incident_id, "user@example.com", "Verified resolution")
        print(f"  5. Closed")
        print(f"     Status: {incident.status.value}")


async def demo_alert_deduplication():
    """Demonstrate alert deduplication."""
    print("\n" + "=" * 80)
    print("DEMO 2: Alert Deduplication")
    print("=" * 80)
    
    manager = get_incident_manager()
    events = create_sample_events()
    
    # Process first event
    event1 = events[0]
    incident1, is_new1 = manager.process_event(event1)
    print(f"\n✓ Event 1: {event1.title}")
    print(f"  Incident ID: {incident1.incident_id[:8]}...")
    print(f"  Is New: {is_new1}")
    print(f"  Event Count: {incident1.event_count}")
    
    # Process duplicate event
    event2 = events[1]
    incident2, is_new2 = manager.process_event(event2)
    print(f"\n✓ Event 2 (duplicate): {event2.title}")
    print(f"  Incident ID: {incident2.incident_id[:8]}...")
    print(f"  Is New: {is_new2}")
    print(f"  Event Count: {incident2.event_count}")
    print(f"  Deduplicated Count: {incident2.deduplicated_count}")
    
    print(f"\n✓ Deduplication Result:")
    print(f"  Same Incident: {incident1.incident_id == incident2.incident_id}")
    print(f"  Total Alerts Received: {manager.total_alerts_received}")
    print(f"  Alerts Deduplicated: {manager.total_alerts_deduplicated}")
    print(f"  Deduplication Rate: {(manager.total_alerts_deduplicated / manager.total_alerts_received * 100):.1f}%")


async def demo_sla_tracking():
    """Demonstrate SLA tracking and escalation."""
    print("\n" + "=" * 80)
    print("DEMO 3: SLA Tracking & Escalation")
    print("=" * 80)
    
    manager = get_incident_manager()
    events = create_sample_events()
    
    # Create critical incident
    critical_event = events[2]  # Data exfiltration
    incident, _ = manager.process_event(critical_event)
    
    print(f"\n✓ Created critical incident: {incident.incident_id[:8]}...")
    print(f"  Priority: {incident.priority.value}")
    print(f"  Severity: {incident.severity.value}")
    
    # Get SLA policy
    policy = manager.sla_tracker.get_policy(incident.priority)
    print(f"\n✓ SLA Policy for {incident.priority.value}:")
    print(f"  Acknowledgement Time: {policy.acknowledgement_time}")
    print(f"  Response Time: {policy.response_time}")
    print(f"  Resolution Time: {policy.resolution_time}")
    print(f"  Escalation Time: {policy.escalation_time}")
    
    # Check SLA status
    breaches = manager.sla_tracker.check_sla(incident)
    print(f"\n✓ Current SLA Status:")
    for breach_type, is_breached in breaches.items():
        status = "❌ BREACHED" if is_breached else "✓ OK"
        print(f"  {breach_type.capitalize()}: {status}")


async def demo_ticketing_integration():
    """Demonstrate ticketing system integration."""
    print("\n" + "=" * 80)
    print("DEMO 4: Ticketing System Integration")
    print("=" * 80)
    
    manager = get_incident_manager()
    ticketing = get_ticketing_manager()
    
    # Configure Jira
    jira_config = TicketingConfig(
        system=TicketingSystem.JIRA,
        enabled=True,
        jira_url="https://your-company.atlassian.net",
        jira_project_key="SEC"
    )
    ticketing.add_integration(jira_config)
    print("\n✓ Configured Jira integration")
    
    # Configure PagerDuty
    pagerduty_config = TicketingConfig(
        system=TicketingSystem.PAGERDUTY,
        enabled=True,
        pagerduty_api_key="dummy-key"
    )
    ticketing.add_integration(pagerduty_config)
    print("✓ Configured PagerDuty integration")
    
    # Create incident
    events = create_sample_events()
    incident, _ = manager.process_event(events[2])  # Critical event
    
    # Create tickets
    print(f"\n✓ Creating tickets for incident: {incident.incident_id[:8]}...")
    tickets = await ticketing.create_tickets(incident)
    
    print(f"\n✓ Created {len(tickets)} tickets:")
    for system, ticket_id in tickets.items():
        print(f"  • {system}: {ticket_id}")


async def demo_incident_metrics():
    """Demonstrate incident metrics and reporting."""
    print("\n" + "=" * 80)
    print("DEMO 5: Incident Metrics & Reporting")
    print("=" * 80)
    
    manager = get_incident_manager()
    
    # Process all events
    events = create_sample_events()
    for event in events:
        manager.process_event(event)
    
    # Get metrics
    metrics = manager.get_metrics()
    
    print(f"\n✓ Incident Metrics:")
    print(f"  Total Incidents: {metrics.total_incidents}")
    print(f"  Open Incidents: {metrics.open_incidents}")
    print(f"  Resolved Incidents: {metrics.resolved_incidents}")
    print(f"  Closed Incidents: {metrics.closed_incidents}")
    print(f"  SLA Breaches: {metrics.sla_breaches}")
    print(f"  Escalations: {metrics.escalations}")
    
    print(f"\n✓ By Priority:")
    for priority, count in metrics.incidents_by_priority.items():
        print(f"  {priority}: {count}")
    
    print(f"\n✓ By Severity:")
    for severity, count in metrics.incidents_by_severity.items():
        print(f"  {severity}: {count}")
    
    print(f"\n✓ Deduplication:")
    print(f"  Alerts Deduplicated: {metrics.alerts_deduplicated}")
    print(f"  Deduplication Rate: {metrics.deduplication_rate:.1f}%")
    
    if metrics.avg_time_to_acknowledge:
        print(f"\n✓ Performance:")
        print(f"  Avg Time to Acknowledge: {metrics.avg_time_to_acknowledge:.1f}s")
    if metrics.avg_time_to_resolve:
        print(f"  Avg Time to Resolve: {metrics.avg_time_to_resolve:.1f}s")


async def main():
    """Run all demonstrations."""
    print("=" * 80)
    print("VAULYTICA INCIDENT MANAGEMENT & ALERTING SYSTEM - DEMO")
    print("=" * 80)
    
    await demo_incident_lifecycle()
    await demo_alert_deduplication()
    await demo_sla_tracking()
    await demo_ticketing_integration()
    await demo_incident_metrics()
    
    print("\n" + "=" * 80)
    print("✅ ALL DEMOS COMPLETED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())

