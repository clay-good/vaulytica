#!/usr/bin/env python3

import asyncio
import time
import random
from datetime import datetime, timedelta
from typing import List

from vaulytica.models import SecurityEvent, Severity, EventCategory, TechnicalIndicator
from vaulytica.dashboard import get_dashboard_manager


def create_sample_event(event_type: str, severity: Severity) -> SecurityEvent:
    """Create a sample security event."""
    timestamp = datetime.utcnow() - timedelta(minutes=random.randint(0, 1440))
    
    event_templates = {
        "brute_force": {
            "title": "Brute Force Attack Detected",
            "description": f"Multiple failed login attempts from {random.choice(['198.51.100.5', '203.0.113.10'])}",
            "category": EventCategory.UNAUTHORIZED_ACCESS,
            "source_ip": random.choice(["198.51.100.5", "203.0.113.10", "192.0.2.50"]),
            "target_ip": f"10.0.1.{random.randint(1, 254)}"
        },
        "malware": {
            "title": "Malware Detected",
            "description": f"Malicious file detected: {random.choice(['Emotet', 'TrickBot', 'Ryuk'])} variant",
            "category": EventCategory.MALWARE,
            "source_ip": f"10.0.2.{random.randint(1, 254)}",
            "target_ip": "10.0.2.100"
        },
        "data_exfil": {
            "title": "Suspicious Data Transfer",
            "description": f"Large data transfer to external IP: {random.randint(100, 999)}GB",
            "category": EventCategory.DATA_EXFILTRATION,
            "source_ip": f"10.0.3.{random.randint(1, 254)}",
            "target_ip": random.choice(["203.0.113.100", "198.51.100.200"])
        },
        "port_scan": {
            "title": "Port Scan Detected",
            "description": f"Port scanning activity detected on {random.randint(100, 65535)} ports",
            "category": EventCategory.RECONNAISSANCE,
            "source_ip": random.choice(["198.51.100.10", "203.0.113.20"]),
            "target_ip": f"10.0.4.{random.randint(1, 254)}"
        },
        "privilege_escalation": {
            "title": "Privilege Escalation Attempt",
            "description": "Unauthorized privilege escalation detected",
            "category": EventCategory.PRIVILEGE_ESCALATION,
            "source_ip": f"10.0.5.{random.randint(1, 254)}",
            "target_ip": f"10.0.5.{random.randint(1, 254)}"
        }
    }
    
    template = event_templates.get(event_type, event_templates["brute_force"])
    
    return SecurityEvent(
        event_id=f"evt_{event_type}_{int(time.time())}_{random.randint(1000, 9999)}",
        source_system=random.choice(["GuardDuty", "CrowdStrike", "Datadog", "GCP SCC"]),
        timestamp=timestamp,
        severity=severity,
        category=template["category"],
        title=template["title"],
        description=template["description"],
        raw_event={"source_ip": template["source_ip"], "target_ip": template["target_ip"]},
        metadata={
            "source_ip": template["source_ip"],
            "target_ip": template["target_ip"],
            "port": random.randint(1, 65535),
            "protocol": random.choice(["tcp", "udp", "http", "https", "ssh"])
        },
        technical_indicators=[
            TechnicalIndicator(
                indicator_type="ip",
                value=template["source_ip"]
            )
        ] if random.random() > 0.5 else []
    )


async def generate_events_continuously(dashboard, interval: float = 5.0):
    """Generate events continuously for demonstration."""
    event_types = ["brute_force", "malware", "data_exfil", "port_scan", "privilege_escalation"]
    severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    severity_weights = [0.1, 0.2, 0.3, 0.3, 0.1]  # Weighted distribution
    
    print("\n🔄 Starting continuous event generation...")
    print(f"   Generating events every {interval} seconds")
    print("   Press Ctrl+C to stop\n")
    
    event_count = 0
    try:
        while True:
            # Generate 1-3 events per interval
            num_events = random.randint(1, 3)
            
            for _ in range(num_events):
                event_type = random.choice(event_types)
                severity = random.choices(severities, weights=severity_weights)[0]
                
                event = create_sample_event(event_type, severity)
                await dashboard.add_event(event)
                
                event_count += 1
                print(f"✓ Generated event #{event_count}: {event.title} ({event.severity.value})")
            
            await asyncio.sleep(interval)
            
    except KeyboardInterrupt:
        print(f"\n\n✅ Generated {event_count} total events")


async def populate_initial_events(dashboard, count: int = 50):
    """Populate dashboard with initial historical events."""
    print(f"\n📝 Populating dashboard with {count} historical events...")
    
    event_types = ["brute_force", "malware", "data_exfil", "port_scan", "privilege_escalation"]
    severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    severity_weights = [0.1, 0.2, 0.3, 0.3, 0.1]
    
    for i in range(count):
        event_type = random.choice(event_types)
        severity = random.choices(severities, weights=severity_weights)[0]
        
        event = create_sample_event(event_type, severity)
        await dashboard.add_event(event)
        
        if (i + 1) % 10 == 0:
            print(f"   Created {i + 1}/{count} events...")
    
    print(f"✅ Created {count} historical events\n")


async def main():
    """Main demo function."""
    print("=" * 80)
    print("🎉 VAULYTICA DASHBOARD DEMO")
    print("=" * 80)
    print()
    print("This demo will:")
    print("1. Initialize the dashboard")
    print("2. Populate with 50 historical events")
    print("3. Generate new events every 5 seconds")
    print()
    print("📊 Open your browser to: http://localhost:8000")
    print()
    print("=" * 80)
    
    # Get dashboard manager
    dashboard = get_dashboard_manager()
    
    # Populate initial events
    await populate_initial_events(dashboard, count=50)
    
    # Show statistics
    stats = dashboard.get_stats()
    print("\n📊 Dashboard Statistics:")
    print(f"   Total Events: {stats.total_events}")
    print(f"   Critical Events: {stats.critical_events}")
    print(f"   High Events: {stats.high_events}")
    print(f"   Anomalies Detected: {stats.anomalies_detected}")
    print(f"   Threats Predicted: {stats.threats_predicted}")
    print()
    
    # Start continuous generation
    print("🚀 Dashboard is ready!")
    print("   Open http://localhost:8000 in your browser")
    print()
    
    # Note: In production, this would run alongside the API server
    # For demo purposes, we'll just show how to generate events
    print("💡 To run the full dashboard:")
    print("   1. Start the API server: python3 -m vaulytica.api")
    print("   2. Open http://localhost:8000 in your browser")
    print("   3. Use the 'Create Test Event' button or API endpoint")
    print()
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())

