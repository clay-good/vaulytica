#!/usr/bin/env python3
"""
Vaulytica Advanced Visualizations Demo

Demonstrates all visualization capabilities:
- Attack Graph
- Threat Map
- Network Topology
- Timeline
- Correlation Matrix

Author: World-Class Software Engineering Team
Version: 0.13.0
"""

import sys
import random
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.models import SecurityEvent, Severity, EventCategory
from vaulytica.visualizations import (
    VisualizationEngine,
    get_visualization_engine,
    AttackGraphBuilder,
    ThreatMapBuilder,
    NetworkTopologyBuilder,
    TimelineBuilder,
    CorrelationMatrixBuilder
)


def create_sample_events(num_events: int = 50) -> list:
    """Create sample security events for demonstration."""
    events = []
    
    # Sample IPs
    source_ips = [
        "192.168.1.100", "10.0.0.50", "172.16.0.10",
        "203.0.113.45", "198.51.100.23", "192.0.2.100"
    ]
    
    dest_ips = [
        "10.0.0.100", "10.0.0.200", "10.0.0.300",
        "172.16.1.50", "172.16.1.100"
    ]
    
    users = ["admin", "user1", "user2", "service_account", "root"]
    
    resources = [
        "database-prod", "web-server-01", "api-gateway",
        "file-server", "backup-system"
    ]
    
    # Create events with attack chain progression
    base_time = datetime.utcnow() - timedelta(hours=24)
    
    for i in range(num_events):
        # Simulate attack progression
        if i < 10:
            # Reconnaissance phase
            category = EventCategory.RECONNAISSANCE
            severity = Severity.LOW
            title = f"Port scan detected from {random.choice(source_ips)}"
        elif i < 20:
            # Initial access
            category = EventCategory.UNAUTHORIZED_ACCESS
            severity = Severity.MEDIUM
            title = f"Failed login attempts from {random.choice(source_ips)}"
        elif i < 30:
            # Privilege escalation
            category = EventCategory.PRIVILEGE_ESCALATION
            severity = Severity.HIGH
            title = f"Privilege escalation attempt by {random.choice(users)}"
        elif i < 40:
            # Lateral movement
            category = EventCategory.LATERAL_MOVEMENT
            severity = Severity.HIGH
            title = f"Suspicious lateral movement detected"
        else:
            # Data exfiltration
            category = EventCategory.DATA_EXFILTRATION
            severity = Severity.CRITICAL
            title = f"Large data transfer to external IP"
        
        event = SecurityEvent(
            event_id=f"event_{i:04d}",
            source_system="demo",
            timestamp=base_time + timedelta(minutes=i * 30),
            severity=severity,
            category=category,
            title=title,
            description=f"Detailed description of {title}",
            raw_event={"demo": True, "index": i},
            metadata={
                "source_ip": random.choice(source_ips),
                "destination_ip": random.choice(dest_ips),
                "target_ip": random.choice(dest_ips),
                "user": random.choice(users) if random.random() > 0.3 else None,
                "resource": random.choice(resources) if random.random() > 0.5 else None
            }
        )
        
        events.append(event)
    
    return events


def demo_attack_graph():
    """Demonstrate attack graph visualization."""
    print("\n" + "="*80)
    print("🔗 ATTACK GRAPH DEMONSTRATION")
    print("="*80)
    
    # Create sample events
    events = create_sample_events(30)
    
    # Build attack graph
    builder = AttackGraphBuilder()
    graph = builder.build_from_events(events)
    
    print(f"\n✓ Attack Graph Generated:")
    print(f"  - Nodes: {len(graph.nodes)}")
    print(f"  - Edges: {len(graph.edges)}")
    print(f"  - Total Events: {graph.metadata.get('total_events', 0)}")
    
    # Show sample nodes
    print(f"\n  Sample Nodes:")
    for node in graph.nodes[:5]:
        print(f"    • {node.label} ({node.type.value}) - {node.severity.value if node.severity else 'N/A'}")
    
    # Show sample edges
    print(f"\n  Sample Edges:")
    for edge in graph.edges[:5]:
        print(f"    • {edge.source} → {edge.target} ({edge.type.value})")
    
    return graph


def demo_threat_map():
    """Demonstrate threat map visualization."""
    print("\n" + "="*80)
    print("🌍 THREAT MAP DEMONSTRATION")
    print("="*80)
    
    # Create sample events
    events = create_sample_events(40)
    
    # Build threat map
    builder = ThreatMapBuilder()
    threat_map = builder.build_from_events(events)
    
    print(f"\n✓ Threat Map Generated:")
    print(f"  - Threat Points: {len(threat_map['points'])}")
    print(f"  - Connections: {len(threat_map['connections'])}")
    print(f"  - Unique IPs: {threat_map['metadata'].get('unique_ips', 0)}")
    
    # Show sample threat points
    print(f"\n  Sample Threat Origins:")
    for point in threat_map['points'][:5]:
        print(f"    • {point['country']} ({point['city']}) - {point['event_count']} events - {point['severity']}")
    
    return threat_map


def demo_network_topology():
    """Demonstrate network topology visualization."""
    print("\n" + "="*80)
    print("🔌 NETWORK TOPOLOGY DEMONSTRATION")
    print("="*80)
    
    # Create sample events
    events = create_sample_events(35)
    
    # Build network topology
    builder = NetworkTopologyBuilder()
    graph = builder.build_from_events(events)
    
    print(f"\n✓ Network Topology Generated:")
    print(f"  - Assets: {graph.metadata.get('total_assets', 0)}")
    print(f"  - Compromised Assets: {graph.metadata.get('compromised_assets', 0)}")
    print(f"  - Connections: {len(graph.edges)}")
    
    # Show compromised assets
    print(f"\n  Compromised Assets:")
    for node in graph.nodes:
        if node.properties.get('compromised', False):
            print(f"    • {node.label} - {node.properties.get('event_count', 0)} events")
    
    return graph


def demo_timeline():
    """Demonstrate timeline visualization."""
    print("\n" + "="*80)
    print("⏱️  TIMELINE DEMONSTRATION")
    print("="*80)
    
    # Create sample events
    events = create_sample_events(50)
    
    # Build timeline
    builder = TimelineBuilder()
    timeline = builder.build_from_events(events)
    
    print(f"\n✓ Timeline Generated:")
    print(f"  - Total Events: {len(timeline['events'])}")
    print(f"  - Time Periods: {len(timeline['grouped'])}")
    
    # Show time range
    metadata = timeline['metadata']
    print(f"  - Time Range: {metadata['time_range']['start']} to {metadata['time_range']['end']}")
    
    # Show events by severity
    severity_counts = {}
    for event in timeline['events']:
        severity = event['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    print(f"\n  Events by Severity:")
    for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    • {severity}: {count}")
    
    return timeline


def demo_correlation_matrix():
    """Demonstrate correlation matrix visualization."""
    print("\n" + "="*80)
    print("📊 CORRELATION MATRIX DEMONSTRATION")
    print("="*80)
    
    # Create sample events
    events = create_sample_events(45)
    
    # Build correlation matrix
    builder = CorrelationMatrixBuilder()
    matrix = builder.build_from_events(events, dimension1="source_ip", dimension2="category")
    
    print(f"\n✓ Correlation Matrix Generated:")
    print(f"  - Dimensions: {matrix['metadata']['dimension1']} x {matrix['metadata']['dimension2']}")
    print(f"  - Rows: {len(matrix['dimensions']['rows'])}")
    print(f"  - Columns: {len(matrix['dimensions']['columns'])}")
    print(f"  - Total Cells: {len(matrix['matrix'])}")
    
    # Show top correlations
    sorted_cells = sorted(matrix['matrix'], key=lambda x: x['count'], reverse=True)
    print(f"\n  Top Correlations:")
    for cell in sorted_cells[:5]:
        if cell['count'] > 0:
            print(f"    • {cell['row']} ↔ {cell['column']}: {cell['count']} events (value: {cell['value']:.3f})")
    
    return matrix


def demo_visualization_engine():
    """Demonstrate the unified visualization engine."""
    print("\n" + "="*80)
    print("🎨 VISUALIZATION ENGINE DEMONSTRATION")
    print("="*80)
    
    # Get visualization engine
    engine = get_visualization_engine()
    
    # Create sample events
    events = create_sample_events(40)
    
    print(f"\n✓ Generating all visualizations for {len(events)} events...")
    
    # Generate all visualizations at once
    all_viz = engine.generate_all(events)
    
    print(f"\n✓ All Visualizations Generated:")
    print(f"  - Attack Graph: {len(all_viz['attack_graph']['nodes'])} nodes, {len(all_viz['attack_graph']['edges'])} edges")
    print(f"  - Threat Map: {len(all_viz['threat_map']['points'])} points, {len(all_viz['threat_map']['connections'])} connections")
    print(f"  - Network Topology: {len(all_viz['network_topology']['nodes'])} nodes, {len(all_viz['network_topology']['edges'])} edges")
    print(f"  - Timeline: {len(all_viz['timeline']['events'])} events")
    print(f"  - Correlation Matrix: {len(all_viz['correlation_matrix']['matrix'])} cells")
    
    # Show engine stats
    stats = engine.get_stats()
    print(f"\n✓ Engine Statistics:")
    print(f"  - Total Visualizations Generated: {stats['visualizations_generated']}")
    print(f"  - Attack Graphs: {stats['attack_graphs']}")
    print(f"  - Threat Maps: {stats['threat_maps']}")
    print(f"  - Network Topologies: {stats['network_topologies']}")
    print(f"  - Timelines: {stats['timelines']}")
    print(f"  - Correlation Matrices: {stats['correlation_matrices']}")
    
    return all_viz, stats


def main():
    """Run all demonstrations."""
    print("="*80)
    print("🎨 VAULYTICA ADVANCED VISUALIZATIONS DEMO")
    print("="*80)
    print("\nDemonstrating world-class visualization capabilities:")
    print("  • Attack Graph - Interactive attack chain visualization")
    print("  • Threat Map - Geographic threat origin mapping")
    print("  • Network Topology - Asset relationship visualization")
    print("  • Timeline - Attack progression timeline")
    print("  • Correlation Matrix - Multi-dimensional correlation heatmap")
    
    # Run demonstrations
    demo_attack_graph()
    demo_threat_map()
    demo_network_topology()
    demo_timeline()
    demo_correlation_matrix()
    demo_visualization_engine()
    
    print("\n" + "="*80)
    print("✅ ALL DEMONSTRATIONS COMPLETE!")
    print("="*80)
    print("\n🚀 Next Steps:")
    print("  1. Start the API server: python3 -m vaulytica.api")
    print("  2. Open browser: https://example.com:8000/visualizations")
    print("  3. Explore interactive visualizations with real-time data")
    print("\n" + "="*80)


if __name__ == "__main__":
    main()

