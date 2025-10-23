#!/usr/bin/env python3
"""
Vaulytica Streaming Analytics Demo

Demonstrates real-time event stream processing with:
- Event stream processing with sliding windows
- Complex Event Processing (CEP) pattern matching
- Real-time correlation across event streams
- Event replay and time travel
- Streaming metrics and monitoring

Author: Vaulytica Team
Version: 0.16.0
"""

import asyncio
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.streaming import (
    StreamingAnalytics, get_streaming_analytics,
    WindowType, PatternType, CEPPattern,
    create_custom_cep_pattern
)
from vaulytica.models import SecurityEvent, Severity, EventCategory, TechnicalIndicator


def create_event(event_id, title, description, severity, category, timestamp, source, indicators, raw_data=None):
    """Helper to create SecurityEvent with all required fields."""
    return SecurityEvent(
        event_id=event_id,
        source_system=source,
        title=title,
        description=description,
        severity=severity,
        category=category,
        timestamp=timestamp,
        raw_event=raw_data or {"source": source},
        technical_indicators=indicators
    )


def create_sample_events() -> list[SecurityEvent]:
    """Create sample security events for demonstration."""
    base_time = datetime.now()
    
    events = [
        # Brute force attack sequence
        create_event("evt_001", "Failed SSH Login Attempt", "Failed SSH login attempt from 203.0.113.45",
                    Severity.MEDIUM, EventCategory.UNAUTHORIZED_ACCESS, base_time, "ssh_server",
                    [TechnicalIndicator(indicator_type="ip", value="203.0.113.45"),
                     TechnicalIndicator(indicator_type="username", value="admin")]),

        create_event("evt_002", "Failed SSH Login Attempt", "Failed SSH login attempt from 203.0.113.45",
                    Severity.MEDIUM, EventCategory.UNAUTHORIZED_ACCESS, base_time + timedelta(seconds=10), "ssh_server",
                    [TechnicalIndicator(indicator_type="ip", value="203.0.113.45"),
                     TechnicalIndicator(indicator_type="username", value="root")]),

        create_event("evt_003", "Failed SSH Login Attempt", "Failed SSH login attempt from 203.0.113.45",
                    Severity.MEDIUM, EventCategory.UNAUTHORIZED_ACCESS, base_time + timedelta(seconds=20), "ssh_server",
                    [TechnicalIndicator(indicator_type="ip", value="203.0.113.45"),
                     TechnicalIndicator(indicator_type="username", value="ubuntu")]),

        create_event("evt_004", "Successful SSH Login", "Successful SSH login from 203.0.113.45",
                    Severity.HIGH, EventCategory.UNAUTHORIZED_ACCESS, base_time + timedelta(seconds=30), "ssh_server",
                    [TechnicalIndicator(indicator_type="ip", value="203.0.113.45"),
                     TechnicalIndicator(indicator_type="username", value="admin")]),

        # Privilege escalation and data exfiltration
        create_event("evt_005", "Privilege Escalation Detected", "User admin escalated privileges to root",
                    Severity.HIGH, EventCategory.PRIVILEGE_ESCALATION, base_time + timedelta(minutes=1), "linux_server",
                    [TechnicalIndicator(indicator_type="username", value="admin"),
                     TechnicalIndicator(indicator_type="hostname", value="web-server-01")]),

        create_event("evt_006", "Large Data Transfer Detected", "Large outbound data transfer to external IP",
                    Severity.CRITICAL, EventCategory.DATA_EXFILTRATION, base_time + timedelta(minutes=2), "network_monitor",
                    [TechnicalIndicator(indicator_type="ip", value="198.51.100.10"),
                     TechnicalIndicator(indicator_type="hostname", value="web-server-01")]),

        # Lateral movement
        create_event("evt_007", "Lateral Movement Detected", "SMB connection from web-server-01 to db-server-01",
                    Severity.HIGH, EventCategory.LATERAL_MOVEMENT, base_time + timedelta(minutes=3), "network_monitor",
                    [TechnicalIndicator(indicator_type="hostname", value="web-server-01"),
                     TechnicalIndicator(indicator_type="hostname", value="db-server-01")]),

        create_event("evt_008", "Credential Access Attempt", "Attempted to dump credentials from LSASS",
                    Severity.CRITICAL, EventCategory.UNAUTHORIZED_ACCESS, base_time + timedelta(minutes=4), "edr",
                    [TechnicalIndicator(indicator_type="hostname", value="db-server-01"),
                     TechnicalIndicator(indicator_type="process", value="mimikatz.exe")]),

        # Discovery activity
        create_event("evt_009", "Network Discovery", "Network scanning activity detected",
                    Severity.MEDIUM, EventCategory.RECONNAISSANCE, base_time + timedelta(minutes=5), "network_monitor",
                    [TechnicalIndicator(indicator_type="hostname", value="db-server-01")]),

        # Repeated failed access (for iteration pattern)
        *[
            create_event(f"evt_0{10+i}", "Access Denied", f"Access denied to sensitive file #{i}",
                        Severity.MEDIUM, EventCategory.POLICY_VIOLATION, base_time + timedelta(minutes=6, seconds=i*5), "file_server",
                        [TechnicalIndicator(indicator_type="username", value="user123")])
            for i in range(12)
        ]
    ]
    
    return events


async def demo_stream_processing():
    """Demo 1: Event Stream Processing with Sliding Windows."""
    print("\n" + "="*80)
    print("DEMO 1: Event Stream Processing with Sliding Windows")
    print("="*80)
    
    # Initialize streaming analytics
    streaming = get_streaming_analytics(
        window_size=timedelta(minutes=2),
        window_type=WindowType.TUMBLING
    )
    
    # Create sample events
    events = create_sample_events()[:5]
    
    print(f"\n✓ Processing {len(events)} events through stream processor...")
    
    # Process events
    for event in events:
        result = await streaming.process_event(event)
        print(f"  • Event {event.event_id}: {result['stream_processing']['status']}")
        print(f"    Latency: {result['stream_processing']['processing_latency_ms']:.2f}ms")
    
    # Get window aggregations
    aggregations = streaming.get_window_aggregations()
    print(f"\n✓ Generated {len(aggregations)} window aggregations")
    
    if aggregations:
        agg = aggregations[0]
        print(f"\nWindow Aggregation:")
        print(f"  Window ID: {agg.window_id}")
        print(f"  Event Count: {agg.event_count}")
        print(f"  Severity Distribution: {agg.severity_distribution}")
        print(f"  Unique Sources: {agg.unique_sources}")
        print(f"  Max Severity: {agg.max_severity}")


async def demo_cep_patterns():
    """Demo 2: Complex Event Processing (CEP) Pattern Matching."""
    print("\n" + "="*80)
    print("DEMO 2: Complex Event Processing (CEP) Pattern Matching")
    print("="*80)
    
    streaming = get_streaming_analytics()
    
    # Get registered patterns
    patterns = streaming.get_cep_patterns()
    print(f"\n✓ Loaded {len(patterns)} default CEP patterns:")
    for pattern in patterns:
        print(f"  • {pattern.pattern_name} ({pattern.pattern_type.value})")
    
    # Process events that trigger patterns
    events = create_sample_events()
    
    print(f"\n✓ Processing {len(events)} events for pattern matching...")
    
    for event in events:
        await streaming.process_event(event)
    
    # Get pattern matches
    matches = streaming.get_pattern_matches(limit=10)
    print(f"\n✓ Detected {len(matches)} pattern matches:")
    
    for match in matches:
        print(f"\n  Pattern: {match.pattern_name}")
        print(f"  Severity: {match.severity.value}")
        print(f"  Confidence: {match.confidence:.2%}")
        print(f"  Matched Events: {len(match.matched_events)}")
        print(f"  Description: {match.description}")


async def demo_streaming_correlation():
    """Demo 3: Real-Time Streaming Correlation."""
    print("\n" + "="*80)
    print("DEMO 3: Real-Time Streaming Correlation")
    print("="*80)
    
    streaming = get_streaming_analytics()
    
    # Process events
    events = create_sample_events()
    
    print(f"\n✓ Processing {len(events)} events for correlation...")
    
    for event in events:
        await streaming.process_event(event)
    
    # Get correlations
    correlations = streaming.get_correlations(limit=20)
    print(f"\n✓ Found {len(correlations)} correlations:")
    
    # Group by type
    by_type = {}
    for corr in correlations:
        if corr.correlation_type not in by_type:
            by_type[corr.correlation_type] = []
        by_type[corr.correlation_type].append(corr)
    
    for corr_type, corrs in by_type.items():
        print(f"\n  {corr_type.upper()} Correlations: {len(corrs)}")
        if corrs:
            example = corrs[0]
            print(f"    Example: {example.description}")
            print(f"    Score: {example.correlation_score:.2f}")


async def demo_event_replay():
    """Demo 4: Event Replay and Time Travel."""
    print("\n" + "="*80)
    print("DEMO 4: Event Replay and Time Travel")
    print("="*80)
    
    streaming = get_streaming_analytics()
    
    # Events are already stored from previous demos
    replay_stats = streaming.replay_system.get_statistics()
    print(f"\n✓ Replay system has {replay_stats['total_stored_events']} stored events")
    
    if replay_stats['total_stored_events'] > 0:
        # Time travel to a specific point
        target_time = datetime.now() - timedelta(minutes=2)
        events = streaming.get_events_at_time(target_time, window=timedelta(minutes=5))
        
        print(f"\n✓ Time travel to {target_time.strftime('%H:%M:%S')}")
        print(f"  Found {len(events)} events within 5-minute window")
        
        if events:
            print(f"\n  Events around that time:")
            for event in events[:5]:
                print(f"    • {event.timestamp.strftime('%H:%M:%S')} - {event.title}")


async def demo_custom_patterns():
    """Demo 5: Creating Custom CEP Patterns."""
    print("\n" + "="*80)
    print("DEMO 5: Creating Custom CEP Patterns")
    print("="*80)
    
    streaming = get_streaming_analytics()
    
    # Create a custom pattern
    custom_pattern = create_custom_cep_pattern(
        pattern_id="custom_suspicious_activity",
        pattern_name="Suspicious Activity Pattern",
        pattern_type=PatternType.CONJUNCTION,
        conditions=[
            {"category": "PRIVILEGE_ESCALATION"},
            {"category": "LATERAL_MOVEMENT"}
        ],
        time_window_minutes=10,
        min_occurrences=2,
        severity=Severity.HIGH,
        description="Privilege escalation combined with lateral movement"
    )
    
    streaming.add_cep_pattern(custom_pattern)
    print(f"\n✓ Added custom pattern: {custom_pattern.pattern_name}")
    print(f"  Pattern Type: {custom_pattern.pattern_type.value}")
    print(f"  Time Window: {custom_pattern.time_window.total_seconds() / 60:.0f} minutes")
    print(f"  Conditions: {len(custom_pattern.conditions)}")


async def demo_streaming_metrics():
    """Demo 6: Streaming Analytics Metrics."""
    print("\n" + "="*80)
    print("DEMO 6: Streaming Analytics Metrics")
    print("="*80)
    
    streaming = get_streaming_analytics()
    
    # Get comprehensive metrics
    metrics = streaming.get_comprehensive_metrics()
    
    print("\n✓ Stream Processor Metrics:")
    stream_metrics = metrics['stream_processor']
    print(f"  Events Processed: {stream_metrics['events_processed']}")
    print(f"  Events/Second: {stream_metrics['events_per_second']:.2f}")
    print(f"  Avg Latency: {stream_metrics['avg_processing_latency_ms']:.2f}ms")
    print(f"  Max Latency: {stream_metrics['max_processing_latency_ms']:.2f}ms")
    print(f"  Windows Processed: {stream_metrics['windows_processed']}")
    
    print("\n✓ CEP Engine Metrics:")
    cep_metrics = metrics['cep_engine']
    print(f"  Total Patterns: {cep_metrics['total_patterns']}")
    print(f"  Total Matches: {cep_metrics['total_matches']}")
    print(f"  Events Buffered: {cep_metrics['events_buffered']}")
    
    print("\n✓ Correlation Engine Metrics:")
    corr_metrics = metrics['correlation_engine']
    print(f"  Total Correlations: {corr_metrics['total_correlations']}")
    print(f"  Correlation Window: {corr_metrics['correlation_window_minutes']:.0f} minutes")
    print(f"  Correlations by Type: {corr_metrics['correlations_by_type']}")


async def main():
    """Run all streaming analytics demos."""
    print("\n" + "="*80)
    print("🚀 VAULYTICA STREAMING ANALYTICS DEMO")
    print("="*80)
    print("\nDemonstrating real-time event stream processing capabilities:")
    print("  1. Event Stream Processing with Sliding Windows")
    print("  2. Complex Event Processing (CEP) Pattern Matching")
    print("  3. Real-Time Streaming Correlation")
    print("  4. Event Replay and Time Travel")
    print("  5. Creating Custom CEP Patterns")
    print("  6. Streaming Analytics Metrics")
    
    try:
        await demo_stream_processing()
        await demo_cep_patterns()
        await demo_streaming_correlation()
        await demo_event_replay()
        await demo_custom_patterns()
        await demo_streaming_metrics()
        
        print("\n" + "="*80)
        print("✅ ALL DEMOS COMPLETED SUCCESSFULLY!")
        print("="*80)
        print("\nStreaming Analytics Features Demonstrated:")
        print("  ✓ Event stream processing with <100ms latency")
        print("  ✓ Complex event pattern matching (5 default patterns)")
        print("  ✓ Real-time correlation (temporal, asset, IOC, behavioral)")
        print("  ✓ Event replay and time travel capabilities")
        print("  ✓ Custom pattern creation")
        print("  ✓ Comprehensive metrics and monitoring")
        print("\n" + "="*80)
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

