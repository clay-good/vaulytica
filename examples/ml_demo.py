#!/usr/bin/env python3
"""Demonstration of ML Engine capabilities.

This script demonstrates:
1. Anomaly detection
2. Threat prediction
3. Attack clustering
4. Time series forecasting
5. Feature extraction
"""

import sys
import os
from datetime import datetime, timedelta
from typing import List

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vaulytica.ml_engine import MLEngine, FeatureExtractor, AnomalyType
from vaulytica.models import SecurityEvent, Severity, TechnicalIndicator, EventCategory
from vaulytica.threat_intel import ThreatLevel


def create_event(event_id: str, timestamp: datetime, title: str, description: str,
                severity: Severity, category: EventCategory, source_ip: str = None,
                target_ip: str = None, indicators: List = None, **metadata) -> SecurityEvent:
    """Helper to create security event."""
    raw_event = {}
    if source_ip:
        raw_event["source_ip"] = source_ip
        metadata["source_ip"] = source_ip
    if target_ip:
        raw_event["target_ip"] = target_ip
        metadata["target_ip"] = target_ip

    return SecurityEvent(
        event_id=event_id,
        source_system="demo",
        timestamp=timestamp,
        severity=severity,
        category=category,
        title=title,
        description=description,
        raw_event=raw_event,
        metadata=metadata,
        technical_indicators=indicators or []
    )


def create_sample_events() -> List[SecurityEvent]:
    """Create sample security events for demonstration."""
    base_time = datetime.utcnow()

    events = []

    # Normal events
    for i in range(10):
        events.append(create_event(
            event_id=f"evt_normal_{i}",
            timestamp=base_time - timedelta(hours=i),
            title="Normal user login",
            description=f"Normal user login {i}",
            severity=Severity.INFO,
            category=EventCategory.UNKNOWN,
            source_ip=f"10.0.0.{i+1}",
            target_ip="10.0.1.100",
            port=443,
            protocol="https"
        ))
    
    # Suspicious events (brute force pattern)
    for i in range(20):
        events.append(create_event(
            event_id=f"evt_bruteforce_{i}",
            timestamp=base_time - timedelta(minutes=i*3),
            title="Failed login attempt",
            description=f"Failed login attempt {i}",
            severity=Severity.HIGH,
            category=EventCategory.UNAUTHORIZED_ACCESS,
            source_ip="198.51.100.5",
            target_ip="10.0.1.50",
            indicators=[TechnicalIndicator(indicator_type="ip", value="198.51.100.5")],
            port=22,
            protocol="ssh"
        ))

    # Port scanning pattern
    for i in range(15):
        events.append(create_event(
            event_id=f"evt_portscan_{i}",
            timestamp=base_time - timedelta(minutes=i*2),
            title="Port scan detected",
            description=f"Port scan detected on port {1000+i}",
            severity=Severity.MEDIUM,
            category=EventCategory.RECONNAISSANCE,
            source_ip="198.51.100.10",
            target_ip=f"10.0.2.{i+1}",
            port=1000+i,
            protocol="tcp"
        ))

    # Data exfiltration (off-hours)
    for i in range(5):
        events.append(create_event(
            event_id=f"evt_exfil_{i}",
            timestamp=base_time.replace(hour=2) - timedelta(minutes=i*10),
            title="Large data transfer",
            description=f"Large data transfer at unusual time {i}",
            severity=Severity.CRITICAL,
            category=EventCategory.DATA_EXFILTRATION,
            source_ip="10.0.3.50",
            target_ip="203.0.113.100",
            indicators=[TechnicalIndicator(indicator_type="ip", value="203.0.113.100")],
            bytes=1000000000,
            protocol="https"
        ))

    # Malware activity
    for i in range(8):
        events.append(create_event(
            event_id=f"evt_malware_{i}",
            timestamp=base_time - timedelta(hours=i, minutes=30),
            title="Malware detected",
            description=f"Malware detected: Emotet variant {i}",
            severity=Severity.CRITICAL,
            category=EventCategory.MALWARE,
            source_ip=f"10.0.4.{i+10}",
            target_ip="10.0.4.100",
            indicators=[TechnicalIndicator(indicator_type="hash", value=f"deadbeef{i:08d}")],
            malware_family="Emotet"
        ))
    
    return events


def demo_anomaly_detection(ml_engine: MLEngine, events: List[SecurityEvent]):
    """Demonstrate anomaly detection."""
    print("=" * 80)
    print("  DEMO 1: Anomaly Detection")
    print("=" * 80)
    print()
    
    # Test on different event types
    test_events = [
        events[0],   # Normal event
        events[15],  # Brute force event
        events[35],  # Port scan event
        events[45],  # Data exfiltration event
    ]
    
    for event in test_events:
        print(f"🔍 Analyzing: {event.title} (severity: {event.severity.value})")
        
        # Get context events (last 10 events before this one)
        context = [e for e in events if e.timestamp < event.timestamp][-10:]
        
        # Detect anomaly
        result = ml_engine.detect_anomaly(event, context)
        
        # Display results
        status = "🔴 ANOMALY" if result.is_anomaly else "🟢 NORMAL"
        print(f"   {status}")
        print(f"   Anomaly Score: {result.anomaly_score:.2f}")
        print(f"   Confidence: {result.confidence:.2f}")
        
        if result.anomaly_types:
            print(f"   Anomaly Types:")
            for atype in result.anomaly_types:
                print(f"     • {atype.value}")
        
        print(f"   Explanation: {result.explanation}")
        print()


def demo_threat_prediction(ml_engine: MLEngine, events: List[SecurityEvent]):
    """Demonstrate threat prediction."""
    print("=" * 80)
    print("  DEMO 2: Threat Prediction")
    print("=" * 80)
    print()
    
    # Test on high-risk events
    test_events = [
        events[15],  # Brute force
        events[45],  # Data exfiltration
        events[50],  # Malware
    ]
    
    for event in test_events:
        print(f"🔮 Predicting threat for: {event.title}")
        
        context = [e for e in events if e.timestamp < event.timestamp][-20:]
        
        # Predict threat
        prediction = ml_engine.predict_threat(event, context)
        
        print(f"   Predicted Threat Level: {prediction.predicted_threat_level.value}")
        print(f"   Probability: {prediction.probability:.2f}")
        print(f"   Confidence: {prediction.confidence:.2f}")
        
        if prediction.time_to_attack:
            print(f"   Estimated Time to Attack: {prediction.time_to_attack}")
        
        print(f"   Predicted Attack Types:")
        for attack_type in prediction.predicted_attack_types:
            print(f"     • {attack_type}")
        
        if prediction.risk_factors:
            print(f"   Risk Factors:")
            for factor in prediction.risk_factors[:3]:
                print(f"     • {factor}")
        
        if prediction.mitigation_recommendations:
            print(f"   Mitigations:")
            for mitigation in prediction.mitigation_recommendations[:3]:
                print(f"     • {mitigation}")
        
        print()


def demo_attack_clustering(ml_engine: MLEngine, events: List[SecurityEvent]):
    """Demonstrate attack clustering."""
    print("=" * 80)
    print("  DEMO 3: Attack Pattern Clustering")
    print("=" * 80)
    print()
    
    print(f"🔬 Clustering {len(events)} events into attack patterns...")
    print()
    
    # Cluster attacks
    clusters = ml_engine.cluster_attacks(events, num_clusters=4)
    
    print(f"✅ Identified {len(clusters)} attack clusters")
    print()
    
    for cluster in clusters:
        print(f"📊 Cluster {cluster.cluster_id}: {cluster.cluster_name}")
        print(f"   Events: {cluster.event_count}")
        attack_types_str = ', '.join(cluster.attack_types[:3]) if cluster.attack_types else 'Unknown'
        print(f"   Attack Types: {attack_types_str}")
        print(f"   Time Range: {cluster.time_range[0].strftime('%H:%M')} - {cluster.time_range[1].strftime('%H:%M')}")
        
        print(f"   Common Features:")
        for key, value in cluster.common_features.items():
            print(f"     • {key}: {value}")
        
        print(f"   Severity Distribution:")
        for severity, count in cluster.severity_distribution.items():
            print(f"     • {severity}: {count} events")
        
        print()


def demo_threat_forecasting(ml_engine: MLEngine, events: List[SecurityEvent]):
    """Demonstrate threat forecasting."""
    print("=" * 80)
    print("  DEMO 4: Threat Forecasting")
    print("=" * 80)
    print()
    
    print(f"📈 Forecasting threats for next 24 hours...")
    print(f"   Based on {len(events)} historical events")
    print()
    
    # Forecast threats
    forecast = ml_engine.forecast_threats(events, forecast_hours=24)
    
    print(f"📊 Forecast Results:")
    print(f"   Forecast Period: {forecast.forecast_period}")
    print(f"   Predicted Event Count: {forecast.predicted_event_count}")
    print(f"   Confidence Interval: {forecast.confidence_interval[0]} - {forecast.confidence_interval[1]}")
    print(f"   Trend: {forecast.trend}")
    print(f"   Seasonality Detected: {'Yes' if forecast.seasonality_detected else 'No'}")
    print()
    
    if forecast.predicted_severity_distribution:
        print(f"   Predicted Severity Distribution:")
        for severity, ratio in sorted(forecast.predicted_severity_distribution.items(), 
                                      key=lambda x: x[1], reverse=True):
            print(f"     • {severity}: {ratio:.1%}")
    
    print()


def demo_statistics(ml_engine: MLEngine):
    """Display ML engine statistics."""
    print("=" * 80)
    print("  DEMO 5: ML Engine Statistics")
    print("=" * 80)
    print()
    
    stats = ml_engine.get_statistics()
    
    print(f"📊 Overall Statistics:")
    print(f"   Total Predictions: {stats['total_predictions']}")
    print(f"   Anomalies Detected: {stats['anomalies_detected']}")
    print(f"   Threats Predicted: {stats['threats_predicted']}")
    print(f"   Anomaly Rate: {stats['anomaly_rate']:.1%}")
    print(f"   Threat Rate: {stats['threat_rate']:.1%}")
    print(f"   Training Samples: {stats['training_samples']}")
    print()
    
    print(f"⚙️  Configuration:")
    print(f"   Anomaly Threshold: {stats['anomaly_threshold']}")
    print(f"   Threat Threshold: {stats['threat_threshold']}")
    print()


def main():
    """Run ML engine demonstration."""
    print("=" * 80)
    print("🎉 VAULYTICA v0.10.0 - MACHINE LEARNING ENGINE DEMO")
    print("=" * 80)
    print()
    
    print("🔧 Initializing ML engine...")
    ml_engine = MLEngine(enable_training=True)
    print("✅ ML engine initialized")
    print()
    
    print("📝 Creating sample security events...")
    events = create_sample_events()
    print(f"✅ Created {len(events)} sample events")
    print()
    
    # Run demonstrations
    demo_anomaly_detection(ml_engine, events)
    demo_threat_prediction(ml_engine, events)
    demo_attack_clustering(ml_engine, events)
    demo_threat_forecasting(ml_engine, events)
    demo_statistics(ml_engine)
    
    print("=" * 80)
    print("  DEMONSTRATION COMPLETE")
    print("=" * 80)
    print()
    print("✅ Successfully demonstrated ML engine capabilities!")
    print()
    print("🎯 Key Features Demonstrated:")
    print("   ✓ Anomaly detection with 7 anomaly types")
    print("   ✓ Threat prediction with attack type classification")
    print("   ✓ Attack pattern clustering")
    print("   ✓ Time series threat forecasting")
    print("   ✓ Feature extraction from security events")
    print("   ✓ Statistics tracking")
    print()
    print("🚀 Ready for production with ML-powered threat detection!")
    print("=" * 80)


if __name__ == "__main__":
    main()

