#!/usr/bin/env python3

import asyncio
import json
from pathlib import Path

from vaulytica.config import load_config
from vaulytica.parsers import GuardDutyParser
from vaulytica.agents import SecurityAnalystAgent
from vaulytica.metrics import get_metrics_collector


async def demo_metrics():
    """Demonstrate metrics collection."""
    
    print("📊 Vaulytica Metrics Demo\n")
    print("=" * 60)
    
    # Initialize
    config = load_config()
    parser = GuardDutyParser()
    agent = SecurityAnalystAgent(config)
    metrics = get_metrics_collector()
    
    print("✓ Components initialized\n")
    
    # Load test events
    test_files = [
        "test_data/guardduty_crypto_mining.json",
        "test_data/guardduty_ssh_bruteforce.json",
        "test_data/guardduty_backdoor_c2.json",
    ]
    
    print(f"📁 Processing {len(test_files)} test events...\n")
    
    # Process events and collect metrics
    for i, test_file in enumerate(test_files, 1):
        file_path = Path(test_file)
        if not file_path.exists():
            print(f"⚠️  Skipping {test_file} (not found)")
            continue
        
        print(f"[{i}/{len(test_files)}] Analyzing {file_path.name}...")
        
        try:
            # Load and parse
            with open(file_path) as f:
                raw_event = json.load(f)
            
            event = parser.parse(raw_event)
            
            # Analyze
            result = await agent.analyze([event])
            
            # Metrics are automatically recorded in the API,
            # but for CLI we can record manually
            mitre_ids = [t.technique_id for t in result.mitre_techniques]
            metrics.record_analysis(
                platform="guardduty",
                risk_score=result.risk_score,
                latency_seconds=result.processing_time_seconds,
                tokens_used=result.tokens_used if hasattr(result, 'tokens_used') else 0,
                cached=False,
                mitre_techniques=mitre_ids
            )
            
            print(f"  ✓ Risk: {result.risk_score:.1f}/10, "
                  f"Latency: {result.processing_time_seconds:.2f}s, "
                  f"MITRE: {len(mitre_ids)} techniques")
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
            metrics.record_analysis(
                platform="guardduty",
                risk_score=0.0,
                latency_seconds=0.0,
                tokens_used=0,
                cached=False,
                error=True
            )
    
    print("\n" + "=" * 60)
    print("📈 Metrics Summary\n")
    
    # Get metrics summary
    summary = metrics.get_summary()
    
    # Display analysis metrics
    print("Analysis:")
    print(f"  Total: {summary['analysis']['total_analyses']}")
    print(f"  Errors: {summary['analysis']['errors']} "
          f"({summary['analysis']['error_rate']:.1f}%)")
    print(f"  By platform: {summary['analysis']['by_platform']}")
    
    # Display cache metrics
    print("\nCache:")
    print(f"  Hits: {summary['cache']['hits']}")
    print(f"  Misses: {summary['cache']['misses']}")
    print(f"  Hit rate: {summary['cache']['hit_rate_percent']:.1f}%")
    
    # Display performance metrics
    print("\nPerformance:")
    print(f"  Avg latency: {summary['performance']['avg_latency_seconds']}s")
    print(f"  P95 latency: {summary['performance']['p95_latency_seconds']}s")
    print(f"  P99 latency: {summary['performance']['p99_latency_seconds']}s")
    
    # Display cost metrics
    print("\nCost:")
    print(f"  Total tokens: {summary['cost']['total_tokens']:,}")
    print(f"  Total cost: ${summary['cost']['total_cost_usd']:.4f}")
    print(f"  Avg tokens/analysis: {summary['cost']['avg_tokens_per_analysis']}")
    
    # Display risk metrics
    print("\nRisk Distribution:")
    print(f"  Average: {summary['risk']['average_risk_score']:.2f}/10")
    print(f"  High (≥7): {summary['risk']['high_risk_events']}")
    print(f"  Medium (4-7): {summary['risk']['medium_risk_events']}")
    print(f"  Low (<4): {summary['risk']['low_risk_events']}")
    
    # Display threat intelligence
    if summary['threats']['top_mitre_techniques']:
        print("\nTop MITRE ATT&CK Techniques:")
        for technique, count in summary['threats']['top_mitre_techniques'][:5]:
            print(f"  {technique}: {count}")
    
    print("\n" + "=" * 60)
    print("📤 Exporting Metrics\n")
    
    # Export Prometheus format
    prometheus_metrics = metrics.export_prometheus()
    prometheus_file = Path("outputs/metrics.prom")
    prometheus_file.parent.mkdir(exist_ok=True)
    with open(prometheus_file, "w") as f:
        f.write(prometheus_metrics)
    print(f"✓ Prometheus format: {prometheus_file}")
    
    # Export JSON format
    json_file = Path("outputs/metrics.json")
    with open(json_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"✓ JSON format: {json_file}")
    
    print("\n" + "=" * 60)
    print("🔍 Prometheus Metrics Preview\n")
    print(prometheus_metrics[:500] + "...\n")
    
    print("=" * 60)
    print("✅ Metrics demo complete!\n")
    
    print("💡 Integration Examples:\n")
    print("1. Prometheus scraping:")
    print("   curl http://localhost:8000/metrics/prometheus")
    print("\n2. JSON metrics API:")
    print("   curl http://localhost:8000/metrics")
    print("\n3. CLI metrics:")
    print("   python -m vaulytica.cli stats --metrics")
    print("\n4. Grafana dashboard:")
    print("   Import metrics from Prometheus datasource")
    print()


async def demo_custom_metrics():
    """Demonstrate custom metrics collection."""
    
    print("\n" + "=" * 60)
    print("🎯 Custom Metrics Demo\n")
    
    metrics = get_metrics_collector()
    
    # Custom counters
    print("Recording custom counters...")
    metrics.increment_counter("custom_events_processed", 10, {"source": "demo"})
    metrics.increment_counter("custom_alerts_sent", 3, {"channel": "slack"})
    
    # Custom gauges
    print("Recording custom gauges...")
    metrics.set_gauge("custom_queue_size", 42, {"queue": "analysis"})
    metrics.set_gauge("custom_active_connections", 15)
    
    # Custom histograms
    print("Recording custom histograms...")
    for value in [0.1, 0.2, 0.15, 0.3, 0.25]:
        metrics.observe_histogram("custom_processing_time", value, {"type": "demo"})
    
    print("✓ Custom metrics recorded\n")
    
    print("📊 Custom metrics can be used for:")
    print("  - Application-specific KPIs")
    print("  - Business metrics")
    print("  - Custom performance tracking")
    print("  - Integration monitoring")
    print()


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--custom":
        asyncio.run(demo_custom_metrics())
    else:
        asyncio.run(demo_metrics())


if __name__ == "__main__":
    main()

