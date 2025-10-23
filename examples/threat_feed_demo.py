#!/usr/bin/env python3
"""
Threat Feed Integration Demonstration

This script demonstrates the real-time threat intelligence feed integration
capabilities of Vaulytica v0.9.0.

Features demonstrated:
- Single IOC enrichment from multiple sources
- Batch IOC enrichment
- Threat feed statistics
- Cache performance
- Consensus verdict aggregation
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from vaulytica.threat_feeds import ThreatFeedIntegration, ThreatFeedSource
from datetime import datetime


def print_header(title: str):
    """Print formatted header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_result(result):
    """Print enrichment result."""
    print(f"\n📊 IOC: {result.ioc_value} ({result.ioc_type})")
    print(f"   Verdict: {result.consensus_verdict}")
    print(f"   Malicious: {'YES' if result.is_malicious else 'NO'}")
    print(f"   Threat Score: {result.overall_threat_score}/100")
    print(f"   Confidence: {result.overall_confidence:.2%}")
    print(f"   Sources: {result.sources_flagged}/{result.sources_checked} flagged")
    
    if result.tags:
        print(f"   Tags: {', '.join(list(result.tags)[:5])}")
    if result.malware_families:
        print(f"   Malware: {', '.join(list(result.malware_families)[:3])}")
    if result.threat_actors:
        print(f"   Actors: {', '.join(list(result.threat_actors)[:3])}")
    
    print(f"\n   Source Breakdown:")
    for source_result in result.results:
        status = "🔴 MALICIOUS" if source_result.is_malicious else "🟢 CLEAN"
        print(f"     • {source_result.source.value}: {status} "
              f"(score: {source_result.threat_score}, confidence: {source_result.confidence:.2%})")


def demo_single_enrichment(engine: ThreatFeedIntegration):
    """Demonstrate single IOC enrichment."""
    print_header("DEMO 1: Single IOC Enrichment")
    
    # Test various IOC types
    test_iocs = [
        ("198.51.100.5", "ip", "Suspicious IP from test range"),
        ("evil-malware.com", "domain", "Domain with suspicious keyword"),
        ("8.8.8.8", "ip", "Google DNS (should be clean)"),
        ("example.com", "domain", "Legitimate domain"),
    ]
    
    for ioc_value, ioc_type, description in test_iocs:
        print(f"\n🔍 Testing: {description}")
        result = engine.enrich_ioc(ioc_value, ioc_type)
        print_result(result)


def demo_batch_enrichment(engine: ThreatFeedIntegration):
    """Demonstrate batch IOC enrichment."""
    print_header("DEMO 2: Batch IOC Enrichment")
    
    iocs = [
        ("198.51.100.10", "ip"),
        ("198.51.100.20", "ip"),
        ("malicious-site.com", "domain"),
        ("phishing-page.net", "domain"),
        ("deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678", "hash"),
    ]
    
    print(f"\n🔍 Enriching {len(iocs)} IOCs in batch...")
    results = engine.batch_enrich(iocs)
    
    print(f"\n✅ Enriched {len(results)} IOCs")
    
    malicious_count = sum(1 for r in results.values() if r.is_malicious)
    print(f"\n📊 Summary:")
    print(f"   Total IOCs: {len(results)}")
    print(f"   Malicious: {malicious_count}")
    print(f"   Clean: {len(results) - malicious_count}")
    
    print(f"\n📋 Results:")
    for ioc_value, result in results.items():
        verdict_emoji = "🔴" if result.is_malicious else "🟢"
        print(f"   {verdict_emoji} {ioc_value}: {result.consensus_verdict} "
              f"(score: {result.overall_threat_score})")


def demo_cache_performance(engine: ThreatFeedIntegration):
    """Demonstrate cache performance."""
    print_header("DEMO 3: Cache Performance")
    
    test_ioc = ("198.51.100.5", "ip")
    
    print(f"\n🔍 First lookup (cache miss)...")
    start = datetime.now()
    result1 = engine.enrich_ioc(*test_ioc)
    time1 = (datetime.now() - start).total_seconds()
    print(f"   Time: {time1:.3f}s")
    print(f"   Sources checked: {result1.sources_checked}")
    
    print(f"\n🔍 Second lookup (cache hit)...")
    start = datetime.now()
    result2 = engine.enrich_ioc(*test_ioc)
    time2 = (datetime.now() - start).total_seconds()
    print(f"   Time: {time2:.3f}s")
    print(f"   Sources checked: {result2.sources_checked}")
    
    speedup = time1 / time2 if time2 > 0 else float('inf')
    print(f"\n⚡ Cache speedup: {speedup:.1f}x faster")


def demo_statistics(engine: ThreatFeedIntegration):
    """Demonstrate statistics tracking."""
    print_header("DEMO 4: Threat Feed Statistics")
    
    stats = engine.get_statistics()
    
    print(f"\n📊 Overall Statistics:")
    print(f"   Total lookups: {stats['total_lookups']}")
    print(f"   Cache hits: {stats['cache_hits']}")
    print(f"   Cache hit rate: {stats['cache_hit_rate']:.1%}")
    print(f"   API calls: {stats['api_calls']}")
    print(f"   Errors: {stats['errors']}")
    print(f"   Cache size: {stats['cache_size']} entries")
    
    print(f"\n📊 By Source:")
    for source, count in stats['by_source'].items():
        if count > 0:
            print(f"   • {source}: {count} queries")


def demo_consensus_voting(engine: ThreatFeedIntegration):
    """Demonstrate consensus voting across sources."""
    print_header("DEMO 5: Consensus Voting")
    
    print("\n🔍 Testing IOC with mixed verdicts...")
    
    # This will query multiple sources and show how consensus works
    result = engine.enrich_ioc("192.0.2.100", "ip")
    
    print(f"\n📊 Consensus Analysis:")
    print(f"   IOC: {result.ioc_value}")
    print(f"   Sources checked: {result.sources_checked}")
    print(f"   Sources flagged: {result.sources_flagged}")
    if result.sources_checked > 0:
        print(f"   Flagged ratio: {result.sources_flagged / result.sources_checked:.1%}")
    else:
        print(f"   Flagged ratio: N/A (no sources available)")
    print(f"   Consensus verdict: {result.consensus_verdict}")
    
    print(f"\n📋 Voting Breakdown:")
    malicious_votes = []
    clean_votes = []
    
    for source_result in result.results:
        if source_result.is_malicious:
            malicious_votes.append(source_result.source.value)
        else:
            clean_votes.append(source_result.source.value)
    
    if malicious_votes:
        print(f"   🔴 Malicious ({len(malicious_votes)}): {', '.join(malicious_votes)}")
    if clean_votes:
        print(f"   🟢 Clean ({len(clean_votes)}): {', '.join(clean_votes)}")
    
    print(f"\n💡 Verdict Logic:")
    if result.sources_checked > 0:
        ratio = result.sources_flagged / result.sources_checked
        if ratio >= 0.7:
            print(f"   ≥70% sources flagged → MALICIOUS")
        elif ratio >= 0.3:
            print(f"   ≥30% sources flagged → SUSPICIOUS")
        else:
            print(f"   <30% sources flagged → CLEAN")
    else:
        print(f"   No sources available → UNKNOWN")


def main():
    """Run all demonstrations."""
    print("=" * 80)
    print("🎉 VAULYTICA v0.9.0 - THREAT FEED INTEGRATION DEMO")
    print("=" * 80)
    print("\nThis demo uses simulated threat feeds for demonstration purposes.")
    print("In production, configure API keys for real threat intelligence sources:")
    print("  • VirusTotal")
    print("  • AlienVault OTX")
    print("  • AbuseIPDB")
    print("  • Shodan")
    print("  • URLhaus (public)")
    print("  • ThreatFox (public)")
    
    # Initialize threat feed integration (simulated mode)
    print("\n🔧 Initializing threat feed integration...")
    engine = ThreatFeedIntegration(
        enable_cache=True,
        cache_ttl_hours=24,
        timeout_seconds=10
    )
    print("✅ Threat feed integration initialized")
    
    # Run demonstrations
    try:
        demo_single_enrichment(engine)
        demo_batch_enrichment(engine)
        demo_cache_performance(engine)
        demo_consensus_voting(engine)
        demo_statistics(engine)
        
        # Final summary
        print_header("DEMONSTRATION COMPLETE")
        
        stats = engine.get_statistics()
        print(f"\n✅ Successfully demonstrated threat feed integration!")
        print(f"\n📊 Final Statistics:")
        print(f"   Total IOC lookups: {stats['total_lookups']}")
        print(f"   Cache hit rate: {stats['cache_hit_rate']:.1%}")
        print(f"   API calls made: {stats['api_calls']}")
        print(f"   Errors: {stats['errors']}")
        
        print(f"\n🎯 Key Features Demonstrated:")
        print(f"   ✓ Single IOC enrichment")
        print(f"   ✓ Batch IOC enrichment")
        print(f"   ✓ Multi-source aggregation")
        print(f"   ✓ Consensus voting")
        print(f"   ✓ Cache performance")
        print(f"   ✓ Statistics tracking")
        
        print(f"\n🚀 Ready for production with real API keys!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

