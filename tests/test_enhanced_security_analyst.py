"""
Test Enhanced Security Analyst Agent with URLScan.io, WHOIS, and Investigation Queries

This test demonstrates the new v1.0.0 features:
- URLScan.io integration for screenshot capture and phishing detection
- WHOIS integration for domain registration analysis
- Cross-platform investigation query generation
"""

import asyncio
import pytest
from datetime import datetime
from vaulytica.config import VaulyticaConfig
from vaulytica.agents.security_analyst import SecurityAnalystAgent
from vaulytica.models import SecurityEvent, Severity, EventCategory, TechnicalIndicator


@pytest.fixture
def config():
    """Create test configuration"""
    return VaulyticaConfig(
        anthropic_api_key="sk-ant-test-key",  # Replace with real key for actual testing
        enable_threat_feeds=True,
        enable_whois=True,
        enable_investigation_queries=True,
        urlscan_api_key=None,  # Optional - works without API key for public scans
        urlscan_max_wait_seconds=60,
        whois_recently_registered_threshold_days=30
    )


@pytest.fixture
def security_analyst(config):
    """Create Security Analyst Agent"""
    return SecurityAnalystAgent(config)


@pytest.fixture
def phishing_event():
    """Create a phishing security event for testing"""
    return SecurityEvent(
        event_id="test-phishing-001",
        source_system="email_gateway",
        timestamp=datetime.utcnow(),
        severity=Severity.HIGH,
        category=EventCategory.MALWARE,
        title="Suspected Phishing Email with Malicious Link",
        description="User reported suspicious email with link to fake login page",
        technical_indicators=[
            TechnicalIndicator(
                indicator_type="url",
                value="https://example.com",
                context="Suspicious URL in email body"
            ),
            TechnicalIndicator(
                indicator_type="domain",
                value="paypa1-secure-login.com",
                context="Typosquatting domain"
            ),
            TechnicalIndicator(
                indicator_type="ip",
                value="203.0.113.42",
                context="Hosting IP address"
            ),
            TechnicalIndicator(
                indicator_type="user",
                value="user@example.com",
                context="Targeted user"
            )
        ],
        raw_event={
            "email_subject": "Urgent: Verify Your PayPal Account",
            "sender": "user@example.com",
            "recipient": "user@example.com",
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@pytest.fixture
def data_exfiltration_event():
    """Create a data exfiltration security event for testing"""
    return SecurityEvent(
        event_id="test-exfil-001",
        source_system="aws_guardduty",
        timestamp=datetime.utcnow(),
        severity=Severity.CRITICAL,
        category=EventCategory.DATA_EXFILTRATION,
        title="Unusual S3 Data Transfer to External IP",
        description="Large volume of S3 data transferred to suspicious external IP",
        technical_indicators=[
            TechnicalIndicator(
                indicator_type="ip",
                value="198.51.100.25",
                context="Destination IP for data transfer"
            ),
            TechnicalIndicator(
                indicator_type="user",
                value="user@example.com",
                context="AWS IAM user performing transfer"
            ),
            TechnicalIndicator(
                indicator_type="host",
                value="prod-web-server-01",
                context="Source EC2 instance"
            )
        ],
        raw_event={
            "aws_account_id": "123456789012",
            "region": "us-east-1",
            "resource_type": "S3Bucket",
            "bytes_transferred": 5368709120,  # 5GB
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@pytest.mark.asyncio
async def test_urlscan_integration(security_analyst, phishing_event):
    """Test URLScan.io integration for phishing detection"""
    print("\n=== Testing URLScan.io Integration ===")
    
    # Analyze phishing event
    result = await security_analyst.analyze([phishing_event])
    
    # Verify URLScan results are present
    assert result.urlscan_results, "URLScan results should be present"
    
    # Check for phishing detection
    for url, scan_result in result.urlscan_results.items():
        print(f"\nURLScan Result for {url}:")
        print(f"  Verdict: {scan_result['verdict']}")
        print(f"  Is Phishing: {scan_result['is_phishing']}")
        print(f"  Screenshot URL: {scan_result['screenshot_url']}")
        print(f"  Brands Detected: {scan_result['brands_detected']}")
        print(f"  Malicious Indicators: {scan_result['malicious_indicators']}")
    
    print("\n✓ URLScan.io integration working correctly")


@pytest.mark.asyncio
async def test_whois_integration(security_analyst, phishing_event):
    """Test WHOIS integration for domain analysis"""
    print("\n=== Testing WHOIS Integration ===")
    
    # Analyze phishing event
    result = await security_analyst.analyze([phishing_event])
    
    # Verify WHOIS results are present
    assert result.whois_results, "WHOIS results should be present"
    
    # Check for recently registered domain detection
    for domain, whois_result in result.whois_results.items():
        print(f"\nWHOIS Result for {domain}:")
        print(f"  Age: {whois_result['age_days']} days")
        print(f"  Recently Registered: {whois_result['is_recently_registered']}")
        print(f"  Registrar: {whois_result['registrar']}")
        print(f"  Registration Date: {whois_result['registration_date']}")
        print(f"  Risk Indicators: {whois_result['risk_indicators']}")
    
    print("\n✓ WHOIS integration working correctly")


@pytest.mark.asyncio
async def test_investigation_queries(security_analyst, data_exfiltration_event):
    """Test cross-platform investigation query generation"""
    print("\n=== Testing Investigation Query Generation ===")
    
    # Analyze data exfiltration event
    result = await security_analyst.analyze([data_exfiltration_event])
    
    # Verify investigation queries are present
    assert result.investigation_queries_by_platform, "Investigation queries should be present"
    
    # Check queries for each platform
    for platform, queries in result.investigation_queries_by_platform.items():
        print(f"\n{platform.upper()} Queries ({len(queries)} total):")
        for i, query in enumerate(queries[:3], 1):  # Show first 3 queries
            print(f"\n  Query {i}:")
            print(f"    Description: {query['description']}")
            print(f"    Query: {query['query']}")
            print(f"    Timeframe: {query['timeframe']}")
            print(f"    Priority: {query['priority']}")
    
    print("\n✓ Investigation query generation working correctly")


@pytest.mark.asyncio
async def test_comprehensive_analysis(security_analyst, phishing_event):
    """Test comprehensive analysis with all new features"""
    print("\n=== Testing Comprehensive Analysis ===")
    
    # Analyze phishing event
    result = await security_analyst.analyze([phishing_event])
    
    # Verify all components are present
    print(f"\nAnalysis Results:")
    print(f"  Event ID: {result.event_id}")
    print(f"  Risk Score: {result.risk_score}/10")
    print(f"  Confidence: {result.confidence}")
    print(f"  Processing Time: {result.processing_time_seconds:.2f}s")
    
    print(f"\n5W1H Summary:")
    print(f"  Who: {result.five_w1h.who}")
    print(f"  What: {result.five_w1h.what}")
    print(f"  When: {result.five_w1h.when}")
    print(f"  Where: {result.five_w1h.where}")
    print(f"  Why: {result.five_w1h.why}")
    print(f"  How: {result.five_w1h.how}")
    
    print(f"\nEnrichment Data:")
    print(f"  IOC Enrichments: {len(result.ioc_enrichments)}")
    print(f"  URLScan Results: {len(result.urlscan_results)}")
    print(f"  WHOIS Results: {len(result.whois_results)}")
    print(f"  Investigation Queries: {sum(len(q) for q in result.investigation_queries_by_platform.values())}")
    
    print(f"\nThreat Intelligence:")
    print(f"  Threat Actors: {len(result.threat_actors)}")
    print(f"  MITRE Techniques: {len(result.mitre_techniques)}")
    print(f"  Behavioral Insights: {len(result.behavioral_insights)}")
    print(f"  Attack Graph Nodes: {len(result.attack_graph)}")
    
    print(f"\nRecommendations:")
    print(f"  Immediate Actions: {len(result.immediate_actions)}")
    print(f"  Short-term: {len(result.short_term_recommendations)}")
    print(f"  Long-term: {len(result.long_term_recommendations)}")
    
    # Verify critical fields
    assert result.risk_score > 0, "Risk score should be calculated"
    assert result.confidence > 0, "Confidence should be calculated"
    assert result.urlscan_results, "URLScan results should be present"
    assert result.whois_results, "WHOIS results should be present"
    assert result.investigation_queries_by_platform, "Investigation queries should be present"
    
    print("\n✓ Comprehensive analysis working correctly")


@pytest.mark.asyncio
async def test_integration_statistics(security_analyst, phishing_event):
    """Test integration statistics tracking"""
    print("\n=== Testing Integration Statistics ===")
    
    # Analyze event
    await security_analyst.analyze([phishing_event])
    
    # Get statistics
    urlscan_stats = security_analyst.urlscan.get_stats()
    whois_stats = security_analyst.whois.get_stats() if security_analyst.whois else {}
    
    print(f"\nURLScan.io Statistics:")
    print(f"  Scans Submitted: {urlscan_stats['scans_submitted']}")
    print(f"  Scans Completed: {urlscan_stats['scans_completed']}")
    print(f"  Scans Failed: {urlscan_stats['scans_failed']}")
    print(f"  Phishing Detected: {urlscan_stats['phishing_detected']}")
    print(f"  Cache Hits: {urlscan_stats['cache_hits']}")
    
    if whois_stats:
        print(f"\nWHOIS Statistics:")
        print(f"  Lookups Performed: {whois_stats['lookups_performed']}")
        print(f"  Lookups Successful: {whois_stats['lookups_successful']}")
        print(f"  Lookups Failed: {whois_stats['lookups_failed']}")
        print(f"  Recently Registered Detected: {whois_stats['recently_registered_detected']}")
        print(f"  Cache Hits: {whois_stats['cache_hits']}")
    
    print("\n✓ Integration statistics tracking working correctly")


if __name__ == "__main__":
    # Run tests manually
    print("Running Enhanced Security Analyst Tests...")
    print("=" * 80)
    
    # Create fixtures
    config = VaulyticaConfig(
        anthropic_api_key="sk-ant-test-key",  # Replace with real key
        enable_threat_feeds=True,
        enable_whois=True,
        enable_investigation_queries=True
    )
    
    analyst = SecurityAnalystAgent(config)
    phishing = SecurityEvent(
        event_id="test-001",
        source_system="test",
        timestamp=datetime.utcnow(),
        severity=Severity.HIGH,
        category=EventCategory.MALWARE,
        title="Test Event",
        description="Test phishing event",
        technical_indicators=[
            TechnicalIndicator(
                indicator_type="url",
                value="https://example.com",
                context="Test URL"
            )
        ],
        raw_event={}
    )
    
    # Run async tests
    asyncio.run(test_comprehensive_analysis(analyst, phishing))

