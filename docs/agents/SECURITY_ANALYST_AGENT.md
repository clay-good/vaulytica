# Security Analyst AI Agent

**Version**: 1.0.0
**Status**: Production Ready
**Last Updated**: 2025-10-21

---

## Overview

The Security Analyst Agent is an AI-powered security analyst that performs comprehensive threat analysis on security events. It combines multi-source threat intelligence, behavioral analysis, machine learning, and AI reasoning to provide deep security insights.

### Key Capabilities

- **12-Phase Analysis Pipeline**: Systematic threat analysis from IOC enrichment to confidence scoring
- **Multi-Source Threat Intelligence**: VirusTotal, AlienVault OTX, AbuseIPDB, Shodan, URLhaus, ThreatFox, URLScan.io
- **WHOIS & Domain Analysis**: Domain registration details, registrar information, age analysis
- **Behavioral Anomaly Detection**: 8 attack pattern signatures with ML-powered detection
- **Threat Actor Attribution**: Correlation with known APT groups and campaigns
- **Attack Graph Construction**: Visual representation of attack paths
- **Cross-Platform Investigation Queries**: Recommended queries for Datadog, AWS, GCP, Google Workspace
- **MITRE ATT&CK Mapping**: Automatic technique identification and tactic classification

---

## Architecture

### Analysis Pipeline

```
Security Event(s)
    ↓
1. IOC Extraction & Enrichment
   - VirusTotal (file/IP/domain/URL reputation)
   - URLScan.io (screenshot, DOM analysis, HTTP transactions)
   - WHOIS (domain registration, registrar, age)
   - AlienVault OTX (threat pulses, campaigns)
   - AbuseIPDB (IP reputation, abuse reports)
   - Shodan (port scanning, service detection)
   - URLhaus (malicious URL database)
   - ThreatFox (IOC feeds)
    ↓
2. Behavioral Analysis
   - Anomaly detection (8 attack patterns)
   - Sequence analysis (attack chain detection)
   - Baseline comparison (deviation from normal)
    ↓
3. ML-Powered Analysis
   - Isolation Forest (anomaly detection)
   - Random Forest (threat prediction)
   - Feature engineering (50+ security features)
    ↓
4. Threat Actor Attribution
   - APT group correlation
   - TTP matching (tactics, techniques, procedures)
   - Campaign identification
    ↓
5. AI Analysis (Claude)
   - Deep reasoning over all collected evidence
   - Natural language threat summary
   - Recommended actions
    ↓
6. Cross-Platform Investigation Queries
   - Datadog log queries
   - AWS CloudTrail queries
   - GCP audit log queries
   - Google Workspace queries
    ↓
7. Attack Graph Construction
   - Visual attack path representation
   - Node relationships (leads_to, enables, exploits)
    ↓
8. Confidence Scoring
   - Evidence-based confidence calculation
   - Multi-source validation
    ↓
Analysis Result (JSON)
```

---

## Configuration

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Threat Intelligence APIs (at least one recommended)
VIRUSTOTAL_API_KEY=your-vt-key
URLSCAN_API_KEY=your-urlscan-key
ALIENVAULT_OTX_API_KEY=your-otx-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
SHODAN_API_KEY=your-shodan-key

# Optional
ENABLE_THREAT_FEEDS=true
THREAT_FEED_CACHE_TTL=24  # hours
THREAT_FEED_TIMEOUT=10    # seconds
```

### Python Configuration

```python
from vaulytica.config import VaulyticaConfig
from vaulytica.agents.security_analyst import SecurityAnalystAgent

config = VaulyticaConfig(
    anthropic_api_key="sk-ant-...",
    virustotal_api_key="your-vt-key",
    urlscan_api_key="your-urlscan-key",
    alienvault_otx_api_key="your-otx-key",
    abuseipdb_api_key="your-abuseipdb-key",
    shodan_api_key="your-shodan-key",
    enable_threat_feeds=True,
    threat_feed_cache_ttl=24,
    threat_feed_timeout=10
)

agent = SecurityAnalystAgent(config)
```

---

## Usage

### Basic Analysis

```python
from vaulytica.models import SecurityEvent
from vaulytica.agents.security_analyst import SecurityAnalystAgent
from vaulytica.config import get_config

# Initialize agent
config = get_config()
agent = SecurityAnalystAgent(config)

# Create security event
event = SecurityEvent(
    event_id="evt-123",
    source_system="Datadog Security Monitoring",
    timestamp=datetime.utcnow(),
    severity="HIGH",
    category="intrusion_detection",
    title="Suspicious API Access from Unknown IP",
    description="Multiple failed authentication attempts followed by successful login",
    affected_assets=["api-gateway-prod", "user-service"],
    technical_indicators={
        "source_ip": "203.0.113.42",
        "user_agent": "python-requests/2.28.0",
        "endpoint": "/api/v1/users",
        "status_codes": [401, 401, 401, 200]
    },
    raw_event={...}
)

# Analyze event
result = await agent.analyze([event])

# Access results
print(f"Severity: {result.severity}")
print(f"Confidence: {result.confidence_score}")
print(f"Summary: {result.summary}")
print(f"Threat Actor: {result.threat_actor_profile.name if result.threat_actor_profile else 'Unknown'}")
print(f"MITRE Techniques: {[t.technique_id for t in result.mitre_attack]}")
print(f"Recommended Actions: {result.recommended_actions}")
```

### Datadog Integration

```python
from vaulytica.parsers.datadog import DatadogParser
from vaulytica.datadog_integration import get_datadog_case_manager

# Parse Datadog security signal
parser = DatadogParser()
event = parser.parse(datadog_signal_json)

# Analyze with Security Analyst Agent
result = await agent.analyze([event])

# Create Datadog case with enriched analysis
case_manager = get_datadog_case_manager()
case = await case_manager.create_case_from_incident(
    incident_id="inc-123",
    analysis=result
)
```

---

## Threat Intelligence Enrichment

### VirusTotal Integration

**Capabilities**:
- File hash reputation (MD5, SHA1, SHA256)
- IP address reputation
- Domain reputation
- URL scanning
- Detection rate from 70+ antivirus engines

**Example Output**:
```json
{
  "source": "VIRUSTOTAL",
  "ioc_value": "203.0.113.42",
  "ioc_type": "ip",
  "is_malicious": true,
  "confidence": 0.85,
  "threat_score": 75,
  "tags": ["malware", "botnet", "c2"],
  "metadata": {
    "detection_rate": "45/70",
    "malware_families": ["Emotet", "TrickBot"],
    "last_analysis_date": "2025-10-21T10:30:00Z"
  }
}
```

### URLScan.io Integration

**Capabilities**:
- Full page screenshot capture
- DOM analysis (JavaScript execution, redirects)
- HTTP transaction logging
- Resource loading analysis
- Phishing detection
- Brand impersonation detection

**Example Output**:
```json
{
  "source": "URLSCAN",
  "url": "https://example.com",
  "screenshot_url": "https://example.com",
  "verdict": "malicious",
  "brands_detected": ["Microsoft", "Office365"],
  "is_phishing": true,
  "technologies": ["PHP", "Bootstrap", "jQuery"],
  "redirects": [
    "https://example.com",
    "https://example.com"
  ],
  "http_transactions": 45,
  "resources_loaded": 120,
  "malicious_indicators": [
    "Fake login form",
    "Credential harvesting script",
    "Redirect to known malicious domain"
  ]
}
```

**Jira Integration**: Screenshots automatically attached to Jira tickets for visual evidence

### WHOIS Integration

**Capabilities**:
- Domain registration date
- Registrar information
- Registrant contact details (if not privacy-protected)
- Name servers
- Domain age analysis
- Recently registered domain detection (<30 days = suspicious)

**Example Output**:
```json
{
  "domain": "suspicious-domain.com",
  "registrar": "NameCheap Inc.",
  "registration_date": "2025-10-15T00:00:00Z",
  "expiration_date": "2026-10-15T00:00:00Z",
  "age_days": 6,
  "is_recently_registered": true,
  "registrant": {
    "name": "REDACTED FOR PRIVACY",
    "organization": "Privacy Protect, LLC",
    "email": "user@example.com"
  },
  "name_servers": [
    "ns1.suspicious-hosting.com",
    "ns2.suspicious-hosting.com"
  ],
  "risk_indicators": [
    "Recently registered (6 days old)",
    "Privacy protection enabled",
    "Hosting provider associated with malicious activity"
  ]
}
```

---

## Cross-Platform Investigation Queries

The Security Analyst Agent generates recommended queries for investigating threats across your infrastructure. These are **read-only queries** for manual investigation (automation can be added later).

### Datadog Queries

```python
# Example: Investigate suspicious IP across all services
result.investigation_queries["datadog"] = [
    {
        "query": "source:* @network.client.ip:203.0.113.42",
        "description": "Find all logs from suspicious IP",
        "timeframe": "last_7_days"
    },
    {
        "query": "service:api-gateway @http.status_code:[400 TO 499] @network.client.ip:203.0.113.42",
        "description": "Find failed authentication attempts from this IP",
        "timeframe": "last_24_hours"
    },
    {
        "query": "@usr.id:user-12345 @network.client.ip:*",
        "description": "Find all IPs used by compromised user",
        "timeframe": "last_7_days"
    }
]
```

### AWS CloudTrail Queries

```python
result.investigation_queries["aws_cloudtrail"] = [
    {
        "query": "sourceIPAddress = '203.0.113.42'",
        "description": "Find all AWS API calls from suspicious IP",
        "service": "CloudTrail"
    },
    {
        "query": "userIdentity.userName = 'compromised-user' AND errorCode EXISTS",
        "description": "Find failed API calls by compromised user",
        "service": "CloudTrail"
    }
]
```

### GCP Audit Logs Queries

```python
result.investigation_queries["gcp_audit"] = [
    {
        "query": 'protoPayload.requestMetadata.callerIp="203.0.113.42"',
        "description": "Find all GCP API calls from suspicious IP",
        "log_type": "cloudaudit.googleapis.com/activity"
    }
]
```

### Google Workspace Queries

```python
result.investigation_queries["google_workspace"] = [
    {
        "query": "ip_address:203.0.113.42",
        "description": "Find all Workspace logins from suspicious IP",
        "application": "login"
    },
    {
        "query": "email:user@example.com event_name:add_forwarding_address",
        "description": "Check if user added email forwarding rules",
        "application": "gmail"
    }
]
```

---

## Analysis Result Structure

```python
@dataclass
class AnalysisResult:
    event_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence_score: float  # 0.0 to 1.0
    summary: str
    detailed_analysis: str
    mitre_attack: List[MitreAttack]
    five_w1h: FiveW1H
    threat_actor_profile: Optional[ThreatActorProfile]
    behavioral_insights: List[BehavioralInsight]
    attack_graph: List[AttackGraphNode]
    recommended_actions: List[str]
    investigation_queries: Dict[str, List[Dict]]  # NEW: Cross-platform queries
    ioc_enrichment: Dict[str, IOCEnrichment]
    timestamp: datetime
    analysis_duration_seconds: float
```

---

## Performance

- **Average Analysis Time**: 2-5 seconds per event
- **Threat Intelligence Cache Hit Rate**: 83%
- **ML Model Inference Time**: <50ms
- **API Rate Limiting**: Automatic backoff and retry
- **Concurrent Analysis**: Up to 10 events in parallel

---

## Integration with Incident Response Agent

The Incident Response Agent automatically ingests Security Analyst results:

```python
from vaulytica.agents.incident_response import IncidentResponseAgent

# Security Analyst performs analysis
security_result = await security_analyst.analyze([event])

# Incident Response Agent uses enriched analysis
ir_agent = IncidentResponseAgent(config)
incident = await ir_agent.handle_incident(
    incident_id="inc-123",
    security_analysis=security_result  # Pre-enriched with threat intel
)
```

**Benefits**:
- No duplicate threat intelligence API calls
- Consistent IOC enrichment across both agents
- Faster incident response (analysis already complete)

---

## Troubleshooting

### Issue: Threat Intelligence APIs Timing Out

**Solution**: Increase timeout or disable slow sources
```python
config.threat_feed_timeout = 30  # seconds
config.enable_shodan = False  # Disable if consistently slow
```

### Issue: Rate Limiting from VirusTotal

**Solution**: Implement request throttling
```python
config.virustotal_requests_per_minute = 4  # Free tier limit
```

### Issue: URLScan.io Screenshots Not Appearing

**Solution**: Check API key and submission status
```python
# URLScan.io scans take 10-30 seconds to complete
# Agent will poll for results up to 60 seconds
config.urlscan_max_wait_seconds = 60
```

---

## Best Practices

1. **Use Threat Intelligence Caching**: Reduces API costs and improves performance
2. **Configure Multiple Threat Feeds**: Cross-validation improves accuracy
3. **Review Investigation Queries**: Use recommended queries to investigate further
4. **Monitor API Quotas**: Track usage to avoid rate limiting
5. **Tune Confidence Thresholds**: Adjust based on your risk tolerance

---

## API Reference

See `vaulytica/agents/security_analyst.py` for full API documentation.

**Key Methods**:
- `analyze(events: List[SecurityEvent]) -> AnalysisResult`
- `enrich_ioc(ioc_value: str, ioc_type: str) -> IOCEnrichment`
- `generate_investigation_queries(event: SecurityEvent) -> Dict[str, List[Dict]]`

---

## Changelog

**v1.0.0** (2025-10-21):
- Added URLScan.io integration for screenshot capture
- Added WHOIS integration for domain analysis
- Added cross-platform investigation query generation
- Enhanced Datadog integration
- Improved threat actor attribution
- Added attack graph visualization

---

## Support

For issues or questions:
- GitHub Issues: https://example.com
- Documentation: https://docs.vaulytica.com
- Email: support@vaulytica.com

