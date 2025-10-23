# Incident Response AI Agent

**Version**: 1.0.0
**Status**: Production Ready
**Last Updated**: 2025-10-21

---

## Overview

The Incident Response Agent manages the complete incident response lifecycle from detection through recovery. It automatically ingests enriched analysis from the Security Analyst Agent and orchestrates response activities across multiple systems.

### Key Capabilities

- **Complete Incident Lifecycle Management**: Detection, analysis, containment, eradication, recovery, post-incident
- **Automatic Security Analyst Integration**: Ingests pre-enriched threat intelligence and IOC analysis
- **Timeline Reconstruction**: Builds detailed incident timeline with evidence correlation
- **Root Cause Analysis**: Identifies initial attack vector and contributing factors
- **Business Impact Assessment**: Calculates financial, reputational, and regulatory impact
- **MTTD/MTTC/MTTR Tracking**: Measures detection, containment, and recovery times
- **Post-Mortem Generation**: Creates comprehensive incident reports with corrective actions
- **Multi-System Integration**: Jira, ServiceNow, PagerDuty, Datadog Case Management

---

## Architecture

### Incident Response Lifecycle

```
Incident Detected
    ↓
1. DETECTION PHASE
   - Ingest Security Analyst analysis (pre-enriched)
   - Extract IOCs, threat intel, MITRE techniques
   - Calculate MTTD (Mean Time To Detect)
   - Create incident record
    ↓
2. ANALYSIS PHASE
   - Timeline reconstruction
   - Scope determination (affected systems/users)
   - Attack path analysis
   - Evidence collection
    ↓
3. CONTAINMENT PHASE
   - Generate containment actions
   - Track containment execution
   - Calculate MTTC (Mean Time To Contain)
   - Prevent lateral movement
    ↓
4. ERADICATION PHASE
   - Remove threat actor access
   - Patch vulnerabilities
   - Eliminate persistence mechanisms
   - Validate eradication
    ↓
5. RECOVERY PHASE
   - Restore normal operations
   - Validate system integrity
   - Monitor for reinfection
   - Calculate MTTR (Mean Time To Recover)
    ↓
6. POST-INCIDENT PHASE
   - Generate post-mortem report
   - Identify corrective actions
   - Update runbooks/playbooks
   - Lessons learned documentation
    ↓
Incident Closed
```

---

## Configuration

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Datadog Integration
DATADOG_API_KEY=your-dd-api-key
DATADOG_APP_KEY=your-dd-app-key
DATADOG_SITE=datadoghq.com

# Ticketing Integration (at least one recommended)
JIRA_URL=https://your-company.atlassian.net
JIRA_USERNAME=user@example.com
JIRA_API_TOKEN=your-jira-token
JIRA_PROJECT_KEY=SEC

SERVICENOW_INSTANCE=your-instance.service-now.com
SERVICENOW_USERNAME=admin
SERVICENOW_PASSWORD=your-password

# Alerting Integration
PAGERDUTY_API_KEY=your-pd-key
PAGERDUTY_SERVICE_ID=your-service-id
```

### Python Configuration

```python
from vaulytica.config import VaulyticaConfig
from vaulytica.agents.incident_response import IncidentResponseAgent

config = VaulyticaConfig(
    anthropic_api_key="sk-ant-...",
    datadog_api_key="your-dd-api-key",
    datadog_app_key="your-dd-app-key",
    jira_url="https://your-company.atlassian.net",
    jira_username="user@example.com",
    jira_api_token="your-jira-token",
    jira_project_key="SEC"
)

agent = IncidentResponseAgent(config)
```

---

## Usage

### Basic Incident Response

```python
from vaulytica.agents.incident_response import IncidentResponseAgent
from vaulytica.agents.security_analyst import SecurityAnalystAgent
from vaulytica.config import get_config

# Initialize agents
config = get_config()
security_analyst = SecurityAnalystAgent(config)
ir_agent = IncidentResponseAgent(config)

# Step 1: Security Analyst performs analysis
security_result = await security_analyst.analyze([event])

# Step 2: Incident Response Agent handles incident
# (automatically ingests security_result with all threat intel)
incident = await ir_agent.handle_incident(
    incident_id="inc-123",
    security_analysis=security_result,
    severity="HIGH",
    affected_systems=["api-gateway-prod", "user-service"],
    affected_users=["user-12345"]
)

# Access incident details
print(f"Status: {incident.status}")
print(f"MTTD: {incident.metrics.mttd} seconds")
print(f"MTTC: {incident.metrics.mttc} seconds")
print(f"Business Impact: ${incident.business_impact.financial_impact}")
print(f"Corrective Actions: {len(incident.corrective_actions)}")
```

### Datadog Integration

```python
from vaulytica.datadog_integration import get_datadog_case_manager

# Initialize case manager with auto-sync
case_manager = get_datadog_case_manager(
    api_key=config.datadog_api_key,
    app_key=config.datadog_app_key,
    auto_create_cases=True,
    auto_sync=True,
    sync_interval=300  # 5 minutes
)

# Handle incident (automatically creates Datadog case)
incident = await ir_agent.handle_incident(
    incident_id="inc-123",
    security_analysis=security_result
)

# Case is automatically created and synced
case = await case_manager.get_case_by_incident_id("inc-123")
print(f"Datadog Case ID: {case.case_id}")
print(f"Case URL: https://example.com")
```

### Jira Integration

```python
from vaulytica.integrations.jira import JiraIntegration

# Initialize Jira integration
jira = JiraIntegration(
    url=config.jira_url,
    username=config.jira_username,
    api_token=config.jira_api_token
)

# Create Jira ticket with incident details
ticket = await jira.create_incident_ticket(
    project_key="SEC",
    incident=incident,
    security_analysis=security_result
)

# Ticket includes:
# - Full incident timeline
# - IOC enrichment (VirusTotal, URLScan.io, WHOIS)
# - URLScan.io screenshots (attached)
# - Recommended containment actions
# - Investigation queries for Datadog/AWS/GCP/Workspace
print(f"Jira Ticket: {ticket.key}")
print(f"Attachments: {len(ticket.attachments)} (including screenshots)")
```

---

## Integration with Security Analyst Agent

The Incident Response Agent is designed to work seamlessly with the Security Analyst Agent:

### Automatic Enrichment Ingestion

```python
# Security Analyst enriches event with:
# - VirusTotal reputation
# - URLScan.io screenshots
# - WHOIS domain info
# - Threat actor attribution
# - MITRE ATT&CK techniques
# - Cross-platform investigation queries
security_result = await security_analyst.analyze([event])

# Incident Response Agent receives ALL enrichment
# No duplicate API calls, no re-analysis needed
incident = await ir_agent.handle_incident(
    incident_id="inc-123",
    security_analysis=security_result  # Pre-enriched
)

# Incident now includes:
# - All IOC enrichment from Security Analyst
# - URLScan.io screenshots
# - WHOIS details
# - Investigation queries
# - Threat actor profile
```

### Benefits

1. **No Duplicate API Calls**: Security Analyst already called VirusTotal, URLScan.io, WHOIS
2. **Faster Response**: Analysis is complete, IR agent focuses on response actions
3. **Consistent Data**: Both agents use same enriched IOC data
4. **Cost Savings**: Single set of threat intelligence API calls

---

## Incident Response Phases

### Phase 1: Detection

**Activities**:
- Ingest security event and analysis
- Extract IOCs and threat intelligence
- Determine incident severity
- Calculate MTTD (time from attack to detection)
- Create incident record
- Notify stakeholders (PagerDuty, Slack)

**Output**:
```python
{
  "phase": "DETECTION",
  "mttd_seconds": 1800,  # 30 minutes
  "severity": "HIGH",
  "iocs": ["203.0.113.42", "malicious-domain.com"],
  "threat_actor": "APT28",
  "mitre_techniques": ["T1078", "T1110"]
}
```

### Phase 2: Analysis

**Activities**:
- Reconstruct incident timeline
- Identify affected systems and users
- Determine attack path
- Collect evidence
- Assess scope

**Output**:
```python
{
  "phase": "ANALYSIS",
  "timeline": [
    {"time": "2025-10-21T10:00:00Z", "event": "Initial access via compromised credentials"},
    {"time": "2025-10-21T10:15:00Z", "event": "Lateral movement to api-gateway"},
    {"time": "2025-10-21T10:30:00Z", "event": "Data exfiltration detected"}
  ],
  "affected_systems": ["api-gateway-prod", "user-service", "database-prod"],
  "affected_users": ["user-12345", "user-67890"],
  "attack_path": "Initial Access → Lateral Movement → Data Exfiltration"
}
```

### Phase 3: Containment

**Activities**:
- Block malicious IPs/domains
- Disable compromised accounts
- Isolate affected systems
- Prevent lateral movement
- Calculate MTTC

**Output**:
```python
{
  "phase": "CONTAINMENT",
  "mttc_seconds": 900,  # 15 minutes
  "actions_taken": [
    "Blocked IP 203.0.113.42 at firewall",
    "Disabled user account user-12345",
    "Isolated api-gateway-prod from production network",
    "Revoked all active sessions for affected users"
  ]
}
```

### Phase 4: Eradication

**Activities**:
- Remove malware/backdoors
- Patch vulnerabilities
- Reset compromised credentials
- Eliminate persistence mechanisms

**Output**:
```python
{
  "phase": "ERADICATION",
  "actions_taken": [
    "Removed malicious cron job from api-gateway",
    "Patched authentication bypass vulnerability",
    "Reset passwords for all affected users",
    "Removed unauthorized SSH keys"
  ]
}
```

### Phase 5: Recovery

**Activities**:
- Restore systems from clean backups
- Validate system integrity
- Monitor for reinfection
- Calculate MTTR

**Output**:
```python
{
  "phase": "RECOVERY",
  "mttr_seconds": 3600,  # 1 hour
  "actions_taken": [
    "Restored api-gateway from clean backup",
    "Validated system integrity with file integrity monitoring",
    "Enabled enhanced monitoring for 7 days",
    "Confirmed no reinfection after 24 hours"
  ]
}
```

### Phase 6: Post-Incident

**Activities**:
- Generate post-mortem report
- Identify root cause
- Document lessons learned
- Create corrective actions
- Update runbooks

**Output**: See Post-Mortem Report section below

---

## Post-Mortem Report

The Incident Response Agent automatically generates comprehensive post-mortem reports:

### Report Structure

```markdown
# Incident Post-Mortem: INC-123

## Executive Summary
High-severity security incident involving compromised credentials and data exfiltration.
Detected within 30 minutes, contained within 15 minutes, full recovery within 1 hour.

## Incident Timeline
- 2025-10-21 10:00:00 UTC: Initial access via compromised credentials
- 2025-10-21 10:15:00 UTC: Lateral movement to api-gateway
- 2025-10-21 10:30:00 UTC: Data exfiltration detected
- 2025-10-21 10:30:00 UTC: Incident detected by Datadog security monitoring
- 2025-10-21 10:45:00 UTC: Containment actions completed
- 2025-10-21 11:30:00 UTC: Full recovery completed

## Root Cause Analysis
**Initial Attack Vector**: Compromised user credentials (weak password)
**Contributing Factors**:
- MFA not enforced for API access
- Insufficient rate limiting on authentication endpoints
- Delayed detection due to alert tuning

## Business Impact
- **Financial**: $50,000 (estimated incident response costs)
- **Reputational**: Low (no customer data exposed)
- **Regulatory**: Medium (potential GDPR notification required)
- **Operational**: 4 hours of service degradation

## Metrics
- **MTTD**: 30 minutes (Mean Time To Detect)
- **MTTC**: 15 minutes (Mean Time To Contain)
- **MTTR**: 1 hour (Mean Time To Recover)

## Corrective Actions
1. [HIGH] Enforce MFA for all API access (Owner: Security Team, Due: 2025-10-28)
2. [HIGH] Implement rate limiting on auth endpoints (Owner: Platform Team, Due: 2025-10-28)
3. [MEDIUM] Review and tune Datadog detection rules (Owner: Security Team, Due: 2025-11-04)
4. [MEDIUM] Conduct security awareness training on password hygiene (Owner: HR, Due: 2025-11-15)

## Lessons Learned
- Early detection prevented significant data loss
- Automated containment actions reduced MTTC
- Cross-platform investigation queries helped identify full scope quickly
- Need better visibility into API authentication patterns

## Recommendations
- Implement continuous authentication monitoring
- Deploy UEBA (User and Entity Behavior Analytics)
- Enhance API security posture
```

---

## Metrics Tracking

### Key Metrics

- **MTTD** (Mean Time To Detect): Time from attack start to detection
- **MTTC** (Mean Time To Contain): Time from detection to containment
- **MTTR** (Mean Time To Recover): Time from detection to full recovery
- **Business Impact**: Financial, reputational, regulatory, operational

### Metrics Dashboard

```python
# Get incident metrics
metrics = incident.metrics

print(f"MTTD: {metrics.mttd / 60:.1f} minutes")
print(f"MTTC: {metrics.mttc / 60:.1f} minutes")
print(f"MTTR: {metrics.mttr / 60:.1f} minutes")
print(f"Total Duration: {metrics.total_duration / 3600:.1f} hours")

# Business impact
impact = incident.business_impact
print(f"Financial Impact: ${impact.financial_impact:,.2f}")
print(f"Affected Customers: {impact.affected_customers}")
print(f"Regulatory Exposure: {impact.regulatory_exposure}")
```

---

## Best Practices

1. **Always Use Security Analyst First**: Let Security Analyst enrich IOCs before IR agent
2. **Enable Auto-Sync with Datadog**: Keep case management synchronized
3. **Configure Jira Integration**: Automatic ticket creation with full context
4. **Review Post-Mortems**: Use lessons learned to improve detection and response
5. **Track Metrics Over Time**: Monitor MTTD/MTTC/MTTR trends to measure improvement

---

## Troubleshooting

### Issue: Incident Not Creating Datadog Case

**Solution**: Check auto_create_cases setting
```python
case_manager = get_datadog_case_manager(
    auto_create_cases=True  # Ensure this is True
)
```

### Issue: Jira Ticket Missing Screenshots

**Solution**: Ensure Security Analyst ran URLScan.io enrichment first
```python
# Security Analyst must complete analysis first
security_result = await security_analyst.analyze([event])

# Then IR agent can attach screenshots to Jira
incident = await ir_agent.handle_incident(
    security_analysis=security_result  # Includes screenshots
)
```

---

## API Reference

See `vaulytica/agents/incident_response.py` for full API documentation.

**Key Methods**:
- `handle_incident(incident_id, security_analysis, ...) -> Incident`
- `generate_post_mortem(incident) -> PostMortemReport`
- `calculate_metrics(incident) -> IncidentMetrics`
- `assess_business_impact(incident) -> BusinessImpact`

---

## Changelog

**v1.0.0** (2025-10-21):
- Automatic Security Analyst integration
- Enhanced Datadog case management
- Jira integration with screenshot attachments
- Post-mortem report generation
- Business impact assessment
- MTTD/MTTC/MTTR tracking

---

## Support

For issues or questions:
- GitHub Issues: https://example.com
- Documentation: https://docs.vaulytica.com
- Email: support@vaulytica.com

