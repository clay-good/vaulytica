# Vaulytica CLI Usage Guide

## Overview

Vaulytica is a modular AI agent framework designed CLI-first for security teams. Each of the 6 AI agents can be invoked independently from the command line, making it perfect for integration into security workflows, SOAR platforms, and automation pipelines.

## Installation

```bash
# Install Vaulytica
pip install -e .

# Set API key
export ANTHROPIC_API_KEY="your-api-key"

# Verify installation
vaulytica --version
vaulytica list-agents
```

## Available Agents

### 1. Security Analysis Agent

Analyzes security events from SIEM platforms with AI-powered threat analysis.

```bash
# Analyze a GuardDuty finding
vaulytica analyze test_data/guardduty_crypto_mining.json \
  --source guardduty \
  --output-json analysis.json \
  --output-html report.html

# Analyze Datadog security event
vaulytica analyze test_data/datadog_data_exfiltration.json \
  --source datadog \
  --enable-rag \
  --enable-cache

# Batch process multiple events
vaulytica batch test_data/ \
  --source guardduty \
  --pattern "guardduty_*.json" \
  --output-report batch_report.json
```

**Supported Sources**: guardduty, gcp-scc, datadog, crowdstrike, snowflake

**Output**: Risk score, MITRE ATT&CK techniques, IOCs, recommendations

### 2. Incident Response Agent

Automated incident response with intelligent containment and remediation.

```bash
# Respond to an incident
vaulytica incident-response incident.json --output response_plan.json
```

**Input Format** (incident.json):
```json
{
  "incident_id": "INC-001",
  "severity": "high",
  "description": "Suspected data exfiltration",
  "affected_systems": ["server-01", "server-02"],
  "iocs": ["malicious-domain.com", "192.168.1.100"]
}
```

**Output**: Containment actions, investigation steps, remediation plan

### 3. Vulnerability Management Agent

Vulnerability analysis and automated remediation planning.

```bash
# Analyze vulnerability
vaulytica vuln-management vulnerability.json --output remediation.json
```

**Input Format** (vulnerability.json):
```json
{
  "vuln_id": "CVE-2024-1234",
  "severity": "critical",
  "affected_assets": ["app-server-01"],
  "package": "log4j",
  "version": "2.14.1"
}
```

**Output**: Remediation plan, dependency analysis, patch recommendations

### 4. Detection Engineering Agent

Automated detection tuning and false positive reduction.

```bash
# Tune detection rule
vaulytica detection-engineering detection.json --output tuning.json
```

**Input Format** (detection.json):
```json
{
  "detection_id": "DET-001",
  "platform": "datadog",
  "rule_name": "Failed Login Attempts",
  "query": "source:auth action:login_failed",
  "alerts": [
    {"timestamp": "2024-01-01T10:00:00Z", "outcome": "false_positive"},
    {"timestamp": "2024-01-01T11:00:00Z", "outcome": "true_positive"}
  ]
}
```

**Output**: Tuning recommendations, exclusion patterns, A/B test plan

### 5. Brand Protection Agent

Domain monitoring and takedown coordination.

```bash
# Generate domain permutations
vaulytica brand-protection --domain vaulytica.com --output permutations.json
```

**Output**: Domain permutations, threat scores, takedown recommendations

### 6. Security Questionnaire Agent

Automated security questionnaire completion using RAG.

```bash
# Answer questionnaire
vaulytica security-questionnaire questionnaire.csv \
  --documents-dir ./security_docs \
  --output answers.json
```

**Input**: CSV/Excel questionnaire with questions
**Documents**: PDF, DOCX, TXT, MD, HTML files with security documentation
**Output**: Answered questionnaire with source citations

## Common Options

All commands support these options:

```bash
--api-key TEXT          Anthropic API key (or set ANTHROPIC_API_KEY env var)
--output PATH           Output file path
--debug                 Enable debug logging
--log-file PATH         Log file path
```

## System Commands

### View Statistics

```bash
# Show system stats
vaulytica stats

# Show detailed metrics
vaulytica stats --metrics
```

### Cache Management

```bash
# Clear all cache
vaulytica clear --clear-cache

# Clear expired entries only
vaulytica clear --clear-expired
```

### Start API Server

```bash
# Start REST API server
vaulytica serve --host 0.0.0.0 --port 8000

# Development mode with auto-reload
vaulytica serve --reload

# Production mode with multiple workers
vaulytica serve --workers 4
```

## Integration Examples

### SOAR Integration

```bash
# In your SOAR playbook
INCIDENT_DATA=$(cat incident.json)
RESPONSE=$(vaulytica incident-response incident.json --output /tmp/response.json)
cat /tmp/response.json | jq '.containment_actions'
```

### CI/CD Pipeline

```bash
# In GitLab CI/CD
script:
  - vaulytica vuln-management scan_results.json --output remediation.json
  - cat remediation.json | jq '.high_priority_vulns' > high_priority.json
  - if [ $(jq length high_priority.json) -gt 0 ]; then exit 1; fi
```

### Cron Job for Detection Tuning

```bash
# Daily detection tuning
0 2 * * * vaulytica detection-engineering /var/log/detections.json --output /var/log/tuning_$(date +\%Y\%m\%d).json
```

### Slack Integration

```bash
# Alert on high-risk findings
RISK_SCORE=$(vaulytica analyze alert.json --output-json /tmp/analysis.json | jq '.risk_score')
if [ $RISK_SCORE -gt 7 ]; then
  curl -X POST $SLACK_WEBHOOK -d "{\"text\": \"High risk alert: $RISK_SCORE\"}"
fi
```

## Python API Usage

All agents can also be used programmatically:

```python
from vaulytica.agents import (
    SecurityAnalysisAgent,
    IncidentResponseAgent,
    VulnerabilityManagementAgent,
    DetectionEngineeringAgent,
    BrandProtectionAgent,
    SecurityQuestionnaireAgent,
    AgentInput,
    AgentContext
)

# Initialize agent
agent = IncidentResponseAgent()

# Create input
agent_input = AgentInput(
    task="respond_to_incident",
    context=AgentContext(
        incident_id="INC-001",
        workflow_id="WORKFLOW-001"
    ),
    parameters={
        "severity": "high",
        "description": "Data exfiltration detected"
    }
)

# Execute
result = await agent.execute(agent_input)
print(f"Status: {result.status}")
print(f"Data: {result.data}")
```

## Agent Orchestration

Use multiple agents together:

```python
from vaulytica.agents import AgentOrchestrator, WorkflowDefinition, WorkflowStep

# Define workflow
workflow = WorkflowDefinition(
    name="Incident Response Workflow",
    steps=[
        WorkflowStep(agent="security_analysis", task="analyze_threat"),
        WorkflowStep(agent="incident_response", task="respond_to_incident"),
        WorkflowStep(agent="vulnerability_management", task="assess_vulnerabilities")
    ]
)

# Execute workflow
orchestrator = AgentOrchestrator()
result = await orchestrator.execute_workflow(workflow, context)
```

## Best Practices

1. **Use Environment Variables**: Store API keys in environment variables, not in code
2. **Enable Caching**: Use `--enable-cache` for repeated analyses to save costs
3. **Batch Processing**: Use `batch` command for multiple events to improve performance
4. **Output to Files**: Always use `--output` for production workflows
5. **Monitor Metrics**: Regularly check `vaulytica stats --metrics` for performance
6. **Log Everything**: Use `--log-file` for audit trails and debugging

## Troubleshooting

### API Key Issues
```bash
# Verify API key is set
echo $ANTHROPIC_API_KEY

# Test with explicit key
vaulytica analyze test.json --source guardduty --api-key "your-key"
```

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Verify installation
python -c "import vaulytica; print(vaulytica.__version__)"
```

### Performance Issues
```bash
# Clear cache
vaulytica clear --clear-cache

# Check stats
vaulytica stats --metrics
```

## Support

For issues and questions:
- GitHub: https://github.com/clay-good/vaulytica
- Documentation: See docs/ directory

