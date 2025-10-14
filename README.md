# Vaulytica

Security event analysis framework with expert-level incident analysis, automated threat intelligence correlation, and professional reporting.

## Overview

Vaulytica is a security analysis tool that transforms raw security events into actionable intelligence using AI. Built for security operations centers (SOCs), incident response teams, and security analysts, it provides expert-level analysis in seconds with comprehensive 5W1H summaries, MITRE ATT&CK mapping, and professional reports.

### Key Features

- **AI-Powered Analysis**: Claude AI provides expert-level security analysis with 10-phase methodology
- **5W1H Quick Summary**: Rapid incident understanding (Who, What, When, Where, Why, How)
- **Multi-Source Support**: AWS GuardDuty, GCP Security Command Center, Datadog, CrowdStrike, Snowflake
- **Historical Context**: RAG system correlates with similar past incidents
- **Intelligent Caching**: 90% cost reduction with sub-100ms cache hits
- **Batch Processing**: Parallel analysis of multiple events
- **Professional Reports**: JSON, Markdown, and HTML outputs
- **SOAR Integration**: CLI tool integrates with Tines, Datadog Workflows, and other platforms
- **Production-Ready**: Comprehensive error handling, logging, and validation

### Use Cases

1. **Incident Response**: Rapid triage and analysis of security alerts
2. **Threat Hunting**: Analyze suspicious events with historical context
3. **SOAR Integration**: Automated analysis in security orchestration workflows
4. **Security Training**: Learn from AI-generated analysis and investigation queries
5. **Compliance Reporting**: Generate professional reports for stakeholders

## Installation

### Prerequisites

- Python 3.9 or higher
- Anthropic API key (Claude AI)
- 2GB RAM minimum
- 500MB disk space

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/vaulytica.git
cd vaulytica
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Configure API Key

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

Or create a `.env` file:

```bash
echo "ANTHROPIC_API_KEY=sk-ant-api03-..." > .env
```

### Step 4: Verify Installation

```bash
python -m vaulytica.cli --version
```

Expected output: `cli, version 0.3.0`

## Quick Start

### Example 1: Analyze Single Event

```bash
python -m vaulytica.cli analyze test_data/guardduty_crypto_mining.json \
  --source guardduty \
  --output-html outputs/analysis.html
```

**Expected Output:**
```
============================================================
  VAULYTICA SECURITY ANALYST
============================================================

✓ Parsed 1 event(s) from guardduty
✓ Found 3 similar historical incident(s)
⚙ Analyzing with AI security analyst...
✓ Analysis stored in RAG database

Generating Reports:
  ✓ HTML: outputs/analysis.html

============================================================
  Risk Score: 8.5/10
  Confidence: 92%
  Processing Time: 18.3s
============================================================
```

### Example 2: Generate All Report Formats

```bash
python -m vaulytica.cli analyze test_data/snowflake_data_exfiltration.json \
  --source snowflake \
  --output-json outputs/analysis.json \
  --output-markdown outputs/analysis.md \
  --output-html outputs/analysis.html
```

### Example 3: Batch Processing

```bash
python -m vaulytica.cli batch test_data \
  --source guardduty \
  --pattern "guardduty*.json" \
  --output-report outputs/batch_report.json
```

### Example 4: Disable Caching for Fresh Analysis

```bash
python -m vaulytica.cli analyze test_data/event.json \
  --source guardduty \
  --no-cache \
  --output-html outputs/fresh_analysis.html
```

### Example 5: View System Statistics

```bash
python -m vaulytica.cli stats
```

**Expected Output:**
```
=== Vaulytica System Statistics ===

RAG Database:
  Total incidents: 12
  Collection: security_incidents

Cache:
  Total entries: 8
  Total size: 0.15 MB
  TTL: 24 hours
  Cache directory: ./.cache
```

### Example 6: Enable Debug Logging

```bash
python -m vaulytica.cli --debug --log-file vaulytica.log analyze test_data/event.json \
  --source guardduty \
  --output-html outputs/analysis.html
```

## Supported Data Sources

Vaulytica supports security events from multiple platforms with normalized parsing:

### 1. AWS GuardDuty

Amazon's threat detection service for AWS environments.

**Supported Event Types:**
- Cryptocurrency mining
- Backdoor activity
- Trojan infections
- Unauthorized access
- Data exfiltration
- Reconnaissance
- Brute force attacks

**Example:**
```bash
python -m vaulytica.cli analyze guardduty_event.json --source guardduty
```

### 2. GCP Security Command Center

Google Cloud's security and risk management platform.

**Supported Event Types:**
- IAM privilege escalation
- Unauthorized API calls
- Data access anomalies
- Configuration violations
- Vulnerability findings

**Example:**
```bash
python -m vaulytica.cli analyze gcp_scc_event.json --source gcp-scc
```

### 3. Datadog Security Monitoring

Cloud-scale security monitoring and threat detection.

**Supported Event Types:**
- Application security events
- Infrastructure threats
- Data exfiltration
- Anomalous behavior
- Policy violations

**Example:**
```bash
python -m vaulytica.cli analyze datadog_event.json --source datadog
```

### 4. CrowdStrike Falcon

Endpoint detection and response (EDR) platform.

**Supported Event Types:**
- Malware detections
- Insider threats
- Lateral movement
- Privilege escalation
- Data collection

**Example:**
```bash
python -m vaulytica.cli analyze crowdstrike_event.json --source crowdstrike
```

### 5. Snowflake

Cloud data platform security and audit events.

**Supported Event Types:**
- Data exfiltration (large exports, unusual queries)
- Privilege escalation (role grants, admin access)
- Unauthorized access (suspicious logins, geographic anomalies)
- Query execution monitoring
- User activity tracking

**Example:**
```bash
python -m vaulytica.cli analyze snowflake_event.json --source snowflake
```

## Analysis Methodology

Vaulytica uses a comprehensive 10-phase analysis methodology powered by Claude AI:

### Phase 0: 5W1H Quick Summary

Rapid incident understanding framework for immediate context:

- **WHO**: Identifies all actors (attacker, victim, accounts, systems)
- **WHAT**: Describes attack type, actions taken, and impact
- **WHEN**: Provides timeline, duration, and temporal context
- **WHERE**: Lists affected systems, locations, and networks
- **WHY**: Assesses attacker motivation and objectives
- **HOW**: Explains techniques, tools, and methods used

This summary appears at the top of all reports for quick executive briefings.

### Phase 1: Event Classification

- Categorize event type (malware, unauthorized access, data exfiltration, etc.)
- Determine severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Identify primary security domain affected

### Phase 2: Technical Analysis

- Deep dive into technical indicators
- Network traffic analysis
- System behavior examination
- File and process analysis
- Authentication and authorization review

### Phase 3: Threat Intelligence Correlation

- Match against known APT groups
- Identify malware families
- Correlate with attack patterns
- Check threat intelligence databases
- Assess threat actor sophistication

### Phase 4: MITRE ATT&CK Mapping

- Map to ATT&CK tactics (Initial Access, Execution, Persistence, etc.)
- Identify specific techniques (T1078, T1190, T1567, etc.)
- Determine attack chain progression
- Assess coverage of kill chain

### Phase 5: Impact Assessment

- Evaluate business impact
- Assess data sensitivity
- Determine scope of compromise
- Calculate potential damage
- Identify affected assets

### Phase 6: Risk Scoring

- Calculate risk score (0.0-10.0)
- Factor in severity, impact, and exploitability
- Consider environmental context
- Assess urgency of response

### Phase 7: Root Cause Analysis

- Identify initial attack vector
- Determine security control failures
- Analyze contributing factors
- Assess detection gaps

### Phase 8: Remediation Recommendations

- Immediate containment actions
- Short-term mitigation steps
- Long-term security improvements
- Policy and process updates

### Phase 9: Investigation Queries

- Generate ready-to-run queries for:
  - SIEM systems (Splunk, Elastic)
  - Cloud platforms (AWS CloudTrail, GCP Logs)
  - EDR tools (CrowdStrike, Carbon Black)
  - Database audit logs (Snowflake, PostgreSQL)

### Confidence Scoring

Each analysis includes a confidence score (0-100%) based on:
- Data completeness
- Indicator strength
- Historical correlation quality
- Threat intelligence matches

## Output Formats

Vaulytica generates professional reports in three formats, each optimized for different use cases:

### JSON Output

Machine-readable format for automation and integration.

**Use Cases:**
- SOAR platform integration
- API consumption
- Data pipeline processing
- Custom tooling

**Structure:**
```json
{
  "event": {
    "event_id": "...",
    "source_system": "...",
    "severity": "HIGH",
    "category": "DATA_EXFILTRATION"
  },
  "analysis": {
    "five_w1h": {
      "who": "...",
      "what": "...",
      "when": "...",
      "where": "...",
      "why": "...",
      "how": "..."
    },
    "risk_score": 8.5,
    "confidence": 0.92,
    "executive_summary": "...",
    "mitre_attack": [...],
    "recommendations": [...],
    "investigation_queries": {...}
  }
}
```

### Markdown Output

Human-readable format for documentation and collaboration.

**Use Cases:**
- Incident reports
- Documentation
- Knowledge base articles
- Team collaboration (GitHub, Confluence)

**Features:**
- 5W1H summary table
- Formatted sections
- Code blocks for queries
- Easy to read and edit

### HTML Output

Professional presentation format for stakeholders.

**Use Cases:**
- Executive briefings
- Case management attachments
- Audit reports
- Client deliverables

**Features:**
- Modern gradient design
- Color-coded risk scores
- Responsive layout
- Print-friendly
- Embedded CSS (no external dependencies)

## SOAR Integration

Vaulytica integrates seamlessly with Security Orchestration, Automation and Response (SOAR) platforms.

### Integration Pattern

1. SOAR platform receives security alert
2. Webhook/action calls Vaulytica CLI with event JSON
3. Vaulytica analyzes event and generates reports
4. Reports are attached to case management ticket
5. Analyst reviews AI-generated analysis

### Current Capabilities

- CLI tool accepts JSON input from any source
- Generates comprehensive analysis reports
- Outputs in multiple formats (JSON, Markdown, HTML)
- Fast analysis (15-30 seconds, <100ms with cache)
- Batch processing for multiple events

### Tines Integration Example

```python
import subprocess
import json

# Tines action: Analyze security event
event_data = {
    "detail": {
        "severity": "HIGH",
        "type": "UnauthorizedAccess:EC2/SSHBruteForce",
        # ... event details
    }
}

# Save event to temp file
with open('/tmp/event.json', 'w') as f:
    json.dump(event_data, f)

# Run Vaulytica analysis
result = subprocess.run([
    'python', '-m', 'vaulytica.cli', 'analyze',
    '/tmp/event.json',
    '--source', 'guardduty',
    '--output-json', '/tmp/analysis.json',
    '--output-html', '/tmp/analysis.html'
], capture_output=True, text=True)

# Read analysis results
with open('/tmp/analysis.json', 'r') as f:
    analysis = json.load(f)

# Attach to case in Tines
# (Use Tines HTTP action to upload files)
```

### Datadog Workflows Integration Example

```yaml
name: Analyze Security Event with Vaulytica
trigger:
  - type: security_signal
    source: datadog

steps:
  - name: save_event
    action: core.writeFile
    params:
      path: /tmp/event.json
      content: "{{ trigger.event }}"

  - name: run_analysis
    action: core.executeCommand
    params:
      command: |
        python -m vaulytica.cli analyze /tmp/event.json \
          --source datadog \
          --output-json /tmp/analysis.json \
          --output-html /tmp/analysis.html

  - name: read_analysis
    action: core.readFile
    params:
      path: /tmp/analysis.json

  - name: create_case
    action: servicenow.createIncident
    params:
      short_description: "Security Event: {{ analysis.five_w1h.what }}"
      description: "{{ analysis.executive_summary }}"
      priority: "{{ analysis.risk_score > 7 ? 'high' : 'medium' }}"
      attachments:
        - /tmp/analysis.html
```

### Future Enhancements for Full Bidirectional Integration

To enable complete SOAR integration, future versions could include:

- REST API server mode
- Webhook receiver endpoints
- Native platform connectors (Tines, Splunk SOAR, Palo Alto XSOAR)
- Case management integrations (Jira, ServiceNow)
- Notification integrations (Slack, Microsoft Teams)
- Bi-directional data sync

## Configuration

### Environment Variables

All configuration options can be set via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Required | Claude API key for AI analysis |
| `VAULYTICA_MODEL_NAME` | `claude-3-haiku-20240307` | Claude model to use |
| `VAULYTICA_MAX_TOKENS` | `4000` | Maximum tokens per API request |
| `VAULYTICA_TEMPERATURE` | `0.0` | Model temperature (0.0-1.0, lower = more deterministic) |
| `VAULYTICA_ENABLE_RAG` | `true` | Enable historical incident correlation |
| `VAULYTICA_ENABLE_CACHE` | `true` | Enable analysis caching |
| `VAULYTICA_MAX_HISTORICAL_INCIDENTS` | `5` | Max similar incidents to retrieve |
| `VAULYTICA_OUTPUT_DIR` | `./outputs` | Output directory for reports |
| `VAULYTICA_CHROMA_DB_PATH` | `./chroma_db` | RAG database storage path |
| `VAULYTICA_BATCH_MAX_WORKERS` | `3` | Parallel workers for batch processing |

### Configuration File

Create a `.env` file in the project root:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-api03-...

# Optional - AI Model Settings
VAULYTICA_MODEL_NAME=claude-3-haiku-20240307
VAULYTICA_MAX_TOKENS=4000
VAULYTICA_TEMPERATURE=0.0

# Optional - Feature Flags
VAULYTICA_ENABLE_RAG=true
VAULYTICA_ENABLE_CACHE=true

# Optional - Performance Tuning
VAULYTICA_MAX_HISTORICAL_INCIDENTS=5
VAULYTICA_BATCH_MAX_WORKERS=3

# Optional - Storage Paths
VAULYTICA_OUTPUT_DIR=./outputs
VAULYTICA_CHROMA_DB_PATH=./chroma_db
```

### Command-Line Options

Override configuration for individual commands:

```bash
# Disable caching for fresh analysis
vaulytica analyze event.json --source guardduty --no-cache

# Disable RAG for faster processing
vaulytica analyze event.json --source guardduty --no-rag

# Specify custom API key
vaulytica analyze event.json --source guardduty --api-key sk-ant-...

# Custom output paths
vaulytica analyze event.json --source guardduty \
  --output-json /custom/path/analysis.json \
  --output-html /custom/path/report.html

# Enable debug logging
vaulytica --debug --log-file debug.log analyze event.json --source guardduty
```

## Batch Processing

Process multiple security events in parallel for high-volume environments.

### Basic Batch Processing

```bash
python -m vaulytica.cli batch /path/to/events \
  --source guardduty \
  --pattern "*.json" \
  --output-report batch_report.json
```

### Advanced Options

```bash
# Process specific file pattern
python -m vaulytica.cli batch test_data \
  --source guardduty \
  --pattern "guardduty_crypto*.json" \
  --output-report crypto_batch.json

# Disable caching for fresh analysis
python -m vaulytica.cli batch test_data \
  --source guardduty \
  --no-cache \
  --output-report fresh_batch.json
```

### Batch Report Structure

```json
{
  "summary": {
    "total_events": 10,
    "successful": 9,
    "failed": 1,
    "cache_hits": 3,
    "cache_misses": 6,
    "processing_time_seconds": 45.2
  },
  "results": [
    {
      "file": "event1.json",
      "status": "success",
      "risk_score": 8.5,
      "cached": false
    }
  ],
  "errors": [
    {
      "file": "event10.json",
      "error": "Parsing error: Invalid JSON"
    }
  ]
}
```

### Performance Tuning

Adjust parallel workers based on your system:

```bash
# High-performance system (8+ cores)
export VAULYTICA_BATCH_MAX_WORKERS=6

# Low-resource system (2-4 cores)
export VAULYTICA_BATCH_MAX_WORKERS=2
```

## Caching

Intelligent caching reduces API costs and improves response times.

### How Caching Works

1. Event is hashed using SHA256 of normalized content
2. Cache is checked for existing analysis
3. If found and not expired (24h TTL), cached result is returned
4. If not found, fresh analysis is performed and cached

### Cache Performance

- **Cache Hit**: <100ms response time, $0 API cost
- **Cache Miss**: 15-30s response time, ~$0.01 API cost
- **Hit Rate**: ~90% for repeated analyses

### Cache Management

```bash
# View cache statistics
python -m vaulytica.cli stats

# Clear all cache
python -m vaulytica.cli clear --clear-cache

# Clear only expired entries
python -m vaulytica.cli clear --clear-expired
```

### Cache Location

Default: `./.cache/vaulytica/`

Configure with: `VAULYTICA_CACHE_DIR=/custom/path`

## Test Data

Comprehensive synthetic test data covering various attack scenarios:

### AWS GuardDuty Events

- `guardduty_crypto_mining.json` - Cryptocurrency mining detection
- `guardduty_cryptojacking_advanced.json` - Advanced cryptojacking with obfuscation
- `guardduty_ransomware.json` - LockBit 3.0 ransomware infection with C2
- `guardduty_backdoor_c2.json` - Backdoor with command and control activity
- `guardduty_ssh_bruteforce.json` - SSH brute force attack

### GCP Security Command Center Events

- `gcp_scc_privilege_escalation.json` - IAM privilege escalation anomaly

### Datadog Security Events

- `datadog_data_exfiltration.json` - Large-scale data exfiltration to external S3

### CrowdStrike Falcon Events

- `crowdstrike_insider_threat.json` - Insider threat with USB data collection

### Snowflake Security Events

- `snowflake_data_exfiltration.json` - 5M row PII export by contractor
- `snowflake_privilege_escalation.json` - Service account granted ACCOUNTADMIN
- `snowflake_unauthorized_access.json` - Suspicious login from Russia without MFA

### Running Tests

Test individual parsers:

```bash
# Test Snowflake parser
python -m vaulytica.cli analyze test_data/snowflake_data_exfiltration.json \
  --source snowflake \
  --output-html outputs/test_snowflake.html

# Test all GuardDuty events
for file in test_data/guardduty*.json; do
  python -m vaulytica.cli analyze "$file" \
    --source guardduty \
    --output-html "outputs/$(basename $file .json).html"
done
```

Test batch processing:

```bash
# Process all test data
python -m vaulytica.cli batch test_data \
  --source guardduty \
  --pattern "guardduty*.json" \
  --output-report outputs/test_batch.json
```

## Troubleshooting

### API Key Issues

**Problem**: `Configuration error: ANTHROPIC_API_KEY is required`

**Solution**: Set the environment variable or use `--api-key` option

```bash
export ANTHROPIC_API_KEY="your-key-here"
# or
python -m vaulytica.cli analyze event.json --source guardduty --api-key "your-key-here"
```

### Model Not Available

**Problem**: `Error: model not found`

**Solution**: Verify your API key has access to the configured model. Try using a different model:

```bash
export VAULYTICA_MODEL_NAME="claude-3-sonnet-20240229"
```

### Parsing Errors

**Problem**: `Parsing error: Invalid structure`

**Solution**: Verify the input file matches the specified source format. Check the test data for examples:

```bash
# Validate JSON structure
cat event.json | jq .

# Compare with test data
diff event.json test_data/guardduty_crypto_mining.json
```

### ChromaDB Warnings

**Problem**: `NotOpenSSLWarning: urllib3 v2 only supports OpenSSL 1.1.1+`

**Solution**: This is a non-blocking warning. To suppress:

```bash
export TOKENIZERS_PARALLELISM=false
```

### Cache Issues

**Problem**: Stale cache entries or cache corruption

**Solution**: Clear the cache:

```bash
# Clear all cache
python -m vaulytica.cli clear --clear-cache

# Clear only expired entries
python -m vaulytica.cli clear --clear-expired
```

### Performance Issues

**Problem**: Slow analysis or high memory usage

**Solution**: Adjust configuration:

```bash
# Disable RAG for faster processing
python -m vaulytica.cli analyze event.json --source guardduty --no-rag

# Reduce batch workers
export VAULYTICA_BATCH_MAX_WORKERS=1

# Reduce historical incidents
export VAULYTICA_MAX_HISTORICAL_INCIDENTS=3
```

### File Not Found Errors

**Problem**: `Validation error: File not found`

**Solution**: Verify file path is correct and file exists:

```bash
# Check file exists
ls -la event.json

# Use absolute path
python -m vaulytica.cli analyze /full/path/to/event.json --source guardduty
```

### Permission Errors

**Problem**: `Permission denied` when writing outputs

**Solution**: Ensure output directory is writable:

```bash
# Create output directory
mkdir -p outputs

# Check permissions
ls -ld outputs

# Fix permissions if needed
chmod 755 outputs
```

## Development

### Project Structure

```
vaulytica/
├── agents/              # AI agent implementations
│   └── security_analyst.py
├── parsers/             # Data source parsers
│   ├── base.py
│   ├── guardduty.py
│   ├── gcp_scc.py
│   ├── datadog.py
│   ├── crowdstrike.py
│   └── snowflake.py
├── models.py            # Data models (SecurityEvent, AnalysisResult, FiveW1H)
├── rag.py              # RAG system with ChromaDB
├── cache.py            # Analysis caching layer
├── batch.py            # Batch processing engine
├── output.py           # Output formatters (JSON, Markdown)
├── html_report.py      # HTML report generator
├── config.py           # Configuration management
├── logger.py           # Production logging
├── validators.py       # Input validation and sanitization
└── cli.py              # Command-line interface
```

### Adding New Parsers

Create a new parser class inheriting from `BaseParser`:

```python
from vaulytica.parsers.base import BaseParser
from vaulytica.models import SecurityEvent, Severity, EventCategory

class MyCustomParser(BaseParser):
    def validate(self, raw_event: dict) -> bool:
        """Validate event structure."""
        return 'required_field' in raw_event

    def parse(self, raw_event: dict) -> SecurityEvent:
        """Parse to normalized SecurityEvent model."""
        return SecurityEvent(
            event_id=raw_event['id'],
            source_system="MySystem",
            timestamp=raw_event['timestamp'],
            severity=Severity.HIGH,
            category=EventCategory.UNAUTHORIZED_ACCESS,
            title=raw_event['title'],
            description=raw_event['description'],
            raw_event=raw_event
        )
```

Register the parser in `cli.py`:

```python
from vaulytica.parsers.mycustom import MyCustomParser

parser_map = {
    'guardduty': GuardDutyParser(),
    'mycustom': MyCustomParser(),
    # ...
}
```

Add test data in `test_data/mycustom_event.json` and test:

```bash
python -m vaulytica.cli analyze test_data/mycustom_event.json \
  --source mycustom \
  --output-html outputs/test.html
```

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run unit tests
pytest tests/

# Check code quality
flake8 vaulytica/
black vaulytica/
mypy vaulytica/
```

## Performance

### Analysis Speed

- **Single Event (Cache Miss)**: 15-30 seconds
- **Single Event (Cache Hit)**: <100ms
- **Batch Processing**: 10-20 events per minute with caching
- **RAG Query**: 200-500ms for historical correlation

### Resource Usage

- **Memory**: 200-500MB per analysis
- **Disk**: ~1MB per cached analysis
- **API Costs**: ~$0.01 per analysis (cache miss)

### Optimization Tips

1. **Enable Caching**: Reduces costs by 90% for repeated analyses
2. **Batch Processing**: Process multiple events in parallel
3. **Adjust Workers**: Tune `VAULYTICA_BATCH_MAX_WORKERS` for your system
4. **Disable RAG**: Use `--no-rag` for faster processing when historical context not needed
5. **Use Haiku Model**: Default model balances speed and quality

### Scalability

- **Single Instance**: 100-200 events per hour
- **Horizontal Scaling**: Deploy multiple instances with shared cache
- **High Volume**: Consider batch processing with increased workers

## Production Deployment

### Recommended Setup

```bash
# Production environment variables
export ANTHROPIC_API_KEY="sk-ant-..."
export VAULYTICA_MODEL_NAME="claude-3-haiku-20240307"
export VAULYTICA_ENABLE_RAG=true
export VAULYTICA_ENABLE_CACHE=true
export VAULYTICA_BATCH_MAX_WORKERS=4
export VAULYTICA_OUTPUT_DIR="/var/vaulytica/outputs"
export VAULYTICA_CHROMA_DB_PATH="/var/vaulytica/chroma_db"
export TOKENIZERS_PARALLELISM=false

# Create directories
mkdir -p /var/vaulytica/outputs
mkdir -p /var/vaulytica/chroma_db
mkdir -p /var/log/vaulytica

# Run with logging
python -m vaulytica.cli --log-file /var/log/vaulytica/app.log analyze event.json \
  --source guardduty \
  --output-html /var/vaulytica/outputs/analysis.html
```

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vaulytica/ ./vaulytica/

ENV ANTHROPIC_API_KEY=""
ENV VAULYTICA_OUTPUT_DIR="/data/outputs"
ENV VAULYTICA_CHROMA_DB_PATH="/data/chroma_db"

VOLUME ["/data"]

ENTRYPOINT ["python", "-m", "vaulytica.cli"]
```

Build and run:

```bash
docker build -t vaulytica:latest .

docker run -v $(pwd)/data:/data \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  vaulytica:latest analyze /data/event.json \
  --source guardduty \
  --output-html /data/analysis.html
```

### Monitoring

Key metrics to monitor:

- Analysis success rate
- Average processing time
- Cache hit rate
- API error rate
- Disk usage (cache and RAG database)
- Memory usage

### Security Considerations

1. **API Key Protection**: Never commit API keys to version control
2. **Input Validation**: All inputs are validated and sanitized
3. **File Permissions**: Ensure output directories have appropriate permissions
4. **Logging**: Sensitive data is not logged (API keys, PII)
5. **Network Security**: Consider running in isolated network segment

## Roadmap

Future enhancements under consideration:

- REST API server mode
- Native SOAR platform connectors
- Additional data source parsers (Splunk, Elastic, Azure Sentinel)
- Machine learning for anomaly detection
- Custom playbook support
- Multi-language support
- Real-time streaming analysis
- Advanced threat hunting capabilities