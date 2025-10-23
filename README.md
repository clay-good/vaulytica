# Vaulytica

Enterprise-grade AI-powered Security Operations Center (SOC) platform providing comprehensive security event analysis, incident response, threat intelligence, and automated security operations.

## Overview

Vaulytica is a production-ready security operations platform that combines artificial intelligence, machine learning, and security automation to provide world-class threat detection, incident response, and security analytics capabilities.

## Key Features

- AI-Powered Security Analysis with MITRE ATT&CK mapping
- Automated Incident Response with intelligent playbook execution
- Real-Time Threat Intelligence from multiple sources
- Advanced Machine Learning for threat detection and prediction
- Forensics and Investigation with chain of custody
- Streaming Analytics for real-time event processing
- Cloud Security (CSPM, container security, IAM analysis)
- Compliance and GRC automation
- Vulnerability Management with automated remediation
- Brand Protection and domain monitoring
- Detection Engineering with automated tuning

## Architecture

Vaulytica is built on a modular AI agent framework with the following components:

### Core Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      API Layer (FastAPI)                     │
│  REST API (255+ endpoints) | WebSocket | Python SDK          │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent Framework                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Security   │  │   Incident   │  │ Vulnerability│      │
│  │   Analysis   │  │   Response   │  │  Management  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Detection  │  │    Brand     │  │ Questionnaire│      │
│  │  Engineering │  │  Protection  │  │   Analysis   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Processing Layer                          │
│  ML Engine | Correlation | Streaming | Forensics | SOAR     │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                          │
│  Jira | PagerDuty | Datadog | Wiz | Socket.dev | GitLab     │
│  GitHub | VirusTotal | AlienVault | AbuseIPDB | Shodan      │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     Data Layer                               │
│  PostgreSQL | Redis | ChromaDB | RabbitMQ                    │
└─────────────────────────────────────────────────────────────┘
```

### AI Agent Framework

The platform uses a modular agent architecture where each agent specializes in specific security tasks:

- **BaseAgent**: Foundation class with async/await, caching, and error handling
- **AgentContext**: Shared context across all agents with incident data, IOCs, and findings
- **AgentOrchestrator**: Coordinates multi-agent workflows and task distribution
- **Document Intelligence**: RAG-based semantic search using ChromaDB

## AI Agents

### Security Analysis Agent
- 12-phase AI analysis framework with Claude integration
- MITRE ATT&CK technique mapping and threat actor attribution
- Multi-platform support: AWS GuardDuty, GCP SCC, Datadog, CrowdStrike, Snowflake
- IOC extraction and enrichment with reputation scoring
- Behavioral analysis with 8 attack signatures

### Incident Response Agent
- Complete incident lifecycle management
- Alert deduplication (40-70% reduction)
- SLA tracking and automated escalation
- Integration with Jira, ServiceNow, PagerDuty
- Automated playbook execution with approval workflows

### Vulnerability Management Agent
- CVE database integration with CVSS scoring
- Automated vulnerability scanning and prioritization
- Remediation tracking with GitLab/GitHub integration
- Automated MR/PR creation for fixes
- Risk-based vulnerability prioritization

### Detection Engineering Agent
- Automated detection tuning and optimization
- False positive pattern recognition
- A/B testing for detection changes
- Multi-SIEM support: Datadog, Splunk, Elastic, Sentinel, Chronicle
- Detection gap analysis from undetected incidents

### Brand Protection Agent
- Domain permutation generation (7 techniques)
- Malicious intent validation with AI
- Automated cease and desist letter generation
- Takedown tracking and monitoring
- Integration with URLScan.io and WHOIS

### Security Questionnaire Agent
- Automated security questionnaire completion
- Document ingestion (PDF, DOCX, TXT, MD, HTML, CSV)
- RAG-based semantic search with ChromaDB
- Response library with version control
- Batch processing support

## File Structure

```
vaulytica/
├── vaulytica/                  # Core platform code
│   ├── agents/                 # AI agent implementations
│   │   ├── framework.py        # Base agent framework
│   │   ├── security_analyst.py # Security analysis agent
│   │   ├── incident_response.py # Incident response agent
│   │   ├── vulnerability_management.py # Vuln management
│   │   ├── detection_engineering.py # Detection tuning
│   │   ├── brand_protection.py # Brand protection
│   │   └── security_questionnaire.py # Questionnaire agent
│   ├── parsers/                # Event parsers
│   │   ├── guardduty.py        # AWS GuardDuty
│   │   ├── gcp_scc.py          # GCP Security Command Center
│   │   ├── datadog.py          # Datadog Security
│   │   ├── crowdstrike.py      # CrowdStrike EDR
│   │   └── snowflake.py        # Snowflake Security
│   ├── integrations/           # External integrations
│   │   ├── jira_integration.py # Jira ticketing
│   │   ├── pagerduty_integration.py # PagerDuty alerting
│   │   ├── wiz_integration.py  # Wiz cloud security
│   │   ├── socketdev_integration.py # Socket.dev supply chain
│   │   ├── gitlab_integration.py # GitLab automation
│   │   └── github_integration.py # GitHub automation
│   ├── api.py                  # FastAPI REST API (255+ endpoints)
│   ├── ml_engine.py            # Machine learning engine
│   ├── correlation.py          # Event correlation
│   ├── streaming.py            # Real-time streaming analytics
│   ├── forensics.py            # Forensics and investigation
│   ├── playbooks.py            # Automated response playbooks
│   ├── threat_feeds.py         # Threat intelligence feeds
│   ├── rag.py                  # RAG document intelligence
│   ├── cspm.py                 # Cloud security posture
│   ├── container_security.py   # Container security
│   ├── iam_security.py         # IAM security analysis
│   ├── vulnerability_management.py # Vulnerability management
│   └── visualizations.py       # Data visualizations
├── tests/                      # Test suites
├── docs/                       # Documentation
│   ├── agents/                 # Agent documentation
│   ├── integrations/           # Integration guides
│   └── README.md               # Documentation index
├── examples/                   # Example scripts
├── config/                     # Configuration files
├── kubernetes/                 # Kubernetes manifests
├── docker-compose.yml          # Docker Compose setup
├── Dockerfile                  # Docker image
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## Core Capabilities

### Security Event Analysis
- Multi-platform event parsing and normalization
- 12-phase AI analysis with MITRE ATT&CK mapping
- Behavioral analysis with 8 attack signatures
- Threat actor attribution with confidence scoring
- IOC extraction and enrichment

### Machine Learning
- Anomaly detection using Isolation Forest (7 anomaly types)
- Threat prediction using Random Forest (8 attack types)
- LSTM and Transformer models for sequence analysis
- AutoML for hyperparameter optimization
- Model ensembles with explainability

### Automated Response
- 15 response actions (isolate host, block IP, disable user, etc.)
- 5 built-in playbooks (ransomware, data exfiltration, cryptomining, etc.)
- Multi-level approval workflows
- Dry-run mode and rollback capabilities
- Comprehensive audit logging

### Forensics and Investigation
- 15 evidence types from 6 sources
- Cryptographic chain of custody
- Pattern detection and IOC extraction
- Investigation templates
- Legal compliance reporting

### Streaming Analytics
- Real-time event processing (1,000+ events/sec)
- Complex Event Processing (CEP)
- Temporal, asset, IOC, and behavioral correlation
- Event replay and time travel
- Backpressure handling

### Cloud Security
- Multi-cloud CSPM (AWS, Azure, GCP)
- Compliance frameworks (CIS, PCI-DSS, HIPAA, SOC2, NIST)
- Container security with image scanning
- Kubernetes security benchmarks
- IAM security and privilege analysis

### Threat Intelligence
- 6 threat feed sources (VirusTotal, AlienVault OTX, AbuseIPDB, Shodan, URLhaus, ThreatFox)
- Multi-source aggregation with consensus voting
- Smart caching (4-5x speedup)
- Batch enrichment support

## Integrations

### Ticketing and Alerting
- Jira - Issue tracking with custom field mapping
- ServiceNow - Incident management with bidirectional sync
- PagerDuty - Alerting and on-call management
- Datadog - Case management integration

### Cloud Security
- Wiz - Cloud security posture management
- AWS GuardDuty - Threat detection
- GCP Security Command Center - Cloud security
- Azure Security Center - Cloud security

### Security Tools
- CrowdStrike - EDR integration
- Datadog - Security monitoring
- Snowflake - Data warehouse security
- Socket.dev - Supply chain security

### Development Platforms
- GitLab - Automated MR creation for remediation
- GitHub - Automated PR creation for remediation

### Threat Intelligence
- VirusTotal - File/URL/IP/domain reputation
- AlienVault OTX - Open threat exchange
- AbuseIPDB - IP reputation and abuse reports
- Shodan - Internet-wide scanning data
- URLhaus - Malicious URL database
- ThreatFox - IOC database

### Domain Intelligence
- URLScan.io - URL analysis and screenshots
- WHOIS/RDAP - Domain registration data

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/clay-good/vaulytica.git
cd vaulytica

# Install dependencies
pip install -r requirements.txt

# Set up configuration
export VAULYTICA_ENV=development
export ANTHROPIC_API_KEY=your-api-key

# Run the API server
python -m vaulytica.api
```

### Docker Deployment

```bash
# Build the image
docker build -t vaulytica:latest .

# Run with Docker Compose
docker-compose up -d
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f kubernetes/

# Check deployment status
kubectl get pods -n vaulytica
```

## Configuration

Configuration is managed through YAML files in the `config/` directory:

- `development.yaml` - Development environment
- `staging.yaml` - Staging environment
- `production.yaml` - Production environment

### Environment Variables

```bash
# Core Configuration
export VAULYTICA_ENV=production
export VAULYTICA_API_KEY=your-api-key
export ANTHROPIC_API_KEY=your-claude-api-key

# Database
export VAULYTICA_DB_URL=postgresql://user:pass@host:5432/vaulytica

# Redis Cache
export REDIS_URL=redis://localhost:6379/0

# Integrations
export JIRA_URL=https://your-company.atlassian.net
export JIRA_USERNAME=user@example.com
export JIRA_API_TOKEN=your-token

export PAGERDUTY_API_KEY=your-key
export DATADOG_API_KEY=your-key
export VIRUSTOTAL_API_KEY=your-key
```

## API

### REST API
- 255+ endpoints across all features
- OpenAPI/Swagger documentation at `/docs`
- Rate limiting and authentication
- CORS support with security headers

### WebSocket API
- Real-time event streaming
- Live collaboration updates
- Streaming analytics data

### Example Usage

```python
from vaulytica.api_client import VaulyticaClient

# Initialize client
client = VaulyticaClient(api_key="your-api-key")

# Analyze security event
result = await client.analyze_event({
    "source": "guardduty",
    "event_data": {...}
})

# Create incident
incident = await client.create_incident({
    "title": "Suspicious Activity Detected",
    "severity": "high",
    "description": "..."
})
```

## System Requirements

### Minimum Requirements
- Python 3.9+
- 4 CPU cores
- 8GB RAM
- 50GB disk space
- PostgreSQL 13+ or SQLite
- Redis 6+

### Recommended for Production
- Python 3.11+
- 16 CPU cores
- 32GB RAM
- 200GB SSD storage
- PostgreSQL 15+
- Redis 7+
- RabbitMQ 3.8+

## Performance

- Event Processing: <100ms latency
- Threat Prediction: <150ms per event
- Anomaly Detection: <100ms per event
- Streaming Throughput: 1,000+ events/sec
- API Response Time: <200ms (p95)
- Agent Execution: 1-3s average

## Security

- Bcrypt/Argon2 password hashing
- Secrets management (Vault, AWS Secrets Manager, Azure Key Vault)
- TLS/SSL encryption
- Rate limiting and DDoS protection
- RBAC (Role-Based Access Control)
- Multi-tenancy with data isolation
- Security headers (CSP, HSTS, X-Frame-Options)
- Input validation and sanitization

## Monitoring

- Prometheus metrics export
- Grafana dashboards
- OpenTelemetry distributed tracing
- Structured logging with correlation IDs
- Health check endpoints at `/health`
- Performance profiling

## Testing

```bash
# Run all tests
pytest tests/

# Run specific test suite
pytest tests/test_security_analyst.py

# Run with coverage
pytest --cov=vaulytica tests/
```

Test Coverage:
- 30+ test suites
- Unit tests, integration tests, end-to-end tests
- Performance and load tests
- Security penetration tests

## Documentation

Documentation is available in the `docs/` directory:

- `docs/agents/` - AI agent documentation
- `docs/integrations/` - Integration guides
- `docs/README.md` - Documentation index

Additional documentation:
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [DEPLOYMENT.md](DEPLOYMENT.md) - Deployment guide
- [PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md) - Production setup
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [ROADMAP.md](ROADMAP.md) - Future plans

## Version

Current Version: 0.30.0

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## License

See [LICENSE](LICENSE) for licensing information.

## Repository

https://github.com/clay-good/vaulytica

