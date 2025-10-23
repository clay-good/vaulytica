# Vaulytica Production Guide

Version: 1.0.0
Last Updated: 2025-10-22

## Overview

Vaulytica is an enterprise-grade AI-powered Security Operations Center (SOC) platform with comprehensive security analysis, incident response, vulnerability management, and detection engineering capabilities.

## Architecture

### Core Components

1. **AI Agent Framework**
   - BaseAgent: Foundation for all agents
   - AgentOrchestrator: Multi-agent workflow coordination
   - AgentRegistry: Agent discovery and management

2. **Security Agents**
   - Security Analysis Agent: Threat detection and analysis
   - Incident Response Agent: Automated incident handling
   - Vulnerability Management Agent: Vulnerability analysis and remediation
   - Security Questionnaire Agent: Automated questionnaire completion
   - Brand Protection Agent: Domain monitoring and takedown
   - Detection Engineering Agent: Detection tuning and optimization

3. **Integrations**
   - Jira: Ticket management
   - PagerDuty: Incident alerting
   - Wiz: Cloud security scanning
   - Socket.dev: Supply chain security
   - GitLab/GitHub: Automated remediation
   - URLScan.io: URL analysis
   - WHOIS/RDAP: Domain intelligence

4. **Data Processing**
   - Document Ingestion: 6 file formats (PDF, DOCX, TXT, MD, CSV, XLSX)
   - RAG System: ChromaDB-based semantic search
   - Response Library: SQLite-based answer storage

## Installation

### Prerequisites

- Python 3.9+
- PostgreSQL 13+ (optional)
- Redis 6+ (optional)
- Docker (optional)

### Quick Start

```bash
# Clone repository
git clone https://example.com
cd vaulytica

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Run tests
python3 -m pytest tests/ -v

# Start API server
uvicorn vaulytica.web_api:app --reload
```

### Configuration

Create `.env` file with required credentials:

```bash
# AI/ML
ANTHROPIC_API_KEY=sk-ant-...

# Integrations
JIRA_URL=https://your-company.atlassian.net
JIRA_USERNAME=user@example.com
JIRA_API_TOKEN=your-token

PAGERDUTY_API_KEY=your-key
PAGERDUTY_INTEGRATION_KEY=your-integration-key

WIZ_CLIENT_ID=your-client-id
WIZ_CLIENT_SECRET=your-secret

SOCKETDEV_API_KEY=your-key

GITLAB_URL=https://gitlab.example.com
GITLAB_TOKEN=your-token

GITHUB_TOKEN=your-token

# Database
CHROMA_DB_PATH=./chroma_db
RESPONSE_LIBRARY_DB=./response_library.db
```

## Agent Usage

### Security Analysis Agent

```python
from vaulytica.agents import SecurityAnalysisAgent, AgentInput, AgentContext

agent = SecurityAnalysisAgent()

input_data = AgentInput(
    task="analyze_threat",
    context=AgentContext(
        incident_id="INC-001",
        workflow_id="WF-001"
    ),
    parameters={
        "ioc": "malicious-domain.com",
        "ioc_type": "domain"
    }
)

result = await agent.execute(input_data)
print(result.results)
```

### Incident Response Agent

```python
from vaulytica.agents import IncidentResponseAgent

agent = IncidentResponseAgent()

input_data = AgentInput(
    task="comprehensive_incident_response",
    context=AgentContext(
        incident_id="INC-001",
        data_sources={
            "logs": [...],
            "alerts": [...]
        }
    ),
    parameters={
        "incident_title": "Suspicious Login Activity",
        "severity": "high"
    }
)

result = await agent.execute(input_data)
```

### Vulnerability Management Agent

```python
from vaulytica.agents import VulnerabilityManagementAgent

agent = VulnerabilityManagementAgent()

input_data = AgentInput(
    task="comprehensive_vulnerability_management",
    context=AgentContext(
        incident_id="VULN-001",
        data_sources={
            "vulnerability": {
                "cve_id": "CVE-2024-1234",
                "package_name": "lodash",
                "package_version": "4.17.20"
            },
            "sbom": {
                "dependencies": [...]
            }
        }
    ),
    parameters={}
)

result = await agent.execute(input_data)
```

### Detection Engineering Agent

```python
from vaulytica.agents import DetectionEngineeringAgent

agent = DetectionEngineeringAgent()

# Analyze detection
input_data = AgentInput(
    task="analyze_detection",
    context=AgentContext(incident_id="DET-001"),
    parameters={
        "detection_id": "det-123",
        "timeframe_days": 30,
        "alerts": [...],
        "detection_rule": {
            "id": "det-123",
            "name": "Suspicious API Access",
            "platform": "datadog",
            "query": "source:api @http.status_code:401 | count() > 5"
        }
    }
)

result = await agent.execute(input_data)
```

## API Endpoints

### Health Check

```bash
GET /health
```

### Agent Execution

```bash
POST /api/v1/agents/{agent_id}/execute
Content-Type: application/json

{
  "task": "analyze_threat",
  "context": {
    "incident_id": "INC-001"
  },
  "parameters": {
    "ioc": "malicious-domain.com"
  }
}
```

### Document Upload

```bash
POST /api/v1/documents/upload
Content-Type: multipart/form-data

file: document.pdf
```

### Questionnaire Processing

```bash
POST /api/v1/questionnaires/process
Content-Type: application/json

{
  "questionnaire_file": "security_questionnaire.csv",
  "document_ids": ["doc-1", "doc-2"]
}
```

## Performance Optimization

### Caching

- ChromaDB for document embeddings
- Redis for API response caching
- In-memory caching for frequently accessed data

### Async Processing

All agents use async/await for non-blocking I/O:

```python
async def execute(self, input_data: AgentInput) -> AgentOutput:
    # Parallel API calls
    results = await asyncio.gather(
        self.api1.call(),
        self.api2.call(),
        self.api3.call()
    )
```

### Batch Processing

```python
from vaulytica.agents import SecurityQuestionnaireAgent

agent = SecurityQuestionnaireAgent()

result = await agent.execute(AgentInput(
    task="batch_process_questionnaires",
    context=context,
    parameters={
        "questionnaires": [
            {"file": "q1.csv", "documents": [...]},
            {"file": "q2.csv", "documents": [...]}
        ]
    }
))
```

## Monitoring

### Metrics

All agents track:
- Execution count
- Success/failure rates
- Average execution time
- Resource usage

```python
stats = agent.get_statistics()
print(stats)
# {
#   "executions": 1000,
#   "successes": 950,
#   "failures": 50,
#   "avg_execution_time": 2.5
# }
```

### Logging

Structured logging with correlation IDs:

```python
from vaulytica.logger import get_logger

logger = get_logger(__name__)
logger.info("Processing incident", extra={
    "incident_id": "INC-001",
    "workflow_id": "WF-001"
})
```

## Security

### Authentication

API endpoints support:
- API Key authentication
- JWT tokens
- OAuth2

### Rate Limiting

```python
from vaulytica.config import VaulyticaConfig

config = VaulyticaConfig(
    rate_limit_per_minute=60,
    rate_limit_per_hour=1000
)
```

### Data Encryption

- At-rest: AES-256 encryption for sensitive data
- In-transit: TLS 1.3 for all API communications

## Deployment

### Docker

```bash
# Build image
docker build -t vaulytica:latest .

# Run container
docker run -p 8000:8000 \
  -e ANTHROPIC_API_KEY=... \
  -e JIRA_URL=... \
  vaulytica:latest
```

### Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/

# Check status
kubectl get pods -n vaulytica
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Verify installation
   python3 -c "import vaulytica; print('OK')"
   ```

2. **API Key Issues**
   ```bash
   # Check environment variables
   env | grep API_KEY
   ```

3. **Database Connection**
   ```bash
   # Test ChromaDB
   python3 -c "from vaulytica.agents.document_intelligence import get_document_intelligence; di = get_document_intelligence(); print('OK')"
   ```

## Support

- Documentation: `/docs`
- Issues: GitHub Issues
- Email: support@vaulytica.com

