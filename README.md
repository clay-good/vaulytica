# Vaulytica

AI-powered security event analysis framework with Claude AI, RAG-based historical correlation, and multi-platform support.

## Features

- **AI Analysis**: Claude-powered 10-phase security analysis with MITRE ATT&CK mapping
- **Multi-Platform**: AWS GuardDuty, GCP SCC, Datadog, CrowdStrike, Snowflake
- **RAG System**: ChromaDB-based historical incident correlation
- **Caching**: 24h TTL cache with 90% cost reduction
- **Batch Processing**: Parallel analysis with configurable workers
- **REST API**: FastAPI server with webhook receivers
- **Notifications**: Real-time alerts via Slack, Teams, Email
- **Output Formats**: JSON, Markdown, HTML reports

## Installation

```bash
# Clone and install
git clone https://github.com/clay-good/vaulytica.git
cd vaulytica
pip install -r requirements.txt

# Set API key
export ANTHROPIC_API_KEY="sk-ant-api03-..."
```

## Quick Start

```bash
# Analyze single event
python -m vaulytica.cli analyze test_data/guardduty_crypto_mining.json \
  --source guardduty \
  --output-html outputs/report.html

# Batch processing
python -m vaulytica.cli batch test_data \
  --source guardduty \
  --pattern "*.json"

# Start API server
python -m vaulytica.cli serve --host 0.0.0.0 --port 8000
```

## CLI Commands

```bash
# Analysis
vaulytica analyze <file> --source <platform> [--output-json|markdown|html <path>]

# Batch processing
vaulytica batch <directory> --source <platform> [--pattern <glob>]

# API server
vaulytica serve [--host <host>] [--port <port>] [--workers <n>]

# Statistics
vaulytica stats

# Cache management
vaulytica cache [--clear-cache|--clear-expired]
```

## Configuration

Environment variables (prefix with `VAULYTICA_`):

```bash
ANTHROPIC_API_KEY=sk-ant-...              # Required
VAULYTICA_MODEL_NAME=claude-3-haiku-20240307
VAULYTICA_MAX_TOKENS=4000
VAULYTICA_TEMPERATURE=0.0
VAULYTICA_ENABLE_RAG=true
VAULYTICA_ENABLE_CACHE=true
VAULYTICA_MAX_HISTORICAL_INCIDENTS=5
VAULYTICA_BATCH_MAX_WORKERS=3
VAULYTICA_OUTPUT_DIR=./outputs
VAULYTICA_CHROMA_DB_PATH=./chroma_db
VAULYTICA_WEBHOOK_SECRET=your-secret

# Notifications
VAULYTICA_SLACK_WEBHOOK_URL=https://hooks.slack.com/...
VAULYTICA_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
VAULYTICA_SMTP_HOST=smtp.gmail.com
VAULYTICA_SMTP_FROM=alerts@example.com
VAULYTICA_SMTP_TO=security@example.com
VAULYTICA_MIN_RISK_SCORE_NOTIFY=5
```

## Python API

```python
import asyncio
from vaulytica.config import load_config
from vaulytica.parsers import GuardDutyParser
from vaulytica.agents import SecurityAnalystAgent
from vaulytica.rag import IncidentRAG
from vaulytica.cache import AnalysisCache

# Initialize
config = load_config()
parser = GuardDutyParser()
agent = SecurityAnalystAgent(config)
rag = IncidentRAG(config)
cache = AnalysisCache(config)

# Parse event
event = parser.parse(raw_event)

# Check cache
result = cache.get(event)
if not result:
    # Find similar incidents
    similar = rag.find_similar_incidents(event, max_results=5)
    
    # Analyze
    result = asyncio.run(agent.analyze([event], historical_context=similar))
    
    # Store
    cache.set(event, result)
    rag.store_incident(event, result)

print(f"Risk: {result.risk_score}/10, Confidence: {result.confidence*100}%")
```

## REST API

```bash
# Start server
python -m vaulytica.cli serve --port 8000

# Analyze event
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"source": "guardduty", "event": {...}}'

# Health check
curl http://localhost:8000/health

# Statistics
curl http://localhost:8000/stats

# Webhooks
POST /webhooks/guardduty    # AWS GuardDuty (SNS)
POST /webhooks/datadog      # Datadog (HMAC-SHA256)
POST /webhooks/crowdstrike  # CrowdStrike Falcon
```

## Notifications

Real-time alerts for high-risk security events:

```bash
# Configure Slack
export VAULYTICA_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export VAULYTICA_MIN_RISK_SCORE_NOTIFY=5

# Configure Microsoft Teams
export VAULYTICA_TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."

# Configure Email (SMTP)
export VAULYTICA_SMTP_HOST="smtp.gmail.com"
export VAULYTICA_SMTP_FROM="alerts@example.com"
export VAULYTICA_SMTP_TO="security@example.com"

# Test notifications
python examples/notification_test.py
```

**Features:**
- Automatic notifications for events above risk threshold
- Color-coded alerts (red ≥8, orange ≥6, yellow <6)
- Rich formatting with event details and MITRE ATT&CK techniques
- Background processing (non-blocking)
- Multiple channels simultaneously

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Input Layer                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │   CLI    │  │ REST API │  │ Webhooks │             │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘             │
└───────┼─────────────┼─────────────┼────────────────────┘
        │             │             │
        └─────────────┴─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │      Parser Layer          │
        │  (5 platform parsers)      │
        └─────────────┬─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │    Processing Layer        │
        │  ┌────────┐  ┌──────────┐ │
        │  │ Cache  │  │   RAG    │ │
        │  │ (24h)  │  │(ChromaDB)│ │
        │  └────────┘  └──────────┘ │
        │  ┌─────────────────────┐  │
        │  │   AI Agent (Claude) │  │
        │  └─────────────────────┘  │
        └─────────────┬─────────────┘
                      │
        ┌─────────────▼─────────────┐
        │     Output Layer           │
        │  JSON | Markdown | HTML    │
        └───────────────────────────┘
```

## System Design

**Data Flow:**
1. **Ingestion** → CLI/API/Webhook receives event
2. **Validation** → Parser validates and normalizes to SecurityEvent
3. **Cache Check** → SHA256 hash lookup (24h TTL)
4. **RAG Query** → Semantic search for similar incidents (ChromaDB)
5. **AI Analysis** → Claude API with 10-phase methodology
6. **Post-Processing** → Store in cache and RAG database
7. **Output** → Generate JSON/Markdown/HTML reports

**Key Components:**
- **Parsers**: Platform-specific event normalization (base class pattern)
- **Agent**: Claude AI with retry logic (exponential backoff)
- **RAG**: Vector embeddings for historical correlation
- **Cache**: File-based with TTL and SHA256 keys
- **Batch**: ThreadPoolExecutor for parallel processing

## File Structure

```
vaulytica/
├── vaulytica/
│   ├── agents/
│   │   ├── base.py              # Base agent interface
│   │   └── security_analyst.py  # Claude AI agent
│   ├── parsers/
│   │   ├── base.py              # Base parser interface
│   │   ├── guardduty.py         # AWS GuardDuty
│   │   ├── gcp_scc.py           # GCP Security Command Center
│   │   ├── datadog.py           # Datadog Security
│   │   ├── crowdstrike.py       # CrowdStrike Falcon
│   │   └── snowflake.py         # Snowflake
│   ├── api.py                   # FastAPI REST server
│   ├── webhooks.py              # Webhook receivers
│   ├── cli.py                   # Click CLI
│   ├── config.py                # Pydantic config
│   ├── models.py                # Data models
│   ├── rag.py                   # ChromaDB RAG
│   ├── cache.py                 # File-based cache
│   ├── batch.py                 # Batch processor
│   ├── output.py                # JSON/Markdown formatters
│   ├── html_report.py           # HTML generator
│   ├── logger.py                # Structured logging
│   └── validators.py            # Input validation
├── tests/                       # Pytest test suite
├── test_data/                   # Synthetic test events
├── examples/                    # Integration examples
├── requirements.txt             # Production deps
├── requirements-dev.txt         # Dev deps
├── setup.py                     # Package setup
└── pyproject.toml               # Project metadata
```

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=vaulytica --cov-report=html

# Specific test
pytest tests/test_parsers.py -v

# Test with real data
python -m vaulytica.cli analyze test_data/guardduty_crypto_mining.json \
  --source guardduty \
  --output-html outputs/test.html
```

## Performance

- **Analysis Time**: 15-30s (cache miss), <100ms (cache hit)
- **Cache Hit Rate**: ~90% for repeated events
- **Memory**: 200-500MB per analysis
- **API Cost**: ~$0.01 per analysis (Haiku model)
- **Batch Throughput**: 10-20 events/min with caching

## Production Deployment

**Docker:**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vaulytica/ ./vaulytica/
ENV ANTHROPIC_API_KEY=""
EXPOSE 8000
CMD ["python", "-m", "vaulytica.cli", "serve", "--host", "0.0.0.0"]
```

**Systemd:**
```ini
[Unit]
Description=Vaulytica API
After=network.target

[Service]
Type=simple
User=vaulytica
WorkingDirectory=/opt/vaulytica
Environment="ANTHROPIC_API_KEY=sk-ant-..."
ExecStart=/opt/vaulytica/venv/bin/python -m vaulytica.cli serve --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

## Development

```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .

# Code quality
black vaulytica/
flake8 vaulytica/
mypy vaulytica/

# Run tests
pytest -v
```

## Version

**Current**: 0.4.0
**Status**: Production Ready

## Requirements

- Python 3.9+
- Anthropic API key
- 2GB RAM (4GB recommended)
- 500MB disk (10GB+ for production)
