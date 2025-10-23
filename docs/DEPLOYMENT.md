# Vaulytica Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying Vaulytica in development, staging, and production environments.

## Prerequisites

### System Requirements

**Minimum Requirements (Development)**
- Operating System: Linux (Ubuntu 20.04+), macOS 11+, or Windows 10+ with WSL2
- Python: 3.9 or higher
- CPU: 2 cores
- Memory: 4GB RAM
- Storage: 10GB free disk space

**Recommended Requirements (Production)**
- Operating System: Linux (Ubuntu 20.04+ or RHEL 8+)
- Python: 3.9 or higher
- CPU: 16+ cores
- Memory: 32GB+ RAM
- Storage: 100GB+ SSD
- Network: High-bandwidth, low-latency connection

### Required Software

```bash
# Python 3.9+
python3 --version

# pip (Python package manager)
pip3 --version

# Git
git --version

# Docker (optional, for containerized deployment)
docker --version

# Kubernetes (optional, for orchestrated deployment)
kubectl version
```

### External Dependencies

**Required**
- PostgreSQL 13+ (or SQLite for development)
- Redis 6+ (for caching and message queues)

**Optional**
- RabbitMQ 3.8+ (for async task processing)
- Elasticsearch 7+ (for log aggregation)
- Prometheus + Grafana (for monitoring)

## Installation

### Method 1: Standard Installation

1. Clone the repository:
```bash
git clone https://example.com
cd vaulytica
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
# Production dependencies
pip install -r requirements.txt

# Development dependencies (optional)
pip install -r requirements-dev.txt
```

4. Set up the database:
```bash
# PostgreSQL
createdb vaulytica
python scripts/init_db.py

# SQLite (development only)
python scripts/init_db.py --sqlite
```

### Method 2: Docker Installation

1. Build the Docker image:
```bash
docker build -t vaulytica:latest .
```

2. Run with Docker Compose:
```bash
docker-compose up -d
```

This will start:
- Vaulytica application
- PostgreSQL database
- Redis cache
- Prometheus monitoring
- Grafana dashboards

### Method 3: Kubernetes Installation

1. Create namespace:
```bash
kubectl create namespace vaulytica
```

2. Apply configurations:
```bash
kubectl apply -f kubernetes/
```

3. Verify deployment:
```bash
kubectl get pods -n vaulytica
kubectl get services -n vaulytica
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Application
VAULYTICA_ENV=production
VAULYTICA_DEBUG=false
VAULYTICA_LOG_LEVEL=INFO

# API
VAULYTICA_API_HOST=0.0.0.0
VAULYTICA_API_PORT=8000
VAULYTICA_API_KEY=your-secure-api-key

# Database
VAULYTICA_DB_URL=postgresql://user:password@localhost:5432/vaulytica
VAULYTICA_DB_POOL_SIZE=20
VAULYTICA_DB_MAX_OVERFLOW=10

# Redis
VAULYTICA_REDIS_URL=redis://localhost:6379/0
VAULYTICA_REDIS_PASSWORD=your-redis-password

# AI/ML
ANTHROPIC_API_KEY=your-anthropic-api-key

# Threat Intelligence
VIRUSTOTAL_API_KEY=your-virustotal-api-key
ALIENVAULT_API_KEY=your-alienvault-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
SHODAN_API_KEY=your-shodan-api-key

# Ticketing
JIRA_URL=https://your-company.atlassian.net
JIRA_USERNAME=your-username
JIRA_API_TOKEN=your-api-token

SERVICENOW_INSTANCE=your-instance
SERVICENOW_USERNAME=your-username
SERVICENOW_PASSWORD=your-password

PAGERDUTY_API_KEY=your-pagerduty-api-key

# Monitoring
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
GRAFANA_ENABLED=true
GRAFANA_PORT=3000
```

### Configuration Files

Configuration is managed through YAML files in the `config/` directory:

**config/development.yaml**
```yaml
environment: development
debug: true
log_level: DEBUG

database:
 url: sqlite:///vaulytica.db
 pool_size: 5

cache:
 enabled: false

api:
 host: 127.0.0.1
 port: 8000
 cors_origins:
 - https://example.com:3000
```

**config/production.yaml**
```yaml
environment: production
debug: false
log_level: INFO

database:
 url: ${VAULYTICA_DB_URL}
 pool_size: 20
 max_overflow: 10

cache:
 enabled: true
 redis_url: ${VAULYTICA_REDIS_URL}
 ttl: 3600

api:
 host: 0.0.0.0
 port: 8000
 cors_origins:
 - https://example.com

security:
 api_key_required: true
 rate_limit_enabled: true
 rate_limit_requests: 100
 rate_limit_period: 60

monitoring:
 prometheus_enabled: true
 tracing_enabled: true
 log_aggregation_enabled: true
```

## Running the Application

### Development Mode

```bash
# Activate virtual environment
source venv/bin/activate

# Run with auto-reload
python -m vaulytica.main --reload

# Or use uvicorn directly
uvicorn vaulytica.main:app --reload --host 127.0.0.1 --port 8000
```

### Production Mode

```bash
# Using gunicorn with uvicorn workers
gunicorn vaulytica.main:app \
 --workers 4 \
 --worker-class uvicorn.workers.UvicornWorker \
 --bind 0.0.0.0:8000 \
 --timeout 120 \
 --access-logfile - \
 --error-logfile -

# Or using systemd service
sudo systemctl start vaulytica
sudo systemctl enable vaulytica
```

### Docker Mode

```bash
# Run single container
docker run -d \
 --name vaulytica \
 -p 8000:8000 \
 -e VAULYTICA_ENV=production \
 -e VAULYTICA_DB_URL=postgresql://... \
 vaulytica:latest

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f vaulytica
```

### Kubernetes Mode

```bash
# Deploy
kubectl apply -f kubernetes/

# Scale deployment
kubectl scale deployment vaulytica --replicas=5 -n vaulytica

# View logs
kubectl logs -f deployment/vaulytica -n vaulytica

# Port forward for testing
kubectl port-forward service/vaulytica 8000:8000 -n vaulytica
```

## Health Checks

### Endpoints

```bash
# Health check
curl https://example.com:8000/health

# Readiness check
curl https://example.com:8000/ready

# Metrics
curl https://example.com:8000/metrics
```

### Expected Responses

**Healthy**
```json
{
 "status": "healthy",
 "version": "0.30.0",
 "uptime": 3600,
 "database": "connected",
 "cache": "connected"
}
```

## Monitoring

### Prometheus Metrics

Access Prometheus at `https://example.com:9090`

Key metrics:
- `vaulytica_requests_total`: Total API requests
- `vaulytica_request_duration_seconds`: Request latency
- `vaulytica_events_processed_total`: Events processed
- `vaulytica_ml_predictions_total`: ML predictions made
- `vaulytica_errors_total`: Total errors

### Grafana Dashboards

Access Grafana at `https://example.com:3000`

Default credentials:
- Username: admin
- Password: admin (change on first login)

Pre-configured dashboards:
- System Overview
- API Performance
- Event Processing
- ML Model Performance
- Security Incidents

### Logging

Logs are written to:
- Console (stdout/stderr)
- File: `/var/log/vaulytica/app.log`
- Syslog (if configured)

Log format:
```json
{
 "timestamp": "2025-10-21T10:30:00Z",
 "level": "INFO",
 "logger": "vaulytica.agents.security_analyst",
 "message": "Event analyzed successfully",
 "correlation_id": "abc123",
 "event_id": "evt_456",
 "duration_ms": 150
}
```

## Security

### TLS/SSL Configuration

```bash
# Generate self-signed certificate (development only)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run with TLS
uvicorn vaulytica.main:app \
 --ssl-keyfile=key.pem \
 --ssl-certfile=cert.pem \
 --host 0.0.0.0 \
 --port 8443
```

### Secrets Management

Use environment variables or external secrets managers:

```bash
# Vault
export VAULT_ADDR=https://example.com
export VAULT_TOKEN=your-token

# AWS Secrets Manager
export AWS_REGION=us-east-1
export AWS_SECRET_NAME=vaulytica/production

# Azure Key Vault
export AZURE_KEY_VAULT_NAME=vaulytica-vault

# GCP Secret Manager
export GCP_PROJECT_ID=your-project
export GCP_SECRET_NAME=vaulytica-secrets
```

### Firewall Rules

```bash
# Allow API access
sudo ufw allow 8000/tcp

# Allow HTTPS
sudo ufw allow 443/tcp

# Allow Prometheus
sudo ufw allow 9090/tcp

# Allow Grafana
sudo ufw allow 3000/tcp
```

## Scaling

### Horizontal Scaling

**Docker Compose**
```bash
docker-compose up -d --scale vaulytica=5
```

**Kubernetes**
```bash
kubectl scale deployment vaulytica --replicas=10 -n vaulytica
```

### Autoscaling

**Kubernetes HPA (Horizontal Pod Autoscaler)**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
 name: vaulytica-hpa
spec:
 scaleTargetRef:
 apiVersion: apps/v1
 kind: Deployment
 name: vaulytica
 minReplicas: 3
 maxReplicas: 20
 metrics:
 - type: Resource
 resource:
 name: cpu
 target:
 type: Utilization
 averageUtilization: 70
 - type: Resource
 resource:
 name: memory
 target:
 type: Utilization
 averageUtilization: 80
```

## Backup and Recovery

### Database Backup

```bash
# PostgreSQL backup
pg_dump vaulytica > backup_$(date +%Y%m%d).sql

# Automated daily backups
0 2 * * * pg_dump vaulytica | gzip > /backups/vaulytica_$(date +\%Y\%m\%d).sql.gz
```

### Restore

```bash
# PostgreSQL restore
psql vaulytica < backup_20251021.sql
```

## Troubleshooting

See the troubleshooting guide in `docs/operations/troubleshooting.md` for common issues and solutions.

## Support

For issues or questions:
- GitHub Issues: https://example.com
- Documentation: https://docs.vaulytica.com
- Community: https://community.vaulytica.com

