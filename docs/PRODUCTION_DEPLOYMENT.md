# Vaulytica Production Deployment Guide

This guide covers deploying Vaulytica in a production environment with best practices for security, reliability, and performance.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Infrastructure Requirements](#infrastructure-requirements)
3. [Deployment Options](#deployment-options)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [Database Setup](#database-setup)
7. [Security Configuration](#security-configuration)
8. [Monitoring and Logging](#monitoring-and-logging)
9. [Backup and Recovery](#backup-and-recovery)
10. [Scaling Considerations](#scaling-considerations)
11. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Google Workspace Requirements

1. **Super Admin Access**: Required for initial OAuth setup
2. **API Scopes**: Enable the following APIs in Google Cloud Console:
   - Admin SDK API
   - Drive API
   - Gmail API (if scanning emails)
   - Calendar API (if scanning calendars)
   - Google Vault API (if using Vault features)

3. **Service Account**: Create a service account with domain-wide delegation
   - Enable "Enable G Suite Domain-wide Delegation"
   - Download the JSON credentials file
   - Add required scopes in Admin Console > Security > API Controls

### Required OAuth Scopes

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/calendar.readonly
https://www.googleapis.com/auth/ediscovery.readonly
```

---

## Infrastructure Requirements

### Minimum Production Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Storage | 50 GB SSD | 100+ GB SSD |
| Database | PostgreSQL 13+ | PostgreSQL 15+ |

### Network Requirements

- Outbound HTTPS (443) to Google APIs
- Internal network access to PostgreSQL
- Port 8000 for backend API
- Port 3000 for frontend (if using web UI)

---

## Deployment Options

### Option 1: Docker Compose (Recommended for Small Deployments)

Best for: Organizations with < 1000 users, single-server deployments.

### Option 2: Kubernetes (Recommended for Large Deployments)

Best for: Organizations with > 1000 users, high-availability requirements.

### Option 3: CLI-Only Deployment

Best for: Scheduled scans without web UI, integration with existing tools.

---

## Docker Deployment

### Step 1: Configure Environment

Create a `.env` file in the project root:

```bash
# Database Configuration
POSTGRES_PASSWORD=<generate-secure-password>
DATABASE_URL=postgresql://vaulytica:${POSTGRES_PASSWORD}@postgres:5432/vaulytica

# Security
SECRET_KEY=<generate-secure-random-string>

# Optional: Scan Runner Configuration
SCAN_CHECK_INTERVAL=60
```

Generate secure passwords:
```bash
# Generate random password
openssl rand -base64 32

# Generate secret key
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### Step 2: Prepare Credentials

1. Place your Google service account JSON file in `./credentials/service-account.json`
2. Set appropriate permissions:
   ```bash
   chmod 600 ./credentials/service-account.json
   ```

### Step 3: Build and Deploy

```bash
# Build images
docker compose build

# Start services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f
```

### Step 4: Initialize Database

The database will be automatically initialized on first run. To manually run migrations:

```bash
docker compose exec backend alembic upgrade head
```

### Step 5: Create Admin User

```bash
docker compose exec backend python -c "
from app.services.user_service import UserService
from app.database import get_db
db = next(get_db())
user_service = UserService(db)
user_service.create_admin_user('admin@example.com', 'secure-password')
"
```

### Health Checks

The deployment includes health checks for all services:
- Backend: `http://localhost:8000/health`
- Frontend: `http://localhost:3000`
- PostgreSQL: Internal health check via `pg_isready`

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- Helm 3.x (optional)

### Namespace Setup

```bash
kubectl create namespace vaulytica
```

### Secrets Configuration

```bash
# Create database secret
kubectl create secret generic vaulytica-db \
  --namespace vaulytica \
  --from-literal=password='<your-password>'

# Create application secrets
kubectl create secret generic vaulytica-secrets \
  --namespace vaulytica \
  --from-literal=secret-key='<your-secret-key>'

# Create Google credentials secret
kubectl create secret generic vaulytica-google \
  --namespace vaulytica \
  --from-file=service-account.json=./credentials/service-account.json
```

### Sample Kubernetes Manifests

See `./k8s/` directory for complete manifests:
- `deployment.yaml` - Application deployments
- `service.yaml` - Service definitions
- `configmap.yaml` - Configuration
- `ingress.yaml` - Ingress rules
- `pvc.yaml` - Persistent volume claims

---

## Database Setup

### PostgreSQL Configuration

For production, use these recommended settings in `postgresql.conf`:

```ini
# Memory
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 64MB
maintenance_work_mem = 512MB

# Connections
max_connections = 100

# Write-ahead log
wal_level = replica
max_wal_senders = 3
wal_keep_size = 1GB

# Logging
log_statement = 'ddl'
log_min_duration_statement = 1000
```

### Database Backup

Using pg_dump:
```bash
# Daily backup
pg_dump -U vaulytica -F c vaulytica > backup_$(date +%Y%m%d).dump

# Restore
pg_restore -U vaulytica -d vaulytica backup_20240101.dump
```

Using Docker:
```bash
docker compose exec postgres pg_dump -U vaulytica vaulytica > backup.sql
```

---

## Security Configuration

### 1. TLS/SSL Setup

Always use TLS in production. Configure with a reverse proxy:

**nginx configuration:**
```nginx
server {
    listen 443 ssl http2;
    server_name vaulytica.example.com;

    ssl_certificate /etc/ssl/certs/vaulytica.crt;
    ssl_certificate_key /etc/ssl/private/vaulytica.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 2. Credential Security

- Store credentials in a secrets manager (HashiCorp Vault, AWS Secrets Manager, etc.)
- Rotate service account keys regularly (every 90 days)
- Use short-lived tokens where possible

### 3. Network Security

- Deploy behind a firewall
- Use private networks for database connections
- Enable audit logging for all database access

### 4. Application Security

Configure CORS in the backend:
```python
CORS_ORIGINS = [
    "https://vaulytica.example.com"  # Only your domain
]
```

---

## Monitoring and Logging

### Prometheus Metrics

Vaulytica exposes Prometheus metrics at `/metrics`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'vaulytica'
    static_configs:
      - targets: ['vaulytica-backend:8000']
```

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `scan_duration_seconds` | Time for scan completion | > 1 hour |
| `findings_total` | Total findings count | Sudden increase |
| `api_request_duration_seconds` | API response time | > 5 seconds |
| `database_connections_active` | Active DB connections | > 80% of max |

### Log Aggregation

Vaulytica uses structured logging (JSON format). Integrate with:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Grafana Loki
- Datadog
- Splunk

Example log configuration:
```yaml
# docker-compose.yml
services:
  backend:
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

---

## Backup and Recovery

### Backup Strategy

1. **Database**: Daily full backups, hourly incremental
2. **Configuration**: Version control all config files
3. **Credentials**: Secure backup in secrets manager

### Disaster Recovery Plan

1. **RTO (Recovery Time Objective)**: < 4 hours
2. **RPO (Recovery Point Objective)**: < 1 hour

### Recovery Steps

1. Deploy fresh infrastructure
2. Restore database from backup
3. Deploy application containers
4. Restore credentials
5. Verify connectivity to Google APIs
6. Run validation scan

---

## Scaling Considerations

### Horizontal Scaling

For large deployments, scale the scan-runner service:

```yaml
# docker-compose.yml
services:
  scan-runner:
    deploy:
      replicas: 3
```

### Database Scaling

For > 10,000 users:
- Use PostgreSQL read replicas
- Enable connection pooling (PgBouncer)
- Consider partitioning large tables

### Rate Limiting

Google APIs have rate limits. Configure appropriate throttling:

```yaml
# config/config.yaml
rate_limits:
  drive_api: 100  # requests per second
  admin_api: 50
  gmail_api: 25
```

---

## Troubleshooting

### Common Issues

#### 1. Authentication Errors

```
Error: 401 Unauthorized - Invalid credentials
```

**Solution:**
- Verify service account JSON is valid
- Check domain-wide delegation is enabled
- Verify required scopes are authorized in Admin Console

#### 2. Rate Limit Exceeded

```
Error: 429 Too Many Requests
```

**Solution:**
- Reduce concurrent scan workers
- Increase delay between API calls
- Enable exponential backoff (already enabled by default)

#### 3. Database Connection Errors

```
Error: Connection refused to database
```

**Solution:**
- Verify PostgreSQL is running
- Check DATABASE_URL is correct
- Verify network connectivity

#### 4. Memory Issues

```
Error: Container killed - Out of memory
```

**Solution:**
- Increase container memory limits
- Enable scan chunking for large files
- Reduce concurrent processing

### Getting Help

1. Check logs: `docker compose logs -f`
2. Enable debug mode: Set `DEBUG=true` in environment
3. Check GitHub issues: https://github.com/your-org/vaulytica/issues

---

## Maintenance

### Regular Tasks

| Task | Frequency | Command |
|------|-----------|---------|
| Database vacuum | Weekly | `docker compose exec postgres vacuumdb -U vaulytica -d vaulytica -z` |
| Clear old scans | Monthly | `vaulytica admin cleanup --older-than 90d` |
| Update dependencies | Monthly | `docker compose build --no-cache` |
| Rotate credentials | Quarterly | See security section |

### Updating Vaulytica

```bash
# Pull latest changes
git pull origin main

# Rebuild containers
docker compose build

# Apply database migrations
docker compose exec backend alembic upgrade head

# Restart services
docker compose up -d
```

---

## Checklist

Before going to production, verify:

- [ ] TLS/SSL configured
- [ ] Strong passwords generated
- [ ] Service account credentials secured
- [ ] Database backups configured
- [ ] Monitoring alerts set up
- [ ] Log aggregation configured
- [ ] Health checks passing
- [ ] Rate limits configured
- [ ] Disaster recovery plan documented
- [ ] Security review completed
