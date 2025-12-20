# Vaulytica

Enterprise-Grade Google Workspace Security, Compliance, and IT Administration Platform

## Overview

Vaulytica is a self-hosted platform providing comprehensive security monitoring, compliance management, and IT automation for Google Workspace environments. It includes a Python CLI tool for scanning and automation, plus a web dashboard (FastAPI backend + Next.js frontend) for visualization and management.

Organizations using Google Workspace face critical security challenges: sensitive data shared externally without detection, shadow IT applications with dangerous permissions, compliance audits requiring manual evidence collection, and no visibility into stale files or dormant accounts. Vaulytica addresses all of these with a unified, self-hosted solution.

---

## Key Features

### Security Scanning (13 Scanners)

- **File Scanner**: Detect externally shared files containing PII (SSN, credit cards, bank accounts)
- **OAuth Scanner**: Identify risky third-party applications with excessive permissions
- **User Scanner**: Find inactive accounts, 2FA non-compliance, admin privileges
- **Group Scanner**: Audit external members, public groups, orphaned groups
- **Device Scanner**: Mobile and Chrome OS security compliance
- **Gmail Scanner**: Email attachments, delegates, forwarding rules, filters
- **Audit Log Scanner**: Suspicious activity detection with anomaly analysis
- **Calendar Scanner**: Public calendars, PII in events
- **Shared Drive Scanner**: Team Drive permissions, external sharing, membership audit
- **Stale Content Scanner**: Files and folders not accessed in configurable time periods
- **External Ownership Scanner**: Files owned by users outside your organization
- **License Scanner**: Unused licenses and cost optimization
- **Vault Scanner**: Legal holds and retention policies

### Security Posture Assessment

- 25+ automated security checks mapped to CIS, NIST, HIPAA, GDPR, PCI-DSS, and SOC2
- Severity-weighted security scoring (0-100)
- Actionable remediation guidance for every finding
- Executive summaries for leadership reporting

### Compliance Reporting

- Automated reports for GDPR, HIPAA, SOC2, PCI-DSS, FERPA, FedRAMP
- Professional HTML dashboards with visualizations
- Export to CSV, JSON, or HTML formats
- Audit-ready evidence packages

### Web Dashboard

- Real-time security metrics and trends
- Scan management and scheduling
- Role-based access control (viewer, editor, admin)
- Alert configuration with email and webhook notifications
- Multi-domain and multi-tenant support

### Integrations

- Jira: Create security issues directly from scan findings
- Slack: Webhook-based notifications
- SIEM: Webhook integration for Splunk, Datadog, Elastic
- Prometheus: Metrics endpoint for monitoring

### IT Administration

- User provisioning: create, update, suspend, restore, delete
- Bulk operations from CSV files
- Automated employee offboarding with Drive transfer
- Organizational unit and calendar resource management

---

## Architecture

```
vaulytica/
  core/
    scanners/       # 13 security scanners
    analyzers/      # Security posture and shadow IT analysis
    reporters/      # HTML, CSV, JSON report generation
  integrations/     # Jira, Slack, webhook integrations
  cli/
    commands/       # Click CLI command implementations

web/
  backend/          # FastAPI REST API
    api/            # API endpoints (auth, scans, findings, etc.)
    db/             # SQLAlchemy models, PostgreSQL
    services/       # Background scan runner
  frontend/         # Next.js 14 React application
    app/            # App Router pages
    components/     # Reusable UI components

shared/             # Shared Python models for CLI-to-Web integration
```

---

## Quick Start

### Prerequisites

- Python 3.9 or higher
- Google Workspace with Admin access
- Service account with domain-wide delegation
- PostgreSQL (for web dashboard)
- Node.js 18+ (for web frontend)

### CLI Installation

```bash
# Clone the repository
git clone https://github.com/clay-good/vaulytica.git
cd vaulytica

# Install dependencies
poetry install

# Verify installation
poetry run vaulytica --version
```

### Configuration

```bash
# Copy the example configuration
cp config.example.yaml config.yaml

# Edit with your service account details
```

Minimum configuration:

```yaml
google_workspace:
  domain: "yourcompany.com"
  credentials_file: "/path/to/service-account.json"
  impersonate_user: "admin@yourcompany.com"
```

### First Scan

```bash
# Test authentication
poetry run vaulytica test

# Run a security scan (READ-ONLY)
poetry run vaulytica scan files --external-only --output report.csv

# Scan for PII in externally shared files
poetry run vaulytica scan files --check-pii --external-only --output pii-report.csv
```

---

## Web Dashboard Setup

### Docker Compose (Recommended)

```bash
# Copy environment file
cp .env.example .env

# Edit environment variables (set SECRET_KEY, DATABASE_URL, etc.)
nano .env

# Start all services
docker-compose up -d postgres backend frontend scan-runner

# Wait for services to start
sleep 10

# Access the dashboard
open http://localhost:3000
```

### Manual Setup

```bash
# 1. Start PostgreSQL
docker run -d \
  --name vaulytica-postgres \
  -e POSTGRES_DB=vaulytica \
  -e POSTGRES_USER=vaulytica \
  -e POSTGRES_PASSWORD=changeme \
  -p 5432:5432 \
  postgres:15-alpine

# 2. Install and start backend
cd web/backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &

# 3. Install and start frontend
cd ../frontend
npm install
npm run dev

# 4. Access dashboard at http://localhost:3000
```

### Create Admin User

```bash
docker-compose exec backend python -c "
from backend.db.database import SessionLocal
from backend.db.models import User
from backend.auth.security import get_password_hash

db = SessionLocal()
admin = User(
    email='admin@example.com',
    hashed_password=get_password_hash('changeme'),
    full_name='Admin User',
    is_superuser=True
)
db.add(admin)
db.commit()
print('Admin user created: admin@example.com / changeme')
"
```

### CLI-to-Web Integration

The CLI can save scan results directly to the PostgreSQL database:

```bash
# Run scans and save to database
vaulytica --save-to-db --db-url postgresql://user:pass@localhost:5432/vaulytica scan files --external-only

# Or set environment variables
export VAULYTICA_SAVE_TO_DB=1
export VAULYTICA_DB_URL=postgresql://user:pass@localhost:5432/vaulytica
vaulytica scan users --inactive-days 90
```

---

## API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Login with email/password |
| `/api/v1/auth/register` | POST | Register new user |
| `/api/v1/auth/me` | GET | Get current user info |
| `/api/v1/auth/forgot-password` | POST | Request password reset |
| `/api/v1/auth/reset-password` | POST | Reset password with token |

### Scans

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scans` | GET | List all scans |
| `/api/v1/scans/trigger` | POST | Trigger new scan |
| `/api/v1/scans/{id}` | GET | Get scan details |
| `/api/v1/scans/{id}/cancel` | POST | Cancel running scan |
| `/api/v1/scans/compare` | GET | Compare two scans |

### Findings

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/findings/security` | GET | Security posture findings |
| `/api/v1/findings/files` | GET | File scan findings |
| `/api/v1/findings/users` | GET | User audit findings |
| `/api/v1/findings/oauth` | GET | OAuth app findings |
| `/api/v1/findings/{id}/status` | PATCH | Update finding status |
| `/api/v1/findings/export/*` | GET | Export findings (CSV/JSON) |

### Schedules

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/schedules` | GET | List scheduled scans |
| `/api/v1/schedules` | POST | Create schedule |
| `/api/v1/schedules/{id}` | PATCH | Update schedule |
| `/api/v1/schedules/{id}` | DELETE | Delete schedule |
| `/api/v1/schedules/{id}/toggle` | POST | Enable/disable schedule |

### Dashboards

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/dashboards/overview` | GET | Dashboard overview metrics |
| `/api/v1/dashboards/trends` | GET | Security trends over time |
| `/api/v1/dashboards/compliance-summary` | GET | Compliance status summary |

Full API documentation available at `/docs` when running the backend.

---

## Command Reference

### Security Scanning (READ-ONLY)

```bash
# File scanning
vaulytica scan files --external-only --check-pii --output report.csv
vaulytica scan files --user user@company.com --check-pii
vaulytica scan files --public-only --output public-files.csv

# Stale content detection
vaulytica scan stale-drives --days 180 --output stale-content.csv

# External ownership audit
vaulytica scan external-owned --output external-owned.csv

# OAuth application audit
vaulytica scan oauth-apps --min-risk-score 70 --output oauth-report.csv

# User audit
vaulytica scan users --inactive-days 90 --check-2fa --output user-audit.csv

# Group audit
vaulytica scan groups --external-members --output groups-report.csv

# Gmail security
vaulytica scan gmail-security --delegates --forwarding --send-as --filters

# Audit logs
vaulytica scan audit-logs --days-back 7 --detect-anomalies

# Shared Drives
vaulytica scan shared-drives --external-only --check-pii
vaulytica scan shared-drive-members --external-only --output members.csv
```

### Security Posture Assessment

```bash
# Full assessment
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com

# Executive summary
vaulytica security-posture summary \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com
```

### Shadow IT Discovery

```bash
vaulytica shadow-it analyze \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --approval-list approved-apps.json \
  --output shadow-it-report.html
```

### Compliance Reporting

```bash
vaulytica compliance report --framework gdpr --output gdpr-report.html
vaulytica compliance report --framework hipaa --output hipaa-report.html
vaulytica compliance report --framework soc2 --output soc2-report.html
vaulytica compliance report --framework pci-dss --output pci-report.html
```

### User Management (READ/WRITE)

```bash
# Create user
vaulytica users create john.doe@company.com \
  --first-name John \
  --last-name Doe \
  --password "TempPass123!" \
  --org-unit "/Engineering"

# Suspend user
vaulytica users suspend user@company.com

# Employee offboarding
vaulytica offboard user@company.com \
  --transfer-to manager@company.com \
  --execute
```

---

## Required OAuth Scopes

### READ-ONLY Scopes (Recommended for Security Scanning)

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.orgunit.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/gmail.settings.basic.readonly
https://www.googleapis.com/auth/calendar.readonly
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/ediscovery.readonly
https://www.googleapis.com/auth/apps.licensing
```

### READ/WRITE Scopes (For User/Resource Management)

```
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/admin.directory.group
https://www.googleapis.com/auth/admin.directory.orgunit
https://www.googleapis.com/auth/admin.directory.resource.calendar
https://www.googleapis.com/auth/drive
```

---

## Service Account Setup

### Step 1: Create Service Account

1. Go to Google Cloud Console
2. Create a new project or select an existing one
3. Enable the required APIs:
   - Admin SDK API
   - Google Drive API
   - Gmail API
   - Calendar API
   - Reports API
4. Navigate to IAM and Admin, then Service Accounts
5. Create a service account
6. Download the JSON key file

### Step 2: Enable Domain-Wide Delegation

1. Go to Google Admin Console
2. Navigate to Security, then API Controls, then Domain-wide Delegation
3. Click Add new
4. Enter your service account client ID
5. Add the OAuth scopes listed above
6. Click Authorize

### Step 3: Test Setup

```bash
poetry run vaulytica test
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection URL | Required |
| `SECRET_KEY` | JWT signing key (generate with `openssl rand -base64 64`) | Required |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | 30 |
| `CORS_ORIGINS` | Allowed CORS origins | `["http://localhost:3000"]` |
| `DEBUG` | Enable debug mode | false |
| `SMTP_HOST` | SMTP server for email | Optional |
| `SMTP_USER` | SMTP username | Optional |
| `SMTP_PASSWORD` | SMTP password | Optional |
| `FRONTEND_URL` | Frontend URL for email links | `http://localhost:3000` |

---

## Test Suite

```bash
# CLI tests
poetry run pytest tests/

# Web backend tests
cd web/backend
python -m pytest tests/ -v

# Web frontend tests
cd web/frontend
npm test
```

---

## Documentation

Detailed documentation is available in the docs/ directory:

- [Architecture and Data Flow](docs/ARCHITECTURE.md) - System design, component architecture, data flow diagrams
- [Production Deployment](docs/PRODUCTION_DEPLOYMENT.md) - Docker, Kubernetes, security configuration
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Database Backup and Restore](docs/DATABASE_BACKUP_RESTORE.md) - Backup strategies, recovery procedures
- [Custom PII Patterns](docs/CUSTOM_PII_PATTERNS.md) - Configuring custom PII detection patterns

---

## Limitations

### API and Performance

- Google API Rate Limits: Large organizations may hit rate limits. Automatic retry with exponential backoff is enabled.
- File Content Scanning: PII detection uses pattern matching on text content. Images and PDFs are not OCR scanned.
- Email Scanning: Gmail scanning requires per-user impersonation and can be slow for large organizations.

### Functional

- Multi-Tenant: The CLI is designed for single-organization use. The web app supports multiple domains within a single deployment.
- Remediation: Vaulytica detects and reports issues but does not automatically remediate most security issues.
- Machine Learning: Anomaly detection is rule-based (statistical thresholds), not ML-based.

### Integration

- Jira: Works with Jira Cloud only. Jira Server/Data Center has not been tested.
- SIEM: Webhook integration sends data in generic JSON format. Custom parsing may be required.
- Email: Requires SMTP configuration. No native SendGrid/Mailgun integration.

### Compliance Reports

Compliance reports are informational summaries based on security scans. They do not constitute official compliance certification or legal verification.

### Security Considerations

- Secure the service account credentials file appropriately
- Use environment variables for sensitive configuration values in production
- Scan output files may contain sensitive information (user emails, file names)
- Change the default SECRET_KEY before deploying to production
