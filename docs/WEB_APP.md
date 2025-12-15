# Vaulytica Web App

Self-hosted web dashboard for visualizing Vaulytica security scans.

## Overview

The Vaulytica Web App provides a browser-based dashboard for:
- Viewing security scan results
- Monitoring compliance posture
- Tracking security trends over time
- Managing multiple Google Workspace domains

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Browser                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Next.js Frontend (Phase 2)                  │
│                   Port 3000                                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   FastAPI Backend                             │
│                   Port 8000                                   │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐   │
│  │  Auth   │  │  Scans   │  │ Findings │  │  Dashboards │   │
│  └─────────┘  └──────────┘  └──────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   PostgreSQL Database                         │
│                   Port 5432                                   │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │
┌─────────────────────────────────────────────────────────────┐
│                   Vaulytica CLI                               │
│                   (Scan results saved to DB)                  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- PostgreSQL (or use the Docker container)
- Python 3.9+ (for CLI)

### Start the Web App

```bash
# Clone the repository
git clone https://github.com/yourusername/vaulytica.git
cd vaulytica

# Copy environment file
cp web/.env.example web/.env

# Edit environment variables
nano web/.env

# Start all services with Docker Compose (database, backend, frontend, scan-runner)
docker-compose up -d postgres backend frontend scan-runner

# Wait for services to start
sleep 10

# Check backend health
curl http://localhost:8000/health

# Access the dashboard
open http://localhost:3000
```

### Create Admin User

```bash
# Connect to the backend container
docker-compose exec backend bash

# Create admin user
python -c "
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

### Access Points

- **Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## API Endpoints

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Login with email/password |
| `/api/auth/register` | POST | Register new user |
| `/api/auth/me` | GET | Get current user info |
| `/api/auth/me` | PUT | Update current user |
| `/api/auth/me/change-password` | POST | Change password |

### Scans

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scans/recent` | GET | Get recent scans |
| `/api/scans/stats` | GET | Get scan statistics |
| `/api/scans/{id}` | GET | Get scan details |
| `/api/scans/{id}/findings/security` | GET | Get security findings |
| `/api/scans/{id}/findings/files` | GET | Get file findings |
| `/api/scans/{id}/findings/users` | GET | Get user findings |
| `/api/scans/{id}/findings/oauth` | GET | Get OAuth findings |

### Findings

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/findings/security` | GET | Get all security findings |
| `/api/findings/security/summary` | GET | Get findings summary |
| `/api/findings/files/high-risk` | GET | Get high-risk files |
| `/api/findings/files/public` | GET | Get public files |
| `/api/findings/files/pii` | GET | Get files with PII |
| `/api/findings/users/inactive` | GET | Get inactive users |
| `/api/findings/users/no-2fa` | GET | Get users without 2FA |
| `/api/findings/oauth/risky` | GET | Get risky OAuth apps |

### Dashboards

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/dashboards/overview` | GET | Get dashboard overview |
| `/api/dashboards/trends` | GET | Get security trends |
| `/api/dashboards/compliance-summary` | GET | Get compliance summary |

### Domains

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/domains` | GET | List domains |
| `/api/domains` | POST | Create domain (admin) |
| `/api/domains/{name}` | GET | Get domain details |
| `/api/domains/{name}` | PUT | Update domain (admin) |
| `/api/domains/{name}` | DELETE | Delete domain (admin) |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection URL | `postgresql://vaulytica:password@localhost:5432/vaulytica` |
| `SECRET_KEY` | JWT signing key | (required) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration | `30` |
| `CORS_ORIGINS` | Allowed CORS origins | `["http://localhost:3000"]` |
| `DEBUG` | Enable debug mode | `false` |

### Database

The web app uses PostgreSQL to store:
- Web app users and authentication
- Scan results from CLI
- Security findings
- Audit logs

## CLI Integration

The CLI tool can save scan results directly to the PostgreSQL database for viewing in the web dashboard.

### Installation

```bash
# Install with database support
pip install vaulytica[database]

# Or with Poetry
poetry install --extras database
```

### Usage

```bash
# Run scans and save to database
vaulytica --save-to-db --db-url postgresql://user:pass@localhost:5432/vaulytica scan files --external-only

# Or set environment variables
export VAULYTICA_SAVE_TO_DB=1
export VAULYTICA_DB_URL=postgresql://user:pass@localhost:5432/vaulytica
vaulytica scan users --inactive-days 90

# Example with all options
vaulytica \
  --save-to-db \
  --db-url postgresql://vaulytica:password@localhost:5432/vaulytica \
  scan files --external-only --check-pii
```

### Supported Scan Types

The following scans save findings to the database:

| Scan Command | Database Table |
|-------------|----------------|
| `scan files` | `file_findings` |
| `scan users` | `user_findings` |
| `scan oauth-apps` | `oauth_findings` |
| `security-posture assess` | `security_findings` |

Each scan creates a `scan_runs` record with summary statistics (total items, high/medium/low risk counts).

### Without Database

If you don't need the web dashboard, the CLI works exactly as before without the `--save-to-db` flag:

```bash
# Traditional file output (no database required)
vaulytica scan files --external-only --output report.csv
```

## Background Scan Runner

The scan runner is a background service that automatically executes scheduled scans configured through the web UI.

### Starting the Scan Runner

```bash
# Via Docker Compose (recommended)
docker-compose up -d scan-runner

# Or run directly
python -m backend.services.scan_runner
```

### Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection URL | Required |
| `SCAN_CHECK_INTERVAL` | Seconds between checks for due scans | `60` |
| `VAULYTICA_CLI_PATH` | Path to vaulytica CLI executable | `vaulytica` |
| `VAULYTICA_CREDENTIALS_PATH` | Path to service account JSON | `/app/credentials/service-account.json` |

### How It Works

1. The scan runner polls the `scheduled_scans` table every `SCAN_CHECK_INTERVAL` seconds
2. For each active schedule where `next_run <= now`:
   - Retrieves the domain configuration
   - Builds the appropriate vaulytica CLI command with `--save-to-db`
   - Executes the scan as a subprocess
   - Updates `last_run` and calculates `next_run` based on schedule type
3. Scan results are saved to the database via the CLI's `--save-to-db` flag
4. Results appear in the web dashboard automatically

### Supported Schedule Types

| Schedule Type | Configuration |
|--------------|---------------|
| `hourly` | Runs every hour |
| `daily` | Runs at specified hour (default 2 AM) |
| `weekly` | Runs on specified day of week at specified hour |
| `monthly` | Runs on specified day of month at specified hour |

### Supported Scan Types

| Scan Type | CLI Command |
|-----------|-------------|
| `files` | `vaulytica scan files` |
| `users` | `vaulytica scan users` |
| `oauth` | `vaulytica scan oauth-apps` |
| `posture` | `vaulytica security-posture assess` |
| `all` | `vaulytica scan files --external-only` (simplified) |

### Monitoring

```bash
# View logs
docker-compose logs -f scan-runner

# Check service status
docker-compose ps scan-runner
```

## Development

### Local Development Setup

```bash
# Create virtual environment
cd web/backend
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start PostgreSQL (Docker)
docker run -d \
  --name vaulytica-postgres \
  -e POSTGRES_DB=vaulytica \
  -e POSTGRES_USER=vaulytica \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  postgres:15-alpine

# Run development server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Running Tests

```bash
cd web/backend
pytest tests/ -v
```

### Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
```

## Security

### Authentication

- JWT-based authentication
- Password hashing with bcrypt
- Token expiration (configurable)

### Authorization

- Role-based access control
- Domain-level access restrictions
- Superuser capabilities for admin tasks

### Best Practices

1. Change default `SECRET_KEY` in production
2. Use strong passwords for admin accounts
3. Enable HTTPS in production
4. Restrict CORS origins to trusted domains
5. Regularly rotate credentials

## Roadmap

### Phase 1 (Complete)
- FastAPI backend setup
- Database models
- Authentication system
- Core API routes

### Phase 2 (Complete)
- Next.js 14 frontend with App Router
- Dashboard UI with security score visualization
- Scan history and individual scan details
- Findings browser (security, files, users, OAuth)
- Login/authentication flow
- Settings page
- TailwindCSS styling with responsive design
- Recharts for data visualization

### Phase 3 (Complete)
- Scheduled scans configuration UI
- API endpoints for CRUD operations on scheduled scans
- CSV/JSON export for all finding types (security, files, users, OAuth)
- Export buttons on findings page

### Phase 4 (Complete)
- Background scan runner (automatic execution of scheduled scans via `scan-runner` Docker service)

### Phase 5 (Planned)
- Alert configuration and notifications
- Report generation (PDF)
- Real-time updates via WebSocket/SSE

## Troubleshooting

### Common Issues

**Database Connection Failed**
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check connection
psql -h localhost -U vaulytica -d vaulytica
```

**JWT Token Invalid**
- Check SECRET_KEY is consistent across restarts
- Verify token hasn't expired
- Ensure correct Authorization header format

**CORS Errors**
- Add frontend URL to CORS_ORIGINS
- Verify credentials are included in requests

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/vaulytica/issues
- Documentation: This file
