# Vaulytica Architecture and Data Flow

This document describes the architecture, components, and data flow of Vaulytica - a Google Workspace security, compliance, and IT administration platform.

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Data Flow](#data-flow)
4. [Security Architecture](#security-architecture)
5. [Database Schema](#database-schema)
6. [API Architecture](#api-architecture)
7. [Scan Pipeline](#scan-pipeline)
8. [Integration Points](#integration-points)

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              VAULYTICA PLATFORM                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Web UI    │    │  REST API   │    │     CLI     │    │  Scan Runner│  │
│  │  (Next.js)  │◄──►│  (FastAPI)  │◄──►│   (Click)   │    │  (Celery)   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                 │                   │                  │          │
│         │                 │                   │                  │          │
│         ▼                 ▼                   ▼                  ▼          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        PostgreSQL Database                           │   │
│  │   (Users, Domains, Scans, Findings, Audit Logs, Compliance)         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      Google Workspace APIs                           │   │
│  │   (Admin SDK, Drive, Gmail, Calendar, Vault)                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### High-Level Architecture

Vaulytica consists of four main components:

| Component | Technology | Purpose |
|-----------|------------|---------|
| Web UI | Next.js 14, React, Tailwind CSS | User interface for managing scans, viewing findings |
| REST API | FastAPI, SQLAlchemy, Pydantic | Backend API for all operations |
| CLI | Click, Rich | Command-line interface for scanning and automation |
| Scan Runner | Background worker | Executes scheduled scans asynchronously |

---

## Component Architecture

### 1. Web Frontend (`web/frontend/`)

```
web/frontend/
├── app/                     # Next.js 14 App Router
│   ├── dashboard/           # Protected dashboard routes
│   │   ├── findings/        # Findings management
│   │   ├── scans/           # Scan management
│   │   ├── schedules/       # Schedule configuration
│   │   ├── alerts/          # Alert rules
│   │   ├── compliance/      # Compliance reports
│   │   └── users/           # User management
│   ├── login/               # Authentication
│   └── layout.tsx           # Root layout
├── components/              # Reusable components
│   ├── layout/              # Header, Sidebar, Navigation
│   ├── ui/                  # Form inputs, Cards, Badges
│   └── dashboard/           # Dashboard-specific widgets
├── contexts/                # React contexts
│   ├── ThemeContext.tsx     # Dark mode
│   ├── PermissionsContext.tsx # RBAC
│   └── MobileSidebarContext.tsx
├── hooks/                   # Custom hooks
│   └── useWebSocket.ts      # Real-time updates
└── lib/                     # Utilities
    ├── api.ts               # API client
    ├── types.ts             # TypeScript types
    └── validation.ts        # Form validation
```

**Key Features:**
- Server-side rendering with Next.js
- Real-time updates via WebSocket
- Role-based UI rendering
- Responsive mobile layout
- Dark mode support

### 2. Backend API (`web/backend/`)

```
web/backend/
├── api/                     # API endpoints
│   ├── v1/                  # Versioned API routes
│   ├── auth.py              # Authentication
│   ├── scans.py             # Scan management
│   ├── findings.py          # Findings CRUD
│   ├── domains.py           # Domain management
│   ├── schedules.py         # Schedule CRUD
│   ├── alerts.py            # Alert rules
│   ├── compliance.py        # Compliance reports
│   ├── users.py             # User management
│   ├── audit.py             # Audit logs
│   └── websocket.py         # WebSocket handlers
├── auth/                    # Authentication
│   ├── security.py          # JWT, RBAC
│   └── schemas.py           # Auth schemas
├── core/                    # Core services
│   ├── cache.py             # In-memory cache
│   ├── email.py             # Email service
│   ├── notifications.py     # Notification service
│   └── websocket.py         # WebSocket manager
├── db/                      # Database
│   ├── database.py          # Connection pool
│   └── models.py            # SQLAlchemy models
├── services/                # Business logic
│   └── scan_runner.py       # Scan execution
└── main.py                  # FastAPI application
```

**Key Features:**
- RESTful API with OpenAPI documentation
- JWT-based authentication with bcrypt
- Role-based access control (RBAC)
- In-memory caching with TTL
- WebSocket for real-time updates
- Rate limiting on sensitive endpoints

### 3. CLI (`vaulytica/`)

```
vaulytica/
├── cli/                     # CLI commands
│   ├── commands/            # Command modules
│   │   ├── scan.py          # Scan commands
│   │   ├── config.py        # Configuration
│   │   └── report.py        # Reporting
│   ├── main.py              # CLI entry point
│   └── validation.py        # Input validation
├── core/                    # Core logic
│   ├── scanners/            # Scanner implementations
│   │   ├── file_scanner.py  # Drive file scanning
│   │   ├── user_scanner.py  # User directory scanning
│   │   ├── oauth_scanner.py # OAuth app scanning
│   │   └── posture_scanner.py # Security posture
│   ├── detectors/           # Detection engines
│   │   └── pii_detector.py  # PII detection
│   ├── compliance/          # Compliance
│   │   └── reporting.py     # Compliance reports
│   └── database/            # Database integration
│       ├── models.py        # SQLAlchemy models
│       └── saver.py         # Database persistence
└── config/                  # Configuration files
    ├── pii_patterns.yaml    # PII detection patterns
    └── compliance_rules.yaml # Compliance rules
```

**Key Features:**
- Command-line scanning for automation
- Configurable PII detection patterns
- Multiple output formats (JSON, CSV)
- Database integration with `--save-to-db`
- Signal handling for graceful cancellation

### 4. Core Scanners

```
┌────────────────────────────────────────────────────────────────────┐
│                        SCANNER ARCHITECTURE                        │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ File Scanner │  │ User Scanner │  │OAuth Scanner │             │
│  │              │  │              │  │              │             │
│  │ - Drive API  │  │ - Admin SDK  │  │ - Admin SDK  │             │
│  │ - File perms │  │ - User list  │  │ - App perms  │             │
│  │ - PII detect │  │ - 2FA status │  │ - Risk score │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
│         │                 │                 │                      │
│         ▼                 ▼                 ▼                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │                    PII Detector                             │   │
│  │                                                             │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       │   │
│  │  │   SSN   │  │ Credit  │  │  Email  │  │  Phone  │       │   │
│  │  │ Pattern │  │  Card   │  │ Pattern │  │ Pattern │       │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘       │   │
│  │                                                             │   │
│  │  Context Keywords → Confidence Boost → Min Threshold       │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### 1. Scan Execution Flow

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│  User   │───►│  API    │───►│ Scanner │───►│  Google │───►│ Database│
│         │    │         │    │         │    │  APIs   │    │         │
└─────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────┘
     │              │              │              │              │
     │  1. Trigger  │              │              │              │
     │─────────────►│              │              │              │
     │              │  2. Create   │              │              │
     │              │    ScanRun   │              │              │
     │              │─────────────►│              │              │
     │              │              │  3. Enumerate│              │
     │              │              │    Users     │              │
     │              │              │─────────────►│              │
     │              │              │◄─────────────│              │
     │              │              │  4. For each │              │
     │              │              │    user:     │              │
     │              │              │    - Files   │              │
     │              │              │    - Perms   │              │
     │              │              │─────────────►│              │
     │              │              │◄─────────────│              │
     │              │              │  5. Detect   │              │
     │              │              │    PII       │              │
     │              │              │              │              │
     │              │              │  6. Save     │              │
     │              │              │    Findings  │              │
     │              │              │─────────────────────────────►│
     │              │◄─────────────│              │              │
     │  7. Progress │              │              │              │
     │    Updates   │              │              │              │
     │◄─────────────│              │              │              │
```

### 2. Authentication Flow

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│ Browser │───►│  API    │───►│   JWT   │───►│ Database│
└─────────┘    └─────────┘    └─────────┘    └─────────┘
     │              │              │              │
     │  1. Login    │              │              │
     │  (email/pwd) │              │              │
     │─────────────►│              │              │
     │              │  2. Verify   │              │
     │              │    Password  │              │
     │              │─────────────────────────────►│
     │              │◄─────────────────────────────│
     │              │  3. Generate │              │
     │              │    JWT Token │              │
     │              │─────────────►│              │
     │              │◄─────────────│              │
     │  4. Return   │              │              │
     │    Token     │              │              │
     │◄─────────────│              │              │
     │              │              │              │
     │  5. Request  │              │              │
     │  (+ Bearer)  │              │              │
     │─────────────►│              │              │
     │              │  6. Verify   │              │
     │              │    Token     │              │
     │              │─────────────►│              │
     │              │◄─────────────│              │
     │              │  7. Check    │              │
     │              │    Permissions              │
     │              │─────────────────────────────►│
     │              │◄─────────────────────────────│
     │  8. Response │              │              │
     │◄─────────────│              │              │
```

### 3. Real-time Updates Flow

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│ Browser │◄──►│WebSocket│◄──►│ Scanner │───►│ Database│
└─────────┘    └─────────┘    └─────────┘    └─────────┘
     │              │              │              │
     │  1. Connect  │              │              │
     │─────────────►│              │              │
     │  (upgrade)   │              │              │
     │◄─────────────│              │              │
     │              │              │              │
     │              │  2. Scan     │              │
     │              │    Progress  │              │
     │              │◄─────────────│              │
     │  3. Push     │              │              │
     │    Update    │              │              │
     │◄─────────────│              │              │
     │              │              │              │
     │              │  4. Finding  │              │
     │              │    Created   │              │
     │              │◄─────────────│              │
     │  5. Push     │              │              │
     │    Finding   │              │              │
     │◄─────────────│              │              │
     │              │              │              │
     │              │  6. Scan     │              │
     │              │    Complete  │              │
     │              │◄─────────────│              │
     │  7. Push     │              │              │
     │    Complete  │              │              │
     │◄─────────────│              │              │
```

---

## Security Architecture

### Authentication & Authorization

```
┌─────────────────────────────────────────────────────────────────────┐
│                      SECURITY ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    AUTHENTICATION LAYER                       │  │
│  │                                                               │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │  │
│  │  │   bcrypt    │  │    JWT      │  │   Rate Limiting     │  │  │
│  │  │  Password   │  │   Tokens    │  │   (slowapi)         │  │  │
│  │  │   Hashing   │  │  (HS256)    │  │                     │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    AUTHORIZATION LAYER                        │  │
│  │                                                               │  │
│  │  ┌─────────────────────────────────────────────────────────┐ │  │
│  │  │                 ROLE-BASED ACCESS CONTROL               │ │  │
│  │  │                                                         │ │  │
│  │  │   ┌─────────┐    ┌─────────┐    ┌─────────┐           │ │  │
│  │  │   │ VIEWER  │ ◄──│ EDITOR  │ ◄──│  ADMIN  │           │ │  │
│  │  │   │         │    │         │    │         │           │ │  │
│  │  │   │ - Read  │    │ - Read  │    │ - Read  │           │ │  │
│  │  │   │ - Export│    │ - Write │    │ - Write │           │ │  │
│  │  │   │         │    │ - Scan  │    │ - Manage│           │ │  │
│  │  │   └─────────┘    └─────────┘    └─────────┘           │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  │                                                               │  │
│  │  + Domain-level access control                                │  │
│  │  + Superuser flag for global admin                            │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    TRANSPORT SECURITY                         │  │
│  │                                                               │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │  │
│  │  │   HTTPS     │  │  Security   │  │      CORS           │  │  │
│  │  │  Redirect   │  │  Headers    │  │   Validation        │  │  │
│  │  │(production) │  │   (HSTS)    │  │                     │  │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/auth/login` | 5 | 1 minute |
| `/auth/register` | 3 | 1 minute |
| `/auth/forgot-password` | 3 | 1 minute |
| `/auth/change-password` | 3 | 1 minute |
| All other endpoints | 100 | 1 minute |

### Security Headers

```python
# Applied in production
SecurityHeadersMiddleware:
  - Strict-Transport-Security: max-age=31536000
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - X-XSS-Protection: 1; mode=block
```

---

## Database Schema

### Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                       DATABASE SCHEMA                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────┐         ┌───────────┐         ┌───────────┐         │
│  │   users   │─────────│user_domain│─────────│  domains  │         │
│  │           │   M:N   │  _access  │   M:N   │           │         │
│  │ - id      │         │           │         │ - id      │         │
│  │ - email   │         │ - user_id │         │ - name    │         │
│  │ - password│         │ - domain_id         │ - active  │         │
│  │ - is_super│         │ - role    │         │ - creds   │         │
│  └───────────┘         └───────────┘         └───────────┘         │
│        │                                            │               │
│        │                                            │               │
│        ▼                                            ▼               │
│  ┌───────────┐                              ┌───────────┐           │
│  │audit_logs │                              │ scan_runs │           │
│  │           │                              │           │           │
│  │ - user_id │                              │ - domain  │           │
│  │ - action  │                              │ - type    │           │
│  │ - resource│                              │ - status  │           │
│  │ - timestamp                              │ - progress│           │
│  └───────────┘                              └───────────┘           │
│                                                   │                 │
│                    ┌──────────────────────────────┼──────────────┐  │
│                    │              │               │              │  │
│                    ▼              ▼               ▼              ▼  │
│              ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│              │ security │  │   file   │  │   user   │  │ oauth  │  │
│              │ findings │  │ findings │  │ findings │  │findings│  │
│              │          │  │          │  │          │  │        │  │
│              │- check   │  │- file_id │  │- user_id │  │- app_id│  │
│              │- severity│  │- sharing │  │- 2fa     │  │- scopes│  │
│              │- status  │  │- pii     │  │- status  │  │- risk  │  │
│              └──────────┘  └──────────┘  └──────────┘  └────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Tables

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `users` | User accounts | email, hashed_password, is_superuser |
| `domains` | Google Workspace domains | name, credentials_encrypted |
| `user_domain_access` | RBAC mapping | user_id, domain_id, role |
| `scan_runs` | Scan execution records | domain, scan_type, status, progress |
| `security_findings` | Security posture findings | check_id, severity, status |
| `file_findings` | File scan findings | file_id, sharing_type, pii_detected |
| `user_findings` | User scan findings | user_email, has_2fa, is_admin |
| `oauth_findings` | OAuth app findings | app_id, scopes, risk_score |
| `compliance_reports` | Compliance reports | framework, score, issues |
| `audit_logs` | Audit trail | user_id, action, timestamp |

---

## API Architecture

### Endpoint Structure

```
/api/v1/
├── auth/
│   ├── POST /login
│   ├── POST /register
│   ├── POST /logout
│   ├── POST /refresh
│   ├── POST /forgot-password
│   ├── POST /reset-password
│   └── GET  /me
│
├── domains/
│   ├── GET    /           # List domains
│   ├── POST   /           # Create domain
│   ├── GET    /{id}       # Get domain
│   ├── PATCH  /{id}       # Update domain
│   └── DELETE /{id}       # Delete domain
│
├── scans/
│   ├── GET    /           # List scans
│   ├── POST   /trigger    # Trigger scan
│   ├── GET    /{id}       # Get scan details
│   ├── POST   /{id}/cancel # Cancel scan
│   ├── PATCH  /{id}/progress # Update progress
│   └── GET    /compare    # Compare scans
│
├── findings/
│   ├── GET    /security   # Security findings
│   ├── GET    /files      # File findings
│   ├── GET    /users      # User findings
│   ├── GET    /oauth      # OAuth findings
│   ├── PATCH  /{id}/status # Update status
│   └── GET    /export/*   # Export endpoints
│
├── schedules/
│   ├── GET    /           # List schedules
│   ├── POST   /           # Create schedule
│   ├── PATCH  /{id}       # Update schedule
│   └── DELETE /{id}       # Delete schedule
│
├── alerts/
│   ├── GET    /           # List alerts
│   ├── POST   /           # Create alert
│   ├── PATCH  /{id}       # Update alert
│   └── DELETE /{id}       # Delete alert
│
├── compliance/
│   ├── GET    /           # List reports
│   ├── POST   /           # Generate report
│   ├── GET    /{id}       # Get report
│   └── GET    /frameworks # Available frameworks
│
├── users/
│   ├── GET    /           # List users (admin)
│   ├── GET    /{id}       # Get user
│   ├── PATCH  /{id}       # Update user
│   └── DELETE /{id}       # Delete user
│
└── ws/
    └── /                  # WebSocket endpoint
```

### Response Format

All API responses follow a consistent format:

```json
// Success response
{
  "items": [...],
  "total": 100,
  "page": 1,
  "page_size": 20,
  "total_pages": 5,
  "has_next": true,
  "has_prev": false
}

// Error response
{
  "detail": "Error message"
}
```

---

## Scan Pipeline

### Scan Types

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SCAN PIPELINE                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. SECURITY POSTURE SCAN                                          │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Domain Settings → Admin Console → 25+ Security Checks  │    │
│     │                                                         │    │
│     │  Checks: 2FA enforcement, password policies, sharing,   │    │
│     │          mobile, OAuth apps, SSO, marketplace apps      │    │
│     │                                                         │    │
│     │  Output: SecurityFinding (check_id, severity, status)   │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                     │
│  2. FILE SCAN                                                       │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Users → Drive Files → Permissions → PII Detection      │    │
│     │                                                         │    │
│     │  - Enumerate all users in domain                        │    │
│     │  - For each user, list Drive files                      │    │
│     │  - Check file permissions (external, anyone, domain)    │    │
│     │  - Download and scan content for PII                    │    │
│     │  - Score risk based on exposure + PII sensitivity       │    │
│     │                                                         │    │
│     │  Output: FileFinding (file_id, pii_types, risk_score)   │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                     │
│  3. USER SCAN                                                       │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Admin SDK → User Directory → Status Analysis           │    │
│     │                                                         │    │
│     │  - List all users via Admin SDK                         │    │
│     │  - Check 2FA enrollment status                          │    │
│     │  - Check admin/delegated admin roles                    │    │
│     │  - Check last login date (inactive detection)           │    │
│     │  - Check suspended/archived status                      │    │
│     │                                                         │    │
│     │  Output: UserFinding (user_id, has_2fa, is_admin)       │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                     │
│  4. OAUTH APP SCAN                                                  │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  Admin SDK → Token Audit → Permission Analysis          │    │
│     │                                                         │    │
│     │  - List all authorized OAuth apps                       │    │
│     │  - Analyze requested scopes                             │    │
│     │  - Check verification status                            │    │
│     │  - Score risk based on permissions                      │    │
│     │  - Identify overly permissive apps                      │    │
│     │                                                         │    │
│     │  Output: OAuthFinding (app_id, scopes, risk_score)      │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### PII Detection Pipeline

```
Input Text
    │
    ▼
┌─────────────────┐
│  Pattern Match  │ ─── SSN, Credit Card, Email, Phone, etc.
└─────────────────┘
    │
    ▼
┌─────────────────┐
│   Validation    │ ─── Luhn algorithm for credit cards
└─────────────────┘
    │
    ▼
┌─────────────────┐
│ Context Search  │ ─── Keywords boost confidence
└─────────────────┘
    │
    ▼
┌─────────────────┐
│ Confidence Calc │ ─── Base + Context boost
└─────────────────┘
    │
    ▼
┌─────────────────┐
│ Min Threshold   │ ─── Filter low confidence matches
└─────────────────┘
    │
    ▼
PII Matches
```

---

## Integration Points

### Google Workspace APIs

| API | Purpose | Scopes Required |
|-----|---------|-----------------|
| Admin SDK | Users, groups, devices | `admin.directory.*` |
| Drive API | File listing and content | `drive.readonly` |
| Gmail API | Email content (optional) | `gmail.readonly` |
| Calendar API | Meeting content (optional) | `calendar.readonly` |
| Vault API | eDiscovery data | `ediscovery.readonly` |

### External Integrations

```
┌─────────────────────────────────────────────────────────────────────┐
│                     EXTERNAL INTEGRATIONS                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  NOTIFICATIONS                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
│  │    SMTP     │  │  Webhooks   │  │   Slack     │                │
│  │   (Email)   │  │   (JSON)    │  │ (Incoming)  │                │
│  └─────────────┘  └─────────────┘  └─────────────┘                │
│                                                                     │
│  TICKETING                                                          │
│  ┌─────────────┐  ┌─────────────┐                                  │
│  │    Jira     │  │  ServiceNow │                                  │
│  │ (via webhook)│  │ (via webhook)│                                  │
│  └─────────────┘  └─────────────┘                                  │
│                                                                     │
│  MONITORING                                                         │
│  ┌─────────────┐  ┌─────────────┐                                  │
│  │ Prometheus  │  │   Grafana   │                                  │
│  │  /metrics   │  │ (dashboards)│                                  │
│  └─────────────┘  └─────────────┘                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### CLI-to-Web Integration

The CLI can save results directly to the web database:

```bash
# Scan and save to web database
vaulytica scan files \
  --domain example.com \
  --save-to-db \
  --db-url postgresql://vaulytica:password@localhost:5432/vaulytica
```

This allows:
- Scheduled scans via cron
- Integration with CI/CD pipelines
- Centralized results in web dashboard

---

## Deployment Architecture

### Docker Compose (Development/Small)

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOCKER COMPOSE                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐  │
│  │   Frontend    │    │    Backend    │    │  Scan Runner  │  │
│  │   (Next.js)   │◄──►│   (FastAPI)   │◄──►│   (Worker)    │  │
│  │   Port: 3000  │    │   Port: 8000  │    │               │  │
│  └───────────────┘    └───────────────┘    └───────────────┘  │
│                              │                     │           │
│                              ▼                     ▼           │
│                       ┌───────────────────────────────┐        │
│                       │       PostgreSQL              │        │
│                       │       Port: 5432              │        │
│                       └───────────────────────────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Kubernetes (Production/Large)

```
┌─────────────────────────────────────────────────────────────────┐
│                      KUBERNETES                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────────────────────────────────────────────┐    │
│  │                    Ingress Controller                   │    │
│  │                    (nginx/traefik)                      │    │
│  └────────────────────────────────────────────────────────┘    │
│                              │                                  │
│              ┌───────────────┴───────────────┐                 │
│              ▼                               ▼                 │
│  ┌───────────────────┐           ┌───────────────────┐        │
│  │  Frontend Service │           │  Backend Service  │        │
│  │   (Deployment)    │           │   (Deployment)    │        │
│  │   replicas: 2     │           │   replicas: 3     │        │
│  └───────────────────┘           └───────────────────┘        │
│                                          │                     │
│                                          ▼                     │
│  ┌───────────────────┐           ┌───────────────────┐        │
│  │ Scan Runner       │           │    PostgreSQL     │        │
│  │ (Deployment)      │◄─────────►│  (StatefulSet)    │        │
│  │ replicas: 2-5     │           │  + PVC for data   │        │
│  └───────────────────┘           └───────────────────┘        │
│                                                                 │
│  ┌───────────────────────────────────────────────────────┐    │
│  │                   ConfigMaps & Secrets                 │    │
│  │  - vaulytica-config (app settings)                    │    │
│  │  - vaulytica-secrets (credentials)                    │    │
│  │  - vaulytica-google (service account)                 │    │
│  └───────────────────────────────────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Performance Characteristics

### Capacity Guidelines

| Metric | Small (<500 users) | Medium (500-5000) | Large (>5000) |
|--------|-------------------|-------------------|---------------|
| Backend replicas | 1 | 2 | 3+ |
| Scan runners | 1 | 2 | 3-5 |
| Database | 1 CPU, 2GB RAM | 2 CPU, 4GB RAM | 4+ CPU, 8GB+ RAM |
| Scan duration | ~10 min | ~30 min | ~1-2 hours |

### Caching Strategy

| Cache Key | TTL | Purpose |
|-----------|-----|---------|
| scan_stats | 5 min | Dashboard metrics |
| findings_summary | 5 min | Findings overview |
| dashboard_overview | 1 min | Dashboard page |
| frameworks | 1 hour | Compliance frameworks |

---

## Monitoring and Observability

### Health Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | Overall system health |
| `/health/db` | Database connectivity |
| `/health/cache` | Cache status |
| `/metrics` | Prometheus metrics |

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `scan_duration_seconds` | Histogram | Time to complete scans |
| `findings_total` | Counter | Total findings by type |
| `api_request_duration_seconds` | Histogram | API response times |
| `active_connections` | Gauge | Database connections |
| `websocket_connections` | Gauge | Active WebSocket clients |
