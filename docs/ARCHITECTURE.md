# Vaulytica Architecture Guide

**Version:** 1.0  
**Last Updated:** 2025-10-28

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [Security Model](#security-model)
6. [Performance Optimizations](#performance-optimizations)
7. [Extensibility](#extensibility)

---

## Overview

Vaulytica is a modular, enterprise-grade security monitoring platform for Google Workspace. The architecture is designed for:

- **Scalability**: Handle 10,000+ users and millions of files
- **Performance**: Concurrent processing, caching, and incremental scanning
- **Reliability**: Comprehensive error handling and retry logic
- **Extensibility**: Plugin-based architecture for custom integrations
- **Security**: Least-privilege access and encrypted credentials

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Scan    │  │  Report  │  │  Policy  │  │ Workflow │   │
│  │ Commands │  │ Commands │  │ Commands │  │ Commands │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Core Services                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Scanners   │  │   Detectors  │  │   Policies   │     │
│  │ - File       │  │ - PII        │  │ - Expiration │     │
│  │ - User       │  │ - DLP        │  │ - Lifecycle  │     │
│  │ - Gmail      │  │ - OAuth      │  │ - Compliance │     │
│  │ - Drive      │  └──────────────┘  └──────────────┘     │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Integration Layer                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Email   │  │  Slack   │  │ Webhook  │  │   SIEM   │   │
│  │  Alerts  │  │  Alerts  │  │  Events  │  │  Export  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Storage & State                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   SQLite     │  │  File Cache  │  │   Metrics    │     │
│  │   Database   │  │   (Pickle)   │  │  (Prometheus)│     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Google Workspace APIs                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Drive API│  │ Admin SDK│  │ Gmail API│  │ Directory│   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Components

### 1. Authentication & Authorization

**Location:** `vaulytica/core/auth/`

**Components:**
- `GoogleWorkspaceClient`: Main API client with service account authentication
- `CredentialManager`: Secure credential storage and rotation
- Domain-wide delegation for impersonation

**Key Features:**
- Service account authentication
- Automatic token refresh
- Credential encryption at rest
- Support for multiple domains

### 2. Scanners

**Location:** `vaulytica/core/scanners/`

**Components:**
- `FileScanner`: Scans Google Drive files for security issues
- `UserScanner`: Scans user accounts for inactive/suspended users
- `GmailScanner`: Scans Gmail attachments for PII
- `SharedDriveScanner`: Scans shared drives
- `OAuthScanner`: Audits OAuth applications

**Key Features:**
- Concurrent processing with ThreadPoolExecutor
- Incremental scanning with state tracking
- Batch API requests for efficiency
- Rate limiting to avoid quota exhaustion
- Progress tracking and callbacks

### 3. Detectors

**Location:** `vaulytica/core/detectors/`

**Components:**
- `PIIDetector`: Detects 20+ types of PII using regex patterns
- `DLPRuleEngine`: Custom data loss prevention rules
- `ComplianceChecker`: HIPAA, SOC2, GDPR compliance validation

**Key Features:**
- Pattern-based detection with confidence scoring
- Context-aware confidence boosting
- Chunked processing for large files
- Support for multiple file formats (PDF, DOCX, XLSX, PPTX)
- Custom rule definitions

### 4. Policies

**Location:** `vaulytica/core/policies/`

**Components:**
- `ExpirationPolicy`: Auto-expire external file shares
- `LifecyclePolicy`: User offboarding automation
- `CompliancePolicy`: Enforce compliance requirements

**Key Features:**
- Configurable expiration periods
- Automatic notification before expiration
- Grace periods for critical files
- Audit logging of all policy actions

### 5. Integrations

**Location:** `vaulytica/integrations/`

**Components:**
- `EmailAlerter`: Send email notifications
- `SlackNotifier`: Post to Slack channels
- `WebhookSender`: Send events to webhooks
- `SIEMExporter`: Export to SIEM systems

**Key Features:**
- Template-based notifications
- Retry logic with exponential backoff
- Batch notifications for efficiency
- Support for custom integrations

### 6. Workflows

**Location:** `vaulytica/workflows/`

**Components:**
- `ExternalPIIAlertWorkflow`: Alert on PII in externally shared files
- `GmailPIIAlertWorkflow`: Alert on PII in Gmail attachments
- `OffboardingWorkflow`: Automated user offboarding

**Key Features:**
- Multi-step workflow execution
- Conditional logic and branching
- Error handling and rollback
- Workflow state persistence

### 7. Utilities

**Location:** `vaulytica/core/utils/`

**Components:**
- `Cache`: In-memory and file-based caching
- `ConcurrentProcessor`: Parallel processing utilities
- `RateLimiter`: API rate limiting
- `RetryHandler`: Exponential backoff retry logic

**Key Features:**
- TTL-based cache expiration
- Configurable concurrency levels
- Token bucket rate limiting
- Jitter for retry delays

---

## Data Flow

### File Scanning Flow

```
1. CLI Command
   └─> scan files --external-only

2. FileScanner Initialization
   ├─> Load configuration
   ├─> Initialize Google Workspace client
   ├─> Load state manager (for incremental scanning)
   └─> Initialize cache

3. File Discovery
   ├─> Query Drive API with filters
   ├─> Apply incremental scan filter (if enabled)
   ├─> Batch API requests (100 files per request)
   └─> Cache file metadata

4. Concurrent Processing
   ├─> Split files into batches
   ├─> Process batches concurrently (ThreadPoolExecutor)
   ├─> Rate limiting between requests
   └─> Progress tracking

5. Content Analysis
   ├─> Download file content
   ├─> Parse file format (PDF, DOCX, etc.)
   ├─> Chunk large files (>1MB)
   ├─> Run PII detection
   └─> Calculate risk score

6. Policy Enforcement
   ├─> Check expiration policies
   ├─> Apply auto-expire if needed
   ├─> Send notifications
   └─> Log policy actions

7. Results Processing
   ├─> Aggregate results
   ├─> Update state database
   ├─> Generate reports
   ├─> Send alerts (email, Slack, webhook)
   └─> Export to SIEM

8. Cleanup
   ├─> Clear expired cache entries
   ├─> Close database connections
   └─> Log summary statistics
```

---

## Security Model

### Authentication

- **Service Account**: Domain-wide delegation for API access
- **Least Privilege**: Minimal required OAuth scopes
- **Credential Encryption**: AES-256 encryption for stored credentials
- **Token Rotation**: Automatic refresh of access tokens

### Data Protection

- **In-Transit**: TLS 1.3 for all API communications
- **At-Rest**: Encrypted SQLite database for state
- **Audit Logging**: All security events logged with timestamps
- **Data Retention**: Configurable retention periods

### Access Control

- **RBAC**: Role-based access control for CLI commands
- **IP Whitelisting**: Restrict access by IP address
- **VPN Required**: Optional VPN requirement for sensitive operations
- **MFA**: Multi-factor authentication for admin operations

---

## Performance Optimizations

### 1. Caching

- **In-Memory Cache**: Fast access to frequently used data
- **File Cache**: Persistent cache across runs
- **TTL-Based Expiration**: Automatic cleanup of stale data
- **Cache Hit Rate**: 80-90% for repeated scans

### 2. Concurrent Processing

- **ThreadPoolExecutor**: Parallel API requests
- **Configurable Workers**: 2-20 concurrent workers
- **Batch Processing**: Group items for efficiency
- **Rate Limiting**: Avoid API quota exhaustion

### 3. Incremental Scanning

- **State Tracking**: SQLite database for scan history
- **Modified Time Filter**: Only scan changed files
- **Performance Gain**: 80-95% faster on subsequent scans

### 4. Chunked Processing

- **Large File Handling**: Process files in 1MB chunks
- **Memory Efficiency**: 90% memory reduction
- **Overlap**: 100-character overlap between chunks

---

## Extensibility

### Custom Detectors

```python
from vaulytica.core.detectors.base import BaseDetector

class CustomDetector(BaseDetector):
    def detect(self, content: str) -> List[Detection]:
        # Custom detection logic
        pass
```

### Custom Integrations

```python
from vaulytica.integrations.base import BaseIntegration

class CustomIntegration(BaseIntegration):
    def send(self, event: Dict[str, Any]) -> bool:
        # Custom integration logic
        pass
```

### Custom Workflows

```python
from vaulytica.workflows.base import BaseWorkflow

class CustomWorkflow(BaseWorkflow):
    def execute(self, context: Dict[str, Any]) -> WorkflowResult:
        # Custom workflow logic
        pass
```

---

## Deployment Considerations

### Scalability

- **Horizontal Scaling**: Run multiple instances with shared state
- **Load Balancing**: Distribute scans across instances
- **Database Sharding**: Split state database by domain

### High Availability

- **Health Checks**: `/health` endpoint for monitoring
- **Graceful Shutdown**: Complete in-flight requests
- **Automatic Restart**: Systemd or Kubernetes restart policies

### Monitoring

- **Metrics**: Prometheus-compatible metrics endpoint
- **Logging**: Structured JSON logs to stdout
- **Alerting**: Integration with PagerDuty, Opsgenie

---

## Future Architecture Enhancements

1. **Microservices**: Split into separate services (scanner, detector, alerter)
2. **Message Queue**: RabbitMQ or Kafka for async processing
3. **Distributed Cache**: Redis for shared cache across instances
4. **GraphQL API**: Modern API for custom integrations
5. **Machine Learning**: ML-based anomaly detection
6. **Real-Time Streaming**: WebSocket for live updates

---

## Conclusion

Vaulytica's architecture is designed for enterprise-scale deployments with a focus on performance, security, and extensibility. The modular design allows for easy customization and integration with existing security infrastructure.

For more information, see:
- [Getting Started Guide](GETTING_STARTED.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Security Guide](SECURITY.md)

