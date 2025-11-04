# Vaulytica Usage Guide

Complete guide to using all features of Vaulytica.

---

## Table of Contents

1. [Basic Scanning](#basic-scanning)
2. [Advanced Scanning](#advanced-scanning)
3. [Employee Lifecycle](#employee-lifecycle)
4. [Policy Management](#policy-management)
5. [Compliance Reporting](#compliance-reporting)
6. [Monitoring & Metrics](#monitoring--metrics)
7. [Multi-Domain Operations](#multi-domain-operations)
8. [Filtering & Search](#filtering--search)
9. [Batch Operations](#batch-operations)

---

## Basic Scanning

### Scan Files for External Sharing

```bash
# Scan all files
vaulytica scan files

# Scan only externally shared files
vaulytica scan files --external-only

# Scan only publicly shared files
vaulytica scan files --public-only

# Scan with PII detection
vaulytica scan files --check-pii

# Scan specific user
vaulytica scan files --user user@example.com

# Export to CSV
vaulytica scan files --output report.csv --format csv

# Export to JSON
vaulytica scan files --output report.json --format json
```

### Scan Users

```bash
# Scan all users
vaulytica scan users

# Find inactive users (no login in 90 days)
vaulytica scan users --inactive-days 90

# Check 2FA status
vaulytica scan users --check-2fa

# Export results
vaulytica scan users --output users.csv
```

### Scan Shared Drives

```bash
# Scan all Shared Drives
vaulytica scan shared-drives

# Scan with PII detection
vaulytica scan shared-drives --check-pii

# Export results
vaulytica scan shared-drives --output shared-drives.json
```

---

## Advanced Scanning

### OAuth App Auditing

```bash
# Audit all OAuth apps
vaulytica scan oauth-apps

# Show only high-risk apps
vaulytica scan oauth-apps --high-risk-only

# Export results
vaulytica scan oauth-apps --output oauth-apps.csv
```

### Gmail Attachment Scanning

```bash
# Scan Gmail attachments
vaulytica scan gmail

# Scan specific user
vaulytica scan gmail --user user@example.com

# Scan date range
vaulytica scan gmail --after 2024-01-01 --before 2024-12-31

# Check for PII
vaulytica scan gmail --check-pii

# Export results
vaulytica scan gmail --output gmail-scan.json
```

---

## Employee Lifecycle

### Offboard Employee

```bash
# Dry-run (default - no changes made)
vaulytica offboard user@example.com

# Execute offboarding
vaulytica offboard user@example.com --execute

# Transfer files to manager
vaulytica offboard user@example.com --transfer-to manager@example.com --execute

# Revoke external shares
vaulytica offboard user@example.com --revoke-external --execute

# Full offboarding
vaulytica offboard user@example.com \
  --transfer-to manager@example.com \
  --revoke-external \
  --execute
```

### Bulk Offboarding

```bash
# Offboard multiple users from file
vaulytica offboard --from-file users.txt --execute

# users.txt format:
# user1@example.com
# user2@example.com
# user3@example.com
```

---

## Policy Management

### Auto-Expire External Shares

```bash
# Dry-run (default)
vaulytica policy expire-shares --days 30

# Execute with grace period
vaulytica policy expire-shares --days 30 --grace-period 7 --execute

# Exempt specific domains
vaulytica policy expire-shares \
  --days 30 \
  --exempt-domain partner.com \
  --execute

# Exempt specific users
vaulytica policy expire-shares \
  --days 30 \
  --exempt-user external-relations@example.com \
  --execute
```

### List Active Policies

```bash
# Show all policies
vaulytica policy list

# Show policy details
vaulytica policy show auto-expire
```

---

## Compliance Reporting

### Generate Compliance Reports

```bash
# GDPR compliance report
vaulytica compliance --framework gdpr --output gdpr-report.json

# HIPAA compliance report
vaulytica compliance --framework hipaa --output hipaa-report.json

# SOC 2 compliance report
vaulytica compliance --framework soc2 --output soc2-report.json

# All frameworks
vaulytica compliance --framework all --output compliance-report.json
```

### Compliance Scoring

```bash
# Show compliance score
vaulytica compliance --framework gdpr --show-score

# Show only high-severity issues
vaulytica compliance --framework gdpr --severity high
```

---

## Monitoring & Metrics

### Health Checks

```bash
# Check system health
vaulytica monitor health

# JSON output
vaulytica monitor health --format json

# Check specific components
vaulytica monitor health --check system
vaulytica monitor health --check api
vaulytica monitor health --check database
```

### Metrics

```bash
# Show all metrics
vaulytica monitor metrics

# Prometheus format
vaulytica monitor metrics --format prometheus

# JSON format
vaulytica monitor metrics --format json

# Table format
vaulytica monitor metrics --format table
```

### Performance Monitoring

```bash
# Show performance statistics
vaulytica monitor performance

# Show specific operation
vaulytica monitor performance --operation scan_files

# Show percentiles
vaulytica monitor performance --percentiles 50,95,99
```

### System Information

```bash
# Show system info
vaulytica monitor system

# Show CPU usage
vaulytica monitor system --cpu

# Show memory usage
vaulytica monitor system --memory

# Show disk usage
vaulytica monitor system --disk
```

---

## Multi-Domain Operations

### Configure Multiple Domains

Edit `config.yaml`:

```yaml
# Multi-domain configuration
domains:
  - domain: "example.com"
    credentials_file: "example-sa.json"
    impersonate_user: "admin@example.com"
    enabled: true
    tags: ["production", "primary"]
  
  - domain: "subsidiary.com"
    credentials_file: "subsidiary-sa.json"
    impersonate_user: "admin@subsidiary.com"
    enabled: true
    tags: ["production", "subsidiary"]
  
  - domain: "dev.example.com"
    credentials_file: "dev-sa.json"
    impersonate_user: "admin@dev.example.com"
    enabled: false  # Disabled
    tags: ["development"]
```

### Scan Multiple Domains

```bash
# Scan all enabled domains
vaulytica scan files --all-domains

# Scan specific domain
vaulytica scan files --domain example.com

# Scan domains with specific tag
vaulytica scan files --domain-tag production

# Parallel scanning (faster)
vaulytica scan files --all-domains --parallel

# Sequential scanning (safer)
vaulytica scan files --all-domains --sequential
```

---

## Filtering & Search

### Filter by Risk Score

```bash
# High risk only (score >= 75)
vaulytica scan files --min-risk 75

# Medium risk (score 50-74)
vaulytica scan files --min-risk 50 --max-risk 74

# Low risk (score 25-49)
vaulytica scan files --min-risk 25 --max-risk 49
```

### Filter by User

```bash
# Specific user
vaulytica scan files --user user@example.com

# Multiple users
vaulytica scan files --user user1@example.com --user user2@example.com
```

### Filter by Date Range

```bash
# Files modified after date
vaulytica scan files --after 2024-01-01

# Files modified before date
vaulytica scan files --before 2024-12-31

# Date range
vaulytica scan files --after 2024-01-01 --before 2024-12-31
```

### Filter by File Type

```bash
# Specific MIME type
vaulytica scan files --mime-type "application/pdf"

# Multiple MIME types
vaulytica scan files \
  --mime-type "application/pdf" \
  --mime-type "application/vnd.google-apps.document"

# Google Docs only
vaulytica scan files --mime-type "application/vnd.google-apps.document"

# Google Sheets only
vaulytica scan files --mime-type "application/vnd.google-apps.spreadsheet"
```

### Complex Filters

```bash
# High-risk PDFs shared externally
vaulytica scan files \
  --external-only \
  --min-risk 75 \
  --mime-type "application/pdf"

# Files with PII modified in last 30 days
vaulytica scan files \
  --check-pii \
  --after $(date -d '30 days ago' +%Y-%m-%d)

# Public files owned by specific users
vaulytica scan files \
  --public-only \
  --user user1@example.com \
  --user user2@example.com
```

---

## Batch Operations

### Large-Scale Scanning

```bash
# Batch scan with progress tracking
vaulytica scan files --batch-size 100 --show-progress

# Resume from checkpoint
vaulytica scan files --resume-from checkpoint.json

# Save checkpoint every N items
vaulytica scan files --checkpoint-interval 100 --checkpoint-dir ./checkpoints
```

### Batch Offboarding

```bash
# Offboard multiple users with checkpointing
vaulytica offboard \
  --from-file users.txt \
  --batch-size 10 \
  --checkpoint-dir ./checkpoints \
  --execute

# Resume failed offboarding
vaulytica offboard \
  --resume-from ./checkpoints/offboard_checkpoint.json \
  --execute
```

---

## Configuration Management

### Initialize Configuration

```bash
# Create default config
vaulytica init

# Create config with specific path
vaulytica init --output custom-config.yaml
```

### Test Configuration

```bash
# Test authentication
vaulytica config test

# Test email alerts
vaulytica config test-email

# Test Slack integration
vaulytica config test-slack

# Test SIEM webhook
vaulytica config test-webhook
```

### Validate Configuration

```bash
# Validate config file
vaulytica config validate

# Validate specific config
vaulytica config validate --config custom-config.yaml
```

---

## Tips & Best Practices

### 1. Always Use Dry-Run First

```bash
# Dry-run (safe)
vaulytica offboard user@example.com

# Then execute
vaulytica offboard user@example.com --execute
```

### 2. Use Incremental Scanning

```bash
# First scan (full)
vaulytica scan files

# Subsequent scans (incremental - only changed files)
vaulytica scan files --incremental
```

### 3. Monitor API Quotas

```bash
# Check quota usage
vaulytica monitor metrics | grep quota

# Adjust rate limits in config.yaml
advanced:
  respect_api_quotas: true
  quota_buffer_percent: 20
```

### 4. Use Checkpoints for Large Operations

```bash
# Enable checkpointing
vaulytica scan files \
  --checkpoint-dir ./checkpoints \
  --checkpoint-interval 100
```

### 5. Filter Results to Reduce Noise

```bash
# Focus on high-risk items
vaulytica scan files --min-risk 75 --external-only
```

---

## Troubleshooting

### Authentication Issues

```bash
# Test authentication
vaulytica config test

# Check credentials
vaulytica config validate
```

### API Rate Limits

```bash
# Check rate limit status
vaulytica monitor metrics --format table | grep rate

# Adjust rate limits in config.yaml
```

### Performance Issues

```bash
# Check system resources
vaulytica monitor system

# Use batch processing
vaulytica scan files --batch-size 50

# Enable incremental scanning
vaulytica scan files --incremental
```

---

For more information, see:
- [Configuration Guide](configuration.md)
- [Authentication Guide](authentication.md)
- [Complete Feature List](FEATURES_COMPLETE.md)
- [Roadmap](roadmap.md)

