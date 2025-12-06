# Vaulytica

**Enterprise-Grade Google Workspace Security, Compliance & IT Administration**

---

## What is Vaulytica?

Vaulytica is a powerful, self-hosted Python CLI tool that provides comprehensive security monitoring, compliance management, and IT automation for Google Workspace environments. Built for security teams, compliance officers, and IT administrators who need complete visibility and control over their organization's data.

> **"24/7 security monitoring for your entire Google Workspace environment. Detect PII in shared files, audit OAuth applications, track user activity, enforce compliance policies, and receive real-time alerts. All automated. All self-hosted. Complete control."**

---

## Why Vaulytica?

**The Problem**: Organizations using Google Workspace face critical security and compliance challenges:
- Sensitive data (SSN, credit cards, health records) shared externally without detection
- Shadow IT applications with dangerous permissions accessing corporate data
- Compliance audits requiring manual evidence collection across multiple systems
- No visibility into stale files, external ownership, or dormant accounts
- Employee offboarding gaps leaving data exposed

**The Solution**: Vaulytica provides a single, unified platform that:
- Scans your entire Google Workspace for security vulnerabilities
- Detects and alerts on PII exposure in real-time
- Generates audit-ready compliance reports for GDPR, HIPAA, SOC2, PCI-DSS, FERPA, and FedRAMP
- Automates IT operations including user provisioning and offboarding
- Integrates with Jira, Slack, webhooks, and SIEM platforms

---

## Who Uses Vaulytica?

| Audience | Primary Use Cases |
|----------|-------------------|
| **Security Teams** | Detect data leaks, audit access controls, monitor OAuth applications, investigate suspicious activity |
| **Compliance Officers** | Automated GDPR/HIPAA/SOC2/PCI-DSS/FERPA/FedRAMP reporting, audit evidence collection |
| **IT Administrators** | User lifecycle management, bulk operations, organizational visibility |
| **Executives & CISOs** | Risk dashboards, compliance scorecards, security posture trending |

---

## Key Capabilities

### Security Scanning (13 Scanners)
- **File Scanner**: Detect externally shared files containing PII (SSN, credit cards, bank accounts)
- **OAuth Scanner**: Identify risky third-party applications with excessive permissions
- **User Scanner**: Find inactive accounts, 2FA non-compliance, admin privileges
- **Group Scanner**: Audit external members, public groups, orphaned groups
- **Device Scanner**: Mobile and Chrome OS security compliance
- **Gmail Scanner**: Email attachments, delegates, forwarding rules, filters
- **Audit Log Scanner**: Suspicious activity detection with anomaly analysis
- **Calendar Scanner**: Public calendars, PII in events
- **Shared Drive Scanner**: Team Drive permissions, external sharing, and membership audit
- **License Scanner**: Unused licenses and cost optimization
- **Vault Scanner**: Legal holds and retention policies

### Security Posture Assessment
- 25+ automated security checks mapped to CIS, NIST, HIPAA, GDPR, PCI-DSS, and SOC2
- Severity-weighted security scoring (0-100)
- Actionable remediation guidance for every finding
- Executive summaries for leadership reporting

### Shadow IT Discovery
- Detect unauthorized OAuth applications not on your approved list
- Risk categorization: Critical, High, Medium, Low
- Identify admin access grants, data exfiltration risks, stale permissions
- Automated remediation playbooks prioritized by urgency

### Drive Content Analysis
- **Stale Content Detection**: Find files and folders not accessed in configurable time periods
- **External Ownership Audit**: Identify files owned by users outside your organization
- **Shared Drive Membership Audit**: Complete visibility into who has access to each Team Drive
- Storage usage analysis and cleanup recommendations

### Compliance Reporting
- Automated reports for GDPR, HIPAA, SOC2, PCI-DSS, FERPA, FedRAMP
- Professional HTML dashboards with Chart.js visualizations
- Export to CSV, JSON, or HTML formats
- Audit-ready evidence packages

### Jira Integration
- Create security issues directly in Jira from scan findings
- Automated weekly security summary reports
- Priority mapping from severity levels
- Rich formatting with Atlassian Document Format

### IT Administration
- User provisioning: create, update, suspend, restore, delete
- Bulk operations from CSV files
- Automated employee offboarding with Drive transfer
- Organizational unit and calendar resource management
- Full backup and export capabilities

### Scheduled Scanning
- APScheduler backend with cron and interval triggers
- Persist schedules to disk for daemon mode operation
- Support for files, users, gmail, shared_drives, oauth scans
- Enable/disable schedules without deletion

### Trend Analysis
- Historical metrics storage in SQLite database
- Week-over-week and month-over-month comparisons
- Trend direction detection (improving/degrading/stable)
- Anomaly detection for sudden spikes or drops
- Track 10 key security metrics over time

### Monitoring & Alerting
- Email alerts for high-risk findings
- Webhook integration for SIEM platforms (Splunk, Datadog, Elastic)
- Prometheus metrics endpoint
- Health checks and system monitoring

---

## Quick Start

### Prerequisites
- Python 3.9 or higher
- Google Workspace with Admin access
- Service account with domain-wide delegation

### Installation

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
# See "Complete Setup Guide" section below
```

### First Scan

```bash
# Test authentication
poetry run vaulytica test

# Run your first security scan (READ-ONLY)
poetry run vaulytica scan files --external-only --output report.csv

# Scan for PII in externally shared files
poetry run vaulytica scan files --check-pii --external-only --output pii-report.csv
```

---

## Complete Command Reference

### Command Groups Overview

| Command Group | Description | Access Level |
|--------------|-------------|--------------|
| `scan` | 13 security scanners for files, users, OAuth, devices, Gmail, etc. | READ-ONLY |
| `security-posture` | Automated security baseline assessment with 25+ checks | READ-ONLY |
| `shadow-it` | OAuth application discovery and risk analysis | READ-ONLY |
| `jira` | Jira integration for creating issues from findings | READ-ONLY + External Write |
| `users` | User provisioning and management | READ & WRITE |
| `bulk` | Bulk operations from CSV files | READ & WRITE |
| `offboard` | Automated employee offboarding | READ & WRITE |
| `ou` | Organizational unit management | READ & WRITE |
| `resources` | Calendar resource management | READ & WRITE |
| `backup` | Data backup and export | READ-ONLY |
| `compliance` | Compliance framework reporting | READ-ONLY |
| `report` | HTML dashboard generation | READ-ONLY |
| `monitor` | System health checks | READ-ONLY |
| `metrics` | Prometheus metrics export | READ-ONLY |
| `workflow` | Automated alerting workflows | READ-ONLY + Alerts |
| `schedule` | Scheduled scan management | READ-ONLY |
| `trend` | Trend analysis and historical reporting | READ-ONLY |
| `custom-pii` | Custom PII pattern management | Configuration |

---

### Security Scanning Commands (READ-ONLY)

All scanning commands are safe to run at any time. They do not modify your Google Workspace.

#### Scan Files

Detect externally shared files containing sensitive data.

```bash
# Scan all externally shared files for PII
vaulytica scan files --external-only --check-pii --output pii-report.csv

# Scan specific user's files
vaulytica scan files --user user@company.com --check-pii

# Limit scan for testing
vaulytica scan files --max-files 100 --external-only

# Public files only
vaulytica scan files --public-only --output public-files.csv
```

**Options:**
- `--external-only`: Only scan externally shared files
- `--public-only`: Only scan publicly accessible files
- `--check-pii`: Enable PII detection (SSN, credit cards, etc.)
- `--user EMAIL`: Scan specific user's files
- `--max-files N`: Limit number of files scanned
- `--output FILE`: Output file path
- `--format FORMAT`: Output format (csv, json)

---

#### Scan Stale Drives

Find files and folders not accessed within a specified time period. Useful for storage cleanup and data governance.

```bash
# Find content not accessed in 180 days
vaulytica scan stale-drives --days 180 --output stale-content.csv

# Find stale folders only (faster)
vaulytica scan stale-drives --days 90 --folders-only --output stale-folders.csv

# Export as JSON
vaulytica scan stale-drives --days 180 --format json --output stale-content.json

# Scan specific domain
vaulytica scan stale-drives --domain company.com --days 180
```

**Options:**
- `--days N`: Number of days without access (default: 180)
- `--folders-only`: Only scan folders, not individual files
- `--domain DOMAIN`: Target domain
- `--output FILE`: Output file path
- `--format FORMAT`: Output format (csv, json)

---

#### Scan External-Owned Files

Identify files in your domain owned by external users. Critical for data sovereignty compliance.

```bash
# Find all externally-owned files
vaulytica scan external-owned --output external-owned.csv

# Filter by minimum file size (bytes)
vaulytica scan external-owned --min-size 1000000 --output large-external.csv

# Export as JSON
vaulytica scan external-owned --format json --output external-owned.json

# Scan specific domain
vaulytica scan external-owned --domain company.com
```

**Options:**
- `--domain DOMAIN`: Organization domain to check ownership against
- `--min-size BYTES`: Minimum file size filter
- `--output FILE`: Output file path
- `--format FORMAT`: Output format (csv, json)

---

#### Scan OAuth Apps

Audit third-party application access to your organization's data.

```bash
# Find high-risk OAuth apps
vaulytica scan oauth-apps --min-risk-score 70 --output oauth-report.csv

# Scan specific user's OAuth tokens
vaulytica scan oauth-apps --user user@company.com
```

**Options:**
- `--min-risk-score N`: Minimum risk score filter (0-100)
- `--user EMAIL`: Scan specific user
- `--output FILE`: Output file path

---

#### Scan Users

Audit user accounts for security and compliance issues.

```bash
# Find inactive users (90+ days)
vaulytica scan users --inactive-days 90 --output inactive-users.csv

# Check 2FA compliance
vaulytica scan users --check-2fa

# Find admin users
vaulytica scan users --admins-only

# Combined filters
vaulytica scan users --inactive-days 90 --check-2fa --output user-audit.csv
```

**Options:**
- `--inactive-days N`: Find users inactive for N days
- `--check-2fa`: Check 2FA enrollment status
- `--admins-only`: Only scan admin users
- `--output FILE`: Output file path

---

#### Scan Groups

Audit Google Groups for security issues.

```bash
# Find groups with external members
vaulytica scan groups --external-members --output groups-report.csv

# Find public groups
vaulytica scan groups --public-groups

# Find orphaned groups (no owners)
vaulytica scan groups --orphaned
```

**Options:**
- `--external-members`: Find groups with external members
- `--public-groups`: Find publicly accessible groups
- `--orphaned`: Find groups without owners
- `--output FILE`: Output file path

---

#### Scan Mobile Devices

Audit mobile device security and compliance.

```bash
# Scan all mobile devices
vaulytica scan devices --output devices-report.csv

# Find inactive devices
vaulytica scan devices --inactive-days 90

# Find devices without passwords
vaulytica scan devices --no-password
```

---

#### Scan Chrome Devices

Audit Chromebook security and compliance.

```bash
# Scan all Chrome OS devices
vaulytica scan chrome-devices --output chrome-report.csv

# Scan specific org unit
vaulytica scan chrome-devices --org-unit "/Students"

# Find inactive Chromebooks
vaulytica scan chrome-devices --inactive-days 90
```

---

#### Scan Gmail

Audit email attachments for sensitive data.

```bash
# Scan Gmail attachments for PII
vaulytica scan gmail --days-back 30 --check-pii --output gmail-report.csv

# Scan specific users
vaulytica scan gmail --user user1@company.com --user user2@company.com

# External emails only
vaulytica scan gmail --external-only --days-back 7
```

---

#### Scan Gmail Security

Audit Gmail security settings including delegates, forwarding, and filters.

```bash
# Check for email delegates
vaulytica scan gmail-security --delegates --output delegates-report.csv

# Check auto-forwarding rules
vaulytica scan gmail-security --forwarding

# Check send-as aliases
vaulytica scan gmail-security --send-as

# Comprehensive security check
vaulytica scan gmail-security --delegates --forwarding --send-as --filters
```

---

#### Scan Audit Logs

Detect suspicious activity in Google Workspace admin logs.

```bash
# Scan recent audit logs
vaulytica scan audit-logs --days-back 7 --output audit-report.csv

# Detect anomalies
vaulytica scan audit-logs --detect-anomalies --days-back 30

# Specific event types
vaulytica scan audit-logs --event-type admin --days-back 7
```

---

#### Scan Shared Drives

Audit Team Drive permissions and sharing.

```bash
# Scan all Shared Drives
vaulytica scan shared-drives --output shared-drives-report.csv

# Scan files in Shared Drives with PII check
vaulytica scan shared-drives --scan-files --check-pii

# External sharing only
vaulytica scan shared-drives --external-only
```

---

#### Scan Shared Drive Members

Audit Shared Drive memberships and identify who has access to each Team Drive.

```bash
# List all members of all Shared Drives
vaulytica scan shared-drive-members --output members.csv

# Show only external (non-domain) members
vaulytica scan shared-drive-members --external-only --output external-access.csv

# Export as JSON
vaulytica scan shared-drive-members --format json --output members.json

# Scan specific domain
vaulytica scan shared-drive-members --domain company.com
```

**Options:**
- `--domain DOMAIN`: Organization domain
- `--external-only`: Only show external members
- `--output FILE`: Output file path
- `--format FORMAT`: Output format (csv, json)

**Output includes:**
- Drive ID and name
- Member email and type (user, group, domain, anyone)
- Role (organizer, fileOrganizer, writer, commenter, reader)
- External member flag
- Access source

---

#### Scan Calendar

Audit calendar sharing and content.

```bash
# Scan calendars for PII
vaulytica scan calendar --check-pii --output calendar-report.csv

# Check upcoming events
vaulytica scan calendar --days-ahead 30

# Scan specific user
vaulytica scan calendar --user user@company.com
```

---

#### Scan Licenses

Analyze license usage and identify cost savings.

```bash
# Scan license usage
vaulytica scan licenses --output licenses-report.csv

# Find unused licenses
vaulytica scan licenses --unused-days 90 --show-recommendations
```

---

#### Scan Vault

Audit Google Vault legal holds and retention.

```bash
# Scan Vault matters
vaulytica scan vault --output vault-report.csv

# Check legal holds
vaulytica scan vault --check-holds
```

---

### Security Posture Assessment

Automated security baseline scanning with compliance framework mapping.

```bash
# Comprehensive assessment with all 25+ checks
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com

# Executive summary (critical and high only)
vaulytica security-posture summary \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com

# Framework-specific assessment
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --framework cis \
  --framework hipaa \
  --output security-assessment.json

# Filter by severity
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --severity-filter critical \
  --output critical-findings.json
```

**Security Checks Include:**
- Authentication: 2FA enforcement, password policies, session timeouts
- Access Control: Admin account security, external sharing restrictions
- Data Protection: DLP policies, email security (SPF/DKIM/DMARC)
- Device Management: MDM enforcement, encryption requirements
- Third-Party Access: OAuth verification, unverified publisher detection
- Audit & Monitoring: Comprehensive logging, API access monitoring

**Supported Frameworks:** CIS, NIST, HIPAA, GDPR, PCI-DSS, SOC2

---

### Shadow IT Discovery

Identify and analyze unauthorized OAuth applications.

```bash
# Comprehensive Shadow IT analysis
vaulytica shadow-it analyze \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --approval-list approved-apps.json \
  --output shadow-it-report.html \
  --format html

# Quick analysis without approval list
vaulytica shadow-it analyze \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --output report.json

# Export approval template
vaulytica shadow-it export-template --output approved-apps.json
```

**Detection Capabilities:**
- Unauthorized applications not on approval list
- Admin access grants (Critical risk)
- Data exfiltration risks (Drive, Gmail, Calendar access)
- Stale grants unused for 90+ days
- Widespread adoption patterns (20+ users)
- Unverified publishers

---

### Jira Integration Commands

Create and manage Jira issues from security findings.

#### Test Jira Connection

```bash
# Verify Jira API connectivity
vaulytica jira test-connection
```

#### Create Single Issue

```bash
# Create a security issue manually
vaulytica jira create-issue \
  --summary "High-risk OAuth app detected" \
  --description "App 'FileSync Pro' has full Drive access for 25 users" \
  --priority high \
  --labels security,oauth
```

**Options:**
- `--summary TEXT`: Issue summary (required)
- `--description TEXT`: Issue description
- `--priority LEVEL`: Priority (critical, high, medium, low)
- `--labels TEXT`: Comma-separated labels
- `--assignee ACCOUNT_ID`: Jira account ID to assign

#### Create Issues from Scan

```bash
# Create issues from file scan findings
vaulytica jira create-from-scan \
  --scan-type files \
  --min-severity high \
  --dry-run

# Execute issue creation
vaulytica jira create-from-scan \
  --scan-type files \
  --min-severity high

# From OAuth scan
vaulytica jira create-from-scan \
  --scan-type oauth \
  --min-severity critical
```

**Options:**
- `--scan-type TYPE`: Scan type (files, oauth, users, security-posture)
- `--min-severity LEVEL`: Minimum severity to create issues
- `--dry-run`: Preview without creating issues
- `--batch-size N`: Issues per batch (rate limiting)

#### Weekly Security Report

```bash
# Generate weekly summary issue in Jira
vaulytica jira weekly-report

# Custom date range
vaulytica jira weekly-report --days 14
```

#### Search Jira Issues

```bash
# Find Vaulytica-created issues
vaulytica jira search --labels vaulytica

# Search by status
vaulytica jira search --status "To Do"

# Search by project
vaulytica jira search --project SEC
```

#### Configure Jira

```bash
# Display configuration instructions
vaulytica jira configure
```

**Configuration (config.yaml):**
```yaml
integrations:
  jira:
    enabled: true
    url: "https://your-org.atlassian.net"
    email: "api-user@company.com"
    api_token: "${JIRA_API_TOKEN}"
    project_key: "SEC"
    issue_type: "Task"
    default_labels:
      - vaulytica
      - security
    priority_mapping:
      critical: "Highest"
      high: "High"
      medium: "Medium"
      low: "Low"
```

---

### User Management Commands (READ & WRITE)

These commands modify your Google Workspace. Use with caution.

#### Create User

```bash
vaulytica users create john.doe@company.com \
  --first-name John \
  --last-name Doe \
  --password "TempPass123!" \
  --org-unit "/Engineering"
```

#### Update User

```bash
vaulytica users update user@company.com \
  --first-name John \
  --last-name Smith \
  --org-unit "/Sales"
```

#### Suspend User

```bash
vaulytica users suspend user@company.com
```

#### Restore User

```bash
vaulytica users restore user@company.com
```

#### Delete User

```bash
vaulytica users delete user@company.com
```

---

### Bulk Operations (READ & WRITE)

#### Bulk Create Users

```bash
# Dry-run first
vaulytica bulk create-users users.csv --dry-run

# Execute
vaulytica bulk create-users users.csv
```

CSV Format: `email,first_name,last_name,password,org_unit`

#### Bulk Suspend Users

```bash
vaulytica bulk suspend-users users.csv --dry-run
vaulytica bulk suspend-users users.csv
```

#### Export Users

```bash
vaulytica bulk export-users --output all-users.csv
```

---

### Employee Offboarding (READ & WRITE)

Automated employee offboarding with Drive transfer, group removal, and OAuth revocation.

```bash
# Dry-run first
vaulytica offboard user@company.com \
  --transfer-to manager@company.com \
  --dry-run

# Execute
vaulytica offboard user@company.com \
  --transfer-to manager@company.com \
  --execute
```

**Offboarding Steps:**
1. Suspend user account
2. Transfer Drive file ownership
3. Remove from all groups
4. Revoke OAuth tokens
5. Backup user data

---

### Organizational Unit Management

#### List OUs

```bash
vaulytica ou list
vaulytica ou list --parent "/Engineering"
vaulytica ou list --output ous.csv
```

#### Create OU

```bash
vaulytica ou create "Engineering" --parent "/" --description "Engineering team"
```

#### Update OU

```bash
vaulytica ou update "/Engineering" --name "Engineering Team" --description "Updated"
```

#### Delete OU

```bash
vaulytica ou delete "/Engineering" --confirm
```

---

### Calendar Resource Management

#### List Resources

```bash
vaulytica resources list
vaulytica resources list --output resources.csv
```

#### Create Resource

```bash
vaulytica resources create "Conference Room A" \
  --type CONFERENCE_ROOM \
  --capacity 10 \
  --building "Building-1" \
  --floor "2nd Floor"
```

#### Update Resource

```bash
vaulytica resources update <resource-id> --capacity 12
```

#### Delete Resource

```bash
vaulytica resources delete <resource-id> --confirm
```

---

### Backup & Export (READ-ONLY)

```bash
# Backup users
vaulytica backup users --format json --backup-dir ./backups

# Backup groups
vaulytica backup groups --format json --backup-dir ./backups

# Backup organizational units
vaulytica backup org-units --format json --backup-dir ./backups

# Full backup
vaulytica backup full --format json --backup-dir ./backups

# List backups
vaulytica backup list --backup-dir ./backups
```

---

### Compliance Reporting (READ-ONLY)

Generate audit-ready compliance reports.

```bash
# GDPR compliance report
vaulytica compliance report --framework gdpr --output gdpr-report.html

# HIPAA compliance report
vaulytica compliance report --framework hipaa --output hipaa-report.html

# SOC 2 compliance report
vaulytica compliance report --framework soc2 --output soc2-report.html

# PCI-DSS compliance report
vaulytica compliance report --framework pci-dss --output pci-report.html

# FERPA compliance report
vaulytica compliance report --framework ferpa --output ferpa-report.html

# FedRAMP compliance report
vaulytica compliance report --framework fedramp --output fedramp-report.html
```

**Supported Frameworks:** GDPR, HIPAA, SOC2, PCI-DSS, FERPA, FedRAMP

---

### Report Generation (READ-ONLY)

Generate executive HTML dashboards with charts and visualizations.

```bash
vaulytica report generate --format html --output dashboard.html
```

---

### Monitoring & Metrics (READ-ONLY)

```bash
# Health check
vaulytica monitor health

# Export metrics
vaulytica metrics export --output metrics.txt
vaulytica metrics export --format json --output metrics.json

# Serve Prometheus endpoint
vaulytica metrics serve --port 9090
```

---

### Automated Workflows

#### External PII Alert

```bash
vaulytica workflow external-pii-alert \
  --domain company.com \
  --alert-email security@company.com \
  --alert-webhook https://siem.company.com/webhook
```

#### Gmail External PII Alert

```bash
vaulytica workflow gmail-external-pii-alert \
  --domain company.com \
  --user user@company.com \
  --days-back 7 \
  --alert-email security@company.com
```

---

### Scheduled Scanning

Schedule automated recurring scans using cron expressions or intervals.

```bash
# Add a daily file scan at 2 AM
vaulytica schedule add \
  --name "Daily File Scan" \
  --scan-type files \
  --schedule "0 2 * * *"

# Add a user scan every 6 hours
vaulytica schedule add \
  --name "Periodic User Scan" \
  --scan-type users \
  --schedule-type interval \
  --schedule "6h"

# List all schedules
vaulytica schedule list

# Show schedule details
vaulytica schedule show <scan_id>

# Enable/disable schedules
vaulytica schedule enable <scan_id>
vaulytica schedule disable <scan_id>

# Remove a schedule
vaulytica schedule remove <scan_id>

# Run scheduler (foreground, blocking)
vaulytica schedule run

# Run scheduler as daemon
vaulytica schedule run --daemon

# Stop scheduler
vaulytica schedule stop
```

**Supported Scan Types:** files, users, gmail, shared_drives, oauth

**Schedule Formats:**
- Cron: `"0 2 * * *"` (daily at 2 AM)
- Interval: `"6h"` (every 6 hours), `"30m"` (every 30 minutes), `"1d"` (daily)

---

### Trend Analysis

Track security metrics over time and detect trends.

```bash
# Analyze trend for a specific metric
vaulytica trend analyze -m external_shares -d company.com --days 30

# Compare two time periods
vaulytica trend compare -m external_shares -d company.com \
  --from-date 2024-01-01 --to-date 2024-01-31 \
  --compare-from 2024-02-01 --compare-to 2024-02-28

# Generate comprehensive trend report
vaulytica trend report -d company.com --days 30 -o report.json

# Week-over-week change
vaulytica trend week-over-week -m external_shares -d company.com

# Month-over-month change
vaulytica trend month-over-month -m users_without_2fa -d company.com

# Manually record a metric value
vaulytica trend record -m external_shares -v 42 -d company.com
```

**Available Metrics:**
- `external_shares` - Files shared externally
- `public_files` - Publicly accessible files
- `users_without_2fa` - Users without 2FA enabled
- `high_risk_oauth` - High-risk OAuth applications
- `inactive_users` - Inactive user accounts
- `external_members` - External group members
- `stale_files` - Files not accessed recently
- `external_owned_files` - Files owned by external users
- `security_score` - Overall security score (0-100)
- `compliance_score` - Compliance score (0-100)

---

### Custom PII Patterns

```bash
# Add custom pattern
vaulytica custom-pii add \
  --name "Employee ID" \
  --pattern "EMP-\d{6}" \
  --category "CUSTOM"

# List patterns
vaulytica custom-pii list

# Remove pattern
vaulytica custom-pii remove --name "Employee ID"
```

---

### Configuration & Testing

```bash
# Interactive setup wizard
vaulytica init

# Test connection
vaulytica test

# Show configuration
vaulytica config

# Show version
vaulytica version
```

---

## Required OAuth Scopes

### READ-ONLY Scopes (Recommended for Security Scanning)

```
# User & Group Management
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.orgunit.readonly

# Device Management
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly

# Resource Management
https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly

# Data Access
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/gmail.settings.basic.readonly
https://www.googleapis.com/auth/calendar.readonly

# Audit & Compliance
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/ediscovery.readonly

# Licensing
https://www.googleapis.com/auth/apps.licensing
```

### READ & WRITE Scopes (Required for User/Resource Management)

Only add these if you need to create, modify, or delete users and resources:

```
# User & Group Management
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/admin.directory.group
https://www.googleapis.com/auth/admin.directory.orgunit

# Resource Management
https://www.googleapis.com/auth/admin.directory.resource.calendar

# Data Management
https://www.googleapis.com/auth/drive
```

---

## Complete Setup Guide

### Step 1: Create Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the following APIs:
   - Admin SDK API
   - Google Drive API
   - Gmail API
   - Calendar API
   - Reports API
4. Navigate to IAM & Admin > Service Accounts
5. Click "Create Service Account"
6. Download the JSON key file and store it securely

### Step 2: Enable Domain-Wide Delegation

1. Go to [Google Admin Console](https://admin.google.com/)
2. Navigate to Security > API Controls > Domain-wide Delegation
3. Click "Add new"
4. Enter your service account client ID (from the JSON key file)
5. Add the OAuth scopes listed above
6. Click "Authorize"

### Step 3: Configure Vaulytica

```bash
# Copy example configuration
cp config.example.yaml config.yaml

# Edit configuration
nano config.yaml
```

Minimum configuration:

```yaml
google_workspace:
  domain: "yourcompany.com"
  credentials_file: "/path/to/service-account.json"
  impersonate_user: "admin@yourcompany.com"
```

### Step 4: Test Setup

```bash
poetry run vaulytica test
```

Expected output:
```
Configuration loaded successfully
Credentials validated
API connection successful
Domain access confirmed
```

---

## Common Use Cases

### Security Team: Daily Security Monitoring

```bash
# Morning security scan
vaulytica scan files --external-only --check-pii --output daily-pii-scan.csv
vaulytica scan oauth-apps --min-risk-score 70 --output oauth-audit.csv
vaulytica scan audit-logs --days-back 1 --detect-anomalies

# Find stale content for cleanup
vaulytica scan stale-drives --days 180 --output stale-content.csv

# Identify external ownership risks
vaulytica scan external-owned --output external-owned.csv
```

### Compliance Team: Quarterly Audit

```bash
# Generate compliance reports
vaulytica compliance report --framework gdpr --output gdpr-q1.html
vaulytica compliance report --framework hipaa --output hipaa-q1.html
vaulytica compliance report --framework soc2 --output soc2-q1.html

# Security posture baseline
vaulytica security-posture assess --output security-baseline.json
```

### IT Admin: Employee Onboarding

```bash
# Create new user
vaulytica users create john.doe@company.com \
  --first-name John \
  --last-name Doe \
  --password "TempPass123!" \
  --org-unit "/Engineering"
```

### IT Admin: Employee Offboarding

```bash
# Automated secure offboarding
vaulytica offboard john.doe@company.com \
  --transfer-to manager@company.com \
  --execute
```

### IT Admin: Cost Optimization

```bash
# Find unused licenses
vaulytica scan licenses --unused-days 90 --show-recommendations

# Find stale content consuming storage
vaulytica scan stale-drives --days 365 --output year-old-content.csv
```

### Security Team: Jira Integration

```bash
# Create issues from critical findings
vaulytica jira create-from-scan --scan-type files --min-severity critical

# Weekly security summary
vaulytica jira weekly-report
```

---

## Test Suite

Vaulytica includes a comprehensive test suite with 535+ tests.

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=vaulytica --cov-report=html

# Run specific test files
poetry run pytest tests/scanners/
poetry run pytest tests/integrations/test_jira.py
```

---

## Architecture

Vaulytica is built with a modular architecture:

```
vaulytica/
  core/
    scanners/       # 13 security scanners
    analyzers/      # Security posture and shadow IT analysis
    reporters/      # HTML, CSV, JSON report generation
  integrations/     # Jira, Slack, webhook integrations
  cli/
    commands/       # Click CLI command implementations
  config/           # Configuration loading and validation
```

---

## Contributing

Contributions are welcome. Please read the contributing guidelines before submitting pull requests.

---

## License

See LICENSE file for details.

---

## Support

For issues and feature requests, please use the GitHub issue tracker.

---

**Vaulytica** - Enterprise-Grade Google Workspace Security
