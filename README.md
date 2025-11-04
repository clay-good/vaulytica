# Vaulytica 

**Complete Google Workspace Security, Compliance & IT Administration**

---

## What is Vaulytica?

A powerful, self-hosted Python CLI tool for comprehensive security monitoring, compliance management, and IT automation for Google Workspace.

> **"24/7 security monitoring for your entire Google Workspace environment—detect PII in shared files, audit OAuth apps, track user activity, enforce compliance policies, and get real-time alerts. All automated and self-hosted."**

**For Security Teams**: Detect data leaks, audit access controls, monitor suspicious activity
**For Compliance Teams**: Automated GDPR/HIPAA/SOC2/PCI-DSS/FERPA/FedRAMP reporting
**For IT Admins**: Employee lifecycle automation, bulk operations, comprehensive visibility
**For Executives**: Risk dashboards, compliance scorecards, trend analysis

### Key Features

- 🔍 **13 Security Scanners** - Files, OAuth apps, users, groups, mobile devices, Chrome OS, Gmail, audit logs, calendar, Vault, shared drives, licenses, Gmail security
- 👥 **User Lifecycle Management** - Create, update, suspend, restore, delete users with bulk operations
- 🏢 **Organizational Management** - Full CRUD operations for OUs and calendar resources
- 💾 **Backup & Export** - Automated backups of users, groups, and organizational structure
- 📊 **Compliance Reporting** - GDPR, HIPAA, SOC2, PCI-DSS, FERPA, FedRAMP
- 🚨 **Real-time Monitoring** - Health checks, Prometheus metrics, automated alerts
- 🔄 **Automated Workflows** - Scheduled scans, employee offboarding, PII detection alerts
- 🎨 **Custom PII Detection** - Industry-specific patterns with 20+ built-in detectors
- 📈 **HTML Dashboards** - Executive-friendly reports with charts and visualizations
- 🌐 **Multi-Domain Support** - Manage multiple Google Workspace domains
- ✅ **535 Tests** - 100% passing with comprehensive coverage

---

## 🚀 Quick Start

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

### Setup & First Scan

```bash
# 1. Configure credentials (see Setup Guide below)
cp examples/basic-config.yaml config.yaml
# Edit config.yaml with your service account details

# 2. Test authentication
poetry run vaulytica test

# 3. Run your first READ-ONLY scan
poetry run vaulytica scan files --external-only --output report.csv

# 4. Check for PII in shared files (READ-ONLY)
poetry run vaulytica scan files --check-pii --external-only
```

**Prerequisites**: Python 3.9+, Google Workspace, Admin access, Service account with domain-wide delegation

---

## 📋 Complete Command Reference

### Quick Reference Table

| Command Group | Commands | Access Level | Use Case |
|--------------|----------|--------------|----------|
| **scan** | 13 scanners | READ-ONLY ✅ | Security scanning & auditing |
| **users** | create, update, suspend, restore, delete | READ & WRITE ⚠️ | User provisioning |
| **bulk** | create-users, suspend-users, export-users | READ & WRITE ⚠️ | Bulk operations |
| **offboard** | user | READ & WRITE ⚠️ | Employee offboarding |
| **ou** | list, get, create, update, delete | READ & WRITE ⚠️ | OU management |
| **resources** | list, get, create, update, delete | READ & WRITE ⚠️ | Calendar resources |
| **backup** | users, groups, org-units, full, list | READ-ONLY ✅ | Data backup |
| **compliance** | report | READ-ONLY ✅ | Compliance reporting |
| **monitor** | health | READ-ONLY ✅ | System health |
| **metrics** | export, serve | READ-ONLY ✅ | Prometheus metrics |
| **workflow** | external-pii-alert, gmail-external-pii-alert | READ-ONLY + Alerts | Automated workflows |
| **schedule** | add, list, run | READ-ONLY ✅ | Scheduled scans |
| **custom-pii** | add, list, remove | Configuration ⚙️ | Custom PII patterns |
| **report** | generate | READ-ONLY ✅ | HTML dashboards |
| **init** | - | Configuration ⚙️ | Setup wizard |
| **test** | - | READ-ONLY ✅ | Connection test |
| **config** | - | READ-ONLY ✅ | View config |
| **version** | - | READ-ONLY ✅ | Version info |

---

### 🔍 **Security Scanning Commands** (READ-ONLY)

All scanning commands are **READ-ONLY** and safe to run anytime. They do NOT modify your Google Workspace.

#### 1. **Scan Files** - Find externally shared files with PII 🔥 Most Popular

```bash
# Scan all externally shared files for PII
vaulytica scan files --external-only --check-pii --output pii-report.csv

# Scan specific user's files
vaulytica scan files --user user@company.com --check-pii

# Scan with max file limit (for testing)
vaulytica scan files --max-files 100 --external-only
```

**Why it's important**: Detects sensitive data (SSN, credit cards, bank accounts) shared outside your organization
**Permissions**: `drive.readonly`, `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

#### 2. **Scan OAuth Apps** - Audit third-party access

```bash
# Find high-risk OAuth apps
vaulytica scan oauth-apps --min-risk-score 70 --output oauth-report.csv

# Scan specific user's OAuth tokens
vaulytica scan oauth-apps --user user@company.com
```

**Why it's important**: Identifies risky third-party apps with excessive permissions
**Permissions**: `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

#### 3. **Scan Users** - Find inactive users & 2FA compliance

```bash
# Find inactive users (90+ days)
vaulytica scan users --inactive-days 90 --output users-report.csv

# Check 2FA compliance
vaulytica scan users --check-2fa

# Find admin users
vaulytica scan users --admins-only
```

**Why it's important**: Identifies security risks from inactive accounts and missing 2FA
**Permissions**: `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

#### 4. **Scan Groups** - Audit external members & public groups

```bash
# Find groups with external members
vaulytica scan groups --external-members --output groups-report.csv

# Find public groups
vaulytica scan groups --public-groups

# Find orphaned groups (no owners)
vaulytica scan groups --orphaned
```

**Why it's important**: Prevents data leaks through group memberships
**Permissions**: `admin.directory.group.readonly`
**Access**: READ-ONLY ✅

---

#### 5. **Scan Mobile Devices** - Security & compliance checks

```bash
# Scan all mobile devices
vaulytica scan devices --output devices-report.csv

# Find inactive devices
vaulytica scan devices --inactive-days 90

# Find devices without passwords
vaulytica scan devices --no-password
```

**Why it's important**: Identifies compromised, unencrypted, or inactive mobile devices
**Permissions**: `admin.directory.device.mobile.readonly`
**Access**: READ-ONLY ✅

---

#### 6. **Scan Chrome Devices** - Chromebook security

```bash
# Scan all Chrome OS devices
vaulytica scan chrome-devices --output chrome-report.csv

# Scan specific org unit
vaulytica scan chrome-devices --org-unit "/Students"

# Find inactive Chromebooks
vaulytica scan chrome-devices --inactive-days 90
```

**Why it's important**: Finds Chromebooks with expired auto-updates or developer mode
**Permissions**: `admin.directory.device.chromeos.readonly`
**Access**: READ-ONLY ✅

---

#### 7. **Scan Gmail** - Email attachments & PII

```bash
# Scan Gmail attachments for PII
vaulytica scan gmail --days-back 30 --check-pii --output gmail-report.csv

# Scan specific users
vaulytica scan gmail --user user1@company.com --user user2@company.com

# External emails only
vaulytica scan gmail --external-only --days-back 7
```

**Why it's important**: Detects PII in email attachments sent externally
**Permissions**: `gmail.readonly`, `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

#### 8. **Scan Gmail Security** - Delegates, forwarding, filters

```bash
# Check for email delegates
vaulytica scan gmail-security --delegates --output delegates-report.csv

# Check auto-forwarding rules
vaulytica scan gmail-security --forwarding

# Check send-as aliases
vaulytica scan gmail-security --send-as

# Check all security settings
vaulytica scan gmail-security --delegates --forwarding --send-as --filters
```

**Why it's important**: Detects unauthorized email access and forwarding rules
**Permissions**: `gmail.settings.basic.readonly`
**Access**: READ-ONLY ✅

---

#### 9. **Scan Audit Logs** - Suspicious activity detection

```bash
# Scan recent audit logs
vaulytica scan audit-logs --days-back 7 --output audit-report.csv

# Detect anomalies
vaulytica scan audit-logs --detect-anomalies --days-back 30

# Specific event types
vaulytica scan audit-logs --event-type admin --days-back 7
```

**Why it's important**: Detects suspicious admin activity and security events
**Permissions**: `admin.reports.audit.readonly`
**Access**: READ-ONLY ✅

---

#### 10. **Scan Calendar** - Public calendars & PII

```bash
# Scan calendars for PII
vaulytica scan calendar --check-pii --output calendar-report.csv

# Check for public calendars
vaulytica scan calendar --days-ahead 30

# Scan specific users
vaulytica scan calendar --user user@company.com
```

**Why it's important**: Finds calendar events with PII or public sharing
**Permissions**: `calendar.readonly`, `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

#### 11. **Scan Shared Drives** - Team Drive security

```bash
# Scan all Shared Drives
vaulytica scan shared-drives --output shared-drives-report.csv

# Scan files in Shared Drives
vaulytica scan shared-drives --scan-files --check-pii

# External sharing only
vaulytica scan shared-drives --external-only
```

**Why it's important**: Audits Team Drive permissions and external sharing
**Permissions**: `drive.readonly`
**Access**: READ-ONLY ✅

---

#### 12. **Scan Licenses** - Cost optimization

```bash
# Scan license usage
vaulytica scan licenses --output licenses-report.csv

# Find unused licenses
vaulytica scan licenses --unused-days 90 --show-recommendations

# Cost analysis
vaulytica scan licenses --show-recommendations
```

**Why it's important**: Identifies unused licenses to reduce costs
**Permissions**: `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

#### 13. **Scan Vault** - Legal holds & retention

```bash
# Scan Vault matters
vaulytica scan vault --output vault-report.csv

# Check legal holds
vaulytica scan vault --check-holds

# Specific matter
vaulytica scan vault --matter-id <matter-id>
```

**Why it's important**: Audits legal holds and retention policies
**Permissions**: `ediscovery.readonly`
**Access**: READ-ONLY ✅

---

### ✏️ **User Management Commands** (READ & WRITE)

⚠️ **Warning**: These commands MODIFY your Google Workspace. Use with caution!

#### 14. **Create User** - Provision new employee

```bash
# Create new user
vaulytica users create john.doe@company.com \
  --first-name John \
  --last-name Doe \
  --password "TempPass123!" \
  --org-unit "/Engineering"
```

**Why it's important**: Automates employee onboarding
**Permissions**: `admin.directory.user` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 15. **Update User** - Modify user account

```bash
# Update user details
vaulytica users update user@company.com \
  --first-name John \
  --last-name Smith \
  --org-unit "/Sales"
```

**Why it's important**: Updates employee information
**Permissions**: `admin.directory.user` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 16. **Suspend User** - Block account access

```bash
# Suspend user immediately
vaulytica users suspend user@company.com
```

**Why it's important**: Immediately blocks compromised or terminated accounts
**Permissions**: `admin.directory.user` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 17. **Restore User** - Reactivate suspended account

```bash
# Restore suspended user
vaulytica users restore user@company.com
```

**Why it's important**: Reactivates accidentally suspended accounts
**Permissions**: `admin.directory.user` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 18. **Delete User** - Permanently remove account

```bash
# Delete user (permanent!)
vaulytica users delete user@company.com
```

**Why it's important**: Removes terminated employee accounts
**Permissions**: `admin.directory.user` (READ & WRITE)
**Access**: READ & WRITE ⚠️ **PERMANENT**

---

### 📦 **Bulk Operations** (READ & WRITE)

#### 19. **Bulk Create Users** - Create multiple users from CSV

```bash
# Dry-run first (READ-ONLY)
vaulytica bulk create-users users.csv --dry-run

# Execute (WRITE)
vaulytica bulk create-users users.csv
```

**CSV Format**: `email,first_name,last_name,password,org_unit`
**Why it's important**: Automates mass employee onboarding
**Permissions**: `admin.directory.user` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 20. **Bulk Suspend Users** - Suspend multiple users from CSV

```bash
# Dry-run first (READ-ONLY)
vaulytica bulk suspend-users users.csv --dry-run

# Execute (WRITE)
vaulytica bulk suspend-users users.csv
```

**CSV Format**: `email`
**Why it's important**: Mass account suspension for security incidents
**Permissions**: `admin.directory.user` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 21. **Export Users** - Export all users to CSV

```bash
# Export all users
vaulytica bulk export-users --output all-users.csv
```

**Why it's important**: Backup user data or migrate to other systems
**Permissions**: `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

### 👋 **Employee Offboarding** (READ & WRITE)

#### 22. **Offboard User** - Automated employee offboarding

```bash
# Dry-run first (READ-ONLY)
vaulytica offboard user@company.com \
  --transfer-to manager@company.com \
  --dry-run

# Execute (WRITE)
vaulytica offboard user@company.com \
  --transfer-to manager@company.com \
  --execute
```

**What it does**:
1. Suspends user account
2. Transfers Drive file ownership
3. Removes from all groups
4. Revokes OAuth tokens
5. Backs up user data

**Why it's important**: Ensures secure employee termination
**Permissions**: `admin.directory.user`, `drive` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

### 🏢 **Organizational Unit Management** (READ & WRITE)

#### 23. **List OUs** - View organizational structure

```bash
# List all OUs
vaulytica ou list

# Filter by parent
vaulytica ou list --parent "/Engineering"

# Export to CSV
vaulytica ou list --output ous.csv
```

**Why it's important**: Understand organizational structure
**Permissions**: `admin.directory.orgunit.readonly`
**Access**: READ-ONLY ✅

---

#### 24. **Create OU** - Create organizational unit

```bash
# Create new OU
vaulytica ou create "Engineering" \
  --parent "/" \
  --description "Engineering team"
```

**Why it's important**: Organize users by department
**Permissions**: `admin.directory.orgunit` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 25. **Update OU** - Modify organizational unit

```bash
# Update OU
vaulytica ou update "/Engineering" \
  --name "Engineering Team" \
  --description "Updated description"
```

**Why it's important**: Maintain organizational structure
**Permissions**: `admin.directory.orgunit` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 26. **Delete OU** - Remove organizational unit

```bash
# Delete OU
vaulytica ou delete "/Engineering" --confirm
```

**Why it's important**: Clean up unused organizational units
**Permissions**: `admin.directory.orgunit` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

### 🏢 **Calendar Resource Management** (READ & WRITE)

#### 27. **List Resources** - View conference rooms & equipment

```bash
# List all resources
vaulytica resources list

# Export to CSV
vaulytica resources list --output resources.csv
```

**Why it's important**: Manage conference rooms and equipment
**Permissions**: `admin.directory.resource.calendar.readonly`
**Access**: READ-ONLY ✅

---

#### 28. **Create Resource** - Add conference room

```bash
# Create conference room
vaulytica resources create "Conference Room A" \
  --type CONFERENCE_ROOM \
  --capacity 10 \
  --building "Building-1" \
  --floor "2nd Floor"
```

**Why it's important**: Manage bookable resources
**Permissions**: `admin.directory.resource.calendar` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 29. **Update Resource** - Modify resource details

```bash
# Update resource
vaulytica resources update <resource-id> \
  --capacity 12 \
  --description "Updated room"
```

**Why it's important**: Keep resource information current
**Permissions**: `admin.directory.resource.calendar` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

#### 30. **Delete Resource** - Remove resource

```bash
# Delete resource
vaulytica resources delete <resource-id> --confirm
```

**Why it's important**: Remove decommissioned resources
**Permissions**: `admin.directory.resource.calendar` (READ & WRITE)
**Access**: READ & WRITE ⚠️

---

### 💾 **Backup & Export** (READ-ONLY)

#### 31. **Backup Users** - Export all user data

```bash
# Backup users to JSON
vaulytica backup users --format json --backup-dir ./backups

# Backup to CSV
vaulytica backup users --format csv
```

**Why it's important**: Regular backups for disaster recovery
**Permissions**: `admin.directory.user.readonly`
**Access**: READ-ONLY ✅

---

#### 32. **Backup Groups** - Export all group data

```bash
# Backup groups
vaulytica backup groups --format json --backup-dir ./backups
```

**Why it's important**: Backup group configurations
**Permissions**: `admin.directory.group.readonly`
**Access**: READ-ONLY ✅

---

#### 33. **Backup OUs** - Export organizational structure

```bash
# Backup organizational units
vaulytica backup org-units --format json --backup-dir ./backups
```

**Why it's important**: Backup organizational structure
**Permissions**: `admin.directory.orgunit.readonly`
**Access**: READ-ONLY ✅

---

#### 34. **Full Backup** - Backup everything

```bash
# Full backup (users, groups, OUs)
vaulytica backup full --format json --backup-dir ./backups
```

**Why it's important**: Complete disaster recovery backup
**Permissions**: Multiple readonly scopes
**Access**: READ-ONLY ✅

---

#### 35. **List Backups** - View backup history

```bash
# List all backups
vaulytica backup list --backup-dir ./backups
```

**Why it's important**: Track backup history
**Permissions**: None (local files)
**Access**: READ-ONLY ✅

---

### 📊 **Compliance Reporting** (READ-ONLY)

#### 36. **Generate Compliance Report** - GDPR, HIPAA, SOC2, etc.

```bash
# GDPR compliance report
vaulytica compliance report --framework gdpr --output gdpr-report.html

# HIPAA compliance report
vaulytica compliance report --framework hipaa --output hipaa-report.html

# SOC 2 compliance report
vaulytica compliance report --framework soc2 --output soc2-report.html
```

**Supported Frameworks**: GDPR, HIPAA, SOC2, PCI-DSS, FERPA, FedRAMP
**Why it's important**: Automated compliance reporting
**Permissions**: Multiple readonly scopes
**Access**: READ-ONLY ✅

---

### 📈 **Monitoring & Alerting** (READ-ONLY)

#### 37. **Health Check** - System health status

```bash
# Check system health
vaulytica monitor health
```

**Why it's important**: Verify Vaulytica is working correctly
**Permissions**: None (local check)
**Access**: READ-ONLY ✅

---

#### 38. **Export Metrics** - Prometheus metrics

```bash
# Export metrics
vaulytica metrics export --output metrics.txt

# Export as JSON
vaulytica metrics export --format json --output metrics.json
```

**Why it's important**: Monitor Vaulytica performance
**Permissions**: None (local metrics)
**Access**: READ-ONLY ✅

---

#### 39. **Serve Metrics** - Prometheus HTTP endpoint

```bash
# Start metrics server
vaulytica metrics serve --port 9090
```

**Why it's important**: Integrate with Prometheus monitoring
**Permissions**: None (local server)
**Access**: READ-ONLY ✅

---

### 🔄 **Automated Workflows** (READ-ONLY + Alerts)

#### 40. **External PII Alert Workflow** - Automated PII detection & alerts

```bash
# Scan for external PII and send alerts
vaulytica workflow external-pii-alert \
  --domain company.com \
  --alert-email security@company.com \
  --alert-webhook https://siem.company.com/webhook
```

**Why it's important**: Automated security monitoring
**Permissions**: `drive.readonly` + alert permissions
**Access**: READ-ONLY (scans) + WRITE (sends alerts) ⚠️

---

#### 41. **Gmail External PII Alert** - Email attachment monitoring

```bash
# Scan Gmail for external PII
vaulytica workflow gmail-external-pii-alert \
  --domain company.com \
  --user user@company.com \
  --days-back 7 \
  --alert-email security@company.com
```

**Why it's important**: Monitor email attachments for data leaks
**Permissions**: `gmail.readonly` + alert permissions
**Access**: READ-ONLY (scans) + WRITE (sends alerts) ⚠️

---

### ⏰ **Scheduled Scanning** (READ-ONLY)

#### 42. **Schedule Scan** - Automated recurring scans

```bash
# Schedule daily file scan
vaulytica schedule add \
  --name "daily-file-scan" \
  --command "scan files --external-only --check-pii" \
  --cron "0 2 * * *"  # 2 AM daily
```

**Why it's important**: Continuous security monitoring
**Permissions**: Same as scheduled command
**Access**: READ-ONLY (for scans) ✅

---

#### 43. **List Schedules** - View scheduled scans

```bash
# List all scheduled scans
vaulytica schedule list
```

**Why it's important**: Manage automated scans
**Permissions**: None (local config)
**Access**: READ-ONLY ✅

---

### 🎨 **Custom PII Patterns** (Configuration)

#### 44. **Add Custom PII Pattern** - Industry-specific detection

```bash
# Add custom pattern
vaulytica custom-pii add \
  --name "Employee ID" \
  --pattern "EMP-\d{6}" \
  --category "CUSTOM"
```

**Why it's important**: Detect industry-specific sensitive data
**Permissions**: None (local config)
**Access**: Configuration ⚙️

---

#### 45. **List Custom Patterns** - View custom patterns

```bash
# List all custom patterns
vaulytica custom-pii list
```

**Why it's important**: Manage custom PII detection
**Permissions**: None (local config)
**Access**: READ-ONLY ✅

---

### 📄 **Report Generation** (READ-ONLY)

#### 46. **Generate HTML Dashboard** - Visual reports

```bash
# Generate HTML dashboard
vaulytica report generate --format html --output dashboard.html
```

**Why it's important**: Executive-friendly security reports
**Permissions**: None (uses existing scan data)
**Access**: READ-ONLY ✅

---

### 🔧 **Configuration & Testing**

#### 47. **Initialize Config** - Setup wizard

```bash
# Interactive setup
vaulytica init
```

**Why it's important**: Easy initial configuration
**Permissions**: None (local config)
**Access**: Configuration ⚙️

---

#### 48. **Test Connection** - Verify setup

```bash
# Test Google Workspace connection
vaulytica test
```

**Why it's important**: Verify credentials and permissions
**Permissions**: Minimal (connection test)
**Access**: READ-ONLY ✅

---

#### 49. **Show Config** - View current configuration

```bash
# Display current config
vaulytica config
```

**Why it's important**: Verify configuration
**Permissions**: None (local config)
**Access**: READ-ONLY ✅

---

#### 50. **Version Info** - Show version

```bash
# Show version
vaulytica version
```

**Why it's important**: Track Vaulytica version
**Permissions**: None
**Access**: READ-ONLY ✅

---

## 🔑 Required OAuth Scopes

### READ-ONLY Scopes (Safe for security scanning)

Use these scopes if you only want to **scan and monitor** without making changes:

```
# User & Group Management (READ-ONLY)
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.orgunit.readonly

# Device Management (READ-ONLY)
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly

# Resource Management (READ-ONLY)
https://www.googleapis.com/auth/admin.directory.resource.calendar.readonly

# Data Access (READ-ONLY)
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/gmail.settings.basic.readonly
https://www.googleapis.com/auth/calendar.readonly

# Audit & Compliance (READ-ONLY)
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/ediscovery.readonly

# Licensing (READ-ONLY)
https://www.googleapis.com/auth/apps.licensing
```

### READ & WRITE Scopes (Required for user/resource management)

⚠️ **Only add these if you need to create/modify/delete users, groups, or resources:**

```
# User & Group Management (READ & WRITE)
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/admin.directory.group
https://www.googleapis.com/auth/admin.directory.orgunit

# Resource Management (READ & WRITE)
https://www.googleapis.com/auth/admin.directory.resource.calendar

# Data Management (READ & WRITE)
https://www.googleapis.com/auth/drive
```

### Scope Recommendations by Use Case

| Use Case | Required Scopes | Access Level |
|----------|----------------|--------------|
| **Security Scanning Only** | All `.readonly` scopes | READ-ONLY ✅ |
| **Compliance Reporting** | All `.readonly` scopes | READ-ONLY ✅ |
| **User Provisioning** | `admin.directory.user` | READ & WRITE ⚠️ |
| **Employee Offboarding** | `admin.directory.user`, `drive` | READ & WRITE ⚠️ |
| **OU Management** | `admin.directory.orgunit` | READ & WRITE ⚠️ |
| **Resource Management** | `admin.directory.resource.calendar` | READ & WRITE ⚠️ |

**⚠️ Important**: If you only want READ-ONLY scanning, use only the `.readonly` scopes above!

---

## 📖 Complete Setup Guide

### Step 1: Create Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable APIs:
   - Admin SDK API
   - Google Drive API
   - Gmail API
   - Calendar API
   - Reports API
4. Create Service Account:
   - IAM & Admin → Service Accounts → Create
   - Download JSON key file

### Step 2: Enable Domain-Wide Delegation

1. Go to [Google Admin Console](https://admin.google.com/)
2. Security → API Controls → Domain-wide Delegation
3. Add your service account client ID
4. Add OAuth scopes (see above)
5. Click "Authorize"

### Step 3: Configure Vaulytica

```bash
# Copy example config
cp examples/basic-config.yaml config.yaml

# Edit config.yaml
nano config.yaml
```

```yaml
google_workspace:
  domain: "yourcompany.com"
  credentials_file: "/path/to/service-account.json"
  impersonate_user: "admin@yourcompany.com"  # Admin user to impersonate
```

### Step 4: Test Setup

```bash
poetry run vaulytica test
```

Expected output:
```
✓ Configuration loaded successfully
✓ Credentials validated
✓ API connection successful
✓ Domain access confirmed
```

---

## 🎯 Common Use Cases

### For Security Teams

**Daily Security Scan**:
```bash
# Scan for external PII exposure
vaulytica scan files --external-only --check-pii --output daily-pii-scan.csv

# Audit OAuth apps
vaulytica scan oauth-apps --min-risk-score 70 --output oauth-audit.csv

# Check for suspicious activity
vaulytica scan audit-logs --days-back 1 --detect-anomalies
```

**Automated Monitoring**:
```bash
# Schedule daily scans
vaulytica schedule add --name "daily-security-scan" \
  --command "workflow external-pii-alert --alert-email security@company.com" \
  --cron "0 2 * * *"
```

### For Compliance Teams

**Quarterly Compliance Reports**:
```bash
# Generate GDPR report
vaulytica compliance report --framework gdpr --output gdpr-q1-2024.html

# Generate HIPAA report
vaulytica compliance report --framework hipaa --output hipaa-q1-2024.html

# Generate SOC 2 report
vaulytica compliance report --framework soc2 --output soc2-q1-2024.html
```

### For IT Admins

**Employee Onboarding**:
```bash
# Create new user
vaulytica users create john.doe@company.com \
  --first-name John --last-name Doe \
  --password "TempPass123!" --org-unit "/Engineering"
```

**Employee Offboarding**:
```bash
# Automated offboarding
vaulytica offboard john.doe@company.com \
  --transfer-to manager@company.com --execute
```

**Bulk Operations**:
```bash
# Create multiple users from CSV
vaulytica bulk create-users new-hires.csv

# Export all users for backup
vaulytica bulk export-users --output all-users-backup.csv
```

### For Executives

**Monthly Dashboard**:
```bash
# Generate HTML dashboard
vaulytica report generate --format html --output monthly-dashboard.html
```

