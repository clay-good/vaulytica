# Getting Started with Vaulytica

Welcome to Vaulytica! This guide will help you get up and running in minutes.

---

## Table of Contents

1. [What is Vaulytica?](#what-is-vaulytica)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Google Workspace Setup](#google-workspace-setup)
5. [Configuration](#configuration)
6. [Your First Scan](#your-first-scan)
7. [Common Use Cases](#common-use-cases)
8. [Next Steps](#next-steps)

---

## What is Vaulytica?

Vaulytica is an open-source security monitoring tool for Google Workspace that helps you:

- 🔍 **Detect PII** in files and emails (SSN, credit cards, medical records, etc.)
- 🔒 **Monitor external sharing** and identify security risks
- 👥 **Audit user activity** and find inactive accounts
- 📧 **Scan Gmail attachments** for sensitive data
- 🤖 **Automate security workflows** with scheduled scans
- 📊 **Generate compliance reports** for HIPAA, SOC2, GDPR, etc.

---

## Prerequisites

### Required

- **Python 3.10 or higher**
- **Google Workspace Admin account**
- **Poetry** (for dependency management)

### Check Your Python Version

```bash
python3 --version
# Should show Python 3.10.0 or higher
```

### Install Poetry

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

---

## Installation

### Option 1: Install from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/clay-good/vaulytica.git
cd vaulytica

# Install dependencies
poetry install

# Verify installation
poetry run vaulytica --version
```

### Option 2: Install with pip (Coming Soon)

```bash
pip install vaulytica
```

---

## Google Workspace Setup

### Step 1: Create a Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Navigate to **IAM & Admin** → **Service Accounts**
4. Click **Create Service Account**
5. Name it `vaulytica` and click **Create**
6. Skip granting roles (click **Continue**)
7. Click **Done**

### Step 2: Create Service Account Key

1. Click on the service account you just created
2. Go to **Keys** tab
3. Click **Add Key** → **Create new key**
4. Choose **JSON** format
5. Click **Create**
6. Save the downloaded JSON file securely (e.g., `service-account.json`)

⚠️ **Important:** Keep this file secure! Never commit it to version control.

### Step 3: Enable Required APIs

Enable these APIs in your Google Cloud project:

1. [Admin SDK API](https://console.cloud.google.com/apis/library/admin.googleapis.com)
2. [Google Drive API](https://console.cloud.google.com/apis/library/drive.googleapis.com)
3. [Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com)

### Step 4: Enable Domain-Wide Delegation

1. In the service account details, click **Show Domain-Wide Delegation**
2. Check **Enable Google Workspace Domain-wide Delegation**
3. Click **Save**
4. Copy the **Client ID** (you'll need this next)

### Step 5: Authorize in Google Workspace Admin

1. Go to [Google Workspace Admin Console](https://admin.google.com/)
2. Navigate to **Security** → **API Controls** → **Domain-wide Delegation**
3. Click **Add new**
4. Paste the **Client ID** from Step 4
5. Add these OAuth scopes (comma-separated):

```
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/drive.readonly,
https://www.googleapis.com/auth/gmail.readonly,
https://www.googleapis.com/auth/admin.directory.domain.readonly
```

6. Click **Authorize**

✅ **Done!** Your service account now has access to Google Workspace.

---

## Configuration

### Step 1: Create Configuration File

```bash
# Copy example configuration
cp examples/basic-config.yaml config.yaml
```

### Step 2: Edit Configuration

Open `config.yaml` and update these values:

```yaml
google_workspace:
  # Your Google Workspace domain
  domain: "example.com"  # ← Change this
  
  # Admin email for domain-wide delegation
  admin_email: "admin@example.com"  # ← Change this
  
  # Path to service account JSON file
  service_account_file: "service-account.json"  # ← Update path

scanning:
  batch_size: 100
  rate_limit_delay: 0.1
  enable_cache: true

pii_detection:
  enabled: true
  confidence_threshold: 0.5
  patterns:
    - ssn
    - credit_card
    - email
    - phone

integrations:
  email:
    enabled: false  # Enable later
```

### Step 3: Test Configuration

```bash
poetry run vaulytica test --test-auth
```

You should see:
```
✓ Authentication successful
✓ Domain access verified
✓ API permissions confirmed
```

---

## Your First Scan

### Scan for External File Shares

```bash
poetry run vaulytica scan files --external-only
```

**What this does:**
- Scans all Google Drive files
- Finds files shared with external users
- Shows risk scores and sharing details

**Example output:**
```
Found 15 files with sharing issues:

┌─────────────────────────┬──────────────┬────────────┐
│ File Name               │ Owner        │ Risk Score │
├─────────────────────────┼──────────────┼────────────┤
│ Q4 Financial Report.pdf │ john@ex.com  │ 0.85       │
│ Customer Database.xlsx  │ jane@ex.com  │ 0.92       │
└─────────────────────────┴──────────────┴────────────┘
```

### Scan for PII in Files

```bash
poetry run vaulytica scan files --external-only --check-pii
```

**What this does:**
- Scans externally shared files
- Detects PII (SSN, credit cards, etc.)
- Shows confidence scores

**Example output:**
```
Found 3 files with PII:

File: Customer_List.xlsx
  - SSN: ***-**-1234 (confidence: 0.95)
  - Credit Card: ****-****-****-5678 (confidence: 0.89)
```

### Scan for Inactive Users

```bash
poetry run vaulytica scan users --inactive-days 90
```

**What this does:**
- Finds users inactive for 90+ days
- Shows last login time
- Identifies potential security risks

---

## Common Use Cases

### Use Case 1: Daily Security Scan

**Goal:** Monitor external sharing and PII daily

**Command:**
```bash
poetry run vaulytica scan files \
  --external-only \
  --check-pii \
  --incremental \
  --output daily-scan.csv \
  --format csv
```

**Schedule with cron:**
```bash
# Run daily at 2 AM
0 2 * * * cd /path/to/vaulytica && poetry run vaulytica scan files --external-only --check-pii --incremental
```

### Use Case 2: Employee Offboarding

**Goal:** Transfer files and revoke access when employee leaves

**Command:**
```bash
poetry run vaulytica offboard user \
  --email departing@example.com \
  --transfer-to manager@example.com \
  --suspend
```

**What this does:**
- Transfers file ownership to manager
- Suspends the user account
- Generates offboarding report

### Use Case 3: Compliance Reporting

**Goal:** Generate monthly compliance report

**Command:**
```bash
poetry run vaulytica compliance report \
  --standard hipaa \
  --output compliance-report.pdf \
  --format pdf
```

### Use Case 4: Auto-Expire External Shares

**Goal:** Automatically expire external shares after 30 days

**Command:**
```bash
poetry run vaulytica policy apply \
  --policy auto-expire \
  --days 30 \
  --notify
```

### Use Case 5: Gmail Attachment Scanning

**Goal:** Scan Gmail attachments for PII

**Command:**
```bash
poetry run vaulytica scan gmail \
  --days-back 7 \
  --check-attachments \
  --check-pii
```

---

## Next Steps

### 1. Enable Email Alerts

Update `config.yaml`:

```yaml
integrations:
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "alerts@example.com"
    smtp_password: "your-app-password"
    from_address: "vaulytica@example.com"
    to_addresses:
      - "security-team@example.com"
```

Test email:
```bash
poetry run vaulytica test --test-email
```

### 2. Set Up Automated Workflows

Run the external PII alert workflow:
```bash
poetry run vaulytica workflow run external-pii-alert
```

Schedule it:
```bash
# Add to crontab
0 */6 * * * cd /path/to/vaulytica && poetry run vaulytica workflow run external-pii-alert
```

### 3. Enable Slack Notifications

Update `config.yaml`:

```yaml
integrations:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    channel: "#security-alerts"
```

### 4. Explore Advanced Features

- **Incremental Scanning:** Only scan changed files
  ```bash
  vaulytica scan files --incremental
  ```

- **Report Generation:** Create HTML reports
  ```bash
  vaulytica report generate --format html --output report.html
  ```

- **Custom DLP Rules:** Define your own patterns
  ```bash
  vaulytica dlp create-rule --name "API Keys" --pattern "sk-[a-zA-Z0-9]{32}"
  ```

### 5. Deploy to Production

See our [Deployment Guide](DEPLOYMENT.md) for:
- Docker deployment
- Kubernetes deployment
- Systemd service setup

---

## Troubleshooting

### Issue: Authentication Failed

**Error:** `Authentication failed: Invalid credentials`

**Solution:**
1. Verify service account JSON file path
2. Check domain-wide delegation is enabled
3. Verify OAuth scopes are correct
4. Ensure admin email is correct

### Issue: API Quota Exceeded

**Error:** `Rate limit exceeded`

**Solution:** Increase rate limit delay in `config.yaml`:
```yaml
scanning:
  rate_limit_delay: 0.5  # Increase from 0.1
```

### Issue: No Files Found

**Error:** `Found 0 files`

**Solution:**
1. Check you have files in Google Drive
2. Verify service account has access
3. Try without `--external-only` flag

### Issue: PII Not Detected

**Error:** PII exists but not detected

**Solution:** Lower confidence threshold:
```yaml
pii_detection:
  confidence_threshold: 0.3  # Lower from 0.5
```

---

## Getting Help

- 📖 **Documentation:** [docs/](../docs/)
- 🐛 **Issues:** [GitHub Issues](https://github.com/clay-good/vaulytica/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/clay-good/vaulytica/discussions)
- 📧 **Email:** clay@claygood.com

---

## Quick Reference

### Essential Commands

```bash
# Authentication test
vaulytica test --test-auth

# Scan external files
vaulytica scan files --external-only

# Scan with PII detection
vaulytica scan files --external-only --check-pii

# Scan inactive users
vaulytica scan users --inactive-days 90

# Generate report
vaulytica report generate --format html --output report.html

# Run workflow
vaulytica workflow run external-pii-alert

# Get help
vaulytica --help
vaulytica scan --help
```

---

## What's Next?

Now that you're up and running, explore:

1. **[Example Configurations](../examples/)** - Pre-built configs for common scenarios
2. **[Deployment Guide](DEPLOYMENT.md)** - Deploy to production
3. **[API Documentation](API.md)** - Integrate with other tools
4. **[Workflow Guide](WORKFLOWS.md)** - Automate security tasks

**Happy securing! 🔒**

