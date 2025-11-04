# 🚀 Vaulytica Quick Start Guide

Get Vaulytica up and running in **under 10 minutes**.

## Prerequisites

- **Python 3.9+** installed
- **Google Workspace Enterprise Plus** account
- **Super Admin** access to Google Workspace
- **Poetry** (Python package manager) - [Install here](https://python-poetry.org/docs/#installation)

---

## Step 1: Install Vaulytica

```bash
# Clone the repository
git clone https://github.com/clay-good/vaulytica.git
cd vaulytica

# Install dependencies
poetry install

# Verify installation
poetry run vaulytica --version
```

---

## Step 2: Set Up Google Workspace Service Account

### 2.1 Create a Service Account

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to **IAM & Admin** → **Service Accounts**
4. Click **Create Service Account**
   - Name: `vaulytica-service-account`
   - Description: `Service account for Vaulytica security scanning`
5. Click **Create and Continue**
6. Skip role assignment (click **Continue**)
7. Click **Done**

### 2.2 Create Service Account Key

1. Click on the newly created service account
2. Go to the **Keys** tab
3. Click **Add Key** → **Create new key**
4. Select **JSON** format
5. Click **Create**
6. Save the downloaded JSON file as `credentials.json` in your vaulytica directory

### 2.3 Enable Required APIs

Enable these APIs in your Google Cloud project:

```bash
# Or enable via Cloud Console:
# https://console.cloud.google.com/apis/library
```

Required APIs:
- Admin SDK API
- Google Drive API
- Gmail API
- Google Calendar API
- Reports API
- Vault API (if using Vault features)

**Enable via Console:**
1. Go to [API Library](https://console.cloud.google.com/apis/library)
2. Search for each API above
3. Click **Enable**

### 2.4 Enable Domain-Wide Delegation

1. In the Service Account details, click **Show Domain-Wide Delegation**
2. Click **Enable Domain-Wide Delegation**
3. Copy the **Client ID** (you'll need this next)

### 2.5 Authorize API Scopes in Google Workspace

1. Go to [Google Workspace Admin Console](https://admin.google.com/)
2. Navigate to **Security** → **Access and data control** → **API Controls**
3. Click **Manage Domain-Wide Delegation**
4. Click **Add new**
5. Paste the **Client ID** from step 2.4
6. Add these OAuth scopes (comma-separated):

```
https://www.googleapis.com/auth/admin.directory.user.readonly,
https://www.googleapis.com/auth/admin.directory.group.readonly,
https://www.googleapis.com/auth/admin.reports.audit.readonly,
https://www.googleapis.com/auth/drive.readonly,
https://www.googleapis.com/auth/gmail.readonly,
https://www.googleapis.com/auth/calendar.readonly,
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,
https://www.googleapis.com/auth/admin.directory.orgunit.readonly,
https://www.googleapis.com/auth/ediscovery.readonly
```

7. Click **Authorize**

---

## Step 3: Configure Vaulytica

### Option A: Interactive Setup (Recommended)

```bash
poetry run vaulytica init
```

Follow the prompts to configure:
- Your Google Workspace domain
- Path to credentials.json
- Admin user email for impersonation
- Alert settings (optional)

### Option B: Manual Configuration

```bash
# Copy example config
cp examples/basic-config.yaml config.yaml

# Edit with your details
nano config.yaml
```

**Minimum required configuration:**

```yaml
# config.yaml
google_workspace:
  domain: "yourdomain.com"
  credentials_path: "./credentials.json"
  impersonate_user: "admin@yourdomain.com"  # Super admin email

scanning:
  scan_my_drive: true
  scan_shared_drives: true
  check_pii: true
  
storage:
  database_path: "./vaulytica.db"
  
reporting:
  output_dir: "./reports"
```

---

## Step 4: Test Your Setup

```bash
# Test authentication and connectivity
poetry run vaulytica test

# Expected output:
# ✓ Configuration loaded successfully
# ✓ Credentials validated
# ✓ API connection successful
# ✓ Domain access confirmed
```

---

## Step 5: Run Your First Scan

### Scan for Externally Shared Files

```bash
poetry run vaulytica scan files --external-only --output report.csv
```

### Scan for PII in Shared Files

```bash
poetry run vaulytica scan files --check-pii --external-only --min-risk-score 50
```

### Scan Users for Security Issues

```bash
poetry run vaulytica scan users --inactive-days 90 --check-2fa
```

### Scan Gmail for Security Issues

```bash
poetry run vaulytica scan gmail --check-delegates --check-forwarding
```

### Scan Groups for External Members

```bash
poetry run vaulytica scan groups --external-members
```

---

## Step 6: View Results

Results are saved to:
- **CSV files**: `./reports/` directory
- **Database**: `./vaulytica.db` (SQLite)
- **Console**: Rich formatted tables

### Generate HTML Dashboard

```bash
poetry run vaulytica report generate --format html --output dashboard.html
```

---

## Common Use Cases

### 1. Daily Security Scan (Automated)

```bash
# Add to cron (runs daily at 2 AM)
0 2 * * * cd /path/to/vaulytica && poetry run vaulytica scan files --external-only --check-pii --incremental
```

### 2. Compliance Report

```bash
# Generate HIPAA compliance report
poetry run vaulytica compliance report --framework hipaa --output hipaa-report.pdf

# Generate GDPR compliance report
poetry run vaulytica compliance report --framework gdpr --output gdpr-report.pdf
```

### 3. Employee Offboarding

```bash
# Offboard a user (transfer files, suspend account)
poetry run vaulytica offboard user@yourdomain.com --transfer-to manager@yourdomain.com
```

### 4. Audit OAuth Apps

```bash
# Find risky third-party apps
poetry run vaulytica scan oauth-apps --min-risk-score 70
```

### 5. Monitor Audit Logs

```bash
# Scan for suspicious activity
poetry run vaulytica scan audit-logs --anomalies --days-back 7
```

---

## Troubleshooting

### Error: "Configuration file not found"

```bash
# Run init to create config
poetry run vaulytica init
```

### Error: "Authentication failed"

1. Verify `credentials.json` exists and is valid
2. Check domain-wide delegation is enabled
3. Verify OAuth scopes are authorized in Admin Console
4. Ensure `impersonate_user` is a super admin

### Error: "API not enabled"

Enable required APIs in Google Cloud Console:
https://console.cloud.google.com/apis/library

### Error: "Insufficient permissions"

1. Verify service account has domain-wide delegation
2. Check OAuth scopes in Admin Console
3. Ensure impersonated user is a super admin

### Need Help?

- 📖 [Full Documentation](./docs/GETTING_STARTED.md)
- 🐛 [Report Issues](https://github.com/clay-good/vaulytica/issues)
- 💬 [Discussions](https://github.com/clay-good/vaulytica/discussions)

---

## Next Steps

1. **Schedule Regular Scans**: Set up cron jobs or use `vaulytica schedule`
2. **Configure Alerts**: Set up Slack/email notifications
3. **Create Workflows**: Automate common tasks
4. **Explore Advanced Features**: Check out the [full documentation](./docs/)

---

## Security Best Practices

✅ **DO:**
- Store `credentials.json` securely (never commit to git)
- Use a dedicated service account
- Rotate service account keys regularly
- Limit OAuth scopes to minimum required
- Review scan results regularly

❌ **DON'T:**
- Commit credentials to version control
- Share service account keys
- Use personal admin account for automation
- Grant unnecessary API scopes

---

**🎉 You're all set! Start securing your Google Workspace environment with Vaulytica.**

