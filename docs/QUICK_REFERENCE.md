# Vaulytica - Quick Reference Card

**Repository**: https://github.com/clay-good/vaulytica  
**Version**: 0.1.0  
**License**: MIT

---

## 🚀 Installation

```bash
git clone https://github.com/clay-good/vaulytica.git
cd vaulytica
poetry install
poetry run vaulytica --version
```

---

## 🔑 OAuth Scopes

### READ-ONLY (Safe for security scanning)
```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
https://www.googleapis.com/auth/drive.readonly
https://www.googleapis.com/auth/gmail.readonly
https://www.googleapis.com/auth/calendar.readonly
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/ediscovery.readonly
```

### READ & WRITE (Required for user management)
```
https://www.googleapis.com/auth/admin.directory.user
https://www.googleapis.com/auth/admin.directory.group
https://www.googleapis.com/auth/drive
```

---

## 📋 Most Popular Commands

### 1. Find PII in Externally Shared Files (READ-ONLY)
```bash
poetry run vaulytica scan files --external-only --check-pii --output pii-report.csv
```

### 2. Audit OAuth Apps (READ-ONLY)
```bash
poetry run vaulytica scan oauth-apps --min-risk-score 70 --output oauth-apps.csv
```

### 3. Find Inactive Users (READ-ONLY)
```bash
poetry run vaulytica scan users --inactive-days 90 --check-2fa --output users-report.csv
```

### 4. Scan Gmail for PII (READ-ONLY)
```bash
poetry run vaulytica scan gmail --days-back 30 --external-only --check-pii --output gmail-report.csv
```

### 5. Scan Chrome OS Devices (READ-ONLY)
```bash
poetry run vaulytica scan chrome-devices --org-unit "/Students" --output chrome-report.csv
```

### 6. Generate GDPR Report (READ-ONLY)
```bash
poetry run vaulytica compliance report --framework gdpr --output gdpr-report.html
```

### 7. Create User (READ & WRITE) ⚠️
```bash
poetry run vaulytica users create john.doe@company.com --first-name John --last-name Doe
```

### 8. Offboard Employee (READ & WRITE) ⚠️
```bash
# Dry-run first
poetry run vaulytica offboard user@company.com --transfer-to manager@company.com --dry-run

# Execute
poetry run vaulytica offboard user@company.com --transfer-to manager@company.com --execute
```

---

## 🔍 All Scanners (READ-ONLY)

| Scanner | Command | What It Does |
|---------|---------|--------------|
| **Files** | `scan files` | External sharing, PII detection |
| **Users** | `scan users` | Inactive users, 2FA compliance |
| **Gmail** | `scan gmail` | Attachment scanning, PII detection |
| **Groups** | `scan groups` | External members, public groups |
| **OAuth** | `scan oauth-apps` | Third-party app auditing |
| **Mobile** | `scan mobile-devices` | Android/iOS security |
| **Chrome** | `scan chrome-devices` | Chromebook security 🆕 |
| **Audit Logs** | `scan audit-logs` | Anomaly detection |
| **Calendar** | `scan calendar` | PII in events |
| **Vault** | `scan vault` | Legal holds |

---

## 📊 Compliance Frameworks

```bash
# GDPR
poetry run vaulytica compliance report --framework gdpr --output gdpr-report.html

# HIPAA
poetry run vaulytica compliance report --framework hipaa --output hipaa-report.html

# SOC 2
poetry run vaulytica compliance report --framework soc2 --output soc2-report.html

# PCI-DSS
poetry run vaulytica compliance report --framework pci-dss --output pci-dss-report.html

# FERPA
poetry run vaulytica compliance report --framework ferpa --output ferpa-report.html

# FedRAMP
poetry run vaulytica compliance report --framework fedramp --output fedramp-report.html
```

---

## 🛠️ User Management (READ & WRITE) ⚠️

```bash
# Create user
poetry run vaulytica users create user@company.com --first-name John --last-name Doe

# Suspend user
poetry run vaulytica users suspend user@company.com

# Restore user
poetry run vaulytica users restore user@company.com

# Delete user
poetry run vaulytica users delete user@company.com

# Update user
poetry run vaulytica users update user@company.com --first-name Jane

# Bulk operations
poetry run vaulytica bulk create-users users.csv --dry-run
poetry run vaulytica bulk create-users users.csv  # Execute
```

---

## 📁 Output Formats

```bash
# CSV
--output report.csv

# JSON
--output report.json

# HTML Dashboard
--output report.html
```

---

## 🔧 Configuration

```yaml
# config.yaml
google_workspace:
  domain: "yourcompany.com"
  credentials_file: "/path/to/service-account.json"
  impersonate_user: "admin@yourcompany.com"

integrations:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  
  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    smtp_user: "alerts@yourcompany.com"
    smtp_password: "your-app-password"
```

---

## 🧪 Testing

```bash
# Test authentication
poetry run vaulytica test

# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=vaulytica --cov-report=html
```

---

## 📚 Documentation

- [README.md](README.md) - Complete guide with READ/WRITE permissions
- [QUICKSTART.md](QUICKSTART.md) - 10-minute setup guide
- [FEATURES.md](FEATURES.md) - Complete feature list
- [GAP_ANALYSIS.md](GAP_ANALYSIS.md) - Gap analysis & optimization
- [CHROME_ENTERPRISE.md](docs/CHROME_ENTERPRISE.md) - Chrome OS guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Developer guide

---

## 🐛 Troubleshooting

### Error: "Configuration file not found"
```bash
cp examples/basic-config.yaml config.yaml
# Edit config.yaml with your details
```

### Error: "Authentication failed"
```bash
# Verify service account has domain-wide delegation
# Check OAuth scopes are authorized
# Verify impersonate_user is a super admin
```

### Error: "Insufficient permissions"
```bash
# Add required OAuth scopes to domain-wide delegation
# See OAuth Scopes section above
```

---

## 📞 Support

- 📖 [Documentation](https://github.com/clay-good/vaulytica/tree/main/docs)
- 🐛 [Report Issues](https://github.com/clay-good/vaulytica/issues)
- 💬 [Discussions](https://github.com/clay-good/vaulytica/discussions)
- 📧 [Email](mailto:clay@claygood.com)

---

## 🎯 Key Features

✅ **15+ Security Scanners** - Files, Users, Gmail, Groups, OAuth, Mobile, Chrome OS, Audit Logs, Calendar, Vault  
✅ **20+ PII Patterns** - SSN, Credit Cards, Bank Accounts, Medical Records, etc.  
✅ **6 Compliance Frameworks** - GDPR, HIPAA, SOC 2, PCI-DSS, FERPA, FedRAMP  
✅ **IT Automation** - User provisioning, bulk operations, offboarding  
✅ **Integrations** - Slack, Email, Webhooks, SIEM  
✅ **Production-Ready** - 313 tests, CI/CD, Docker support  

---

**⭐ Star the repo**: https://github.com/clay-good/vaulytica

