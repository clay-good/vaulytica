## Vaulytica Examples

This directory contains example files for using Vaulytica.

### Configuration

**[basic-config.yaml](basic-config.yaml)** - Basic configuration template
- Copy to `config.yaml` in the project root
- Update with your Google Workspace details
- Configure scanning, PII detection, alerts, and compliance settings

### Bulk Operations

**[bulk-users-create.csv](bulk-users-create.csv)** - Example CSV for bulk user creation
- Use with: `vaulytica bulk create-users bulk-users-create.csv`
- Format: `email,first_name,last_name,password,org_unit`

**[bulk-users-suspend.csv](bulk-users-suspend.csv)** - Example CSV for bulk user suspension
- Use with: `vaulytica bulk suspend-users bulk-users-suspend.csv`
- Format: `email`

### DLP Rules

**[dlp-rules.yaml](dlp-rules.yaml)** - Example DLP rules configuration
- Defines custom Data Loss Prevention rules
- Includes patterns for:
  - SSN, Credit Cards, Phone Numbers
  - Employee IDs, Medical Record Numbers
  - API Keys, AWS Access Keys
  - Custom industry-specific patterns
- Use with: `vaulytica scan files --dlp-rules examples/dlp-rules.yaml`

### Usage Examples

#### 1. First-time Setup

```bash
# Copy example config
cp examples/basic-config.yaml config.yaml

# Edit with your details
nano config.yaml

# Test configuration
poetry run vaulytica test
```

#### 2. Bulk User Creation

```bash
# Dry-run first (safe)
poetry run vaulytica bulk create-users examples/bulk-users-create.csv --dry-run

# Create users
poetry run vaulytica bulk create-users examples/bulk-users-create.csv
```

#### 3. PII Scanning with Custom Rules

```bash
# Scan files with custom DLP rules
poetry run vaulytica scan files \
  --check-pii \
  --dlp-rules examples/dlp-rules.yaml \
  --output pii-scan.json
```

#### 4. Compliance Reporting

```bash
# Generate GDPR report
poetry run vaulytica compliance report \
  --framework gdpr \
  --output reports/gdpr-$(date +%Y%m%d).html
```

#### 5. Employee Offboarding

```bash
# Dry-run first
poetry run vaulytica offboard terminated@company.com \
  --transfer-to manager@company.com \
  --dry-run

# Execute offboarding
poetry run vaulytica offboard terminated@company.com \
  --transfer-to manager@company.com
```

#### 6. Scheduled Scanning

```bash
# Add daily file scan
poetry run vaulytica schedule add \
  --name "daily-pii-scan" \
  --command "scan files --check-pii --external-only --output reports/daily-scan.csv" \
  --cron "0 2 * * *"  # 2 AM daily

# List schedules
poetry run vaulytica schedule list
```

### Need Help?

- **Documentation**: See [docs/](../docs/) directory
- **Troubleshooting**: See [TROUBLESHOOTING.md](../docs/TROUBLESHOOTING.md)
- **Issues**: Open an issue on [GitHub](https://github.com/clay-good/vaulytica/issues)
