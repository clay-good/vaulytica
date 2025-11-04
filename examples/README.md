# Vaulytica Configuration Examples

This directory contains example configurations for common use cases.

---

## Available Examples

1. **[basic-config.yaml](basic-config.yaml)** - Minimal configuration for getting started
2. **[small-business-config.yaml](small-business-config.yaml)** - Small business (10-100 users)
3. **[enterprise-config.yaml](enterprise-config.yaml)** - Full-featured enterprise setup
4. **[healthcare-hipaa-config.yaml](healthcare-hipaa-config.yaml)** - Healthcare with HIPAA compliance
5. **[education-ferpa-config.yaml](education-ferpa-config.yaml)** - Education with FERPA compliance
6. **[financial-services-config.yaml](financial-services-config.yaml)** - Financial services (PCI-DSS, SOX, GLBA)
7. **[government-fedramp-config.yaml](government-fedramp-config.yaml)** - Government agencies (FedRAMP, FISMA, NIST 800-53)
8. **[compliance-focused.yaml](compliance-focused.yaml)** - Multi-framework compliance (HIPAA/SOC2/GDPR/PCI-DSS)
9. **[high-security.yaml](high-security.yaml)** - Maximum security settings

---

## Quick Start

1. Copy an example configuration:
   ```bash
   cp examples/basic-config.yaml config.yaml
   ```

2. Edit the configuration with your details:
   ```bash
   nano config.yaml
   ```

3. Initialize Vaulytica:
   ```bash
   vaulytica init
   ```

4. Run your first scan:
   ```bash
   vaulytica scan files --external-only
   ```

---

## Configuration Structure

All configurations follow this structure:

```yaml
google_workspace:
  domain: "example.com"
  admin_email: "admin@example.com"
  service_account_file: "path/to/service-account.json"

scanning:
  batch_size: 100
  rate_limit_delay: 0.1
  enable_cache: true

pii_detection:
  enabled: true
  confidence_threshold: 0.5
  patterns: [...]

integrations:
  email: {...}
  slack: {...}
  webhook: {...}

policies:
  auto_expire: {...}
  external_sharing: {...}

logging:
  level: "INFO"
  format: "json"
```

---

## Configuration Descriptions

### 1. Basic Configuration (`basic-config.yaml`)

**Best for:** Small teams, getting started, testing

**Features:**
- Minimal configuration
- Essential security checks
- Email notifications
- Simple reporting

**Use when:**
- You're new to Vaulytica
- You have a small team (< 50 users)
- You want to test the tool
- You need basic security monitoring

---

### 2. Small Business Configuration (`small-business-config.yaml`)

**Best for:** Small businesses (10-100 users)

**Features:**
- Simple security monitoring
- Email notifications
- Basic PII detection
- Affordable resource usage (1 core, 512 MB RAM)
- Easy maintenance
- Cost optimization
- Off-peak scanning

**Use when:**
- You're a small business
- You have limited IT resources
- You need affordable security
- You want easy setup and maintenance

**Estimated Costs:** Well within Google Workspace free tier

---

### 3. Enterprise Configuration (`enterprise-config.yaml`)

**Best for:** Large organizations (1,000+ users)

**Features:**
- Multi-domain support
- All scanners enabled
- Comprehensive PII detection (20+ types)
- All integrations (Email, Slack, Webhook, SIEM)
- Advanced policies
- Compliance reporting
- High performance settings (20 workers)

**Use when:**
- You have 1,000+ users
- You need comprehensive security monitoring
- You have dedicated security team
- You need compliance reporting

**Resource Requirements:** 8 cores, 16 GB RAM, 10 GB storage

---

### 4. Healthcare Configuration (`healthcare-hipaa-config.yaml`)

**Best for:** Healthcare organizations, HIPAA compliance

**Features:**
- HIPAA compliance (Privacy Rule, Security Rule, Breach Notification)
- PHI (Protected Health Information) detection
- Medical record number detection
- Medicare/Medicaid number detection
- NPI and DEA number detection
- 7-year data retention
- Comprehensive audit logging
- Encrypted storage (AES-256-GCM)
- 72-hour breach notification workflow

**Use when:**
- You're a healthcare organization
- You need HIPAA compliance
- You handle PHI
- You need to meet HITECH requirements

**Compliance:** HIPAA Privacy Rule, Security Rule, Breach Notification Rule

---

### 5. Education Configuration (`education-ferpa-config.yaml`)

**Best for:** Schools, universities, educational institutions

**Features:**
- FERPA compliance
- Student data protection (student IDs, grades, GPAs, transcripts)
- Financial aid information detection
- Academic calendar integration
- Faculty/staff access controls
- Graduation workflow
- 5-year data retention
- Student Information System (SIS) integration

**Use when:**
- You're an educational institution
- You need FERPA compliance
- You handle student records
- You need to protect educational data

**Compliance:** FERPA (Family Educational Rights and Privacy Act)

---

### 6. Financial Services Configuration (`financial-services-config.yaml`)

**Best for:** Banks, investment firms, financial institutions

**Features:**
- PCI-DSS compliance (payment card data protection)
- SOX compliance (financial reporting controls)
- GLBA compliance (customer financial information)
- Real-time fraud detection
- Insider trading prevention
- Credit card detection with Luhn validation
- Bank account and routing number detection
- 7-year audit trail
- HSM (Hardware Security Module) integration
- Real-time monitoring (5-second latency)

**Use when:**
- You're a financial institution
- You handle payment card data
- You need SOX compliance
- You need to prevent insider trading

**Compliance:** PCI-DSS 4.0, SOX (Sections 302, 404, 409, 802), GLBA

**Resource Requirements:** 16 cores, 32 GB RAM, 50 GB storage, HSM

---

### 7. Government Configuration (`government-fedramp-config.yaml`)

**Best for:** Federal, state, and local government agencies

**Features:**
- FedRAMP compliance (Moderate/High)
- FISMA compliance
- NIST 800-53 Rev 5 controls
- CJIS compliance (for law enforcement)
- Classified/CUI/FOUO data detection
- Security clearance verification
- PIV/CAC card requirement
- FIPS 140-2 compliant encryption
- Tamper-proof audit logging
- Continuous monitoring (every 15 minutes)
- Real-time incident response
- 7-year data retention
- HSM key management
- Block external sharing by default

**Use when:**
- You're a government agency
- You need FedRAMP authorization
- You handle classified information
- You need NIST 800-53 compliance
- You handle CUI (Controlled Unclassified Information)
- You're a law enforcement agency (CJIS)

**Compliance:** FedRAMP (Moderate/High), FISMA, NIST 800-53 Rev 5, CJIS, FIPS 140-2

**Resource Requirements:** 8 cores, 16 GB RAM, 100 GB storage, HSM, SIEM

**Estimated Costs:** ~$27,000/month (infrastructure + HSM + SIEM)

---

### 8. Compliance-Focused Configuration (`compliance-focused.yaml`)

**Best for:** Regulated industries requiring multiple frameworks

**Features:**
- HIPAA, SOC2, GDPR, PCI-DSS compliance
- Strict data retention policies
- Comprehensive audit logging
- Encrypted storage
- Advanced access controls
- Multi-framework reporting

**Use when:**
- You're in a regulated industry
- You need to meet multiple compliance requirements
- You need audit trails
- You handle sensitive data

**Compliance:** HIPAA, SOC 2, GDPR, PCI-DSS

---

### 9. High-Security Configuration (`high-security.yaml`)

**Best for:** Defense contractors, government agencies, sensitive organizations

**Features:**
- Maximum security settings
- Real-time monitoring
- Immediate alerts
- Strict access controls
- Zero external sharing
- Comprehensive logging
- Air-gapped deployment support

**Use when:**
- You handle classified information
- You need maximum security
- You have zero-trust requirements
- External sharing is prohibited

**Security Level:** Maximum (suitable for classified environments)

---

## Use Case Guides

### 1. Basic Security Monitoring

**Goal:** Monitor external file sharing and detect PII

**Configuration:** [basic-config.yaml](basic-config.yaml)

**Commands:**
```bash
# Daily scan for external shares
vaulytica scan files --external-only --check-pii

# Weekly user audit
vaulytica scan users --inactive-days 90
```

---

### 2. Enterprise Compliance

**Goal:** Meet HIPAA, SOC2, GDPR requirements

**Configuration:** [compliance-focused.yaml](compliance-focused.yaml)

**Features:**
- Comprehensive PII detection
- Automated compliance reporting
- Audit logging
- Data retention policies

**Commands:**
```bash
# Generate compliance report
vaulytica compliance report --standard hipaa --output report.pdf

# Scan for sensitive data
vaulytica scan files --check-pii --output findings.csv
```

---

### 3. High Security Environment

**Goal:** Maximum security for sensitive organizations

**Configuration:** [high-security.yaml](high-security.yaml)

**Features:**
- Strict external sharing policies
- Auto-expire all external shares
- Real-time alerting
- OAuth app auditing

**Commands:**
```bash
# Enforce strict policies
vaulytica policy apply --policy-file policies/strict.yaml

# Audit OAuth apps
vaulytica scan oauth-apps --risky-only
```

---

### 4. Multi-Domain Management

**Goal:** Manage multiple Google Workspace domains

**Configuration:** [multi-domain.yaml](multi-domain.yaml)

**Commands:**
```bash
# Scan all domains
vaulytica scan files --all-domains

# Domain-specific scan
vaulytica scan files --domain subsidiary.com
```

---

### 5. Automated Workflows

**Goal:** Automated security response

**Configuration:** [automated-workflows.yaml](automated-workflows.yaml)

**Features:**
- Automatic PII detection and alerting
- Auto-remediation of policy violations
- Scheduled scans
- Integration with SIEM

**Commands:**
```bash
# Run workflow
vaulytica workflow run external-pii-alert

# Schedule workflow
vaulytica workflow schedule external-pii-alert --cron "0 */6 * * *"
```

---

## Environment Variables

Override configuration values with environment variables:

```bash
# Google Workspace
export GWS_DOMAIN="example.com"
export GWS_ADMIN_EMAIL="admin@example.com"
export GWS_SERVICE_ACCOUNT_FILE="/path/to/service-account.json"

# Scanning
export GWS_BATCH_SIZE=100
export GWS_RATE_LIMIT_DELAY=0.1
export GWS_ENABLE_CACHE=true

# Integrations
export GWS_SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export GWS_EMAIL_SMTP_HOST="smtp.gmail.com"
export GWS_EMAIL_SMTP_PORT=587

# Logging
export GWS_LOG_LEVEL="INFO"
export GWS_LOG_FORMAT="json"
```

---

## Best Practices

### 1. Start Simple
- Begin with `basic-config.yaml`
- Test with a small subset of users
- Gradually enable more features

### 2. Test Before Production
- Use a test domain or OU
- Verify alerts work correctly
- Check performance impact

### 3. Monitor Performance
- Start with small batch sizes
- Increase rate limit delay if hitting quotas
- Enable caching for better performance

### 4. Security
- Never commit service account JSON to git
- Use environment variables for secrets
- Rotate credentials regularly

### 5. Incremental Rollout
- Enable one feature at a time
- Monitor for false positives
- Adjust thresholds based on results

---

## Troubleshooting

### Issue: API Quota Exceeded

**Solution:** Increase `rate_limit_delay` in config:
```yaml
scanning:
  rate_limit_delay: 0.5  # Increase from 0.1
```

### Issue: Too Many False Positives

**Solution:** Increase PII confidence threshold:
```yaml
pii_detection:
  confidence_threshold: 0.7  # Increase from 0.5
```

### Issue: Slow Scans

**Solution:** Enable caching and increase batch size:
```yaml
scanning:
  batch_size: 200  # Increase from 100
  enable_cache: true
```

---

## Next Steps

- [Deployment Guide](../docs/DEPLOYMENT.md)
- [Getting Started Guide](../docs/GETTING_STARTED.md)
- [API Documentation](../docs/API.md)

