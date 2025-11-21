# Security Posture Assessment & Baseline Scanner

## Overview

The Security Posture Assessment feature is a comprehensive automated security auditing system for Google Workspace that evaluates your organization's security configurations against industry standards and compliance frameworks. It performs 25+ security checks, provides severity-weighted scoring (0-100), and delivers actionable remediation guidance mapped to multiple compliance frameworks including CIS Benchmarks, NIST Cybersecurity Framework, HIPAA, GDPR, PCI-DSS, and SOC2.

## 🎯 Key Capabilities

### 1. **Automated Security Baseline Scanning** (`posture_scanner.py`)
- **25+ Security Checks** across authentication, access control, data protection, and monitoring
- **Compliance Framework Mapping** to CIS, NIST, HIPAA, GDPR, PCI-DSS, SOC2, Google Best Practices
- **Severity-Weighted Scoring** (0-100) based on CRITICAL/HIGH/MEDIUM/LOW/INFO findings
- **Actionable Remediation Guidance** for every failed check
- **Selective Check Execution** - enable/disable specific check categories
- **Rich Terminal Output** with color-coded results and detailed tables

### 2. **Security Check Categories**
- **Authentication & Access Control** (2FA enforcement, admin account security, session management)
- **Sharing & Collaboration** (External sharing policies, public file detection, guest user controls)
- **Third-Party Access** (OAuth app verification, API security, unverified publishers)
- **Mobile & Device Management** (MDM enforcement, device encryption, remote wipe capabilities)
- **Data Protection** (Password policies, DLP policies, email security)
- **Audit & Monitoring** (Audit logging, alerting, suspicious activity detection)

### 3. **Compliance Reporting**
- **CIS Google Workspace Benchmark** controls
- **NIST Cybersecurity Framework** categories
- **HIPAA** security rules
- **GDPR** data protection requirements
- **PCI-DSS** access control requirements
- **SOC2** trust service criteria
- **Google Best Practices** recommendations

## 🚀 Quick Start

### Run a Complete Security Assessment

```bash
# Full security posture assessment with all checks
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com

# Assessment for specific compliance framework
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --framework cis \
  --framework hipaa
```

### Get Executive Summary (Critical & High Issues Only)

```bash
# Quick summary showing only critical and high-severity findings
vaulytica security-posture summary \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com
```

### List Available Compliance Frameworks

```bash
# View all supported compliance frameworks
vaulytica security-posture frameworks
```

### Export Results to JSON

```bash
# Save assessment results for integration with SIEM or ticketing systems
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --output security-assessment.json
```

### Filter Results by Severity

```bash
# Show only critical findings
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --severity-filter critical

# Show critical and high findings
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --severity-filter high
```

### Include Passed Checks in Output

```bash
# Show both passed and failed checks for complete audit trail
vaulytica security-posture assess \
  --credentials service-account.json \
  --admin-email admin@company.com \
  --domain company.com \
  --show-passed
```

## 📋 Security Checks Catalog

### Authentication & Access Control (5 checks)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **2FA-001** | CRITICAL | 2FA enforcement for all users | CIS, NIST, HIPAA, PCI-DSS, SOC2 |
| **2FA-002** | HIGH | 2FA enrollment compliance rate | CIS, NIST, SOC2 |
| **ADMIN-001** | HIGH | Admin account separation (no super admins as regular users) | CIS, NIST, PCI-DSS |
| **ADMIN-002** | CRITICAL | Admin 2FA enforcement | CIS, NIST, HIPAA, PCI-DSS, SOC2 |
| **ADMIN-003** | MEDIUM | Minimal admin accounts (fewer than 5) | CIS, SOC2 |

### Sharing & External Access (3 checks)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **SHARE-001** | HIGH | External sharing restrictions enabled | CIS, GDPR, HIPAA, SOC2 |
| **SHARE-002** | CRITICAL | Public file sharing disabled | CIS, GDPR, HIPAA, NIST |
| **SHARE-003** | MEDIUM | Link sharing restrictions configured | CIS, GDPR |

### OAuth & API Security (2 checks)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **OAUTH-001** | HIGH | OAuth app verification required | CIS, NIST, SOC2 |
| **OAUTH-002** | HIGH | Unverified OAuth apps detected | CIS, NIST, SOC2 |

### Mobile Device Management (2 checks)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **MDM-001** | CRITICAL | MDM enforcement for mobile devices | CIS, HIPAA, PCI-DSS, SOC2 |
| **MDM-002** | HIGH | Device encryption requirements | CIS, HIPAA, PCI-DSS, GDPR |

### Password & Session Management (2 checks)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **PWD-001** | HIGH | Strong password policy enforcement (8+ chars, complexity) | CIS, NIST, HIPAA, PCI-DSS |
| **SESSION-001** | MEDIUM | Session timeout configured (8 hours or less) | CIS, NIST, PCI-DSS |

### Data Loss Prevention (1 check)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **DLP-001** | HIGH | DLP policies configured | GDPR, HIPAA, PCI-DSS, SOC2 |

### Email Security (1 check)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **EMAIL-001** | MEDIUM | SPF/DKIM/DMARC email authentication | CIS, NIST, Google Best Practices |

### Audit & Monitoring (2 checks)

| Check ID | Severity | Description | Compliance Frameworks |
|----------|----------|-------------|----------------------|
| **AUDIT-001** | HIGH | Comprehensive audit logging enabled | CIS, NIST, HIPAA, SOC2, PCI-DSS |
| **API-001** | MEDIUM | API access logging and monitoring | CIS, NIST, SOC2 |

## 🔒 Understanding Security Scores

### Score Calculation

The security score (0-100) is calculated using a severity-weighted algorithm:

```python
# Severity weights
CRITICAL = 10 points per finding
HIGH     = 5 points per finding
MEDIUM   = 2 points per finding
LOW      = 1 point per finding
INFO     = 0 points (informational only)

# Formula
score = (passed_weighted_checks / total_weighted_checks) × 100
```

### Score Interpretation

| Score Range | Rating | Interpretation | Recommended Action |
|-------------|--------|----------------|-------------------|
| **90-100** | Excellent | Strong security posture, minimal risks | Maintain current controls, monitor regularly |
| **80-89** | Good | Solid security, some improvements needed | Address high-severity findings |
| **70-79** | Fair | Moderate security gaps present | Review and remediate high/critical findings |
| **60-69** | Poor | Significant security weaknesses | Immediate action required on critical findings |
| **0-59** | Critical | Severe security deficiencies | Emergency remediation of all critical findings |

### Example Output

```
Security Posture Assessment
==========================
Domain: company.com
Scan Date: 2025-01-20 14:30:00 UTC
Scan Duration: 45.2 seconds

Overall Security Score: 72/100 (Fair)

Findings Summary
===============
✓ Passed:    18 checks
✗ Failed:    7 checks
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total:       25 checks

Findings by Severity
===================
🔴 CRITICAL:  2 findings (IMMEDIATE ACTION REQUIRED!)
🟠 HIGH:      3 findings
🟡 MEDIUM:    2 findings
🟢 LOW:       0 findings
ℹ️  INFO:      0 findings

Critical Findings (MUST FIX IMMEDIATELY)
======================================
🔴 CRITICAL: MDM-001
   Title: MDM Not Enforced
   Description: Mobile Device Management (MDM) is not enforced
   Impact: Unmanaged mobile devices can access corporate data without security controls
   Remediation: Enable MDM enforcement in Admin Console → Devices → Mobile → Settings
   Frameworks: CIS, HIPAA, PCI-DSS, SOC2

🔴 CRITICAL: ADMIN-002
   Title: Admin 2FA Not Enforced
   Description: Not all admin users have 2FA enabled
   Impact: Admin accounts vulnerable to credential theft and account takeover
   Remediation: Enforce 2FA for all admin users in Admin Console → Security → 2-Step Verification
   Frameworks: CIS, NIST, HIPAA, PCI-DSS, SOC2
```

## 🔧 CLI Commands Reference

### `security-posture assess`

Perform comprehensive security posture assessment.

```bash
vaulytica security-posture assess [OPTIONS]

Options:
  -c, --credentials PATH       Service account credentials JSON file [required]
  -a, --admin-email EMAIL      Admin email for impersonation [required]
  -d, --domain DOMAIN          Google Workspace domain [required]
  -f, --framework FRAMEWORK    Filter by compliance framework (can specify multiple)
                               Choices: cis, nist, google_best_practices, hipaa,
                                        pci_dss, gdpr, soc2
  -o, --output PATH            Save results to JSON file
  --show-passed               Show passed checks (default: only failures)
  --severity-filter SEVERITY   Filter by minimum severity
                               Choices: critical, high, medium, low

Examples:
  # Full assessment
  vaulytica security-posture assess -c creds.json -a admin@co.com -d co.com

  # CIS Benchmark only
  vaulytica security-posture assess -c creds.json -a admin@co.com -d co.com -f cis

  # Critical findings only
  vaulytica security-posture assess -c creds.json -a admin@co.com -d co.com \
    --severity-filter critical

  # Export to JSON
  vaulytica security-posture assess -c creds.json -a admin@co.com -d co.com \
    -o assessment.json
```

### `security-posture summary`

Quick executive summary showing only critical and high-severity findings.

```bash
vaulytica security-posture summary [OPTIONS]

Options:
  -c, --credentials PATH       Service account credentials JSON file [required]
  -a, --admin-email EMAIL      Admin email for impersonation [required]
  -d, --domain DOMAIN          Google Workspace domain [required]
  -o, --output PATH            Save results to JSON file

Example:
  # Executive summary
  vaulytica security-posture summary -c creds.json -a admin@co.com -d co.com
```

### `security-posture frameworks`

List all supported compliance frameworks.

```bash
vaulytica security-posture frameworks

Example output:
  Supported Compliance Frameworks:
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • CIS - CIS Google Workspace Benchmark
  • NIST - NIST Cybersecurity Framework
  • Google Best Practices - Google recommended security controls
  • HIPAA - Health Insurance Portability and Accountability Act
  • PCI-DSS - Payment Card Industry Data Security Standard
  • GDPR - General Data Protection Regulation
  • SOC2 - Service Organization Control 2
```

## 📊 Integration Examples

### Automated Daily Security Monitoring

```bash
#!/bin/bash
# daily-security-check.sh

# Run security assessment daily at 6 AM
vaulytica security-posture assess \
  --credentials /etc/vaulytica/service-account.json \
  --admin-email security-bot@company.com \
  --domain company.com \
  --output /var/log/vaulytica/security-assessment-$(date +%Y%m%d).json

# Send alert if score is below 70
SCORE=$(jq -r '.security_score' /var/log/vaulytica/security-assessment-$(date +%Y%m%d).json)
if (( $(echo "$SCORE < 70" | bc -l) )); then
  echo "Security score dropped to $SCORE!" | mail -s "Security Alert" security@company.com
fi
```

### Schedule with Cron

```bash
# Add to crontab: Run daily at 6 AM
0 6 * * * /usr/local/bin/vaulytica security-posture assess \
  -c /etc/vaulytica/creds.json \
  -a admin@company.com \
  -d company.com \
  -o /var/log/security-$(date +\%Y\%m\%d).json
```

### SIEM Integration (JSON Export)

```bash
# Export to JSON and send to SIEM
vaulytica security-posture assess \
  -c creds.json \
  -a admin@company.com \
  -d company.com \
  -o assessment.json

# Send to Splunk HTTP Event Collector
curl -X POST https://splunk.company.com:8088/services/collector \
  -H "Authorization: Splunk YOUR-TOKEN" \
  -d @assessment.json

# Send to Elasticsearch
curl -X POST "https://elasticsearch.company.com:9200/security-assessments/_doc" \
  -H "Content-Type: application/json" \
  -d @assessment.json
```

### Jira Ticket Creation for Critical Findings

```python
#!/usr/bin/env python3
"""Create Jira tickets for critical security findings."""

import json
import sys
from jira import JIRA

# Load assessment results
with open(sys.argv[1]) as f:
    assessment = json.load(f)

# Connect to Jira
jira = JIRA("https://jira.company.com", basic_auth=("user", "token"))

# Create tickets for critical findings
for finding in assessment["findings"]:
    if finding["severity"] == "CRITICAL" and finding["status"] == "FAILED":
        issue = jira.create_issue(
            project="SEC",
            summary=f"[CRITICAL] {finding['title']}",
            description=f"""
*Security Check Failed*

*Check ID:* {finding['check_id']}
*Domain:* {assessment['domain']}
*Severity:* CRITICAL

*Description:*
{finding['description']}

*Impact:*
{finding['impact']}

*Remediation:*
{finding['remediation']}

*Compliance Frameworks:*
{', '.join(finding['frameworks'])}

*Scan Date:* {assessment['scan_date']}
            """,
            issuetype={"name": "Security Issue"},
            priority={"name": "Highest"},
            labels=["security", "compliance", "critical"]
        )
        print(f"Created Jira ticket: {issue.key}")
```

### Slack Alerting

```bash
#!/bin/bash
# Send security summary to Slack

# Run assessment and extract critical findings
CRITICAL_COUNT=$(vaulytica security-posture assess \
  -c creds.json -a admin@company.com -d company.com -o /tmp/assess.json | \
  jq '.severity_counts.CRITICAL')

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
    -H 'Content-Type: application/json' \
    -d "{
      \"text\": \":rotating_light: *Security Alert* :rotating_light:\",
      \"attachments\": [{
        \"color\": \"danger\",
        \"text\": \"$CRITICAL_COUNT critical security findings detected in company.com\",
        \"fields\": [
          {\"title\": \"Action Required\", \"value\": \"Review security assessment immediately\", \"short\": false}
        ]
      }]
    }"
fi
```

## 📈 Compliance Framework Coverage

### CIS Google Workspace Benchmark

Covers the following CIS control areas:
- **Section 1:** Account and Access Management (2FA, admin accounts, password policies)
- **Section 2:** Data Governance (sharing policies, DLP, external access)
- **Section 3:** Mobile Device Management (MDM enforcement, encryption)
- **Section 4:** Email Security (SPF, DKIM, DMARC)
- **Section 5:** Audit and Monitoring (audit logs, API monitoring)

### NIST Cybersecurity Framework

Maps to NIST CSF categories:
- **Identify (ID):** Asset management, governance
- **Protect (PR):** Access control, data security, protective technology
- **Detect (DE):** Security monitoring, continuous monitoring
- **Respond (RS):** Response planning, communications
- **Recover (RC):** Recovery planning, improvements

### HIPAA Security Rule

Addresses HIPAA requirements:
- **Administrative Safeguards:** Access management, workforce security
- **Physical Safeguards:** Device and media controls
- **Technical Safeguards:** Access control, audit controls, transmission security
- **Organizational Requirements:** Business associate agreements, policies

### GDPR

Supports GDPR compliance:
- **Article 5:** Principles of data processing
- **Article 25:** Data protection by design and default
- **Article 32:** Security of processing
- **Article 33-34:** Breach notification

### PCI-DSS

Aligns with PCI-DSS requirements:
- **Requirement 7:** Restrict access to cardholder data
- **Requirement 8:** Identify and authenticate access
- **Requirement 10:** Track and monitor all access to network resources
- **Requirement 12:** Information security policy

### SOC2 Trust Service Criteria

Maps to SOC2 criteria:
- **Security:** Access controls, system monitoring, change management
- **Availability:** System availability, incident response
- **Confidentiality:** Data classification, encryption
- **Privacy:** Data collection, retention, disposal

## 🛠️ Programmatic Usage

### Python API

```python
from pathlib import Path
from vaulytica.core.security import (
    PostureScanner,
    ComplianceFramework,
    FindingSeverity,
)

# Initialize scanner
scanner = PostureScanner(
    credentials_path=Path("service-account.json"),
    admin_email="admin@company.com",
    domain="company.com"
)

# Run full assessment
baseline = scanner.scan_security_posture()

# Print summary
print(f"Security Score: {baseline.security_score}/100")
print(f"Total Checks: {baseline.total_checks}")
print(f"Passed: {baseline.checks_passed}")
print(f"Failed: {baseline.checks_failed}")

# Get critical findings
critical = baseline.get_findings_by_severity(FindingSeverity.CRITICAL)
for finding in critical:
    if finding.status == "FAILED":
        print(f"🔴 {finding.check_id}: {finding.title}")
        print(f"   Remediation: {finding.remediation}")

# Filter by compliance framework
hipaa_findings = baseline.get_findings_by_framework(ComplianceFramework.HIPAA)
print(f"HIPAA-related findings: {len(hipaa_findings)}")

# Export to dictionary
data = baseline.to_dict()

# Save to JSON
import json
with open("assessment.json", "w") as f:
    json.dump(data, f, indent=2)
```

### Selective Check Execution

```python
# Run only specific check categories
baseline = scanner.scan_security_posture(
    include_2fa_check=True,
    include_admin_check=True,
    include_sharing_check=False,  # Skip sharing checks
    include_oauth_check=False,     # Skip OAuth checks
    include_mobile_check=True,
)
```

### Framework-Specific Assessment

```python
# Run assessment for specific compliance frameworks
baseline = scanner.scan_security_posture(
    frameworks=[
        ComplianceFramework.CIS,
        ComplianceFramework.HIPAA,
    ]
)

# Only findings mapped to CIS or HIPAA will be included
```

## 🎯 Best Practices

### 1. **Run Regular Assessments**
```bash
# Schedule weekly assessments
0 0 * * 0 vaulytica security-posture assess \
  -c /etc/vaulytica/creds.json \
  -a admin@company.com \
  -d company.com \
  -o /var/log/security-weekly.json
```

### 2. **Track Score Trends Over Time**
```bash
#!/bin/bash
# Track security score trends
SCORE=$(vaulytica security-posture assess \
  -c creds.json -a admin@co.com -d co.com -o /tmp/assess.json | \
  jq -r '.security_score')

echo "$(date +%Y-%m-%d),$SCORE" >> /var/log/security-scores.csv

# Plot trend with gnuplot or send to monitoring system
```

### 3. **Prioritize Critical Findings First**
```bash
# Focus on critical findings
vaulytica security-posture assess \
  -c creds.json -a admin@co.com -d co.com \
  --severity-filter critical
```

### 4. **Maintain Compliance Documentation**
```bash
# Generate quarterly compliance reports
vaulytica security-posture assess \
  -c creds.json -a admin@co.com -d co.com \
  -f hipaa -f pci_dss \
  -o compliance-reports/Q1-2025.json \
  --show-passed  # Include passed checks for audit trail
```

### 5. **Integrate with Change Management**
```bash
# Run before and after major changes
# Before change
vaulytica security-posture assess \
  -c creds.json -a admin@co.com -d co.com \
  -o before-change.json

# Make changes...

# After change
vaulytica security-posture assess \
  -c creds.json -a admin@co.com -d co.com \
  -o after-change.json

# Compare scores
diff <(jq -r '.security_score' before-change.json) \
     <(jq -r '.security_score' after-change.json)
```

## 🔍 Troubleshooting

### Issue: Permission Denied Errors

**Solution:** Ensure service account has required scopes:
```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.reports.audit.readonly
https://www.googleapis.com/auth/admin.directory.domain.readonly
```

### Issue: Some Checks Skipped

**Solution:** Some checks require specific Google Workspace editions:
- **DLP checks:** Require Google Workspace Enterprise Plus
- **MDM checks:** Require mobile device management enabled
- **Vault checks:** Require Google Vault license

### Issue: Low Security Score

**Solution:** Focus on critical and high-severity findings first:
1. Enable 2FA for all users (especially admins)
2. Enable MDM for mobile devices
3. Restrict external sharing
4. Configure password policies
5. Enable audit logging

## 📚 Additional Resources

- [CIS Google Workspace Benchmark](https://www.cisecurity.org/benchmark/google_workspace)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Google Workspace Security Best Practices](https://support.google.com/a/answer/7587183)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [GDPR Article 32](https://gdpr-info.eu/art-32-gdpr/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)

## 🚨 Support

For issues, questions, or feature requests:
- GitHub Issues: [https://github.com/clay-good/vaulytica/issues](https://github.com/clay-good/vaulytica/issues)
- Documentation: [docs/](../docs/)

---

**Last Updated:** 2025-01-20
**Version:** 1.0.0
**Feature Status:** Production Ready ✅
