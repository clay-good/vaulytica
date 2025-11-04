# Vaulytica Security Guide

**Version:** 1.0  
**Last Updated:** 2025-10-28

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication & Authorization](#authentication--authorization)
3. [Data Protection](#data-protection)
4. [Network Security](#network-security)
5. [Audit Logging](#audit-logging)
6. [Compliance](#compliance)
7. [Security Best Practices](#security-best-practices)
8. [Incident Response](#incident-response)
9. [Security Hardening](#security-hardening)

---

## Security Overview

Vaulytica is designed with security as a top priority. This guide covers security features, best practices, and hardening recommendations for production deployments.

### Security Principles

1. **Least Privilege**: Minimal required permissions
2. **Defense in Depth**: Multiple layers of security
3. **Zero Trust**: Verify every request
4. **Encryption Everywhere**: Data encrypted in transit and at rest
5. **Audit Everything**: Comprehensive logging of all actions

---

## Authentication & Authorization

### Service Account Setup

**Recommended Configuration:**

```yaml
google_workspace:
  service_account_file: "/secure/path/service-account.json"
  subject_email: "admin@example.com"
  scopes:
    - "https://www.googleapis.com/auth/drive.readonly"
    - "https://www.googleapis.com/auth/admin.directory.user.readonly"
    - "https://www.googleapis.com/auth/gmail.readonly"
```

**Security Checklist:**

- [ ] Use dedicated service account (not personal account)
- [ ] Enable domain-wide delegation with minimal scopes
- [ ] Store service account key in secure location (e.g., HashiCorp Vault)
- [ ] Rotate service account keys every 90 days
- [ ] Use separate service accounts for dev/staging/prod
- [ ] Enable audit logging for service account usage
- [ ] Restrict service account to specific IP addresses

### OAuth Scopes

**Minimal Required Scopes:**

| Scope | Purpose | Risk Level |
|-------|---------|------------|
| `drive.readonly` | Read Drive files | Medium |
| `admin.directory.user.readonly` | Read user info | Low |
| `gmail.readonly` | Read Gmail messages | High |
| `admin.directory.group.readonly` | Read groups | Low |

**Security Notes:**
- Never use `drive` (full access) - always use `drive.readonly`
- Avoid `gmail.modify` unless absolutely necessary
- Document why each scope is required
- Review scopes quarterly

### Credential Management

**Best Practices:**

1. **Environment Variables:**
   ```bash
   export GWS_SERVICE_ACCOUNT_FILE="/secure/path/service-account.json"
   export GWS_SUBJECT_EMAIL="admin@example.com"
   ```

2. **HashiCorp Vault:**
   ```bash
   vault kv put secret/vaulytica \
     service_account=@service-account.json \
     subject_email=admin@example.com
   ```

3. **AWS Secrets Manager:**
   ```bash
   aws secretsmanager create-secret \
     --name vaulytica/service-account \
     --secret-string file://service-account.json
   ```

4. **Kubernetes Secrets:**
   ```bash
   kubectl create secret generic vaulytica-creds \
     --from-file=service-account.json \
     --from-literal=subject-email=admin@example.com
   ```

**Never:**
- Commit credentials to version control
- Store credentials in plain text
- Share credentials via email or Slack
- Use production credentials in development

---

## Data Protection

### Encryption at Rest

**SQLite Database:**

```yaml
storage:
  database_path: "/var/lib/vaulytica/state.db"
  encryption: true
  encryption_key_file: "/secure/path/db-encryption-key"
```

**File Cache:**

```yaml
cache:
  cache_dir: "/var/cache/vaulytica"
  encryption: true
  encryption_algorithm: "AES-256-GCM"
```

### Encryption in Transit

**TLS Configuration:**

```yaml
security:
  tls:
    min_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
    verify_certificates: true
```

**API Communication:**
- All Google Workspace API calls use HTTPS
- Certificate pinning for critical endpoints
- Mutual TLS (mTLS) for webhook endpoints

### Data Retention

**Configuration:**

```yaml
data_retention:
  scan_history_days: 90
  file_state_days: 365
  audit_logs_days: 2555  # 7 years for compliance
  cache_ttl_seconds: 3600
```

**Automatic Cleanup:**

```bash
# Run daily cleanup
vaulytica cleanup --older-than 90d
```

### Sensitive Data Handling

**PII Detection Results:**

```yaml
pii_detection:
  redact_in_logs: true
  redact_in_reports: false  # Keep for security team
  encryption_required: true
  access_control: "security-team-only"
```

**Best Practices:**
- Redact PII in logs and non-secure outputs
- Encrypt PII detection results
- Limit access to PII data to security team
- Implement data masking for non-production environments

---

## Network Security

### Firewall Rules

**Inbound:**
```bash
# Allow only from trusted networks
iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

**Outbound:**
```bash
# Allow only Google Workspace APIs
iptables -A OUTPUT -d 142.250.0.0/15 -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j DROP
```

### IP Whitelisting

**Configuration:**

```yaml
security:
  ip_whitelist:
    enabled: true
    allowed_ips:
      - "10.0.0.0/8"
      - "192.168.1.0/24"
    block_by_default: true
```

### VPN Requirements

**Configuration:**

```yaml
security:
  vpn_required: true
  vpn_check_endpoint: "https://vpn.example.com/check"
  vpn_bypass_ips:
    - "10.0.0.1"  # Admin workstation
```

### Rate Limiting

**Configuration:**

```yaml
rate_limiting:
  enabled: true
  requests_per_minute: 60
  burst_size: 10
  block_duration_seconds: 300
```

---

## Audit Logging

### Log Configuration

**Structured Logging:**

```yaml
logging:
  level: "INFO"
  format: "json"
  output: "/var/log/vaulytica/audit.log"
  rotation:
    max_size_mb: 100
    max_files: 10
    compress: true
```

**Log Fields:**

```json
{
  "timestamp": "2025-10-28T12:00:00Z",
  "level": "INFO",
  "event": "file_scanned",
  "user": "admin@example.com",
  "file_id": "abc123",
  "action": "scan",
  "result": "pii_detected",
  "ip_address": "10.0.0.1",
  "session_id": "xyz789"
}
```

### Security Events

**Critical Events to Log:**

1. **Authentication:**
   - Service account authentication
   - Token refresh
   - Authentication failures

2. **Authorization:**
   - Permission checks
   - Access denials
   - Privilege escalation attempts

3. **Data Access:**
   - File scans
   - PII detections
   - Data exports

4. **Configuration Changes:**
   - Policy updates
   - Integration changes
   - User modifications

5. **Security Incidents:**
   - Failed login attempts
   - Suspicious activity
   - Policy violations

### Log Forwarding

**Syslog:**

```yaml
logging:
  syslog:
    enabled: true
    host: "syslog.example.com"
    port: 514
    protocol: "tcp"
    tls: true
```

**SIEM Integration:**

```yaml
integrations:
  siem:
    type: "splunk"
    endpoint: "https://splunk.example.com:8088"
    token: "${SPLUNK_HEC_TOKEN}"
    index: "vaulytica"
```

---

## Compliance

### HIPAA Compliance

**Configuration:**

```yaml
compliance:
  hipaa:
    enabled: true
    encryption_required: true
    audit_logging: "comprehensive"
    data_retention_days: 2555  # 7 years
    access_controls: "strict"
    phi_detection: true
```

**Requirements:**
- [ ] Encrypt all PHI at rest and in transit
- [ ] Maintain audit logs for 7 years
- [ ] Implement access controls (RBAC)
- [ ] Regular security assessments
- [ ] Business Associate Agreements (BAAs)

### SOC 2 Compliance

**Configuration:**

```yaml
compliance:
  soc2:
    enabled: true
    change_management: true
    incident_response: true
    vulnerability_scanning: true
    penetration_testing: "annual"
```

**Requirements:**
- [ ] Document security policies
- [ ] Implement change management
- [ ] Conduct regular security training
- [ ] Perform vulnerability scans
- [ ] Annual penetration testing

### GDPR Compliance

**Configuration:**

```yaml
compliance:
  gdpr:
    enabled: true
    data_subject_rights: true
    right_to_erasure: true
    data_portability: true
    consent_management: true
```

**Requirements:**
- [ ] Data processing agreements
- [ ] Right to access (data export)
- [ ] Right to erasure (data deletion)
- [ ] Data breach notification (72 hours)
- [ ] Privacy by design

---

## Security Best Practices

### 1. Principle of Least Privilege

- Use minimal OAuth scopes
- Restrict service account permissions
- Implement RBAC for CLI commands
- Regular permission audits

### 2. Defense in Depth

- Multiple layers of security controls
- Network segmentation
- Application-level security
- Data-level encryption

### 3. Regular Security Updates

```bash
# Update dependencies weekly
poetry update

# Check for vulnerabilities
poetry run safety check

# Update base images (Docker)
docker pull python:3.14-slim
```

### 4. Security Monitoring

```yaml
monitoring:
  security_alerts:
    - failed_authentication
    - suspicious_activity
    - policy_violations
    - unusual_api_usage
  alert_channels:
    - email: security@example.com
    - slack: "#security-alerts"
    - pagerduty: "security-team"
```

### 5. Incident Response Plan

1. **Detection**: Automated alerts for security events
2. **Containment**: Disable compromised accounts
3. **Investigation**: Review audit logs
4. **Remediation**: Patch vulnerabilities
5. **Recovery**: Restore from backups
6. **Lessons Learned**: Post-incident review

---

## Security Hardening

### Operating System

```bash
# Disable unnecessary services
systemctl disable bluetooth
systemctl disable cups

# Enable firewall
ufw enable
ufw default deny incoming
ufw allow from 10.0.0.0/8 to any port 22

# Automatic security updates
apt install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

### Application

```yaml
security:
  hardening:
    disable_debug_mode: true
    remove_default_credentials: true
    disable_directory_listing: true
    set_security_headers: true
    enable_csrf_protection: true
    enable_xss_protection: true
```

### Docker

```dockerfile
# Use non-root user
USER vaulytica

# Read-only filesystem
RUN chmod -R 555 /app

# Drop capabilities
SECURITY_OPT:
  - no-new-privileges:true
  - seccomp=unconfined
```

### Kubernetes

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

---

## Reporting Security Issues

If you discover a security vulnerability, please email:

**security@example.com**

**Do NOT:**
- Open a public GitHub issue
- Discuss on Slack or forums
- Share details publicly

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response Time:**
- Initial response: 24 hours
- Status update: 72 hours
- Fix timeline: Based on severity

---

## Security Checklist

### Pre-Deployment

- [ ] Review all OAuth scopes
- [ ] Secure service account credentials
- [ ] Enable encryption at rest
- [ ] Configure TLS 1.3
- [ ] Set up audit logging
- [ ] Implement IP whitelisting
- [ ] Configure rate limiting
- [ ] Review firewall rules
- [ ] Set up monitoring and alerting
- [ ] Document security procedures

### Post-Deployment

- [ ] Verify encryption is working
- [ ] Test audit logging
- [ ] Validate access controls
- [ ] Review security logs
- [ ] Conduct security assessment
- [ ] Train security team
- [ ] Document incident response plan
- [ ] Schedule regular security reviews

---

## Conclusion

Security is an ongoing process, not a one-time configuration. Regularly review and update your security posture to protect against evolving threats.

For more information, see:
- [Architecture Guide](ARCHITECTURE.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Compliance Documentation](COMPLIANCE.md)

