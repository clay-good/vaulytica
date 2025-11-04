# Vaulytica Troubleshooting Guide

**Version:** 1.0  
**Last Updated:** 2025-10-28

---

## Table of Contents

1. [Common Issues](#common-issues)
2. [Authentication Problems](#authentication-problems)
3. [API Errors](#api-errors)
4. [Performance Issues](#performance-issues)
5. [PII Detection Issues](#pii-detection-issues)
6. [Integration Problems](#integration-problems)
7. [Debugging Tips](#debugging-tips)
8. [Getting Help](#getting-help)

---

## Common Issues

### Issue: "Command not found: vaulytica"

**Symptoms:**
```bash
$ vaulytica scan files
bash: vaulytica: command not found
```

**Causes:**
- Vaulytica not installed
- Not in PATH
- Virtual environment not activated

**Solutions:**

1. **Install Vaulytica:**
   ```bash
   pip install vaulytica
   # or
   poetry install
   ```

2. **Activate virtual environment:**
   ```bash
   poetry shell
   # or
   source .venv/bin/activate
   ```

3. **Use full path:**
   ```bash
   poetry run vaulytica scan files
   ```

---

### Issue: "Configuration file not found"

**Symptoms:**
```bash
Error: Configuration file 'config.yaml' not found
```

**Causes:**
- No configuration file created
- Wrong working directory
- Incorrect file path

**Solutions:**

1. **Create configuration:**
   ```bash
   vaulytica init
   ```

2. **Specify config path:**
   ```bash
   vaulytica --config /path/to/config.yaml scan files
   ```

3. **Copy example config:**
   ```bash
   cp examples/basic-config.yaml config.yaml
   ```

---

## Authentication Problems

### Issue: "Service account authentication failed"

**Symptoms:**
```
Error: Failed to authenticate with service account
google.auth.exceptions.DefaultCredentialsError
```

**Causes:**
- Invalid service account file
- Missing service account file
- Incorrect file permissions
- Wrong subject email

**Solutions:**

1. **Verify service account file exists:**
   ```bash
   ls -la /path/to/service-account.json
   ```

2. **Check file permissions:**
   ```bash
   chmod 600 /path/to/service-account.json
   ```

3. **Validate JSON format:**
   ```bash
   python -m json.tool service-account.json
   ```

4. **Verify subject email:**
   ```yaml
   google_workspace:
     subject_email: "admin@example.com"  # Must be valid admin
   ```

5. **Test authentication:**
   ```bash
   vaulytica test --test-auth
   ```

---

### Issue: "Domain-wide delegation not enabled"

**Symptoms:**
```
Error: Domain-wide delegation is not enabled for this service account
```

**Causes:**
- Domain-wide delegation not configured
- Wrong OAuth scopes
- Service account not authorized

**Solutions:**

1. **Enable domain-wide delegation:**
   - Go to Google Cloud Console
   - Navigate to IAM & Admin > Service Accounts
   - Click on your service account
   - Click "Enable G Suite Domain-wide Delegation"

2. **Authorize scopes in Admin Console:**
   - Go to admin.google.com
   - Security > API Controls > Domain-wide Delegation
   - Add service account client ID
   - Add required scopes:
     ```
     https://www.googleapis.com/auth/drive.readonly
     https://www.googleapis.com/auth/admin.directory.user.readonly
     https://www.googleapis.com/auth/gmail.readonly
     ```

3. **Wait for propagation (up to 24 hours)**

---

### Issue: "Insufficient permissions"

**Symptoms:**
```
Error: The caller does not have permission
HttpError 403: Forbidden
```

**Causes:**
- Missing OAuth scopes
- Subject email not an admin
- API not enabled

**Solutions:**

1. **Add required scopes:**
   ```yaml
   google_workspace:
     scopes:
       - "https://www.googleapis.com/auth/drive.readonly"
       - "https://www.googleapis.com/auth/admin.directory.user.readonly"
   ```

2. **Verify admin privileges:**
   - Subject email must be a Super Admin or have required admin roles

3. **Enable APIs:**
   - Go to Google Cloud Console
   - APIs & Services > Library
   - Enable: Drive API, Admin SDK, Gmail API

---

## API Errors

### Issue: "Rate limit exceeded"

**Symptoms:**
```
Error: Rate limit exceeded
HttpError 429: Too Many Requests
```

**Causes:**
- Too many API requests
- Insufficient rate limiting
- Multiple concurrent scans

**Solutions:**

1. **Increase rate limit delay:**
   ```yaml
   performance:
     rate_limit_delay: 0.5  # Increase from 0.1
   ```

2. **Reduce concurrency:**
   ```yaml
   performance:
     max_workers: 5  # Reduce from 10
   ```

3. **Enable caching:**
   ```yaml
   cache:
     enabled: true
     ttl_seconds: 3600
   ```

4. **Use incremental scanning:**
   ```bash
   vaulytica scan files --incremental
   ```

---

### Issue: "Quota exceeded"

**Symptoms:**
```
Error: Quota exceeded for quota metric 'Queries' and limit 'Queries per day'
HttpError 403: Quota exceeded
```

**Causes:**
- Daily API quota exceeded
- Too many scans in one day

**Solutions:**

1. **Check quota usage:**
   - Go to Google Cloud Console
   - APIs & Services > Dashboard
   - View quota usage

2. **Request quota increase:**
   - APIs & Services > Quotas
   - Select API
   - Request increase

3. **Optimize scanning:**
   ```yaml
   scanning:
     batch_size: 100  # Larger batches = fewer requests
   cache:
     enabled: true
   incremental:
     enabled: true
   ```

---

### Issue: "File not found"

**Symptoms:**
```
Error: File not found
HttpError 404: Not Found
```

**Causes:**
- File deleted
- No access to file
- File in trash

**Solutions:**

1. **Skip deleted files:**
   ```yaml
   scanning:
     skip_trashed: true
   ```

2. **Handle errors gracefully:**
   ```yaml
   error_handling:
     continue_on_error: true
   ```

---

## Performance Issues

### Issue: "Scanning is very slow"

**Symptoms:**
- Scans take hours to complete
- High CPU/memory usage
- Timeouts

**Causes:**
- Large number of files
- No caching
- Low concurrency
- PII detection on all files

**Solutions:**

1. **Enable caching:**
   ```yaml
   cache:
     enabled: true
     ttl_seconds: 3600
   ```

2. **Increase concurrency:**
   ```yaml
   performance:
     max_workers: 20  # Increase workers
   ```

3. **Use incremental scanning:**
   ```bash
   vaulytica scan files --incremental
   ```

4. **Scan external files only:**
   ```bash
   vaulytica scan files --external-only
   ```

5. **Optimize PII detection:**
   ```yaml
   pii_detection:
     confidence_threshold: 0.8  # Higher = fewer false positives
     chunk_size: 1048576  # 1MB chunks for large files
   ```

---

### Issue: "Out of memory"

**Symptoms:**
```
MemoryError: Unable to allocate memory
Killed
```

**Causes:**
- Large files
- No chunked processing
- Too many concurrent workers

**Solutions:**

1. **Enable chunked processing:**
   ```yaml
   pii_detection:
     chunked_processing: true
     chunk_size: 1048576  # 1MB
   ```

2. **Reduce concurrency:**
   ```yaml
   performance:
     max_workers: 5
   ```

3. **Increase system memory:**
   ```bash
   # Docker
   docker run -m 4g ...
   
   # Kubernetes
   resources:
     limits:
       memory: "4Gi"
   ```

---

## PII Detection Issues

### Issue: "Too many false positives"

**Symptoms:**
- Many non-PII items flagged
- Low confidence scores
- Irrelevant detections

**Solutions:**

1. **Increase confidence threshold:**
   ```yaml
   pii_detection:
     confidence_threshold: 0.8  # Increase from 0.5
   ```

2. **Disable noisy patterns:**
   ```yaml
   pii_detection:
     patterns:
       - type: "phone"
         enabled: false  # Disable if too many false positives
   ```

3. **Add custom patterns:**
   ```yaml
   pii_detection:
     patterns:
       - type: "employee_id"
         pattern: "EMP-\\d{6}"
         confidence: 0.9
   ```

---

### Issue: "PII not detected"

**Symptoms:**
- Known PII not flagged
- Missing detections
- Low recall

**Solutions:**

1. **Lower confidence threshold:**
   ```yaml
   pii_detection:
     confidence_threshold: 0.5  # Lower threshold
   ```

2. **Enable more patterns:**
   ```yaml
   pii_detection:
     patterns:
       - type: "ssn"
         enabled: true
       - type: "credit_card"
         enabled: true
       # Enable all relevant patterns
   ```

3. **Add custom patterns:**
   ```yaml
   pii_detection:
     patterns:
       - type: "custom_id"
         pattern: "YOUR-REGEX-HERE"
         confidence: 0.8
   ```

4. **Check file format support:**
   - Supported: PDF, DOCX, XLSX, PPTX, TXT, CSV
   - Unsupported: Images, videos, encrypted files

---

## Integration Problems

### Issue: "Email alerts not sending"

**Symptoms:**
- No email notifications
- SMTP errors
- Connection timeouts

**Solutions:**

1. **Verify SMTP settings:**
   ```yaml
   integrations:
     email:
       smtp_host: "smtp.gmail.com"
       smtp_port: 587
       smtp_user: "alerts@example.com"
       smtp_password: "${SMTP_PASSWORD}"
   ```

2. **Test SMTP connection:**
   ```bash
   vaulytica test --test-email
   ```

3. **Check firewall:**
   ```bash
   telnet smtp.gmail.com 587
   ```

4. **Use app password (Gmail):**
   - Go to Google Account settings
   - Security > 2-Step Verification > App passwords
   - Generate app password

---

### Issue: "Slack notifications not working"

**Symptoms:**
- No Slack messages
- Webhook errors
- 404 errors

**Solutions:**

1. **Verify webhook URL:**
   ```yaml
   integrations:
     slack:
       webhook_url: "https://hooks.slack.com/services/..."
   ```

2. **Test webhook:**
   ```bash
   curl -X POST -H 'Content-type: application/json' \
     --data '{"text":"Test"}' \
     YOUR_WEBHOOK_URL
   ```

3. **Check Slack app permissions:**
   - Go to api.slack.com/apps
   - Select your app
   - Verify webhook is active

---

## Debugging Tips

### Enable Debug Logging

```yaml
logging:
  level: "DEBUG"
  format: "json"
  output: "/var/log/vaulytica/debug.log"
```

### Run with Verbose Output

```bash
vaulytica --verbose scan files
```

### Test Individual Components

```bash
# Test authentication
vaulytica test --test-auth

# Test configuration
vaulytica test --test-config

# Test email
vaulytica test --test-email

# Test Slack
vaulytica test --test-slack
```

### Check Logs

```bash
# View logs
tail -f /var/log/vaulytica/vaulytica.log

# Search for errors
grep ERROR /var/log/vaulytica/vaulytica.log

# View last 100 lines
tail -n 100 /var/log/vaulytica/vaulytica.log
```

### Python Debugging

```python
# Add to code for debugging
import pdb; pdb.set_trace()

# Or use logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## Getting Help

### Check Documentation

1. [Getting Started Guide](GETTING_STARTED.md)
2. [Architecture Guide](ARCHITECTURE.md)
3. [API Reference](API_REFERENCE.md)
4. [Security Guide](SECURITY.md)

### Community Support

- **GitHub Issues:** https://github.com/clay-good/vaulytica/issues
- **Discussions:** https://github.com/clay-good/vaulytica/discussions
- **Slack Community:** https://slack.example.com

### Report a Bug

When reporting a bug, include:

1. **Vaulytica version:**
   ```bash
   vaulytica --version
   ```

2. **Python version:**
   ```bash
   python --version
   ```

3. **Operating system:**
   ```bash
   uname -a
   ```

4. **Configuration (redacted):**
   ```yaml
   # Remove sensitive information
   ```

5. **Error message:**
   ```
   Full error traceback
   ```

6. **Steps to reproduce:**
   ```
   1. Run command X
   2. See error Y
   ```

7. **Logs:**
   ```bash
   # Last 50 lines of logs
   tail -n 50 /var/log/vaulytica/vaulytica.log
   ```

### Commercial Support

For enterprise support, contact: support@example.com

---

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `DefaultCredentialsError` | Invalid service account | Check service account file |
| `HttpError 403` | Insufficient permissions | Add required scopes |
| `HttpError 429` | Rate limit exceeded | Reduce request rate |
| `HttpError 404` | File not found | Skip deleted files |
| `MemoryError` | Out of memory | Enable chunked processing |
| `ConnectionError` | Network issue | Check internet connection |
| `TimeoutError` | Request timeout | Increase timeout value |
| `JSONDecodeError` | Invalid JSON | Validate configuration file |

---

## Performance Optimization Checklist

- [ ] Enable caching
- [ ] Use incremental scanning
- [ ] Increase concurrency (if resources allow)
- [ ] Scan external files only (if applicable)
- [ ] Enable chunked processing for large files
- [ ] Optimize PII patterns (disable unused patterns)
- [ ] Use batch API requests
- [ ] Schedule scans during off-peak hours
- [ ] Monitor resource usage
- [ ] Review and optimize configuration

---

For more help, see the [Getting Started Guide](GETTING_STARTED.md) or open an issue on GitHub.

