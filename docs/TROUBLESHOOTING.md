# Vaulytica Troubleshooting Guide

This guide covers common issues, error messages, and their solutions for both the CLI and web application.

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Authentication & Authorization](#authentication--authorization)
3. [Google API Errors](#google-api-errors)
4. [Scanning Issues](#scanning-issues)
5. [Database Issues](#database-issues)
6. [Web Application Issues](#web-application-issues)
7. [Docker Issues](#docker-issues)
8. [Performance Issues](#performance-issues)
9. [CLI Issues](#cli-issues)
10. [Getting Help](#getting-help)

---

## Quick Diagnostics

### Health Check Commands

```bash
# CLI health check
vaulytica --version
vaulytica config validate

# Web backend health check
curl http://localhost:8000/health

# Database connectivity
curl http://localhost:8000/health | jq '.database'

# Docker container status
docker compose ps
docker compose logs --tail=50
```

### Enable Debug Logging

```bash
# CLI
export VAULYTICA_LOG_LEVEL=DEBUG
vaulytica scan files --domain example.com

# Web backend (in .env)
DEBUG=true
LOG_LEVEL=DEBUG
```

### Collect Diagnostic Information

```bash
# System info
uname -a
python --version
pip show vaulytica

# Docker info
docker version
docker compose version

# Database info
psql -U vaulytica -c "SELECT version();"
```

---

## Authentication & Authorization

### Error: 401 Unauthorized - Invalid credentials

**Symptom:**
```
Error: 401 Unauthorized - Invalid credentials
```

**Causes & Solutions:**

1. **Service account JSON is invalid or expired**
   ```bash
   # Verify JSON file is valid
   cat credentials/service-account.json | jq .

   # Check expiration
   cat credentials/service-account.json | jq '.private_key_id'
   ```
   **Solution:** Generate a new service account key in Google Cloud Console.

2. **Wrong credentials file path**
   ```bash
   # Check file exists
   ls -la ~/.vaulytica/credentials.json

   # Or custom path
   ls -la $GOOGLE_APPLICATION_CREDENTIALS
   ```
   **Solution:** Set correct path:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
   ```

3. **Domain-wide delegation not enabled**
   - Go to Google Admin Console > Security > API Controls
   - Verify the service account client ID is authorized
   - Verify all required scopes are listed

### Error: 403 Forbidden - Insufficient permissions

**Symptom:**
```
Error: 403 Forbidden - User not authorized to access domain
```

**Causes & Solutions:**

1. **Missing OAuth scopes**

   Required scopes for full functionality:
   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly
   https://www.googleapis.com/auth/admin.directory.group.readonly
   https://www.googleapis.com/auth/drive.readonly
   https://www.googleapis.com/auth/gmail.readonly
   ```

   **Solution:** Add missing scopes in Admin Console > Security > API Controls > Domain-wide Delegation

2. **Service account not delegated**

   **Solution:**
   - In Google Cloud Console, enable "Enable G Suite Domain-wide Delegation" for the service account
   - In Admin Console, add the client ID with required scopes

3. **User doesn't have admin privileges**
   ```
   Error: User admin@example.com does not have access to domain
   ```

   **Solution:** Ensure the impersonated user is a Google Workspace super admin.

### Error: Token refresh failed

**Symptom:**
```
google.auth.exceptions.RefreshError: The credentials do not contain the necessary fields
```

**Solutions:**

1. Check service account JSON has all required fields:
   ```bash
   cat credentials.json | jq 'keys'
   # Should include: client_email, private_key, project_id, etc.
   ```

2. Regenerate credentials:
   - Go to Google Cloud Console > IAM > Service Accounts
   - Select your service account
   - Keys > Add Key > Create new key > JSON

---

## Google API Errors

### Error: 429 Too Many Requests - Rate limit exceeded

**Symptom:**
```
Error: 429 Too Many Requests - Rate limit exceeded. Retry after 60 seconds.
```

**Solutions:**

1. **Reduce concurrent requests**
   ```bash
   # CLI: Use smaller batch size
   vaulytica scan files --domain example.com --batch-size 10
   ```

2. **Configure rate limiting in config**
   ```yaml
   # config/config.yaml
   rate_limits:
     drive_api: 50  # requests per second
     admin_api: 25
     gmail_api: 10
   ```

3. **Enable exponential backoff** (enabled by default)
   ```python
   # Already handled in scanners
   # Retries: 3 attempts with exponential backoff
   ```

4. **Request quota increase**
   - Go to Google Cloud Console > APIs & Services > Quotas
   - Request increased quota for affected APIs

### Error: 404 Not Found - File/User not found

**Symptom:**
```
Error: 404 Not Found - File 'abc123' not found
```

**Causes:**
- File was deleted between scan runs
- User lost access to the file
- File ID is from a different domain

**Solution:** This is typically informational. The scanner will continue with remaining files.

### Error: 500 Internal Server Error from Google

**Symptom:**
```
Error: 500 Backend Error - Google API internal error
```

**Solutions:**

1. **Retry the operation** - Google API errors are often transient
   ```bash
   # Scanner automatically retries with exponential backoff
   ```

2. **Check Google Workspace Status Dashboard**
   - https://www.google.com/appsstatus/dashboard/

3. **Reduce batch size**
   ```bash
   vaulytica scan files --domain example.com --batch-size 5
   ```

---

## Scanning Issues

### Scan Stuck at 0%

**Symptom:** Scan shows "Running" but progress stays at 0%.

**Causes & Solutions:**

1. **Authentication issue**
   ```bash
   # Test authentication
   vaulytica test-auth --domain example.com
   ```

2. **Large domain initialization**
   - First scan on large domains may take time to enumerate users/files
   - Check logs for progress:
   ```bash
   docker compose logs -f scan-runner
   ```

3. **Network connectivity issue**
   ```bash
   # Test connectivity to Google APIs
   curl -I https://www.googleapis.com/discovery/v1/apis
   ```

### Scan Completes with 0 Findings

**Symptom:** Scan completes successfully but shows 0 findings.

**Causes & Solutions:**

1. **No externally shared files exist**
   - This might be expected if your domain has strict sharing settings

2. **Insufficient permissions**
   ```bash
   # Verify the impersonated user can see files
   # Check logs for permission errors
   docker compose logs backend | grep -i "permission\|forbidden"
   ```

3. **Filter too restrictive**
   ```bash
   # Scan all file types, not just high-risk
   vaulytica scan files --domain example.com --include-all
   ```

### Scan Fails Midway

**Symptom:** Scan starts but fails before completion.

**Solutions:**

1. **Check for rate limiting**
   ```bash
   docker compose logs backend | grep -i "429\|rate"
   ```

2. **Check for memory issues**
   ```bash
   docker stats
   ```

   Increase memory limits in docker-compose.yml:
   ```yaml
   services:
     scan-runner:
       deploy:
         resources:
           limits:
             memory: 4G
   ```

3. **Enable partial result saving** (default behavior)
   - Partial results are saved automatically
   - Check findings from before the failure

### PII Detection Missing Expected Patterns

**Symptom:** Known PII in files is not detected.

**Solutions:**

1. **Check if pattern is enabled**
   ```yaml
   # vaulytica/config/pii_patterns.yaml
   ssn:
     enabled: true  # Make sure this is true
   ```

2. **Check confidence threshold**
   ```yaml
   ssn:
     min_confidence: 0.5  # Lower if missing matches
   ```

3. **Test pattern manually**
   ```bash
   vaulytica scan files --domain example.com \
     --test-pattern "ssn" \
     --content "SSN: 123-45-6789"
   ```

4. **Add custom pattern**
   ```yaml
   # vaulytica/config/pii_patterns.yaml
   custom:
     my_pattern:
       enabled: true
       patterns:
         - pattern: '\bMY-\d{6}\b'
           confidence: 0.9
   ```

---

## Database Issues

### Error: Connection refused to database

**Symptom:**
```
sqlalchemy.exc.OperationalError: could not connect to server: Connection refused
```

**Solutions:**

1. **Verify PostgreSQL is running**
   ```bash
   docker compose ps postgres
   # Should show "running" or "healthy"

   # Start if not running
   docker compose up -d postgres
   ```

2. **Check DATABASE_URL format**
   ```bash
   # Correct format
   DATABASE_URL=postgresql://user:password@host:5432/database

   # Common mistakes:
   # - Missing postgresql:// prefix
   # - Wrong port (default is 5432)
   # - Password with special characters needs URL encoding
   ```

3. **Check network connectivity (Docker)**
   ```bash
   # Backend should connect to postgres, not localhost
   DATABASE_URL=postgresql://vaulytica:password@postgres:5432/vaulytica
   ```

### Error: Database migration failed

**Symptom:**
```
alembic.util.exc.CommandError: Can't locate revision identified by 'abc123'
```

**Solutions:**

1. **Reset migration state** (development only)
   ```bash
   # Backup data first!
   docker compose exec backend alembic downgrade base
   docker compose exec backend alembic upgrade head
   ```

2. **Stamp current revision**
   ```bash
   docker compose exec backend alembic stamp head
   ```

3. **Manual schema fix**
   ```sql
   -- Check current state
   SELECT * FROM alembic_version;

   -- Update to match actual schema
   UPDATE alembic_version SET version_num = 'current_revision';
   ```

### Error: Duplicate key violation

**Symptom:**
```
sqlalchemy.exc.IntegrityError: duplicate key value violates unique constraint
```

**Solutions:**

1. **For scan data conflicts**
   ```bash
   # Data may already exist from previous scan
   # Delete and re-scan
   vaulytica admin cleanup --domain example.com --scans
   ```

2. **Check for race conditions**
   - Ensure only one scan runs per domain at a time
   - Web UI prevents concurrent scans automatically

### Database Performance Degradation

**Symptom:** Queries taking longer over time.

**Solutions:**

1. **Run VACUUM ANALYZE**
   ```bash
   docker compose exec postgres vacuumdb -U vaulytica -d vaulytica -z
   ```

2. **Check for missing indexes**
   ```sql
   -- Find slow queries
   SELECT query, calls, mean_time
   FROM pg_stat_statements
   ORDER BY mean_time DESC
   LIMIT 10;
   ```

3. **Check table bloat**
   ```sql
   SELECT schemaname, tablename,
          pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
   FROM pg_tables
   WHERE schemaname = 'public'
   ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
   ```

---

## Web Application Issues

### Frontend: White screen / App won't load

**Symptom:** Browser shows white screen or loading indefinitely.

**Solutions:**

1. **Check for JavaScript errors**
   - Open browser DevTools (F12)
   - Check Console tab for errors

2. **Clear browser cache**
   - Hard refresh: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (Mac)

3. **Verify frontend is running**
   ```bash
   docker compose ps frontend
   curl http://localhost:3000
   ```

4. **Check for API connectivity**
   ```bash
   curl http://localhost:8000/api/v1/auth/me
   # Should return 401, not connection error
   ```

### API: 500 Internal Server Error

**Symptom:** API calls return 500 errors.

**Solutions:**

1. **Check backend logs**
   ```bash
   docker compose logs backend --tail=100
   ```

2. **Enable debug mode**
   ```bash
   # In .env
   DEBUG=true
   ```

3. **Common causes:**
   - Database connection lost
   - Invalid configuration
   - Missing environment variables

### WebSocket Connection Failed

**Symptom:** "Live" indicator shows "Polling" instead of "Live".

**Solutions:**

1. **Check WebSocket endpoint**
   ```bash
   # Should return 101 Switching Protocols
   curl -i -N \
     -H "Connection: Upgrade" \
     -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" \
     -H "Sec-WebSocket-Key: test" \
     http://localhost:8000/api/v1/ws
   ```

2. **Check for proxy issues**
   - Nginx/reverse proxy must support WebSocket
   ```nginx
   location /api/v1/ws {
       proxy_pass http://backend:8000;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
   }
   ```

3. **Fallback to polling is safe**
   - The app automatically falls back to polling
   - Functionality is not affected

### Login Failed - CORS Error

**Symptom:**
```
Access to fetch at 'http://localhost:8000/api' from origin 'http://localhost:3000'
has been blocked by CORS policy
```

**Solutions:**

1. **Check CORS_ORIGINS in backend**
   ```bash
   # In .env
   CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
   ```

2. **For development**
   ```bash
   # Allow all origins (development only!)
   CORS_ORIGINS=*
   ```

3. **Verify frontend is using correct API URL**
   ```typescript
   // lib/api.ts
   const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
   ```

---

## Docker Issues

### Container Keeps Restarting

**Symptom:** Container shows "Restarting" status.

**Solutions:**

1. **Check container logs**
   ```bash
   docker compose logs backend --tail=100
   ```

2. **Check for missing environment variables**
   ```bash
   docker compose config  # Validate compose file
   ```

3. **Check for port conflicts**
   ```bash
   lsof -i :8000  # Check if port is in use
   ```

4. **Increase resource limits**
   ```yaml
   services:
     backend:
       deploy:
         resources:
           limits:
             memory: 2G
   ```

### Error: No space left on device

**Symptom:**
```
Error: no space left on device
```

**Solutions:**

1. **Clean up Docker resources**
   ```bash
   docker system prune -a --volumes
   ```

2. **Remove old images**
   ```bash
   docker image prune -a
   ```

3. **Check disk usage**
   ```bash
   docker system df
   df -h
   ```

### Build Fails

**Symptom:** `docker compose build` fails.

**Solutions:**

1. **Clear build cache**
   ```bash
   docker compose build --no-cache
   ```

2. **Check Dockerfile syntax**
   ```bash
   docker build --check .
   ```

3. **Check for network issues**
   ```bash
   # If pip/npm can't download packages
   docker compose build --network host
   ```

---

## Performance Issues

### High Memory Usage

**Symptom:** Container/process using excessive memory.

**Solutions:**

1. **Enable scan chunking**
   ```bash
   # Process files in smaller batches
   vaulytica scan files --domain example.com --chunk-size 100
   ```

2. **Limit concurrent operations**
   ```yaml
   # config/config.yaml
   concurrency:
     max_workers: 2  # Reduce from default
   ```

3. **Increase swap space** (temporary fix)
   ```bash
   sudo fallocate -l 4G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   ```

### Slow API Responses

**Symptom:** API calls taking > 5 seconds.

**Solutions:**

1. **Check database query performance**
   ```sql
   -- Enable slow query logging
   ALTER SYSTEM SET log_min_duration_statement = 1000;  -- Log queries > 1s
   SELECT pg_reload_conf();
   ```

2. **Check cache status**
   ```bash
   curl http://localhost:8000/health | jq '.cache'
   ```

3. **Add database indexes**
   ```sql
   -- Check for missing indexes
   EXPLAIN ANALYZE SELECT * FROM security_findings WHERE domain_id = 1;
   ```

### Scan Taking Too Long

**Symptom:** Scans taking hours for medium-sized domains.

**Solutions:**

1. **Use parallel scanning**
   ```bash
   vaulytica scan files --domain example.com --workers 4
   ```

2. **Scan specific file types**
   ```bash
   # Only scan documents, not images/videos
   vaulytica scan files --domain example.com \
     --file-types "document,spreadsheet,presentation"
   ```

3. **Exclude users**
   ```bash
   # Skip certain users
   vaulytica scan files --domain example.com \
     --exclude-users "service-account@example.com"
   ```

---

## CLI Issues

### Command Not Found

**Symptom:**
```
bash: vaulytica: command not found
```

**Solutions:**

1. **Install vaulytica**
   ```bash
   pip install vaulytica
   # or
   pip install -e .  # From source
   ```

2. **Check PATH**
   ```bash
   which vaulytica
   # or
   python -m vaulytica --help
   ```

3. **Activate virtual environment**
   ```bash
   source venv/bin/activate
   ```

### Configuration Not Found

**Symptom:**
```
Error: Configuration file not found at ~/.vaulytica/config.yaml
```

**Solutions:**

1. **Initialize configuration**
   ```bash
   vaulytica init
   ```

2. **Specify config path**
   ```bash
   vaulytica --config /path/to/config.yaml scan files
   ```

3. **Use environment variables**
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/creds.json
   export VAULYTICA_DOMAIN=example.com
   ```

### Output Encoding Issues

**Symptom:**
```
UnicodeEncodeError: 'ascii' codec can't encode character
```

**Solutions:**

1. **Set locale**
   ```bash
   export LANG=en_US.UTF-8
   export LC_ALL=en_US.UTF-8
   ```

2. **Use UTF-8 output**
   ```bash
   vaulytica scan files --domain example.com --output report.json
   # Instead of piping to console
   ```

---

## Getting Help

### Collect Debug Information

When reporting issues, include:

```bash
# System information
uname -a
python --version
pip show vaulytica

# Docker information (if applicable)
docker version
docker compose version
docker compose ps

# Recent logs
docker compose logs --tail=200 > logs.txt

# Configuration (sanitized)
cat .env | grep -v PASSWORD | grep -v SECRET
```

### Log Locations

| Component | Location |
|-----------|----------|
| CLI | `~/.vaulytica/logs/` or console |
| Backend | `docker compose logs backend` |
| Frontend | Browser DevTools Console |
| PostgreSQL | `docker compose logs postgres` |
| Scan Runner | `docker compose logs scan-runner` |

### Support Resources

1. **Documentation**
   - Production Deployment: [PRODUCTION_DEPLOYMENT.md](./PRODUCTION_DEPLOYMENT.md)
   - Custom PII Patterns: [CUSTOM_PII_PATTERNS.md](./CUSTOM_PII_PATTERNS.md)
   - Database Backup: [DATABASE_BACKUP_RESTORE.md](./DATABASE_BACKUP_RESTORE.md)

2. **GitHub Issues**
   - Search existing issues first
   - Include debug information when creating new issues

3. **Community**
   - Check discussions for common questions
   - Share solutions that worked for you

### Error Code Reference

| Code | Category | Description |
|------|----------|-------------|
| AUTH001 | Authentication | Invalid credentials |
| AUTH002 | Authentication | Token expired |
| AUTH003 | Authorization | Insufficient permissions |
| API001 | Google API | Rate limit exceeded |
| API002 | Google API | Resource not found |
| API003 | Google API | Internal server error |
| DB001 | Database | Connection failed |
| DB002 | Database | Query timeout |
| DB003 | Database | Constraint violation |
| SCAN001 | Scanning | No files found |
| SCAN002 | Scanning | Scan cancelled |
| SCAN003 | Scanning | Partial failure |
