# Database Backup and Restore Guide

This guide covers backup and restore procedures for Vaulytica's PostgreSQL database, including automated backups, point-in-time recovery, and disaster recovery scenarios.

## Table of Contents

1. [Backup Types](#backup-types)
2. [Manual Backups](#manual-backups)
3. [Automated Backups](#automated-backups)
4. [Restore Procedures](#restore-procedures)
5. [Point-in-Time Recovery](#point-in-time-recovery)
6. [Cloud Provider Backups](#cloud-provider-backups)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Backup Types

### Full Backup (pg_dump)

Creates a complete snapshot of the database. Best for:
- Small to medium databases (< 10GB)
- Regular scheduled backups
- Migration between environments

### Continuous Archiving (WAL)

Continuously archives write-ahead logs for point-in-time recovery. Best for:
- Large databases
- Minimal data loss requirements (RPO < 5 minutes)
- Compliance requirements

### File System Backup

Physical backup of PostgreSQL data directory. Best for:
- Very large databases (> 100GB)
- Fastest restore times
- Requires database shutdown or pg_basebackup

---

## Manual Backups

### Using pg_dump (Recommended)

#### Full Database Backup

```bash
# Plain SQL format (human-readable, slower restore)
pg_dump -U vaulytica -h localhost -d vaulytica > backup_$(date +%Y%m%d_%H%M%S).sql

# Custom format (compressed, parallel restore)
pg_dump -U vaulytica -h localhost -d vaulytica -Fc > backup_$(date +%Y%m%d_%H%M%S).dump

# Directory format (parallel dump and restore)
pg_dump -U vaulytica -h localhost -d vaulytica -Fd -j 4 -f backup_$(date +%Y%m%d)
```

#### Docker Environment

```bash
# Backup from Docker container
docker compose exec -T postgres pg_dump -U vaulytica vaulytica > backup_$(date +%Y%m%d_%H%M%S).sql

# Custom format backup
docker compose exec -T postgres pg_dump -U vaulytica -Fc vaulytica > backup_$(date +%Y%m%d_%H%M%S).dump
```

#### Backup Specific Tables

```bash
# Backup only scan-related tables
pg_dump -U vaulytica -d vaulytica \
  -t scan_runs \
  -t security_findings \
  -t file_findings \
  -t user_findings \
  -t oauth_findings \
  -Fc > scans_backup.dump

# Backup only user/auth tables
pg_dump -U vaulytica -d vaulytica \
  -t users \
  -t domains \
  -t user_domain_access \
  -t password_reset_tokens \
  -Fc > auth_backup.dump
```

#### Backup with Data Exclusion

```bash
# Schema only (no data)
pg_dump -U vaulytica -d vaulytica --schema-only > schema_backup.sql

# Exclude large tables from backup
pg_dump -U vaulytica -d vaulytica \
  --exclude-table=audit_logs \
  --exclude-table=finding_history \
  -Fc > backup_without_history.dump
```

### Verify Backup Integrity

```bash
# List contents of custom format backup
pg_restore -l backup.dump

# Test restore without actually restoring
pg_restore --list backup.dump > /dev/null && echo "Backup is valid"

# Check backup file size and compression
ls -lh backup.dump
```

---

## Automated Backups

### Cron-based Backups

Create a backup script at `/opt/vaulytica/scripts/backup.sh`:

```bash
#!/bin/bash
set -e

# Configuration
BACKUP_DIR="/var/backups/vaulytica"
RETENTION_DAYS=30
DB_USER="vaulytica"
DB_NAME="vaulytica"
DB_HOST="localhost"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/vaulytica_${TIMESTAMP}.dump"

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Perform backup
echo "Starting backup at $(date)"
pg_dump -U "${DB_USER}" -h "${DB_HOST}" -d "${DB_NAME}" -Fc -f "${BACKUP_FILE}"

# Verify backup
if pg_restore -l "${BACKUP_FILE}" > /dev/null 2>&1; then
    echo "Backup verified successfully"

    # Compress with gzip for additional space savings
    gzip "${BACKUP_FILE}"
    BACKUP_FILE="${BACKUP_FILE}.gz"

    echo "Backup completed: ${BACKUP_FILE}"
    echo "Size: $(ls -lh ${BACKUP_FILE} | awk '{print $5}')"
else
    echo "ERROR: Backup verification failed!"
    rm -f "${BACKUP_FILE}"
    exit 1
fi

# Cleanup old backups
echo "Cleaning up backups older than ${RETENTION_DAYS} days"
find "${BACKUP_DIR}" -name "vaulytica_*.dump.gz" -mtime +${RETENTION_DAYS} -delete

# Log completion
echo "Backup completed at $(date)"
```

Add to crontab:

```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /opt/vaulytica/scripts/backup.sh >> /var/log/vaulytica-backup.log 2>&1

# Add hourly backup for critical environments
0 * * * * /opt/vaulytica/scripts/backup.sh >> /var/log/vaulytica-backup.log 2>&1
```

### Docker Compose Backup Service

Add to `docker-compose.yml`:

```yaml
services:
  backup:
    image: postgres:15
    volumes:
      - ./backups:/backups
      - ./scripts/docker-backup.sh:/backup.sh:ro
    environment:
      PGHOST: postgres
      PGUSER: vaulytica
      PGPASSWORD: ${POSTGRES_PASSWORD}
      PGDATABASE: vaulytica
    entrypoint: ["/bin/sh", "-c"]
    command: ["while true; do /backup.sh; sleep 86400; done"]
    depends_on:
      postgres:
        condition: service_healthy
```

Create `scripts/docker-backup.sh`:

```bash
#!/bin/bash
BACKUP_FILE="/backups/vaulytica_$(date +%Y%m%d_%H%M%S).dump"
pg_dump -Fc -f "${BACKUP_FILE}"
gzip "${BACKUP_FILE}"
find /backups -name "*.dump.gz" -mtime +30 -delete
echo "Backup completed: ${BACKUP_FILE}.gz"
```

### Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vaulytica-db-backup
  namespace: vaulytica
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15
            env:
            - name: PGHOST
              value: postgres-service
            - name: PGUSER
              valueFrom:
                secretKeyRef:
                  name: vaulytica-db
                  key: username
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: vaulytica-db
                  key: password
            - name: PGDATABASE
              value: vaulytica
            command:
            - /bin/sh
            - -c
            - |
              BACKUP_FILE="/backups/vaulytica_$(date +%Y%m%d_%H%M%S).dump"
              pg_dump -Fc -f "${BACKUP_FILE}"
              gzip "${BACKUP_FILE}"
            volumeMounts:
            - name: backup-storage
              mountPath: /backups
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

---

## Restore Procedures

### Full Database Restore

#### From Custom Format (.dump)

```bash
# Drop and recreate database (CAUTION: destroys all data)
dropdb -U vaulytica vaulytica
createdb -U vaulytica vaulytica

# Restore
pg_restore -U vaulytica -d vaulytica -Fc backup.dump

# Or restore with verbose output
pg_restore -U vaulytica -d vaulytica -Fc -v backup.dump
```

#### From SQL Format

```bash
# Drop and recreate database
dropdb -U vaulytica vaulytica
createdb -U vaulytica vaulytica

# Restore
psql -U vaulytica -d vaulytica < backup.sql
```

#### Docker Environment

```bash
# Stop application containers (keep postgres running)
docker compose stop backend scan-runner

# Restore from backup
gunzip -k backup.dump.gz  # Decompress if needed
docker compose exec -T postgres psql -U vaulytica -c "DROP DATABASE vaulytica;"
docker compose exec -T postgres psql -U vaulytica -c "CREATE DATABASE vaulytica;"
docker compose exec -T postgres pg_restore -U vaulytica -d vaulytica -Fc < backup.dump

# Restart application
docker compose up -d
```

### Partial Restore (Specific Tables)

```bash
# List available tables in backup
pg_restore -l backup.dump | grep TABLE

# Restore only specific tables
pg_restore -U vaulytica -d vaulytica \
  -t scan_runs \
  -t security_findings \
  --data-only \
  backup.dump
```

### Restore to Different Database

```bash
# Create new database
createdb -U vaulytica vaulytica_restored

# Restore
pg_restore -U vaulytica -d vaulytica_restored backup.dump

# Verify
psql -U vaulytica -d vaulytica_restored -c "\dt"
```

### Parallel Restore (Faster for Large Databases)

```bash
# Restore with 4 parallel jobs
pg_restore -U vaulytica -d vaulytica -j 4 backup.dump
```

---

## Point-in-Time Recovery

### Enable WAL Archiving

Configure PostgreSQL for continuous archiving in `postgresql.conf`:

```ini
# Enable WAL archiving
wal_level = replica
archive_mode = on
archive_command = 'cp %p /var/lib/postgresql/wal_archive/%f'

# Keep more WAL files
max_wal_senders = 3
wal_keep_size = 1GB
```

### Create Base Backup

```bash
# Create base backup using pg_basebackup
pg_basebackup -U vaulytica -D /var/backups/base -Fp -Xs -P

# Create compressed base backup
pg_basebackup -U vaulytica -D /var/backups/base -Ft -z -Xs -P
```

### Recover to Specific Point in Time

1. Stop PostgreSQL:
```bash
systemctl stop postgresql
```

2. Backup current data directory:
```bash
mv /var/lib/postgresql/15/main /var/lib/postgresql/15/main_old
```

3. Restore base backup:
```bash
cp -r /var/backups/base /var/lib/postgresql/15/main
```

4. Create recovery signal file with target time:
```bash
cat > /var/lib/postgresql/15/main/recovery.signal << EOF
# Recovery will proceed until this point
EOF

cat >> /var/lib/postgresql/15/main/postgresql.auto.conf << EOF
restore_command = 'cp /var/lib/postgresql/wal_archive/%f %p'
recovery_target_time = '2024-12-15 14:30:00'
recovery_target_action = 'promote'
EOF
```

5. Start PostgreSQL:
```bash
systemctl start postgresql
```

6. Verify recovery:
```bash
psql -U vaulytica -d vaulytica -c "SELECT MAX(created_at) FROM scan_runs;"
```

---

## Cloud Provider Backups

### AWS RDS

```bash
# Create manual snapshot
aws rds create-db-snapshot \
  --db-instance-identifier vaulytica-prod \
  --db-snapshot-identifier vaulytica-backup-$(date +%Y%m%d)

# List snapshots
aws rds describe-db-snapshots \
  --db-instance-identifier vaulytica-prod

# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier vaulytica-restored \
  --db-snapshot-identifier vaulytica-backup-20241215
```

Enable automated backups:
```bash
aws rds modify-db-instance \
  --db-instance-identifier vaulytica-prod \
  --backup-retention-period 30 \
  --preferred-backup-window "02:00-03:00" \
  --apply-immediately
```

### Google Cloud SQL

```bash
# Create backup
gcloud sql backups create \
  --instance=vaulytica-prod \
  --description="Manual backup $(date)"

# List backups
gcloud sql backups list --instance=vaulytica-prod

# Restore from backup
gcloud sql backups restore BACKUP_ID \
  --restore-instance=vaulytica-prod \
  --backup-instance=vaulytica-prod
```

### Azure Database for PostgreSQL

```bash
# Create backup (via Portal or ARM template)
az postgres server-backup create \
  --resource-group vaulytica-rg \
  --server-name vaulytica-prod \
  --backup-name vaulytica-backup-$(date +%Y%m%d)

# Restore to new server
az postgres server restore \
  --resource-group vaulytica-rg \
  --name vaulytica-restored \
  --source-server vaulytica-prod \
  --restore-point-in-time "2024-12-15T14:30:00Z"
```

### Backup to S3/GCS

```bash
# Backup to S3
pg_dump -U vaulytica -Fc vaulytica | \
  aws s3 cp - s3://vaulytica-backups/vaulytica_$(date +%Y%m%d).dump

# Backup to GCS
pg_dump -U vaulytica -Fc vaulytica | \
  gsutil cp - gs://vaulytica-backups/vaulytica_$(date +%Y%m%d).dump

# Restore from S3
aws s3 cp s3://vaulytica-backups/vaulytica_20241215.dump - | \
  pg_restore -U vaulytica -d vaulytica
```

---

## Best Practices

### Backup Strategy

1. **3-2-1 Rule**:
   - 3 copies of data
   - 2 different storage media
   - 1 offsite copy

2. **Frequency**:
   - Production: Daily full backup + continuous WAL archiving
   - Staging: Daily full backup
   - Development: Weekly full backup

3. **Retention**:
   - Daily backups: 7 days
   - Weekly backups: 4 weeks
   - Monthly backups: 12 months
   - Annual backups: 7 years (for compliance)

### Security

1. **Encrypt backups**:
```bash
# Encrypt with GPG
pg_dump -U vaulytica -Fc vaulytica | \
  gpg --symmetric --cipher-algo AES256 > backup.dump.gpg

# Decrypt for restore
gpg --decrypt backup.dump.gpg | pg_restore -U vaulytica -d vaulytica
```

2. **Secure backup storage**:
   - Use separate IAM roles for backup access
   - Enable versioning on S3/GCS buckets
   - Enable access logging

3. **Test restores regularly**:
   - Monthly: Full restore to test environment
   - Quarterly: Full disaster recovery drill

### Monitoring

1. **Alert on backup failures**:
```bash
# Add to backup script
if [ $? -ne 0 ]; then
    curl -X POST https://hooks.slack.com/... \
      -d '{"text":"Vaulytica backup failed!"}'
fi
```

2. **Monitor backup size trends**:
```bash
# Check backup sizes
ls -lh /var/backups/vaulytica/*.dump.gz | tail -10
```

3. **Verify backup integrity weekly**:
```bash
# Add verification script
for f in /var/backups/vaulytica/*.dump.gz; do
    gunzip -t "$f" && echo "OK: $f" || echo "CORRUPT: $f"
done
```

---

## Troubleshooting

### Common Issues

#### 1. Backup Fails with "Connection Refused"

```
pg_dump: error: connection to server failed: Connection refused
```

**Solution:**
- Verify PostgreSQL is running: `systemctl status postgresql`
- Check connection settings in `pg_hba.conf`
- Verify PGHOST and PGPORT are correct

#### 2. Backup Fails with "Permission Denied"

```
pg_dump: error: query failed: permission denied for table
```

**Solution:**
- Ensure backup user has SELECT privileges:
```sql
GRANT SELECT ON ALL TABLES IN SCHEMA public TO backup_user;
```

#### 3. Restore Fails with "Database Already Exists"

```
pg_restore: error: could not execute query: database "vaulytica" already exists
```

**Solution:**
```bash
# Drop existing database first
dropdb -U vaulytica vaulytica
createdb -U vaulytica vaulytica
pg_restore -U vaulytica -d vaulytica backup.dump
```

#### 4. Restore Fails with "Role Does Not Exist"

```
pg_restore: error: role "some_user" does not exist
```

**Solution:**
```bash
# Create missing role before restore
psql -U postgres -c "CREATE ROLE some_user;"

# Or ignore role-related errors
pg_restore --no-owner --no-privileges -U vaulytica -d vaulytica backup.dump
```

#### 5. Backup Takes Too Long

**Solution:**
- Use parallel dump:
```bash
pg_dump -j 4 -Fd -f /backup/dir vaulytica
```
- Exclude large tables if not critical
- Run backups during low-traffic periods

#### 6. Out of Disk Space

```
pg_dump: error: could not write to output file: No space left on device
```

**Solution:**
- Clean up old backups
- Use compression:
```bash
pg_dump -U vaulytica vaulytica | gzip > backup.sql.gz
```
- Stream to remote storage:
```bash
pg_dump -U vaulytica -Fc vaulytica | aws s3 cp - s3://bucket/backup.dump
```

### Recovery Verification Checklist

After restoring, verify:

```bash
# 1. Check table counts
psql -U vaulytica -d vaulytica -c "
SELECT schemaname, relname, n_live_tup
FROM pg_stat_user_tables
ORDER BY n_live_tup DESC;"

# 2. Check latest records
psql -U vaulytica -d vaulytica -c "
SELECT MAX(created_at) as latest FROM scan_runs;
SELECT MAX(detected_at) as latest FROM security_findings;"

# 3. Run application health check
curl http://localhost:8000/health

# 4. Verify user authentication works
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "test"}'
```

---

## Quick Reference

### Backup Commands

| Command | Description |
|---------|-------------|
| `pg_dump -Fc vaulytica > backup.dump` | Full backup (custom format) |
| `pg_dump -Fp vaulytica > backup.sql` | Full backup (SQL format) |
| `pg_dump -Fd -j 4 -f dir/ vaulytica` | Parallel backup |
| `pg_dump --schema-only vaulytica` | Schema only |
| `pg_dump -t table_name vaulytica` | Single table |

### Restore Commands

| Command | Description |
|---------|-------------|
| `pg_restore -d vaulytica backup.dump` | Full restore |
| `pg_restore -j 4 -d vaulytica backup.dump` | Parallel restore |
| `pg_restore --data-only -d vaulytica backup.dump` | Data only |
| `pg_restore -t table_name -d vaulytica backup.dump` | Single table |
| `psql -d vaulytica < backup.sql` | Restore SQL format |

### Docker Commands

| Command | Description |
|---------|-------------|
| `docker compose exec -T postgres pg_dump -U vaulytica vaulytica` | Backup from container |
| `docker compose exec -T postgres pg_restore -d vaulytica < backup.dump` | Restore to container |
