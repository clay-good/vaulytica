# Vaulytica API Client SDK

A Python client library for interacting with the Vaulytica API.

## Installation

```bash
pip install vaulytica-client
```

Or install from source:

```bash
cd sdk
pip install -e .
```

## Quick Start

### Basic Usage

```python
from vaulytica_client import VaulyticaClient

# Initialize client
client = VaulyticaClient(base_url="https://vaulytica.example.com")

# Authenticate
client.login("admin@example.com", "your-password")

# List recent scans
scans = client.scans.list(page=1, page_size=10)
print(f"Found {scans['total']} scans")

# Trigger a new file scan
scan = client.scans.trigger(domain_id=1, scan_type="files")
print(f"Started scan {scan['id']}")

# Get security findings
findings = client.findings.list_security(severity="critical")
for finding in findings['items']:
    print(f"- {finding['title']} ({finding['severity']})")

# Export findings to CSV
csv_data = client.findings.export_security(format="csv")
with open("findings.csv", "wb") as f:
    f.write(csv_data)

# Clean up
client.close()
```

### Using Context Manager

```python
from vaulytica_client import VaulyticaClient

with VaulyticaClient(base_url="https://vaulytica.example.com") as client:
    client.login("admin@example.com", "password")
    scans = client.scans.list()
```

### Async Usage

```python
import asyncio
from vaulytica_client.client import AsyncVaulyticaClient

async def main():
    async with AsyncVaulyticaClient(base_url="https://vaulytica.example.com") as client:
        await client.login("admin@example.com", "password")

        # Concurrent requests
        scans, findings = await asyncio.gather(
            client.scans.list(),
            client.findings.list_security()
        )

        print(f"Scans: {scans['total']}, Findings: {findings['total']}")

asyncio.run(main())
```

## API Resources

### Scans

```python
# List scans
scans = client.scans.list(
    page=1,
    page_size=20,
    domain_id=1,
    scan_type="files",  # files, users, oauth, posture, all
    status="completed"   # pending, running, completed, failed, cancelled
)

# Get specific scan
scan = client.scans.get(scan_id=123)

# Trigger new scan
scan = client.scans.trigger(
    domain_id=1,
    scan_type="all"
)

# Cancel running scan
scan = client.scans.cancel(scan_id=123, reason="User requested")

# Compare two scans
comparison = client.scans.compare(scan_id_1=100, scan_id_2=123)

# Get scan statistics
stats = client.scans.get_stats()
```

### Findings

```python
# Security findings
findings = client.findings.list_security(
    domain_id=1,
    severity="critical",  # critical, high, medium, low, info
    status="open"         # open, acknowledged, resolved, false_positive
)

# File findings
files = client.findings.list_files(
    domain_id=1,
    high_risk=True,
    public=True
)

# User findings
users = client.findings.list_users(
    domain_id=1,
    inactive=True,
    no_2fa=True
)

# OAuth app findings
oauth = client.findings.list_oauth(
    domain_id=1,
    risky=True
)

# Get specific finding
finding = client.findings.get_security(finding_id=456)

# Update finding status
client.findings.update_status(
    finding_id=456,
    status="resolved",
    notes="Fixed by IT team"
)

# Export findings
csv = client.findings.export_security(format="csv")
json_data = client.findings.export_files(format="json")
```

### Domains

```python
# List domains
domains = client.domains.list()

# Create domain
domain = client.domains.create(
    name="example.com",
    credentials={"type": "service_account", ...},
    admin_email="admin@example.com"
)

# Update domain
client.domains.update(
    domain_id=1,
    is_active=False
)

# Delete domain
client.domains.delete(domain_id=1)
```

### Schedules

```python
# List schedules
schedules = client.schedules.list(domain_id=1)

# Create schedule
schedule = client.schedules.create(
    name="Daily File Scan",
    domain_id=1,
    scan_type="files",
    schedule_type="daily",  # daily, weekly, monthly
    hour=2                   # Run at 2 AM
)

# Update schedule
client.schedules.update(
    schedule_id=1,
    hour=3
)

# Toggle pause/resume
client.schedules.toggle(schedule_id=1)

# Delete schedule
client.schedules.delete(schedule_id=1)
```

### Alerts

```python
# List alert rules
alerts = client.alerts.list(domain_id=1)

# Get condition types
conditions = client.alerts.get_condition_types()

# Create alert
alert = client.alerts.create(
    name="High Risk File Alert",
    domain_id=1,
    condition_type="high_risk_file",
    threshold=5,
    email_recipients=["security@example.com"],
    webhook_url="https://hooks.slack.com/..."
)

# Update alert
client.alerts.update(alert_id=1, threshold=10)

# Delete alert
client.alerts.delete(alert_id=1)
```

### Compliance

```python
# List reports
reports = client.compliance.list(
    domain_id=1,
    framework="hipaa"
)

# Get available frameworks
frameworks = client.compliance.get_frameworks()

# Generate new report
report = client.compliance.generate(
    domain_id=1,
    framework="gdpr"  # gdpr, hipaa, soc2, pci_dss, ferpa, fedramp
)

# Get report details
report = client.compliance.get(report_id=1)

# Delete report
client.compliance.delete(report_id=1)

# Schedule compliance reports
schedule = client.compliance.create_schedule(
    name="Monthly HIPAA",
    domain_id=1,
    framework="hipaa",
    schedule_type="monthly",
    recipients=["compliance@example.com"],
    day_of_month=1
)
```

### Users (Admin)

```python
# List users
users = client.users.list(
    search="john",
    is_active=True,
    is_superuser=False
)

# Get user
user = client.users.get(user_id=1)

# Update user
client.users.update(
    user_id=1,
    name="John Smith",
    is_superuser=True
)

# Deactivate user
client.users.deactivate(user_id=1)

# Activate user
client.users.activate(user_id=1)

# Delete user
client.users.delete(user_id=1)
```

### Audit Logs

```python
# List audit logs
logs = client.audit.list(
    action="login",
    resource_type="user",
    user_id=1,
    start_date="2024-01-01",
    end_date="2024-12-31"
)

# Get summary
summary = client.audit.get_summary()
```

### Delta Tracking & Deduplication

Track changes between scans and identify recurring findings.

```python
# Compare two scans to see what changed
delta = client.delta.compare(
    scan_id_1=100,  # Older scan
    scan_id_2=123,  # Newer scan
    finding_type="security"  # security, file, user, oauth
)
print(f"New: {delta['summary']['new_count']}")
print(f"Resolved: {delta['summary']['resolved_count']}")
print(f"Changed: {delta['summary']['changed_count']}")
print(f"Unchanged: {delta['summary']['unchanged_count']}")

# Get latest delta (between two most recent scans)
delta = client.delta.get_latest(
    domain="example.com",
    finding_type="files"
)

# Get trend data over multiple scans
trend = client.delta.get_trend(
    domain="example.com",
    finding_type="users",
    num_scans=10
)
for point in trend['data_points']:
    print(f"{point['scan_time']}: {point['total_findings']} findings")
    if point['new'] is not None:
        print(f"  +{point['new']} new, -{point['resolved']} resolved")

# Find duplicate/recurring findings
duplicates = client.delta.get_duplicates(
    domain="example.com",
    finding_type="oauth",
    lookback_scans=5
)
print(f"Found {duplicates['duplicate_count']} recurring findings")

# Get history of a specific finding by fingerprint
history = client.delta.get_history(
    fingerprint="abc123def456",
    domain="example.com",
    finding_type="security",
    max_scans=10
)
for entry in history['history']:
    status = "Present" if entry['present'] else "Not found"
    print(f"{entry['scan_time']}: {status}")

# Analyze a scan to see new vs recurring findings
analysis = client.delta.analyze(
    scan_id=123,
    finding_type="files"
)
print(f"Total: {analysis['total']}")
print(f"New: {analysis['new']}")
print(f"Recurring: {analysis['recurring']}")
```

## Error Handling

```python
from vaulytica_client import (
    VaulyticaClient,
    VaulyticaError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ValidationError
)

client = VaulyticaClient(base_url="https://vaulytica.example.com")

try:
    client.login("admin@example.com", "wrong-password")
except AuthenticationError as e:
    print(f"Login failed: {e}")

try:
    scan = client.scans.get(scan_id=99999)
except NotFoundError as e:
    print(f"Scan not found: {e}")

try:
    # Trigger many scans rapidly
    for i in range(100):
        client.scans.trigger(domain_id=1, scan_type="files")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds")

try:
    client.scans.trigger(domain_id=1, scan_type="invalid")
except ValidationError as e:
    print(f"Validation error: {e.errors}")

except VaulyticaError as e:
    # Catch-all for other API errors
    print(f"API error [{e.status_code}]: {e.message}")
```

## Configuration

### Timeout

```python
# Set custom timeout (default: 30 seconds)
client = VaulyticaClient(
    base_url="https://vaulytica.example.com",
    timeout=60.0
)
```

### SSL Verification

```python
# Disable SSL verification (not recommended for production)
client = VaulyticaClient(
    base_url="https://vaulytica.example.com",
    verify_ssl=False
)
```

### API Key Authentication

```python
# Use API key instead of login
client = VaulyticaClient(
    base_url="https://vaulytica.example.com",
    api_key="your-api-key"
)
```

## Development

### Running Tests

```bash
cd sdk
pip install -e ".[dev]"
pytest
```

### Type Checking

```bash
mypy vaulytica_client
```

## License

MIT License
