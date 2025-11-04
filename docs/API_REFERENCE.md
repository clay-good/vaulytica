# Vaulytica API Reference

**Version:** 1.0  
**Last Updated:** 2025-10-28

---

## Table of Contents

1. [Core Modules](#core-modules)
2. [Scanners](#scanners)
3. [Detectors](#detectors)
4. [Integrations](#integrations)
5. [Utilities](#utilities)
6. [Storage](#storage)
7. [CLI Commands](#cli-commands)

---

## Core Modules

### GoogleWorkspaceClient

**Location:** `vaulytica/core/auth/client.py`

Main client for interacting with Google Workspace APIs.

#### Constructor

```python
GoogleWorkspaceClient(
    service_account_file: str,
    subject_email: str,
    scopes: List[str]
)
```

**Parameters:**
- `service_account_file` (str): Path to service account JSON file
- `subject_email` (str): Email address to impersonate
- `scopes` (List[str]): OAuth scopes to request

**Example:**
```python
client = GoogleWorkspaceClient(
    service_account_file="/path/to/service-account.json",
    subject_email="admin@example.com",
    scopes=[
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.readonly"
    ]
)
```

#### Methods

##### `get_drive_service() -> Resource`

Returns authenticated Google Drive API service.

**Returns:** `googleapiclient.discovery.Resource`

**Example:**
```python
drive = client.get_drive_service()
files = drive.files().list(pageSize=10).execute()
```

##### `get_admin_service() -> Resource`

Returns authenticated Admin SDK service.

**Returns:** `googleapiclient.discovery.Resource`

**Example:**
```python
admin = client.get_admin_service()
users = admin.users().list(domain="example.com").execute()
```

##### `get_gmail_service() -> Resource`

Returns authenticated Gmail API service.

**Returns:** `googleapiclient.discovery.Resource`

**Example:**
```python
gmail = client.get_gmail_service()
messages = gmail.users().messages().list(userId="me").execute()
```

---

## Scanners

### FileScanner

**Location:** `vaulytica/core/scanners/file_scanner.py`

Scans Google Drive files for security issues.

#### Constructor

```python
FileScanner(
    client: GoogleWorkspaceClient,
    config: Dict[str, Any],
    pii_detector: Optional[PIIDetector] = None,
    state_manager: Optional[StateManager] = None
)
```

**Parameters:**
- `client` (GoogleWorkspaceClient): Authenticated Google Workspace client
- `config` (Dict): Scanner configuration
- `pii_detector` (PIIDetector, optional): PII detector instance
- `state_manager` (StateManager, optional): State manager for incremental scanning

#### Methods

##### `scan_files(external_only: bool = False, check_pii: bool = False, incremental: bool = False) -> List[Dict]`

Scans files for security issues.

**Parameters:**
- `external_only` (bool): Only scan externally shared files
- `check_pii` (bool): Run PII detection on file content
- `incremental` (bool): Only scan files modified since last scan

**Returns:** List of file scan results

**Example:**
```python
scanner = FileScanner(client, config)
results = scanner.scan_files(external_only=True, check_pii=True)

for result in results:
    print(f"File: {result['name']}")
    print(f"Risk Score: {result['risk_score']}")
    if result.get('pii_findings'):
        print(f"PII Found: {result['pii_findings']}")
```

##### `get_file_content(file_id: str) -> str`

Downloads and extracts text content from a file.

**Parameters:**
- `file_id` (str): Google Drive file ID

**Returns:** Extracted text content

**Supported Formats:** PDF, DOCX, XLSX, PPTX, TXT, CSV

**Example:**
```python
content = scanner.get_file_content("abc123xyz")
print(content)
```

---

### UserScanner

**Location:** `vaulytica/core/scanners/user_scanner.py`

Scans user accounts for security issues.

#### Constructor

```python
UserScanner(
    client: GoogleWorkspaceClient,
    config: Dict[str, Any]
)
```

#### Methods

##### `scan_users(inactive_days: int = 90, check_mfa: bool = False) -> List[Dict]`

Scans user accounts.

**Parameters:**
- `inactive_days` (int): Days of inactivity to flag users
- `check_mfa` (bool): Check if MFA is enabled

**Returns:** List of user scan results

**Example:**
```python
scanner = UserScanner(client, config)
results = scanner.scan_users(inactive_days=90, check_mfa=True)

for user in results:
    if user['is_inactive']:
        print(f"Inactive user: {user['email']}")
    if not user.get('mfa_enabled'):
        print(f"MFA not enabled: {user['email']}")
```

---

### GmailScanner

**Location:** `vaulytica/core/scanners/gmail_scanner.py`

Scans Gmail messages and attachments.

#### Constructor

```python
GmailScanner(
    client: GoogleWorkspaceClient,
    config: Dict[str, Any],
    pii_detector: Optional[PIIDetector] = None
)
```

#### Methods

##### `scan_messages(user_email: str, max_messages: int = 100, check_attachments: bool = True) -> List[Dict]`

Scans Gmail messages for a user.

**Parameters:**
- `user_email` (str): Email address to scan
- `max_messages` (int): Maximum messages to scan
- `check_attachments` (bool): Scan attachments for PII

**Returns:** List of message scan results

**Example:**
```python
scanner = GmailScanner(client, config, pii_detector)
results = scanner.scan_messages(
    user_email="user@example.com",
    max_messages=100,
    check_attachments=True
)

for msg in results:
    if msg.get('has_external_recipients'):
        print(f"External email: {msg['subject']}")
        if msg.get('pii_in_attachments'):
            print(f"  PII found in attachments!")
```

---

## Detectors

### PIIDetector

**Location:** `vaulytica/core/detectors/pii_detector.py`

Detects personally identifiable information (PII) in text.

#### Constructor

```python
PIIDetector(
    config: Dict[str, Any],
    confidence_threshold: float = 0.7
)
```

**Parameters:**
- `config` (Dict): Detector configuration with patterns
- `confidence_threshold` (float): Minimum confidence score (0.0-1.0)

#### Methods

##### `detect(content: str) -> List[Dict]`

Detects PII in text content.

**Parameters:**
- `content` (str): Text to scan

**Returns:** List of PII detections

**Example:**
```python
detector = PIIDetector(config, confidence_threshold=0.7)
findings = detector.detect("My SSN is 123-45-6789")

for finding in findings:
    print(f"Type: {finding['type']}")
    print(f"Value: {finding['value']}")
    print(f"Confidence: {finding['confidence']}")
    print(f"Position: {finding['start']}-{finding['end']}")
```

##### `detect_chunked(content: str, chunk_size: int = 1048576) -> List[Dict]`

Detects PII in large text using chunked processing.

**Parameters:**
- `content` (str): Text to scan
- `chunk_size` (int): Size of each chunk in bytes (default: 1MB)

**Returns:** List of PII detections

**Example:**
```python
# For large files (>1MB)
findings = detector.detect_chunked(large_content, chunk_size=1048576)
```

#### Supported PII Types

| Type | Description | Example |
|------|-------------|---------|
| `ssn` | Social Security Number | 123-45-6789 |
| `credit_card` | Credit card number | 4532-1234-5678-9010 |
| `email` | Email address | user@example.com |
| `phone` | Phone number | (555) 123-4567 |
| `dob` | Date of birth | 01/15/1990 |
| `passport` | Passport number | A12345678 |
| `drivers_license` | Driver's license | D1234567 |
| `bank_account` | Bank account number | 123456789012 |
| `ip_address` | IP address | 192.168.1.1 |
| `mac_address` | MAC address | 00:1B:44:11:3A:B7 |
| `itin` | Individual Taxpayer ID | 9XX-XX-XXXX |
| `ein` | Employer ID Number | 12-3456789 |
| `medical_record` | Medical record number | MRN123456 |
| `health_insurance` | Health insurance number | H123456789 |
| `biometric` | Biometric identifier | FP-ABC123 |
| `vehicle_id` | Vehicle ID (VIN) | 1HGBH41JXMN109186 |
| `financial_account` | Financial account | ACC-123456 |
| `crypto_wallet` | Cryptocurrency wallet | 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa |
| `api_key` | API key | sk_live_abc123... |
| `jwt_token` | JWT token | eyJhbGciOiJIUzI1NiIs... |

---

## Integrations

### EmailAlerter

**Location:** `vaulytica/integrations/email.py`

Sends email notifications.

#### Constructor

```python
EmailAlerter(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_address: str,
    to_addresses: List[str]
)
```

#### Methods

##### `send_alert(subject: str, body: str, attachments: Optional[List[str]] = None) -> bool`

Sends an email alert.

**Parameters:**
- `subject` (str): Email subject
- `body` (str): Email body (plain text or HTML)
- `attachments` (List[str], optional): Paths to attachment files

**Returns:** True if successful, False otherwise

**Example:**
```python
alerter = EmailAlerter(
    smtp_host="smtp.gmail.com",
    smtp_port=587,
    smtp_user="alerts@example.com",
    smtp_password="password",
    from_address="alerts@example.com",
    to_addresses=["security@example.com"]
)

alerter.send_alert(
    subject="PII Detected",
    body="PII was found in file: document.pdf",
    attachments=["/path/to/report.pdf"]
)
```

---

### SlackNotifier

**Location:** `vaulytica/integrations/slack.py`

Sends Slack notifications.

#### Constructor

```python
SlackNotifier(
    webhook_url: str,
    channel: Optional[str] = None
)
```

#### Methods

##### `send_notification(message: str, severity: str = "info") -> bool`

Sends a Slack notification.

**Parameters:**
- `message` (str): Message text
- `severity` (str): Severity level ("info", "warning", "error", "critical")

**Returns:** True if successful, False otherwise

**Example:**
```python
notifier = SlackNotifier(
    webhook_url="https://hooks.slack.com/services/...",
    channel="#security-alerts"
)

notifier.send_notification(
    message="PII detected in externally shared file",
    severity="critical"
)
```

---

## Utilities

### Cache

**Location:** `vaulytica/core/utils/cache.py`

In-memory cache with TTL support.

#### Constructor

```python
Cache(default_ttl: int = 3600)
```

**Parameters:**
- `default_ttl` (int): Default time-to-live in seconds

#### Methods

##### `get(key: str) -> Optional[Any]`

Gets a value from cache.

**Parameters:**
- `key` (str): Cache key

**Returns:** Cached value or None if not found/expired

##### `set(key: str, value: Any, ttl: Optional[int] = None) -> None`

Sets a value in cache.

**Parameters:**
- `key` (str): Cache key
- `value` (Any): Value to cache
- `ttl` (int, optional): Time-to-live in seconds

##### `delete(key: str) -> None`

Deletes a value from cache.

##### `clear() -> None`

Clears all cache entries.

##### `get_stats() -> Dict[str, int]`

Returns cache statistics.

**Returns:** Dict with `hits`, `misses`, `size`

**Example:**
```python
cache = Cache(default_ttl=3600)

# Set value
cache.set("user:123", {"name": "John"}, ttl=1800)

# Get value
user = cache.get("user:123")

# Check stats
stats = cache.get_stats()
print(f"Hit rate: {stats['hits'] / (stats['hits'] + stats['misses'])}")
```

---

### ConcurrentProcessor

**Location:** `vaulytica/core/utils/concurrent.py`

Parallel processing with ThreadPoolExecutor.

#### Constructor

```python
ConcurrentProcessor(max_workers: int = 10)
```

**Parameters:**
- `max_workers` (int): Maximum concurrent workers

#### Methods

##### `process(items: List[T], process_func: Callable[[T], R], error_handler: Optional[Callable] = None) -> List[R]`

Processes items concurrently.

**Parameters:**
- `items` (List): Items to process
- `process_func` (Callable): Function to process each item
- `error_handler` (Callable, optional): Error handler function

**Returns:** List of results

**Example:**
```python
def process_file(file_id):
    # Process file
    return result

processor = ConcurrentProcessor(max_workers=10)
results = processor.process(
    items=file_ids,
    process_func=process_file,
    error_handler=lambda e: print(f"Error: {e}")
)
```

---

## Storage

### StateManager

**Location:** `vaulytica/storage/state.py`

Manages scan state and history.

#### Constructor

```python
StateManager(database_path: str = "state.db")
```

**Parameters:**
- `database_path` (str): Path to SQLite database

#### Methods

##### `record_scan_start(scan_type: str, domain: str, metadata: Optional[Dict] = None) -> int`

Records the start of a scan.

**Parameters:**
- `scan_type` (str): Type of scan ("files", "users", "gmail")
- `domain` (str): Domain being scanned
- `metadata` (Dict, optional): Additional metadata

**Returns:** Scan ID

##### `record_scan_end(scan_id: int, status: str, files_scanned: int, issues_found: int) -> None`

Records the end of a scan.

**Parameters:**
- `scan_id` (int): Scan ID from `record_scan_start`
- `status` (str): Scan status ("completed", "failed", "partial")
- `files_scanned` (int): Number of files scanned
- `issues_found` (int): Number of issues found

##### `get_last_scan_time(scan_type: str, domain: str) -> Optional[datetime]`

Gets the last scan time for incremental scanning.

**Parameters:**
- `scan_type` (str): Type of scan
- `domain` (str): Domain

**Returns:** Last scan datetime or None

**Example:**
```python
state = StateManager("state.db")

# Start scan
scan_id = state.record_scan_start("files", "example.com")

# ... perform scan ...

# End scan
state.record_scan_end(scan_id, "completed", 1000, 5)

# Get last scan time for incremental
last_scan = state.get_last_scan_time("files", "example.com")
```

---

## CLI Commands

### scan files

Scans Google Drive files.

```bash
vaulytica scan files [OPTIONS]
```

**Options:**
- `--external-only` - Only scan externally shared files
- `--check-pii` - Run PII detection
- `--incremental` - Only scan changed files
- `--output PATH` - Save results to file
- `--format {csv,json}` - Output format

**Example:**
```bash
vaulytica scan files --external-only --check-pii --output results.csv
```

### scan users

Scans user accounts.

```bash
vaulytica scan users [OPTIONS]
```

**Options:**
- `--inactive-days INT` - Days of inactivity threshold
- `--check-mfa` - Check MFA status
- `--output PATH` - Save results to file

**Example:**
```bash
vaulytica scan users --inactive-days 90 --check-mfa
```

### report generate

Generates reports from scan results.

```bash
vaulytica report generate [OPTIONS]
```

**Options:**
- `--format {csv,json,html}` - Report format
- `--output PATH` - Output file path
- `--period {day,week,month}` - Time period

**Example:**
```bash
vaulytica report generate --format html --output report.html --period week
```

---

For more information, see:
- [Architecture Guide](ARCHITECTURE.md)
- [Getting Started Guide](GETTING_STARTED.md)
- [Security Guide](SECURITY.md)

