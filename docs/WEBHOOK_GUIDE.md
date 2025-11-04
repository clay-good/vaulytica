# Webhook Integration Guide

**Enhanced Webhook Integration with Retry Logic, Authentication, and Custom Templates**

---

## Overview

Vaulytica's webhook integration allows you to send security events to external systems (SIEM, monitoring tools, custom endpoints) with:

- **Exponential backoff retry logic** (automatic retries with increasing delays)
- **Multiple authentication methods** (API key, Bearer token, Basic auth, HMAC, OAuth2)
- **Custom payload templates** (Jinja2 templates or Python functions)
- **Pre-built formats** (Splunk HEC, Datadog, Elasticsearch, generic JSON)
- **Batch sending** (send multiple events efficiently)

---

## Quick Start

### Basic Webhook

```python
from vaulytica.integrations.webhook import WebhookSender, WebhookConfig

# Create webhook config
config = WebhookConfig(
    url="https://your-siem.example.com/webhook",
    format="json",
)

# Create sender
sender = WebhookSender(config)

# Send event
sender.send_event(
    event_type="file_shared_externally",
    event_data={
        "file_id": "abc123",
        "file_name": "sensitive.pdf",
        "owner": "user@example.com",
        "shared_with": "external@partner.com",
    },
    severity="warning",
)
```

---

## Authentication

### 1. API Key Authentication

```python
from vaulytica.integrations.webhook import (
    WebhookConfig,
    WebhookAuth,
    WebhookAuthType,
)

auth = WebhookAuth(
    auth_type=WebhookAuthType.API_KEY,
    api_key="your-api-key-here",
    api_key_header="X-API-Key",  # Default header name
)

config = WebhookConfig(
    url="https://api.example.com/events",
    auth=auth,
)
```

**Request Headers:**
```
X-API-Key: your-api-key-here
Content-Type: application/json
```

---

### 2. Bearer Token Authentication

```python
auth = WebhookAuth(
    auth_type=WebhookAuthType.BEARER_TOKEN,
    bearer_token="your-bearer-token-here",
)

config = WebhookConfig(
    url="https://api.example.com/events",
    auth=auth,
)
```

**Request Headers:**
```
Authorization: Bearer your-bearer-token-here
Content-Type: application/json
```

---

### 3. Basic Authentication

```python
auth = WebhookAuth(
    auth_type=WebhookAuthType.BASIC_AUTH,
    username="your-username",
    password="your-password",
)

config = WebhookConfig(
    url="https://api.example.com/events",
    auth=auth,
)
```

**Request Headers:**
```
Authorization: Basic <base64-encoded-credentials>
Content-Type: application/json
```

---

### 4. HMAC SHA256 Signature

```python
auth = WebhookAuth(
    auth_type=WebhookAuthType.HMAC_SHA256,
    hmac_secret="your-secret-key",
    hmac_header="X-Signature",  # Default header name
)

config = WebhookConfig(
    url="https://api.example.com/events",
    auth=auth,
)
```

**Request Headers:**
```
X-Signature: <hmac-sha256-signature-of-payload>
Content-Type: application/json
```

**Signature Verification (Server Side):**

```python
import hmac
import hashlib
import json

def verify_signature(payload: dict, signature: str, secret: str) -> bool:
    payload_str = json.dumps(payload, sort_keys=True)
    expected_signature = hmac.new(
        secret.encode(),
        payload_str.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, expected_signature)
```

---

### 5. OAuth2 Client Credentials

```python
auth = WebhookAuth(
    auth_type=WebhookAuthType.OAUTH2,
    oauth2_token_url="https://auth.example.com/oauth/token",
    oauth2_client_id="your-client-id",
    oauth2_client_secret="your-client-secret",
)

config = WebhookConfig(
    url="https://api.example.com/events",
    auth=auth,
)
```

**Token Caching:**
- Tokens are automatically cached
- Refreshed before expiration
- 1-minute buffer before expiry

---

## Retry Configuration

### Exponential Backoff

```python
from vaulytica.integrations.webhook import WebhookRetryConfig

retry_config = WebhookRetryConfig(
    max_retries=5,              # Maximum retry attempts
    initial_delay=1.0,          # Initial delay (seconds)
    max_delay=60.0,             # Maximum delay (seconds)
    exponential_base=2.0,       # Exponential multiplier
    jitter=True,                # Add random jitter
)

config = WebhookConfig(
    url="https://api.example.com/events",
    retry_config=retry_config,
)
```

**Retry Delays:**

| Attempt | Delay (without jitter) | Delay (with jitter)   |
| ------- | ---------------------- | --------------------- |
| 1       | 1.0s                   | 0.5s - 1.0s           |
| 2       | 2.0s                   | 1.0s - 2.0s           |
| 3       | 4.0s                   | 2.0s - 4.0s           |
| 4       | 8.0s                   | 4.0s - 8.0s           |
| 5       | 16.0s                  | 8.0s - 16.0s          |
| 6       | 32.0s                  | 16.0s - 32.0s         |
| 7       | 60.0s (capped)         | 30.0s - 60.0s (capped)|

**Benefits of Jitter:**
- Prevents thundering herd problem
- Distributes retry load
- Reduces server overload

---

## Payload Formats

### 1. Generic JSON (Default)

```python
config = WebhookConfig(
    url="https://api.example.com/events",
    format="json",  # or WebhookFormat.JSON
)
```

**Payload:**

```json
{
  "timestamp": "2025-10-29T12:00:00Z",
  "source": "vaulytica",
  "event_type": "file_shared_externally",
  "severity": "warning",
  "data": {
    "file_id": "abc123",
    "file_name": "sensitive.pdf",
    "owner": "user@example.com",
    "shared_with": "external@partner.com"
  }
}
```

---

### 2. Splunk HEC Format

```python
config = WebhookConfig(
    url="https://splunk.example.com:8088/services/collector/event",
    format="splunk_hec",  # or WebhookFormat.SPLUNK_HEC
    headers={
        "Authorization": "Splunk your-hec-token",
    },
)
```

**Payload:**

```json
{
  "time": 1730217600,
  "host": "vaulytica",
  "source": "vaulytica",
  "sourcetype": "vaulytica:file_shared_externally",
  "event": {
    "event_type": "file_shared_externally",
    "severity": "warning",
    "timestamp": "2025-10-29T12:00:00Z",
    "file_id": "abc123",
    "file_name": "sensitive.pdf",
    "owner": "user@example.com",
    "shared_with": "external@partner.com"
  }
}
```

---

### 3. Datadog Format

```python
config = WebhookConfig(
    url="https://api.datadoghq.com/api/v1/events",
    format="datadog",  # or WebhookFormat.DATADOG
    headers={
        "DD-API-KEY": "your-api-key",
    },
)
```

**Payload:**

```json
{
  "title": "Vaulytica: file_shared_externally",
  "text": "{\n  \"file_id\": \"abc123\",\n  \"file_name\": \"sensitive.pdf\"\n}",
  "alert_type": "warning",
  "source_type_name": "vaulytica",
  "tags": [
    "event_type:file_shared_externally",
    "severity:warning",
    "source:vaulytica"
  ],
  "date_happened": 1730217600
}
```

---

### 4. Elasticsearch Format

```python
config = WebhookConfig(
    url="https://elasticsearch.example.com:9200/vaulytica/_doc",
    format="elastic",  # or WebhookFormat.ELASTIC
)
```

**Payload:**

```json
{
  "@timestamp": "2025-10-29T12:00:00Z",
  "event": {
    "kind": "alert",
    "category": ["security"],
    "type": ["file_shared_externally"],
    "severity": 2
  },
  "observer": {
    "name": "vaulytica",
    "type": "security_scanner"
  },
  "message": "Vaulytica event: file_shared_externally",
  "vaulytica": {
    "file_id": "abc123",
    "file_name": "sensitive.pdf",
    "owner": "user@example.com",
    "shared_with": "external@partner.com"
  }
}
```

---

### 5. Custom Template (Jinja2)

```python
custom_template = """
{
  "alert": {
    "type": "{{ event_type }}",
    "level": "{{ severity }}",
    "time": "{{ timestamp }}",
    "details": {
      "file": "{{ event_data.file_name }}",
      "owner": "{{ event_data.owner }}",
      "recipient": "{{ event_data.shared_with }}"
    }
  }
}
"""

config = WebhookConfig(
    url="https://api.example.com/alerts",
    format="custom",  # or WebhookFormat.CUSTOM
    custom_template=custom_template,
)
```

**Payload:**

```json
{
  "alert": {
    "type": "file_shared_externally",
    "level": "warning",
    "time": "2025-10-29T12:00:00Z",
    "details": {
      "file": "sensitive.pdf",
      "owner": "user@example.com",
      "recipient": "external@partner.com"
    }
  }
}
```

---

### 6. Custom Template (Python Function)

```python
def custom_formatter(context):
    return {
        "alert_type": context["event_type"],
        "alert_severity": context["severity"],
        "alert_timestamp": context["timestamp"],
        "alert_data": context["event_data"],
        "alert_source": "vaulytica",
    }

config = WebhookConfig(
    url="https://api.example.com/alerts",
    format="custom",  # or WebhookFormat.CUSTOM
    custom_template_func=custom_formatter,
)
```

---

## Batch Sending

Send multiple events efficiently:

```python
events = [
    {
        "type": "file_shared_externally",
        "data": {"file_id": "abc123", "file_name": "doc1.pdf"},
        "severity": "warning",
    },
    {
        "type": "file_shared_externally",
        "data": {"file_id": "def456", "file_name": "doc2.pdf"},
        "severity": "warning",
    },
    {
        "type": "pii_detected",
        "data": {"file_id": "ghi789", "pii_types": ["ssn", "email"]},
        "severity": "critical",
    },
]

success_count = sender.send_batch(events)
print(f"Sent {success_count}/{len(events)} events")
```

---

## Testing

### Test Connection

```python
if sender.test_connection():
    print("Webhook connection successful!")
else:
    print("Webhook connection failed!")
```

---

## Configuration Examples

### Example 1: Splunk with API Key

```python
config = WebhookConfig(
    url="https://splunk.example.com:8088/services/collector/event",
    format=WebhookFormat.SPLUNK_HEC,
    auth=WebhookAuth(
        auth_type=WebhookAuthType.API_KEY,
        api_key="your-hec-token",
        api_key_header="Authorization",
    ),
    retry_config=WebhookRetryConfig(
        max_retries=5,
        initial_delay=2.0,
        max_delay=120.0,
    ),
    timeout=30,
    verify_ssl=True,
)
```

---

### Example 2: Custom Endpoint with HMAC

```python
config = WebhookConfig(
    url="https://api.example.com/security/events",
    format=WebhookFormat.JSON,
    auth=WebhookAuth(
        auth_type=WebhookAuthType.HMAC_SHA256,
        hmac_secret="your-secret-key",
    ),
    retry_config=WebhookRetryConfig(
        max_retries=3,
        initial_delay=1.0,
        exponential_base=2.0,
        jitter=True,
    ),
)
```

---

### Example 3: Datadog with OAuth2

```python
config = WebhookConfig(
    url="https://api.datadoghq.com/api/v1/events",
    format=WebhookFormat.DATADOG,
    auth=WebhookAuth(
        auth_type=WebhookAuthType.OAUTH2,
        oauth2_token_url="https://auth.datadoghq.com/oauth/token",
        oauth2_client_id="your-client-id",
        oauth2_client_secret="your-client-secret",
    ),
)
```

---

## Best Practices

### 1. Use Appropriate Retry Configuration

```python
# For critical events (aggressive retries)
retry_config = WebhookRetryConfig(
    max_retries=10,
    initial_delay=0.5,
    max_delay=300.0,  # 5 minutes
)

# For non-critical events (conservative retries)
retry_config = WebhookRetryConfig(
    max_retries=3,
    initial_delay=2.0,
    max_delay=60.0,
)
```

### 2. Enable SSL Verification

```python
config = WebhookConfig(
    url="https://api.example.com/events",
    verify_ssl=True,  # Always verify SSL in production
)
```

### 3. Use HMAC for Security

```python
# Secure webhook with HMAC signature
auth = WebhookAuth(
    auth_type=WebhookAuthType.HMAC_SHA256,
    hmac_secret="your-secret-key",
)
```

### 4. Monitor Webhook Performance

```python
import time

start = time.time()
sender.send_event("test", {"message": "test"}, "info")
duration = time.time() - start

print(f"Webhook latency: {duration:.2f}s")
```

---

## Troubleshooting

### Issue: Webhook Timeouts

**Solution:** Increase timeout and retry configuration:

```python
config = WebhookConfig(
    url="https://slow-api.example.com/events",
    timeout=60,  # Increase from default 30s
    retry_config=WebhookRetryConfig(
        max_retries=5,
        initial_delay=5.0,
    ),
)
```

---

### Issue: SSL Certificate Errors

**Solution:** Disable SSL verification (not recommended for production):

```python
config = WebhookConfig(
    url="https://api.example.com/events",
    verify_ssl=False,  # Only for testing!
)
```

---

### Issue: Authentication Failures

**Solution:** Test authentication separately:

```python
# Test connection
if not sender.test_connection():
    print("Authentication failed!")
    # Check credentials, token expiry, etc.
```

---

## Next Steps

- [Scheduler Guide](SCHEDULER_GUIDE.md)
- [Deployment Guide](DEPLOYMENT.md)
- [API Reference](API_REFERENCE.md)

