# Vaulytica Configuration Guide

## Overview

Vaulytica uses a flexible configuration system that supports:
- Environment-based configuration (development, staging, production)
- Environment variables
- Configuration files (YAML/JSON)
- Secrets management integration
- Runtime validation

## Configuration Priority

Configuration values are loaded in the following order (later sources override earlier ones):

1. Default values (defined in `vaulytica/config.py`)
2. Configuration files (`config/*.yaml`)
3. `.env` file
4. Environment variables
5. Runtime overrides (CLI arguments, API parameters)

## Environment Variables

All configuration can be set via environment variables with the `VAULYTICA_` prefix:

```bash
export VAULYTICA_ENVIRONMENT=production
export VAULYTICA_LOG_LEVEL=INFO
export ANTHROPIC_API_KEY=sk-ant-api03-...
```

See `.env.example` for a complete list of available variables.

## Configuration Files

### Using YAML Configuration

```bash
# Load production configuration
VAULYTICA_ENVIRONMENT=production python -m vaulytica.cli serve

# Or specify config file explicitly
python -m vaulytica.cli serve --config config/production.yaml
```

### Configuration File Structure

```yaml
# Environment
environment: production  # development, staging, production, testing
debug: false

# Model Configuration
model_name: claude-3-haiku-20240307
max_tokens: 4000
temperature: 0.0

# Logging
log_level: INFO

# Features
enable_rag: true
max_historical_incidents: 10
enable_cache: true

# Performance
batch_max_workers: 8
chunk_size: 50000
```

## Environment-Specific Configurations

### Development (`config/development.yaml`)

- Debug mode enabled
- Verbose logging (DEBUG level)
- Lower notification thresholds
- Fewer workers for resource conservation

### Staging (`config/staging.yaml`)

- Production-like settings
- INFO level logging
- Moderate resource allocation
- Testing integrations

### Production (`config/production.yaml`)

- Debug mode disabled
- INFO level logging
- Higher notification thresholds
- Maximum performance settings
- Strict validation

## Secrets Management

### Option 1: Environment Variables (Recommended)

```bash
export ANTHROPIC_API_KEY=sk-ant-api03-...
export VAULYTICA_SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

### Option 2: .env File (Development Only)

```bash
# Copy example file
cp .env.example .env

# Edit with your values
nano .env
```

**⚠️ Never commit `.env` files to version control!**

### Option 3: Secrets Manager (Production)

#### AWS Secrets Manager

```python
import boto3
import json

def load_secrets_from_aws():
    client = boto3.client('secretsmanager', region_name='us-west-2')
    response = client.get_secret_value(SecretId='vaulytica/production')
    secrets = json.loads(response['SecretString'])
    
    os.environ['ANTHROPIC_API_KEY'] = secrets['anthropic_api_key']
    os.environ['VAULYTICA_SLACK_WEBHOOK_URL'] = secrets['slack_webhook_url']
```

#### HashiCorp Vault

```python
import hvac

def load_secrets_from_vault():
    client = hvac.Client(url='https://vault.example.com')
    client.token = os.environ['VAULT_TOKEN']
    
    secrets = client.secrets.kv.v2.read_secret_version(
        path='vaulytica/production'
    )
    
    for key, value in secrets['data']['data'].items():
        os.environ[f'VAULYTICA_{key.upper()}'] = value
```

## Configuration Validation

Vaulytica validates configuration on startup:

```python
from vaulytica.config import load_config

try:
    config = load_config()
    print(f"Configuration loaded for {config.get_environment_name()}")
except ValueError as e:
    print(f"Configuration error: {e}")
    sys.exit(1)
```

### Production Validation Rules

- Debug mode must be disabled
- Log level cannot be DEBUG
- Valid API key format required
- Required directories must be writable

## Configuration in Code

### Loading Configuration

```python
from vaulytica.config import load_config, load_config_from_file

# Load with defaults and environment variables
config = load_config()

# Load with API key override
config = load_config(api_key="sk-ant-api03-...")

# Load from specific file
config = load_config_from_file(Path("config/production.yaml"))
```

### Accessing Configuration

```python
# Check environment
if config.is_production():
    print("Running in production mode")

# Get configuration as dictionary
config_dict = config.to_dict(mask_secrets=True)

# Access specific values
print(f"Model: {config.model_name}")
print(f"Max tokens: {config.max_tokens}")
print(f"RAG enabled: {config.enable_rag}")
```

## Docker Configuration

### Using Environment Variables

```bash
docker run -d \
  -e ANTHROPIC_API_KEY="sk-ant-api03-..." \
  -e VAULYTICA_ENVIRONMENT=production \
  -e VAULYTICA_LOG_LEVEL=INFO \
  vaulytica:latest
```

### Using .env File

```bash
docker run -d \
  --env-file .env \
  vaulytica:latest
```

### Using Docker Secrets

```bash
# Create secret
echo "sk-ant-api03-..." | docker secret create anthropic_api_key -

# Use in service
docker service create \
  --name vaulytica \
  --secret anthropic_api_key \
  vaulytica:latest
```

## Kubernetes Configuration

### Using ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vaulytica-config
data:
  environment: "production"
  log-level: "INFO"
  model-name: "claude-3-haiku-20240307"
```

### Using Secrets

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: vaulytica-secrets
type: Opaque
stringData:
  anthropic-api-key: "sk-ant-api03-..."
  slack-webhook-url: "https://hooks.slack.com/..."
```

### In Deployment

```yaml
env:
- name: VAULYTICA_ENVIRONMENT
  valueFrom:
    configMapKeyRef:
      name: vaulytica-config
      key: environment
- name: ANTHROPIC_API_KEY
  valueFrom:
    secretKeyRef:
      name: vaulytica-secrets
      key: anthropic-api-key
```

## Configuration Best Practices

### 1. Never Commit Secrets

```bash
# Add to .gitignore
.env
*.secret
config/production.yaml  # If it contains secrets
```

### 2. Use Environment-Specific Files

```
config/
├── development.yaml    # Development settings
├── staging.yaml        # Staging settings
├── production.yaml     # Production settings (no secrets!)
└── testing.yaml        # Test settings
```

### 3. Validate on Startup

```python
def main():
    try:
        config = load_config()
        config.validate()  # Explicit validation
    except ValueError as e:
        logger.error(f"Invalid configuration: {e}")
        sys.exit(1)
```

### 4. Use Secrets Managers in Production

- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- GCP Secret Manager

### 5. Document Required Variables

Maintain an up-to-date `.env.example` file with all required variables.

### 6. Use Type Hints

Configuration is fully typed with Pydantic for IDE support and validation.

## Troubleshooting

### Configuration Not Loading

```bash
# Check environment variables
env | grep VAULYTICA

# Verify .env file exists
ls -la .env

# Test configuration loading
python -c "from vaulytica.config import load_config; print(load_config().to_dict())"
```

### Invalid API Key

```
ValueError: Invalid Anthropic API key format (should start with 'sk-ant-')
```

**Solution**: Ensure your API key starts with `sk-ant-api03-`

### Production Validation Errors

```
ValueError: Debug mode must be disabled in production
```

**Solution**: Set `VAULYTICA_DEBUG=false` or `debug: false` in config file

## Support

For configuration issues:
1. Check this documentation
2. Review `.env.example` for required variables
3. Verify environment-specific config files
4. Check application logs for validation errors

---

**Version**: 0.17.0  
**Last Updated**: 2024-01-15

