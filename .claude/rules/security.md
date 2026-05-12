---
paths:
  - "**/*.py"
  - "**/*.js"
  - "**/*.ts"
  - "**/*.go"
  - "**/*.rs"
---

# Security Rules

When writing or modifying code, always follow these security rules:

## Never Use
- eval()
- exec()
- shell=True
- os.system()
- subprocess.call(..., shell=True)
- String formatting in SQL queries — use parameterized queries
- pickle.loads() on untrusted data
- yaml.load() without SafeLoader

## Always Do
- Validate and sanitize all external input
- Use parameterized queries for database operations
- Set explicit timeouts on network calls and subprocesses
- Use context managers for file handles and connections
- Check return values from security-sensitive operations
- Use secrets module for random token generation, not random

## Credential Safety
- Never hardcode API keys, passwords, or tokens
- Load secrets from environment variables only
- Never log secrets — use masking/redaction
- Never commit .env files
