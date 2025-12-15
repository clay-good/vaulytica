# Custom PII Pattern Configuration Guide

Vaulytica supports customizable PII (Personally Identifiable Information) detection patterns through a YAML configuration file. This guide explains how to create, modify, and test custom patterns.

## Table of Contents

1. [Configuration File Location](#configuration-file-location)
2. [Pattern Structure](#pattern-structure)
3. [Writing Regex Patterns](#writing-regex-patterns)
4. [Confidence Scoring](#confidence-scoring)
5. [Context Keywords](#context-keywords)
6. [Built-in Patterns](#built-in-patterns)
7. [Custom Pattern Examples](#custom-pattern-examples)
8. [Testing Patterns](#testing-patterns)
9. [Best Practices](#best-practices)

---

## Configuration File Location

The PII patterns configuration file is located at:

```
vaulytica/config/pii_patterns.yaml
```

This file is automatically loaded when Vaulytica starts. You can also specify a custom path:

```python
from vaulytica.core.detectors.pii_detector import PIIDetector

detector = PIIDetector(config_path="/path/to/custom_patterns.yaml")
```

---

## Pattern Structure

Each PII type in the configuration follows this structure:

```yaml
pattern_name:
  enabled: true                    # Enable/disable this pattern type
  description: "Human-readable description"
  min_confidence: 0.5              # Minimum confidence to report a match (0.0-1.0)
  validate_luhn: false             # Enable Luhn algorithm validation (for credit cards)
  patterns:
    - pattern: '\b\d{3}-\d{2}-\d{4}\b'  # Regex pattern
      confidence: 0.9                    # Base confidence score
      description: "Pattern description"
  context_keywords:                # Keywords that boost confidence
    - "keyword1"
    - "keyword2"
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | boolean | No | Enable/disable pattern (default: true) |
| `description` | string | No | Human-readable description |
| `min_confidence` | float | No | Minimum confidence threshold (default: 0.5) |
| `validate_luhn` | boolean | No | Use Luhn algorithm validation |
| `patterns` | list | Yes | List of regex patterns |
| `patterns[].pattern` | string | Yes | Regex pattern |
| `patterns[].confidence` | float | Yes | Base confidence score (0.0-1.0) |
| `patterns[].description` | string | No | Pattern description |
| `context_keywords` | list | No | Keywords that increase confidence |

---

## Writing Regex Patterns

### Basic Syntax

Vaulytica uses Python's `re` module with `re.IGNORECASE` flag. Key regex elements:

| Pattern | Matches | Example |
|---------|---------|---------|
| `\d` | Any digit | `\d{4}` matches "1234" |
| `\w` | Word character | `\w+` matches "hello123" |
| `\s` | Whitespace | `\s+` matches spaces, tabs |
| `\b` | Word boundary | `\bSSN\b` matches "SSN" not "TSSN" |
| `[...]` | Character class | `[A-Z]` matches uppercase letters |
| `(?:...)` | Non-capturing group | `(?:Mr\|Mrs)` matches "Mr" or "Mrs" |
| `?` | Optional | `\d{3}-?\d{4}` matches "123-4567" or "1234567" |
| `{n,m}` | Quantity | `\d{8,12}` matches 8-12 digits |

### YAML Escaping

In YAML, use single quotes and escape backslashes:

```yaml
# Correct
pattern: '\b\d{3}-\d{2}-\d{4}\b'

# Also correct (double escape with double quotes)
pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
```

### Word Boundaries

Always use `\b` word boundaries to prevent partial matches:

```yaml
# Good - matches "SSN: 123-45-6789" but not "1234567890123456"
pattern: '\b\d{3}-\d{2}-\d{4}\b'

# Bad - could match within larger numbers
pattern: '\d{3}-\d{2}-\d{4}'
```

---

## Confidence Scoring

### Base Confidence

Set base confidence based on pattern specificity:

| Confidence | Use Case |
|------------|----------|
| 0.9 - 1.0 | Highly specific patterns (email, IP address) |
| 0.7 - 0.9 | Specific but could have false positives |
| 0.5 - 0.7 | Generic patterns requiring context |
| 0.3 - 0.5 | Very generic, requires strong context |
| < 0.3 | Almost always requires context |

### Context Boost

When context keywords are found nearby, confidence is boosted by 0.1 (up to max 1.0).

### Minimum Confidence

Set `min_confidence` to filter low-confidence matches:

```yaml
bank_account:
  min_confidence: 0.6  # Only report matches with 0.6+ confidence
  patterns:
    - pattern: '\b\d{8,17}\b'
      confidence: 0.5  # Base is 0.5, needs context to reach 0.6
```

---

## Context Keywords

Context keywords are case-insensitive words/phrases that increase confidence when found near a match:

```yaml
ssn:
  context_keywords:
    - "ssn"
    - "social security"
    - "social-security"
    - "ss#"
    - "ss number"
```

### How Context Works

1. Vaulytica extracts a window of text around each match (default: 50 characters)
2. Context keywords are searched within this window
3. If any keyword is found, confidence increases by 0.1

---

## Built-in Patterns

Vaulytica includes patterns for these PII types:

### US Identifiers
- `ssn` - Social Security Number
- `itin` - Individual Taxpayer Identification Number
- `ein` - Employer Identification Number

### Financial
- `credit_card` - Credit/Debit Card Numbers (with Luhn validation)
- `bank_account` - Bank Account Numbers
- `routing_number` - Bank Routing Numbers

### Contact Information
- `phone` - Phone Numbers (US and international)
- `email` - Email Addresses

### Healthcare (HIPAA)
- `medical_record` - Medical Record Numbers
- `health_insurance` - Health Insurance Numbers
- `medicare` - Medicare Numbers
- `medicaid` - Medicaid Numbers
- `dea_number` - DEA Registration Numbers
- `npi` - National Provider Identifier

### Personal Identifiers
- `passport` - Passport Numbers
- `drivers_license` - Driver's License Numbers
- `date_of_birth` - Dates of Birth

### Technical
- `ip_address` - IP Addresses (IPv4 and IPv6)
- `mac_address` - MAC Addresses
- `vehicle_vin` - Vehicle Identification Numbers
- `crypto_wallet` - Cryptocurrency Wallet Addresses

---

## Custom Pattern Examples

### Example 1: Employee ID

```yaml
custom:
  employee_id:
    enabled: true
    description: "Internal Employee ID"
    min_confidence: 0.7
    patterns:
      - pattern: '\bEMP-\d{6}\b'
        confidence: 0.9
        description: "Employee ID: EMP-XXXXXX"
      - pattern: '\bE\d{7}\b'
        confidence: 0.7
        description: "Legacy format: EXXXXXXX"
    context_keywords:
      - "employee"
      - "staff"
      - "emp id"
      - "employee number"
```

### Example 2: Internal Project Codes

```yaml
custom:
  project_code:
    enabled: true
    description: "Internal Project Code"
    min_confidence: 0.8
    patterns:
      - pattern: '\bPRJ-[A-Z]{2}\d{4}-\d{3}\b'
        confidence: 0.95
        description: "Project code: PRJ-XX0000-000"
    context_keywords:
      - "project"
      - "prj"
      - "project code"
```

### Example 3: Customer ID

```yaml
custom:
  customer_id:
    enabled: true
    description: "Customer Account Number"
    min_confidence: 0.6
    patterns:
      - pattern: '\bCUST-\d{8}\b'
        confidence: 0.9
        description: "Customer ID with prefix"
      - pattern: '\b[A-Z]{3}\d{10}\b'
        confidence: 0.5
        description: "Legacy format (requires context)"
    context_keywords:
      - "customer"
      - "account"
      - "cust id"
      - "customer number"
```

### Example 4: UK National Insurance Number

```yaml
custom:
  uk_ni_number:
    enabled: true
    description: "UK National Insurance Number"
    min_confidence: 0.7
    patterns:
      - pattern: '\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b'
        confidence: 0.85
        description: "UK NI Number: XX 00 00 00 X"
    context_keywords:
      - "national insurance"
      - "ni number"
      - "nino"
      - "insurance number"
```

### Example 5: German Tax ID (Steuer-ID)

```yaml
custom:
  german_tax_id:
    enabled: true
    description: "German Tax Identification Number"
    min_confidence: 0.6
    patterns:
      - pattern: '\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b'
        confidence: 0.7
        description: "Steuer-ID: XX XXX XXX XXX"
    context_keywords:
      - "steuer-id"
      - "steueridentifikationsnummer"
      - "tax id"
      - "steuernummer"
```

---

## Testing Patterns

### Using the CLI

Test patterns with sample content:

```bash
# Test a specific pattern
vaulytica scan files --domain example.com --test-pattern "employee_id" --content "Employee EMP-123456 reported..."

# Scan a test file
vaulytica scan files --domain example.com --test-file /path/to/test.txt
```

### Using Python

```python
from vaulytica.core.detectors.pii_detector import PIIDetector

# Load custom config
detector = PIIDetector(config_path="/path/to/custom_patterns.yaml")

# Test detection
content = """
Employee ID: EMP-123456
Project: PRJ-AB2024-001
Contact: john.doe@example.com
"""

result = detector.detect(content)

for match in result.matches:
    print(f"Type: {match.pii_type.value}")
    print(f"Value: {match.value}")
    print(f"Confidence: {match.confidence}")
    print(f"Context: {match.context}")
    print("---")
```

### Unit Tests

Create unit tests for your custom patterns:

```python
import pytest
from vaulytica.core.detectors.pii_detector import PIIDetector, PIIType

def test_employee_id_detection():
    detector = PIIDetector(enabled_patterns=["employee_id"])

    # Should detect
    result = detector.detect("Employee ID: EMP-123456")
    assert result.total_matches >= 1

    # Should not detect
    result = detector.detect("Regular text without patterns")
    assert result.total_matches == 0

def test_employee_id_context_boost():
    detector = PIIDetector(enabled_patterns=["employee_id"])

    # With context
    result_with = detector.detect("Employee number: E1234567")

    # Without context
    result_without = detector.detect("Code: E1234567")

    # Context should increase confidence
    if result_with.matches and result_without.matches:
        assert result_with.matches[0].confidence >= result_without.matches[0].confidence
```

---

## Best Practices

### 1. Start Specific, Then Generalize

Begin with highly specific patterns and add more generic ones only if needed:

```yaml
# Good: specific first, generic second
patterns:
  - pattern: '\bSSN:\s*\d{3}-\d{2}-\d{4}\b'
    confidence: 0.95
  - pattern: '\b\d{3}-\d{2}-\d{4}\b'
    confidence: 0.85
```

### 2. Use Appropriate Confidence Levels

- Don't set all patterns to 0.9+ confidence
- Generic patterns should have lower base confidence
- Let context keywords boost confidence naturally

### 3. Test with Real Data

- Test patterns against actual documents
- Look for false positives and false negatives
- Adjust confidence and keywords based on results

### 4. Document Your Patterns

- Add descriptions to all patterns
- Explain the format in description field
- Document context keywords selection rationale

### 5. Regular Review

- Review custom patterns quarterly
- Check for new false positive patterns
- Update as business requirements change

### 6. Performance Considerations

- Avoid overly complex regex patterns
- Limit the number of patterns per type
- Use non-capturing groups `(?:...)` when you don't need captures

### 7. Security

- Don't log actual PII values (use hashes)
- Limit access to pattern configuration
- Audit changes to patterns

---

## Troubleshooting

### Pattern Not Matching

1. Test regex independently:
   ```python
   import re
   pattern = r'\b\d{3}-\d{2}-\d{4}\b'
   text = "SSN: 123-45-6789"
   print(re.findall(pattern, text, re.IGNORECASE))
   ```

2. Check YAML escaping (use single quotes)
3. Verify `enabled: true`
4. Check `min_confidence` isn't too high

### Too Many False Positives

1. Increase `min_confidence`
2. Make pattern more specific
3. Add word boundaries `\b`
4. Add context keywords

### Performance Issues

1. Reduce pattern complexity
2. Use `{n,m}` instead of `*` or `+` where possible
3. Avoid lookahead/lookbehind when not needed

---

## Reference

### Regex Cheat Sheet

| Pattern | Description |
|---------|-------------|
| `\d` | Digit [0-9] |
| `\D` | Non-digit |
| `\w` | Word character [a-zA-Z0-9_] |
| `\W` | Non-word character |
| `\s` | Whitespace |
| `\S` | Non-whitespace |
| `\b` | Word boundary |
| `.` | Any character except newline |
| `*` | 0 or more |
| `+` | 1 or more |
| `?` | 0 or 1 |
| `{n}` | Exactly n |
| `{n,}` | n or more |
| `{n,m}` | Between n and m |
| `[abc]` | Character class |
| `[^abc]` | Negated class |
| `(...)` | Capturing group |
| `(?:...)` | Non-capturing group |
| `a\|b` | Alternation |

### Common PII Formats

| Type | Format | Example |
|------|--------|---------|
| US SSN | XXX-XX-XXXX | 123-45-6789 |
| US Phone | (XXX) XXX-XXXX | (555) 123-4567 |
| Credit Card | XXXX XXXX XXXX XXXX | 4111 1111 1111 1111 |
| Email | user@domain.tld | john@example.com |
| IPv4 | X.X.X.X | 192.168.1.1 |
| MAC Address | XX:XX:XX:XX:XX:XX | 00:1A:2B:3C:4D:5E |
