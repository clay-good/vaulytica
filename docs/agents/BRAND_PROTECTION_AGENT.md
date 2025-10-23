# Brand Protection AI Agent

**Version**: 1.0.0 (Planned)
**Status**: Design Phase
**Target Release**: Q3 2026
**Last Updated**: 2025-10-21

---

## Overview

The Brand Protection Agent automatically detects typosquatting domains, validates malicious intent, and generates cease & desist letters for legal action. It monitors domain registrations, certificate transparency logs, and DNS records to protect your brand from phishing and impersonation attacks.

### Key Capabilities

- **Typosquatting Detection**: Generate domain permutations and check for registrations
- **Certificate Transparency Monitoring**: Monitor CT logs for suspicious certificates
- **WHOIS Analysis**: Extract registrant details and registrar information
- **URLScan.io Integration**: Capture screenshots and analyze page content
- **Malicious Intent Validation**: Determine if domain is actually malicious
- **Cease & Desist Generation**: Create legal-ready takedown letters
- **Jira Integration**: Create tickets for legal team follow-up
- **Takedown Tracking**: Monitor domain status and response times

---

## Architecture

### Brand Protection Workflow

```
Monitor Domain Registrations
    ↓
1. Domain Permutation Generation
   - Character omission (gogle.com)
   - Character repetition (gooogle.com)
   - Character transposition (googel.com)
   - Homoglyphs (goog1e.com, gооgle.com)
   - TLD variations (google.co, google.net)
   - Subdomain variations (login-google.com)
    ↓
2. Domain Registration Check
   - DNS resolution (is domain registered?)
   - Certificate Transparency logs
   - WHOIS lookup
   - Registration date analysis
    ↓
3. Malicious Intent Validation
   - URLScan.io screenshot capture
   - Content similarity analysis
   - Phishing indicator detection
   - Brand impersonation detection
   - SSL certificate analysis
    ↓
4. Threat Scoring
   - Recently registered (<30 days)
   - Content similarity to legitimate site
   - Phishing indicators present
   - Hosting provider reputation
   - SSL certificate details
    ↓
5. Evidence Collection
   - Screenshots (URLScan.io)
   - WHOIS records
   - DNS records
   - SSL certificate details
   - Page content analysis
    ↓
6. Cease & Desist Generation
   - Generate C&D letter with evidence
   - Include registrar contact info
   - Include hosting provider details
   - Export to DOCX/PDF
    ↓
7. Jira Ticket Creation
   - Create ticket for legal team
   - Attach all evidence
   - Include recommended actions
    ↓
8. Takedown Tracking
   - Monitor domain status
   - Track response times
   - Update Jira ticket
    ↓
Domain Taken Down
```

---

## Domain Permutation Generation

### Typosquatting Techniques

```python
from vaulytica.agents.brand_protection import BrandProtectionAgent

agent = BrandProtectionAgent(config)

# Generate domain permutations
permutations = await agent.generate_permutations(
    domain="google.com",
    techniques=[
        "omission",
        "repetition",
        "transposition",
        "homoglyph",
        "tld_variation",
        "subdomain"
    ]
)

# Output:
{
  "original_domain": "google.com",
  "total_permutations": 1247,
  
  "permutations_by_technique": {
    "omission": [
      "gogle.com",    # Missing 'o'
      "goole.com",    # Missing 'g'
      "googl.com"     # Missing 'e'
    ],
    
    "repetition": [
      "gooogle.com",  # Extra 'o'
      "googgle.com",  # Extra 'g'
      "googlee.com"   # Extra 'e'
    ],
    
    "transposition": [
      "googel.com",   # 'e' and 'l' swapped
      "gogole.com",   # 'o' and 'g' swapped
      "goolge.com"    # 'l' and 'g' swapped
    ],
    
    "homoglyph": [
      "goog1e.com",   # 'l' → '1'
      "gооgle.com",   # 'o' → Cyrillic 'о'
      "g00gle.com"    # 'o' → '0'
    ],
    
    "tld_variation": [
      "google.co",
      "google.net",
      "google.org",
      "google.io",
      "google.app"
    ],
    
    "subdomain": [
      "login-google.com",
      "accounts-google.com",
      "secure-google.com",
      "verify-google.com"
    ]
  }
}
```

---

## Domain Registration Check

### Check for Registered Domains

```python
# Check which permutations are registered
registered = await agent.check_registrations(
    permutations=permutations.permutations_by_technique
)

# Output:
{
  "total_checked": 1247,
  "registered": 23,
  "unregistered": 1224,
  
  "registered_domains": [
    {
      "domain": "gogle.com",
      "registered": true,
      "registration_date": "2025-10-15T00:00:00Z",
      "age_days": 6,
      "is_recently_registered": true,
      "dns_records": {
        "A": ["203.0.113.42"],
        "MX": [],
        "NS": ["ns1.suspicious-hosting.com"]
      },
      "has_ssl": true,
      "ssl_issuer": "Let's Encrypt"
    }
  ]
}
```

---

## Certificate Transparency Monitoring

### Monitor CT Logs

```python
# Monitor Certificate Transparency logs for new certificates
ct_results = await agent.monitor_certificate_transparency(
    domain_pattern="*google*",
    days_back=7
)

# Output:
{
  "certificates_found": 15,
  "suspicious_certificates": 3,
  
  "suspicious_certs": [
    {
      "domain": "login-google-verify.com",
      "issued_date": "2025-10-20T12:00:00Z",
      "issuer": "Let's Encrypt",
      "subject_alt_names": [
        "login-google-verify.com",
        "www.login-google-verify.com"
      ],
      "is_suspicious": true,
      "reasons": [
        "Recently issued (1 day ago)",
        "Subdomain pattern matches phishing",
        "Domain not owned by Google"
      ]
    }
  ]
}
```

---

## Malicious Intent Validation

### Validate Domain is Actually Malicious

```python
# Validate domain is malicious (not just similar)
validation = await agent.validate_malicious_intent(
    domain="gogle.com"
)

# Output:
{
  "domain": "gogle.com",
  "is_malicious": true,
  "confidence": 0.95,
  
  "evidence": {
    "urlscan_result": {
      "screenshot_url": "https://example.com",
      "verdict": "malicious",
      "is_phishing": true,
      "brands_detected": ["Google"],
      "content_similarity": 0.92,  # 92% similar to real google.com
      "phishing_indicators": [
        "Fake login form",
        "Credential harvesting script",
        "Mimics Google branding"
      ]
    },
    
    "whois_result": {
      "registrar": "NameCheap Inc.",
      "registration_date": "2025-10-15T00:00:00Z",
      "age_days": 6,
      "is_recently_registered": true,
      "registrant": "REDACTED FOR PRIVACY",
      "registrant_email": "user@example.com"
    },
    
    "dns_analysis": {
      "hosting_provider": "Suspicious Hosting LLC",
      "hosting_country": "Unknown",
      "is_known_malicious_host": true
    },
    
    "ssl_analysis": {
      "has_ssl": true,
      "issuer": "Let's Encrypt",
      "valid_from": "2025-10-15",
      "valid_to": "2026-01-15",
      "is_suspicious": true,
      "reasons": [
        "Certificate issued same day as domain registration",
        "Short validity period (90 days)"
      ]
    }
  },
  
  "threat_score": 95,  # 0-100
  "threat_level": "CRITICAL",
  
  "recommended_action": "IMMEDIATE_TAKEDOWN"
}
```

---

## Cease & Desist Letter Generation

### Generate Legal Takedown Letter

```python
# Generate cease & desist letter
cease_and_desist = await agent.generate_cease_and_desist(
    domain="gogle.com",
    validation=validation,
    company_info={
        "name": "Google LLC",
        "address": "1600 Amphitheatre Parkway, Mountain View, CA 94043",
        "legal_contact": "user@example.com",
        "trademark": "GOOGLE (Reg. No. 3,353,920)"
    }
)

# Output: DOCX file with legal letter
# Content:
"""
CEASE AND DESIST LETTER

Date: October 21, 2025

To: Domain Registrant (gogle.com)
    Via: NameCheap Inc. (Registrar)
    Email: user@example.com

From: Google LLC
      1600 Amphitheatre Parkway
      Mountain View, CA 94043
      Legal Contact: user@example.com

RE: Unauthorized Use of GOOGLE Trademark - Domain gogle.com

Dear Sir/Madam,

We represent Google LLC ("Google"), the owner of the registered trademark GOOGLE 
(Reg. No. 3,353,920). It has come to our attention that you have registered and 
are operating the domain name "gogle.com" which infringes upon Google's trademark 
rights.

EVIDENCE OF INFRINGEMENT:

1. Domain Registration:
   - Domain: gogle.com
   - Registered: October 15, 2025 (6 days ago)
   - Registrar: NameCheap Inc.

2. Trademark Infringement:
   - The domain "gogle.com" is confusingly similar to Google's registered trademark
   - The domain is being used to impersonate Google's services
   - The website mimics Google's branding and design (92% content similarity)

3. Phishing Activity:
   - The website contains a fake login form designed to harvest credentials
   - The website is being used for phishing attacks against Google users
   - Evidence: Screenshot attached (Exhibit A)

4. Technical Evidence:
   - WHOIS records (Exhibit B)
   - URLScan.io analysis (Exhibit C)
   - SSL certificate details (Exhibit D)

LEGAL BASIS:

Your use of the domain "gogle.com" constitutes:
1. Trademark infringement under 15 U.S.C. § 1114
2. Cybersquatting under 15 U.S.C. § 1125(d) (ACPA)
3. Unfair competition under 15 U.S.C. § 1125(a)
4. Computer fraud under 18 U.S.C. § 1030 (CFAA)

DEMAND:

We demand that you immediately:
1. Cease all use of the domain "gogle.com"
2. Transfer the domain to Google LLC
3. Cease all phishing activities
4. Provide information about any data collected through the phishing site

You have 10 business days from receipt of this letter to comply with these demands.

CONSEQUENCES OF NON-COMPLIANCE:

If you fail to comply, Google will pursue all available legal remedies, including:
1. Filing a lawsuit for trademark infringement and cybersquatting
2. Seeking statutory damages up to $100,000 per domain under ACPA
3. Seeking injunctive relief
4. Reporting criminal activity to law enforcement
5. Filing a UDRP complaint with ICANN

CONTACT INFORMATION:

Registrar: NameCheap Inc.
Abuse Contact: user@example.com
Hosting Provider: Suspicious Hosting LLC
Abuse Contact: user@example.com

Please confirm receipt of this letter and your compliance within 10 business days.

Sincerely,

Legal Department
Google LLC
user@example.com

Attachments:
- Exhibit A: URLScan.io screenshot
- Exhibit B: WHOIS records
- Exhibit C: URLScan.io analysis report
- Exhibit D: SSL certificate details
"""
```

---

## Jira Integration

### Create Legal Team Ticket

```python
# Create Jira ticket for legal team
jira_ticket = await agent.create_legal_ticket(
    domain="gogle.com",
    validation=validation,
    cease_and_desist=cease_and_desist
)

# Output:
{
  "ticket_key": "LEGAL-123",
  "ticket_url": "https://your-company.atlassian.net",
  
  "ticket_content": {
    "summary": "[URGENT] Typosquatting & Phishing - gogle.com",
    "description": """
      ## Threat Summary
      Typosquatting domain "gogle.com" is actively being used for phishing attacks 
      against our users.
      
      ## Evidence
      - Domain registered 6 days ago (2025-10-15)
      - 92% content similarity to legitimate site
      - Active phishing form collecting credentials
      - 95/100 threat score
      
      ## Actions Taken
      - Generated cease & desist letter (attached)
      - Collected evidence (screenshots, WHOIS, DNS records)
      - Identified registrar and hosting provider contacts
      
      ## Recommended Next Steps
      1. Review and send cease & desist letter
      2. Contact registrar (NameCheap) for expedited takedown
      3. Contact hosting provider (Suspicious Hosting LLC)
      4. File UDRP complaint if no response within 10 days
      5. Report to law enforcement if phishing continues
      
      ## Contacts
      - Registrar: user@example.com
      - Hosting: user@example.com
    """,
    "priority": "Highest",
    "labels": ["typosquatting", "phishing", "brand-protection", "urgent"],
    "attachments": [
      "cease_and_desist_gogle.com.docx",
      "screenshot_gogle.com.png",
      "whois_gogle.com.txt",
      "urlscan_report_gogle.com.pdf"
    ]
  }
}
```

---

## Takedown Tracking

### Monitor Domain Status

```python
# Track takedown progress
tracking = await agent.track_takedown(
    domain="gogle.com",
    jira_ticket="LEGAL-123"
)

# Output:
{
  "domain": "gogle.com",
  "jira_ticket": "LEGAL-123",
  "status": "IN_PROGRESS",
  
  "timeline": [
    {
      "date": "2025-10-21T10:00:00Z",
      "event": "Domain detected and validated as malicious"
    },
    {
      "date": "2025-10-21T10:30:00Z",
      "event": "Cease & desist letter generated"
    },
    {
      "date": "2025-10-21T11:00:00Z",
      "event": "Jira ticket created for legal team"
    },
    {
      "date": "2025-10-21T14:00:00Z",
      "event": "C&D letter sent to registrar"
    },
    {
      "date": "2025-10-23T09:00:00Z",
      "event": "Registrar acknowledged receipt"
    },
    {
      "date": "2025-10-25T16:00:00Z",
      "event": "Domain suspended by registrar"
    },
    {
      "date": "2025-10-26T10:00:00Z",
      "event": "Domain no longer resolves (TAKEN DOWN)"
    }
  ],
  
  "metrics": {
    "time_to_detection": "6 days",  # From registration to detection
    "time_to_c_and_d": "30 minutes",  # From detection to C&D generation
    "time_to_takedown": "5 days",  # From C&D to takedown
    "total_time": "11 days"  # From registration to takedown
  },
  
  "current_status": {
    "domain_resolves": false,
    "website_accessible": false,
    "ssl_certificate_valid": false,
    "status": "TAKEN_DOWN"
  }
}
```

---

## Automated Monitoring

### Continuous Domain Monitoring

```python
# Set up continuous monitoring
monitoring = await agent.setup_monitoring(
    domains=["google.com", "gmail.com", "youtube.com"],
    check_frequency_hours=24,
    alert_on_new_registrations=True
)

# Agent will:
# 1. Generate permutations daily
# 2. Check for new registrations
# 3. Validate malicious intent
# 4. Auto-generate C&D letters
# 5. Create Jira tickets
# 6. Alert security team via PagerDuty/Slack

# Daily monitoring report:
{
  "date": "2025-10-21",
  "domains_monitored": 3,
  "permutations_checked": 3741,
  "new_registrations_found": 5,
  "malicious_domains_detected": 2,
  "c_and_d_letters_generated": 2,
  "jira_tickets_created": 2,
  
  "new_threats": [
    {
      "domain": "gogle.com",
      "threat_score": 95,
      "jira_ticket": "LEGAL-123"
    },
    {
      "domain": "login-google-verify.com",
      "threat_score": 88,
      "jira_ticket": "LEGAL-124"
    }
  ]
}
```

---

## Configuration

```python
from vaulytica.agents.brand_protection import BrandProtectionAgent

agent = BrandProtectionAgent(
    config=config,
    
    # API keys
    urlscan_api_key="your-urlscan-key",
    
    # Company information
    company_name="Google LLC",
    company_address="1600 Amphitheatre Parkway, Mountain View, CA 94043",
    legal_contact="user@example.com",
    trademarks=["GOOGLE (Reg. No. 3,353,920)"],
    
    # Monitoring settings
    monitored_domains=["google.com", "gmail.com", "youtube.com"],
    check_frequency_hours=24,
    
    # Threat scoring thresholds
    min_threat_score=70,  # Minimum score to generate C&D
    min_content_similarity=0.7,  # Minimum similarity to flag as impersonation
    
    # Jira integration
    jira_url="https://your-company.atlassian.net",
    jira_project_key="LEGAL",
    jira_username="user@example.com",
    jira_api_token="your-jira-token",
    
    # Alerting
    alert_on_new_threats=True,
    pagerduty_service_id="your-pd-service-id"
)
```

---

## Best Practices

1. **Monitor Certificate Transparency Logs**: Catch domains before they're used for attacks
2. **Validate Before Taking Action**: Ensure domain is actually malicious (not just similar)
3. **Document Everything**: Collect comprehensive evidence for legal action
4. **Act Quickly**: Respond within 24-48 hours of detection
5. **Track Metrics**: Monitor time-to-takedown and improve processes

---

## Support

For questions or feedback:
- GitHub Issues: https://example.com
- Documentation: https://docs.vaulytica.com

