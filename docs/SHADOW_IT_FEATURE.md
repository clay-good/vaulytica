# Shadow IT Discovery & Risk Analysis

## Overview

The Shadow IT Discovery feature is an advanced OAuth application security analyzer designed specifically for Google Workspace security teams and administrators. It provides comprehensive visibility into unauthorized third-party applications, identifies security risks, and generates actionable remediation plans.

## Key Capabilities

### 1. **Unauthorized App Discovery**
- Automatically identifies OAuth applications not on your approved list
- Classifies apps as Shadow IT vs. Approved
- Google apps are automatically considered approved
- Supports custom approval lists for organization-specific apps

### 2. **Advanced Risk Analysis**
- **Admin Access Detection**: Flags apps with domain-wide admin privileges (CRITICAL)
- **Data Exfiltration Risks**: Identifies apps with Drive, Gmail, or Calendar access
- **Excessive Permissions**: Detects apps requesting unnecessary scopes
- **Unverified Publishers**: Highlights apps from non-Google-verified publishers
- **Stale Grant Detection**: Finds OAuth grants unused for 90+ days (configurable)
- **Widespread Adoption**: Identifies shadow IT used by 20+ users

### 3. **Multi-Level Risk Categorization**
- **CRITICAL**: Apps with admin access or severe security implications
- **HIGH**: Data exfiltration risks, high-risk permissions, widespread unverified apps
- **MEDIUM**: Excessive permissions, unverified publishers, moderate risks
- **LOW**: Stale grants, low-adoption apps

### 4. **Automated Remediation Playbooks**
- Prioritized action items (Priority 1-5)
- Urgency levels (Immediate, High, Medium, Low, Preventive)
- Specific step-by-step remediation instructions
- Timeline recommendations for each action
- Preventive control recommendations

### 5. **Executive Reporting**
- Executive-friendly summary reports
- Business impact analysis
- Risk metrics and KPIs
- Multiple output formats (JSON, CSV, HTML)

## Usage

### Basic Analysis

```bash
# Quick analysis without approval list
vaulytica shadow-it analyze \
  --credentials service-account.json \
  --admin-email admin@example.com \
  --domain example.com \
  --output shadow-it-report.json
```

### With Approval List

```bash
# Create approval template first
vaulytica shadow-it export-template --output approved-apps.json

# Edit approved-apps.json and add your approved apps

# Run analysis with approval list
vaulytica shadow-it analyze \
  --credentials service-account.json \
  --admin-email admin@example.com \
  --domain example.com \
  --approval-list approved-apps.json \
  --output shadow-it-report.html \
  --format html
```

### Configuration Options

- `--credentials`: Path to service account JSON file (required)
- `--admin-email`: Admin email for domain-wide delegation (required)
- `--domain`: Google Workspace domain to analyze (required)
- `--approval-list`: Path to approved apps JSON file (optional)
- `--stale-days`: Days to consider OAuth grant stale (default: 90)
- `--max-users`: Maximum users to analyze for testing (optional)
- `--no-audit-logs`: Skip audit log analysis for faster execution
- `--output`: Output file path (optional)
- `--format`: Output format - json, csv, or html (default: json)

## Approval List Format

The approval list is a JSON file containing your organization's approved OAuth applications:

```json
{
  "approved_apps": [
    {
      "client_id": "123456.apps.googleusercontent.com",
      "app_name": "Slack",
      "approved_by": "security-team@example.com",
      "approved_at": "2024-01-01T00:00:00Z",
      "notes": "Approved for company-wide collaboration"
    },
    {
      "client_id": "another-app-id.com",
      "app_name": "Zoom",
      "approved_by": "it-admin@example.com",
      "approved_at": "2024-02-15T00:00:00Z",
      "notes": "Video conferencing - approved for all departments"
    }
  ]
}
```

## Output Formats

### JSON Output
Complete machine-readable report with all findings, metadata, and recommendations.

### CSV Output
Tabular format suitable for spreadsheets with key finding details.

### HTML Output
Beautiful, interactive dashboard with:
- Executive summary
- Risk metrics cards
- Detailed findings with color coding
- Complete remediation playbook
- Print-friendly design

## Security & Privacy

- **READ-ONLY Operation**: The analyzer never modifies your Google Workspace
- **No Data Storage**: All analysis is done in memory
- **Audit Logging**: All API calls are logged for compliance
- **Permissions Required**:
  - `admin.directory.user.readonly` - Read user information
  - `admin.reports.audit.readonly` - Read audit logs (optional but recommended)

## Integration with Existing Workflows

### Scheduled Scanning
```bash
# Add to cron for monthly scans
vaulytica schedule add \
  "shadow-it analyze --credentials /path/to/creds.json --admin-email admin@example.com --domain example.com --output /reports/shadow-it-$(date +%Y%m%d).html --format html" \
  --frequency monthly \
  --name "Monthly Shadow IT Scan"
```

### Alerting
The Shadow IT analyzer can be integrated with existing alert workflows:
- CRITICAL findings trigger immediate alerts
- HIGH findings can be scheduled for weekly review
- Monthly summary reports for stakeholders

### SIEM Integration
JSON output can be ingested by SIEM systems for:
- Trend analysis over time
- Correlation with other security events
- Automated response workflows

## Use Cases

### For Security Teams
- **Threat Hunting**: Discover unauthorized apps with admin access
- **Incident Response**: Identify potentially malicious OAuth applications
- **Risk Assessment**: Quantify OAuth security posture
- **Compliance**: Demonstrate OAuth app governance

### For IT Administrators
- **App Management**: Maintain approved app catalog
- **User Education**: Identify apps to communicate about
- **Policy Enforcement**: Find policy violations
- **License Optimization**: Identify redundant apps

### For Compliance Teams
- **Audit Preparation**: Document OAuth app controls
- **Policy Compliance**: Verify adherence to app approval process
- **Risk Reporting**: Executive-level risk summaries
- **Regulatory Requirements**: SOC 2, ISO 27001 evidence

## Best Practices

### 1. Establish Approval Process
- Create formal OAuth app approval workflow
- Document business justification requirements
- Define security review criteria
- Maintain approval list

### 2. Regular Scanning
- Run monthly Shadow IT scans minimum
- Weekly scans for high-security environments
- Ad-hoc scans after security incidents

### 3. Risk-Based Response
- CRITICAL: Address within 24 hours
- HIGH: Review within 1 week
- MEDIUM: Address within 2 weeks
- LOW: Include in regular maintenance

### 4. User Communication
- Educate users on OAuth risks
- Provide approved alternatives
- Communicate policy clearly
- Offer easy approval process for legitimate apps

### 5. Preventive Controls
- Enable OAuth app whitelisting in Google Admin Console
- Implement app allowlists/blocklists
- Set up automated approval workflows
- Monitor new app authorizations

## Example Findings

### Critical Finding Example
```
🔴 CRITICAL: Unauthorized Admin Tool
Category: Admin Access Risk
Risk Score: 95/100
Users: 5

Description: App has admin-level permissions that could compromise your entire Google Workspace.

Evidence:
- Has admin directory access
- Can manage users, groups, or domain settings
- Risk Score: 95/100

Remediation Steps:
⚠️ IMMEDIATE ACTION REQUIRED
1. Revoke access immediately if not approved
2. Investigate recent admin actions via audit logs
3. Review affected user accounts for unauthorized changes
4. Consider implementing OAuth app whitelisting
```

### High Finding Example
```
🟠 HIGH: File Sync App
Category: Data Exfiltration Risk, Widespread Adoption
Risk Score: 75/100
Users: 25

Description: App has access to Drive and Email, used by 25 users (widespread adoption).

Evidence:
- Full Drive access
- Email access
- User Count: 25
- Indicates potential business need

Remediation Steps:
1. Investigate business justification
2. Consider formal approval if legitimate
3. Review app's data handling and privacy policy
4. Check for data classification violations
5. Implement organization-wide policy
```

## Troubleshooting

### "Insufficient Permissions" Error
Ensure your service account has domain-wide delegation with required scopes:
- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/admin.reports.audit.readonly` (optional)

### Slow Performance
- Use `--max-users` to limit scope for testing
- Use `--no-audit-logs` to skip audit analysis
- Consider scheduled scans during off-hours

### False Positives
- Maintain comprehensive approval list
- Document exceptions in approval notes
- Use risk-based approach (focus on CRITICAL/HIGH first)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Shadow IT Analyzer                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │   OAuth      │───>│    Risk      │───>│  Remediation │ │
│  │   Scanner    │    │   Analyzer   │    │   Playbook   │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│         │                    │                    │         │
│         v                    v                    v         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │  App List    │    │  Findings    │    │   Reports    │ │
│  │ Classification│    │Categorization│    │  (JSON/CSV/  │ │
│  │              │    │              │    │   HTML)      │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│         │                    │                    │         │
│         └────────────────────┴────────────────────┘         │
│                              │                              │
│                              v                              │
│                    ┌──────────────────┐                     │
│                    │  Output Formats  │                     │
│                    │  - Executive     │                     │
│                    │  - Detailed      │                     │
│                    │  - Actionable    │                     │
│                    └──────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

## Testing

The Shadow IT analyzer includes comprehensive test coverage:
- 20 unit tests covering all major functionality
- 97% code coverage
- Mocked Google API calls for reliable testing
- Edge case handling

Run tests with:
```bash
poetry run pytest tests/core/analyzers/test_shadow_it_analyzer.py -v
```

## Future Enhancements

Potential future improvements:
- Machine learning-based risk scoring
- Historical trend analysis
- Automatic app categorization
- Integration with threat intelligence feeds
- User behavior analytics
- Automated remediation actions (with approval)
- Real-time OAuth grant monitoring
- App reputation scoring from community data

## Support & Feedback

For issues, questions, or feature requests:
- GitHub Issues: https://github.com/clay-good/vaulytica/issues
- Documentation: https://github.com/clay-good/vaulytica/README.md

## License

MIT License - See LICENSE file for details
