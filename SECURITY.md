# Security Policy

Vaulytica is a static web page with no backend, no database, no analytics, and no telemetry. The threat model is documented in [`docs/threat-model.md`](docs/threat-model.md) (added in build step 15). In short: we protect against network exfiltration, vendor mining, and server-side breach because there is no server to breach. We do not protect against a compromised browser, a malicious extension, or the user themselves sharing their report.

## Reporting a vulnerability

Please report security issues privately via [GitHub Security Advisories](https://github.com/claygood/vaulytica/security/advisories/new). Do not open public issues for security reports. Reasonable disclosures will receive an acknowledgement within 7 days.
