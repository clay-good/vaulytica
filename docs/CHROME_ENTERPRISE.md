# Chrome Enterprise Management with Vaulytica

Complete guide for managing Chrome OS devices, Chrome Browser, and Chrome Enterprise profiles using Vaulytica.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Chrome OS Device Management](#chrome-os-device-management)
3. [Use Cases](#use-cases)
4. [Setup & Configuration](#setup--configuration)
5. [Commands & Examples](#commands--examples)
6. [Security Best Practices](#security-best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Overview

Vaulytica provides comprehensive management and security monitoring for Chrome Enterprise environments:

### Supported Devices
- **Chromebooks** - Laptops running Chrome OS
- **Chromeboxes** - Desktop devices running Chrome OS
- **Chromebases** - All-in-one devices running Chrome OS
- **Chrome Enterprise** - Managed Chrome Browser on Windows/Mac/Linux

### Key Capabilities
- ✅ Device inventory and tracking
- ✅ Auto-update expiration monitoring
- ✅ Developer mode detection
- ✅ Inactive device identification
- ✅ Compliance reporting
- ✅ Security policy enforcement
- ✅ Organizational unit filtering
- ✅ Risk scoring and prioritization

---

## Chrome OS Device Management

### What Vaulytica Monitors

#### 1. **Auto-Update Expiration** (Critical)
Chrome OS devices have an Auto-Update Expiration (AUE) date. After this date, devices no longer receive:
- Security updates
- Feature updates
- Bug fixes

**Risk:** Expired devices are vulnerable to security exploits.

**Detection:**
```bash
vaulytica scan chrome-devices --output expired-devices.csv
```

Vaulytica automatically identifies devices past their AUE date and flags them as **critical risk**.

#### 2. **Developer Mode** (High Risk)
Developer mode disables Chrome OS security features:
- Verified boot disabled
- System integrity checks disabled
- Root access enabled
- Data encryption may be compromised

**Risk:** Devices in developer mode are highly vulnerable to malware and data theft.

**Detection:**
```bash
vaulytica scan chrome-devices --output dev-mode-devices.csv
```

Vaulytica flags all devices in developer mode as **high risk**.

#### 3. **Inactive Devices**
Devices that haven't synced in 90+ days (configurable) may be:
- Lost or stolen
- Unused and wasting licenses
- Forgotten in storage

**Detection:**
```bash
vaulytica scan chrome-devices --inactive-days 90 --output inactive-devices.csv
```

#### 4. **Device Status**
- **ACTIVE** - Device is active and in use
- **PROVISIONED** - Device is enrolled but not yet activated
- **DISABLED** - Device has been administratively disabled
- **DEPROVISIONED** - Device has been removed from management

#### 5. **Device Inventory**
Track all Chrome devices with:
- Serial numbers
- Asset IDs
- Models
- OS versions
- Firmware versions
- Assigned users
- Locations
- Organizational units

---

## Use Cases

### 1. **Security Audit - Find Vulnerable Devices**

**Scenario:** You need to identify all Chrome devices with security risks.

```bash
# Scan all Chrome devices
vaulytica scan chrome-devices --output security-audit.json

# Filter by organizational unit
vaulytica scan chrome-devices --org-unit "/Students" --output student-devices.csv
```

**What You Get:**
- Devices with expired auto-updates (critical)
- Devices in developer mode (high risk)
- Inactive devices (medium risk)
- Risk scores for prioritization

### 2. **Compliance Reporting - Device Inventory**

**Scenario:** You need a complete inventory for compliance (SOC 2, ISO 27001, etc.).

```bash
# Export all devices to CSV
vaulytica scan chrome-devices --output device-inventory.csv
```

**CSV Includes:**
- Device ID, Serial Number, Asset ID
- Model, OS Version, Firmware Version
- Status, Last Sync Date
- Assigned User, Location
- Organizational Unit
- Security Status (Auto-Update, Developer Mode)
- Risk Score

### 3. **License Optimization - Find Unused Devices**

**Scenario:** You're paying for Chrome Enterprise licenses but some devices are inactive.

```bash
# Find devices inactive for 180+ days
vaulytica scan chrome-devices --inactive-days 180 --output unused-devices.csv
```

**Action:** Deprovision unused devices to reclaim licenses.

### 4. **Auto-Update Expiration Management**

**Scenario:** You need to plan device replacements before AUE dates.

```bash
# Scan all devices
vaulytica scan chrome-devices --output aue-report.json
```

**JSON Output Includes:**
```json
{
  "devices": [
    {
      "serial_number": "ABC123",
      "model": "HP Chromebook 14",
      "auto_update_expired": true,
      "auto_update_expiration": "2024-06-30T00:00:00Z",
      "risk_score": 85,
      "user": "student@school.edu"
    }
  ]
}
```

**Action:** Replace devices before AUE date or accept security risks.

### 5. **Developer Mode Detection**

**Scenario:** You need to ensure no devices have developer mode enabled (security policy).

```bash
# Scan for developer mode devices
vaulytica scan chrome-devices --output dev-mode-check.csv
```

**Action:** Devices in developer mode should be:
1. Powerwashed (factory reset)
2. Re-enrolled in verified mode
3. Or deprovisioned if unauthorized

### 6. **Organizational Unit Auditing**

**Scenario:** You want to audit devices in a specific department or location.

```bash
# Scan specific OU
vaulytica scan chrome-devices --org-unit "/Engineering" --output engineering-devices.csv

# Scan student devices
vaulytica scan chrome-devices --org-unit "/Students/Grade12" --output grade12-devices.csv
```

### 7. **Scheduled Compliance Scans**

**Scenario:** You need weekly reports on Chrome device security.

```bash
# Add to cron (weekly on Monday at 8 AM)
0 8 * * 1 /usr/local/bin/vaulytica scan chrome-devices --output /reports/chrome-devices-$(date +\%Y\%m\%d).csv
```

### 8. **Integration with SIEM/Ticketing**

**Scenario:** You want to automatically create tickets for high-risk devices.

```bash
# Scan and send to webhook
vaulytica scan chrome-devices --output chrome-devices.json

# Parse JSON and create tickets for devices with risk_score > 70
```

---

## Setup & Configuration

### Required OAuth Scopes

Add this scope to your service account's domain-wide delegation:

```
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
```

### Required Admin Roles

The impersonated admin user needs:
- **Chrome OS Device Management** (read-only)
- Or **Super Admin** role

### Configuration

No special configuration needed. Vaulytica uses your existing `config.yaml`:

```yaml
google_workspace:
  domain: "yourcompany.com"
  credentials_file: "/path/to/service-account.json"
  impersonate_user: "admin@yourcompany.com"
```

---

## Commands & Examples

### Basic Scan

```bash
# Scan all Chrome devices
vaulytica scan chrome-devices
```

**Output:**
```
🔍 Scanning Chrome OS Devices...

✓ Chrome Device Scan Complete

┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Metric               ┃ Count ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Total Devices        │ 1,234 │
│ Active Devices       │ 1,150 │
│ Provisioned Devices  │ 50    │
│ Disabled Devices     │ 34    │
│ Auto-Update Expired  │ 45    │
│ Developer Mode       │ 3     │
│ Inactive Devices     │ 84    │
│ Total Issues         │ 132   │
└──────────────────────┴───────┘
```

### Filter by Organizational Unit

```bash
# Scan specific OU
vaulytica scan chrome-devices --org-unit "/Students"

# Scan nested OU
vaulytica scan chrome-devices --org-unit "/Engineering/QA"
```

### Adjust Inactive Threshold

```bash
# Consider devices inactive after 180 days
vaulytica scan chrome-devices --inactive-days 180

# Consider devices inactive after 30 days
vaulytica scan chrome-devices --inactive-days 30
```

### Export to CSV

```bash
# Export all devices to CSV
vaulytica scan chrome-devices --output devices.csv
```

**CSV Columns:**
- Device ID
- Serial Number
- Model
- Status
- OS Version
- User
- Location
- Last Sync
- Auto-Update Expired
- Developer Mode
- Risk Score

### Export to JSON

```bash
# Export to JSON for programmatic processing
vaulytica scan chrome-devices --output devices.json
```

**JSON Structure:**
```json
{
  "scan_type": "chrome_devices",
  "summary": {
    "total_devices": 1234,
    "active_devices": 1150,
    "auto_update_expired": 45,
    "dev_mode_devices": 3,
    "inactive_devices": 84
  },
  "devices": [...],
  "issues": [...]
}
```

---

## Security Best Practices

### 1. **Monitor Auto-Update Expiration**
- Run monthly scans to identify devices approaching AUE
- Plan device replacements 6-12 months before AUE
- Budget for device refresh cycles

### 2. **Prohibit Developer Mode**
- Set organizational policy to prevent developer mode
- Regularly scan for developer mode violations
- Deprovision devices that violate policy

### 3. **Track Inactive Devices**
- Scan quarterly for inactive devices
- Deprovision devices inactive for 180+ days
- Reclaim licenses to reduce costs

### 4. **Maintain Device Inventory**
- Export device inventory monthly
- Track serial numbers and asset IDs
- Maintain accurate user assignments

### 5. **Organizational Unit Structure**
- Use OUs to organize devices by:
  - Department (Engineering, Sales, HR)
  - Location (Building A, Remote)
  - Device type (Chromebooks, Chromeboxes)
  - User type (Employees, Contractors, Students)

---

## Troubleshooting

### Error: "Insufficient permissions"

**Cause:** Service account doesn't have Chrome OS device management scope.

**Fix:**
1. Go to Google Admin Console → Security → API Controls → Domain-wide Delegation
2. Find your service account
3. Add scope: `https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly`
4. Click "Authorize"

### Error: "No devices found"

**Possible causes:**
1. No Chrome devices enrolled in your domain
2. Organizational unit filter is too restrictive
3. Service account doesn't have access to the OU

**Fix:**
- Remove `--org-unit` filter to scan all devices
- Verify devices are enrolled in Google Admin Console
- Check service account permissions

### Devices showing as "inactive" but are in use

**Cause:** Devices may not be syncing properly.

**Fix:**
1. Check device network connectivity
2. Verify device is signed in to a user account
3. Check for sync errors in Chrome OS settings
4. Adjust `--inactive-days` threshold if needed

---

## Additional Resources

- [Google Chrome Enterprise Documentation](https://support.google.com/chrome/a/)
- [Chrome OS Auto-Update Policy](https://support.google.com/chrome/a/answer/6220366)
- [Chrome Device Management API](https://developers.google.com/admin-sdk/directory/reference/rest/v1/chromeosdevices)
- [Vaulytica Documentation](../README.md)

---

**Need help?** Open an issue on [GitHub](https://github.com/clay-good/vaulytica/issues).

