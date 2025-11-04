# Collaborative Phishing Response - Google Apps Script

Automatically blocks senders and quarantines messages when multiple users in your organization report an email as spam or phishing.

## 🎯 Overview

This Google Apps Script monitors spam reports across your Google Workspace domain. When a threshold number of users report the same email as spam/phishing, it automatically:

1. **Blocks the sender** domain-wide
2. **Quarantines the message** for all users in the organization
3. **Sends alerts** to security team via email and/or SIEM webhook

## 🔧 Features

- ✅ **Automatic Detection**: Monitors spam folders across all users
- ✅ **Threshold-Based Action**: Only acts when X users report the same email
- ✅ **Sender Blocking**: Prevents future emails from malicious senders
- ✅ **Message Quarantine**: Removes phishing emails from all mailboxes
- ✅ **Security Alerts**: Notifies security team via email and webhook
- ✅ **Whitelist Support**: Protects trusted senders from being blocked
- ✅ **Configurable**: Easy to customize thresholds and behavior
- ✅ **Data Retention**: Automatically cleans up old tracking data

## 📋 Prerequisites

- Google Workspace domain with admin access
- Super Admin privileges to authorize the script
- Basic familiarity with Google Apps Script

## 🚀 Installation

### Step 1: Create the Apps Script Project

1. Go to [script.google.com](https://script.google.com)
2. Click **"New Project"**
3. Name your project: "Phishing Response System"

### Step 2: Add the Code

1. Delete the default `function myFunction() {}` code
2. Copy the entire contents of `Code.gs` from this repository
3. Paste it into the script editor

### Step 3: Configure Settings

Update the `CONFIG` object at the top of the script:

```javascript
const CONFIG = {
  // Your organization domain
  DOMAIN: 'companyname.com',
  
  // Number of users who must report before taking action
  THRESHOLD: 3,  // Recommended: 3-5
  
  // How often to check (in minutes)
  CHECK_INTERVAL: 5,
  
  // Enable/disable automatic actions
  AUTO_BLOCK: true,
  AUTO_QUARANTINE: true,
  
  // Email addresses to notify
  ALERT_EMAILS: [
    'security@companyname.com',
    'it-admin@companyname.com'
  ],
  
  // Optional: Webhook URL for SIEM integration
  WEBHOOK_URL: 'https://siem.companyname.com/webhook',
  
  // Whitelist: senders that should never be blocked
  WHITELIST: [
    '@companyname.com',
    '@google.com',
    '@microsoft.com'
  ]
};
```

### Step 4: Enable Required APIs

1. In the Apps Script editor, click **"Services"** (+ icon on the left sidebar)
2. Add these services:
   - **Gmail API** (v1)
   - **Admin SDK API** (directory_v1)

### Step 5: Run Setup

1. In the script editor, select the `setup` function from the dropdown
2. Click **"Run"** (▶️ button)
3. **Authorize the script** when prompted:
   - Click "Review Permissions"
   - Choose your admin account
   - Click "Advanced" → "Go to Phishing Response System (unsafe)"
   - Click "Allow"

The setup function will:
- Create a time-based trigger to run every 5 minutes (or your configured interval)
- Initialize the tracking database

### Step 6: Verify Installation

1. Check the **"Executions"** tab to see the trigger running
2. Check the **"Logs"** to verify it's working
3. Run the `testPhishingResponse` function manually to test

## 🔐 Required OAuth Scopes

The script requires these permissions:

- `https://www.googleapis.com/auth/gmail.readonly` - Read spam reports
- `https://www.googleapis.com/auth/gmail.modify` - Quarantine messages
- `https://www.googleapis.com/auth/admin.directory.user.readonly` - List domain users
- `https://www.googleapis.com/auth/script.scriptapp` - Manage triggers

## ⚙️ Configuration Options

### Threshold

**Recommended values:**
- **Small org (< 50 users)**: 3 reports
- **Medium org (50-500 users)**: 4-5 reports
- **Large org (> 500 users)**: 5-7 reports

**Why?**
- Too low (1-2): High false positive rate
- Too high (10+): Slow response to real threats
- **Sweet spot: 3-5** balances speed and accuracy

### Check Interval

**Recommended: 5 minutes**

- Faster (1-2 min): More API calls, higher quota usage
- Slower (10+ min): Delayed response to threats

### Auto-Block vs Auto-Quarantine

You can enable/disable each action independently:

```javascript
AUTO_BLOCK: true,        // Block sender domain-wide
AUTO_QUARANTINE: true,   // Remove message from all mailboxes
```

**Recommended:** Enable both for maximum protection

### Whitelist

Add trusted senders/domains that should never be blocked:

```javascript
WHITELIST: [
  '@companyname.com',      // Your own domain
  '@google.com',           // Google services
  '@microsoft.com',        // Microsoft services
  'noreply@github.com',    // Specific addresses
]
```

## 📊 How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  1. Users report emails as spam/phishing                    │
│     (by clicking "Report spam" in Gmail)                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Script runs every 5 minutes                             │
│     - Checks all users' spam folders                        │
│     - Tracks reports by message ID                          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Threshold check                                         │
│     - Has this message been reported by ≥ 3 users?         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼ YES
┌─────────────────────────────────────────────────────────────┐
│  4. Automatic action                                        │
│     ✓ Block sender domain-wide                             │
│     ✓ Quarantine message for all users                     │
│     ✓ Send alerts to security team                         │
└─────────────────────────────────────────────────────────────┘
```

## 🔍 Monitoring

### View Logs

1. In Apps Script editor, click **"Executions"**
2. Click on any execution to see logs
3. Look for:
   - `"THRESHOLD MET"` - Action was taken
   - `"User X reported message"` - New report tracked
   - `"Sender blocked"` - Sender was blocked
   - `"Message quarantined"` - Message was removed

### Email Alerts

You'll receive an email alert when action is taken:

```
Subject: 🚨 Phishing Alert: Automatic Action Taken

DETAILS:
- Sender: phishing@malicious.com
- Subject: Urgent: Verify your account
- Reported by: 3 users
- Reporters: user1@company.com, user2@company.com, user3@company.com

ACTIONS TAKEN:
✓ Sender blocked domain-wide
✓ Message quarantined for all users
```

### SIEM Integration

If you configure a webhook URL, the script will send JSON payloads:

```json
{
  "timestamp": "2024-10-28T10:30:00Z",
  "alert_type": "collaborative_phishing_response",
  "severity": "high",
  "sender": "phishing@malicious.com",
  "subject": "Urgent: Verify your account",
  "report_count": 3,
  "reporters": ["user1@company.com", "user2@company.com", "user3@company.com"],
  "first_reported": "2024-10-28T10:25:00Z",
  "action_taken": {
    "blocked": true,
    "quarantined": true
  }
}
```

## 🧪 Testing

### Manual Test

1. Select the `testPhishingResponse` function
2. Click **"Run"**
3. Check the logs for output

### Simulate a Phishing Attack

1. Send a test email to 3+ users
2. Have each user click "Report spam" in Gmail
3. Wait for the next check interval (5 minutes)
4. Verify the sender is blocked and message is quarantined
5. Check that security team received an alert

## 🛠️ Troubleshooting

### Script Not Running

**Check:**
- Trigger is created (Triggers tab)
- No authorization errors (Executions tab)
- Script hasn't been disabled

**Fix:**
- Re-run the `setup` function
- Check quota limits (see below)

### No Reports Detected

**Check:**
- Users are actually reporting emails as spam
- Script has permission to read Gmail
- Domain is configured correctly

**Fix:**
- Verify CONFIG.DOMAIN matches your organization
- Check that users are using "Report spam" button

### Quota Limits

Google Apps Script has quotas:
- **Gmail API calls**: 10,000/day
- **Admin SDK calls**: 2,500/day

**For large organizations:**
- Increase CHECK_INTERVAL to 10-15 minutes
- Limit user scanning to active users only

### False Positives

**If legitimate emails are being blocked:**
- Increase THRESHOLD (e.g., from 3 to 5)
- Add sender to WHITELIST
- Disable AUTO_BLOCK temporarily

## 📈 Best Practices

1. **Start Conservative**: Begin with THRESHOLD=5 and AUTO_BLOCK=false
2. **Monitor First Week**: Watch logs and alerts closely
3. **Adjust Threshold**: Lower threshold once you're confident
4. **Maintain Whitelist**: Add trusted senders as needed
5. **Regular Reviews**: Check blocked senders list monthly
6. **User Training**: Educate users on when to report spam

## 🔄 Updates and Maintenance

### Update the Script

1. Copy new code from repository
2. Paste into Apps Script editor
3. Save (Ctrl+S or Cmd+S)
4. No need to re-authorize unless scopes change

### Data Cleanup

The script automatically cleans up old data after 30 days (configurable via `DATA_RETENTION_DAYS`).

### Uninstall

1. Delete all triggers (Triggers tab)
2. Delete the Apps Script project
3. Revoke authorization in Google Account settings

## 🆚 Comparison: Apps Script vs Python Tool

| Feature | Apps Script | Python (vaulytica) |
|---------|-------------|----------------------|
| **Real-time response** | ✅ Yes (triggers) | ❌ Requires polling |
| **Hosting** | ✅ Google's infrastructure | ❌ Need own server |
| **Setup complexity** | ✅ Simple | ⚠️ More complex |
| **Maintenance** | ✅ Low | ⚠️ Higher |
| **Best for** | Reactive workflows | Batch scanning |

**Recommendation:** Use Apps Script for this phishing response use case.

## 📞 Support

For issues or questions:
1. Check the logs in Apps Script
2. Review this README
3. Open an issue in the repository

## 📄 License

MIT License - See main repository LICENSE file

---

**Security Note:** This script has powerful permissions. Only authorize it with a trusted admin account and review the code before deployment.

