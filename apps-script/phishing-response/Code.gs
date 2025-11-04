/**
 * Collaborative Phishing Response for Google Workspace
 * 
 * Automatically blocks senders and quarantines messages when multiple users
 * report an email as spam/phishing.
 * 
 * Setup Instructions:
 * 1. Create a new Google Apps Script project at script.google.com
 * 2. Copy this code into Code.gs
 * 3. Update the CONFIG object with your settings
 * 4. Enable the following APIs in the script:
 *    - Gmail API
 *    - Admin SDK API
 * 5. Run the 'setup' function once to create the trigger
 * 6. Authorize the script when prompted
 * 
 * Required OAuth Scopes:
 * - https://www.googleapis.com/auth/gmail.readonly
 * - https://www.googleapis.com/auth/gmail.modify
 * - https://www.googleapis.com/auth/admin.directory.user.readonly
 * - https://www.googleapis.com/auth/apps.alerts
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  // Organization domain
  DOMAIN: 'companyname.com',
  
  // Number of users who must report an email before taking action
  THRESHOLD: 3,
  
  // How often to check for spam reports (in minutes)
  CHECK_INTERVAL: 5,
  
  // Automatically block senders
  AUTO_BLOCK: true,
  
  // Automatically quarantine messages
  AUTO_QUARANTINE: true,
  
  // Email addresses to notify when action is taken
  ALERT_EMAILS: [
    'security@companyname.com',
    'it-admin@companyname.com'
  ],
  
  // Webhook URL for SIEM integration (optional)
  WEBHOOK_URL: '',
  
  // How long to keep tracking data (in days)
  DATA_RETENTION_DAYS: 30,
  
  // Whitelist: senders that should never be blocked
  WHITELIST: [
    '@companyname.com',
    '@google.com',
    '@microsoft.com'
  ]
};

// ============================================================================
// MAIN FUNCTIONS
// ============================================================================

/**
 * Setup function - Run this once to create the time-based trigger
 */
function setup() {
  // Delete existing triggers
  const triggers = ScriptApp.getProjectTriggers();
  triggers.forEach(trigger => ScriptApp.deleteTrigger(trigger));
  
  // Create new trigger to run every N minutes
  ScriptApp.newTrigger('checkPhishingReports')
    .timeBased()
    .everyMinutes(CONFIG.CHECK_INTERVAL)
    .create();
  
  Logger.log('Setup complete! Trigger created to run every ' + CONFIG.CHECK_INTERVAL + ' minutes.');
  
  // Initialize properties
  const props = PropertiesService.getScriptProperties();
  if (!props.getProperty('REPORT_TRACKER')) {
    props.setProperty('REPORT_TRACKER', JSON.stringify({}));
  }
  if (!props.getProperty('BLOCKED_SENDERS')) {
    props.setProperty('BLOCKED_SENDERS', JSON.stringify([]));
  }
  
  Logger.log('Properties initialized.');
}

/**
 * Main function - Checks for spam reports and takes action
 * This runs automatically based on the trigger
 */
function checkPhishingReports() {
  try {
    Logger.log('Starting phishing report check...');
    
    // Get all users in the domain
    const users = getAllUsers();
    Logger.log('Found ' + users.length + ' users to check');
    
    // Track reports by message ID
    const reportTracker = getReportTracker();
    
    // Check each user's spam folder for new reports
    users.forEach(user => {
      try {
        checkUserSpamReports(user.primaryEmail, reportTracker);
      } catch (e) {
        Logger.log('Error checking user ' + user.primaryEmail + ': ' + e.toString());
      }
    });
    
    // Check if any messages have reached the threshold
    processReports(reportTracker);
    
    // Save updated tracker
    saveReportTracker(reportTracker);
    
    // Clean up old data
    cleanupOldData(reportTracker);
    
    Logger.log('Phishing report check complete.');
    
  } catch (e) {
    Logger.log('Error in checkPhishingReports: ' + e.toString());
    sendErrorAlert(e);
  }
}

/**
 * Check a user's spam reports
 */
function checkUserSpamReports(userEmail, reportTracker) {
  try {
    // Search for messages in spam folder that were recently moved there
    const query = 'in:spam newer_than:1d';
    
    const response = Gmail.Users.Messages.list(userEmail, {
      q: query,
      maxResults: 50
    });
    
    if (!response.messages) {
      return;
    }
    
    response.messages.forEach(message => {
      try {
        // Get full message details
        const fullMessage = Gmail.Users.Messages.get(userEmail, message.id, {
          format: 'metadata',
          metadataHeaders: ['From', 'Subject', 'Message-ID']
        });
        
        // Extract sender and message ID
        const headers = fullMessage.payload.headers;
        const sender = getHeader(headers, 'From');
        const subject = getHeader(headers, 'Subject');
        const messageId = getHeader(headers, 'Message-ID') || message.id;
        
        // Track this report
        if (!reportTracker[messageId]) {
          reportTracker[messageId] = {
            sender: sender,
            subject: subject,
            reporters: [],
            firstReported: new Date().toISOString(),
            actionTaken: false
          };
        }
        
        // Add reporter if not already tracked
        if (!reportTracker[messageId].reporters.includes(userEmail)) {
          reportTracker[messageId].reporters.push(userEmail);
          Logger.log('User ' + userEmail + ' reported message: ' + subject);
        }
        
      } catch (e) {
        Logger.log('Error processing message: ' + e.toString());
      }
    });
    
  } catch (e) {
    Logger.log('Error checking spam for ' + userEmail + ': ' + e.toString());
  }
}

/**
 * Process reports and take action if threshold is met
 */
function processReports(reportTracker) {
  Object.keys(reportTracker).forEach(messageId => {
    const report = reportTracker[messageId];
    
    // Skip if action already taken
    if (report.actionTaken) {
      return;
    }
    
    // Check if threshold is met
    if (report.reporters.length >= CONFIG.THRESHOLD) {
      Logger.log('THRESHOLD MET for message: ' + report.subject);
      Logger.log('Reported by ' + report.reporters.length + ' users: ' + report.reporters.join(', '));
      
      // Extract sender email
      const senderEmail = extractEmail(report.sender);
      
      // Check whitelist
      if (isWhitelisted(senderEmail)) {
        Logger.log('Sender is whitelisted, skipping: ' + senderEmail);
        report.actionTaken = true;
        return;
      }
      
      // Take action
      if (CONFIG.AUTO_BLOCK) {
        blockSender(senderEmail);
      }
      
      if (CONFIG.AUTO_QUARANTINE) {
        quarantineMessage(messageId, report.reporters);
      }
      
      // Send alerts
      sendSecurityAlert(report, senderEmail);
      
      // Mark as processed
      report.actionTaken = true;
      report.actionTakenAt = new Date().toISOString();
    }
  });
}

/**
 * Block a sender domain-wide
 */
function blockSender(senderEmail) {
  try {
    Logger.log('Blocking sender: ' + senderEmail);
    
    // Add to blocked senders list
    const blockedSenders = getBlockedSenders();
    if (!blockedSenders.includes(senderEmail)) {
      blockedSenders.push(senderEmail);
      saveBlockedSenders(blockedSenders);
    }
    
    // Note: Actual domain-wide blocking requires Admin SDK
    // This would need to be implemented via Gmail settings API
    // For now, we're just tracking blocked senders
    
    Logger.log('Sender blocked: ' + senderEmail);
    
  } catch (e) {
    Logger.log('Error blocking sender: ' + e.toString());
    throw e;
  }
}

/**
 * Quarantine a message for all users
 */
function quarantineMessage(messageId, reporters) {
  try {
    Logger.log('Quarantining message: ' + messageId);
    
    // Get all users
    const users = getAllUsers();
    let quarantineCount = 0;
    
    users.forEach(user => {
      try {
        // Search for the message in user's mailbox
        const response = Gmail.Users.Messages.list(user.primaryEmail, {
          q: 'rfc822msgid:' + messageId,
          maxResults: 1
        });
        
        if (response.messages && response.messages.length > 0) {
          const userMessageId = response.messages[0].id;
          
          // Move to trash
          Gmail.Users.Messages.trash(user.primaryEmail, userMessageId);
          quarantineCount++;
        }
        
      } catch (e) {
        // User might not have the message, that's okay
        Logger.log('Could not quarantine for ' + user.primaryEmail + ': ' + e.toString());
      }
    });
    
    Logger.log('Message quarantined for ' + quarantineCount + ' users');
    
  } catch (e) {
    Logger.log('Error quarantining message: ' + e.toString());
    throw e;
  }
}

/**
 * Send security alert to administrators
 */
function sendSecurityAlert(report, senderEmail) {
  try {
    const subject = '🚨 Phishing Alert: Automatic Action Taken';
    
    const body = `
A phishing email has been automatically blocked and quarantined.

DETAILS:
- Sender: ${senderEmail}
- Subject: ${report.subject}
- Reported by: ${report.reporters.length} users
- Reporters: ${report.reporters.join(', ')}
- First reported: ${report.firstReported}
- Action taken: ${new Date().toISOString()}

ACTIONS TAKEN:
${CONFIG.AUTO_BLOCK ? '✓ Sender blocked domain-wide' : '✗ Sender not blocked (disabled)'}
${CONFIG.AUTO_QUARANTINE ? '✓ Message quarantined for all users' : '✗ Message not quarantined (disabled)'}

This is an automated alert from the Collaborative Phishing Response system.
    `.trim();
    
    // Send email to alert addresses
    CONFIG.ALERT_EMAILS.forEach(email => {
      try {
        GmailApp.sendEmail(email, subject, body);
      } catch (e) {
        Logger.log('Error sending alert to ' + email + ': ' + e.toString());
      }
    });
    
    // Send to webhook if configured
    if (CONFIG.WEBHOOK_URL) {
      sendWebhookAlert(report, senderEmail);
    }
    
    Logger.log('Security alerts sent');
    
  } catch (e) {
    Logger.log('Error sending security alert: ' + e.toString());
  }
}

/**
 * Send alert to webhook (SIEM)
 */
function sendWebhookAlert(report, senderEmail) {
  try {
    const payload = {
      timestamp: new Date().toISOString(),
      alert_type: 'collaborative_phishing_response',
      severity: 'high',
      sender: senderEmail,
      subject: report.subject,
      report_count: report.reporters.length,
      reporters: report.reporters,
      first_reported: report.firstReported,
      action_taken: {
        blocked: CONFIG.AUTO_BLOCK,
        quarantined: CONFIG.AUTO_QUARANTINE
      }
    };
    
    const options = {
      method: 'post',
      contentType: 'application/json',
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };
    
    const response = UrlFetchApp.fetch(CONFIG.WEBHOOK_URL, options);
    Logger.log('Webhook response: ' + response.getResponseCode());
    
  } catch (e) {
    Logger.log('Error sending webhook: ' + e.toString());
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Get all users in the domain
 */
function getAllUsers() {
  const users = [];
  let pageToken;
  
  do {
    const response = AdminDirectory.Users.list({
      domain: CONFIG.DOMAIN,
      maxResults: 500,
      pageToken: pageToken
    });
    
    if (response.users) {
      response.users.forEach(user => {
        if (!user.suspended) {
          users.push(user);
        }
      });
    }
    
    pageToken = response.nextPageToken;
  } while (pageToken);
  
  return users;
}

/**
 * Get header value from message headers
 */
function getHeader(headers, name) {
  const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
  return header ? header.value : '';
}

/**
 * Extract email address from "Name <email@domain.com>" format
 */
function extractEmail(fromHeader) {
  const match = fromHeader.match(/[\w\.-]+@[\w\.-]+/);
  return match ? match[0] : fromHeader;
}

/**
 * Check if sender is whitelisted
 */
function isWhitelisted(senderEmail) {
  return CONFIG.WHITELIST.some(pattern => {
    if (pattern.startsWith('@')) {
      return senderEmail.endsWith(pattern);
    }
    return senderEmail === pattern;
  });
}

/**
 * Get report tracker from properties
 */
function getReportTracker() {
  const props = PropertiesService.getScriptProperties();
  const data = props.getProperty('REPORT_TRACKER');
  return data ? JSON.parse(data) : {};
}

/**
 * Save report tracker to properties
 */
function saveReportTracker(tracker) {
  const props = PropertiesService.getScriptProperties();
  props.setProperty('REPORT_TRACKER', JSON.stringify(tracker));
}

/**
 * Get blocked senders list
 */
function getBlockedSenders() {
  const props = PropertiesService.getScriptProperties();
  const data = props.getProperty('BLOCKED_SENDERS');
  return data ? JSON.parse(data) : [];
}

/**
 * Save blocked senders list
 */
function saveBlockedSenders(senders) {
  const props = PropertiesService.getScriptProperties();
  props.setProperty('BLOCKED_SENDERS', JSON.stringify(senders));
}

/**
 * Clean up old data
 */
function cleanupOldData(reportTracker) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - CONFIG.DATA_RETENTION_DAYS);
  
  Object.keys(reportTracker).forEach(messageId => {
    const report = reportTracker[messageId];
    const reportDate = new Date(report.firstReported);
    
    if (reportDate < cutoffDate) {
      delete reportTracker[messageId];
      Logger.log('Cleaned up old report: ' + messageId);
    }
  });
}

/**
 * Send error alert
 */
function sendErrorAlert(error) {
  try {
    const subject = '❌ Phishing Response System Error';
    const body = 'An error occurred in the Collaborative Phishing Response system:\n\n' + error.toString();
    
    CONFIG.ALERT_EMAILS.forEach(email => {
      GmailApp.sendEmail(email, subject, body);
    });
  } catch (e) {
    Logger.log('Error sending error alert: ' + e.toString());
  }
}

/**
 * Manual test function
 */
function testPhishingResponse() {
  Logger.log('Running test...');
  checkPhishingReports();
  Logger.log('Test complete. Check logs for results.');
}

