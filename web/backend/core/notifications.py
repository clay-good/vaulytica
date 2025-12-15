"""Notification service for sending alerts."""

import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

import httpx

from .email import EmailService
from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class NotificationService:
    """Service for sending notifications through various channels."""

    def __init__(self):
        """Initialize notification service."""
        self.email_service = EmailService()

    def send_notification(
        self,
        channels: List[str],
        config: Dict[str, Any],
        subject: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, bool]:
        """Send notification through specified channels.

        Args:
            channels: List of notification channels (email, webhook)
            config: Channel-specific configuration
            subject: Notification subject
            message: Notification message
            details: Additional details (optional)

        Returns:
            Dict mapping channel to success status
        """
        results = {}

        for channel in channels:
            if channel == "email":
                results["email"] = self._send_email_notification(
                    config.get("emails", []),
                    subject,
                    message,
                    details,
                )
            elif channel == "webhook":
                results["webhook"] = self._send_webhook_notification(
                    config.get("webhook_url"),
                    subject,
                    message,
                    details,
                )
            else:
                logger.warning(f"Unknown notification channel: {channel}")
                results[channel] = False

        return results

    def _send_email_notification(
        self,
        emails: List[str],
        subject: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send email notification.

        Args:
            emails: List of recipient email addresses
            subject: Email subject
            message: Email message
            details: Additional details for email body

        Returns:
            True if all emails sent successfully
        """
        if not emails:
            logger.warning("No email addresses configured for notification")
            return False

        html_content = self._build_email_html(subject, message, details)
        text_content = self._build_email_text(subject, message, details)

        all_sent = True
        for email in emails:
            try:
                success = self.email_service.send_email(
                    to_email=email,
                    subject=f"[Vaulytica Alert] {subject}",
                    html_content=html_content,
                    text_content=text_content,
                )
                if not success:
                    all_sent = False
                    logger.warning(f"Failed to send notification email to {email}")
            except Exception as e:
                all_sent = False
                logger.error(f"Error sending notification email to {email}: {e}")

        return all_sent

    def _send_webhook_notification(
        self,
        webhook_url: Optional[str],
        subject: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send webhook notification.

        Args:
            webhook_url: Webhook URL to POST to
            subject: Notification subject
            message: Notification message
            details: Additional details

        Returns:
            True if webhook request succeeded
        """
        if not webhook_url:
            logger.warning("No webhook URL configured for notification")
            return False

        payload = {
            "source": "vaulytica",
            "timestamp": datetime.utcnow().isoformat(),
            "subject": subject,
            "message": message,
            "details": details or {},
        }

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                logger.info(f"Webhook notification sent successfully to {webhook_url}")
                return True
        except httpx.HTTPStatusError as e:
            logger.error(f"Webhook request failed with status {e.response.status_code}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False

    def _build_email_html(
        self,
        subject: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Build HTML email content."""
        details_html = ""
        if details:
            details_rows = "".join(
                f"<tr><td style='padding: 8px; border: 1px solid #ddd;'><strong>{k}</strong></td>"
                f"<td style='padding: 8px; border: 1px solid #ddd;'>{v}</td></tr>"
                for k, v in details.items()
            )
            details_html = f"""
            <h3 style="color: #333; margin-top: 20px;">Details</h3>
            <table style="border-collapse: collapse; width: 100%;">
                {details_rows}
            </table>
            """

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{subject}</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px;">
                <h1 style="color: #dc3545; margin: 0 0 10px 0; font-size: 24px;">Vaulytica Alert</h1>
                <h2 style="color: #333; margin: 0 0 20px 0; font-size: 18px;">{subject}</h2>
                <p style="margin: 0 0 20px 0;">{message}</p>
                {details_html}
                <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                <p style="font-size: 12px; color: #666; margin: 0;">
                    This is an automated notification from Vaulytica Security Scanner.
                    <br>Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
                </p>
            </div>
        </body>
        </html>
        """

    def _build_email_text(
        self,
        subject: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Build plain text email content."""
        details_text = ""
        if details:
            details_text = "\n\nDetails:\n" + "\n".join(
                f"  {k}: {v}" for k, v in details.items()
            )

        return f"""
VAULYTICA ALERT
===============

{subject}

{message}
{details_text}

---
This is an automated notification from Vaulytica Security Scanner.
Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """.strip()


def send_scan_completion_notification(
    domain_name: str,
    scan_type: str,
    scan_id: int,
    status: str,
    total_items: int,
    issues_found: int,
    channels: List[str],
    config: Dict[str, Any],
) -> Dict[str, bool]:
    """Send notification when a scan completes.

    Args:
        domain_name: Domain that was scanned
        scan_type: Type of scan
        scan_id: Scan ID
        status: Scan status (completed, failed, cancelled)
        total_items: Total items scanned
        issues_found: Number of issues found
        channels: Notification channels
        config: Channel configuration

    Returns:
        Dict mapping channel to success status
    """
    service = NotificationService()

    if status == "completed":
        subject = f"Scan Completed: {scan_type} scan on {domain_name}"
        message = f"The {scan_type} scan on {domain_name} has completed successfully."
    elif status == "failed":
        subject = f"Scan Failed: {scan_type} scan on {domain_name}"
        message = f"The {scan_type} scan on {domain_name} has failed."
    else:
        subject = f"Scan {status.capitalize()}: {scan_type} scan on {domain_name}"
        message = f"The {scan_type} scan on {domain_name} has been {status}."

    details = {
        "Domain": domain_name,
        "Scan Type": scan_type,
        "Scan ID": scan_id,
        "Status": status,
        "Total Items": total_items,
        "Issues Found": issues_found,
    }

    return service.send_notification(channels, config, subject, message, details)


def send_alert_notification(
    rule_name: str,
    condition_type: str,
    domain_name: str,
    findings_count: int,
    channels: List[str],
    config: Dict[str, Any],
    sample_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, bool]:
    """Send notification when an alert rule is triggered.

    Args:
        rule_name: Name of the alert rule
        condition_type: Type of condition that triggered
        domain_name: Domain where findings were detected
        findings_count: Number of findings that matched
        channels: Notification channels
        config: Channel configuration
        sample_findings: Sample of findings (optional)

    Returns:
        Dict mapping channel to success status
    """
    service = NotificationService()

    subject = f"Alert: {rule_name}"
    message = f"{findings_count} finding(s) matched the alert rule '{rule_name}' on {domain_name}."

    details = {
        "Alert Rule": rule_name,
        "Condition Type": condition_type,
        "Domain": domain_name,
        "Matching Findings": findings_count,
    }

    if sample_findings:
        details["Sample Findings"] = ", ".join(
            str(f.get("name") or f.get("title") or f.get("email", "Unknown"))
            for f in sample_findings[:5]
        )

    return service.send_notification(channels, config, subject, message, details)
