"""
Notification integrations for Vaulytica.

Supports sending analysis results to various notification channels:
- Slack
- Microsoft Teams
- Email (SMTP)
"""

import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any
from datetime import datetime

import httpx
from pydantic import BaseModel, Field

from vaulytica.models import AnalysisResult

logger = logging.getLogger(__name__)


class NotificationConfig(BaseModel):
    """Configuration for notification channels."""

    # Slack
    slack_webhook_url: Optional[str] = Field(None, description="Slack webhook URL")
    slack_channel: Optional[str] = Field(None, description="Slack channel override")
    slack_username: Optional[str] = Field("Vaulytica", description="Slack bot username")

    # Microsoft Teams
    teams_webhook_url: Optional[str] = Field(None, description="Teams webhook URL")

    # Email
    smtp_host: Optional[str] = Field(None, description="SMTP server host")
    smtp_port: int = Field(587, description="SMTP server port")
    smtp_username: Optional[str] = Field(None, description="SMTP username")
    smtp_password: Optional[str] = Field(None, description="SMTP password")
    smtp_from: Optional[str] = Field(None, description="From email address")
    smtp_to: Optional[str] = Field(None, description="To email address(es), comma-separated")
    smtp_use_tls: bool = Field(True, description="Use TLS for SMTP")

    # Notification settings
    min_risk_score: int = Field(5, description="Minimum risk score to trigger notification")
    notify_on_cache_hit: bool = Field(False, description="Send notifications for cached results")


class NotificationManager:
    """Manages sending notifications to various channels."""

    def __init__(self, config: NotificationConfig):
        """Initialize notification manager."""
        self.config = config
        self.http_client = httpx.AsyncClient(timeout=30.0)

    async def send_notification(
        self,
        result: AnalysisResult,
        event_source: str,
        cached: bool = False
    ) -> Dict[str, bool]:
        """
        Send notification to all configured channels.

        Args:
            result: Analysis result
            event_source: Source platform (guardduty, datadog, etc.)
            cached: Whether result was from cache

        Returns:
            Dictionary of channel -> success status
        """
        # Check if notification should be sent
        if cached and not self.config.notify_on_cache_hit:
            logger.debug("Skipping notification for cached result")
            return {}

        if result.risk_score < self.config.min_risk_score:
            logger.debug(f"Risk score {result.risk_score} below threshold {self.config.min_risk_score}")
            return {}

        results = {}

        # Send to Slack
        if self.config.slack_webhook_url:
            try:
                success = await self._send_slack(result, event_source, cached)
                results['slack'] = success
            except Exception as e:
                logger.error(f"Failed to send Slack notification: {e}")
                results['slack'] = False

        # Send to Teams
        if self.config.teams_webhook_url:
            try:
                success = await self._send_teams(result, event_source, cached)
                results['teams'] = success
            except Exception as e:
                logger.error(f"Failed to send Teams notification: {e}")
                results['teams'] = False

        # Send email
        if self.config.smtp_host and self.config.smtp_to:
            try:
                success = self._send_email(result, event_source, cached)
                results['email'] = success
            except Exception as e:
                logger.error(f"Failed to send email notification: {e}")
                results['email'] = False

        return results

    async def _send_slack(
        self,
        result: AnalysisResult,
        event_source: str,
        cached: bool
    ) -> bool:
        """Send notification to Slack."""
        # Determine color based on risk score
        if result.risk_score >= 8:
            color = "#d32f2"  # Red
            emoji = "🚨"
        elif result.risk_score >= 6:
            color = "#f57c00"  # Orange
            emoji = "⚠️"
        else:
            color = "#fbc02d"  # Yellow
            emoji = "ℹ️"

        # Build Slack message
        payload = {
            "username": self.config.slack_username,
            "attachments": [
                {
                    "color": color,
                    "title": f"{emoji} Security Event Analysis",
                    "fields": [
                        {
                            "title": "Event ID",
                            "value": result.event_id,
                            "short": True
                        },
                        {
                            "title": "Source",
                            "value": event_source.upper(),
                            "short": True
                        },
                        {
                            "title": "Risk Score",
                            "value": f"{result.risk_score}/10",
                            "short": True
                        },
                        {
                            "title": "Confidence",
                            "value": f"{result.confidence * 100:.0f}%",
                            "short": True
                        },
                        {
                            "title": "Summary",
                            "value": result.summary,
                            "short": False
                        },
                        {
                            "title": "MITRE ATT&CK",
                            "value": ", ".join(result.mitre_attack_techniques[:3]) if result.mitre_attack_techniques else "None",
                            "short": False
                        }
                    ],
                    "footer": "Vaulytica Security Analysis",
                    "ts": int(datetime.utcnow().timestamp())
                }
            ]
        }

        # Add channel override if specified
        if self.config.slack_channel:
            payload["channel"] = self.config.slack_channel

        # Add cached indicator
        if cached:
            payload["attachments"][0]["fields"].append({
                "title": "Cache",
                "value": "✓ Cached result",
                "short": True
            })

        # Send to Slack
        response = await self.http_client.post(
            self.config.slack_webhook_url,
            json=payload
        )

        if response.status_code == 200:
            logger.info(f"Slack notification sent for event {result.event_id}")
            return True
        else:
            logger.error(f"Slack notification failed: {response.status_code} - {response.text}")
            return False

    async def _send_teams(
        self,
        result: AnalysisResult,
        event_source: str,
        cached: bool
    ) -> bool:
        """Send notification to Microsoft Teams."""
        # Determine theme color based on risk score
        if result.risk_score >= 8:
            theme_color = "d32f2"  # Red
        elif result.risk_score >= 6:
            theme_color = "f57c00"  # Orange
        else:
            theme_color = "fbc02d"  # Yellow

        # Build Teams message card
        payload = {
            "@type": "MessageCard",
            "@context": "https://example.com",
            "summary": f"Security Event Analysis - Risk {result.risk_score}/10",
            "themeColor": theme_color,
            "title": "🔒 Security Event Analysis",
            "sections": [
                {
                    "activityTitle": f"Event: {result.event_id}",
                    "activitySubtitle": f"Source: {event_source.upper()}",
                    "facts": [
                        {"name": "Risk Score", "value": f"{result.risk_score}/10"},
                        {"name": "Confidence", "value": f"{result.confidence * 100:.0f}%"},
                        {"name": "MITRE ATT&CK", "value": ", ".join(result.mitre_attack_techniques[:3]) if result.mitre_attack_techniques else "None"},
                        {"name": "Cached", "value": "Yes" if cached else "No"}
                    ],
                    "text": result.summary
                }
            ]
        }

        # Send to Teams
        response = await self.http_client.post(
            self.config.teams_webhook_url,
            json=payload
        )

        if response.status_code == 200:
            logger.info(f"Teams notification sent for event {result.event_id}")
            return True
        else:
            logger.error(f"Teams notification failed: {response.status_code} - {response.text}")
            return False

    def _send_email(
        self,
        result: AnalysisResult,
        event_source: str,
        cached: bool
    ) -> bool:
        """Send notification via email."""
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[Vaulytica] Security Alert - Risk {result.risk_score}/10"
        msg['From'] = self.config.smtp_from
        msg['To'] = self.config.smtp_to

        # Create plain text version
        text_body = """
Security Event Analysis

Event ID: {result.event_id}
Source: {event_source.upper()}
Risk Score: {result.risk_score}/10
Confidence: {result.confidence * 100:.0f}%
Cached: {'Yes' if cached else 'No'}

Summary:
{result.summary}

MITRE ATT&CK Techniques:
{chr(10).join('- ' + t for t in result.mitre_attack_techniques[:5]) if result.mitre_attack_techniques else 'None'}

Immediate Actions:
{chr(10).join('- ' + a for a in result.immediate_actions[:3])}

---
Generated by Vaulytica Security Analysis Framework
"""

        msg.attach(MIMEText(text_body, 'plain'))

        # Send email
        try:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                if self.config.smtp_use_tls:
                    server.starttls()
                if self.config.smtp_username and self.config.smtp_password:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                server.send_message(msg)

            logger.info(f"Email notification sent for event {result.event_id}")
            return True
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()
