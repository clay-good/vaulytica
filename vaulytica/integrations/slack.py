"""Slack integration for alerts and notifications."""

from typing import Optional, Dict, Any
from datetime import datetime

import structlog
import requests

from vaulytica.core.reporters.base import ScanReport

logger = structlog.get_logger(__name__)


class SlackError(Exception):
    """Raised when Slack operations fail."""

    pass


class SlackAlerter:
    """Send alerts to Slack via webhook."""

    def __init__(
        self,
        webhook_url: str,
        channel: Optional[str] = None,
        username: str = "Vaulytica",
        icon_emoji: str = ":shield:",
    ):
        """Initialize Slack alerter.

        Args:
            webhook_url: Slack webhook URL
            channel: Optional channel override (e.g., "#security")
            username: Bot username
            icon_emoji: Bot icon emoji
        """
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji

        logger.info("slack_alerter_initialized", channel=channel)

    def send_alert(
        self,
        report: ScanReport,
        threshold: str = "medium",
    ) -> None:
        """Send scan report alert to Slack.

        Args:
            report: ScanReport to send
            threshold: Alert threshold (low, medium, high)

        Raises:
            SlackError: If sending fails
        """
        logger.info(
            "sending_slack_alert",
            scan_id=report.scan_id,
            threshold=threshold,
        )

        # Check if alert should be sent
        if not self._should_send_alert(report, threshold):
            logger.info("alert_threshold_not_met", threshold=threshold)
            return

        # Build message
        message = self._build_message(report)

        # Send to Slack
        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            if response.status_code != 200:
                raise SlackError(
                    f"Slack API returned {response.status_code}: {response.text}"
                )

            logger.info("slack_alert_sent", scan_id=report.scan_id)

        except requests.exceptions.RequestException as e:
            logger.error("slack_alert_failed", error=str(e))
            raise SlackError(f"Failed to send Slack alert: {e}")

    def send_test_message(self) -> None:
        """Send a test message to Slack.

        Raises:
            SlackError: If sending fails
        """
        message = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": "🧪 Vaulytica Test Alert",
            "attachments": [
                {
                    "color": "good",
                    "text": "This is a test message from Vaulytica. Your Slack integration is working correctly!",
                    "footer": "Vaulytica",
                    "ts": int(datetime.now().timestamp()),
                }
            ],
        }

        if self.channel:
            message["channel"] = self.channel

        try:
            response = requests.post(
                self.webhook_url,
                json=message,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

            if response.status_code != 200:
                raise SlackError(
                    f"Slack API returned {response.status_code}: {response.text}"
                )

            logger.info("slack_test_message_sent")

        except requests.exceptions.RequestException as e:
            logger.error("slack_test_failed", error=str(e))
            raise SlackError(f"Failed to send test message: {e}")

    def _should_send_alert(self, report: ScanReport, threshold: str) -> bool:
        """Check if alert should be sent based on threshold.

        Args:
            report: ScanReport
            threshold: Alert threshold

        Returns:
            True if alert should be sent
        """
        summary = report.summary

        if threshold == "high":
            return summary.get("high_risk_files", 0) > 0
        elif threshold == "medium":
            return (
                summary.get("high_risk_files", 0) > 0
                or summary.get("medium_risk_files", 0) > 0
            )
        else:  # low
            return report.files_with_issues > 0

    def _build_message(self, report: ScanReport) -> Dict[str, Any]:
        """Build Slack message from report.

        Args:
            report: ScanReport

        Returns:
            Slack message dict
        """
        summary = report.summary

        # Determine severity
        high_risk = summary.get("high_risk_files", 0)
        medium_risk = summary.get("medium_risk_files", 0)

        if high_risk > 0:
            color = "danger"
            severity = "🔴 HIGH RISK"
        elif medium_risk > 0:
            color = "warning"
            severity = "🟡 MEDIUM RISK"
        else:
            color = "good"
            severity = "🟢 LOW RISK"

        # Build main text
        text = f"{severity} - Vaulytica Security Scan"

        # Build attachment fields
        fields = [
            {
                "title": "Scan ID",
                "value": report.scan_id,
                "short": True,
            },
            {
                "title": "Domain",
                "value": report.domain,
                "short": True,
            },
            {
                "title": "Files Scanned",
                "value": str(summary.get("total_files", 0)),
                "short": True,
            },
            {
                "title": "Files with Issues",
                "value": str(report.files_with_issues),
                "short": True,
            },
        ]

        # Add risk breakdown
        if high_risk > 0:
            fields.append({
                "title": "🔴 High Risk Files",
                "value": str(high_risk),
                "short": True,
            })

        if medium_risk > 0:
            fields.append({
                "title": "🟡 Medium Risk Files",
                "value": str(medium_risk),
                "short": True,
            })

        # Add sharing stats
        if summary.get("public_files", 0) > 0:
            fields.append({
                "title": "🌐 Publicly Shared",
                "value": str(summary.get("public_files", 0)),
                "short": True,
            })

        if summary.get("externally_shared_files", 0) > 0:
            fields.append({
                "title": "🔗 Externally Shared",
                "value": str(summary.get("externally_shared_files", 0)),
                "short": True,
            })

        # Add PII stats
        if summary.get("files_with_pii", 0) > 0:
            fields.append({
                "title": "🔐 Files with PII",
                "value": str(summary.get("files_with_pii", 0)),
                "short": True,
            })

        # Build top files section
        top_files_text = ""
        if report.files:
            # Sort by risk score
            sorted_files = sorted(report.files, key=lambda f: f.risk_score, reverse=True)
            top_files = sorted_files[:5]

            top_files_text = "\n*Top Risk Files:*\n"
            for file_info in top_files:
                risk_emoji = "🔴" if file_info.risk_score >= 75 else "🟡" if file_info.risk_score >= 50 else "🟢"
                top_files_text += f"{risk_emoji} `{file_info.name[:40]}` (Risk: {file_info.risk_score})\n"

        # Build message
        message = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "text": text,
            "attachments": [
                {
                    "color": color,
                    "fields": fields,
                    "text": top_files_text,
                    "footer": "Vaulytica",
                    "ts": int(report.scan_time.timestamp()),
                }
            ],
        }

        if self.channel:
            message["channel"] = self.channel

        return message


def create_slack_alerter_from_config(config: Dict[str, Any]) -> Optional[SlackAlerter]:
    """Create SlackAlerter from configuration.

    Args:
        config: Configuration dict

    Returns:
        SlackAlerter instance or None if not configured
    """
    slack_config = config.get("alerts", {}).get("slack", {})

    if not slack_config.get("enabled", False):
        return None

    webhook_url = slack_config.get("webhook_url")
    if not webhook_url:
        logger.warning("slack_enabled_but_no_webhook_url")
        return None

    return SlackAlerter(
        webhook_url=webhook_url,
        channel=slack_config.get("channel"),
        username=slack_config.get("username", "Vaulytica"),
        icon_emoji=slack_config.get("icon_emoji", ":shield:"),
    )

