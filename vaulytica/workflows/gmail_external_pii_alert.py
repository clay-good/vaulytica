"""Workflow for detecting and alerting on Gmail attachments with PII sent externally."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

import structlog
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.scanners.gmail_scanner import GmailScanner, AttachmentScanResult
from vaulytica.integrations.webhook import WebhookSender, WebhookConfig

logger = structlog.get_logger(__name__)


@dataclass
class GmailExternalPIIAlertConfig:
    """Configuration for Gmail external PII alert workflow."""

    domain: str
    users: Optional[List[str]] = None  # Specific users to scan, or None for all
    days_back: int = 7  # How far back to scan
    max_messages_per_user: int = 100
    min_risk_score: int = 50  # Minimum risk score to alert on
    alert_email: Optional[List[str]] = None
    alert_webhook: Optional[str] = None
    webhook_format: str = "json"
    dry_run: bool = False


@dataclass
class GmailExternalPIIAlertResult:
    """Results from Gmail external PII alert workflow."""

    total_users_scanned: int = 0
    total_messages_scanned: int = 0
    total_attachments_scanned: int = 0
    external_attachments_found: int = 0
    attachments_with_pii: int = 0
    alerts_sent: int = 0
    findings: List[AttachmentScanResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def duration_seconds(self) -> float:
        """Calculate duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class GmailExternalPIIAlertWorkflow:
    """Automated workflow for detecting Gmail attachments with PII sent externally."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        config: GmailExternalPIIAlertConfig,
    ):
        """Initialize workflow.

        Args:
            client: GoogleWorkspaceClient instance
            config: Workflow configuration
        """
        self.client = client
        self.config = config

        # Initialize components
        self.gmail_scanner = GmailScanner(client, config.domain)

        # Initialize alerting
        self.webhook_sender = None

        if config.alert_webhook:
            webhook_config = WebhookConfig(
                url=config.alert_webhook,
                format=config.webhook_format,
            )
            self.webhook_sender = WebhookSender(webhook_config)

        logger.info(
            "gmail_external_pii_workflow_initialized",
            domain=config.domain,
            dry_run=config.dry_run,
        )

    def run(self, show_progress: bool = True) -> GmailExternalPIIAlertResult:
        """Run the workflow.

        Args:
            show_progress: Whether to show progress bars

        Returns:
            GmailExternalPIIAlertResult
        """
        result = GmailExternalPIIAlertResult()
        result.start_time = datetime.now(timezone.utc)

        logger.info("gmail_external_pii_workflow_started", domain=self.config.domain)

        try:
            # Get list of users to scan
            users_to_scan = self._get_users_to_scan()

            if show_progress:
                self._run_with_progress(result, users_to_scan)
            else:
                self._run_without_progress(result, users_to_scan)

        except Exception as e:
            logger.error("workflow_failed", error=str(e))
            result.errors.append(f"Workflow failed: {e}")

        result.end_time = datetime.now(timezone.utc)

        logger.info(
            "gmail_external_pii_workflow_completed",
            duration=result.duration_seconds(),
            users_scanned=result.total_users_scanned,
            attachments_with_pii=result.attachments_with_pii,
            alerts_sent=result.alerts_sent,
        )

        return result

    def _get_users_to_scan(self) -> List[str]:
        """Get list of users to scan.

        Returns:
            List of user email addresses
        """
        if self.config.users:
            return self.config.users

        # If no specific users, get all users from domain
        try:
            users = []
            page_token = None

            while True:
                response = (
                    self.client.admin.users()
                    .list(
                        domain=self.config.domain,
                        maxResults=500,
                        pageToken=page_token,
                    )
                    .execute()
                )

                for user in response.get("users", []):
                    if not user.get("suspended", False):
                        users.append(user["primaryEmail"])

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

            return users

        except Exception as e:
            logger.error("failed_to_list_users", error=str(e))
            return []

    def _run_with_progress(
        self, result: GmailExternalPIIAlertResult, users: List[str]
    ) -> None:
        """Run workflow with progress bars."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            # Scan users
            user_task = progress.add_task(
                f"Scanning {len(users)} users...",
                total=len(users),
            )

            for user_email in users:
                try:
                    # Scan user's Gmail attachments (external only)
                    scan_result = self.gmail_scanner.scan_user_attachments(
                        user_email=user_email,
                        days_back=self.config.days_back,
                        max_messages=self.config.max_messages_per_user,
                        external_only=True,  # Only scan external emails
                    )

                    result.total_users_scanned += 1
                    result.total_messages_scanned += scan_result.total_messages
                    result.total_attachments_scanned += scan_result.attachments_scanned

                    # Process findings
                    for attachment_result in scan_result.results:
                        if attachment_result.attachment.is_sent_externally:
                            result.external_attachments_found += 1

                        if (
                            attachment_result.pii_result
                            and attachment_result.pii_result.has_pii
                        ):
                            if attachment_result.risk_score >= self.config.min_risk_score:
                                result.findings.append(attachment_result)
                                result.attachments_with_pii += 1

                except Exception as e:
                    logger.error("user_scan_failed", user_email=user_email, error=str(e))
                    result.errors.append(f"Failed to scan {user_email}: {e}")

                progress.advance(user_task)

            progress.update(
                user_task,
                description=f"[green]✓[/green] Scanned {result.total_users_scanned} users",
            )

            # Send alerts
            if result.findings and not self.config.dry_run:
                alert_task = progress.add_task(
                    "Sending alerts...",
                    total=len(result.findings),
                )

                for finding in result.findings:
                    try:
                        self._send_alert(finding)
                        result.alerts_sent += 1
                    except Exception as e:
                        logger.error(
                            "alert_failed",
                            attachment=finding.attachment.filename,
                            error=str(e),
                        )
                        result.errors.append(
                            f"Alert failed for {finding.attachment.filename}: {e}"
                        )

                    progress.advance(alert_task)

                progress.update(
                    alert_task,
                    description=f"[green]✓[/green] Sent {result.alerts_sent} alerts",
                )

    def _run_without_progress(
        self, result: GmailExternalPIIAlertResult, users: List[str]
    ) -> None:
        """Run workflow without progress bars."""
        for user_email in users:
            try:
                scan_result = self.gmail_scanner.scan_user_attachments(
                    user_email=user_email,
                    days_back=self.config.days_back,
                    max_messages=self.config.max_messages_per_user,
                    external_only=True,
                )

                result.total_users_scanned += 1
                result.total_messages_scanned += scan_result.total_messages
                result.total_attachments_scanned += scan_result.attachments_scanned

                for attachment_result in scan_result.results:
                    if attachment_result.attachment.is_sent_externally:
                        result.external_attachments_found += 1

                    if (
                        attachment_result.pii_result
                        and attachment_result.pii_result.has_pii
                    ):
                        if attachment_result.risk_score >= self.config.min_risk_score:
                            result.findings.append(attachment_result)
                            result.attachments_with_pii += 1

            except Exception as e:
                logger.error("user_scan_failed", user_email=user_email, error=str(e))
                result.errors.append(f"Failed to scan {user_email}: {e}")

        # Send alerts
        if result.findings and not self.config.dry_run:
            for finding in result.findings:
                try:
                    self._send_alert(finding)
                    result.alerts_sent += 1
                except Exception as e:
                    logger.error(
                        "alert_failed",
                        attachment=finding.attachment.filename,
                        error=str(e),
                    )
                    result.errors.append(
                        f"Alert failed for {finding.attachment.filename}: {e}"
                    )

    def _send_alert(self, finding: AttachmentScanResult) -> None:
        """Send alert for a finding.

        Args:
            finding: AttachmentScanResult object
        """
        # Build alert data
        alert_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "gmail_external_attachment_with_pii",
            "severity": "high" if finding.risk_score >= 75 else "medium",
            "email": {
                "user": finding.attachment.user_email,
                "subject": finding.attachment.subject,
                "sender": finding.attachment.sender,
                "date": finding.attachment.date.isoformat(),
                "message_id": finding.attachment.message_id,
                "recipients": finding.attachment.recipients,
                "external_recipients": finding.attachment.external_recipients,
            },
            "attachment": {
                "filename": finding.attachment.filename,
                "mime_type": finding.attachment.mime_type,
                "size": finding.attachment.size,
                "attachment_id": finding.attachment.attachment_id,
            },
            "pii": {
                "types_found": [t.value for t in finding.pii_result.pii_types_found]
                if finding.pii_result
                else [],
                "total_matches": finding.pii_result.total_matches
                if finding.pii_result
                else 0,
                "high_confidence_matches": finding.pii_result.high_confidence_matches
                if finding.pii_result
                else 0,
            },
            "risk_score": finding.risk_score,
        }

        # Send to webhook (SIEM)
        if self.webhook_sender:
            try:
                self.webhook_sender.send_event(
                    event_type="gmail_external_attachment_with_pii",
                    event_data=alert_data,
                    severity=alert_data["severity"],
                )
                logger.info(
                    "webhook_alert_sent",
                    user=finding.attachment.user_email,
                    filename=finding.attachment.filename,
                )
            except Exception as e:
                logger.error("webhook_alert_failed", error=str(e))
                raise

