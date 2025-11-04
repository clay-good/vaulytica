"""Workflow for detecting and alerting on externally shared files with PII."""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

import structlog
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.scanners.file_scanner import FileScanner, FileInfo
from vaulytica.core.detectors.pii_detector import PIIDetector, PIIDetectionResult
from vaulytica.core.utils.concurrent import ConcurrentProcessor
from vaulytica.integrations.email import EmailAlerter
from vaulytica.integrations.webhook import WebhookSender, WebhookConfig

logger = structlog.get_logger(__name__)


@dataclass
class ExternalPIIAlertConfig:
    """Configuration for external PII alert workflow."""

    domain: str
    min_risk_score: int = 50  # Minimum risk score to alert on
    max_file_size_mb: int = 10  # Max file size to download for content scanning
    scan_file_content: bool = True  # Whether to download and scan file content
    alert_email: Optional[List[str]] = None
    alert_webhook: Optional[str] = None
    webhook_format: str = "json"  # json, splunk, datadog, elasticsearch
    dry_run: bool = False


@dataclass
class FileWithPII:
    """Represents a file with PII detected."""

    file_info: FileInfo
    pii_result: PIIDetectionResult
    content_scanned: bool = False


@dataclass
class ExternalPIIAlertResult:
    """Results from external PII alert workflow."""

    total_files_scanned: int = 0
    external_files_found: int = 0
    files_with_pii: int = 0
    alerts_sent: int = 0
    findings: List[FileWithPII] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def duration_seconds(self) -> float:
        """Calculate duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


class ExternalPIIAlertWorkflow:
    """Automated workflow for detecting externally shared files with PII."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        config: ExternalPIIAlertConfig,
    ):
        """Initialize workflow.

        Args:
            client: GoogleWorkspaceClient instance
            config: Workflow configuration
        """
        self.client = client
        self.config = config

        # Initialize components
        self.file_scanner = FileScanner(client, config.domain)
        self.pii_detector = PIIDetector()

        # Initialize alerting
        self.email_alerter = None
        self.webhook_sender = None

        # Note: Email alerter initialization requires SMTP config from main config
        # This will be set via set_email_alerter() method if email alerts are configured

        if config.alert_webhook:
            webhook_config = WebhookConfig(
                url=config.alert_webhook,
                format=config.webhook_format,
            )
            self.webhook_sender = WebhookSender(webhook_config)

        logger.info(
            "external_pii_workflow_initialized",
            domain=config.domain,
            dry_run=config.dry_run,
        )

    def set_email_alerter(self, email_alerter) -> None:
        """Set the email alerter for sending email alerts.

        Args:
            email_alerter: EmailAlerter instance
        """
        self.email_alerter = email_alerter

    def run(self, show_progress: bool = True) -> ExternalPIIAlertResult:
        """Run the workflow.

        Args:
            show_progress: Whether to show progress bars

        Returns:
            ExternalPIIAlertResult
        """
        result = ExternalPIIAlertResult()
        result.start_time = datetime.now(timezone.utc)

        logger.info("external_pii_workflow_started", domain=self.config.domain)

        try:
            if show_progress:
                self._run_with_progress(result)
            else:
                self._run_without_progress(result)

        except Exception as e:
            logger.error("workflow_failed", error=str(e))
            result.errors.append(f"Workflow failed: {e}")

        result.end_time = datetime.now(timezone.utc)

        logger.info(
            "external_pii_workflow_completed",
            duration=result.duration_seconds(),
            files_scanned=result.total_files_scanned,
            files_with_pii=result.files_with_pii,
            alerts_sent=result.alerts_sent,
        )

        return result

    def _run_with_progress(self, result: ExternalPIIAlertResult) -> None:
        """Run workflow with progress bars."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        ) as progress:
            # Step 1: Scan for externally shared files
            scan_task = progress.add_task("Scanning for external files...", total=None)

            external_files = list(
                self.file_scanner.scan_all_files(external_only=True)
            )

            result.total_files_scanned = len(external_files)
            result.external_files_found = len(external_files)

            progress.update(
                scan_task,
                description=f"[green]✓[/green] Found {len(external_files)} external files",
                completed=True,
            )

            if not external_files:
                return

            # Step 2: Scan files for PII
            pii_task = progress.add_task(
                "Scanning for PII...",
                total=len(external_files),
            )

            for file_info in external_files:
                finding = self._scan_file_for_pii(file_info)

                if finding and finding.pii_result.total_matches > 0:
                    # Check risk score threshold
                    if file_info.risk_score >= self.config.min_risk_score:
                        result.findings.append(finding)
                        result.files_with_pii += 1

                progress.advance(pii_task)

            progress.update(
                pii_task,
                description=f"[green]✓[/green] Found {result.files_with_pii} files with PII",
            )

            # Step 3: Send alerts
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
                        logger.error("alert_failed", file_id=finding.file_info.id, error=str(e))
                        result.errors.append(f"Alert failed for {finding.file_info.name}: {e}")

                    progress.advance(alert_task)

                progress.update(
                    alert_task,
                    description=f"[green]✓[/green] Sent {result.alerts_sent} alerts",
                )

    def _run_without_progress(self, result: ExternalPIIAlertResult) -> None:
        """Run workflow without progress bars."""
        # Step 1: Scan for externally shared files
        external_files = list(self.file_scanner.scan_all_files(external_only=True))
        result.total_files_scanned = len(external_files)
        result.external_files_found = len(external_files)

        # Step 2: Scan files for PII
        for file_info in external_files:
            finding = self._scan_file_for_pii(file_info)

            if finding and finding.pii_result.total_matches > 0:
                if file_info.risk_score >= self.config.min_risk_score:
                    result.findings.append(finding)
                    result.files_with_pii += 1

        # Step 3: Send alerts
        if result.findings and not self.config.dry_run:
            for finding in result.findings:
                try:
                    self._send_alert(finding)
                    result.alerts_sent += 1
                except Exception as e:
                    logger.error("alert_failed", file_id=finding.file_info.id, error=str(e))
                    result.errors.append(f"Alert failed for {finding.file_info.name}: {e}")

    def _scan_file_for_pii(self, file_info: FileInfo) -> Optional[FileWithPII]:
        """Scan a file for PII.

        Args:
            file_info: File information

        Returns:
            FileWithPII if PII detected, None otherwise
        """
        if not self.config.scan_file_content:
            # Just return file info without content scanning
            return FileWithPII(
                file_info=file_info,
                pii_result=PIIDetectionResult(),
                content_scanned=False,
            )

        try:
            # Download and scan file content
            content = self._download_file_content(file_info)

            if content:
                pii_result = self.pii_detector.detect(content)

                return FileWithPII(
                    file_info=file_info,
                    pii_result=pii_result,
                    content_scanned=True,
                )

        except Exception as e:
            logger.error(
                "file_scan_failed",
                file_id=file_info.id,
                file_name=file_info.name,
                error=str(e),
            )

        return None

    def _download_file_content(self, file_info: FileInfo) -> Optional[str]:
        """Download file content for scanning.

        Args:
            file_info: File information

        Returns:
            File content as string, or None if download fails
        """
        # Check file size
        if file_info.size and file_info.size > self.config.max_file_size_mb * 1024 * 1024:
            logger.debug("file_too_large", file_id=file_info.id, size=file_info.size)
            return None

        try:
            # For Google Docs, Sheets, etc., export as text
            if file_info.mime_type.startswith("application/vnd.google-apps"):
                return self._export_google_doc(file_info)
            else:
                # For other files, download binary content
                # This is a simplified version - would need proper text extraction
                return None

        except Exception as e:
            logger.error("download_failed", file_id=file_info.id, error=str(e))
            return None

    def _export_google_doc(self, file_info: FileInfo) -> Optional[str]:
        """Export Google Doc/Sheet/Slide as text.

        Args:
            file_info: File information

        Returns:
            Exported text content
        """
        try:
            # Determine export MIME type
            export_mime_type = "text/plain"

            if "spreadsheet" in file_info.mime_type:
                export_mime_type = "text/csv"
            elif "presentation" in file_info.mime_type:
                export_mime_type = "text/plain"

            # Export file
            request = self.client.drive.files().export_media(
                fileId=file_info.id,
                mimeType=export_mime_type,
            )

            content = request.execute()

            if isinstance(content, bytes):
                return content.decode("utf-8", errors="ignore")
            else:
                return str(content)

        except Exception as e:
            logger.error("export_failed", file_id=file_info.id, error=str(e))
            return None

    def _send_alert(self, finding: FileWithPII) -> None:
        """Send alert for a finding.

        Args:
            finding: FileWithPII object
        """
        # Build alert data
        alert_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": "external_file_with_pii",
            "severity": "high" if finding.file_info.risk_score >= 75 else "medium",
            "file": {
                "id": finding.file_info.id,
                "name": finding.file_info.name,
                "owner": finding.file_info.owner_email,
                "url": finding.file_info.web_view_link,
                "risk_score": finding.file_info.risk_score,
                "is_public": finding.file_info.is_public,
                "external_domains": finding.file_info.external_domains,
                "external_emails": finding.file_info.external_emails,
            },
            "pii": {
                "types_found": [t.value for t in finding.pii_result.pii_types_found],
                "total_matches": finding.pii_result.total_matches,
                "high_confidence_matches": finding.pii_result.high_confidence_matches,
            },
        }

        # Send to webhook (SIEM)
        if self.webhook_sender:
            try:
                self.webhook_sender.send_event(
                    event_type="external_file_with_pii",
                    event_data=alert_data,
                    severity=alert_data["severity"],
                )
                logger.info("webhook_alert_sent", file_id=finding.file_info.id)
            except Exception as e:
                logger.error("webhook_alert_failed", error=str(e))
                raise

        # Send email alert if configured
        if self.email_alerter and self.config.alert_email:
            try:
                # Create a simple text email body for PII alerts
                subject = f"[Vaulytica] PII Detected in External File: {finding.file_info.name}"

                body = f"""
                <html>
                <body>
                    <h2>PII Detected in Externally Shared File</h2>

                    <h3>File Details</h3>
                    <ul>
                        <li><strong>File Name:</strong> {finding.file_info.name}</li>
                        <li><strong>Owner:</strong> {finding.file_info.owner_email}</li>
                        <li><strong>Risk Score:</strong> {finding.file_info.risk_score}</li>
                        <li><strong>Public:</strong> {"Yes" if finding.file_info.is_public else "No"}</li>
                        <li><strong>View Link:</strong> <a href="{finding.file_info.web_view_link}">{finding.file_info.web_view_link}</a></li>
                    </ul>

                    <h3>PII Found</h3>
                    <ul>
                        <li><strong>PII Types:</strong> {", ".join([t.value for t in finding.pii_result.pii_types_found])}</li>
                        <li><strong>Total Matches:</strong> {finding.pii_result.total_matches}</li>
                        <li><strong>High Confidence Matches:</strong> {finding.pii_result.high_confidence_matches}</li>
                    </ul>

                    <h3>External Sharing</h3>
                    <ul>
                        <li><strong>External Domains:</strong> {", ".join(finding.file_info.external_domains) if finding.file_info.external_domains else "N/A"}</li>
                        <li><strong>External Emails:</strong> {", ".join(finding.file_info.external_emails) if finding.file_info.external_emails else "N/A"}</li>
                    </ul>

                    <p style="margin-top: 30px; color: #666;">
                        This is an automated alert from Vaulytica.<br>
                        Please review this file and take appropriate action.
                    </p>
                </body>
                </html>
                """

                # Send email using a simple SMTP approach
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                msg = MIMEMultipart()
                msg["From"] = self.email_alerter.from_address
                msg["To"] = ", ".join(self.config.alert_email)
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "html"))

                if self.email_alerter.use_ssl:
                    server = smtplib.SMTP_SSL(self.email_alerter.smtp_host, self.email_alerter.smtp_port)
                else:
                    server = smtplib.SMTP(self.email_alerter.smtp_host, self.email_alerter.smtp_port)

                if self.email_alerter.use_tls and not self.email_alerter.use_ssl:
                    server.starttls()

                server.login(self.email_alerter.smtp_user, self.email_alerter.smtp_password)
                server.send_message(msg)
                server.quit()

                logger.info("email_alert_sent", file_id=finding.file_info.id, recipients=self.config.alert_email)
            except Exception as e:
                logger.error("email_alert_failed", error=str(e), file_id=finding.file_info.id)

