"""Email alerting integration."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import List, Optional

import structlog

from vaulytica.core.reporters.base import ScanReport

logger = structlog.get_logger(__name__)


class EmailError(Exception):
    """Raised when email sending fails."""

    pass


class EmailAlerter:
    """Sends email alerts for scan results."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        from_address: str,
        use_tls: bool = True,
        use_ssl: bool = False,
    ):
        """Initialize email alerter.

        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_user: SMTP username
            smtp_password: SMTP password
            from_address: From email address
            use_tls: Use STARTTLS
            use_ssl: Use SSL/TLS
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_address = from_address
        self.use_tls = use_tls
        self.use_ssl = use_ssl

        logger.info(
            "email_alerter_initialized",
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            use_tls=use_tls,
        )

    def send_alert(
        self,
        recipients: List[str],
        report: ScanReport,
        attachments: Optional[List[Path]] = None,
        threshold: str = "medium",
    ) -> None:
        """Send email alert with scan results.

        Args:
            recipients: List of recipient email addresses
            report: ScanReport to send
            attachments: Optional list of file paths to attach
            threshold: Alert threshold (low, medium, high)

        Raises:
            EmailError: If email sending fails
        """
        logger.info(
            "sending_email_alert",
            recipients=recipients,
            scan_id=report.scan_id,
            threshold=threshold,
        )

        # Calculate summary if not already done
        if not report.summary:
            report.calculate_summary()

        # Check if alert should be sent based on threshold
        if not self._should_send_alert(report, threshold):
            logger.info("alert_threshold_not_met", threshold=threshold)
            return

        # Create email message
        msg = MIMEMultipart()
        msg["From"] = self.from_address
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = self._create_subject(report)

        # Create email body
        body = self._create_body(report)
        msg.attach(MIMEText(body, "html"))

        # Attach files if provided
        if attachments:
            for attachment_path in attachments:
                self._attach_file(msg, attachment_path)

        # Send email
        try:
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)

            if self.use_tls and not self.use_ssl:
                server.starttls()

            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()

            logger.info("email_alert_sent", recipients=recipients)

        except Exception as e:
            logger.error("email_send_failed", error=str(e))
            raise EmailError(f"Failed to send email: {e}")

    def send_test_email(self, recipients: List[str]) -> None:
        """Send a test email.

        Args:
            recipients: List of recipient email addresses

        Raises:
            EmailError: If email sending fails
        """
        logger.info("sending_test_email", recipients=recipients)

        msg = MIMEMultipart()
        msg["From"] = self.from_address
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = "Vaulytica Test Email"

        body = """
        <html>
        <body>
            <h2>Vaulytica Test Email</h2>
            <p>This is a test email from Vaulytica.</p>
            <p>If you received this email, your email configuration is working correctly.</p>
        </body>
        </html>
        """

        msg.attach(MIMEText(body, "html"))

        try:
            if self.use_ssl:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port)

            if self.use_tls and not self.use_ssl:
                server.starttls()

            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)
            server.quit()

            logger.info("test_email_sent", recipients=recipients)

        except Exception as e:
            logger.error("test_email_failed", error=str(e))
            raise EmailError(f"Failed to send test email: {e}")

    def _should_send_alert(self, report: ScanReport, threshold: str) -> bool:
        """Check if alert should be sent based on threshold.

        Args:
            report: ScanReport
            threshold: Alert threshold (low, medium, high)

        Returns:
            True if alert should be sent
        """
        summary = report.summary

        if threshold == "high":
            return summary.get("high_risk", 0) > 0
        elif threshold == "medium":
            return summary.get("high_risk", 0) > 0 or summary.get("medium_risk", 0) > 0
        else:  # low
            return report.files_with_issues > 0

    def _create_subject(self, report: ScanReport) -> str:
        """Create email subject line.

        Args:
            report: ScanReport

        Returns:
            Email subject
        """
        summary = report.summary
        high_risk = summary.get("high_risk", 0)
        medium_risk = summary.get("medium_risk", 0)

        if high_risk > 0:
            severity = "🔴 HIGH RISK"
        elif medium_risk > 0:
            severity = "🟡 MEDIUM RISK"
        else:
            severity = "🟢 LOW RISK"

        return f"[Vaulytica] {severity} - {report.files_with_issues} Files with Issues"

    def _create_body(self, report: ScanReport) -> str:
        """Create HTML email body.

        Args:
            report: ScanReport

        Returns:
            HTML email body
        """
        summary = report.summary

        # Sort files by risk score
        top_files = sorted(report.files, key=lambda f: f.risk_score, reverse=True)[:10]

        # Build file table
        file_rows = ""
        for file_info in top_files:
            risk_color = "#dc3545" if file_info.risk_score >= 75 else "#ffc107" if file_info.risk_score >= 50 else "#28a745"
            file_rows += f"""
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd;">{file_info.name}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">{file_info.owner_email}</td>
                <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                    <span style="color: {risk_color}; font-weight: bold;">{file_info.risk_score}</span>
                </td>
                <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                    {"✓" if file_info.is_public else ""}
                </td>
                <td style="padding: 8px; border: 1px solid #ddd; text-align: center;">
                    {"✓" if file_info.is_shared_externally else ""}
                </td>
            </tr>
            """

        body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .metric {{ margin: 10px 0; }}
                .metric-label {{ font-weight: bold; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th {{ background-color: #007bff; color: white; padding: 10px; text-align: left; }}
            </style>
        </head>
        <body>
            <h2>Vaulytica Security Scan Report</h2>

            <div class="summary">
                <h3>Summary</h3>
                <div class="metric">
                    <span class="metric-label">Scan ID:</span> {report.scan_id}
                </div>
                <div class="metric">
                    <span class="metric-label">Scan Time:</span> {report.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")}
                </div>
                <div class="metric">
                    <span class="metric-label">Domain:</span> {report.domain}
                </div>
                <div class="metric">
                    <span class="metric-label">Files Scanned:</span> {report.files_scanned}
                </div>
                <div class="metric">
                    <span class="metric-label">Files with Issues:</span> {report.files_with_issues}
                </div>
                <div class="metric">
                    <span class="metric-label">High Risk Files:</span> <span style="color: #dc3545; font-weight: bold;">{summary.get("high_risk", 0)}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Medium Risk Files:</span> <span style="color: #ffc107; font-weight: bold;">{summary.get("medium_risk", 0)}</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Public Files:</span> {summary.get("public_files", 0)}
                </div>
                <div class="metric">
                    <span class="metric-label">Externally Shared Files:</span> {summary.get("externally_shared", 0)}
                </div>
            </div>

            <h3>Top 10 Highest Risk Files</h3>
            <table>
                <thead>
                    <tr>
                        <th>File Name</th>
                        <th>Owner</th>
                        <th style="text-align: center;">Risk Score</th>
                        <th style="text-align: center;">Public</th>
                        <th style="text-align: center;">External</th>
                    </tr>
                </thead>
                <tbody>
                    {file_rows}
                </tbody>
            </table>

            <p style="margin-top: 30px; color: #666;">
                This is an automated alert from Vaulytica.<br>
                For more details, please review the attached report.
            </p>
        </body>
        </html>
        """

        return body

    def _attach_file(self, msg: MIMEMultipart, file_path: Path) -> None:
        """Attach a file to the email message.

        Args:
            msg: Email message
            file_path: Path to file to attach
        """
        try:
            with open(file_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())

            encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition",
                f"attachment; filename= {file_path.name}",
            )

            msg.attach(part)
            logger.debug("file_attached", filename=file_path.name)

        except Exception as e:
            logger.error("file_attachment_failed", filename=str(file_path), error=str(e))

