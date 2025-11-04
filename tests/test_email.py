"""Tests for email alerting."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock

from vaulytica.integrations.email import EmailAlerter, EmailError
from vaulytica.core.reporters.base import ScanReport
from vaulytica.core.scanners.file_scanner import FileInfo


@pytest.fixture
def email_alerter():
    """Create an EmailAlerter instance for testing."""
    return EmailAlerter(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="test@example.com",
        smtp_password="password",
        from_address="alerts@example.com",
        use_tls=True,
    )


@pytest.fixture
def sample_report():
    """Create a sample scan report."""
    file1 = FileInfo(
        id="file1",
        name="high_risk.pdf",
        mime_type="application/pdf",
        owner_email="owner@example.com",
        owner_name="Owner",
        created_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
        is_public=True,
        risk_score=90,
    )

    file2 = FileInfo(
        id="file2",
        name="medium_risk.docx",
        mime_type="application/vnd.google-apps.document",
        owner_email="owner@example.com",
        owner_name="Owner",
        created_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
        is_shared_externally=True,
        risk_score=60,
    )

    report = ScanReport(
        scan_id="test123",
        scan_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        domain="example.com",
        files_scanned=100,
        files_with_issues=2,
        files=[file1, file2],
    )

    report.calculate_summary()
    return report


class TestEmailAlerter:
    """Tests for EmailAlerter."""

    def test_init(self, email_alerter):
        """Test EmailAlerter initialization."""
        assert email_alerter.smtp_host == "smtp.example.com"
        assert email_alerter.smtp_port == 587
        assert email_alerter.smtp_user == "test@example.com"
        assert email_alerter.from_address == "alerts@example.com"
        assert email_alerter.use_tls is True

    def test_should_send_alert_high_threshold(self, email_alerter, sample_report):
        """Test alert threshold check for high risk."""
        # Report has high risk files
        assert email_alerter._should_send_alert(sample_report, "high") is True

    def test_should_send_alert_medium_threshold(self, email_alerter, sample_report):
        """Test alert threshold check for medium risk."""
        # Report has medium risk files
        assert email_alerter._should_send_alert(sample_report, "medium") is True

    def test_should_send_alert_low_threshold(self, email_alerter, sample_report):
        """Test alert threshold check for low risk."""
        # Report has any issues
        assert email_alerter._should_send_alert(sample_report, "low") is True

    def test_should_not_send_alert_high_threshold(self, email_alerter):
        """Test alert not sent when no high risk files."""
        report = ScanReport(
            scan_id="test123",
            scan_time=datetime.now(timezone.utc),
            domain="example.com",
            files_scanned=100,
            files_with_issues=0,
            files=[],
        )
        report.calculate_summary()

        assert email_alerter._should_send_alert(report, "high") is False

    def test_create_subject_high_risk(self, email_alerter, sample_report):
        """Test subject creation for high risk report."""
        subject = email_alerter._create_subject(sample_report)

        assert "HIGH RISK" in subject
        assert "2 Files" in subject

    def test_create_body(self, email_alerter, sample_report):
        """Test HTML body creation."""
        body = email_alerter._create_body(sample_report)

        assert "Vaulytica Security Scan Report" in body
        assert "test123" in body  # Scan ID
        assert "example.com" in body  # Domain
        assert "high_risk.pdf" in body  # File name
        assert "owner@example.com" in body  # Owner email

    @patch("vaulytica.integrations.email.smtplib.SMTP")
    def test_send_alert_success(self, mock_smtp, email_alerter, sample_report):
        """Test successful email sending."""
        mock_server = Mock()
        mock_smtp.return_value = mock_server

        recipients = ["security@example.com"]
        email_alerter.send_alert(recipients, sample_report)

        # Verify SMTP calls
        mock_smtp.assert_called_once_with("smtp.example.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("test@example.com", "password")
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch("vaulytica.integrations.email.smtplib.SMTP")
    def test_send_alert_failure(self, mock_smtp, email_alerter, sample_report):
        """Test email sending failure."""
        mock_server = Mock()
        mock_server.login.side_effect = Exception("Authentication failed")
        mock_smtp.return_value = mock_server

        recipients = ["security@example.com"]

        with pytest.raises(EmailError, match="Failed to send email"):
            email_alerter.send_alert(recipients, sample_report)

    @patch("vaulytica.integrations.email.smtplib.SMTP")
    def test_send_test_email(self, mock_smtp, email_alerter):
        """Test sending test email."""
        mock_server = Mock()
        mock_smtp.return_value = mock_server

        recipients = ["test@example.com"]
        email_alerter.send_test_email(recipients)

        # Verify SMTP calls
        mock_smtp.assert_called_once()
        mock_server.send_message.assert_called_once()

    @patch("vaulytica.integrations.email.smtplib.SMTP_SSL")
    def test_send_with_ssl(self, mock_smtp_ssl):
        """Test sending email with SSL."""
        alerter = EmailAlerter(
            smtp_host="smtp.example.com",
            smtp_port=465,
            smtp_user="test@example.com",
            smtp_password="password",
            from_address="alerts@example.com",
            use_ssl=True,
        )

        mock_server = Mock()
        mock_smtp_ssl.return_value.__enter__.return_value = mock_server

        recipients = ["test@example.com"]
        alerter.send_test_email(recipients)

        # Should not call starttls with SSL
        mock_server.starttls.assert_not_called()

    def test_threshold_not_met(self, email_alerter):
        """Test that alert is not sent when threshold not met."""
        # Create report with only low risk files
        file1 = FileInfo(
            id="file1",
            name="low_risk.pdf",
            mime_type="application/pdf",
            owner_email="owner@example.com",
            owner_name="Owner",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            risk_score=20,
        )

        report = ScanReport(
            scan_id="test123",
            scan_time=datetime.now(timezone.utc),
            domain="example.com",
            files_scanned=100,
            files_with_issues=1,
            files=[file1],
        )
        report.calculate_summary()

        # Should not send alert with high threshold
        with patch("vaulytica.integrations.email.smtplib.SMTP") as mock_smtp:
            email_alerter.send_alert(["test@example.com"], report, threshold="high")
            # SMTP should not be called
            mock_smtp.assert_not_called()

