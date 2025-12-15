"""Tests for email service."""

import pytest
from unittest.mock import patch, MagicMock
import smtplib

from backend.core.email import EmailService, send_password_reset_email, send_password_reset_confirmation_email


class TestEmailService:
    """Test EmailService class."""

    def test_is_configured_false_when_no_smtp_host(self):
        """Test that service reports not configured without SMTP host."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = None
            mock_settings.return_value.smtp_user = "user"
            mock_settings.return_value.smtp_password = "pass"

            service = EmailService()
            assert not service.is_configured

    def test_is_configured_false_when_no_smtp_user(self):
        """Test that service reports not configured without SMTP user."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = "smtp.example.com"
            mock_settings.return_value.smtp_user = None
            mock_settings.return_value.smtp_password = "pass"

            service = EmailService()
            assert not service.is_configured

    def test_is_configured_false_when_no_smtp_password(self):
        """Test that service reports not configured without SMTP password."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = "smtp.example.com"
            mock_settings.return_value.smtp_user = "user"
            mock_settings.return_value.smtp_password = None

            service = EmailService()
            assert not service.is_configured

    def test_is_configured_true_when_all_settings_present(self):
        """Test that service reports configured when all settings present."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = "smtp.example.com"
            mock_settings.return_value.smtp_user = "user"
            mock_settings.return_value.smtp_password = "pass"

            service = EmailService()
            assert service.is_configured

    def test_send_email_returns_false_when_not_configured(self):
        """Test that send_email returns False when not configured."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = None
            mock_settings.return_value.smtp_user = None
            mock_settings.return_value.smtp_password = None

            service = EmailService()
            result = service.send_email(
                to_email="test@example.com",
                subject="Test",
                html_content="<p>Test</p>",
            )
            assert result is False

    @patch("backend.core.email.smtplib.SMTP")
    def test_send_email_success_with_tls(self, mock_smtp_class):
        """Test successful email sending with TLS."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = "smtp.example.com"
            mock_settings.return_value.smtp_port = 587
            mock_settings.return_value.smtp_user = "user"
            mock_settings.return_value.smtp_password = "pass"
            mock_settings.return_value.smtp_from_email = "noreply@example.com"
            mock_settings.return_value.smtp_from_name = "Test"
            mock_settings.return_value.smtp_use_tls = True
            mock_settings.return_value.smtp_use_ssl = False

            mock_smtp = MagicMock()
            mock_smtp_class.return_value = mock_smtp

            service = EmailService()
            result = service.send_email(
                to_email="test@example.com",
                subject="Test Subject",
                html_content="<p>Test HTML</p>",
                text_content="Test Text",
            )

            assert result is True
            mock_smtp.starttls.assert_called_once()
            mock_smtp.login.assert_called_once_with("user", "pass")
            mock_smtp.sendmail.assert_called_once()
            mock_smtp.quit.assert_called_once()

    @patch("backend.core.email.smtplib.SMTP_SSL")
    def test_send_email_success_with_ssl(self, mock_smtp_ssl_class):
        """Test successful email sending with SSL."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = "smtp.example.com"
            mock_settings.return_value.smtp_port = 465
            mock_settings.return_value.smtp_user = "user"
            mock_settings.return_value.smtp_password = "pass"
            mock_settings.return_value.smtp_from_email = "noreply@example.com"
            mock_settings.return_value.smtp_from_name = "Test"
            mock_settings.return_value.smtp_use_tls = False
            mock_settings.return_value.smtp_use_ssl = True

            mock_smtp = MagicMock()
            mock_smtp_ssl_class.return_value = mock_smtp

            service = EmailService()
            result = service.send_email(
                to_email="test@example.com",
                subject="Test Subject",
                html_content="<p>Test HTML</p>",
            )

            assert result is True
            mock_smtp.login.assert_called_once_with("user", "pass")
            mock_smtp.sendmail.assert_called_once()
            mock_smtp.quit.assert_called_once()

    @patch("backend.core.email.smtplib.SMTP")
    def test_send_email_auth_failure(self, mock_smtp_class):
        """Test email sending with authentication failure."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = "smtp.example.com"
            mock_settings.return_value.smtp_port = 587
            mock_settings.return_value.smtp_user = "user"
            mock_settings.return_value.smtp_password = "wrong"
            mock_settings.return_value.smtp_from_email = "noreply@example.com"
            mock_settings.return_value.smtp_from_name = "Test"
            mock_settings.return_value.smtp_use_tls = True
            mock_settings.return_value.smtp_use_ssl = False

            mock_smtp = MagicMock()
            mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Auth failed")
            mock_smtp_class.return_value = mock_smtp

            service = EmailService()
            result = service.send_email(
                to_email="test@example.com",
                subject="Test",
                html_content="<p>Test</p>",
            )

            assert result is False


class TestPasswordResetEmails:
    """Test password reset email functions."""

    def test_send_password_reset_email_not_configured(self):
        """Test password reset email when SMTP not configured."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = None
            mock_settings.return_value.smtp_user = None
            mock_settings.return_value.smtp_password = None
            mock_settings.return_value.frontend_url = "http://localhost:3000"
            mock_settings.return_value.debug = False

            result = send_password_reset_email("test@example.com", "token123", "Test User")
            assert result is False

    def test_send_password_reset_confirmation_not_configured(self):
        """Test password reset confirmation email when SMTP not configured."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.smtp_host = None
            mock_settings.return_value.smtp_user = None
            mock_settings.return_value.smtp_password = None
            mock_settings.return_value.frontend_url = "http://localhost:3000"

            result = send_password_reset_confirmation_email("test@example.com", "Test User")
            assert result is False

    @patch("backend.core.email.EmailService")
    def test_send_password_reset_email_success(self, mock_service_class):
        """Test successful password reset email."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.frontend_url = "http://localhost:3000"
            mock_settings.return_value.debug = False

            mock_service = MagicMock()
            mock_service.is_configured = True
            mock_service.send_email.return_value = True
            mock_service_class.return_value = mock_service

            result = send_password_reset_email("test@example.com", "token123", "Test User")

            assert result is True
            mock_service.send_email.assert_called_once()
            call_args = mock_service.send_email.call_args
            assert call_args.kwargs["to_email"] == "test@example.com"
            assert call_args.kwargs["subject"] == "Reset Your Vaulytica Password"
            assert "token123" in call_args.kwargs["html_content"]
            assert "Test User" in call_args.kwargs["html_content"]

    @patch("backend.core.email.EmailService")
    def test_send_password_reset_confirmation_success(self, mock_service_class):
        """Test successful password reset confirmation email."""
        with patch("backend.core.email.get_settings") as mock_settings:
            mock_settings.return_value.frontend_url = "http://localhost:3000"

            mock_service = MagicMock()
            mock_service.is_configured = True
            mock_service.send_email.return_value = True
            mock_service_class.return_value = mock_service

            result = send_password_reset_confirmation_email("test@example.com", "Test User")

            assert result is True
            mock_service.send_email.assert_called_once()
            call_args = mock_service.send_email.call_args
            assert call_args.kwargs["to_email"] == "test@example.com"
            assert "Password Has Been Changed" in call_args.kwargs["subject"]
