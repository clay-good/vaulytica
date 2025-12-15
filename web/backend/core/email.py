"""Email service for sending transactional emails."""

import asyncio
import smtplib
import ssl
import logging
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List

from ..config import get_settings

logger = logging.getLogger(__name__)

# Thread pool for async email sending
_email_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="email_")


class EmailService:
    """Service for sending emails via SMTP."""

    def __init__(self):
        """Initialize email service with settings."""
        self.settings = get_settings()
        self._configured = self._check_configuration()

    def _check_configuration(self) -> bool:
        """Check if email is properly configured."""
        return bool(
            self.settings.smtp_host
            and self.settings.smtp_user
            and self.settings.smtp_password
        )

    @property
    def is_configured(self) -> bool:
        """Check if email service is configured."""
        return self._configured

    def _create_smtp_connection(self):
        """Create SMTP connection based on settings."""
        if self.settings.smtp_use_ssl:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(
                self.settings.smtp_host,
                self.settings.smtp_port,
                context=context,
            )
        else:
            server = smtplib.SMTP(
                self.settings.smtp_host,
                self.settings.smtp_port,
            )
            if self.settings.smtp_use_tls:
                context = ssl.create_default_context()
                server.starttls(context=context)

        return server

    def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
    ) -> bool:
        """Send an email.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML body content
            text_content: Plain text fallback (optional)

        Returns:
            True if email was sent successfully, False otherwise
        """
        if not self._configured:
            logger.warning(
                "Email not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD. "
                f"Attempted to send email to {to_email} with subject: {subject}"
            )
            return False

        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{self.settings.smtp_from_name} <{self.settings.smtp_from_email}>"
        message["To"] = to_email

        if text_content:
            message.attach(MIMEText(text_content, "plain"))
        message.attach(MIMEText(html_content, "html"))

        try:
            server = self._create_smtp_connection()
            server.login(self.settings.smtp_user, self.settings.smtp_password)
            server.sendmail(
                self.settings.smtp_from_email,
                to_email,
                message.as_string(),
            )
            server.quit()

            logger.info(f"Email sent to {to_email} with subject: {subject}")
            return True

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Email authentication failed for {to_email}: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"Email send failed for {to_email}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected email error for {to_email}: {e}")
            return False

    async def send_email_async(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
    ) -> bool:
        """Send an email asynchronously.

        Uses a thread pool to avoid blocking the event loop with SMTP operations.

        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML body content
            text_content: Plain text fallback (optional)

        Returns:
            True if email was sent successfully, False otherwise
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _email_executor,
            self.send_email,
            to_email,
            subject,
            html_content,
            text_content,
        )

    async def send_bulk_emails_async(
        self,
        recipients: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
    ) -> dict:
        """Send emails to multiple recipients asynchronously.

        Args:
            recipients: List of recipient email addresses
            subject: Email subject
            html_content: HTML body content
            text_content: Plain text fallback (optional)

        Returns:
            Dict with 'success' and 'failed' lists of email addresses
        """
        if not self._configured:
            logger.warning(
                f"Email not configured. Bulk send to {len(recipients)} recipients skipped."
            )
            return {"success": [], "failed": recipients}

        results = {"success": [], "failed": []}

        # Send all emails concurrently
        tasks = [
            self.send_email_async(email, subject, html_content, text_content)
            for email in recipients
        ]

        outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for email, outcome in zip(recipients, outcomes):
            if isinstance(outcome, Exception):
                logger.error(f"Bulk email failed for {email}: {outcome}")
                results["failed"].append(email)
            elif outcome:
                results["success"].append(email)
            else:
                results["failed"].append(email)

        logger.info(
            f"Bulk email complete: {len(results['success'])} sent, {len(results['failed'])} failed"
        )
        return results


def send_password_reset_email(email: str, token: str, user_name: Optional[str] = None) -> bool:
    """Send password reset email.

    Args:
        email: User's email address
        token: Password reset token
        user_name: User's name (optional)

    Returns:
        True if email was sent, False otherwise
    """
    settings = get_settings()
    service = EmailService()

    reset_url = f"{settings.frontend_url}/reset-password?token={token}"
    greeting = f"Hi {user_name}," if user_name else "Hi,"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 24px;">Vaulytica</h1>
        </div>
        <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
            <h2 style="color: #333; margin-top: 0;">Password Reset Request</h2>
            <p>{greeting}</p>
            <p>We received a request to reset your password for your Vaulytica account. Click the button below to create a new password:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{reset_url}" style="display: inline-block; padding: 14px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
            </div>
            <p style="font-size: 14px; color: #666;">This link will expire in 1 hour for security reasons.</p>
            <p style="font-size: 14px; color: #666;">If you didn't request this password reset, you can safely ignore this email. Your password will remain unchanged.</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
            <p style="font-size: 12px; color: #999;">If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="font-size: 12px; color: #667eea; word-break: break-all;">{reset_url}</p>
        </div>
        <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
            <p>This email was sent by Vaulytica Security Platform</p>
        </div>
    </body>
    </html>
    """

    text_content = f"""
{greeting}

We received a request to reset your password for your Vaulytica account.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour for security reasons.

If you didn't request this password reset, you can safely ignore this email.
Your password will remain unchanged.

---
This email was sent by Vaulytica Security Platform
    """

    # If email is not configured, log the token for development
    if not service.is_configured:
        if settings.debug:
            logger.info(
                f"Password reset token for {email}: {token} "
                f"(reset URL: {reset_url}). "
                "Email not configured - configure SMTP settings for production."
            )
        return False

    return service.send_email(
        to_email=email,
        subject="Reset Your Vaulytica Password",
        html_content=html_content,
        text_content=text_content,
    )


def send_password_reset_confirmation_email(email: str, user_name: Optional[str] = None) -> bool:
    """Send confirmation email after password was reset.

    Args:
        email: User's email address
        user_name: User's name (optional)

    Returns:
        True if email was sent, False otherwise
    """
    settings = get_settings()
    service = EmailService()

    login_url = f"{settings.frontend_url}/login"
    greeting = f"Hi {user_name}," if user_name else "Hi,"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px 10px 0 0;">
            <h1 style="color: white; margin: 0; font-size: 24px;">Vaulytica</h1>
        </div>
        <div style="background: #ffffff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
            <h2 style="color: #333; margin-top: 0;">Password Changed Successfully</h2>
            <p>{greeting}</p>
            <p>Your Vaulytica password has been successfully changed.</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{login_url}" style="display: inline-block; padding: 14px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">Log In Now</a>
            </div>
            <p style="font-size: 14px; color: #666;">If you did not make this change, please contact your administrator immediately.</p>
        </div>
        <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
            <p>This email was sent by Vaulytica Security Platform</p>
        </div>
    </body>
    </html>
    """

    text_content = f"""
{greeting}

Your Vaulytica password has been successfully changed.

You can now log in at: {login_url}

If you did not make this change, please contact your administrator immediately.

---
This email was sent by Vaulytica Security Platform
    """

    if not service.is_configured:
        return False

    return service.send_email(
        to_email=email,
        subject="Your Vaulytica Password Has Been Changed",
        html_content=html_content,
        text_content=text_content,
    )
