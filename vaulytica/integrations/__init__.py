"""Integration modules for external services (Slack, email, SIEM, etc.)."""

from vaulytica.integrations.email import EmailAlerter, EmailError
from vaulytica.integrations.slack import SlackAlerter, SlackError
from vaulytica.integrations.webhook import (
    WebhookSender,
    WebhookConfig,
    WebhookFormat,
    WebhookError,
    WebhookAuth,
    WebhookAuthType,
    WebhookRetryConfig,
)

__all__ = [
    "EmailAlerter",
    "EmailError",
    "SlackAlerter",
    "SlackError",
    "WebhookSender",
    "WebhookConfig",
    "WebhookFormat",
    "WebhookError",
    "WebhookAuth",
    "WebhookAuthType",
    "WebhookRetryConfig",
]
