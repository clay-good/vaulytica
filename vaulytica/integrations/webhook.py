"""Webhook integration for SIEM systems."""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable
from enum import Enum

import requests
import structlog

logger = structlog.get_logger(__name__)


class WebhookFormat(Enum):
    """Webhook payload formats."""

    JSON = "json"
    SPLUNK_HEC = "splunk_hec"
    DATADOG = "datadog"
    ELASTIC = "elastic"
    GENERIC = "generic"
    CUSTOM = "custom"


class WebhookAuthType(Enum):
    """Webhook authentication types."""

    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    HMAC_SHA256 = "hmac_sha256"
    OAUTH2 = "oauth2"


@dataclass
class WebhookAuth:
    """Webhook authentication configuration."""

    auth_type: WebhookAuthType = WebhookAuthType.NONE
    api_key: Optional[str] = None
    api_key_header: str = "X-API-Key"
    bearer_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    hmac_secret: Optional[str] = None
    hmac_header: str = "X-Signature"
    oauth2_token_url: Optional[str] = None
    oauth2_client_id: Optional[str] = None
    oauth2_client_secret: Optional[str] = None


@dataclass
class WebhookRetryConfig:
    """Webhook retry configuration."""

    max_retries: int = 3
    initial_delay: float = 1.0  # seconds
    max_delay: float = 60.0  # seconds
    exponential_base: float = 2.0
    jitter: bool = True


@dataclass
class WebhookConfig:
    """Webhook configuration."""

    url: str
    format: WebhookFormat = WebhookFormat.JSON
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30
    retry_count: int = 3  # Deprecated, use retry_config
    retry_delay: int = 5  # Deprecated, use retry_config
    verify_ssl: bool = True
    auth: Optional[WebhookAuth] = None
    retry_config: Optional[WebhookRetryConfig] = None
    custom_template: Optional[str] = None  # Jinja2 template for custom format
    custom_template_func: Optional[Callable] = None  # Custom template function

    def __post_init__(self):
        """Initialize defaults."""
        if not self.headers:
            self.headers = {"Content-Type": "application/json"}

        if self.auth is None:
            self.auth = WebhookAuth()

        if self.retry_config is None:
            # Use legacy retry settings if provided
            self.retry_config = WebhookRetryConfig(
                max_retries=self.retry_count,
                initial_delay=float(self.retry_delay),
            )


class WebhookError(Exception):
    """Raised when webhook delivery fails."""

    pass


class WebhookSender:
    """Send events to SIEM systems via webhooks with retry logic and authentication."""

    def __init__(self, config: WebhookConfig):
        """Initialize webhook sender.

        Args:
            config: Webhook configuration
        """
        self.config = config
        self._oauth2_token: Optional[str] = None
        self._oauth2_token_expiry: Optional[float] = None

        # Handle both string and enum format
        format_value = config.format.value if isinstance(config.format, WebhookConfig) else config.format

        logger.info(
            "webhook_sender_initialized",
            url=config.url,
            format=format_value,
            auth_type=config.auth.auth_type.value if config.auth else "none",
        )

    def send_event(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str = "info",
    ) -> bool:
        """Send an event to the webhook with exponential backoff retry.

        Args:
            event_type: Type of event (e.g., "file_shared", "user_offboarded")
            event_data: Event data dictionary
            severity: Event severity (info, warning, error, critical)

        Returns:
            True if successful

        Raises:
            WebhookError: If delivery fails after retries
        """
        # Build payload based on format
        payload = self._build_payload(event_type, event_data, severity)

        # Prepare headers with authentication
        headers = self._prepare_headers(payload)

        # Send with exponential backoff retry
        retry_config = self.config.retry_config

        for attempt in range(retry_config.max_retries + 1):
            try:
                # Prepare request kwargs
                request_kwargs = {
                    "url": self.config.url,
                    "json": payload,
                    "headers": headers,
                    "timeout": self.config.timeout,
                    "verify": self.config.verify_ssl,
                }

                # Add basic auth if configured
                if self.config.auth.auth_type == WebhookAuthType.BASIC_AUTH:
                    request_kwargs["auth"] = (
                        self.config.auth.username,
                        self.config.auth.password,
                    )

                response = requests.post(**request_kwargs)

                response.raise_for_status()

                logger.info(
                    "webhook_sent",
                    event_type=event_type,
                    status_code=response.status_code,
                    attempt=attempt + 1,
                    response_time=response.elapsed.total_seconds(),
                )

                return True

            except requests.exceptions.RequestException as e:
                is_last_attempt = attempt >= retry_config.max_retries

                logger.warning(
                    "webhook_send_failed",
                    event_type=event_type,
                    attempt=attempt + 1,
                    max_retries=retry_config.max_retries + 1,
                    error=str(e),
                    will_retry=not is_last_attempt,
                )

                if is_last_attempt:
                    raise WebhookError(
                        f"Failed to send webhook after {retry_config.max_retries + 1} attempts: {e}"
                    )

                # Calculate delay with exponential backoff
                delay = self._calculate_retry_delay(attempt, retry_config)

                logger.debug(
                    "webhook_retry_delay",
                    attempt=attempt + 1,
                    delay=f"{delay:.2f}s",
                )

                time.sleep(delay)

        return False

    def send_batch(
        self,
        events: List[Dict[str, Any]],
    ) -> int:
        """Send multiple events in batch.

        Args:
            events: List of event dictionaries with 'type', 'data', and 'severity'

        Returns:
            Number of successfully sent events
        """
        success_count = 0

        for event in events:
            try:
                self.send_event(
                    event_type=event.get("type", "unknown"),
                    event_data=event.get("data", {}),
                    severity=event.get("severity", "info"),
                )
                success_count += 1
            except WebhookError as e:
                logger.error("batch_event_failed", error=str(e))

        logger.info(
            "batch_send_complete",
            total=len(events),
            success=success_count,
            failed=len(events) - success_count,
        )

        return success_count

    def _build_payload(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str,
    ) -> Dict[str, Any]:
        """Build webhook payload based on format.

        Args:
            event_type: Event type
            event_data: Event data
            severity: Event severity

        Returns:
            Formatted payload dictionary
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        if self.config.format == WebhookFormat.SPLUNK_HEC:
            return self._build_splunk_payload(event_type, event_data, severity, timestamp)
        elif self.config.format == WebhookFormat.DATADOG:
            return self._build_datadog_payload(event_type, event_data, severity, timestamp)
        elif self.config.format == WebhookFormat.ELASTIC:
            return self._build_elastic_payload(event_type, event_data, severity, timestamp)
        elif self.config.format == WebhookFormat.CUSTOM:
            return self._build_custom_payload(event_type, event_data, severity, timestamp)
        else:
            return self._build_generic_payload(event_type, event_data, severity, timestamp)

    def _build_generic_payload(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str,
        timestamp: str,
    ) -> Dict[str, Any]:
        """Build generic JSON payload.

        Args:
            event_type: Event type
            event_data: Event data
            severity: Event severity
            timestamp: ISO timestamp

        Returns:
            Generic payload
        """
        return {
            "timestamp": timestamp,
            "source": "vaulytica",
            "event_type": event_type,
            "severity": severity,
            "data": event_data,
        }

    def _build_splunk_payload(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str,
        timestamp: str,
    ) -> Dict[str, Any]:
        """Build Splunk HEC payload.

        Args:
            event_type: Event type
            event_data: Event data
            severity: Event severity
            timestamp: ISO timestamp

        Returns:
            Splunk HEC formatted payload
        """
        return {
            "time": int(datetime.now(timezone.utc).timestamp()),
            "host": "vaulytica",
            "source": "vaulytica",
            "sourcetype": f"vaulytica:{event_type}",
            "event": {
                "event_type": event_type,
                "severity": severity,
                "timestamp": timestamp,
                **event_data,
            },
        }

    def _build_datadog_payload(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str,
        timestamp: str,
    ) -> Dict[str, Any]:
        """Build Datadog payload.

        Args:
            event_type: Event type
            event_data: Event data
            severity: Event severity
            timestamp: ISO timestamp

        Returns:
            Datadog formatted payload
        """
        # Map severity to Datadog alert type
        alert_type_map = {
            "critical": "error",
            "error": "error",
            "warning": "warning",
            "info": "info",
        }

        return {
            "title": f"Vaulytica: {event_type}",
            "text": json.dumps(event_data, indent=2),
            "alert_type": alert_type_map.get(severity, "info"),
            "source_type_name": "vaulytica",
            "tags": [
                f"event_type:{event_type}",
                f"severity:{severity}",
                "source:vaulytica",
            ],
            "date_happened": int(datetime.now(timezone.utc).timestamp()),
        }

    def _build_elastic_payload(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str,
        timestamp: str,
    ) -> Dict[str, Any]:
        """Build Elasticsearch payload.

        Args:
            event_type: Event type
            event_data: Event data
            severity: Event severity
            timestamp: ISO timestamp

        Returns:
            Elasticsearch formatted payload
        """
        return {
            "@timestamp": timestamp,
            "event": {
                "kind": "alert",
                "category": ["security"],
                "type": [event_type],
                "severity": self._severity_to_number(severity),
            },
            "observer": {
                "name": "vaulytica",
                "type": "security_scanner",
            },
            "message": f"Vaulytica event: {event_type}",
            "vaulytica": event_data,
        }

    @staticmethod
    def _severity_to_number(severity: str) -> int:
        """Convert severity string to number.

        Args:
            severity: Severity string

        Returns:
            Severity number (0-4)
        """
        severity_map = {
            "critical": 4,
            "error": 3,
            "warning": 2,
            "info": 1,
            "debug": 0,
        }

        return severity_map.get(severity.lower(), 1)

    def _prepare_headers(self, payload: Dict[str, Any]) -> Dict[str, str]:
        """Prepare headers with authentication.

        Args:
            payload: Request payload

        Returns:
            Headers dictionary
        """
        headers = self.config.headers.copy()

        auth = self.config.auth

        if auth.auth_type == WebhookAuthType.API_KEY:
            headers[auth.api_key_header] = auth.api_key

        elif auth.auth_type == WebhookAuthType.BEARER_TOKEN:
            headers["Authorization"] = f"Bearer {auth.bearer_token}"

        elif auth.auth_type == WebhookAuthType.HMAC_SHA256:
            # Generate HMAC signature
            payload_str = json.dumps(payload, sort_keys=True)
            signature = hmac.new(
                auth.hmac_secret.encode(),
                payload_str.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers[auth.hmac_header] = signature

        elif auth.auth_type == WebhookAuthType.OAUTH2:
            # Get OAuth2 token (with caching)
            token = self._get_oauth2_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"

        return headers

    def _get_oauth2_token(self) -> Optional[str]:
        """Get OAuth2 access token (with caching).

        Returns:
            Access token or None
        """
        auth = self.config.auth

        # Check if cached token is still valid
        if self._oauth2_token and self._oauth2_token_expiry:
            if time.time() < self._oauth2_token_expiry:
                return self._oauth2_token

        # Request new token
        try:
            response = requests.post(
                auth.oauth2_token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": auth.oauth2_client_id,
                    "client_secret": auth.oauth2_client_secret,
                },
                timeout=30,
            )

            response.raise_for_status()
            data = response.json()

            self._oauth2_token = data.get("access_token")
            expires_in = data.get("expires_in", 3600)
            self._oauth2_token_expiry = time.time() + expires_in - 60  # 1 min buffer

            logger.info("oauth2_token_obtained", expires_in=expires_in)

            return self._oauth2_token

        except Exception as e:
            logger.error("oauth2_token_failed", error=str(e))
            return None

    def _calculate_retry_delay(
        self,
        attempt: int,
        retry_config: WebhookRetryConfig,
    ) -> float:
        """Calculate retry delay with exponential backoff.

        Args:
            attempt: Current attempt number (0-based)
            retry_config: Retry configuration

        Returns:
            Delay in seconds
        """
        import random

        # Calculate exponential backoff
        delay = retry_config.initial_delay * (retry_config.exponential_base ** attempt)

        # Cap at max delay
        delay = min(delay, retry_config.max_delay)

        # Add jitter to prevent thundering herd
        if retry_config.jitter:
            delay = delay * (0.5 + random.random() * 0.5)

        return delay

    def _build_custom_payload(
        self,
        event_type: str,
        event_data: Dict[str, Any],
        severity: str,
        timestamp: str,
    ) -> Dict[str, Any]:
        """Build custom payload using template.

        Args:
            event_type: Event type
            event_data: Event data
            severity: Event severity
            timestamp: ISO timestamp

        Returns:
            Custom payload
        """
        context = {
            "event_type": event_type,
            "event_data": event_data,
            "severity": severity,
            "timestamp": timestamp,
            "source": "vaulytica",
        }

        # Use custom template function if provided
        if self.config.custom_template_func:
            return self.config.custom_template_func(context)

        # Use Jinja2 template if provided
        if self.config.custom_template:
            try:
                from jinja2 import Template

                template = Template(self.config.custom_template)
                rendered = template.render(context)
                return json.loads(rendered)

            except Exception as e:
                logger.error("custom_template_failed", error=str(e))
                # Fall back to generic format
                return self._build_generic_payload(event_type, event_data, severity, timestamp)

        # Default to generic format
        return self._build_generic_payload(event_type, event_data, severity, timestamp)

    def test_connection(self) -> bool:
        """Test webhook connection.

        Returns:
            True if connection successful
        """
        try:
            test_event = {
                "message": "Vaulytica webhook test",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self.send_event(
                event_type="test",
                event_data=test_event,
                severity="info",
            )

            logger.info("webhook_test_successful")
            return True

        except WebhookError as e:
            logger.error("webhook_test_failed", error=str(e))
            return False

