"""
Structured Logging Configuration for Vaulytica

This module provides structured JSON logging that's compatible with
log aggregation systems like ELK Stack, Grafana Loki, Datadog, and Splunk.
"""

import json
import logging
import sys
import traceback
from datetime import datetime
from typing import Any, Optional
from contextvars import ContextVar
from uuid import uuid4

# Context variables for request tracing
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
user_id_var: ContextVar[Optional[int]] = ContextVar("user_id", default=None)
domain_id_var: ContextVar[Optional[int]] = ContextVar("domain_id", default=None)


def get_request_id() -> Optional[str]:
    """Get current request ID."""
    return request_id_var.get()


def set_request_id(request_id: Optional[str] = None) -> str:
    """Set request ID, generating one if not provided."""
    if request_id is None:
        request_id = str(uuid4())
    request_id_var.set(request_id)
    return request_id


def set_user_context(user_id: Optional[int] = None, domain_id: Optional[int] = None):
    """Set user context for logging."""
    if user_id is not None:
        user_id_var.set(user_id)
    if domain_id is not None:
        domain_id_var.set(domain_id)


def clear_context():
    """Clear all context variables."""
    request_id_var.set(None)
    user_id_var.set(None)
    domain_id_var.set(None)


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Output format is compatible with common log aggregation systems:
    - ELK Stack (Elasticsearch, Logstash, Kibana)
    - Grafana Loki
    - Datadog
    - Splunk
    - AWS CloudWatch
    """

    def __init__(
        self,
        service_name: str = "vaulytica",
        environment: str = "development",
        include_extra_fields: bool = True,
    ):
        super().__init__()
        self.service_name = service_name
        self.environment = environment
        self.include_extra_fields = include_extra_fields

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service_name,
            "environment": self.environment,
        }

        # Add source location
        log_entry["source"] = {
            "file": record.pathname,
            "line": record.lineno,
            "function": record.funcName,
            "module": record.module,
        }

        # Add context from context vars
        request_id = get_request_id()
        if request_id:
            log_entry["request_id"] = request_id

        user_id = user_id_var.get()
        if user_id:
            log_entry["user_id"] = user_id

        domain_id = domain_id_var.get()
        if domain_id:
            log_entry["domain_id"] = domain_id

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "stacktrace": traceback.format_exception(*record.exc_info),
            }

        # Add extra fields from record
        if self.include_extra_fields:
            extra_fields = {}
            for key, value in record.__dict__.items():
                if key not in [
                    "name", "msg", "args", "created", "filename", "funcName",
                    "levelname", "levelno", "lineno", "module", "msecs",
                    "pathname", "process", "processName", "relativeCreated",
                    "stack_info", "exc_info", "exc_text", "thread", "threadName",
                    "message", "taskName",
                ]:
                    extra_fields[key] = self._serialize_value(value)

            if extra_fields:
                log_entry["extra"] = extra_fields

        return json.dumps(log_entry, default=str)

    def _serialize_value(self, value: Any) -> Any:
        """Serialize a value for JSON output."""
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        if isinstance(value, (list, tuple)):
            return [self._serialize_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}
        return str(value)


class RequestContextFilter(logging.Filter):
    """Filter that adds request context to log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Add request context to the log record."""
        record.request_id = get_request_id()
        record.user_id = user_id_var.get()
        record.domain_id = domain_id_var.get()
        return True


def setup_logging(
    log_level: str = "INFO",
    service_name: str = "vaulytica",
    environment: str = "development",
    json_output: bool = True,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """
    Configure structured logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        service_name: Name of the service for log identification
        environment: Environment name (development, staging, production)
        json_output: If True, output logs as JSON; otherwise use standard format
        log_file: Optional file path to also write logs to

    Returns:
        Configured root logger
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Remove existing handlers
    root_logger.handlers = []

    # Create handler for stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))

    if json_output:
        formatter = JSONFormatter(
            service_name=service_name,
            environment=environment,
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    console_handler.setFormatter(formatter)
    console_handler.addFilter(RequestContextFilter())
    root_logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level.upper()))
        file_handler.setFormatter(formatter)
        file_handler.addFilter(RequestContextFilter())
        root_logger.addHandler(file_handler)

    # Configure specific loggers
    # Reduce verbosity of third-party loggers
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger
    """
    return logging.getLogger(name)


# Convenience functions for structured logging with extra fields
class StructuredLogger:
    """
    A wrapper around the standard logger that makes it easy to add
    structured fields to log messages.

    Example:
        logger = StructuredLogger(__name__)
        logger.info("User logged in", user_email="test@example.com", ip="192.168.1.1")
    """

    def __init__(self, name: str):
        self._logger = logging.getLogger(name)

    def _log(self, level: int, message: str, **kwargs):
        """Log a message with extra fields."""
        self._logger.log(level, message, extra=kwargs)

    def debug(self, message: str, **kwargs):
        """Log debug message with optional structured fields."""
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message with optional structured fields."""
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with optional structured fields."""
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log error message with optional structured fields."""
        self._logger.error(message, exc_info=exc_info, extra=kwargs)

    def critical(self, message: str, exc_info: bool = False, **kwargs):
        """Log critical message with optional structured fields."""
        self._logger.critical(message, exc_info=exc_info, extra=kwargs)

    def exception(self, message: str, **kwargs):
        """Log exception with traceback."""
        self._logger.exception(message, extra=kwargs)


# Pre-defined loggers for common use cases
class LogEvent:
    """Predefined log event types for consistent logging."""

    # Authentication events
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILED = "auth.login.failed"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_REFRESH = "auth.token.refresh"
    AUTH_PASSWORD_RESET = "auth.password.reset"

    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    SCAN_PROGRESS = "scan.progress"

    # Finding events
    FINDING_CREATED = "finding.created"
    FINDING_STATUS_CHANGED = "finding.status.changed"
    FINDING_EXPORTED = "finding.exported"

    # Domain events
    DOMAIN_CREATED = "domain.created"
    DOMAIN_UPDATED = "domain.updated"
    DOMAIN_DELETED = "domain.deleted"
    DOMAIN_CREDENTIALS_ROTATED = "domain.credentials.rotated"

    # User events
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ACTIVATED = "user.activated"
    USER_DEACTIVATED = "user.deactivated"

    # Alert events
    ALERT_TRIGGERED = "alert.triggered"
    ALERT_NOTIFICATION_SENT = "alert.notification.sent"
    ALERT_NOTIFICATION_FAILED = "alert.notification.failed"

    # Compliance events
    COMPLIANCE_REPORT_GENERATED = "compliance.report.generated"
    COMPLIANCE_REPORT_EXPORTED = "compliance.report.exported"

    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    RATE_LIMIT_EXCEEDED = "system.rate_limit.exceeded"


def log_event(
    event_type: str,
    message: str,
    level: str = "INFO",
    **kwargs,
):
    """
    Log a structured event with consistent formatting.

    Args:
        event_type: Type of event (use LogEvent constants)
        message: Human-readable message
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        **kwargs: Additional structured fields

    Example:
        log_event(
            LogEvent.AUTH_LOGIN_SUCCESS,
            "User logged in successfully",
            user_email="test@example.com",
            ip_address="192.168.1.1",
        )
    """
    logger = logging.getLogger("vaulytica.events")
    log_level = getattr(logging, level.upper())
    logger.log(log_level, message, extra={"event_type": event_type, **kwargs})
