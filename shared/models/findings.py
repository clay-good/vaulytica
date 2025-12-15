"""Shared finding model mixins for Vaulytica.

These mixins provide consistent field definitions for findings across
CLI and web backends. The mixins use standardized field names.

Field naming conventions (normalized between CLI and web):
- is_2fa_enrolled / two_factor_enabled -> two_factor_enabled
- is_externally_shared / is_shared_externally -> is_externally_shared
- is_inactive (both use this)
- risk_score (both use this)
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.orm import declared_attr


class ScanRunMixin:
    """Mixin for scan run fields - shared between CLI and web.

    CLI: scan_runs table with files/users/devices relationships
    Web: scan_runs table with domain relationships and progress tracking
    """

    @declared_attr
    def scan_type(cls) -> Column:
        return Column(String(50), nullable=False, index=True)

    @declared_attr
    def start_time(cls) -> Column:
        return Column(DateTime, nullable=False, default=datetime.utcnow)

    @declared_attr
    def end_time(cls) -> Column:
        return Column(DateTime, nullable=True)

    @declared_attr
    def status(cls) -> Column:
        return Column(String(20), nullable=False, default="running")

    @declared_attr
    def total_items(cls) -> Column:
        return Column(Integer, default=0)

    @declared_attr
    def issues_found(cls) -> Column:
        return Column(Integer, default=0)

    @declared_attr
    def config(cls) -> Column:
        return Column(JSON, nullable=True)

    @declared_attr
    def error_message(cls) -> Column:
        return Column(Text, nullable=True)


class BaseFindingMixin:
    """Base mixin for all finding types - provides common fields."""

    @declared_attr
    def severity(cls) -> Column:
        return Column(String(20), nullable=False, index=True)

    @declared_attr
    def risk_score(cls) -> Column:
        return Column(Integer, default=0, index=True)

    @declared_attr
    def risk_factors(cls) -> Column:
        return Column(JSON, nullable=True)

    @declared_attr
    def detected_at(cls) -> Column:
        return Column(DateTime, default=datetime.utcnow, index=True)


class FileRecordMixin(BaseFindingMixin):
    """Mixin for file-related findings.

    Unified field names:
    - is_externally_shared (CLI) / is_shared_externally (Web) -> is_externally_shared
    """

    @declared_attr
    def file_id(cls) -> Column:
        return Column(String(255), nullable=False, index=True)

    @declared_attr
    def file_name(cls) -> Column:
        return Column(String(500), nullable=False)

    @declared_attr
    def owner_email(cls) -> Column:
        return Column(String(255), index=True)

    @declared_attr
    def mime_type(cls) -> Column:
        return Column(String(255), nullable=True)

    @declared_attr
    def file_size(cls) -> Column:
        """File size in bytes. Named 'size_bytes' in CLI, 'file_size' in web."""
        return Column(Integer, nullable=True)

    @declared_attr
    def is_externally_shared(cls) -> Column:
        """Whether the file is shared outside the organization."""
        return Column(Boolean, default=False, index=True)

    @declared_attr
    def is_public(cls) -> Column:
        """Whether the file is publicly accessible."""
        return Column(Boolean, default=False, index=True)

    @declared_attr
    def pii_detected(cls) -> Column:
        """Whether PII was detected in the file."""
        return Column(Boolean, default=False, index=True)

    @declared_attr
    def pii_types(cls) -> Column:
        """List of PII types detected."""
        return Column(JSON, nullable=True)


class UserRecordMixin(BaseFindingMixin):
    """Mixin for user-related findings.

    Unified field names:
    - is_2fa_enrolled (CLI) / two_factor_enabled (Web) -> two_factor_enabled
    - inactive_days (CLI) / days_since_last_login (Web) -> days_inactive
    """

    @declared_attr
    def user_email(cls) -> Column:
        """User's email address. Named 'user_email' in CLI, 'email' in web."""
        return Column(String(255), nullable=False, index=True)

    @declared_attr
    def full_name(cls) -> Column:
        return Column(String(255), nullable=True)

    @declared_attr
    def is_admin(cls) -> Column:
        return Column(Boolean, default=False)

    @declared_attr
    def is_suspended(cls) -> Column:
        return Column(Boolean, default=False, index=True)

    @declared_attr
    def two_factor_enabled(cls) -> Column:
        """Whether 2FA/MFA is enabled for the user."""
        return Column(Boolean, default=False, index=True)

    @declared_attr
    def last_login_time(cls) -> Column:
        return Column(DateTime, index=True, nullable=True)

    @declared_attr
    def creation_time(cls) -> Column:
        return Column(DateTime, nullable=True)

    @declared_attr
    def org_unit_path(cls) -> Column:
        return Column(String(500), nullable=True)

    @declared_attr
    def is_inactive(cls) -> Column:
        return Column(Boolean, default=False, index=True)

    @declared_attr
    def days_inactive(cls) -> Column:
        """Number of days since last login. Standardized name."""
        return Column(Integer, default=0)


class OAuthRecordMixin(BaseFindingMixin):
    """Mixin for OAuth/third-party app findings."""

    @declared_attr
    def client_id(cls) -> Column:
        return Column(String(255), nullable=False, index=True)

    @declared_attr
    def display_text(cls) -> Column:
        """Display name of the OAuth application."""
        return Column(String(500), nullable=True)

    @declared_attr
    def scopes(cls) -> Column:
        """List of OAuth scopes requested by the app."""
        return Column(JSON, nullable=True)

    @declared_attr
    def user_count(cls) -> Column:
        """Number of users who have authorized this app."""
        return Column(Integer, default=0)

    @declared_attr
    def users(cls) -> Column:
        """List of user emails who have authorized this app."""
        return Column(JSON, nullable=True)

    @declared_attr
    def is_verified(cls) -> Column:
        """Whether the app is verified by Google."""
        return Column(Boolean, default=False)

    @declared_attr
    def is_google_app(cls) -> Column:
        """Whether this is a first-party Google app."""
        return Column(Boolean, default=False)

    @declared_attr
    def is_internal(cls) -> Column:
        """Whether this is an internal/organization app."""
        return Column(Boolean, default=False)


class SecurityPostureMixin(BaseFindingMixin):
    """Mixin for security posture findings."""

    @declared_attr
    def check_id(cls) -> Column:
        """Unique identifier for the security check."""
        return Column(String(50), nullable=False, index=True)

    @declared_attr
    def title(cls) -> Column:
        return Column(String(255), nullable=False)

    @declared_attr
    def description(cls) -> Column:
        return Column(Text, nullable=True)

    @declared_attr
    def passed(cls) -> Column:
        """Whether the check passed."""
        return Column(Boolean, nullable=False, index=True)

    @declared_attr
    def current_value(cls) -> Column:
        """Current observed value."""
        return Column(Text, nullable=True)

    @declared_attr
    def expected_value(cls) -> Column:
        """Expected/compliant value."""
        return Column(Text, nullable=True)

    @declared_attr
    def impact(cls) -> Column:
        """Business impact description."""
        return Column(Text, nullable=True)

    @declared_attr
    def remediation(cls) -> Column:
        """How to remediate this finding."""
        return Column(Text, nullable=True)

    @declared_attr
    def frameworks(cls) -> Column:
        """Compliance frameworks this check maps to."""
        return Column(JSON, nullable=True)


class AuditLogMixin:
    """Mixin for audit log entries."""

    @declared_attr
    def timestamp(cls) -> Column:
        return Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    @declared_attr
    def action(cls) -> Column:
        return Column(String(100), nullable=False, index=True)

    @declared_attr
    def resource_type(cls) -> Column:
        return Column(String(100), nullable=True)

    @declared_attr
    def resource_id(cls) -> Column:
        return Column(String(255), nullable=True)

    @declared_attr
    def status(cls) -> Column:
        return Column(String(20), nullable=True)

    @declared_attr
    def details(cls) -> Column:
        return Column(JSON, nullable=True)

    @declared_attr
    def ip_address(cls) -> Column:
        return Column(String(45), nullable=True)


class ComplianceReportMixin:
    """Mixin for compliance report fields."""

    @declared_attr
    def framework(cls) -> Column:
        return Column(String(50), nullable=False, index=True)

    @declared_attr
    def compliance_score(cls) -> Column:
        """Compliance score as percentage (0-100)."""
        return Column(Float, nullable=True)

    @declared_attr
    def total_checks(cls) -> Column:
        return Column(Integer, default=0)

    @declared_attr
    def passed_checks(cls) -> Column:
        return Column(Integer, default=0)

    @declared_attr
    def failed_checks(cls) -> Column:
        return Column(Integer, default=0)

    @declared_attr
    def report_data(cls) -> Column:
        """Full report data as JSON."""
        return Column(JSON, nullable=True)
