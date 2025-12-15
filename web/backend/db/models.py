"""SQLAlchemy database models for Vaulytica web app."""

from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship, DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class Tenant(Base):
    """Tenant for multi-tenant support.

    Each tenant represents an organization using Vaulytica.
    Tenants have their own users, domains, and isolated data.
    """

    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    plan = Column(String(50), default="free")  # free, professional, enterprise
    max_domains = Column(Integer, default=1)
    max_users = Column(Integer, default=5)
    settings = Column(JSON)  # Tenant-specific settings
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    members = relationship("TenantMember", back_populates="tenant", cascade="all, delete-orphan")
    domains = relationship("Domain", back_populates="tenant", cascade="all, delete-orphan")
    users = relationship("User", back_populates="tenant")

    __table_args__ = (Index("ix_tenants_is_active", "is_active"),)


class TenantMember(Base):
    """Maps users to tenants they belong to.

    Users can belong to multiple tenants with different roles.
    """

    __tablename__ = "tenant_members"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("webapp_users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(50), default="member", nullable=False)  # owner, admin, member
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    tenant = relationship("Tenant", back_populates="members")
    user = relationship("User", back_populates="tenant_memberships")

    __table_args__ = (
        Index("idx_tenant_members_tenant_user", "tenant_id", "user_id", unique=True),
        Index("ix_tenant_members_user_id", "user_id"),
    )


class User(Base):
    """Web app user (different from Google Workspace users being scanned)."""

    __tablename__ = "webapp_users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

    # Multi-tenant support
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True)

    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    tenant_memberships = relationship("TenantMember", back_populates="user", cascade="all, delete-orphan")
    domains = relationship("UserDomain", back_populates="user", cascade="all, delete-orphan")


class UserDomain(Base):
    """Maps which Google Workspace domains a user can access."""

    __tablename__ = "user_domains"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("webapp_users.id", ondelete="CASCADE"), nullable=False)
    domain = Column(String(255), nullable=False)
    role = Column(String(50), default="viewer")  # viewer, editor, admin
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="domains")

    __table_args__ = (Index("idx_user_domain", "user_id", "domain", unique=True),)


class Domain(Base):
    """Registered Google Workspace domains."""

    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    credentials_path = Column(Text)  # Path to service account credentials
    admin_email = Column(String(255))  # Admin email for impersonation
    credentials_rotated_at = Column(DateTime, nullable=True)  # When credentials were last rotated
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Multi-tenant support
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)

    # Relationships
    tenant = relationship("Tenant", back_populates="domains")
    scan_runs = relationship("ScanRun", back_populates="domain_ref")


class ScanRun(Base):
    """Record of a scan execution."""

    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(50), nullable=False, index=True)
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String(20), nullable=False, default="running")  # running, completed, failed
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    domain_name = Column(String(255), nullable=False, index=True)
    total_items = Column(Integer, default=0)
    issues_found = Column(Integer, default=0)
    high_risk_count = Column(Integer, default=0)
    medium_risk_count = Column(Integer, default=0)
    low_risk_count = Column(Integer, default=0)
    config = Column(JSON)  # Scan configuration options
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    triggered_by = Column(String(255))  # user email or "scheduled"
    # Progress tracking fields
    progress_percent = Column(Integer, default=0)  # 0-100 percentage
    progress_message = Column(String(255))  # Current operation (e.g., "Scanning files...")
    items_processed = Column(Integer, default=0)  # Items processed so far
    estimated_total = Column(Integer)  # Estimated total items (if known)

    # Multi-tenant support
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)

    # Relationships
    domain_ref = relationship("Domain", back_populates="scan_runs")
    findings = relationship("SecurityFinding", back_populates="scan_run", cascade="all, delete-orphan")
    file_findings = relationship("FileFinding", back_populates="scan_run", cascade="all, delete-orphan")
    user_findings = relationship("UserFinding", back_populates="scan_run", cascade="all, delete-orphan")
    oauth_findings = relationship("OAuthFinding", back_populates="scan_run", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_run_domain_time", "domain_name", "start_time"),
        Index("idx_scan_run_status", "status"),
        Index("idx_scan_runs_tenant_domain", "tenant_id", "domain_name"),
    )


class SecurityFinding(Base):
    """Security posture findings from compliance scans."""

    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    check_id = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low
    passed = Column(Boolean, nullable=False, index=True)
    current_value = Column(Text)
    expected_value = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    frameworks = Column(JSON)  # List of compliance frameworks: ["GDPR", "HIPAA", "SOC2"]
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    detected_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="open", index=True)  # open, acknowledged, resolved, false_positive
    status_notes = Column(Text)
    status_updated_at = Column(DateTime)
    status_updated_by = Column(String(255))

    scan_run = relationship("ScanRun", back_populates="findings")

    __table_args__ = (
        Index("idx_finding_severity", "severity", "passed"),
        Index("idx_finding_scan", "scan_run_id", "severity"),
        Index("idx_finding_detected_at", "detected_at"),
    )


class FileFinding(Base):
    """File sharing and PII findings from file scans."""

    __tablename__ = "file_findings"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    file_id = Column(String(255), nullable=False, index=True)
    file_name = Column(String(500), nullable=False)
    owner_email = Column(String(255), index=True)
    owner_name = Column(String(255))
    mime_type = Column(String(255))
    file_size = Column(Integer)
    web_view_link = Column(Text)
    is_public = Column(Boolean, default=False, index=True)
    is_shared_externally = Column(Boolean, default=False, index=True)
    external_domains = Column(JSON)  # List of external domains with access
    external_emails = Column(JSON)  # List of external email addresses
    risk_score = Column(Integer, default=0)
    pii_detected = Column(Boolean, default=False)
    pii_types = Column(JSON)  # List of PII types detected
    created_time = Column(DateTime)
    modified_time = Column(DateTime)
    detected_at = Column(DateTime, default=datetime.utcnow)

    scan_run = relationship("ScanRun", back_populates="file_findings")

    __table_args__ = (
        Index("idx_file_finding_risk", "risk_score"),
        Index("idx_file_finding_sharing", "is_public", "is_shared_externally"),
        Index("idx_file_finding_detected_at", "detected_at"),
        Index("idx_file_finding_pii", "pii_detected"),
    )


class UserFinding(Base):
    """User-related findings from user scans."""

    __tablename__ = "user_findings"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    full_name = Column(String(255))
    is_admin = Column(Boolean, default=False)
    is_suspended = Column(Boolean, default=False)
    is_archived = Column(Boolean, default=False)
    last_login_time = Column(DateTime)
    creation_time = Column(DateTime)
    two_factor_enabled = Column(Boolean, default=False)
    org_unit_path = Column(String(500))
    is_inactive = Column(Boolean, default=False, index=True)
    days_since_last_login = Column(Integer)
    risk_score = Column(Integer, default=0)
    risk_factors = Column(JSON)  # List of risk factors
    detected_at = Column(DateTime, default=datetime.utcnow)

    scan_run = relationship("ScanRun", back_populates="user_findings")

    __table_args__ = (
        Index("idx_user_finding_inactive", "is_inactive"),
        Index("idx_user_finding_2fa", "two_factor_enabled"),
        Index("idx_user_finding_risk", "risk_score"),
        Index("idx_user_finding_detected_at", "detected_at"),
    )


class OAuthFinding(Base):
    """OAuth application findings."""

    __tablename__ = "oauth_findings"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    client_id = Column(String(255), nullable=False, index=True)
    display_text = Column(String(500))
    scopes = Column(JSON)  # List of OAuth scopes
    user_count = Column(Integer, default=0)
    users = Column(JSON)  # List of user emails using this app
    risk_score = Column(Integer, default=0)
    is_verified = Column(Boolean, default=False)
    is_google_app = Column(Boolean, default=False)
    is_internal = Column(Boolean, default=False)
    risk_factors = Column(JSON)  # List of risk factors
    detected_at = Column(DateTime, default=datetime.utcnow)

    scan_run = relationship("ScanRun", back_populates="oauth_findings")

    __table_args__ = (
        Index("idx_oauth_finding_risk", "risk_score"),
        Index("idx_oauth_finding_verified", "is_verified"),
        Index("idx_oauth_finding_detected_at", "detected_at"),
    )


class AuditLog(Base):
    """Audit log for web app actions."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("webapp_users.id", ondelete="SET NULL"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Multi-tenant support
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True)

    __table_args__ = (Index("idx_audit_log_user_action", "user_id", "action"),)


class AlertRule(Base):
    """Alert rules for automated notifications."""

    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=True)
    condition_type = Column(String(50), nullable=False)  # risk_score, public_file, inactive_user, etc.
    condition_value = Column(JSON)  # Condition parameters
    notification_channels = Column(JSON)  # ["email", "slack", "webhook"]
    notification_config = Column(JSON)  # Channel-specific configuration
    created_by = Column(Integer, ForeignKey("webapp_users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Multi-tenant support
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)


class ScheduledScan(Base):
    """Scheduled scan configurations."""

    __tablename__ = "scheduled_scans"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(50), nullable=False)  # files, users, oauth, posture, all
    schedule_type = Column(String(20), nullable=False)  # hourly, daily, weekly, monthly
    schedule_config = Column(JSON)  # Cron-like configuration
    scan_config = Column(JSON)  # Scan-specific options
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    created_by = Column(Integer, ForeignKey("webapp_users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Multi-tenant support
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True, index=True)


class PasswordResetToken(Base):
    """Password reset tokens for forgot password flow."""

    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("webapp_users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(255), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class ComplianceReport(Base):
    """Generated compliance reports."""

    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    domain_name = Column(String(255), nullable=False, index=True)
    framework = Column(String(50), nullable=False, index=True)  # gdpr, hipaa, soc2, pci-dss, ferpa, fedramp
    status = Column(String(20), default="pending")  # pending, completed, failed
    compliance_score = Column(Integer)  # 0-100
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    report_data = Column(JSON)  # Full report data including issues
    error_message = Column(Text)
    generated_by = Column(Integer, ForeignKey("webapp_users.id", ondelete="SET NULL"))
    generated_at = Column(DateTime, default=datetime.utcnow)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="SET NULL"))

    __table_args__ = (
        Index("idx_compliance_domain_framework", "domain_id", "framework"),
    )


class ScheduledReport(Base):
    """Scheduled compliance report configurations."""

    __tablename__ = "scheduled_reports"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    framework = Column(String(50), nullable=False)  # gdpr, hipaa, soc2, pci-dss, ferpa, fedramp
    schedule_type = Column(String(20), nullable=False)  # daily, weekly, monthly
    schedule_config = Column(JSON)  # Configuration: hour, day_of_week, day
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime)
    next_run = Column(DateTime)
    last_report_id = Column(Integer, ForeignKey("compliance_reports.id", ondelete="SET NULL"))
    recipients = Column(JSON)  # List of email addresses to send report to
    created_by = Column(Integer, ForeignKey("webapp_users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("idx_scheduled_report_domain", "domain_id"),
        Index("idx_scheduled_report_next_run", "next_run", "is_active"),
    )
