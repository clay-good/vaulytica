"""Database models for historical tracking and large-scale data management."""

from datetime import datetime
from typing import Optional
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
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import structlog

logger = structlog.get_logger(__name__)

Base = declarative_base()


class ScanRun(Base):
    """Record of a scan execution."""

    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(50), nullable=False, index=True)
    start_time = Column(DateTime, nullable=False, default=datetime.now)
    end_time = Column(DateTime)
    status = Column(String(20), nullable=False)  # running, completed, failed
    total_items = Column(Integer, default=0)
    issues_found = Column(Integer, default=0)
    config = Column(JSON)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.now)

    # Relationships
    files = relationship("FileRecord", back_populates="scan_run", cascade="all, delete-orphan")
    users = relationship("UserRecord", back_populates="scan_run", cascade="all, delete-orphan")
    devices = relationship("DeviceRecord", back_populates="scan_run", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_type_start_time", "scan_type", "start_time"),
        Index("idx_status", "status"),
    )


class FileRecord(Base):
    """Record of a scanned file."""

    __tablename__ = "file_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    file_id = Column(String(255), nullable=False, index=True)
    file_name = Column(String(500))
    file_path = Column(Text)
    owner_email = Column(String(255), index=True)
    mime_type = Column(String(100))
    size_bytes = Column(Integer)
    created_time = Column(DateTime)
    modified_time = Column(DateTime)
    is_externally_shared = Column(Boolean, default=False, index=True)
    shared_with = Column(JSON)  # List of emails/domains
    permissions_count = Column(Integer, default=0)
    has_pii = Column(Boolean, default=False, index=True)
    pii_types = Column(JSON)  # List of PII types found
    risk_score = Column(Integer, default=0, index=True)
    risk_factors = Column(JSON)
    scan_timestamp = Column(DateTime, default=datetime.now)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="files")

    __table_args__ = (
        Index("idx_file_owner", "owner_email"),
        Index("idx_file_risk", "risk_score", "has_pii"),
        Index("idx_file_external", "is_externally_shared", "has_pii"),
    )


class UserRecord(Base):
    """Record of a scanned user."""

    __tablename__ = "user_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    user_email = Column(String(255), nullable=False, index=True)
    full_name = Column(String(255))
    is_admin = Column(Boolean, default=False)
    is_suspended = Column(Boolean, default=False, index=True)
    is_2fa_enrolled = Column(Boolean, default=False, index=True)
    last_login_time = Column(DateTime, index=True)
    creation_time = Column(DateTime)
    org_unit_path = Column(String(500))
    is_inactive = Column(Boolean, default=False, index=True)
    inactive_days = Column(Integer, default=0)
    risk_score = Column(Integer, default=0, index=True)
    risk_factors = Column(JSON)
    scan_timestamp = Column(DateTime, default=datetime.now)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="users")

    __table_args__ = (
        Index("idx_user_status", "is_suspended", "is_inactive"),
        Index("idx_user_2fa", "is_2fa_enrolled"),
        Index("idx_user_risk", "risk_score"),
    )


class DeviceRecord(Base):
    """Record of a scanned device (mobile or Chrome OS)."""

    __tablename__ = "device_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    device_id = Column(String(255), nullable=False, index=True)
    device_type = Column(String(50), nullable=False)  # mobile, chromeos
    serial_number = Column(String(255))
    model = Column(String(255))
    os_version = Column(String(100))
    status = Column(String(50), index=True)
    user_email = Column(String(255), index=True)
    last_sync = Column(DateTime, index=True)
    is_compromised = Column(Boolean, default=False, index=True)
    is_developer_mode = Column(Boolean, default=False, index=True)
    auto_update_expired = Column(Boolean, default=False, index=True)
    risk_score = Column(Integer, default=0, index=True)
    risk_factors = Column(JSON)
    scan_timestamp = Column(DateTime, default=datetime.now)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="devices")

    __table_args__ = (
        Index("idx_device_type_status", "device_type", "status"),
        Index("idx_device_risk", "risk_score", "is_compromised"),
        Index("idx_device_user", "user_email"),
    )


class PIIDetection(Base):
    """Record of PII detection in files or emails."""

    __tablename__ = "pii_detections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_id = Column(String(255), index=True)
    file_name = Column(String(500))
    owner_email = Column(String(255), index=True)
    pii_type = Column(String(100), nullable=False, index=True)
    pii_value_hash = Column(String(64))  # SHA-256 hash of PII value
    location = Column(String(500))  # File path or email subject
    is_externally_shared = Column(Boolean, default=False, index=True)
    severity = Column(String(20), index=True)  # low, medium, high, critical
    detected_at = Column(DateTime, default=datetime.now, index=True)
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime)
    resolution_action = Column(String(100))

    __table_args__ = (
        Index("idx_pii_type_severity", "pii_type", "severity"),
        Index("idx_pii_external", "is_externally_shared", "resolved"),
        Index("idx_pii_owner", "owner_email", "detected_at"),
    )


class ComplianceReport(Base):
    """Record of compliance report generation."""

    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    framework = Column(String(50), nullable=False, index=True)
    report_date = Column(DateTime, nullable=False, default=datetime.now, index=True)
    compliance_score = Column(Float)
    total_checks = Column(Integer)
    passed_checks = Column(Integer)
    failed_checks = Column(Integer)
    warnings = Column(Integer)
    report_data = Column(JSON)
    report_path = Column(String(500))
    created_at = Column(DateTime, default=datetime.now)

    __table_args__ = (Index("idx_framework_date", "framework", "report_date"),)


class AuditLog(Base):
    """Audit log for all Vaulytica operations."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now, index=True)
    action = Column(String(100), nullable=False, index=True)
    user = Column(String(255), index=True)
    resource_type = Column(String(50))
    resource_id = Column(String(255))
    status = Column(String(20))  # success, failure
    details = Column(JSON)
    ip_address = Column(String(45))
    error_message = Column(Text)

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_action_status", "action", "status"),
        Index("idx_audit_user", "user", "timestamp"),
    )


class DatabaseManager:
    """Manager for database operations."""

    def __init__(self, database_url: str = "sqlite:///vaulytica.db"):
        """
        Initialize database manager.

        Args:
            database_url: SQLAlchemy database URL
        """
        self.database_url = database_url
        self.engine = create_engine(database_url, echo=False)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        logger.info("database_manager_initialized", database_url=database_url)

    def create_tables(self):
        """Create all database tables."""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("database_tables_created")
        except Exception as e:
            logger.error("failed_to_create_tables", error=str(e))
            raise

    def drop_tables(self):
        """Drop all database tables."""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.info("database_tables_dropped")
        except Exception as e:
            logger.error("failed_to_drop_tables", error=str(e))
            raise

    def get_session(self):
        """Get a new database session."""
        return self.SessionLocal()

    def create_scan_run(self, scan_type: str, config: dict = None) -> ScanRun:
        """Create a new scan run record."""
        session = self.get_session()
        try:
            scan_run = ScanRun(
                scan_type=scan_type,
                status="running",
                config=config,
                start_time=datetime.now(),
            )
            session.add(scan_run)
            session.commit()
            session.refresh(scan_run)
            logger.info("scan_run_created", scan_run_id=scan_run.id, scan_type=scan_type)
            return scan_run
        except Exception as e:
            session.rollback()
            logger.error("failed_to_create_scan_run", error=str(e))
            raise
        finally:
            session.close()

    def update_scan_run(
        self,
        scan_run_id: int,
        status: str = None,
        total_items: int = None,
        issues_found: int = None,
        error_message: str = None,
    ):
        """Update a scan run record."""
        session = self.get_session()
        try:
            scan_run = session.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
            if scan_run:
                if status:
                    scan_run.status = status
                if total_items is not None:
                    scan_run.total_items = total_items
                if issues_found is not None:
                    scan_run.issues_found = issues_found
                if error_message:
                    scan_run.error_message = error_message
                if status in ["completed", "failed"]:
                    scan_run.end_time = datetime.now()
                session.commit()
                logger.info("scan_run_updated", scan_run_id=scan_run_id, status=status)
        except Exception as e:
            session.rollback()
            logger.error("failed_to_update_scan_run", error=str(e))
            raise
        finally:
            session.close()

    def log_audit_event(
        self,
        action: str,
        user: str = None,
        resource_type: str = None,
        resource_id: str = None,
        status: str = "success",
        details: dict = None,
        error_message: str = None,
    ):
        """Log an audit event."""
        session = self.get_session()
        try:
            audit_log = AuditLog(
                action=action,
                user=user,
                resource_type=resource_type,
                resource_id=resource_id,
                status=status,
                details=details,
                error_message=error_message,
            )
            session.add(audit_log)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("failed_to_log_audit_event", error=str(e))
        finally:
            session.close()

