"""Database models for historical tracking and large-scale data management."""

from datetime import datetime
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

    # Soft delete support
    is_deleted = Column(Boolean, default=False, index=True)
    deleted_at = Column(DateTime)
    deleted_by = Column(String(255))
    deletion_reason = Column(String(500))

    __table_args__ = (
        Index("idx_pii_type_severity", "pii_type", "severity"),
        Index("idx_pii_external", "is_externally_shared", "resolved"),
        Index("idx_pii_owner", "owner_email", "detected_at"),
        Index("idx_pii_soft_delete", "is_deleted", "detected_at"),
    )


class Finding(Base):
    """Generic security finding with full audit trail and soft delete support.

    This model provides a unified way to track all types of security findings
    with comprehensive audit capabilities for compliance purposes.
    """

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Finding identification
    finding_type = Column(String(100), nullable=False, index=True)  # pii, oauth, posture, etc.
    category = Column(String(100), nullable=False, index=True)  # data_exposure, access_control, etc.
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low
    title = Column(String(500), nullable=False)
    description = Column(Text)

    # Affected resource
    resource_type = Column(String(50), nullable=False)  # file, user, device, app
    resource_id = Column(String(255), index=True)
    resource_name = Column(String(500))
    resource_owner = Column(String(255), index=True)

    # Detection metadata
    detected_at = Column(DateTime, default=datetime.now, index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"))
    confidence_score = Column(Float)  # 0.0 to 1.0
    raw_data = Column(JSON)  # Original detection data

    # Status tracking
    status = Column(String(50), default="open", index=True)  # open, acknowledged, in_progress, resolved, false_positive
    status_changed_at = Column(DateTime)
    status_changed_by = Column(String(255))

    # Resolution tracking
    resolution_action = Column(String(100))  # remediated, accepted_risk, false_positive, etc.
    resolution_notes = Column(Text)
    resolved_at = Column(DateTime)
    resolved_by = Column(String(255))

    # Soft delete support (for audit trail)
    is_deleted = Column(Boolean, default=False, index=True)
    deleted_at = Column(DateTime)
    deleted_by = Column(String(255))
    deletion_reason = Column(String(500))

    # Timestamps
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    __table_args__ = (
        Index("idx_finding_type_severity", "finding_type", "severity"),
        Index("idx_finding_status", "status", "is_deleted"),
        Index("idx_finding_resource", "resource_type", "resource_id"),
        Index("idx_finding_owner", "resource_owner", "detected_at"),
        Index("idx_finding_soft_delete", "is_deleted", "detected_at"),
    )


class FindingHistory(Base):
    """Audit trail for all changes to findings.

    Every state change or update to a finding is recorded here
    for compliance and audit purposes.
    """

    __tablename__ = "finding_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)

    # Change tracking
    action = Column(String(50), nullable=False)  # created, updated, status_changed, deleted, restored
    field_changed = Column(String(100))  # Which field was changed (null for create/delete)
    old_value = Column(Text)
    new_value = Column(Text)

    # Who and when
    changed_by = Column(String(255), index=True)
    changed_at = Column(DateTime, default=datetime.now, index=True)
    change_reason = Column(String(500))

    # Additional context
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    metadata = Column(JSON)

    __table_args__ = (
        Index("idx_history_finding", "finding_id", "changed_at"),
        Index("idx_history_action", "action", "changed_at"),
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

    # ============================================================================
    # Finding Management with Soft Delete and Audit Trail
    # ============================================================================

    def create_finding(
        self,
        finding_type: str,
        category: str,
        severity: str,
        title: str,
        resource_type: str,
        resource_id: str = None,
        resource_name: str = None,
        resource_owner: str = None,
        description: str = None,
        confidence_score: float = None,
        scan_run_id: int = None,
        raw_data: dict = None,
        created_by: str = None,
    ) -> Finding:
        """Create a new finding with audit trail.

        Args:
            finding_type: Type of finding (pii, oauth, posture, etc.)
            category: Category (data_exposure, access_control, etc.)
            severity: Severity level (critical, high, medium, low)
            title: Short title for the finding
            resource_type: Type of affected resource (file, user, device, app)
            resource_id: ID of the affected resource
            resource_name: Name of the affected resource
            resource_owner: Owner of the affected resource
            description: Detailed description
            confidence_score: Detection confidence (0.0 to 1.0)
            scan_run_id: Associated scan run ID
            raw_data: Original detection data
            created_by: User who created/detected this finding

        Returns:
            Created Finding object
        """
        session = self.get_session()
        try:
            finding = Finding(
                finding_type=finding_type,
                category=category,
                severity=severity,
                title=title,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_name,
                resource_owner=resource_owner,
                description=description,
                confidence_score=confidence_score,
                scan_run_id=scan_run_id,
                raw_data=raw_data,
            )
            session.add(finding)
            session.flush()  # Get the ID

            # Record creation in history
            history = FindingHistory(
                finding_id=finding.id,
                action="created",
                changed_by=created_by,
                metadata={"finding_type": finding_type, "severity": severity},
            )
            session.add(history)

            session.commit()
            session.refresh(finding)

            logger.info(
                "finding_created",
                finding_id=finding.id,
                finding_type=finding_type,
                severity=severity,
            )
            return finding
        except Exception as e:
            session.rollback()
            logger.error("failed_to_create_finding", error=str(e))
            raise
        finally:
            session.close()

    def soft_delete_finding(
        self,
        finding_id: int,
        deleted_by: str,
        reason: str = None,
    ) -> bool:
        """Soft delete a finding (marks as deleted but keeps data for audit).

        Args:
            finding_id: ID of the finding to delete
            deleted_by: User performing the deletion
            reason: Reason for deletion

        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                logger.warning("finding_not_found", finding_id=finding_id)
                return False

            if finding.is_deleted:
                logger.warning("finding_already_deleted", finding_id=finding_id)
                return False

            # Record old state
            old_state = {
                "status": finding.status,
                "is_deleted": finding.is_deleted,
            }

            # Soft delete
            finding.is_deleted = True
            finding.deleted_at = datetime.now()
            finding.deleted_by = deleted_by
            finding.deletion_reason = reason

            # Record in history
            history = FindingHistory(
                finding_id=finding_id,
                action="deleted",
                field_changed="is_deleted",
                old_value="false",
                new_value="true",
                changed_by=deleted_by,
                change_reason=reason,
                metadata=old_state,
            )
            session.add(history)

            session.commit()
            logger.info(
                "finding_soft_deleted",
                finding_id=finding_id,
                deleted_by=deleted_by,
                reason=reason,
            )
            return True
        except Exception as e:
            session.rollback()
            logger.error("failed_to_soft_delete_finding", error=str(e))
            raise
        finally:
            session.close()

    def restore_finding(
        self,
        finding_id: int,
        restored_by: str,
        reason: str = None,
    ) -> bool:
        """Restore a soft-deleted finding.

        Args:
            finding_id: ID of the finding to restore
            restored_by: User performing the restoration
            reason: Reason for restoration

        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                logger.warning("finding_not_found", finding_id=finding_id)
                return False

            if not finding.is_deleted:
                logger.warning("finding_not_deleted", finding_id=finding_id)
                return False

            # Restore
            finding.is_deleted = False
            finding.deleted_at = None
            finding.deleted_by = None
            finding.deletion_reason = None

            # Record in history
            history = FindingHistory(
                finding_id=finding_id,
                action="restored",
                field_changed="is_deleted",
                old_value="true",
                new_value="false",
                changed_by=restored_by,
                change_reason=reason,
            )
            session.add(history)

            session.commit()
            logger.info(
                "finding_restored",
                finding_id=finding_id,
                restored_by=restored_by,
            )
            return True
        except Exception as e:
            session.rollback()
            logger.error("failed_to_restore_finding", error=str(e))
            raise
        finally:
            session.close()

    def update_finding_status(
        self,
        finding_id: int,
        status: str,
        changed_by: str,
        resolution_action: str = None,
        resolution_notes: str = None,
        change_reason: str = None,
    ) -> bool:
        """Update finding status with audit trail.

        Args:
            finding_id: ID of the finding
            status: New status (open, acknowledged, in_progress, resolved, false_positive)
            changed_by: User making the change
            resolution_action: Action taken to resolve (if resolving)
            resolution_notes: Notes about the resolution
            change_reason: Reason for the status change

        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                logger.warning("finding_not_found", finding_id=finding_id)
                return False

            old_status = finding.status

            # Update status
            finding.status = status
            finding.status_changed_at = datetime.now()
            finding.status_changed_by = changed_by

            # Handle resolution
            if status in ["resolved", "false_positive"]:
                finding.resolved_at = datetime.now()
                finding.resolved_by = changed_by
                if resolution_action:
                    finding.resolution_action = resolution_action
                if resolution_notes:
                    finding.resolution_notes = resolution_notes

            # Record in history
            history = FindingHistory(
                finding_id=finding_id,
                action="status_changed",
                field_changed="status",
                old_value=old_status,
                new_value=status,
                changed_by=changed_by,
                change_reason=change_reason,
                metadata={
                    "resolution_action": resolution_action,
                    "resolution_notes": resolution_notes,
                },
            )
            session.add(history)

            session.commit()
            logger.info(
                "finding_status_updated",
                finding_id=finding_id,
                old_status=old_status,
                new_status=status,
                changed_by=changed_by,
            )
            return True
        except Exception as e:
            session.rollback()
            logger.error("failed_to_update_finding_status", error=str(e))
            raise
        finally:
            session.close()

    def get_findings(
        self,
        include_deleted: bool = False,
        finding_type: str = None,
        severity: str = None,
        status: str = None,
        resource_owner: str = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list:
        """Get findings with optional filters.

        Args:
            include_deleted: Whether to include soft-deleted findings
            finding_type: Filter by finding type
            severity: Filter by severity
            status: Filter by status
            resource_owner: Filter by resource owner
            limit: Maximum number of results
            offset: Offset for pagination

        Returns:
            List of Finding objects
        """
        session = self.get_session()
        try:
            query = session.query(Finding)

            if not include_deleted:
                query = query.filter(Finding.is_deleted == False)

            if finding_type:
                query = query.filter(Finding.finding_type == finding_type)
            if severity:
                query = query.filter(Finding.severity == severity)
            if status:
                query = query.filter(Finding.status == status)
            if resource_owner:
                query = query.filter(Finding.resource_owner == resource_owner)

            query = query.order_by(Finding.detected_at.desc())
            query = query.limit(limit).offset(offset)

            return query.all()
        finally:
            session.close()

    def get_finding_history(self, finding_id: int) -> list:
        """Get complete audit history for a finding.

        Args:
            finding_id: ID of the finding

        Returns:
            List of FindingHistory objects ordered by timestamp
        """
        session = self.get_session()
        try:
            return (
                session.query(FindingHistory)
                .filter(FindingHistory.finding_id == finding_id)
                .order_by(FindingHistory.changed_at.asc())
                .all()
            )
        finally:
            session.close()

    def soft_delete_pii_detection(
        self,
        detection_id: int,
        deleted_by: str,
        reason: str = None,
    ) -> bool:
        """Soft delete a PII detection (marks as deleted but keeps data for audit).

        Args:
            detection_id: ID of the PII detection to delete
            deleted_by: User performing the deletion
            reason: Reason for deletion

        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            detection = (
                session.query(PIIDetection)
                .filter(PIIDetection.id == detection_id)
                .first()
            )
            if not detection:
                logger.warning("pii_detection_not_found", detection_id=detection_id)
                return False

            if detection.is_deleted:
                logger.warning("pii_detection_already_deleted", detection_id=detection_id)
                return False

            # Soft delete
            detection.is_deleted = True
            detection.deleted_at = datetime.now()
            detection.deleted_by = deleted_by
            detection.deletion_reason = reason

            # Log audit event
            self.log_audit_event(
                action="pii_detection_soft_deleted",
                user=deleted_by,
                resource_type="pii_detection",
                resource_id=str(detection_id),
                details={
                    "file_id": detection.file_id,
                    "pii_type": detection.pii_type,
                    "reason": reason,
                },
            )

            session.commit()
            logger.info(
                "pii_detection_soft_deleted",
                detection_id=detection_id,
                deleted_by=deleted_by,
            )
            return True
        except Exception as e:
            session.rollback()
            logger.error("failed_to_soft_delete_pii_detection", error=str(e))
            raise
        finally:
            session.close()

