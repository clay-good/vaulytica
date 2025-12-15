"""Database saver for CLI scan results.

This module bridges the CLI scan outputs to the web app's PostgreSQL database,
allowing scan results to be stored and viewed in the web dashboard.

The saver defines SQLAlchemy models that match the web app's database schema,
ensuring compatibility without requiring the web app as a dependency.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    create_engine,
)
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase


# Define models that match the web app's schema
class WebBase(DeclarativeBase):
    """Base class for web app compatible models."""
    pass


class ScanRun(WebBase):
    """Record of a scan execution - matches web app schema."""

    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(50), nullable=False, index=True)
    start_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String(20), nullable=False, default="running")
    domain_id = Column(Integer, nullable=True)
    domain_name = Column(String(255), nullable=False, index=True)
    total_items = Column(Integer, default=0)
    issues_found = Column(Integer, default=0)
    high_risk_count = Column(Integer, default=0)
    medium_risk_count = Column(Integer, default=0)
    low_risk_count = Column(Integer, default=0)
    config = Column(JSON)
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    triggered_by = Column(String(255))
    # Progress tracking fields
    progress_percent = Column(Integer, default=0)
    progress_message = Column(String(255))
    items_processed = Column(Integer, default=0)
    estimated_total = Column(Integer)


class SecurityFinding(WebBase):
    """Security posture findings - matches web app schema."""

    __tablename__ = "security_findings"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    check_id = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False, index=True)
    passed = Column(Boolean, nullable=False, index=True)
    current_value = Column(Text)
    expected_value = Column(Text)
    impact = Column(Text)
    remediation = Column(Text)
    frameworks = Column(JSON)
    resource_type = Column(String(100))
    resource_id = Column(String(255))
    detected_at = Column(DateTime, default=datetime.utcnow)


class FileFinding(WebBase):
    """File sharing and PII findings - matches web app schema."""

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
    external_domains = Column(JSON)
    external_emails = Column(JSON)
    risk_score = Column(Integer, default=0)
    pii_detected = Column(Boolean, default=False)
    pii_types = Column(JSON)
    created_time = Column(DateTime)
    modified_time = Column(DateTime)
    detected_at = Column(DateTime, default=datetime.utcnow)


class UserFinding(WebBase):
    """User-related findings - matches web app schema."""

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
    risk_factors = Column(JSON)
    detected_at = Column(DateTime, default=datetime.utcnow)


class OAuthFinding(WebBase):
    """OAuth application findings - matches web app schema."""

    __tablename__ = "oauth_findings"

    id = Column(Integer, primary_key=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False)
    client_id = Column(String(255), nullable=False, index=True)
    display_text = Column(String(500))
    scopes = Column(JSON)
    user_count = Column(Integer, default=0)
    users = Column(JSON)
    risk_score = Column(Integer, default=0)
    is_verified = Column(Boolean, default=False)
    is_google_app = Column(Boolean, default=False)
    is_internal = Column(Boolean, default=False)
    risk_factors = Column(JSON)
    detected_at = Column(DateTime, default=datetime.utcnow)


class DatabaseSaver:
    """Save CLI scan results to PostgreSQL database.

    This class handles the connection to the web app's database and provides
    methods to save various types of scan results.

    Example:
        >>> saver = DatabaseSaver("postgresql://user:pass@localhost:5432/vaulytica")
        >>> scan_id = saver.start_scan("files", "example.com", triggered_by="cli")
        >>> saver.save_file_findings(scan_id, files)
        >>> saver.complete_scan(scan_id, total_items=100, issues_found=5)
    """

    def __init__(self, database_url: str):
        """Initialize database connection.

        Args:
            database_url: PostgreSQL connection string.
                         Format: postgresql://user:password@host:port/database
        """
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def _get_session(self) -> Session:
        """Create a new database session."""
        return self.SessionLocal()

    def ensure_tables(self) -> None:
        """Create database tables if they don't exist.

        Note: In production, use Alembic migrations instead.
        """
        WebBase.metadata.create_all(bind=self.engine)

    def start_scan(
        self,
        scan_type: str,
        domain_name: str,
        triggered_by: str = "cli",
        config: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Start a new scan run and return its ID.

        Args:
            scan_type: Type of scan (files, users, oauth, posture, groups, etc.)
            domain_name: Google Workspace domain being scanned
            triggered_by: Who/what triggered the scan (default: "cli")
            config: Optional scan configuration parameters

        Returns:
            The ID of the created scan run
        """
        with self._get_session() as session:
            scan_run = ScanRun(
                scan_type=scan_type,
                domain_name=domain_name,
                status="running",
                start_time=datetime.now(timezone.utc),
                triggered_by=triggered_by,
                config=config or {},
            )
            session.add(scan_run)
            session.commit()
            session.refresh(scan_run)
            return scan_run.id

    def complete_scan(
        self,
        scan_id: int,
        total_items: int = 0,
        issues_found: int = 0,
        high_risk_count: int = 0,
        medium_risk_count: int = 0,
        low_risk_count: int = 0,
    ) -> None:
        """Mark a scan as completed with summary statistics.

        Args:
            scan_id: ID of the scan run to update
            total_items: Total number of items scanned
            issues_found: Number of issues/findings discovered
            high_risk_count: Number of high-severity issues
            medium_risk_count: Number of medium-severity issues
            low_risk_count: Number of low-severity issues
        """
        with self._get_session() as session:
            scan_run = session.query(ScanRun).filter(ScanRun.id == scan_id).first()
            if scan_run:
                scan_run.status = "completed"
                scan_run.end_time = datetime.now(timezone.utc)
                scan_run.total_items = total_items
                scan_run.issues_found = issues_found
                scan_run.high_risk_count = high_risk_count
                scan_run.medium_risk_count = medium_risk_count
                scan_run.low_risk_count = low_risk_count
                session.commit()

    def fail_scan(
        self,
        scan_id: int,
        error_message: str,
        total_items: int = 0,
        issues_found: int = 0,
        high_risk_count: int = 0,
        medium_risk_count: int = 0,
        low_risk_count: int = 0,
    ) -> None:
        """Mark a scan as failed with an error message.

        Preserves any partial results that were saved before the failure.

        Args:
            scan_id: ID of the scan run to update
            error_message: Error description
            total_items: Total number of items scanned before failure
            issues_found: Number of issues found before failure
            high_risk_count: Number of high-severity issues
            medium_risk_count: Number of medium-severity issues
            low_risk_count: Number of low-severity issues
        """
        with self._get_session() as session:
            scan_run = session.query(ScanRun).filter(ScanRun.id == scan_id).first()
            if scan_run:
                scan_run.status = "failed"
                scan_run.end_time = datetime.now(timezone.utc)
                scan_run.error_message = error_message
                # Preserve partial results if provided
                if total_items > 0:
                    scan_run.total_items = total_items
                if issues_found > 0:
                    scan_run.issues_found = issues_found
                if high_risk_count > 0:
                    scan_run.high_risk_count = high_risk_count
                if medium_risk_count > 0:
                    scan_run.medium_risk_count = medium_risk_count
                if low_risk_count > 0:
                    scan_run.low_risk_count = low_risk_count
                session.commit()

    def cancel_scan(
        self,
        scan_id: int,
        total_items: int = 0,
        issues_found: int = 0,
        high_risk_count: int = 0,
        medium_risk_count: int = 0,
        low_risk_count: int = 0,
    ) -> None:
        """Mark a scan as cancelled (user interrupted).

        Args:
            scan_id: ID of the scan run to update
            total_items: Total number of items scanned before cancellation
            issues_found: Number of issues found before cancellation
            high_risk_count: Number of high-severity issues
            medium_risk_count: Number of medium-severity issues
            low_risk_count: Number of low-severity issues
        """
        with self._get_session() as session:
            scan_run = session.query(ScanRun).filter(ScanRun.id == scan_id).first()
            if scan_run:
                scan_run.status = "cancelled"
                scan_run.end_time = datetime.now(timezone.utc)
                scan_run.total_items = total_items
                scan_run.issues_found = issues_found
                scan_run.high_risk_count = high_risk_count
                scan_run.medium_risk_count = medium_risk_count
                scan_run.low_risk_count = low_risk_count
                scan_run.error_message = "Scan cancelled by user"
                session.commit()

    def update_progress(
        self,
        scan_id: int,
        percent: int,
        message: Optional[str] = None,
        items_processed: Optional[int] = None,
        estimated_total: Optional[int] = None,
    ) -> None:
        """Update scan progress.

        Args:
            scan_id: ID of the scan run to update
            percent: Progress percentage (0-100)
            message: Current operation message (e.g., "Scanning files...")
            items_processed: Number of items processed so far
            estimated_total: Estimated total items (if known)
        """
        with self._get_session() as session:
            scan_run = session.query(ScanRun).filter(ScanRun.id == scan_id).first()
            if scan_run:
                scan_run.progress_percent = min(100, max(0, percent))
                if message is not None:
                    scan_run.progress_message = message
                if items_processed is not None:
                    scan_run.items_processed = items_processed
                if estimated_total is not None:
                    scan_run.estimated_total = estimated_total
                session.commit()

    def save_file_findings(self, scan_id: int, files: List[Any]) -> int:
        """Save file scan results to database.

        Args:
            scan_id: ID of the parent scan run
            files: List of FileInfo objects from the file scanner

        Returns:
            Number of findings saved
        """
        with self._get_session() as session:
            count = 0
            for file_info in files:
                finding = FileFinding(
                    scan_run_id=scan_id,
                    file_id=file_info.id,
                    file_name=file_info.name,
                    owner_email=file_info.owner_email,
                    owner_name=getattr(file_info, 'owner_name', None),
                    mime_type=getattr(file_info, 'mime_type', None),
                    file_size=getattr(file_info, 'size', None),
                    web_view_link=file_info.web_view_link,
                    is_public=file_info.is_public,
                    is_shared_externally=file_info.is_shared_externally,
                    external_domains=file_info.external_domains or [],
                    external_emails=file_info.external_emails or [],
                    risk_score=file_info.risk_score,
                    pii_detected=getattr(file_info, 'pii_detected', False),
                    pii_types=getattr(file_info, 'pii_types', []),
                    created_time=getattr(file_info, 'created_time', None),
                    modified_time=file_info.modified_time,
                    detected_at=datetime.now(timezone.utc),
                )
                session.add(finding)
                count += 1
            session.commit()
            return count

    def save_user_findings(self, scan_id: int, users: List[Any]) -> int:
        """Save user scan results to database.

        Args:
            scan_id: ID of the parent scan run
            users: List of UserInfo objects from the user scanner

        Returns:
            Number of findings saved
        """
        with self._get_session() as session:
            count = 0
            for user in users:
                # Calculate risk factors
                risk_factors = []
                if getattr(user, 'is_inactive', False):
                    risk_factors.append("inactive")
                if not getattr(user, 'two_factor_enabled', True):
                    risk_factors.append("no_2fa")
                if getattr(user, 'is_admin', False):
                    risk_factors.append("admin")

                finding = UserFinding(
                    scan_run_id=scan_id,
                    user_id=user.id,
                    email=user.email,
                    full_name=user.full_name,
                    is_admin=getattr(user, 'is_admin', False),
                    is_suspended=getattr(user, 'is_suspended', False),
                    is_archived=getattr(user, 'is_archived', False),
                    last_login_time=user.last_login_time,
                    creation_time=getattr(user, 'creation_time', None),
                    two_factor_enabled=getattr(user, 'two_factor_enabled', False),
                    org_unit_path=user.org_unit_path,
                    is_inactive=getattr(user, 'is_inactive', False),
                    days_since_last_login=user.days_since_last_login,
                    risk_score=getattr(user, 'risk_score', 0),
                    risk_factors=risk_factors,
                    detected_at=datetime.now(timezone.utc),
                )
                session.add(finding)
                count += 1
            session.commit()
            return count

    def save_oauth_findings(self, scan_id: int, apps: List[Any]) -> int:
        """Save OAuth app scan results to database.

        Args:
            scan_id: ID of the parent scan run
            apps: List of OAuthApp objects from the OAuth scanner

        Returns:
            Number of findings saved
        """
        with self._get_session() as session:
            count = 0
            for app in apps:
                # Calculate risk factors
                risk_factors = []
                if app.risk_score >= 75:
                    risk_factors.append("high_risk_score")
                if not getattr(app, 'is_verified', True):
                    risk_factors.append("unverified")
                if len(app.scopes) > 5:
                    risk_factors.append("many_scopes")

                finding = OAuthFinding(
                    scan_run_id=scan_id,
                    client_id=app.client_id,
                    display_text=app.display_text,
                    scopes=app.scopes or [],
                    user_count=app.user_count,
                    users=getattr(app, 'users', []),
                    risk_score=app.risk_score,
                    is_verified=getattr(app, 'is_verified', False),
                    is_google_app=app.is_google_app,
                    is_internal=getattr(app, 'is_internal', False),
                    risk_factors=risk_factors,
                    detected_at=datetime.now(timezone.utc),
                )
                session.add(finding)
                count += 1
            session.commit()
            return count

    def save_security_findings(self, scan_id: int, findings_list: List[Any]) -> int:
        """Save security posture findings to database.

        Args:
            scan_id: ID of the parent scan run
            findings_list: List of security check findings from posture scanner

        Returns:
            Number of findings saved
        """
        with self._get_session() as session:
            count = 0
            for finding_data in findings_list:
                # Handle both dict and object inputs
                if isinstance(finding_data, dict):
                    finding = SecurityFinding(
                        scan_run_id=scan_id,
                        check_id=finding_data.get('check_id', ''),
                        title=finding_data.get('title', ''),
                        description=finding_data.get('description', ''),
                        severity=finding_data.get('severity', 'medium'),
                        passed=finding_data.get('passed', False),
                        current_value=finding_data.get('current_value', ''),
                        expected_value=finding_data.get('expected_value', ''),
                        impact=finding_data.get('impact', ''),
                        remediation=finding_data.get('remediation', ''),
                        frameworks=finding_data.get('frameworks', []),
                        resource_type=finding_data.get('resource_type', ''),
                        resource_id=finding_data.get('resource_id', ''),
                        detected_at=datetime.now(timezone.utc),
                    )
                else:
                    finding = SecurityFinding(
                        scan_run_id=scan_id,
                        check_id=getattr(finding_data, 'check_id', ''),
                        title=getattr(finding_data, 'title', ''),
                        description=getattr(finding_data, 'description', ''),
                        severity=getattr(finding_data, 'severity', 'medium'),
                        passed=getattr(finding_data, 'passed', False),
                        current_value=str(getattr(finding_data, 'current_value', '')),
                        expected_value=str(getattr(finding_data, 'expected_value', '')),
                        impact=getattr(finding_data, 'impact', ''),
                        remediation=getattr(finding_data, 'remediation', ''),
                        frameworks=getattr(finding_data, 'frameworks', []),
                        resource_type=getattr(finding_data, 'resource_type', ''),
                        resource_id=getattr(finding_data, 'resource_id', ''),
                        detected_at=datetime.now(timezone.utc),
                    )
                session.add(finding)
                count += 1
            session.commit()
            return count
