"""State management for incremental scanning."""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

import structlog

logger = structlog.get_logger(__name__)


class StateManager:
    """Manage scan state in SQLite database."""

    def __init__(self, db_path: str = "vaulytica.db"):
        """Initialize state manager.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self._init_db()

        logger.info("state_manager_initialized", db_path=str(self.db_path))

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Scan history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL,
                    files_scanned INTEGER DEFAULT 0,
                    issues_found INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)

            # File state table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_state (
                    file_id TEXT PRIMARY KEY,
                    file_name TEXT NOT NULL,
                    owner_email TEXT,
                    modified_time TEXT NOT NULL,
                    last_scanned TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    has_issues BOOLEAN DEFAULT 0,
                    metadata TEXT
                )
            """)

            # User state table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_state (
                    user_email TEXT PRIMARY KEY,
                    user_name TEXT,
                    last_login TEXT,
                    last_scanned TEXT NOT NULL,
                    is_suspended BOOLEAN DEFAULT 0,
                    is_inactive BOOLEAN DEFAULT 0,
                    metadata TEXT
                )
            """)

            # OAuth token state table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS oauth_token_state (
                    user_email TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    last_scanned TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    metadata TEXT,
                    PRIMARY KEY (user_email, client_id)
                )
            """)

            # Create indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_file_modified 
                ON file_state(modified_time)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_file_last_scanned 
                ON file_state(last_scanned)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_history_time 
                ON scan_history(start_time)
            """)

            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get database connection context manager."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def record_scan_start(
        self,
        scan_type: str,
        domain: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Record the start of a scan.

        Args:
            scan_type: Type of scan (files, users, oauth, etc.)
            domain: Domain being scanned
            metadata: Optional metadata dictionary

        Returns:
            Scan ID
        """
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO scan_history 
                (scan_type, domain, start_time, status, metadata)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_type,
                    domain,
                    datetime.now(timezone.utc).isoformat(),
                    "running",
                    json.dumps(metadata) if metadata else None,
                ),
            )

            conn.commit()
            scan_id = cursor.lastrowid

        logger.info("scan_started", scan_id=scan_id, scan_type=scan_type)
        return scan_id

    def record_scan_end(
        self,
        scan_id: int,
        status: str,
        files_scanned: int = 0,
        issues_found: int = 0,
    ) -> None:
        """Record the end of a scan.

        Args:
            scan_id: Scan ID from record_scan_start
            status: Final status (completed, failed, cancelled)
            files_scanned: Number of files scanned
            issues_found: Number of issues found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                UPDATE scan_history
                SET end_time = ?, status = ?, files_scanned = ?, issues_found = ?
                WHERE id = ?
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    status,
                    files_scanned,
                    issues_found,
                    scan_id,
                ),
            )

            conn.commit()

        logger.info(
            "scan_ended",
            scan_id=scan_id,
            status=status,
            files_scanned=files_scanned,
            issues_found=issues_found,
        )

    def update_file_state(
        self,
        file_id: str,
        file_name: str,
        owner_email: str,
        modified_time: datetime,
        risk_score: int = 0,
        has_issues: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update file state.

        Args:
            file_id: File ID
            file_name: File name
            owner_email: Owner email
            modified_time: File modified time
            risk_score: Risk score
            has_issues: Whether file has issues
            metadata: Optional metadata
        """
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO file_state
                (file_id, file_name, owner_email, modified_time, last_scanned, 
                 risk_score, has_issues, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    file_name,
                    owner_email,
                    modified_time.isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                    risk_score,
                    has_issues,
                    json.dumps(metadata) if metadata else None,
                ),
            )

            conn.commit()

    def get_file_state(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get file state.

        Args:
            file_id: File ID

        Returns:
            File state dictionary or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM file_state WHERE file_id = ?",
                (file_id,),
            )

            row = cursor.fetchone()
            if row:
                return dict(row)

        return None

    def get_files_modified_since(self, since: datetime) -> List[str]:
        """Get file IDs modified since a given time.

        Args:
            since: Datetime to check from

        Returns:
            List of file IDs
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT file_id FROM file_state WHERE modified_time > ?",
                (since.isoformat(),),
            )

            return [row["file_id"] for row in cursor.fetchall()]

    def get_last_scan_time(self, scan_type: str, domain: str) -> Optional[datetime]:
        """Get the last successful scan time.

        Args:
            scan_type: Type of scan
            domain: Domain

        Returns:
            Last scan datetime or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT start_time FROM scan_history
                WHERE scan_type = ? AND domain = ? AND status = 'completed'
                ORDER BY start_time DESC
                LIMIT 1
                """,
                (scan_type, domain),
            )

            row = cursor.fetchone()
            if row:
                return datetime.fromisoformat(row["start_time"])

        return None

    def update_user_state(
        self,
        user_email: str,
        user_name: str,
        last_login: Optional[datetime] = None,
        is_suspended: bool = False,
        is_inactive: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update user state.

        Args:
            user_email: User email
            user_name: User name
            last_login: Last login time
            is_suspended: Whether user is suspended
            is_inactive: Whether user is inactive
            metadata: Optional metadata
        """
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO user_state
                (user_email, user_name, last_login, last_scanned, 
                 is_suspended, is_inactive, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_email,
                    user_name,
                    last_login.isoformat() if last_login else None,
                    datetime.now(timezone.utc).isoformat(),
                    is_suspended,
                    is_inactive,
                    json.dumps(metadata) if metadata else None,
                ),
            )

            conn.commit()

    def get_scan_history(
        self,
        scan_type: Optional[str] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get scan history.

        Args:
            scan_type: Filter by scan type (optional)
            limit: Maximum number of records

        Returns:
            List of scan history records
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if scan_type:
                cursor.execute(
                    """
                    SELECT * FROM scan_history
                    WHERE scan_type = ?
                    ORDER BY start_time DESC
                    LIMIT ?
                    """,
                    (scan_type, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM scan_history
                    ORDER BY start_time DESC
                    LIMIT ?
                    """,
                    (limit,),
                )

            return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_state(self, days: int = 90) -> int:
        """Clean up old state data.

        Args:
            days: Keep data newer than this many days

        Returns:
            Number of records deleted
        """
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Delete old scan history
            cursor.execute(
                "DELETE FROM scan_history WHERE start_time < ?",
                (cutoff.isoformat(),),
            )

            deleted = cursor.rowcount
            conn.commit()

        logger.info("state_cleanup_complete", deleted=deleted, days=days)
        return deleted

