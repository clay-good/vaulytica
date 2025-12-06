"""Historical data storage for trend analysis."""

import json
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class MetricType(Enum):
    """Types of metrics tracked for trending."""

    EXTERNAL_SHARES = "external_shares"
    PUBLIC_FILES = "public_files"
    USERS_WITHOUT_2FA = "users_without_2fa"
    HIGH_RISK_OAUTH = "high_risk_oauth"
    INACTIVE_USERS = "inactive_users"
    EXTERNAL_MEMBERS = "external_members"
    STALE_FILES = "stale_files"
    EXTERNAL_OWNED_FILES = "external_owned_files"
    SECURITY_SCORE = "security_score"
    COMPLIANCE_SCORE = "compliance_score"


@dataclass
class MetricSnapshot:
    """A point-in-time metric value."""

    metric_type: MetricType
    value: float
    timestamp: datetime
    domain: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metric_type": self.metric_type.value,
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "domain": self.domain,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MetricSnapshot":
        """Create from dictionary."""
        return cls(
            metric_type=MetricType(data["metric_type"]),
            value=data["value"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            domain=data["domain"],
            metadata=data.get("metadata", {}),
        )


@dataclass
class TrendData:
    """Trend analysis results."""

    metric_type: MetricType
    current_value: float
    previous_value: float
    change_absolute: float
    change_percent: float
    trend_direction: str  # improving, degrading, stable
    period_days: int
    data_points: List[MetricSnapshot] = field(default_factory=list)


class HistoryManager:
    """Manage historical metrics in SQLite database."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize history manager.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or Path.home() / ".vaulytica" / "history.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

        logger.info("history_manager_initialized", db_path=str(self.db_path))

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Metrics history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_type TEXT NOT NULL,
                    value REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    metadata TEXT
                )
            """)

            # Scan results history for detailed tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    total_items INTEGER DEFAULT 0,
                    items_with_issues INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0,
                    results_summary TEXT
                )
            """)

            # Compliance scores history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS compliance_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    score REAL NOT NULL,
                    passed_checks INTEGER DEFAULT 0,
                    failed_checks INTEGER DEFAULT 0,
                    details TEXT
                )
            """)

            # Create indexes for efficient queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_type_time
                ON metrics_history(metric_type, timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_domain_time
                ON metrics_history(domain, timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_results_time
                ON scan_results(scan_type, timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_compliance_time
                ON compliance_history(framework, timestamp)
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

    def record_metric(
        self,
        metric_type: MetricType,
        value: float,
        domain: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a metric value.

        Args:
            metric_type: Type of metric
            value: Metric value
            domain: Domain the metric applies to
            metadata: Optional additional data
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO metrics_history
                (metric_type, value, timestamp, domain, metadata)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    metric_type.value,
                    value,
                    datetime.now(timezone.utc).isoformat(),
                    domain,
                    json.dumps(metadata) if metadata else None,
                ),
            )

            conn.commit()

        logger.debug(
            "metric_recorded",
            metric_type=metric_type.value,
            value=value,
            domain=domain,
        )

    def record_scan_results(
        self,
        scan_type: str,
        domain: str,
        total_items: int,
        items_with_issues: int,
        risk_score: float = 0,
        results_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record scan results for historical tracking.

        Args:
            scan_type: Type of scan performed
            domain: Domain scanned
            total_items: Total items scanned
            items_with_issues: Number of items with issues
            risk_score: Overall risk score
            results_summary: Summary of results
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO scan_results
                (scan_type, domain, timestamp, total_items, items_with_issues,
                 risk_score, results_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_type,
                    domain,
                    datetime.now(timezone.utc).isoformat(),
                    total_items,
                    items_with_issues,
                    risk_score,
                    json.dumps(results_summary) if results_summary else None,
                ),
            )

            conn.commit()

        logger.info(
            "scan_results_recorded",
            scan_type=scan_type,
            total_items=total_items,
            items_with_issues=items_with_issues,
        )

    def record_compliance_score(
        self,
        framework: str,
        domain: str,
        score: float,
        passed_checks: int,
        failed_checks: int,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record compliance score for historical tracking.

        Args:
            framework: Compliance framework (gdpr, hipaa, soc2, etc.)
            domain: Domain assessed
            score: Compliance score (0-100)
            passed_checks: Number of checks passed
            failed_checks: Number of checks failed
            details: Detailed check results
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO compliance_history
                (framework, domain, timestamp, score, passed_checks, failed_checks, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    framework,
                    domain,
                    datetime.now(timezone.utc).isoformat(),
                    score,
                    passed_checks,
                    failed_checks,
                    json.dumps(details) if details else None,
                ),
            )

            conn.commit()

        logger.info(
            "compliance_score_recorded",
            framework=framework,
            score=score,
        )

    def get_metric_history(
        self,
        metric_type: MetricType,
        domain: str,
        days: int = 30,
    ) -> List[MetricSnapshot]:
        """Get metric history for a time period.

        Args:
            metric_type: Type of metric
            domain: Domain to filter by
            days: Number of days to look back

        Returns:
            List of MetricSnapshot objects
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT metric_type, value, timestamp, domain, metadata
                FROM metrics_history
                WHERE metric_type = ? AND domain = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (metric_type.value, domain, cutoff.isoformat()),
            )

            snapshots = []
            for row in cursor.fetchall():
                snapshots.append(MetricSnapshot(
                    metric_type=MetricType(row["metric_type"]),
                    value=row["value"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    domain=row["domain"],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                ))

            return snapshots

    def get_latest_metric(
        self,
        metric_type: MetricType,
        domain: str,
    ) -> Optional[MetricSnapshot]:
        """Get the latest metric value.

        Args:
            metric_type: Type of metric
            domain: Domain to filter by

        Returns:
            Latest MetricSnapshot or None
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT metric_type, value, timestamp, domain, metadata
                FROM metrics_history
                WHERE metric_type = ? AND domain = ?
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (metric_type.value, domain),
            )

            row = cursor.fetchone()
            if row:
                return MetricSnapshot(
                    metric_type=MetricType(row["metric_type"]),
                    value=row["value"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    domain=row["domain"],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                )

        return None

    def get_scan_history(
        self,
        scan_type: str,
        domain: str,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get scan results history.

        Args:
            scan_type: Type of scan
            domain: Domain to filter by
            days: Number of days to look back

        Returns:
            List of scan result records
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM scan_results
                WHERE scan_type = ? AND domain = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (scan_type, domain, cutoff.isoformat()),
            )

            return [dict(row) for row in cursor.fetchall()]

    def get_compliance_history(
        self,
        framework: str,
        domain: str,
        days: int = 90,
    ) -> List[Dict[str, Any]]:
        """Get compliance score history.

        Args:
            framework: Compliance framework
            domain: Domain to filter by
            days: Number of days to look back

        Returns:
            List of compliance score records
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM compliance_history
                WHERE framework = ? AND domain = ? AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (framework, domain, cutoff.isoformat()),
            )

            return [dict(row) for row in cursor.fetchall()]

    def cleanup_old_data(self, days: int = 365) -> Dict[str, int]:
        """Clean up data older than specified days.

        Args:
            days: Keep data newer than this many days

        Returns:
            Dictionary with counts of deleted records per table
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        deleted = {}

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Clean metrics history
            cursor.execute(
                "DELETE FROM metrics_history WHERE timestamp < ?",
                (cutoff.isoformat(),),
            )
            deleted["metrics_history"] = cursor.rowcount

            # Clean scan results
            cursor.execute(
                "DELETE FROM scan_results WHERE timestamp < ?",
                (cutoff.isoformat(),),
            )
            deleted["scan_results"] = cursor.rowcount

            # Clean compliance history
            cursor.execute(
                "DELETE FROM compliance_history WHERE timestamp < ?",
                (cutoff.isoformat(),),
            )
            deleted["compliance_history"] = cursor.rowcount

            conn.commit()

        logger.info("history_cleanup_complete", deleted=deleted, days=days)
        return deleted


# Global history manager instance
_history_manager: Optional[HistoryManager] = None


def get_history_manager(db_path: Optional[Path] = None) -> HistoryManager:
    """Get global history manager instance.

    Args:
        db_path: Path to database file

    Returns:
        HistoryManager instance
    """
    global _history_manager
    if _history_manager is None:
        _history_manager = HistoryManager(db_path)
    return _history_manager
