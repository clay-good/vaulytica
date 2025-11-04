"""Scheduler for automated recurring scans."""

import json
import signal
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from enum import Enum

import structlog
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.job import Job

logger = structlog.get_logger(__name__)


class ScheduleType(Enum):
    """Schedule types."""

    CRON = "cron"
    INTERVAL = "interval"
    ONE_TIME = "one_time"


class ScanType(Enum):
    """Scan types."""

    FILES = "files"
    USERS = "users"
    GMAIL = "gmail"
    SHARED_DRIVES = "shared_drives"
    OAUTH = "oauth"


@dataclass
class ScheduledScan:
    """Configuration for a scheduled scan."""

    id: str
    name: str
    scan_type: ScanType
    schedule_type: ScheduleType
    schedule: str  # Cron expression or interval
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    last_run: Optional[str] = None
    next_run: Optional[str] = None
    run_count: int = 0
    failure_count: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self):
        """Initialize timestamps."""
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if self.updated_at is None:
            self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["scan_type"] = self.scan_type.value
        data["schedule_type"] = self.schedule_type.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScheduledScan":
        """Create from dictionary."""
        data = data.copy()
        data["scan_type"] = ScanType(data["scan_type"])
        data["schedule_type"] = ScheduleType(data["schedule_type"])
        return cls(**data)


class ScanScheduler:
    """Scheduler for automated recurring scans."""

    def __init__(self, config_file: Optional[Path] = None):
        """Initialize scheduler.

        Args:
            config_file: Path to scheduler configuration file
        """
        self.config_file = config_file or Path.home() / ".vaulytica" / "schedules.json"
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        self.scheduler = BackgroundScheduler(
            timezone="UTC",
            job_defaults={
                "coalesce": True,  # Combine missed runs
                "max_instances": 1,  # Only one instance per job
                "misfire_grace_time": 300,  # 5 minutes grace period
            },
        )

        self.scheduled_scans: Dict[str, ScheduledScan] = {}
        self.scan_callbacks: Dict[ScanType, Callable] = {}

        # Load existing schedules
        self._load_schedules()

        logger.info("scan_scheduler_initialized", config_file=str(self.config_file))

    def register_scan_callback(self, scan_type: ScanType, callback: Callable) -> None:
        """Register a callback for a scan type.

        Args:
            scan_type: Type of scan
            callback: Callback function to execute scan
        """
        self.scan_callbacks[scan_type] = callback
        logger.info("scan_callback_registered", scan_type=scan_type.value)

    def add_schedule(
        self,
        name: str,
        scan_type: ScanType,
        schedule_type: ScheduleType,
        schedule: str,
        config: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
    ) -> ScheduledScan:
        """Add a new scheduled scan.

        Args:
            name: Schedule name
            scan_type: Type of scan
            schedule_type: Type of schedule (cron, interval, one_time)
            schedule: Schedule expression (cron or interval)
            config: Scan configuration
            enabled: Whether schedule is enabled

        Returns:
            Created ScheduledScan

        Examples:
            # Cron schedule (every day at 2 AM)
            scheduler.add_schedule(
                name="Daily File Scan",
                scan_type=ScanType.FILES,
                schedule_type=ScheduleType.CRON,
                schedule="0 2 * * *",
            )

            # Interval schedule (every 6 hours)
            scheduler.add_schedule(
                name="Periodic User Scan",
                scan_type=ScanType.USERS,
                schedule_type=ScheduleType.INTERVAL,
                schedule="6h",
            )
        """
        # Generate unique ID
        scan_id = f"{scan_type.value}_{int(time.time())}"

        scheduled_scan = ScheduledScan(
            id=scan_id,
            name=name,
            scan_type=scan_type,
            schedule_type=schedule_type,
            schedule=schedule,
            enabled=enabled,
            config=config or {},
        )

        self.scheduled_scans[scan_id] = scheduled_scan

        # Add to APScheduler if enabled
        if enabled:
            self._add_job(scheduled_scan)

        # Save to disk
        self._save_schedules()

        logger.info(
            "schedule_added",
            id=scan_id,
            name=name,
            scan_type=scan_type.value,
            schedule=schedule,
        )

        return scheduled_scan

    def remove_schedule(self, scan_id: str) -> bool:
        """Remove a scheduled scan.

        Args:
            scan_id: Schedule ID

        Returns:
            True if removed
        """
        if scan_id not in self.scheduled_scans:
            logger.warning("schedule_not_found", id=scan_id)
            return False

        # Remove from APScheduler
        try:
            self.scheduler.remove_job(scan_id)
        except Exception:
            pass  # Job may not exist

        # Remove from memory
        del self.scheduled_scans[scan_id]

        # Save to disk
        self._save_schedules()

        logger.info("schedule_removed", id=scan_id)
        return True

    def enable_schedule(self, scan_id: str) -> bool:
        """Enable a scheduled scan.

        Args:
            scan_id: Schedule ID

        Returns:
            True if enabled
        """
        if scan_id not in self.scheduled_scans:
            logger.warning("schedule_not_found", id=scan_id)
            return False

        scheduled_scan = self.scheduled_scans[scan_id]
        scheduled_scan.enabled = True
        scheduled_scan.updated_at = datetime.now(timezone.utc).isoformat()

        # Add to APScheduler
        self._add_job(scheduled_scan)

        # Save to disk
        self._save_schedules()

        logger.info("schedule_enabled", id=scan_id)
        return True

    def disable_schedule(self, scan_id: str) -> bool:
        """Disable a scheduled scan.

        Args:
            scan_id: Schedule ID

        Returns:
            True if disabled
        """
        if scan_id not in self.scheduled_scans:
            logger.warning("schedule_not_found", id=scan_id)
            return False

        scheduled_scan = self.scheduled_scans[scan_id]
        scheduled_scan.enabled = False
        scheduled_scan.updated_at = datetime.now(timezone.utc).isoformat()

        # Remove from APScheduler
        try:
            self.scheduler.remove_job(scan_id)
        except Exception:
            pass

        # Save to disk
        self._save_schedules()

        logger.info("schedule_disabled", id=scan_id)
        return True

    def list_schedules(self, enabled_only: bool = False) -> List[ScheduledScan]:
        """List all scheduled scans.

        Args:
            enabled_only: Only return enabled schedules

        Returns:
            List of ScheduledScan objects
        """
        schedules = list(self.scheduled_scans.values())

        if enabled_only:
            schedules = [s for s in schedules if s.enabled]

        return schedules

    def get_schedule(self, scan_id: str) -> Optional[ScheduledScan]:
        """Get a scheduled scan by ID.

        Args:
            scan_id: Schedule ID

        Returns:
            ScheduledScan or None
        """
        return self.scheduled_scans.get(scan_id)

    def start(self) -> None:
        """Start the scheduler."""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("scheduler_started", job_count=len(self.scheduler.get_jobs()))

            # Setup signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

    def stop(self) -> None:
        """Stop the scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=True)
            logger.info("scheduler_stopped")

    def run_forever(self) -> None:
        """Start scheduler and run forever (blocking)."""
        self.start()

        logger.info("scheduler_running", message="Press Ctrl+C to exit")

        try:
            # Keep the main thread alive
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            logger.info("scheduler_interrupted")
            self.stop()

    def _add_job(self, scheduled_scan: ScheduledScan) -> None:
        """Add job to APScheduler.

        Args:
            scheduled_scan: Scheduled scan configuration
        """
        # Create trigger based on schedule type
        if scheduled_scan.schedule_type == ScheduleType.CRON:
            trigger = self._create_cron_trigger(scheduled_scan.schedule)
        elif scheduled_scan.schedule_type == ScheduleType.INTERVAL:
            trigger = self._create_interval_trigger(scheduled_scan.schedule)
        else:
            logger.warning("unsupported_schedule_type", type=scheduled_scan.schedule_type)
            return

        # Add job
        self.scheduler.add_job(
            func=self._execute_scan,
            trigger=trigger,
            id=scheduled_scan.id,
            name=scheduled_scan.name,
            args=[scheduled_scan],
            replace_existing=True,
        )

        # Update next run time
        job = self.scheduler.get_job(scheduled_scan.id)
        if job and job.next_run_time:
            scheduled_scan.next_run = job.next_run_time.isoformat()

        logger.info(
            "job_added",
            id=scheduled_scan.id,
            name=scheduled_scan.name,
            next_run=scheduled_scan.next_run,
        )

    def _create_cron_trigger(self, cron_expression: str) -> CronTrigger:
        """Create cron trigger from expression.

        Args:
            cron_expression: Cron expression (e.g., "0 2 * * *")

        Returns:
            CronTrigger
        """
        parts = cron_expression.split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {cron_expression}")

        minute, hour, day, month, day_of_week = parts

        return CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
            timezone="UTC",
        )

    def _create_interval_trigger(self, interval_expression: str) -> IntervalTrigger:
        """Create interval trigger from expression.

        Args:
            interval_expression: Interval expression (e.g., "6h", "30m", "1d")

        Returns:
            IntervalTrigger
        """
        # Parse interval (e.g., "6h" -> 6 hours)
        unit = interval_expression[-1]
        value = int(interval_expression[:-1])

        kwargs = {}
        if unit == "s":
            kwargs["seconds"] = value
        elif unit == "m":
            kwargs["minutes"] = value
        elif unit == "h":
            kwargs["hours"] = value
        elif unit == "d":
            kwargs["days"] = value
        else:
            raise ValueError(f"Invalid interval unit: {unit}")

        return IntervalTrigger(**kwargs, timezone="UTC")

    def _execute_scan(self, scheduled_scan: ScheduledScan) -> None:
        """Execute a scheduled scan.

        Args:
            scheduled_scan: Scheduled scan configuration
        """
        logger.info(
            "scan_started",
            id=scheduled_scan.id,
            name=scheduled_scan.name,
            scan_type=scheduled_scan.scan_type.value,
        )

        start_time = time.time()

        try:
            # Get callback for scan type
            callback = self.scan_callbacks.get(scheduled_scan.scan_type)
            if not callback:
                raise ValueError(f"No callback registered for {scheduled_scan.scan_type.value}")

            # Execute scan
            callback(scheduled_scan.config)

            # Update success metrics
            scheduled_scan.run_count += 1
            scheduled_scan.last_run = datetime.now(timezone.utc).isoformat()

            duration = time.time() - start_time

            logger.info(
                "scan_completed",
                id=scheduled_scan.id,
                name=scheduled_scan.name,
                duration=f"{duration:.2f}s",
                run_count=scheduled_scan.run_count,
            )

        except Exception as e:
            scheduled_scan.failure_count += 1

            logger.error(
                "scan_failed",
                id=scheduled_scan.id,
                name=scheduled_scan.name,
                error=str(e),
                failure_count=scheduled_scan.failure_count,
            )

        finally:
            # Update next run time
            job = self.scheduler.get_job(scheduled_scan.id)
            if job and job.next_run_time:
                scheduled_scan.next_run = job.next_run_time.isoformat()

            # Save updated state
            self._save_schedules()

    def _load_schedules(self) -> None:
        """Load schedules from disk."""
        if not self.config_file.exists():
            logger.info("no_schedules_file", path=str(self.config_file))
            return

        try:
            with open(self.config_file, "r") as f:
                data = json.load(f)

            for scan_data in data.get("schedules", []):
                scheduled_scan = ScheduledScan.from_dict(scan_data)
                self.scheduled_scans[scheduled_scan.id] = scheduled_scan

                # Add to APScheduler if enabled
                if scheduled_scan.enabled:
                    self._add_job(scheduled_scan)

            logger.info("schedules_loaded", count=len(self.scheduled_scans))

        except Exception as e:
            logger.error("failed_to_load_schedules", error=str(e))

    def _save_schedules(self) -> None:
        """Save schedules to disk."""
        try:
            data = {
                "schedules": [scan.to_dict() for scan in self.scheduled_scans.values()],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

            with open(self.config_file, "w") as f:
                json.dump(data, f, indent=2)

            logger.debug("schedules_saved", count=len(self.scheduled_scans))

        except Exception as e:
            logger.error("failed_to_save_schedules", error=str(e))

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info("shutdown_signal_received", signal=signum)
        self.stop()
        sys.exit(0)


# Global scheduler instance
_scheduler: Optional[ScanScheduler] = None


def get_scheduler(config_file: Optional[Path] = None) -> ScanScheduler:
    """Get global scheduler instance.

    Args:
        config_file: Path to scheduler configuration file

    Returns:
        ScanScheduler instance
    """
    global _scheduler
    if _scheduler is None:
        _scheduler = ScanScheduler(config_file)
    return _scheduler


def reset_scheduler() -> None:
    """Reset global scheduler instance (for testing)."""
    global _scheduler
    if _scheduler and _scheduler.scheduler.running:
        _scheduler.stop()
    _scheduler = None

