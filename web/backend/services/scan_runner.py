"""Background scan runner service.

This service monitors the scheduled_scans table and executes scans
when their next_run time has passed. It should be run as a separate
process alongside the FastAPI backend.

Usage:
    # Run directly
    python -m backend.services.scan_runner

    # Or via Docker
    docker-compose up -d scan-runner
"""

import os
import sys
import time
import signal
import subprocess
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.db.models import Base, Domain, ScheduledScan, ScanRun

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://vaulytica:changeme@localhost:5432/vaulytica"
)
CHECK_INTERVAL = int(os.environ.get("SCAN_CHECK_INTERVAL", "60"))  # seconds
VAULYTICA_CLI_PATH = os.environ.get("VAULYTICA_CLI_PATH", "vaulytica")
CREDENTIALS_PATH = os.environ.get("VAULYTICA_CREDENTIALS_PATH", "/app/credentials/service-account.json")

# Retry configuration
MAX_RETRIES = int(os.environ.get("SCAN_MAX_RETRIES", "3"))
RETRY_BASE_DELAY = int(os.environ.get("SCAN_RETRY_DELAY", "30"))  # seconds

# Global flag for graceful shutdown
running = True


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    global running
    logger.info(f"Received signal {signum}, shutting down...")
    running = False


def get_db_session():
    """Create a database session."""
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    return Session()


def calculate_next_run(schedule_type: str, schedule_config: Optional[dict] = None) -> datetime:
    """Calculate the next run time based on schedule configuration."""
    now = datetime.utcnow()

    if schedule_type == "hourly":
        return now + timedelta(hours=1)
    elif schedule_type == "daily":
        hour = schedule_config.get("hour", 2) if schedule_config else 2
        next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run
    elif schedule_type == "weekly":
        day_of_week = schedule_config.get("day_of_week", 0) if schedule_config else 0
        hour = schedule_config.get("hour", 2) if schedule_config else 2
        days_ahead = day_of_week - now.weekday()
        if days_ahead <= 0:
            days_ahead += 7
        next_run = now + timedelta(days=days_ahead)
        return next_run.replace(hour=hour, minute=0, second=0, microsecond=0)
    elif schedule_type == "monthly":
        day = schedule_config.get("day", 1) if schedule_config else 1
        hour = schedule_config.get("hour", 2) if schedule_config else 2
        if now.day >= day:
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1, day=day, hour=hour, minute=0, second=0, microsecond=0)
            else:
                next_run = now.replace(month=now.month + 1, day=day, hour=hour, minute=0, second=0, microsecond=0)
        else:
            next_run = now.replace(day=day, hour=hour, minute=0, second=0, microsecond=0)
        return next_run

    return now + timedelta(days=1)


def build_scan_command(schedule: ScheduledScan, domain: Domain) -> list:
    """Build the vaulytica CLI command for a scheduled scan.

    Args:
        schedule: The scheduled scan configuration
        domain: The domain to scan

    Returns:
        List of command arguments
    """
    cmd = [
        VAULYTICA_CLI_PATH,
        "--save-to-db",
        "--db-url", DATABASE_URL,
    ]

    scan_config = schedule.scan_config or {}
    scan_type = schedule.scan_type

    if scan_type == "files":
        cmd.extend(["scan", "files", "--domain", domain.name])
        if scan_config.get("external_only"):
            cmd.append("--external-only")
        if scan_config.get("check_pii"):
            cmd.append("--check-pii")
        if scan_config.get("max_files"):
            cmd.extend(["--max-files", str(scan_config["max_files"])])

    elif scan_type == "users":
        cmd.extend(["scan", "users", "--domain", domain.name])
        if scan_config.get("inactive_days"):
            cmd.extend(["--inactive-days", str(scan_config["inactive_days"])])
        if scan_config.get("check_2fa"):
            cmd.append("--check-2fa")

    elif scan_type == "oauth":
        cmd.extend(["scan", "oauth-apps", "--domain", domain.name])
        if scan_config.get("min_risk_score"):
            cmd.extend(["--min-risk-score", str(scan_config["min_risk_score"])])

    elif scan_type == "posture":
        cmd.extend([
            "security-posture", "assess",
            "--credentials", domain.credentials_path or CREDENTIALS_PATH,
            "--admin-email", domain.admin_email or f"admin@{domain.name}",
            "--domain", domain.name,
        ])
        if scan_config.get("frameworks"):
            for framework in scan_config["frameworks"]:
                cmd.extend(["--framework", framework])

    elif scan_type == "all":
        # For "all" scan type, we run files, users, and oauth
        # This is a simplified version - could be expanded
        cmd.extend(["scan", "files", "--domain", domain.name, "--external-only"])

    return cmd


def execute_scan_attempt(cmd: list) -> tuple[bool, str, str]:
    """Execute a single scan attempt.

    Args:
        cmd: Command to execute

    Returns:
        Tuple of (success, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour timeout
        )

        if result.returncode == 0:
            return True, result.stdout, result.stderr
        else:
            return False, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        return False, "", "Scan timed out after 1 hour"
    except FileNotFoundError:
        return False, "", f"Vaulytica CLI not found at: {VAULYTICA_CLI_PATH}"
    except Exception as e:
        return False, "", str(e)


def execute_scan(schedule: ScheduledScan, domain: Domain, session) -> bool:
    """Execute a scheduled scan with retry logic.

    Args:
        schedule: The scheduled scan to execute
        domain: The domain to scan
        session: Database session

    Returns:
        True if scan completed successfully, False otherwise
    """
    logger.info(f"Executing scheduled scan: {schedule.name} (ID: {schedule.id})")
    logger.info(f"  Domain: {domain.name}, Type: {schedule.scan_type}")

    # Build command
    cmd = build_scan_command(schedule, domain)
    logger.info(f"  Command: {' '.join(cmd)}")

    last_error = ""
    for attempt in range(MAX_RETRIES):
        if attempt > 0:
            # Calculate exponential backoff delay: base_delay * 2^attempt
            delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
            logger.info(f"  Retry {attempt}/{MAX_RETRIES - 1} after {delay}s delay...")
            time.sleep(delay)

        success, stdout, stderr = execute_scan_attempt(cmd)

        if success:
            logger.info(f"  Scan completed successfully (attempt {attempt + 1})")
            if stdout:
                logger.debug(f"  Output: {stdout[:500]}")
            return True
        else:
            last_error = stderr
            logger.warning(f"  Attempt {attempt + 1}/{MAX_RETRIES} failed: {stderr[:200]}")

    # All retries exhausted
    logger.error(f"  Scan failed after {MAX_RETRIES} attempts")
    logger.error(f"  Last error: {last_error[:500]}")
    return False


def process_due_scans():
    """Find and execute all due scheduled scans."""
    session = get_db_session()

    try:
        now = datetime.utcnow()

        # Find all active schedules that are due
        due_schedules = session.query(ScheduledScan).filter(
            ScheduledScan.is_active == True,
            ScheduledScan.next_run <= now,
        ).all()

        if not due_schedules:
            logger.debug("No scheduled scans due")
            return

        logger.info(f"Found {len(due_schedules)} scheduled scans due for execution")

        for schedule in due_schedules:
            # Get domain
            domain = session.query(Domain).filter(Domain.id == schedule.domain_id).first()
            if not domain:
                logger.warning(f"Domain not found for schedule {schedule.id}, skipping")
                continue

            # Execute the scan
            success = execute_scan(schedule, domain, session)

            # Update schedule
            schedule.last_run = now
            schedule.next_run = calculate_next_run(
                schedule.schedule_type,
                schedule.schedule_config
            )

            logger.info(f"  Next run scheduled for: {schedule.next_run}")

        session.commit()

    except Exception as e:
        logger.error(f"Error processing scheduled scans: {e}")
        session.rollback()
    finally:
        session.close()


def main():
    """Main entry point for the scan runner."""
    global running

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("=" * 60)
    logger.info("Vaulytica Background Scan Runner")
    logger.info("=" * 60)
    logger.info(f"Database URL: {DATABASE_URL.replace(DATABASE_URL.split(':')[2].split('@')[0], '***')}")
    logger.info(f"Check interval: {CHECK_INTERVAL} seconds")
    logger.info(f"CLI path: {VAULYTICA_CLI_PATH}")
    logger.info(f"Max retries: {MAX_RETRIES}")
    logger.info(f"Retry base delay: {RETRY_BASE_DELAY} seconds")
    logger.info("=" * 60)

    # Test database connection
    try:
        session = get_db_session()
        session.execute("SELECT 1")
        session.close()
        logger.info("Database connection successful")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        sys.exit(1)

    logger.info("Starting scan runner loop...")

    while running:
        try:
            process_due_scans()
        except Exception as e:
            logger.error(f"Error in main loop: {e}")

        # Sleep in small increments to allow for graceful shutdown
        for _ in range(CHECK_INTERVAL):
            if not running:
                break
            time.sleep(1)

    logger.info("Scan runner stopped")


if __name__ == "__main__":
    main()
