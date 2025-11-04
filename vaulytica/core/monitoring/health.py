"""Health check and system monitoring."""

import time
import psutil
from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime, timezone

import structlog

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


@dataclass
class HealthStatus:
    """Health check status."""

    healthy: bool
    status: str  # healthy, degraded, unhealthy
    checks: Dict[str, bool]
    details: Dict[str, any]
    timestamp: datetime


class HealthChecker:
    """Performs health checks on the system."""

    def __init__(self, client: Optional[GoogleWorkspaceClient] = None):
        """Initialize health checker.

        Args:
            client: GoogleWorkspaceClient instance
        """
        self.client = client
        logger.info("health_checker_initialized")

    def check_health(self) -> HealthStatus:
        """Perform comprehensive health check.

        Returns:
            HealthStatus
        """
        checks = {}
        details = {}

        # Check system resources
        checks["system_resources"] = self._check_system_resources(details)

        # Check Google API connectivity
        if self.client:
            checks["google_api"] = self._check_google_api(details)

        # Check database
        checks["database"] = self._check_database(details)

        # Determine overall status
        all_healthy = all(checks.values())
        any_unhealthy = not any(checks.values())

        if all_healthy:
            status = "healthy"
        elif any_unhealthy:
            status = "unhealthy"
        else:
            status = "degraded"

        return HealthStatus(
            healthy=all_healthy,
            status=status,
            checks=checks,
            details=details,
            timestamp=datetime.now(timezone.utc),
        )

    def _check_system_resources(self, details: Dict) -> bool:
        """Check system resource availability.

        Args:
            details: Dictionary to populate with details

        Returns:
            True if resources are healthy
        """
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            details["cpu_percent"] = cpu_percent

            # Check memory usage
            memory = psutil.virtual_memory()
            details["memory_percent"] = memory.percent
            details["memory_available_mb"] = memory.available / (1024 * 1024)

            # Check disk usage
            disk = psutil.disk_usage("/")
            details["disk_percent"] = disk.percent
            details["disk_free_gb"] = disk.free / (1024 * 1024 * 1024)

            # Thresholds
            cpu_healthy = cpu_percent < 90
            memory_healthy = memory.percent < 90
            disk_healthy = disk.percent < 90

            return cpu_healthy and memory_healthy and disk_healthy

        except Exception as e:
            logger.error("system_resource_check_failed", error=str(e))
            details["error"] = str(e)
            return False

    def _check_google_api(self, details: Dict) -> bool:
        """Check Google API connectivity.

        Args:
            details: Dictionary to populate with details

        Returns:
            True if API is accessible
        """
        if not self.client:
            details["error"] = "No client configured"
            return False

        try:
            start_time = time.time()

            # Try a simple API call
            self.client.drive.about().get(fields="user").execute()

            duration = time.time() - start_time
            details["api_response_time_ms"] = duration * 1000

            # Check if response time is acceptable
            return duration < 5.0

        except Exception as e:
            logger.error("google_api_check_failed", error=str(e))
            details["error"] = str(e)
            return False

    def _check_database(self, details: Dict) -> bool:
        """Check database connectivity.

        Args:
            details: Dictionary to populate with details

        Returns:
            True if database is accessible
        """
        try:
            from vaulytica.storage import StateManager

            # Try to initialize state manager
            state_manager = StateManager()

            # Try a simple query
            start_time = time.time()
            state_manager.get_scan_history(limit=1)
            duration = time.time() - start_time

            details["db_response_time_ms"] = duration * 1000

            return True

        except Exception as e:
            logger.error("database_check_failed", error=str(e))
            details["error"] = str(e)
            return False

    def get_system_info(self) -> Dict[str, any]:
        """Get system information.

        Returns:
            Dictionary of system information
        """
        info = {}

        try:
            # CPU info
            info["cpu_count"] = psutil.cpu_count()
            info["cpu_percent"] = psutil.cpu_percent(interval=1)

            # Memory info
            memory = psutil.virtual_memory()
            info["memory_total_gb"] = memory.total / (1024 * 1024 * 1024)
            info["memory_available_gb"] = memory.available / (1024 * 1024 * 1024)
            info["memory_percent"] = memory.percent

            # Disk info
            disk = psutil.disk_usage("/")
            info["disk_total_gb"] = disk.total / (1024 * 1024 * 1024)
            info["disk_free_gb"] = disk.free / (1024 * 1024 * 1024)
            info["disk_percent"] = disk.percent

            # Process info
            process = psutil.Process()
            info["process_memory_mb"] = process.memory_info().rss / (1024 * 1024)
            info["process_cpu_percent"] = process.cpu_percent(interval=1)

        except Exception as e:
            logger.error("failed_to_get_system_info", error=str(e))
            info["error"] = str(e)

        return info


class PerformanceMonitor:
    """Monitors performance metrics."""

    def __init__(self):
        """Initialize performance monitor."""
        self.operation_times: Dict[str, List[float]] = {}
        logger.info("performance_monitor_initialized")

    def record_operation(self, operation: str, duration: float) -> None:
        """Record operation duration.

        Args:
            operation: Operation name
            duration: Duration in seconds
        """
        if operation not in self.operation_times:
            self.operation_times[operation] = []

        self.operation_times[operation].append(duration)

        # Keep only last 1000 measurements
        if len(self.operation_times[operation]) > 1000:
            self.operation_times[operation] = self.operation_times[operation][-1000:]

    def get_stats(self, operation: str) -> Optional[Dict[str, float]]:
        """Get statistics for an operation.

        Args:
            operation: Operation name

        Returns:
            Dictionary of statistics or None
        """
        if operation not in self.operation_times:
            return None

        times = self.operation_times[operation]
        if not times:
            return None

        return {
            "count": len(times),
            "min": min(times),
            "max": max(times),
            "avg": sum(times) / len(times),
            "p50": self._percentile(times, 50),
            "p95": self._percentile(times, 95),
            "p99": self._percentile(times, 99),
        }

    def _percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile.

        Args:
            values: List of values
            percentile: Percentile (0-100)

        Returns:
            Percentile value
        """
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        return sorted_values[min(index, len(sorted_values) - 1)]

    def get_all_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all operations.

        Returns:
            Dictionary of operation statistics
        """
        return {
            operation: self.get_stats(operation)
            for operation in self.operation_times.keys()
            if self.get_stats(operation) is not None
        }


class Timer:
    """Context manager for timing operations."""

    def __init__(self, operation: str, monitor: Optional[PerformanceMonitor] = None):
        """Initialize timer.

        Args:
            operation: Operation name
            monitor: PerformanceMonitor instance
        """
        self.operation = operation
        self.monitor = monitor
        self.start_time = 0.0
        self.duration = 0.0

    def __enter__(self):
        """Start timer."""
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop timer and record duration."""
        self.duration = time.time() - self.start_time

        if self.monitor:
            self.monitor.record_operation(self.operation, self.duration)

        logger.debug(
            "operation_completed",
            operation=self.operation,
            duration_ms=self.duration * 1000,
        )


# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance.

    Returns:
        PerformanceMonitor instance
    """
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor

