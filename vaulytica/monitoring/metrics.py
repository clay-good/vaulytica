"""
Monitoring and Metrics Module

Provides Prometheus metrics, custom metrics collection, and performance monitoring.
"""

import time
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging
from functools import wraps

logger = logging.getLogger(__name__)

# Try to import prometheus_client
try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary,
        CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client not available. Install with: pip install prometheus-client")


class MetricType(str, Enum):
    """Metric types"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class MetricDefinition:
    """Metric definition"""
    name: str
    metric_type: MetricType
    description: str
    labels: list = field(default_factory=list)
    buckets: Optional[list] = None  # For histograms


class MetricsCollector:
    """
    Metrics collection and export.

    Features:
    - Prometheus metrics integration
    - Custom metrics collection
    - Performance monitoring
    - Health checks
    """

    def __init__(self, enable_prometheus: bool = True):
        """
        Initialize metrics collector.

        Args:
            enable_prometheus: Enable Prometheus metrics
        """
        self.enable_prometheus = enable_prometheus and PROMETHEUS_AVAILABLE

        if self.enable_prometheus:
            self.registry = CollectorRegistry()
        else:
            self.registry = None

        # Metric storage
        self.metrics: Dict[str, Any] = {}
        self.custom_metrics: Dict[str, list] = {}

        # Initialize default metrics
        self._initialize_default_metrics()

        logger.info(f"MetricsCollector initialized (Prometheus: {self.enable_prometheus})")

    def _initialize_default_metrics(self):
        """Initialize default Vaulytica metrics"""
        if self.enable_prometheus:
            # Request metrics
            self.metrics['http_requests_total'] = Counter(
                'vaulytica_http_requests_total',
                'Total HTTP requests',
                ['method', 'endpoint', 'status'],
                registry=self.registry
            )

            self.metrics['http_request_duration_seconds'] = Histogram(
                'vaulytica_http_request_duration_seconds',
                'HTTP request duration in seconds',
                ['method', 'endpoint'],
                buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
                registry=self.registry
            )

            # Agent metrics
            self.metrics['agent_executions_total'] = Counter(
                'vaulytica_agent_executions_total',
                'Total agent executions',
                ['agent_type', 'status'],
                registry=self.registry
            )

            self.metrics['agent_execution_duration_seconds'] = Histogram(
                'vaulytica_agent_execution_duration_seconds',
                'Agent execution duration in seconds',
                ['agent_type'],
                buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0],
                registry=self.registry
            )

            # Incident metrics
            self.metrics['incidents_total'] = Counter(
                'vaulytica_incidents_total',
                'Total incidents',
                ['severity', 'status'],
                registry=self.registry
            )

            self.metrics['incidents_active'] = Gauge(
                'vaulytica_incidents_active',
                'Currently active incidents',
                ['severity'],
                registry=self.registry
            )

            # Threat metrics
            self.metrics['threats_detected_total'] = Counter(
                'vaulytica_threats_detected_total',
                'Total threats detected',
                ['threat_type', 'severity'],
                registry=self.registry
            )

            self.metrics['threat_response_duration_seconds'] = Histogram(
                'vaulytica_threat_response_duration_seconds',
                'Threat response duration in seconds',
                ['threat_type'],
                buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 300.0],
                registry=self.registry
            )

            # Workflow metrics
            self.metrics['workflow_executions_total'] = Counter(
                'vaulytica_workflow_executions_total',
                'Total workflow executions',
                ['workflow_id', 'status'],
                registry=self.registry
            )

            self.metrics['workflow_execution_duration_seconds'] = Histogram(
                'vaulytica_workflow_execution_duration_seconds',
                'Workflow execution duration in seconds',
                ['workflow_id'],
                buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0],
                registry=self.registry
            )

            # System metrics
            self.metrics['system_cpu_usage'] = Gauge(
                'vaulytica_system_cpu_usage',
                'System CPU usage percentage',
                registry=self.registry
            )

            self.metrics['system_memory_usage'] = Gauge(
                'vaulytica_system_memory_usage',
                'System memory usage percentage',
                registry=self.registry
            )

            self.metrics['system_disk_usage'] = Gauge(
                'vaulytica_system_disk_usage',
                'System disk usage percentage',
                registry=self.registry
            )

            # Database metrics
            self.metrics['db_connections_active'] = Gauge(
                'vaulytica_db_connections_active',
                'Active database connections',
                registry=self.registry
            )

            self.metrics['db_query_duration_seconds'] = Histogram(
                'vaulytica_db_query_duration_seconds',
                'Database query duration in seconds',
                ['query_type'],
                buckets=[0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
                registry=self.registry
            )

    def increment_counter(self, metric_name: str, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        """Increment a counter metric"""
        if self.enable_prometheus and metric_name in self.metrics:
            if labels:
                self.metrics[metric_name].labels(**labels).inc(value)
            else:
                self.metrics[metric_name].inc(value)
        else:
            # Store in custom metrics
            if metric_name not in self.custom_metrics:
                self.custom_metrics[metric_name] = []
            self.custom_metrics[metric_name].append({
                'value': value,
                'labels': labels,
                'timestamp': datetime.utcnow().isoformat()
            })

    def set_gauge(self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge metric value"""
        if self.enable_prometheus and metric_name in self.metrics:
            if labels:
                self.metrics[metric_name].labels(**labels).set(value)
            else:
                self.metrics[metric_name].set(value)
        else:
            # Store in custom metrics
            if metric_name not in self.custom_metrics:
                self.custom_metrics[metric_name] = []
            self.custom_metrics[metric_name].append({
                'value': value,
                'labels': labels,
                'timestamp': datetime.utcnow().isoformat()
            })

    def observe_histogram(self, metric_name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Observe a histogram metric value"""
        if self.enable_prometheus and metric_name in self.metrics:
            if labels:
                self.metrics[metric_name].labels(**labels).observe(value)
            else:
                self.metrics[metric_name].observe(value)
        else:
            # Store in custom metrics
            if metric_name not in self.custom_metrics:
                self.custom_metrics[metric_name] = []
            self.custom_metrics[metric_name].append({
                'value': value,
                'labels': labels,
                'timestamp': datetime.utcnow().isoformat()
            })

    def record_http_request(self, method: str, endpoint: str, status: int, duration: float) -> None:
        """Record HTTP request metrics"""
        self.increment_counter('http_requests_total', {'method': method, 'endpoint': endpoint, 'status': str(status)})
        self.observe_histogram('http_request_duration_seconds', duration, {'method': method, 'endpoint': endpoint})

    def record_agent_execution(self, agent_type: str, status: str, duration: float) -> None:
        """Record agent execution metrics"""
        self.increment_counter('agent_executions_total', {'agent_type': agent_type, 'status': status})
        self.observe_histogram('agent_execution_duration_seconds', duration, {'agent_type': agent_type})

    def record_incident(self, severity: str, status: str) -> None:
        """Record incident metrics"""
        self.increment_counter('incidents_total', {'severity': severity, 'status': status})

    def update_active_incidents(self, severity: str, count: int) -> None:
        """Update active incidents gauge"""
        self.set_gauge('incidents_active', count, {'severity': severity})

    def record_threat_detection(self, threat_type: str, severity: str) -> None:
        """Record threat detection metrics"""
        self.increment_counter('threats_detected_total', {'threat_type': threat_type, 'severity': severity})

    def record_threat_response(self, threat_type: str, duration: float) -> None:
        """Record threat response metrics"""
        self.observe_histogram('threat_response_duration_seconds', duration, {'threat_type': threat_type})

    def record_workflow_execution(self, workflow_id: str, status: str, duration: float) -> None:
        """Record workflow execution metrics"""
        self.increment_counter('workflow_executions_total', {'workflow_id': workflow_id, 'status': status})
        self.observe_histogram('workflow_execution_duration_seconds', duration, {'workflow_id': workflow_id})

    def update_system_metrics(self, cpu: float, memory: float, disk: float) -> None:
        """Update system resource metrics"""
        self.set_gauge('system_cpu_usage', cpu)
        self.set_gauge('system_memory_usage', memory)
        self.set_gauge('system_disk_usage', disk)

    def export_prometheus_metrics(self) -> tuple[bytes, str]:
        """Export metrics in Prometheus format"""
        if self.enable_prometheus:
            return generate_latest(self.registry), CONTENT_TYPE_LATEST
        else:
            return b"Prometheus not available", "text/plain"

    def get_custom_metrics(self) -> Dict[str, Any]:
        """Get custom metrics"""
        return self.custom_metrics

    def clear_custom_metrics(self) -> None:
        """Clear custom metrics"""
        self.custom_metrics.clear()


def timed_metric(metric_name: str, labels: Optional[Dict[str, str]] = None) -> None:
    """
    Decorator to automatically record execution time as a histogram metric.

    Args:
        metric_name: Name of the histogram metric
        labels: Optional labels for the metric
    """
    def decorator(func: Callable) -> Callable:
        """Decorator function for tracking metrics."""
        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            """Synchronous wrapper for metric tracking."""
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                get_metrics_collector().observe_histogram(metric_name, duration, labels)
                return result
            except Exception as e:
                duration = time.time() - start_time
                get_metrics_collector().observe_histogram(metric_name, duration, labels)
                raise

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                get_metrics_collector().observe_histogram(metric_name, duration, labels)
                return result
            except Exception as e:
                duration = time.time() - start_time
                get_metrics_collector().observe_histogram(metric_name, duration, labels)
                raise

        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector
