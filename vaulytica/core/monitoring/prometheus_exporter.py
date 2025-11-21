"""
Prometheus metrics exporter for Vaulytica.

Exports metrics in Prometheus format for monitoring and observability.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Counter:
    """Prometheus counter metric."""
    name: str
    help: str
    value: int = 0
    labels: Dict[str, str] = field(default_factory=dict)

    def inc(self, amount: int = 1) -> None:
        """Increment counter."""
        self.value += amount

    def reset(self) -> None:
        """Reset counter to zero."""
        self.value = 0


@dataclass
class Gauge:
    """Prometheus gauge metric."""
    name: str
    help: str
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)

    def set(self, value: float) -> None:
        """Set gauge value."""
        self.value = value

    def inc(self, amount: float = 1.0) -> None:
        """Increment gauge."""
        self.value += amount

    def dec(self, amount: float = 1.0) -> None:
        """Decrement gauge."""
        self.value -= amount


@dataclass
class Histogram:
    """Prometheus histogram metric."""
    name: str
    help: str
    buckets: List[float] = field(default_factory=lambda: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    observations: List[float] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)

    def observe(self, value: float) -> None:
        """Record an observation."""
        self.observations.append(value)

    def get_buckets(self) -> Dict[float, int]:
        """Get bucket counts."""
        bucket_counts = {}
        for bucket in self.buckets:
            bucket_counts[bucket] = sum(1 for obs in self.observations if obs <= bucket)
        bucket_counts['+Inf'] = len(self.observations)
        return bucket_counts

    def get_sum(self) -> float:
        """Get sum of all observations."""
        return sum(self.observations)

    def get_count(self) -> int:
        """Get count of observations."""
        return len(self.observations)


class PrometheusExporter:
    """
    Prometheus metrics exporter for Vaulytica.

    Tracks and exports metrics in Prometheus format.
    """

    def __init__(self):
        """Initialize Prometheus exporter."""
        self.counters: Dict[str, Counter] = {}
        self.gauges: Dict[str, Gauge] = {}
        self.histograms: Dict[str, Histogram] = {}
        self.start_time = time.time()

        # Initialize default metrics
        self._init_default_metrics()

        logger.info("prometheus_exporter_initialized")

    def _init_default_metrics(self) -> None:
        """Initialize default metrics."""
        # Scan metrics
        self.register_counter(
            "vaulytica_scans_total",
            "Total number of scans performed",
            labels={"scan_type": ""}
        )
        self.register_counter(
            "vaulytica_files_scanned_total",
            "Total number of files scanned",
            labels={"scan_type": ""}
        )
        self.register_counter(
            "vaulytica_issues_found_total",
            "Total number of issues found",
            labels={"issue_type": ""}
        )
        self.register_counter(
            "vaulytica_pii_detections_total",
            "Total number of PII detections",
            labels={"pii_type": ""}
        )

        # Performance metrics
        self.register_histogram(
            "vaulytica_scan_duration_seconds",
            "Duration of scans in seconds",
            labels={"scan_type": ""}
        )
        self.register_histogram(
            "vaulytica_api_request_duration_seconds",
            "Duration of API requests in seconds",
            labels={"api": ""}
        )

        # Current state metrics
        self.register_gauge(
            "vaulytica_active_scans",
            "Number of currently active scans"
        )
        self.register_gauge(
            "vaulytica_cache_hit_rate",
            "Cache hit rate (0-1)"
        )
        self.register_gauge(
            "vaulytica_cache_size",
            "Number of items in cache"
        )

        # Error metrics
        self.register_counter(
            "vaulytica_errors_total",
            "Total number of errors",
            labels={"error_type": ""}
        )
        self.register_counter(
            "vaulytica_api_errors_total",
            "Total number of API errors",
            labels={"api": "", "status_code": ""}
        )

        # Alert metrics
        self.register_counter(
            "vaulytica_alerts_sent_total",
            "Total number of alerts sent",
            labels={"alert_type": "", "destination": ""}
        )

    def register_counter(self, name: str, help: str, labels: Optional[Dict[str, str]] = None) -> Counter:
        """Register a counter metric."""
        counter = Counter(name=name, help=help, labels=labels or {})
        self.counters[name] = counter
        return counter

    def register_gauge(self, name: str, help: str, labels: Optional[Dict[str, str]] = None) -> Gauge:
        """Register a gauge metric."""
        gauge = Gauge(name=name, help=help, labels=labels or {})
        self.gauges[name] = gauge
        return gauge

    def register_histogram(self, name: str, help: str, buckets: Optional[List[float]] = None,
                          labels: Optional[Dict[str, str]] = None) -> Histogram:
        """Register a histogram metric."""
        histogram = Histogram(name=name, help=help, buckets=buckets or [], labels=labels or {})
        self.histograms[name] = histogram
        return histogram

    def inc_counter(self, name: str, amount: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        """Increment a counter."""
        if name in self.counters:
            counter = self.counters[name]
            if labels:
                counter.labels.update(labels)
            counter.inc(amount)
        else:
            logger.warning("counter_not_found", name=name)

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge value."""
        if name in self.gauges:
            gauge = self.gauges[name]
            if labels:
                gauge.labels.update(labels)
            gauge.set(value)
        else:
            logger.warning("gauge_not_found", name=name)

    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        """Record a histogram observation."""
        if name in self.histograms:
            histogram = self.histograms[name]
            if labels:
                histogram.labels.update(labels)
            histogram.observe(value)
        else:
            logger.warning("histogram_not_found", name=name)

    def record_scan_start(self, scan_type: str) -> float:
        """Record scan start and return start time."""
        self.inc_counter("vaulytica_scans_total", labels={"scan_type": scan_type})
        self.set_gauge("vaulytica_active_scans",
                      self.gauges["vaulytica_active_scans"].value + 1)
        return time.time()

    def record_scan_end(self, scan_type: str, start_time: float, files_scanned: int, issues_found: int) -> None:
        """Record scan completion."""
        duration = time.time() - start_time
        self.observe_histogram("vaulytica_scan_duration_seconds", duration,
                              labels={"scan_type": scan_type})
        self.inc_counter("vaulytica_files_scanned_total", files_scanned,
                        labels={"scan_type": scan_type})
        self.inc_counter("vaulytica_issues_found_total", issues_found,
                        labels={"issue_type": "all"})
        self.set_gauge("vaulytica_active_scans",
                      max(0, self.gauges["vaulytica_active_scans"].value - 1))

    def record_pii_detection(self, pii_type: str, count: int = 1) -> None:
        """Record PII detection."""
        self.inc_counter("vaulytica_pii_detections_total", count,
                        labels={"pii_type": pii_type})

    def record_api_request(self, api: str, duration: float, status_code: Optional[int] = None) -> None:
        """Record API request."""
        self.observe_histogram("vaulytica_api_request_duration_seconds", duration,
                              labels={"api": api})
        if status_code and status_code >= 400:
            self.inc_counter("vaulytica_api_errors_total",
                           labels={"api": api, "status_code": str(status_code)})

    def record_error(self, error_type: str) -> None:
        """Record an error."""
        self.inc_counter("vaulytica_errors_total", labels={"error_type": error_type})

    def record_alert(self, alert_type: str, destination: str) -> None:
        """Record an alert sent."""
        self.inc_counter("vaulytica_alerts_sent_total",
                        labels={"alert_type": alert_type, "destination": destination})

    def update_cache_metrics(self, hit_rate: float, size: int) -> None:
        """Update cache metrics."""
        self.set_gauge("vaulytica_cache_hit_rate", hit_rate)
        self.set_gauge("vaulytica_cache_size", float(size))

    def export_metrics(self) -> str:
        """
        Export metrics in Prometheus format.

        Returns:
            Metrics in Prometheus text format
        """
        lines = []

        # Add process info
        lines.append("# HELP vaulytica_info Vaulytica information")
        lines.append("# TYPE vaulytica_info gauge")
        lines.append('vaulytica_info{version="1.0"} 1')
        lines.append("")

        # Add uptime
        uptime = time.time() - self.start_time
        lines.append("# HELP vaulytica_uptime_seconds Uptime in seconds")
        lines.append("# TYPE vaulytica_uptime_seconds counter")
        lines.append(f"vaulytica_uptime_seconds {uptime:.2f}")
        lines.append("")

        # Export counters
        for counter in self.counters.values():
            lines.append(f"# HELP {counter.name} {counter.help}")
            lines.append(f"# TYPE {counter.name} counter")
            label_str = self._format_labels(counter.labels)
            lines.append(f"{counter.name}{label_str} {counter.value}")
            lines.append("")

        # Export gauges
        for gauge in self.gauges.values():
            lines.append(f"# HELP {gauge.name} {gauge.help}")
            lines.append(f"# TYPE {gauge.name} gauge")
            label_str = self._format_labels(gauge.labels)
            lines.append(f"{gauge.name}{label_str} {gauge.value}")
            lines.append("")

        # Export histograms
        for histogram in self.histograms.values():
            lines.append(f"# HELP {histogram.name} {histogram.help}")
            lines.append(f"# TYPE {histogram.name} histogram")
            label_str = self._format_labels(histogram.labels)

            # Buckets
            for bucket, count in histogram.get_buckets().items():
                bucket_label = f'le="{bucket}"'
                if histogram.labels:
                    bucket_label = f'{self._format_labels(histogram.labels, include_braces=False)},{bucket_label}'
                lines.append(f"{histogram.name}_bucket{{{bucket_label}}} {count}")

            # Sum and count
            lines.append(f"{histogram.name}_sum{label_str} {histogram.get_sum():.6f}")
            lines.append(f"{histogram.name}_count{label_str} {histogram.get_count()}")
            lines.append("")

        return "\n".join(lines)

    def _format_labels(self, labels: Dict[str, str], include_braces: bool = True) -> str:
        """Format labels for Prometheus output."""
        if not labels or all(v == "" for v in labels.values()):
            return ""

        # Filter out empty labels
        filtered_labels = {k: v for k, v in labels.items() if v != ""}
        if not filtered_labels:
            return ""

        label_pairs = [f'{k}="{v}"' for k, v in filtered_labels.items()]
        label_str = ",".join(label_pairs)

        if include_braces:
            return f"{{{label_str}}}"
        return label_str

    def export_to_file(self, filepath: str) -> None:
        """Export metrics to a file."""
        try:
            with open(filepath, 'w') as f:
                f.write(self.export_metrics())
            logger.info("metrics_exported_to_file", filepath=filepath)
        except Exception as e:
            logger.error("failed_to_export_metrics", filepath=filepath, error=str(e))
            raise

    def get_summary(self) -> Dict:
        """Get a summary of current metrics."""
        return {
            "uptime_seconds": time.time() - self.start_time,
            "total_scans": self.counters.get("vaulytica_scans_total", Counter("", "")).value,
            "total_files_scanned": self.counters.get("vaulytica_files_scanned_total", Counter("", "")).value,
            "total_issues_found": self.counters.get("vaulytica_issues_found_total", Counter("", "")).value,
            "total_pii_detections": self.counters.get("vaulytica_pii_detections_total", Counter("", "")).value,
            "total_errors": self.counters.get("vaulytica_errors_total", Counter("", "")).value,
            "active_scans": self.gauges.get("vaulytica_active_scans", Gauge("", "")).value,
            "cache_hit_rate": self.gauges.get("vaulytica_cache_hit_rate", Gauge("", "")).value,
            "cache_size": self.gauges.get("vaulytica_cache_size", Gauge("", "")).value,
        }


# Global exporter instance
_exporter: Optional[PrometheusExporter] = None


def get_exporter() -> PrometheusExporter:
    """Get the global Prometheus exporter instance."""
    global _exporter
    if _exporter is None:
        _exporter = PrometheusExporter()
    return _exporter


def reset_exporter() -> None:
    """Reset the global exporter (useful for testing)."""
    global _exporter
    _exporter = None

