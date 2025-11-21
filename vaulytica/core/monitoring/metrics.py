"""Metrics collection and Prometheus export."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from threading import Lock

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Counter:
    """Simple counter metric."""

    name: str
    help_text: str
    value: int = 0
    labels: Dict[str, str] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock, init=False)

    def inc(self, amount: int = 1) -> None:
        """Increment counter."""
        with self.lock:
            self.value += amount

    def get(self) -> int:
        """Get current value."""
        with self.lock:
            return self.value

    def reset(self) -> None:
        """Reset counter to zero."""
        with self.lock:
            self.value = 0


@dataclass
class Gauge:
    """Simple gauge metric."""

    name: str
    help_text: str
    value: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock, init=False)

    def set(self, value: float) -> None:
        """Set gauge value."""
        with self.lock:
            self.value = value

    def inc(self, amount: float = 1.0) -> None:
        """Increment gauge."""
        with self.lock:
            self.value += amount

    def dec(self, amount: float = 1.0) -> None:
        """Decrement gauge."""
        with self.lock:
            self.value -= amount

    def get(self) -> float:
        """Get current value."""
        with self.lock:
            return self.value


@dataclass
class Histogram:
    """Simple histogram metric."""

    name: str
    help_text: str
    buckets: List[float] = field(default_factory=lambda: [0.1, 0.5, 1.0, 2.5, 5.0, 10.0])
    counts: Dict[float, int] = field(default_factory=dict)
    sum: float = 0.0
    count: int = 0
    labels: Dict[str, str] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock, init=False)

    def __post_init__(self):
        """Initialize bucket counts."""
        for bucket in self.buckets:
            self.counts[bucket] = 0
        self.counts[float("inf")] = 0

    def observe(self, value: float) -> None:
        """Observe a value."""
        with self.lock:
            self.sum += value
            self.count += 1

            # Update bucket counts
            for bucket in sorted(self.counts.keys()):
                if value <= bucket:
                    self.counts[bucket] += 1

    def get_stats(self) -> Dict[str, float]:
        """Get histogram statistics."""
        with self.lock:
            return {
                "sum": self.sum,
                "count": self.count,
                "avg": self.sum / self.count if self.count > 0 else 0.0,
            }


class MetricsCollector:
    """Collects and exports metrics."""

    def __init__(self):
        """Initialize metrics collector."""
        self.counters: Dict[str, Counter] = {}
        self.gauges: Dict[str, Gauge] = {}
        self.histograms: Dict[str, Histogram] = {}
        self.lock = Lock()

        # Initialize standard metrics
        self._init_standard_metrics()

        logger.info("metrics_collector_initialized")

    def _init_standard_metrics(self) -> None:
        """Initialize standard metrics."""
        # Scan metrics
        self.register_counter(
            "vaulytica_scans_total",
            "Total number of scans performed",
        )
        self.register_counter(
            "vaulytica_files_scanned_total",
            "Total number of files scanned",
        )
        self.register_counter(
            "vaulytica_pii_findings_total",
            "Total number of PII findings",
        )
        self.register_counter(
            "vaulytica_external_shares_total",
            "Total number of external shares found",
        )

        # API metrics
        self.register_counter(
            "vaulytica_api_calls_total",
            "Total number of API calls",
        )
        self.register_counter(
            "vaulytica_api_errors_total",
            "Total number of API errors",
        )
        self.register_histogram(
            "vaulytica_api_duration_seconds",
            "API call duration in seconds",
        )

        # System metrics
        self.register_gauge(
            "vaulytica_scan_duration_seconds",
            "Duration of last scan in seconds",
        )
        self.register_gauge(
            "vaulytica_quota_usage",
            "Current API quota usage",
        )

    def register_counter(self, name: str, help_text: str, labels: Optional[Dict[str, str]] = None) -> Counter:
        """Register a counter metric.

        Args:
            name: Metric name
            help_text: Help text
            labels: Optional labels

        Returns:
            Counter instance
        """
        with self.lock:
            if name not in self.counters:
                self.counters[name] = Counter(
                    name=name,
                    help_text=help_text,
                    labels=labels or {},
                )
            return self.counters[name]

    def register_gauge(self, name: str, help_text: str, labels: Optional[Dict[str, str]] = None) -> Gauge:
        """Register a gauge metric.

        Args:
            name: Metric name
            help_text: Help text
            labels: Optional labels

        Returns:
            Gauge instance
        """
        with self.lock:
            if name not in self.gauges:
                self.gauges[name] = Gauge(
                    name=name,
                    help_text=help_text,
                    labels=labels or {},
                )
            return self.gauges[name]

    def register_histogram(
        self,
        name: str,
        help_text: str,
        buckets: Optional[List[float]] = None,
        labels: Optional[Dict[str, str]] = None,
    ) -> Histogram:
        """Register a histogram metric.

        Args:
            name: Metric name
            help_text: Help text
            buckets: Histogram buckets
            labels: Optional labels

        Returns:
            Histogram instance
        """
        with self.lock:
            if name not in self.histograms:
                self.histograms[name] = Histogram(
                    name=name,
                    help_text=help_text,
                    buckets=buckets or [0.1, 0.5, 1.0, 2.5, 5.0, 10.0],
                    labels=labels or {},
                )
            return self.histograms[name]

    def get_counter(self, name: str) -> Optional[Counter]:
        """Get a counter by name."""
        return self.counters.get(name)

    def get_gauge(self, name: str) -> Optional[Gauge]:
        """Get a gauge by name."""
        return self.gauges.get(name)

    def get_histogram(self, name: str) -> Optional[Histogram]:
        """Get a histogram by name."""
        return self.histograms.get(name)

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format.

        Returns:
            Prometheus-formatted metrics
        """
        lines = []

        # Export counters
        for counter in self.counters.values():
            lines.append(f"# HELP {counter.name} {counter.help_text}")
            lines.append(f"# TYPE {counter.name} counter")

            label_str = self._format_labels(counter.labels)
            lines.append(f"{counter.name}{label_str} {counter.get()}")

        # Export gauges
        for gauge in self.gauges.values():
            lines.append(f"# HELP {gauge.name} {gauge.help_text}")
            lines.append(f"# TYPE {gauge.name} gauge")

            label_str = self._format_labels(gauge.labels)
            lines.append(f"{gauge.name}{label_str} {gauge.get()}")

        # Export histograms
        for histogram in self.histograms.values():
            lines.append(f"# HELP {histogram.name} {histogram.help_text}")
            lines.append(f"# TYPE {histogram.name} histogram")

            label_str = self._format_labels(histogram.labels)

            # Export buckets
            for bucket, count in sorted(histogram.counts.items()):
                bucket_label = f'{{le="{bucket}"}}'
                lines.append(f"{histogram.name}_bucket{bucket_label} {count}")

            # Export sum and count
            lines.append(f"{histogram.name}_sum{label_str} {histogram.sum}")
            lines.append(f"{histogram.name}_count{label_str} {histogram.count}")

        return "\n".join(lines) + "\n"

    def _format_labels(self, labels: Dict[str, str]) -> str:
        """Format labels for Prometheus.

        Args:
            labels: Label dictionary

        Returns:
            Formatted label string
        """
        if not labels:
            return ""

        label_pairs = [f'{k}="{v}"' for k, v in labels.items()]
        return "{" + ",".join(label_pairs) + "}"

    def get_summary(self) -> Dict[str, any]:
        """Get metrics summary.

        Returns:
            Dictionary of metrics
        """
        summary = {
            "counters": {},
            "gauges": {},
            "histograms": {},
        }

        for name, counter in self.counters.items():
            summary["counters"][name] = counter.get()

        for name, gauge in self.gauges.items():
            summary["gauges"][name] = gauge.get()

        for name, histogram in self.histograms.items():
            summary["histograms"][name] = histogram.get_stats()

        return summary


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance.

    Returns:
        MetricsCollector instance
    """
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector

