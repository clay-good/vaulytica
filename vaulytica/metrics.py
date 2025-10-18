import time
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.logger import get_logger

logger = get_logger(__name__)


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class MetricValue:
    """A single metric value with timestamp."""
    value: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Collect and aggregate metrics for monitoring."""
    
    def __init__(self, retention_hours: int = 24):
        """Initialize metrics collector.
        
        Args:
            retention_hours: How long to retain metric history
        """
        self.retention_hours = retention_hours
        self._lock = Lock()
        
        # Counters (monotonically increasing)
        self._counters: Dict[str, float] = defaultdict(float)
        
        # Gauges (point-in-time values)
        self._gauges: Dict[str, float] = defaultdict(float)
        
        # Histograms (distribution of values)
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        
        # Time series data (for trends)
        self._timeseries: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Analysis metrics
        self.analysis_count = 0
        self.analysis_errors = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.total_tokens_used = 0
        self.total_cost_usd = 0.0
        
        # Performance metrics
        self.analysis_latencies: List[float] = []
        self.api_latencies: List[float] = []
        
        # Risk metrics
        self.risk_scores: List[float] = []
        self.high_risk_events = 0  # risk >= 7
        self.medium_risk_events = 0  # 4 <= risk < 7
        self.low_risk_events = 0  # risk < 4
        
        # Platform metrics
        self.events_by_platform: Dict[str, int] = defaultdict(int)
        self.errors_by_platform: Dict[str, int] = defaultdict(int)
        
        # MITRE ATT&CK metrics
        self.techniques_detected: Dict[str, int] = defaultdict(int)
        
        logger.info("Metrics collector initialized")
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric."""
        with self._lock:
            key = self._make_key(name, labels)
            self._counters[key] += value
            self._record_timeseries(name, self._counters[key], labels)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric."""
        with self._lock:
            key = self._make_key(name, labels)
            self._gauges[key] = value
            self._record_timeseries(name, value, labels)
    
    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a histogram observation."""
        with self._lock:
            key = self._make_key(name, labels)
            self._histograms[key].append(value)
            self._record_timeseries(name, value, labels)
            
            # Limit histogram size
            if len(self._histograms[key]) > 10000:
                self._histograms[key] = self._histograms[key][-5000:]
    
    def record_analysis(
        self,
        platform: str,
        risk_score: float,
        latency_seconds: float,
        tokens_used: int,
        cached: bool = False,
        error: bool = False,
        mitre_techniques: Optional[List[str]] = None
    ):
        """Record metrics for a completed analysis."""
        with self._lock:
            # Basic counters
            self.analysis_count += 1
            self.events_by_platform[platform] += 1
            
            if error:
                self.analysis_errors += 1
                self.errors_by_platform[platform] += 1
                return
            
            # Cache metrics
            if cached:
                self.cache_hits += 1
            else:
                self.cache_misses += 1
            
            # Token and cost tracking
            self.total_tokens_used += tokens_used
            # Approximate cost: $0.25 per 1M input tokens, $1.25 per 1M output tokens (Haiku)
            # Simplified: assume 50/50 split
            cost = (tokens_used / 1_000_000) * 0.75
            self.total_cost_usd += cost
            
            # Performance metrics
            self.analysis_latencies.append(latency_seconds)
            if len(self.analysis_latencies) > 1000:
                self.analysis_latencies = self.analysis_latencies[-500:]
            
            # Risk metrics
            self.risk_scores.append(risk_score)
            if len(self.risk_scores) > 1000:
                self.risk_scores = self.risk_scores[-500:]
            
            if risk_score >= 7:
                self.high_risk_events += 1
            elif risk_score >= 4:
                self.medium_risk_events += 1
            else:
                self.low_risk_events += 1
            
            # MITRE ATT&CK tracking
            if mitre_techniques:
                for technique in mitre_techniques:
                    self.techniques_detected[technique] += 1
            
            # Record as metrics
            self.increment_counter("vaulytica_analyses_total", labels={"platform": platform})
            self.observe_histogram("vaulytica_analysis_duration_seconds", latency_seconds, {"platform": platform})
            self.observe_histogram("vaulytica_risk_score", risk_score, {"platform": platform})
            self.increment_counter("vaulytica_tokens_total", tokens_used, {"platform": platform})
    
    def record_api_request(self, endpoint: str, method: str, status_code: int, latency_seconds: float):
        """Record API request metrics."""
        with self._lock:
            self.api_latencies.append(latency_seconds)
            if len(self.api_latencies) > 1000:
                self.api_latencies = self.api_latencies[-500:]
            
            labels = {
                "endpoint": endpoint,
                "method": method,
                "status": str(status_code)
            }
            self.increment_counter("vaulytica_api_requests_total", labels=labels)
            self.observe_histogram("vaulytica_api_duration_seconds", latency_seconds, labels)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics."""
        with self._lock:
            cache_hit_rate = 0.0
            if self.analysis_count > 0:
                cache_hit_rate = (self.cache_hits / self.analysis_count) * 100
            
            avg_latency = 0.0
            p95_latency = 0.0
            p99_latency = 0.0
            if self.analysis_latencies:
                avg_latency = sum(self.analysis_latencies) / len(self.analysis_latencies)
                sorted_latencies = sorted(self.analysis_latencies)
                p95_idx = int(len(sorted_latencies) * 0.95)
                p99_idx = int(len(sorted_latencies) * 0.99)
                p95_latency = sorted_latencies[p95_idx] if p95_idx < len(sorted_latencies) else 0
                p99_latency = sorted_latencies[p99_idx] if p99_idx < len(sorted_latencies) else 0
            
            avg_risk = 0.0
            if self.risk_scores:
                avg_risk = sum(self.risk_scores) / len(self.risk_scores)
            
            return {
                "analysis": {
                    "total_analyses": self.analysis_count,
                    "errors": self.analysis_errors,
                    "error_rate": (self.analysis_errors / max(self.analysis_count, 1)) * 100,
                    "by_platform": dict(self.events_by_platform),
                },
                "cache": {
                    "hits": self.cache_hits,
                    "misses": self.cache_misses,
                    "hit_rate_percent": cache_hit_rate,
                },
                "performance": {
                    "avg_latency_seconds": round(avg_latency, 3),
                    "p95_latency_seconds": round(p95_latency, 3),
                    "p99_latency_seconds": round(p99_latency, 3),
                },
                "cost": {
                    "total_tokens": self.total_tokens_used,
                    "total_cost_usd": round(self.total_cost_usd, 4),
                    "avg_tokens_per_analysis": self.total_tokens_used // max(self.analysis_count, 1),
                },
                "risk": {
                    "average_risk_score": round(avg_risk, 2),
                    "high_risk_events": self.high_risk_events,
                    "medium_risk_events": self.medium_risk_events,
                    "low_risk_events": self.low_risk_events,
                },
                "threats": {
                    "top_mitre_techniques": sorted(
                        self.techniques_detected.items(),
                        key=lambda x: x[1],
                        reverse=True
                    )[:10],
                },
            }
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        # Help and type declarations
        metrics_meta = [
            ("vaulytica_analyses_total", "counter", "Total number of security analyses performed"),
            ("vaulytica_analysis_errors_total", "counter", "Total number of analysis errors"),
            ("vaulytica_cache_hits_total", "counter", "Total number of cache hits"),
            ("vaulytica_cache_misses_total", "counter", "Total number of cache misses"),
            ("vaulytica_tokens_total", "counter", "Total number of AI tokens used"),
            ("vaulytica_cost_usd_total", "counter", "Total cost in USD"),
            ("vaulytica_high_risk_events_total", "counter", "Total high-risk events (score >= 7)"),
            ("vaulytica_analysis_duration_seconds", "histogram", "Analysis duration in seconds"),
            ("vaulytica_risk_score", "histogram", "Risk score distribution"),
        ]
        
        for name, mtype, help_text in metrics_meta:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} {mtype}")
        
        # Export counter values
        lines.append(f"vaulytica_analyses_total {self.analysis_count}")
        lines.append(f"vaulytica_analysis_errors_total {self.analysis_errors}")
        lines.append(f"vaulytica_cache_hits_total {self.cache_hits}")
        lines.append(f"vaulytica_cache_misses_total {self.cache_misses}")
        lines.append(f"vaulytica_tokens_total {self.total_tokens_used}")
        lines.append(f"vaulytica_cost_usd_total {self.total_cost_usd:.4f}")
        lines.append(f"vaulytica_high_risk_events_total {self.high_risk_events}")
        
        # Export by platform
        for platform, count in self.events_by_platform.items():
            lines.append(f'vaulytica_analyses_total{{platform="{platform}"}} {count}')
        
        # Export histogram summaries
        if self.analysis_latencies:
            sorted_latencies = sorted(self.analysis_latencies)
            lines.append(f"vaulytica_analysis_duration_seconds_sum {sum(sorted_latencies):.3f}")
            lines.append(f"vaulytica_analysis_duration_seconds_count {len(sorted_latencies)}")
        
        if self.risk_scores:
            lines.append(f"vaulytica_risk_score_sum {sum(self.risk_scores):.2f}")
            lines.append(f"vaulytica_risk_score_count {len(self.risk_scores)}")
        
        return "\n".join(lines) + "\n"
    
    def _make_key(self, name: str, labels: Optional[Dict[str, str]]) -> str:
        """Create a unique key for a metric with labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    def _record_timeseries(self, name: str, value: float, labels: Optional[Dict[str, str]]):
        """Record a value in the time series."""
        key = self._make_key(name, labels)
        self._timeseries[key].append(MetricValue(value=value, labels=labels or {}))
        
        # Clean old data
        cutoff = datetime.utcnow() - timedelta(hours=self.retention_hours)
        while self._timeseries[key] and self._timeseries[key][0].timestamp < cutoff:
            self._timeseries[key].popleft()


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get the global metrics collector instance."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def reset_metrics_collector():
    """Reset the global metrics collector (mainly for testing)."""
    global _metrics_collector
    _metrics_collector = MetricsCollector()

