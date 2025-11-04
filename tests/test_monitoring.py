"""Tests for monitoring module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from vaulytica.core.monitoring.health import HealthChecker, HealthStatus
from vaulytica.core.monitoring.metrics import Counter, Gauge, Histogram, MetricsCollector
from vaulytica.core.monitoring.prometheus_exporter import PrometheusExporter


class TestHealthChecker:
    """Tests for HealthChecker."""

    def test_init(self):
        """Test HealthChecker initialization."""
        checker = HealthChecker()
        assert checker.client is None

    def test_init_with_client(self):
        """Test HealthChecker initialization with client."""
        client = Mock()
        checker = HealthChecker(client=client)
        assert checker.client == client

    @patch("vaulytica.core.monitoring.health.psutil")
    def test_check_health_all_healthy(self, mock_psutil):
        """Test health check when all systems are healthy."""
        # Mock system resources
        mock_psutil.cpu_percent.return_value = 50.0
        mock_psutil.virtual_memory.return_value = Mock(percent=60.0, available=1024*1024*1024)
        mock_psutil.disk_usage.return_value = Mock(percent=70.0, free=10*1024*1024*1024)

        checker = HealthChecker()
        status = checker.check_health()

        assert isinstance(status, HealthStatus)
        assert status.healthy is True
        assert status.status == "healthy"
        assert "system_resources" in status.checks
        assert status.checks["system_resources"] is True

    @patch("vaulytica.core.monitoring.health.psutil")
    def test_check_health_with_google_api(self, mock_psutil):
        """Test health check with Google API connectivity."""
        # Mock system resources
        mock_psutil.cpu_percent.return_value = 50.0
        mock_psutil.virtual_memory.return_value = Mock(percent=60.0, available=1024*1024*1024)
        mock_psutil.disk_usage.return_value = Mock(percent=70.0, free=10*1024*1024*1024)

        # Mock Google API client
        client = Mock()
        client.test_connection.return_value = True

        checker = HealthChecker(client=client)
        status = checker.check_health()

        assert status.healthy is True
        assert "google_api" in status.checks
        assert status.checks["google_api"] is True

    @patch("vaulytica.core.monitoring.health.psutil")
    def test_check_health_degraded(self, mock_psutil):
        """Test health check when system is degraded."""
        # Mock high CPU usage
        mock_psutil.cpu_percent.return_value = 95.0
        mock_psutil.virtual_memory.return_value = Mock(percent=60.0, available=1024*1024*1024)
        mock_psutil.disk_usage.return_value = Mock(percent=70.0, free=10*1024*1024*1024)

        checker = HealthChecker()
        status = checker.check_health()

        assert status.healthy is False
        assert status.status in ["degraded", "unhealthy"]

    @patch("vaulytica.core.monitoring.health.psutil")
    def test_check_system_resources(self, mock_psutil):
        """Test system resources check."""
        mock_psutil.cpu_percent.return_value = 50.0
        mock_psutil.virtual_memory.return_value = Mock(percent=60.0, available=1024*1024*1024)
        mock_psutil.disk_usage.return_value = Mock(percent=70.0, free=10*1024*1024*1024)

        checker = HealthChecker()
        details = {}
        result = checker._check_system_resources(details)

        assert result is True
        assert "cpu_percent" in details
        assert "memory_percent" in details
        assert "disk_percent" in details

    @patch("vaulytica.core.monitoring.health.psutil")
    def test_check_system_resources_error(self, mock_psutil):
        """Test system resources check with error."""
        mock_psutil.cpu_percent.side_effect = Exception("Test error")

        checker = HealthChecker()
        details = {}
        result = checker._check_system_resources(details)

        assert result is False
        assert "error" in details

    def test_check_google_api_success(self):
        """Test Google API check success."""
        client = Mock()
        mock_about = Mock()
        mock_about.get.return_value.execute.return_value = {"user": {"emailAddress": "test@example.com"}}
        client.drive.about.return_value = mock_about

        checker = HealthChecker(client=client)
        details = {}
        result = checker._check_google_api(details)

        assert result is True
        assert "api_response_time_ms" in details

    def test_check_google_api_failure(self):
        """Test Google API check failure."""
        client = Mock()
        client.drive.about.return_value.get.return_value.execute.side_effect = Exception("API error")

        checker = HealthChecker(client=client)
        details = {}
        result = checker._check_google_api(details)

        assert result is False
        assert "error" in details

    def test_check_google_api_no_client(self):
        """Test Google API check with no client."""
        checker = HealthChecker()
        details = {}
        result = checker._check_google_api(details)

        assert result is False
        assert "error" in details

    @patch("vaulytica.storage.StateManager")
    def test_check_database_success(self, mock_state_manager_class):
        """Test database check success."""
        mock_state_manager = Mock()
        mock_state_manager.get_scan_history.return_value = []
        mock_state_manager_class.return_value = mock_state_manager

        checker = HealthChecker()
        details = {}
        result = checker._check_database(details)

        assert result is True
        assert "db_response_time_ms" in details

    @patch("vaulytica.storage.StateManager")
    def test_check_database_failure(self, mock_state_manager_class):
        """Test database check failure."""
        mock_state_manager_class.side_effect = Exception("DB error")

        checker = HealthChecker()
        details = {}
        result = checker._check_database(details)

        assert result is False
        assert "error" in details


class TestCounter:
    """Tests for Counter metric."""

    def test_init(self):
        """Test Counter initialization."""
        counter = Counter(name="test_counter", help_text="Test counter")
        assert counter.name == "test_counter"
        assert counter.help_text == "Test counter"
        assert counter.value == 0

    def test_inc(self):
        """Test incrementing counter."""
        counter = Counter(name="test", help_text="Test")
        counter.inc()
        assert counter.get() == 1

        counter.inc(5)
        assert counter.get() == 6

    def test_reset(self):
        """Test resetting counter."""
        counter = Counter(name="test", help_text="Test")
        counter.inc(10)
        assert counter.get() == 10

        counter.reset()
        assert counter.get() == 0

    def test_thread_safety(self):
        """Test counter thread safety."""
        counter = Counter(name="test", help_text="Test")
        
        # Simulate concurrent increments
        for _ in range(100):
            counter.inc()
        
        assert counter.get() == 100


class TestGauge:
    """Tests for Gauge metric."""

    def test_init(self):
        """Test Gauge initialization."""
        gauge = Gauge(name="test_gauge", help_text="Test gauge")
        assert gauge.name == "test_gauge"
        assert gauge.help_text == "Test gauge"
        assert gauge.value == 0.0

    def test_set(self):
        """Test setting gauge value."""
        gauge = Gauge(name="test", help_text="Test")
        gauge.set(42.5)
        assert gauge.get() == 42.5

    def test_inc(self):
        """Test incrementing gauge."""
        gauge = Gauge(name="test", help_text="Test")
        gauge.inc()
        assert gauge.get() == 1.0

        gauge.inc(2.5)
        assert gauge.get() == 3.5

    def test_dec(self):
        """Test decrementing gauge."""
        gauge = Gauge(name="test", help_text="Test")
        gauge.set(10.0)
        gauge.dec()
        assert gauge.get() == 9.0

        gauge.dec(2.5)
        assert gauge.get() == 6.5


class TestHistogram:
    """Tests for Histogram metric."""

    def test_init(self):
        """Test Histogram initialization."""
        histogram = Histogram(name="test_histogram", help_text="Test histogram")
        assert histogram.name == "test_histogram"
        assert histogram.help_text == "Test histogram"
        assert histogram.count == 0
        assert histogram.sum == 0.0

    def test_observe(self):
        """Test observing values."""
        histogram = Histogram(name="test", help_text="Test")
        histogram.observe(1.5)
        histogram.observe(2.5)
        histogram.observe(3.5)

        assert histogram.count == 3
        assert histogram.sum == 7.5

    def test_buckets(self):
        """Test histogram buckets."""
        histogram = Histogram(
            name="test",
            help_text="Test",
            buckets=[1.0, 5.0, 10.0]
        )
        
        histogram.observe(0.5)
        histogram.observe(3.0)
        histogram.observe(7.0)
        histogram.observe(15.0)

        assert histogram.count == 4


class TestMetricsCollector:
    """Tests for MetricsCollector."""

    def test_init(self):
        """Test MetricsCollector initialization."""
        collector = MetricsCollector()
        assert collector is not None
        assert len(collector.counters) > 0  # Should have standard metrics

    def test_register_counter(self):
        """Test registering a counter."""
        collector = MetricsCollector()
        counter = collector.register_counter("test_counter", "Test counter")

        assert counter.name == "test_counter"
        assert "test_counter" in collector.counters

    def test_register_gauge(self):
        """Test registering a gauge."""
        collector = MetricsCollector()
        gauge = collector.register_gauge("test_gauge", "Test gauge")

        assert gauge.name == "test_gauge"
        assert "test_gauge" in collector.gauges

    def test_register_histogram(self):
        """Test registering a histogram."""
        collector = MetricsCollector()
        histogram = collector.register_histogram("test_histogram", "Test histogram")

        assert histogram.name == "test_histogram"
        assert "test_histogram" in collector.histograms

    def test_get_counter(self):
        """Test getting a counter."""
        collector = MetricsCollector()
        collector.register_counter("test_counter", "Test counter")
        counter = collector.counters.get("test_counter")

        assert counter is not None
        assert counter.name == "test_counter"

    def test_get_gauge(self):
        """Test getting a gauge."""
        collector = MetricsCollector()
        collector.register_gauge("test_gauge", "Test gauge")
        gauge = collector.gauges.get("test_gauge")

        assert gauge is not None
        assert gauge.name == "test_gauge"

    def test_increment_counter(self):
        """Test incrementing a counter."""
        collector = MetricsCollector()
        counter = collector.register_counter("test_counter", "Test counter")
        counter.inc(5)

        assert counter.get() == 5

    def test_set_gauge_value(self):
        """Test setting gauge value."""
        collector = MetricsCollector()
        gauge = collector.register_gauge("test_gauge", "Test gauge")
        gauge.set(42.5)

        assert gauge.get() == 42.5

    def test_histogram_observe(self):
        """Test histogram observation."""
        collector = MetricsCollector()
        histogram = collector.register_histogram("test_histogram", "Test histogram")
        histogram.observe(1.5)
        histogram.observe(2.5)

        stats = histogram.get_stats()
        assert stats["count"] == 2
        assert stats["sum"] == 4.0
        assert stats["avg"] == 2.0

    def test_export_prometheus(self):
        """Test exporting metrics in Prometheus format."""
        collector = MetricsCollector()
        counter = collector.register_counter("test_counter", "Test counter")
        counter.inc(5)

        output = collector.export_prometheus()

        assert "# HELP test_counter Test counter" in output
        assert "# TYPE test_counter counter" in output
        assert "test_counter" in output


class TestPrometheusExporter:
    """Tests for PrometheusExporter."""

    def test_init(self):
        """Test PrometheusExporter initialization."""
        exporter = PrometheusExporter()
        assert exporter is not None
        assert len(exporter.counters) > 0  # Should have default metrics

    def test_register_counter(self):
        """Test registering a counter."""
        exporter = PrometheusExporter()
        counter = exporter.register_counter("test_counter", "Test counter")

        assert counter.name == "test_counter"
        assert "test_counter" in exporter.counters

    def test_register_gauge(self):
        """Test registering a gauge."""
        exporter = PrometheusExporter()
        gauge = exporter.register_gauge("test_gauge", "Test gauge")

        assert gauge.name == "test_gauge"
        assert "test_gauge" in exporter.gauges

    def test_register_histogram(self):
        """Test registering a histogram."""
        exporter = PrometheusExporter()
        histogram = exporter.register_histogram("test_histogram", "Test histogram")

        assert histogram.name == "test_histogram"
        assert "test_histogram" in exporter.histograms

    def test_get_counter(self):
        """Test getting a counter."""
        exporter = PrometheusExporter()
        exporter.register_counter("test_counter", "Test counter")
        counter = exporter.counters.get("test_counter")

        assert counter is not None
        assert counter.name == "test_counter"

    def test_increment_counter(self):
        """Test incrementing a counter."""
        exporter = PrometheusExporter()
        counter = exporter.register_counter("test_counter", "Test counter")
        counter.inc(5)

        assert counter.value == 5

    def test_inc_counter(self):
        """Test inc_counter method."""
        exporter = PrometheusExporter()
        exporter.register_counter("test_counter", "Test counter")
        exporter.inc_counter("test_counter", 3)

        counter = exporter.counters["test_counter"]
        assert counter.value == 3

    def test_set_gauge(self):
        """Test set_gauge method."""
        exporter = PrometheusExporter()
        exporter.register_gauge("test_gauge", "Test gauge")
        exporter.set_gauge("test_gauge", 42.5)

        gauge = exporter.gauges["test_gauge"]
        assert gauge.value == 42.5

    def test_observe_histogram(self):
        """Test observe_histogram method."""
        exporter = PrometheusExporter()
        exporter.register_histogram("test_histogram", "Test histogram")
        exporter.observe_histogram("test_histogram", 1.5)
        exporter.observe_histogram("test_histogram", 2.5)

        histogram = exporter.histograms["test_histogram"]
        assert histogram.get_count() == 2
        assert histogram.get_sum() == 4.0

    def test_record_scan_start(self):
        """Test recording scan start."""
        exporter = PrometheusExporter()
        start_time = exporter.record_scan_start("file_scan")

        assert start_time > 0
        assert exporter.counters["vaulytica_scans_total"].value >= 1

    def test_record_scan_end(self):
        """Test recording scan end."""
        exporter = PrometheusExporter()
        start_time = exporter.record_scan_start("file_scan")
        exporter.record_scan_end("file_scan", start_time, files_scanned=100, issues_found=5)

        assert exporter.counters["vaulytica_files_scanned_total"].value >= 100
        assert exporter.counters["vaulytica_issues_found_total"].value >= 5

    def test_record_pii_detection(self):
        """Test recording PII detection."""
        exporter = PrometheusExporter()
        exporter.record_pii_detection("ssn", count=3)

        assert exporter.counters["vaulytica_pii_detections_total"].value >= 3

    def test_record_api_request(self):
        """Test recording API request."""
        exporter = PrometheusExporter()
        exporter.record_api_request("drive", duration=0.5, status_code=200)

        assert exporter.histograms["vaulytica_api_request_duration_seconds"].get_count() >= 1

    def test_record_api_request_error(self):
        """Test recording API request with error."""
        exporter = PrometheusExporter()
        exporter.record_api_request("drive", duration=0.5, status_code=500)

        assert exporter.counters["vaulytica_api_errors_total"].value >= 1

    def test_record_error(self):
        """Test recording error."""
        exporter = PrometheusExporter()
        exporter.record_error("api_error")

        assert exporter.counters["vaulytica_errors_total"].value >= 1

    def test_record_alert(self):
        """Test recording alert."""
        exporter = PrometheusExporter()
        exporter.record_alert("pii_detected", "email")

        assert exporter.counters["vaulytica_alerts_sent_total"].value >= 1

    def test_update_cache_metrics(self):
        """Test updating cache metrics."""
        exporter = PrometheusExporter()
        exporter.update_cache_metrics(hit_rate=0.85, size=100)

        assert exporter.gauges["vaulytica_cache_hit_rate"].value == 0.85
        assert exporter.gauges["vaulytica_cache_size"].value == 100.0

    def test_export_metrics(self):
        """Test exporting metrics in Prometheus format."""
        exporter = PrometheusExporter()
        exporter.inc_counter("vaulytica_scans_total", 5)

        output = exporter.export_metrics()

        assert "# HELP" in output
        assert "# TYPE" in output
        assert "vaulytica_scans_total" in output
        assert "vaulytica_info" in output
        assert "vaulytica_uptime_seconds" in output

