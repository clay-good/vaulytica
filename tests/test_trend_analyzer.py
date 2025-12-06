"""Tests for Phase 3.2: Trend Analysis and Historical Reporting."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
from pathlib import Path
import tempfile

from vaulytica.storage.history import (
    HistoryManager,
    MetricType,
    MetricSnapshot,
)
from vaulytica.core.analyzers.trend_analyzer import (
    TrendAnalyzer,
    TrendDirection,
    AnomalyType,
)


class TestMetricType:
    """Tests for MetricType enum."""

    def test_all_metric_types_defined(self):
        """Test that all expected metric types are defined."""
        expected = [
            "external_shares",
            "public_files",
            "users_without_2fa",
            "high_risk_oauth",
            "inactive_users",
            "external_members",
            "stale_files",
            "external_owned_files",
            "security_score",
            "compliance_score",
        ]

        actual = [m.value for m in MetricType]

        for exp in expected:
            assert exp in actual, f"Missing metric type: {exp}"


class TestHistoryManager:
    """Tests for HistoryManager."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "test_history.db"

    @pytest.fixture
    def history_manager(self, temp_db):
        """Create a HistoryManager with temporary database."""
        return HistoryManager(db_path=temp_db)

    def test_init_creates_database(self, history_manager, temp_db):
        """Test that initialization creates the database file."""
        assert temp_db.exists()

    def test_record_metric(self, history_manager):
        """Test recording a metric value."""
        history_manager.record_metric(
            MetricType.EXTERNAL_SHARES,
            42.0,
            "example.com",
        )

        latest = history_manager.get_latest_metric(
            MetricType.EXTERNAL_SHARES,
            "example.com",
        )

        assert latest is not None
        assert latest.value == 42.0
        assert latest.domain == "example.com"
        assert latest.metric_type == MetricType.EXTERNAL_SHARES

    def test_record_metric_with_metadata(self, history_manager):
        """Test recording a metric with metadata."""
        metadata = {"source": "file_scan", "files_scanned": 1000}

        history_manager.record_metric(
            MetricType.PUBLIC_FILES,
            15.0,
            "example.com",
            metadata=metadata,
        )

        latest = history_manager.get_latest_metric(
            MetricType.PUBLIC_FILES,
            "example.com",
        )

        assert latest is not None
        assert latest.metadata["source"] == "file_scan"
        assert latest.metadata["files_scanned"] == 1000

    def test_get_metric_history(self, history_manager):
        """Test retrieving metric history."""
        # Record multiple values
        for i in range(5):
            history_manager.record_metric(
                MetricType.EXTERNAL_SHARES,
                float(10 + i),
                "example.com",
            )

        history = history_manager.get_metric_history(
            MetricType.EXTERNAL_SHARES,
            "example.com",
            days=30,
        )

        assert len(history) == 5
        assert history[0].value == 10.0
        assert history[-1].value == 14.0

    def test_record_scan_results(self, history_manager):
        """Test recording scan results."""
        history_manager.record_scan_results(
            scan_type="files",
            domain="example.com",
            total_items=1000,
            items_with_issues=50,
            risk_score=25.0,
            results_summary={"external_shares": 30, "public_files": 20},
        )

        history = history_manager.get_scan_history(
            "files",
            "example.com",
            days=30,
        )

        assert len(history) == 1
        assert history[0]["total_items"] == 1000
        assert history[0]["items_with_issues"] == 50

    def test_record_compliance_score(self, history_manager):
        """Test recording compliance scores."""
        history_manager.record_compliance_score(
            framework="gdpr",
            domain="example.com",
            score=85.0,
            passed_checks=17,
            failed_checks=3,
        )

        history = history_manager.get_compliance_history(
            "gdpr",
            "example.com",
            days=90,
        )

        assert len(history) == 1
        assert history[0]["score"] == 85.0
        assert history[0]["passed_checks"] == 17


class TestTrendAnalyzer:
    """Tests for TrendAnalyzer."""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir) / "test_history.db"

    @pytest.fixture
    def history_manager(self, temp_db):
        """Create a HistoryManager with temporary database."""
        return HistoryManager(db_path=temp_db)

    @pytest.fixture
    def analyzer(self, history_manager):
        """Create a TrendAnalyzer."""
        return TrendAnalyzer(history_manager=history_manager)

    def test_analyze_trend_improving(self, analyzer, history_manager):
        """Test trend analysis detecting improvement."""
        # For external_shares, lower is better, so decreasing should be improving
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 100.0, "example.com")
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 80.0, "example.com")
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 60.0, "example.com")

        trend = analyzer.analyze_trend(
            MetricType.EXTERNAL_SHARES,
            "example.com",
            days=30,
        )

        assert trend is not None
        assert trend.trend_direction == TrendDirection.IMPROVING.value
        assert trend.current_value == 60.0
        assert trend.previous_value == 100.0

    def test_analyze_trend_degrading(self, analyzer, history_manager):
        """Test trend analysis detecting degradation."""
        # For external_shares, lower is better, so increasing should be degrading
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 50.0, "example.com")
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 75.0, "example.com")
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 100.0, "example.com")

        trend = analyzer.analyze_trend(
            MetricType.EXTERNAL_SHARES,
            "example.com",
            days=30,
        )

        assert trend is not None
        assert trend.trend_direction == TrendDirection.DEGRADING.value

    def test_analyze_trend_stable(self, analyzer, history_manager):
        """Test trend analysis detecting stable metrics."""
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 50.0, "example.com")
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 51.0, "example.com")
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 50.5, "example.com")

        trend = analyzer.analyze_trend(
            MetricType.EXTERNAL_SHARES,
            "example.com",
            days=30,
        )

        assert trend is not None
        assert trend.trend_direction == TrendDirection.STABLE.value

    def test_analyze_trend_security_score_improving(self, analyzer, history_manager):
        """Test that for security_score, higher is better (not in LOWER_IS_BETTER)."""
        history_manager.record_metric(MetricType.SECURITY_SCORE, 60.0, "example.com")
        history_manager.record_metric(MetricType.SECURITY_SCORE, 80.0, "example.com")

        trend = analyzer.analyze_trend(
            MetricType.SECURITY_SCORE,
            "example.com",
            days=30,
        )

        assert trend is not None
        assert trend.trend_direction == TrendDirection.IMPROVING.value

    def test_analyze_trend_insufficient_data(self, analyzer, history_manager):
        """Test that analysis returns None with insufficient data."""
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 50.0, "example.com")

        trend = analyzer.analyze_trend(
            MetricType.EXTERNAL_SHARES,
            "example.com",
            days=30,
        )

        assert trend is None

    def test_detect_anomalies_spike(self, analyzer, history_manager):
        """Test anomaly detection for spikes."""
        # Record normal values
        for i in range(10):
            history_manager.record_metric(MetricType.EXTERNAL_SHARES, 50.0, "example.com")

        # Record spike
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 200.0, "example.com")

        anomalies = analyzer.detect_anomalies(
            MetricType.EXTERNAL_SHARES,
            "example.com",
            days=30,
        )

        assert len(anomalies) >= 1
        spike_anomalies = [a for a in anomalies if a.anomaly_type == AnomalyType.SPIKE]
        assert len(spike_anomalies) >= 1

    def test_generate_trend_report(self, analyzer, history_manager):
        """Test generating a comprehensive trend report."""
        # Add some test data
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 100.0, "example.com")
        history_manager.record_metric(MetricType.EXTERNAL_SHARES, 80.0, "example.com")
        history_manager.record_metric(MetricType.PUBLIC_FILES, 20.0, "example.com")
        history_manager.record_metric(MetricType.PUBLIC_FILES, 25.0, "example.com")

        report = analyzer.generate_trend_report(
            "example.com",
            days=30,
            metrics=[MetricType.EXTERNAL_SHARES, MetricType.PUBLIC_FILES],
        )

        assert report.domain == "example.com"
        assert report.period_days == 30
        assert len(report.trends) == 2
        assert "total_metrics_analyzed" in report.summary


class TestMetricSnapshot:
    """Tests for MetricSnapshot dataclass."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        snapshot = MetricSnapshot(
            metric_type=MetricType.EXTERNAL_SHARES,
            value=42.0,
            timestamp=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
            domain="example.com",
            metadata={"source": "test"},
        )

        data = snapshot.to_dict()

        assert data["metric_type"] == "external_shares"
        assert data["value"] == 42.0
        assert data["domain"] == "example.com"
        assert data["metadata"]["source"] == "test"

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "metric_type": "external_shares",
            "value": 42.0,
            "timestamp": "2024-01-15T12:00:00+00:00",
            "domain": "example.com",
            "metadata": {"source": "test"},
        }

        snapshot = MetricSnapshot.from_dict(data)

        assert snapshot.metric_type == MetricType.EXTERNAL_SHARES
        assert snapshot.value == 42.0
        assert snapshot.domain == "example.com"
