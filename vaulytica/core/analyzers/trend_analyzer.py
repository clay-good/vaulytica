"""Trend analysis for security metrics over time."""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum

import structlog

from vaulytica.storage.history import (
    HistoryManager,
    MetricType,
    MetricSnapshot,
    TrendData,
    get_history_manager,
)

logger = structlog.get_logger(__name__)


class TrendDirection(Enum):
    """Direction of trend."""

    IMPROVING = "improving"
    DEGRADING = "degrading"
    STABLE = "stable"


class AnomalyType(Enum):
    """Types of anomalies detected."""

    SPIKE = "spike"
    DROP = "drop"
    SUSTAINED_INCREASE = "sustained_increase"
    SUSTAINED_DECREASE = "sustained_decrease"


@dataclass
class Anomaly:
    """Detected anomaly in metrics."""

    anomaly_type: AnomalyType
    metric_type: MetricType
    timestamp: datetime
    value: float
    expected_value: float
    deviation_percent: float
    description: str


@dataclass
class ComparisonResult:
    """Result of comparing two time periods."""

    metric_type: MetricType
    period1_start: datetime
    period1_end: datetime
    period2_start: datetime
    period2_end: datetime
    period1_avg: float
    period2_avg: float
    change_absolute: float
    change_percent: float
    trend_direction: TrendDirection


@dataclass
class TrendReport:
    """Comprehensive trend report."""

    domain: str
    generated_at: datetime
    period_days: int
    trends: List[TrendData] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


class TrendAnalyzer:
    """Analyze trends in security metrics over time."""

    # Threshold for considering a metric "stable" (5% change)
    STABILITY_THRESHOLD = 0.05

    # Threshold for anomaly detection (2 standard deviations)
    ANOMALY_THRESHOLD = 2.0

    # Metrics where lower is better (for trend direction)
    LOWER_IS_BETTER = {
        MetricType.EXTERNAL_SHARES,
        MetricType.PUBLIC_FILES,
        MetricType.USERS_WITHOUT_2FA,
        MetricType.HIGH_RISK_OAUTH,
        MetricType.INACTIVE_USERS,
        MetricType.EXTERNAL_MEMBERS,
        MetricType.STALE_FILES,
        MetricType.EXTERNAL_OWNED_FILES,
    }

    def __init__(self, history_manager: Optional[HistoryManager] = None):
        """Initialize trend analyzer.

        Args:
            history_manager: HistoryManager instance
        """
        self.history = history_manager or get_history_manager()
        logger.info("trend_analyzer_initialized")

    def analyze_trend(
        self,
        metric_type: MetricType,
        domain: str,
        days: int = 30,
    ) -> Optional[TrendData]:
        """Analyze trend for a specific metric.

        Args:
            metric_type: Type of metric to analyze
            domain: Domain to analyze
            days: Number of days to analyze

        Returns:
            TrendData with analysis results, or None if insufficient data
        """
        snapshots = self.history.get_metric_history(metric_type, domain, days)

        if len(snapshots) < 2:
            logger.warning(
                "insufficient_data_for_trend",
                metric_type=metric_type.value,
                data_points=len(snapshots),
            )
            return None

        current_value = snapshots[-1].value
        previous_value = snapshots[0].value

        change_absolute = current_value - previous_value
        change_percent = (
            (change_absolute / previous_value * 100)
            if previous_value != 0
            else 0
        )

        # Determine trend direction
        trend_direction = self._calculate_trend_direction(
            metric_type, change_percent
        )

        return TrendData(
            metric_type=metric_type,
            current_value=current_value,
            previous_value=previous_value,
            change_absolute=change_absolute,
            change_percent=change_percent,
            trend_direction=trend_direction.value,
            period_days=days,
            data_points=snapshots,
        )

    def _calculate_trend_direction(
        self,
        metric_type: MetricType,
        change_percent: float,
    ) -> TrendDirection:
        """Calculate trend direction based on metric type and change.

        Args:
            metric_type: Type of metric
            change_percent: Percentage change

        Returns:
            TrendDirection
        """
        if abs(change_percent) < self.STABILITY_THRESHOLD * 100:
            return TrendDirection.STABLE

        is_increasing = change_percent > 0
        lower_is_better = metric_type in self.LOWER_IS_BETTER

        if lower_is_better:
            return TrendDirection.DEGRADING if is_increasing else TrendDirection.IMPROVING
        else:
            return TrendDirection.IMPROVING if is_increasing else TrendDirection.DEGRADING

    def compare_periods(
        self,
        metric_type: MetricType,
        domain: str,
        period1_start: datetime,
        period1_end: datetime,
        period2_start: datetime,
        period2_end: datetime,
    ) -> Optional[ComparisonResult]:
        """Compare metrics between two time periods.

        Args:
            metric_type: Type of metric to compare
            domain: Domain to analyze
            period1_start: Start of first period
            period1_end: End of first period
            period2_start: Start of second period
            period2_end: End of second period

        Returns:
            ComparisonResult or None if insufficient data
        """
        # Get data for both periods
        days1 = (period1_end - period1_start).days + 1
        days2 = (period2_end - period2_start).days + 1

        # We need to fetch enough history to cover both periods
        max_days = max(
            (datetime.now(timezone.utc) - period1_start).days,
            (datetime.now(timezone.utc) - period2_start).days,
        ) + 1

        all_snapshots = self.history.get_metric_history(metric_type, domain, max_days)

        # Filter snapshots for each period
        period1_data = [
            s for s in all_snapshots
            if period1_start <= s.timestamp <= period1_end
        ]
        period2_data = [
            s for s in all_snapshots
            if period2_start <= s.timestamp <= period2_end
        ]

        if not period1_data or not period2_data:
            logger.warning(
                "insufficient_data_for_comparison",
                period1_count=len(period1_data),
                period2_count=len(period2_data),
            )
            return None

        # Calculate averages
        period1_avg = sum(s.value for s in period1_data) / len(period1_data)
        period2_avg = sum(s.value for s in period2_data) / len(period2_data)

        change_absolute = period2_avg - period1_avg
        change_percent = (
            (change_absolute / period1_avg * 100)
            if period1_avg != 0
            else 0
        )

        trend_direction = self._calculate_trend_direction(metric_type, change_percent)

        return ComparisonResult(
            metric_type=metric_type,
            period1_start=period1_start,
            period1_end=period1_end,
            period2_start=period2_start,
            period2_end=period2_end,
            period1_avg=period1_avg,
            period2_avg=period2_avg,
            change_absolute=change_absolute,
            change_percent=change_percent,
            trend_direction=trend_direction,
        )

    def detect_anomalies(
        self,
        metric_type: MetricType,
        domain: str,
        days: int = 30,
    ) -> List[Anomaly]:
        """Detect anomalies in metric data.

        Uses statistical analysis to identify unusual spikes or drops.

        Args:
            metric_type: Type of metric to analyze
            domain: Domain to analyze
            days: Number of days to analyze

        Returns:
            List of detected Anomaly objects
        """
        snapshots = self.history.get_metric_history(metric_type, domain, days)

        if len(snapshots) < 5:  # Need enough data for statistical analysis
            return []

        values = [s.value for s in snapshots]
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        std_dev = variance ** 0.5

        if std_dev == 0:
            return []

        anomalies = []
        for snapshot in snapshots:
            deviation = (snapshot.value - mean) / std_dev

            if abs(deviation) > self.ANOMALY_THRESHOLD:
                if deviation > 0:
                    anomaly_type = AnomalyType.SPIKE
                    description = (
                        f"Unusual spike detected: {snapshot.value:.1f} "
                        f"(expected ~{mean:.1f}, {abs(deviation):.1f} std devs above)"
                    )
                else:
                    anomaly_type = AnomalyType.DROP
                    description = (
                        f"Unusual drop detected: {snapshot.value:.1f} "
                        f"(expected ~{mean:.1f}, {abs(deviation):.1f} std devs below)"
                    )

                anomalies.append(Anomaly(
                    anomaly_type=anomaly_type,
                    metric_type=metric_type,
                    timestamp=snapshot.timestamp,
                    value=snapshot.value,
                    expected_value=mean,
                    deviation_percent=((snapshot.value - mean) / mean * 100) if mean != 0 else 0,
                    description=description,
                ))

        return anomalies

    def generate_trend_report(
        self,
        domain: str,
        days: int = 30,
        metrics: Optional[List[MetricType]] = None,
    ) -> TrendReport:
        """Generate a comprehensive trend report.

        Args:
            domain: Domain to analyze
            days: Number of days to analyze
            metrics: Specific metrics to include (all if None)

        Returns:
            TrendReport with all trend data
        """
        if metrics is None:
            metrics = list(MetricType)

        trends = []
        all_anomalies = []

        for metric_type in metrics:
            # Get trend data
            trend = self.analyze_trend(metric_type, domain, days)
            if trend:
                trends.append(trend)

            # Detect anomalies
            anomalies = self.detect_anomalies(metric_type, domain, days)
            all_anomalies.extend(anomalies)

        # Generate summary
        summary = self._generate_summary(trends, all_anomalies)

        return TrendReport(
            domain=domain,
            generated_at=datetime.now(timezone.utc),
            period_days=days,
            trends=trends,
            anomalies=all_anomalies,
            summary=summary,
        )

    def _generate_summary(
        self,
        trends: List[TrendData],
        anomalies: List[Anomaly],
    ) -> Dict[str, Any]:
        """Generate summary statistics from trends.

        Args:
            trends: List of trend data
            anomalies: List of anomalies

        Returns:
            Summary dictionary
        """
        improving_count = sum(
            1 for t in trends if t.trend_direction == TrendDirection.IMPROVING.value
        )
        degrading_count = sum(
            1 for t in trends if t.trend_direction == TrendDirection.DEGRADING.value
        )
        stable_count = sum(
            1 for t in trends if t.trend_direction == TrendDirection.STABLE.value
        )

        return {
            "total_metrics_analyzed": len(trends),
            "improving": improving_count,
            "degrading": degrading_count,
            "stable": stable_count,
            "anomalies_detected": len(anomalies),
            "overall_direction": self._determine_overall_direction(
                improving_count, degrading_count, stable_count
            ),
        }

    def _determine_overall_direction(
        self,
        improving: int,
        degrading: int,
        stable: int,
    ) -> str:
        """Determine overall security direction.

        Args:
            improving: Count of improving metrics
            degrading: Count of degrading metrics
            stable: Count of stable metrics

        Returns:
            Overall direction string
        """
        if improving > degrading + stable:
            return "improving"
        elif degrading > improving + stable:
            return "degrading"
        else:
            return "stable"

    def get_week_over_week_change(
        self,
        metric_type: MetricType,
        domain: str,
    ) -> Optional[ComparisonResult]:
        """Get week-over-week change for a metric.

        Args:
            metric_type: Type of metric
            domain: Domain to analyze

        Returns:
            ComparisonResult comparing this week to last week
        """
        now = datetime.now(timezone.utc)
        this_week_start = now - timedelta(days=7)
        last_week_start = now - timedelta(days=14)
        last_week_end = now - timedelta(days=7)

        return self.compare_periods(
            metric_type=metric_type,
            domain=domain,
            period1_start=last_week_start,
            period1_end=last_week_end,
            period2_start=this_week_start,
            period2_end=now,
        )

    def get_month_over_month_change(
        self,
        metric_type: MetricType,
        domain: str,
    ) -> Optional[ComparisonResult]:
        """Get month-over-month change for a metric.

        Args:
            metric_type: Type of metric
            domain: Domain to analyze

        Returns:
            ComparisonResult comparing this month to last month
        """
        now = datetime.now(timezone.utc)
        this_month_start = now - timedelta(days=30)
        last_month_start = now - timedelta(days=60)
        last_month_end = now - timedelta(days=30)

        return self.compare_periods(
            metric_type=metric_type,
            domain=domain,
            period1_start=last_month_start,
            period1_end=last_month_end,
            period2_start=this_month_start,
            period2_end=now,
        )
