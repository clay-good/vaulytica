"""
Advanced Analytics Dashboard for Vaulytica.

Provides real-time metrics, trend analysis, predictive insights, and custom dashboards.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4

logger = logging.getLogger(__name__)


# ==================== Enums ====================

class MetricType(str, Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    RATE = "rate"


class ChartType(str, Enum):
    """Types of charts."""
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    AREA = "area"
    SCATTER = "scatter"
    HEATMAP = "heatmap"
    GAUGE = "gauge"
    TABLE = "table"


class TimeRange(str, Enum):
    """Time ranges for analytics."""
    LAST_HOUR = "last_hour"
    LAST_24_HOURS = "last_24_hours"
    LAST_7_DAYS = "last_7_days"
    LAST_30_DAYS = "last_30_days"
    LAST_90_DAYS = "last_90_days"
    CUSTOM = "custom"


# ==================== Data Models ====================

@dataclass
class Metric:
    """Represents a metric."""
    metric_id: str
    name: str
    metric_type: MetricType
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Widget:
    """Dashboard widget."""
    widget_id: str
    title: str
    chart_type: ChartType
    metric_query: str
    time_range: TimeRange
    refresh_interval_seconds: int = 60
    position: Dict[str, int] = field(default_factory=dict)  # x, y, width, height
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Dashboard:
    """Custom dashboard."""
    dashboard_id: str
    name: str
    description: str
    widgets: List[Widget]
    created_by: str
    created_at: datetime
    is_default: bool = False
    shared: bool = False
    tags: List[str] = field(default_factory=list)


@dataclass
class TrendAnalysis:
    """Trend analysis result."""
    metric_name: str
    time_period: str
    trend_direction: str  # "up", "down", "stable"
    percent_change: float
    current_value: float
    previous_value: float
    data_points: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PredictiveInsight:
    """Predictive insight."""
    insight_id: str
    title: str
    description: str
    prediction: str
    confidence: float
    impact: str  # "high", "medium", "low"
    recommended_actions: List[str]
    created_at: datetime = field(default_factory=datetime.utcnow)


# ==================== Advanced Analytics Dashboard ====================

class AdvancedAnalyticsDashboard:
    """
    Advanced analytics dashboard for security metrics.

    Provides:
    - Real-time metrics tracking
    - Trend analysis
    - Predictive insights
    - Custom dashboards
    """

    def __init__(self):
        """Initialize the analytics dashboard."""
        self.metrics: Dict[str, List[Metric]] = {}
        self.dashboards: Dict[str, Dashboard] = {}
        self.insights: List[PredictiveInsight] = []
        self._initialize_default_dashboards()
        logger.info("Advanced analytics dashboard initialized")

    def _initialize_default_dashboards(self):
        """Initialize default dashboards."""
        # Security Operations Dashboard
        sec_ops_dashboard = Dashboard(
            dashboard_id="sec-ops-001",
            name="Security Operations",
            description="Real-time security operations metrics",
            widgets=[
                Widget(
                    widget_id="widget-001",
                    title="Active Incidents",
                    chart_type=ChartType.GAUGE,
                    metric_query="incidents.active",
                    time_range=TimeRange.LAST_24_HOURS,
                    position={"x": 0, "y": 0, "width": 4, "height": 2}
                ),
                Widget(
                    widget_id="widget-002",
                    title="Incident Trend",
                    chart_type=ChartType.LINE,
                    metric_query="incidents.count",
                    time_range=TimeRange.LAST_7_DAYS,
                    position={"x": 4, "y": 0, "width": 8, "height": 4}
                ),
                Widget(
                    widget_id="widget-003",
                    title="Alert Distribution",
                    chart_type=ChartType.PIE,
                    metric_query="alerts.by_severity",
                    time_range=TimeRange.LAST_24_HOURS,
                    position={"x": 0, "y": 2, "width": 4, "height": 4}
                )
            ],
            created_by="system",
            created_at=datetime.utcnow(),
            is_default=True
        )
        self.dashboards[sec_ops_dashboard.dashboard_id] = sec_ops_dashboard

    # ==================== Metrics Management ====================

    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        tags: Optional[Dict[str, str]] = None
    ) -> Metric:
        """Record a metric."""
        metric = Metric(
            metric_id=str(uuid4()),
            name=name,
            metric_type=metric_type,
            value=value,
            timestamp=datetime.utcnow(),
            tags=tags or {}
        )

        if name not in self.metrics:
            self.metrics[name] = []

        self.metrics[name].append(metric)

        # Keep only last 10000 metrics per name
        if len(self.metrics[name]) > 10000:
            self.metrics[name] = self.metrics[name][-10000:]

        return metric

    def get_metrics(
        self,
        name: str,
        time_range: TimeRange = TimeRange.LAST_24_HOURS,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Metric]:
        """Get metrics for a given time range."""
        if name not in self.metrics:
            return []

        # Calculate time range
        if time_range != TimeRange.CUSTOM:
            end_time = datetime.utcnow()
            if time_range == TimeRange.LAST_HOUR:
                start_time = end_time - timedelta(hours=1)
            elif time_range == TimeRange.LAST_24_HOURS:
                start_time = end_time - timedelta(days=1)
            elif time_range == TimeRange.LAST_7_DAYS:
                start_time = end_time - timedelta(days=7)
            elif time_range == TimeRange.LAST_30_DAYS:
                start_time = end_time - timedelta(days=30)
            elif time_range == TimeRange.LAST_90_DAYS:
                start_time = end_time - timedelta(days=90)

        # Filter metrics by time range
        filtered = [
            m for m in self.metrics[name]
            if (not start_time or m.timestamp >= start_time) and
               (not end_time or m.timestamp <= end_time)
        ]

        return filtered

    # ==================== Trend Analysis ====================

    async def analyze_trend(
        self,
        metric_name: str,
        time_range: TimeRange = TimeRange.LAST_7_DAYS
    ) -> TrendAnalysis:
        """Analyze trend for a metric."""
        logger.info(f"Analyzing trend for: {metric_name}")

        metrics = self.get_metrics(metric_name, time_range)

        if len(metrics) < 2:
            return TrendAnalysis(
                metric_name=metric_name,
                time_period=time_range,
                trend_direction="stable",
                percent_change=0.0,
                current_value=metrics[0].value if metrics else 0.0,
                previous_value=metrics[0].value if metrics else 0.0
            )

        # Calculate trend
        current_value = metrics[-1].value
        previous_value = metrics[0].value

        if previous_value == 0:
            percent_change = 100.0 if current_value > 0 else 0.0
        else:
            percent_change = ((current_value - previous_value) / previous_value) * 100

        # Determine trend direction
        if abs(percent_change) < 5:
            trend_direction = "stable"
        elif percent_change > 0:
            trend_direction = "up"
        else:
            trend_direction = "down"

        return TrendAnalysis(
            metric_name=metric_name,
            time_period=time_range,
            trend_direction=trend_direction,
            percent_change=percent_change,
            current_value=current_value,
            previous_value=previous_value,
            data_points=[{"timestamp": m.timestamp, "value": m.value} for m in metrics]
        )

    # ==================== Predictive Insights ====================

    async def generate_predictive_insights(self) -> List[PredictiveInsight]:
        """Generate predictive insights based on metrics."""
        logger.info("Generating predictive insights")

        insights = []

        # Insight 1: Incident volume prediction
        incident_trend = await self.analyze_trend("incidents.count", TimeRange.LAST_30_DAYS)
        if incident_trend.trend_direction == "up" and incident_trend.percent_change > 20:
            insights.append(PredictiveInsight(
                insight_id=str(uuid4()),
                title="Increasing Incident Volume",
                description=f"Incident volume has increased by {incident_trend.percent_change:.1f}% over the last 30 days",
                prediction="Incident volume is likely to continue increasing",
                confidence=0.75,
                impact="high",
                recommended_actions=[
                    "Review and optimize detection rules",
                    "Consider increasing SOC staffing",
                    "Implement additional automation"
                ]
            ))

        # Insight 2: Alert fatigue prediction
        alert_trend = await self.analyze_trend("alerts.count", TimeRange.LAST_7_DAYS)
        if alert_trend.current_value > 1000:
            insights.append(PredictiveInsight(
                insight_id=str(uuid4()),
                title="Potential Alert Fatigue",
                description=f"High alert volume detected: {alert_trend.current_value:.0f} alerts",
                prediction="Alert fatigue may impact analyst effectiveness",
                confidence=0.80,
                impact="medium",
                recommended_actions=[
                    "Review and tune alert rules",
                    "Implement alert deduplication",
                    "Prioritize critical alerts"
                ]
            ))

        self.insights = insights
        logger.info(f"Generated {len(insights)} predictive insights")
        return insights

    # ==================== Dashboard Management ====================

    def create_dashboard(
        self,
        name: str,
        description: str,
        widgets: List[Widget],
        created_by: str
    ) -> Dashboard:
        """Create a custom dashboard."""
        dashboard = Dashboard(
            dashboard_id=str(uuid4()),
            name=name,
            description=description,
            widgets=widgets,
            created_by=created_by,
            created_at=datetime.utcnow()
        )

        self.dashboards[dashboard.dashboard_id] = dashboard
        logger.info(f"Created dashboard: {name}")
        return dashboard

    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        """Get a dashboard by ID."""
        return self.dashboards.get(dashboard_id)

    def list_dashboards(self, created_by: Optional[str] = None) -> List[Dashboard]:
        """List dashboards."""
        dashboards = list(self.dashboards.values())

        if created_by:
            dashboards = [d for d in dashboards if d.created_by == created_by]

        return dashboards


# Global analytics dashboard instance
_analytics_dashboard: Optional[AdvancedAnalyticsDashboard] = None


def get_analytics_dashboard() -> AdvancedAnalyticsDashboard:
    """Get the global analytics dashboard instance."""
    global _analytics_dashboard
    if _analytics_dashboard is None:
        _analytics_dashboard = AdvancedAnalyticsDashboard()
    return _analytics_dashboard
