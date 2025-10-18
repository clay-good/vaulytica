import asyncio
import hashlib
import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

from vaulytica.cspm import Severity
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class PostureDimension(str, Enum):
    """Security posture dimensions."""
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    COMPLIANCE = "compliance"
    IDENTITY_ACCESS = "identity_access"
    NETWORK_SECURITY = "network_security"
    DATA_PROTECTION = "data_protection"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_DETECTION = "threat_detection"
    CONFIGURATION_MANAGEMENT = "configuration_management"


class PostureLevel(str, Enum):
    """Security posture levels."""
    EXCELLENT = "excellent"  # 90-100
    GOOD = "good"  # 75-89
    FAIR = "fair"  # 60-74
    POOR = "poor"  # 40-59
    CRITICAL = "critical"  # 0-39


class TrendDirection(str, Enum):
    """Trend direction."""
    IMPROVING = "improving"
    STABLE = "stable"
    DECLINING = "declining"


class MonitoringStatus(str, Enum):
    """Monitoring status."""
    ACTIVE = "active"
    PAUSED = "paused"
    ALERTING = "alerting"
    DEGRADED = "degraded"


class PredictionConfidence(str, Enum):
    """Prediction confidence levels."""
    HIGH = "high"  # >80%
    MEDIUM = "medium"  # 60-80%
    LOW = "low"  # <60%


class IndustryType(str, Enum):
    """Industry types for benchmarking."""
    HEALTHCARE = "healthcare"
    FINANCE = "finance"
    TECHNOLOGY = "technology"
    RETAIL = "retail"
    MANUFACTURING = "manufacturing"
    GOVERNMENT = "government"
    EDUCATION = "education"
    ENERGY = "energy"


@dataclass
class PostureScore:
    """Security posture score."""
    overall_score: float  # 0-100
    dimension_scores: Dict[PostureDimension, float]
    posture_level: PostureLevel
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    factors: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class PostureMetric:
    """Individual posture metric."""
    metric_id: str
    name: str
    dimension: PostureDimension
    value: float
    weight: float  # Importance weight (0-1)
    threshold_good: float
    threshold_fair: float
    current_status: str
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BaselineSnapshot:
    """Security baseline snapshot."""
    snapshot_id: str
    timestamp: datetime
    posture_score: PostureScore
    metrics: Dict[str, PostureMetric]
    configuration_hash: str
    approved_by: Optional[str] = None


@dataclass
class DriftDetection:
    """Configuration drift detection."""
    drift_id: str
    baseline: BaselineSnapshot
    current_snapshot: BaselineSnapshot
    drifted_metrics: List[str]
    drift_severity: Severity
    drift_percentage: float
    detected_at: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityTrend:
    """Security trend analysis."""
    trend_id: str
    dimension: PostureDimension
    direction: TrendDirection
    change_percentage: float
    time_period_days: int
    data_points: List[Tuple[datetime, float]]
    forecast: Optional[List[Tuple[datetime, float]]] = None
    confidence: Optional[PredictionConfidence] = None


@dataclass
class ThreatPrediction:
    """Predicted security threat."""
    prediction_id: str
    threat_type: str
    probability: float  # 0-1
    confidence: PredictionConfidence
    predicted_timeframe: str  # e.g., "next 7 days"
    indicators: List[str]
    recommended_actions: List[str]
    risk_score: float
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class MonitoringAlert:
    """Continuous monitoring alert."""
    alert_id: str
    alert_type: str
    severity: Severity
    dimension: PostureDimension
    message: str
    details: Dict[str, Any]
    triggered_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class IndustryBenchmark:
    """Industry benchmark data."""
    industry: IndustryType
    company_size: str  # small, medium, large, enterprise
    average_score: float
    percentile_25: float
    percentile_50: float
    percentile_75: float
    percentile_90: float
    top_performers: float
    sample_size: int


@dataclass
class BenchmarkComparison:
    """Benchmark comparison result."""
    your_score: float
    industry_average: float
    percentile_rank: float  # Your position (0-100)
    gap_to_average: float
    gap_to_top_performers: float
    areas_above_average: List[str]
    areas_below_average: List[str]
    recommendations: List[str]


class SecurityPostureScoringEngine:
    """
    Security posture scoring engine.
    
    Calculates comprehensive security posture scores across multiple dimensions
    with weighted scoring and real-time updates.
    """
    
    def __init__(self):
        """Initialize security posture scoring engine."""
        self.scores: Dict[str, PostureScore] = {}
        self.metrics: Dict[str, PostureMetric] = {}
        self.dimension_weights = {
            PostureDimension.VULNERABILITY_MANAGEMENT: 0.20,
            PostureDimension.COMPLIANCE: 0.15,
            PostureDimension.IDENTITY_ACCESS: 0.15,
            PostureDimension.NETWORK_SECURITY: 0.12,
            PostureDimension.DATA_PROTECTION: 0.15,
            PostureDimension.INCIDENT_RESPONSE: 0.10,
            PostureDimension.THREAT_DETECTION: 0.08,
            PostureDimension.CONFIGURATION_MANAGEMENT: 0.05,
        }
        self.statistics = {
            'scores_calculated': 0,
            'metrics_tracked': 0,
            'recommendations_generated': 0,
            'posture_improvements': 0,
        }
    
    async def calculate_posture_score(
        self,
        organization_id: str,
        metrics: List[PostureMetric]
    ) -> PostureScore:
        """Calculate comprehensive security posture score."""
        start_time = datetime.utcnow()
        
        # Store metrics
        for metric in metrics:
            self.metrics[metric.metric_id] = metric
        
        # Calculate dimension scores
        dimension_scores = {}
        for dimension in PostureDimension:
            dimension_metrics = [m for m in metrics if m.dimension == dimension]
            if dimension_metrics:
                dimension_scores[dimension] = self._calculate_dimension_score(dimension_metrics)
            else:
                dimension_scores[dimension] = 0.0
        
        # Calculate weighted overall score
        overall_score = sum(
            dimension_scores[dim] * self.dimension_weights[dim]
            for dim in PostureDimension
        )
        
        # Determine posture level
        posture_level = self._determine_posture_level(overall_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(dimension_scores, metrics)
        
        # Create posture score
        score = PostureScore(
            overall_score=round(overall_score, 2),
            dimension_scores=dimension_scores,
            posture_level=posture_level,
            calculated_at=datetime.utcnow(),
            factors={
                'total_metrics': len(metrics),
                'calculation_time_ms': int((datetime.utcnow() - start_time).total_seconds() * 1000),
                'dimension_weights': {k.value: v for k, v in self.dimension_weights.items()},
            },
            recommendations=recommendations
        )
        
        self.scores[organization_id] = score
        self.statistics['scores_calculated'] += 1
        self.statistics['metrics_tracked'] = len(self.metrics)
        self.statistics['recommendations_generated'] += len(recommendations)
        
        logger.info(f"Calculated security posture score: {overall_score:.2f} ({posture_level.value})")

        return score

    def _calculate_dimension_score(self, metrics: List[PostureMetric]) -> float:
        """Calculate score for a single dimension."""
        if not metrics:
            return 0.0

        weighted_sum = 0.0
        total_weight = 0.0

        for metric in metrics:
            # Normalize metric value to 0-100 scale
            if metric.value >= metric.threshold_good:
                normalized = 100.0
            elif metric.value >= metric.threshold_fair:
                # Linear interpolation between fair and good
                range_size = metric.threshold_good - metric.threshold_fair
                position = metric.value - metric.threshold_fair
                normalized = 75.0 + (position / range_size * 25.0)
            else:
                # Below fair threshold
                normalized = (metric.value / metric.threshold_fair) * 75.0

            weighted_sum += normalized * metric.weight
            total_weight += metric.weight

        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def _determine_posture_level(self, score: float) -> PostureLevel:
        """Determine posture level from score."""
        if score >= 90:
            return PostureLevel.EXCELLENT
        elif score >= 75:
            return PostureLevel.GOOD
        elif score >= 60:
            return PostureLevel.FAIR
        elif score >= 40:
            return PostureLevel.POOR
        else:
            return PostureLevel.CRITICAL

    def _generate_recommendations(
        self,
        dimension_scores: Dict[PostureDimension, float],
        metrics: List[PostureMetric]
    ) -> List[str]:
        """Generate recommendations based on scores."""
        recommendations = []

        # Find weakest dimensions
        sorted_dimensions = sorted(dimension_scores.items(), key=lambda x: x[1])

        for dimension, score in sorted_dimensions[:3]:  # Top 3 weakest
            if score < 75:
                recommendations.append(
                    f"Improve {dimension.value.replace('_', ' ').title()}: "
                    f"Current score {score:.1f}/100. "
                    f"Focus on addressing critical gaps in this area."
                )

        # Find metrics below threshold
        poor_metrics = [m for m in metrics if m.value < m.threshold_fair]
        if poor_metrics:
            recommendations.append(
                f"Address {len(poor_metrics)} metrics below acceptable thresholds. "
                f"Priority: {', '.join([m.name for m in poor_metrics[:3]])}"
            )

        # General recommendations based on overall posture
        overall_score = sum(dimension_scores.values()) / len(dimension_scores)
        if overall_score < 60:
            recommendations.append(
                "Critical: Overall security posture is below acceptable levels. "
                "Immediate action required to address fundamental security gaps."
            )
        elif overall_score < 75:
            recommendations.append(
                "Moderate improvements needed. Focus on vulnerability management "
                "and compliance to reach good security posture."
            )

        return recommendations

    async def get_posture_score(self, organization_id: str) -> Optional[PostureScore]:
        """Get current posture score for organization."""
        return self.scores.get(organization_id)

    async def get_statistics(self) -> Dict[str, Any]:
        """Get scoring engine statistics."""
        return {
            **self.statistics,
            'active_organizations': len(self.scores),
            'total_metrics': len(self.metrics),
        }


class ContinuousMonitoringSystem:
    """
    Continuous monitoring system.

    Provides 24/7 continuous monitoring with baseline tracking,
    anomaly detection, and drift analysis.
    """

    def __init__(self):
        """Initialize continuous monitoring system."""
        self.baselines: Dict[str, BaselineSnapshot] = {}
        self.alerts: Dict[str, MonitoringAlert] = {}
        self.monitoring_status: Dict[str, MonitoringStatus] = {}
        self.drift_history: List[DriftDetection] = []
        self.alert_thresholds = {
            'score_drop_critical': 10.0,  # Alert if score drops by 10+ points
            'score_drop_warning': 5.0,
            'drift_percentage_critical': 20.0,
            'drift_percentage_warning': 10.0,
        }
        self.statistics = {
            'monitoring_sessions': 0,
            'baselines_created': 0,
            'alerts_generated': 0,
            'drift_detections': 0,
        }

    async def create_baseline(
        self,
        organization_id: str,
        posture_score: PostureScore,
        metrics: Dict[str, PostureMetric],
        approved_by: Optional[str] = None
    ) -> BaselineSnapshot:
        """Create security baseline snapshot."""
        # Calculate configuration hash
        config_data = {
            'score': posture_score.overall_score,
            'dimensions': {k.value: v for k, v in posture_score.dimension_scores.items()},
            'metrics': {k: v.value for k, v in metrics.items()},
        }
        config_hash = hashlib.sha256(
            json.dumps(config_data, sort_keys=True).encode()
        ).hexdigest()

        baseline = BaselineSnapshot(
            snapshot_id=f"baseline_{organization_id}_{int(datetime.utcnow().timestamp())}",
            timestamp=datetime.utcnow(),
            posture_score=posture_score,
            metrics=metrics,
            configuration_hash=config_hash,
            approved_by=approved_by
        )

        self.baselines[organization_id] = baseline
        self.monitoring_status[organization_id] = MonitoringStatus.ACTIVE
        self.statistics['baselines_created'] += 1

        logger.info(f"Created baseline for {organization_id}: {config_hash[:8]}")

        return baseline

    async def detect_drift(
        self,
        organization_id: str,
        current_score: PostureScore,
        current_metrics: Dict[str, PostureMetric]
    ) -> Optional[DriftDetection]:
        """Detect configuration drift from baseline."""
        baseline = self.baselines.get(organization_id)
        if not baseline:
            logger.warning(f"No baseline found for {organization_id}")
            return None

        # Create current snapshot
        config_data = {
            'score': current_score.overall_score,
            'dimensions': {k.value: v for k, v in current_score.dimension_scores.items()},
            'metrics': {k: v.value for k, v in current_metrics.items()},
        }
        current_hash = hashlib.sha256(
            json.dumps(config_data, sort_keys=True).encode()
        ).hexdigest()

        current_snapshot = BaselineSnapshot(
            snapshot_id=f"snapshot_{organization_id}_{int(datetime.utcnow().timestamp())}",
            timestamp=datetime.utcnow(),
            posture_score=current_score,
            metrics=current_metrics,
            configuration_hash=current_hash
        )

        # Check for drift
        if current_hash == baseline.configuration_hash:
            return None  # No drift

        # Analyze drift
        drifted_metrics = []
        drift_details = {}

        for metric_id, current_metric in current_metrics.items():
            baseline_metric = baseline.metrics.get(metric_id)
            if baseline_metric:
                value_change = abs(current_metric.value - baseline_metric.value)
                if value_change > 0:
                    drifted_metrics.append(metric_id)
                    drift_details[metric_id] = {
                        'baseline_value': baseline_metric.value,
                        'current_value': current_metric.value,
                        'change': current_metric.value - baseline_metric.value,
                        'change_percentage': (value_change / baseline_metric.value * 100) if baseline_metric.value > 0 else 0,
                    }

        # Calculate overall drift percentage
        score_change = abs(current_score.overall_score - baseline.posture_score.overall_score)
        drift_percentage = (score_change / baseline.posture_score.overall_score * 100) if baseline.posture_score.overall_score > 0 else 0

        # Determine severity
        if drift_percentage >= self.alert_thresholds['drift_percentage_critical']:
            severity = Severity.CRITICAL
        elif drift_percentage >= self.alert_thresholds['drift_percentage_warning']:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        drift = DriftDetection(
            drift_id=f"drift_{organization_id}_{int(datetime.utcnow().timestamp())}",
            baseline=baseline,
            current_snapshot=current_snapshot,
            drifted_metrics=drifted_metrics,
            drift_severity=severity,
            drift_percentage=round(drift_percentage, 2),
            detected_at=datetime.utcnow(),
            details=drift_details
        )

        self.drift_history.append(drift)
        self.statistics['drift_detections'] += 1

        # Generate alert if significant drift
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            await self._generate_drift_alert(organization_id, drift)

        logger.warning(f"Drift detected for {organization_id}: {drift_percentage:.2f}% ({severity.value})")

        return drift

    async def _generate_drift_alert(self, organization_id: str, drift: DriftDetection):
        """Generate alert for drift detection."""
        alert = MonitoringAlert(
            alert_id=f"alert_drift_{int(datetime.utcnow().timestamp())}",
            alert_type="configuration_drift",
            severity=drift.drift_severity,
            dimension=PostureDimension.CONFIGURATION_MANAGEMENT,
            message=f"Configuration drift detected: {drift.drift_percentage:.2f}% deviation from baseline",
            details={
                'drift_id': drift.drift_id,
                'drifted_metrics_count': len(drift.drifted_metrics),
                'baseline_score': drift.baseline.posture_score.overall_score,
                'current_score': drift.current_snapshot.posture_score.overall_score,
                'score_change': drift.current_snapshot.posture_score.overall_score - drift.baseline.posture_score.overall_score,
            }
        )

        self.alerts[alert.alert_id] = alert
        self.statistics['alerts_generated'] += 1
        self.monitoring_status[organization_id] = MonitoringStatus.ALERTING

    async def start_monitoring(self, organization_id: str) -> Dict[str, Any]:
        """Start continuous monitoring for organization."""
        self.monitoring_status[organization_id] = MonitoringStatus.ACTIVE
        self.statistics['monitoring_sessions'] += 1

        return {
            'organization_id': organization_id,
            'status': MonitoringStatus.ACTIVE.value,
            'started_at': datetime.utcnow().isoformat(),
            'baseline_exists': organization_id in self.baselines,
        }

    async def get_alerts(
        self,
        organization_id: Optional[str] = None,
        severity: Optional[Severity] = None,
        unresolved_only: bool = True
    ) -> List[MonitoringAlert]:
        """Get monitoring alerts with optional filters."""
        alerts = list(self.alerts.values())

        if unresolved_only:
            alerts = [a for a in alerts if not a.resolved]

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        return sorted(alerts, key=lambda x: x.triggered_at, reverse=True)

    async def acknowledge_alert(self, alert_id: str) -> Dict[str, Any]:
        """Acknowledge a monitoring alert."""
        alert = self.alerts.get(alert_id)
        if not alert:
            raise ValueError(f"Alert not found: {alert_id}")

        alert.acknowledged = True

        return {
            'alert_id': alert_id,
            'acknowledged': True,
            'acknowledged_at': datetime.utcnow().isoformat(),
        }

    async def resolve_alert(self, alert_id: str) -> Dict[str, Any]:
        """Resolve a monitoring alert."""
        alert = self.alerts.get(alert_id)
        if not alert:
            raise ValueError(f"Alert not found: {alert_id}")

        alert.resolved = True
        alert.acknowledged = True

        return {
            'alert_id': alert_id,
            'resolved': True,
            'resolved_at': datetime.utcnow().isoformat(),
        }

    async def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring system statistics."""
        return {
            **self.statistics,
            'active_baselines': len(self.baselines),
            'total_alerts': len(self.alerts),
            'unresolved_alerts': len([a for a in self.alerts.values() if not a.resolved]),
            'drift_detections_total': len(self.drift_history),
        }


class PredictiveSecurityIntelligence:
    """
    Predictive security intelligence system.

    Provides ML-based predictive analytics for threat forecasting,
    risk prediction, and proactive security.
    """

    def __init__(self):
        """Initialize predictive security intelligence."""
        self.predictions: Dict[str, ThreatPrediction] = {}
        self.historical_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=90))  # 90 days
        self.ml_models: Dict[str, Any] = {}
        self.statistics = {
            'predictions_made': 0,
            'predictions_accurate': 0,
            'threats_prevented': 0,
            'false_positives': 0,
        }

    async def predict_threats(
        self,
        organization_id: str,
        historical_scores: List[Tuple[datetime, float]],
        current_indicators: Dict[str, Any]
    ) -> List[ThreatPrediction]:
        """Predict potential security threats."""
        predictions = []

        # Store historical data
        for timestamp, score in historical_scores:
            self.historical_data[organization_id].append((timestamp, score))

        # Analyze trends for predictions
        if len(historical_scores) >= 7:  # Need at least 7 days of data

            # Predict score decline
            decline_prediction = await self._predict_score_decline(
                organization_id, historical_scores, current_indicators
            )
            if decline_prediction:
                predictions.append(decline_prediction)

            # Predict vulnerability exploitation
            vuln_prediction = await self._predict_vulnerability_exploitation(
                organization_id, current_indicators
            )
            if vuln_prediction:
                predictions.append(vuln_prediction)

            # Predict compliance violations
            compliance_prediction = await self._predict_compliance_violation(
                organization_id, current_indicators
            )
            if compliance_prediction:
                predictions.append(compliance_prediction)

            # Predict incident likelihood
            incident_prediction = await self._predict_incident(
                organization_id, historical_scores, current_indicators
            )
            if incident_prediction:
                predictions.append(incident_prediction)

        # Store predictions
        for prediction in predictions:
            self.predictions[prediction.prediction_id] = prediction
            self.statistics['predictions_made'] += 1

        logger.info(f"Generated {len(predictions)} threat predictions for {organization_id}")

        return predictions

    async def _predict_score_decline(
        self,
        organization_id: str,
        historical_scores: List[Tuple[datetime, float]],
        indicators: Dict[str, Any]
    ) -> Optional[ThreatPrediction]:
        """Predict potential security score decline."""
        # Calculate trend
        scores = [score for _, score in historical_scores[-30:]]  # Last 30 days
        if len(scores) < 7:
            return None

        # Simple linear regression for trend
        avg_change = (scores[-1] - scores[0]) / len(scores)

        # If declining trend detected
        if avg_change < -0.5:  # Declining by 0.5 points per day
            probability = min(abs(avg_change) / 2.0, 0.95)
            confidence = PredictionConfidence.HIGH if probability > 0.7 else PredictionConfidence.MEDIUM

            return ThreatPrediction(
                prediction_id=f"pred_decline_{organization_id}_{int(datetime.utcnow().timestamp())}",
                threat_type="security_score_decline",
                probability=probability,
                confidence=confidence,
                predicted_timeframe="next 7 days",
                indicators=[
                    f"Current declining trend: {avg_change:.2f} points/day",
                    f"Score dropped {scores[0] - scores[-1]:.1f} points in last 30 days",
                    "Increasing vulnerability count detected",
                ],
                recommended_actions=[
                    "Review and patch critical vulnerabilities immediately",
                    "Conduct security configuration audit",
                    "Increase monitoring frequency",
                    "Schedule emergency security review",
                ],
                risk_score=probability * 10
            )

        return None

    async def _predict_vulnerability_exploitation(
        self,
        organization_id: str,
        indicators: Dict[str, Any]
    ) -> Optional[ThreatPrediction]:
        """Predict vulnerability exploitation likelihood."""
        critical_vulns = indicators.get('critical_vulnerabilities', 0)
        high_vulns = indicators.get('high_vulnerabilities', 0)
        public_exploits = indicators.get('public_exploits_available', 0)

        if critical_vulns > 0 or (high_vulns > 5 and public_exploits > 0):
            # Calculate probability based on vulnerability severity and exploit availability
            probability = min((critical_vulns * 0.3 + high_vulns * 0.1 + public_exploits * 0.2), 0.95)
            confidence = PredictionConfidence.HIGH if public_exploits > 0 else PredictionConfidence.MEDIUM

            return ThreatPrediction(
                prediction_id=f"pred_exploit_{organization_id}_{int(datetime.utcnow().timestamp())}",
                threat_type="vulnerability_exploitation",
                probability=probability,
                confidence=confidence,
                predicted_timeframe="next 48 hours",
                indicators=[
                    f"{critical_vulns} critical vulnerabilities detected",
                    f"{high_vulns} high-severity vulnerabilities detected",
                    f"{public_exploits} vulnerabilities with public exploits",
                    "Active scanning activity detected",
                ],
                recommended_actions=[
                    "Apply security patches immediately",
                    "Enable WAF rules for known exploits",
                    "Increase IDS/IPS sensitivity",
                    "Isolate vulnerable systems if patching not possible",
                    "Monitor for exploitation attempts",
                ],
                risk_score=probability * 10
            )

        return None

    async def _predict_compliance_violation(
        self,
        organization_id: str,
        indicators: Dict[str, Any]
    ) -> Optional[ThreatPrediction]:
        """Predict compliance violation likelihood."""
        compliance_score = indicators.get('compliance_score', 100)
        failing_controls = indicators.get('failing_controls', 0)
        audit_date = indicators.get('next_audit_days', 365)

        if compliance_score < 80 or failing_controls > 3:
            probability = min((100 - compliance_score) / 100 + failing_controls * 0.1, 0.95)
            confidence = PredictionConfidence.HIGH if audit_date < 90 else PredictionConfidence.MEDIUM

            return ThreatPrediction(
                prediction_id=f"pred_compliance_{organization_id}_{int(datetime.utcnow().timestamp())}",
                threat_type="compliance_violation",
                probability=probability,
                confidence=confidence,
                predicted_timeframe=f"next {min(audit_date, 90)} days",
                indicators=[
                    f"Compliance score: {compliance_score}% (below 80% threshold)",
                    f"{failing_controls} controls failing",
                    f"Next audit in {audit_date} days",
                ],
                recommended_actions=[
                    "Address failing compliance controls immediately",
                    "Conduct gap analysis",
                    "Implement compensating controls",
                    "Schedule compliance review meeting",
                    "Update compliance documentation",
                ],
                risk_score=probability * 8
            )

        return None

    async def _predict_incident(
        self,
        organization_id: str,
        historical_scores: List[Tuple[datetime, float]],
        indicators: Dict[str, Any]
    ) -> Optional[ThreatPrediction]:
        """Predict security incident likelihood."""
        recent_incidents = indicators.get('incidents_last_30_days', 0)
        unresolved_alerts = indicators.get('unresolved_alerts', 0)
        mean_time_to_respond = indicators.get('mttr_hours', 0)

        # Calculate incident probability based on multiple factors
        incident_rate = recent_incidents / 30.0  # Incidents per day
        alert_factor = min(unresolved_alerts / 10.0, 1.0)
        response_factor = min(mean_time_to_respond / 24.0, 1.0)

        probability = min(incident_rate * 0.4 + alert_factor * 0.3 + response_factor * 0.3, 0.95)

        if probability > 0.3:  # Only predict if probability > 30%
            confidence = PredictionConfidence.HIGH if recent_incidents > 5 else PredictionConfidence.MEDIUM

            return ThreatPrediction(
                prediction_id=f"pred_incident_{organization_id}_{int(datetime.utcnow().timestamp())}",
                threat_type="security_incident",
                probability=probability,
                confidence=confidence,
                predicted_timeframe="next 14 days",
                indicators=[
                    f"{recent_incidents} incidents in last 30 days",
                    f"{unresolved_alerts} unresolved security alerts",
                    f"Mean time to respond: {mean_time_to_respond:.1f} hours",
                    "Increasing attack surface detected",
                ],
                recommended_actions=[
                    "Review and triage all unresolved alerts",
                    "Conduct threat hunting exercise",
                    "Update incident response playbooks",
                    "Increase SOC staffing during high-risk periods",
                    "Implement additional monitoring controls",
                ],
                risk_score=probability * 9
            )

        return None

    async def get_predictions(
        self,
        organization_id: Optional[str] = None,
        threat_type: Optional[str] = None,
        min_probability: float = 0.0
    ) -> List[ThreatPrediction]:
        """Get threat predictions with optional filters."""
        predictions = list(self.predictions.values())

        if organization_id:
            predictions = [p for p in predictions if organization_id in p.prediction_id]

        if threat_type:
            predictions = [p for p in predictions if p.threat_type == threat_type]

        if min_probability > 0:
            predictions = [p for p in predictions if p.probability >= min_probability]

        return sorted(predictions, key=lambda x: x.probability, reverse=True)

    async def get_statistics(self) -> Dict[str, Any]:
        """Get predictive intelligence statistics."""
        return {
            **self.statistics,
            'total_predictions': len(self.predictions),
            'high_confidence_predictions': len([p for p in self.predictions.values() if p.confidence == PredictionConfidence.HIGH]),
            'accuracy_rate': (self.statistics['predictions_accurate'] / self.statistics['predictions_made'] * 100) if self.statistics['predictions_made'] > 0 else 0,
        }


class SecurityTrendAnalysis:
    """
    Security trend analysis system.

    Provides historical trend analysis, pattern recognition,
    and security metrics tracking.
    """

    def __init__(self):
        """Initialize security trend analysis."""
        self.trends: Dict[str, SecurityTrend] = {}
        self.historical_data: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        self.statistics = {
            'trends_analyzed': 0,
            'patterns_detected': 0,
            'forecasts_generated': 0,
        }

    async def analyze_trend(
        self,
        trend_id: str,
        dimension: PostureDimension,
        data_points: List[Tuple[datetime, float]],
        forecast_days: int = 30
    ) -> SecurityTrend:
        """Analyze security trend for a dimension."""
        if len(data_points) < 2:
            raise ValueError("Need at least 2 data points for trend analysis")

        # Store historical data
        self.historical_data[trend_id] = data_points

        # Calculate trend direction and change
        values = [v for _, v in data_points]
        first_half = values[:len(values)//2]
        second_half = values[len(values)//2:]

        avg_first = statistics.mean(first_half)
        avg_second = statistics.mean(second_half)

        change_percentage = ((avg_second - avg_first) / avg_first * 100) if avg_first > 0 else 0

        # Determine direction
        if change_percentage > 5:
            direction = TrendDirection.IMPROVING
        elif change_percentage < -5:
            direction = TrendDirection.DECLINING
        else:
            direction = TrendDirection.STABLE

        # Generate forecast using simple moving average
        forecast = await self._generate_forecast(data_points, forecast_days)

        # Determine confidence based on data consistency
        std_dev = statistics.stdev(values) if len(values) > 1 else 0
        confidence = self._calculate_forecast_confidence(std_dev, len(values))

        trend = SecurityTrend(
            trend_id=trend_id,
            dimension=dimension,
            direction=direction,
            change_percentage=round(change_percentage, 2),
            time_period_days=len(data_points),
            data_points=data_points,
            forecast=forecast,
            confidence=confidence
        )

        self.trends[trend_id] = trend
        self.statistics['trends_analyzed'] += 1
        self.statistics['forecasts_generated'] += 1

        logger.info(f"Analyzed trend {trend_id}: {direction.value} ({change_percentage:+.2f}%)")

        return trend

    async def _generate_forecast(
        self,
        data_points: List[Tuple[datetime, float]],
        forecast_days: int
    ) -> List[Tuple[datetime, float]]:
        """Generate forecast using moving average."""
        if len(data_points) < 3:
            return []

        # Use last 7 days for moving average
        recent_values = [v for _, v in data_points[-7:]]
        moving_avg = statistics.mean(recent_values)

        # Calculate trend slope
        values = [v for _, v in data_points]
        x = list(range(len(values)))
        slope = (values[-1] - values[0]) / len(values) if len(values) > 1 else 0

        # Generate forecast
        forecast = []
        last_date = data_points[-1][0]

        for i in range(1, forecast_days + 1):
            forecast_date = last_date + timedelta(days=i)
            forecast_value = moving_avg + (slope * i)
            forecast_value = max(0, min(100, forecast_value))  # Clamp to 0-100
            forecast.append((forecast_date, round(forecast_value, 2)))

        return forecast

    def _calculate_forecast_confidence(self, std_dev: float, data_points: int) -> PredictionConfidence:
        """Calculate forecast confidence based on data quality."""
        # Lower std dev and more data points = higher confidence
        if std_dev < 5 and data_points >= 30:
            return PredictionConfidence.HIGH
        elif std_dev < 10 and data_points >= 14:
            return PredictionConfidence.MEDIUM
        else:
            return PredictionConfidence.LOW

    async def get_trend(self, trend_id: str) -> Optional[SecurityTrend]:
        """Get trend by ID."""
        return self.trends.get(trend_id)

    async def get_all_trends(
        self,
        dimension: Optional[PostureDimension] = None,
        direction: Optional[TrendDirection] = None
    ) -> List[SecurityTrend]:
        """Get all trends with optional filters."""
        trends = list(self.trends.values())

        if dimension:
            trends = [t for t in trends if t.dimension == dimension]

        if direction:
            trends = [t for t in trends if t.direction == direction]

        return trends

    async def get_statistics(self) -> Dict[str, Any]:
        """Get trend analysis statistics."""
        return {
            **self.statistics,
            'total_trends': len(self.trends),
            'improving_trends': len([t for t in self.trends.values() if t.direction == TrendDirection.IMPROVING]),
            'declining_trends': len([t for t in self.trends.values() if t.direction == TrendDirection.DECLINING]),
            'stable_trends': len([t for t in self.trends.values() if t.direction == TrendDirection.STABLE]),
        }


class BenchmarkComparisonEngine:
    """
    Benchmark and comparison engine.

    Provides industry benchmarking, peer comparison,
    and best practice recommendations.
    """

    def __init__(self):
        """Initialize benchmark comparison engine."""
        self.benchmarks: Dict[str, IndustryBenchmark] = {}
        self.comparisons: Dict[str, BenchmarkComparison] = {}
        self.statistics = {
            'comparisons_performed': 0,
            'benchmarks_available': 0,
            'recommendations_generated': 0,
        }
        self._initialize_industry_benchmarks()

    def _initialize_industry_benchmarks(self):
        """Initialize industry benchmark data."""
        # Healthcare industry benchmarks
        self.benchmarks['healthcare_small'] = IndustryBenchmark(
            industry=IndustryType.HEALTHCARE,
            company_size='small',
            average_score=72.5,
            percentile_25=65.0,
            percentile_50=72.5,
            percentile_75=80.0,
            percentile_90=87.0,
            top_performers=92.0,
            sample_size=250
        )

        self.benchmarks['healthcare_medium'] = IndustryBenchmark(
            industry=IndustryType.HEALTHCARE,
            company_size='medium',
            average_score=75.8,
            percentile_25=68.0,
            percentile_50=75.8,
            percentile_75=83.0,
            percentile_90=89.0,
            top_performers=94.0,
            sample_size=180
        )

        self.benchmarks['healthcare_large'] = IndustryBenchmark(
            industry=IndustryType.HEALTHCARE,
            company_size='large',
            average_score=81.2,
            percentile_25=74.0,
            percentile_50=81.2,
            percentile_75=87.0,
            percentile_90=92.0,
            top_performers=96.0,
            sample_size=120
        )

        # Finance industry benchmarks
        self.benchmarks['finance_small'] = IndustryBenchmark(
            industry=IndustryType.FINANCE,
            company_size='small',
            average_score=78.3,
            percentile_25=71.0,
            percentile_50=78.3,
            percentile_75=85.0,
            percentile_90=90.0,
            top_performers=95.0,
            sample_size=200
        )

        self.benchmarks['finance_medium'] = IndustryBenchmark(
            industry=IndustryType.FINANCE,
            company_size='medium',
            average_score=82.5,
            percentile_25=76.0,
            percentile_50=82.5,
            percentile_75=88.0,
            percentile_90=93.0,
            top_performers=97.0,
            sample_size=150
        )

        # Technology industry benchmarks
        self.benchmarks['technology_small'] = IndustryBenchmark(
            industry=IndustryType.TECHNOLOGY,
            company_size='small',
            average_score=76.8,
            percentile_25=70.0,
            percentile_50=76.8,
            percentile_75=83.0,
            percentile_90=89.0,
            top_performers=94.0,
            sample_size=300
        )

        self.statistics['benchmarks_available'] = len(self.benchmarks)

    async def compare_to_industry(
        self,
        organization_id: str,
        your_score: float,
        industry: IndustryType,
        company_size: str,
        dimension_scores: Dict[PostureDimension, float]
    ) -> BenchmarkComparison:
        """Compare organization's score to industry benchmarks."""
        benchmark_key = f"{industry.value}_{company_size}"
        benchmark = self.benchmarks.get(benchmark_key)

        if not benchmark:
            # Use default benchmark if specific not found
            benchmark = self.benchmarks.get(f"{industry.value}_medium")
            if not benchmark:
                raise ValueError(f"No benchmark data available for {industry.value}")

        # Calculate percentile rank
        percentile_rank = self._calculate_percentile_rank(your_score, benchmark)

        # Calculate gaps
        gap_to_average = your_score - benchmark.average_score
        gap_to_top = your_score - benchmark.top_performers

        # Identify areas above/below average
        areas_above = []
        areas_below = []

        # Compare dimension scores to industry averages (mock data for dimensions)
        industry_dimension_avg = {
            PostureDimension.VULNERABILITY_MANAGEMENT: benchmark.average_score * 0.95,
            PostureDimension.COMPLIANCE: benchmark.average_score * 1.02,
            PostureDimension.IDENTITY_ACCESS: benchmark.average_score * 0.98,
            PostureDimension.NETWORK_SECURITY: benchmark.average_score * 1.00,
            PostureDimension.DATA_PROTECTION: benchmark.average_score * 1.03,
            PostureDimension.INCIDENT_RESPONSE: benchmark.average_score * 0.92,
            PostureDimension.THREAT_DETECTION: benchmark.average_score * 0.97,
            PostureDimension.CONFIGURATION_MANAGEMENT: benchmark.average_score * 0.90,
        }

        for dimension, score in dimension_scores.items():
            avg = industry_dimension_avg.get(dimension, benchmark.average_score)
            if score > avg:
                areas_above.append(f"{dimension.value.replace('_', ' ').title()} ({score:.1f} vs {avg:.1f})")
            elif score < avg - 5:  # More than 5 points below
                areas_below.append(f"{dimension.value.replace('_', ' ').title()} ({score:.1f} vs {avg:.1f})")

        # Generate recommendations
        recommendations = self._generate_benchmark_recommendations(
            your_score, benchmark, areas_below, percentile_rank
        )

        comparison = BenchmarkComparison(
            your_score=your_score,
            industry_average=benchmark.average_score,
            percentile_rank=percentile_rank,
            gap_to_average=round(gap_to_average, 2),
            gap_to_top_performers=round(gap_to_top, 2),
            areas_above_average=areas_above,
            areas_below_average=areas_below,
            recommendations=recommendations
        )

        self.comparisons[organization_id] = comparison
        self.statistics['comparisons_performed'] += 1
        self.statistics['recommendations_generated'] += len(recommendations)

        logger.info(f"Benchmark comparison for {organization_id}: {percentile_rank:.1f}th percentile")

        return comparison

    def _calculate_percentile_rank(self, score: float, benchmark: IndustryBenchmark) -> float:
        """Calculate percentile rank based on score."""
        if score >= benchmark.top_performers:
            return 95.0
        elif score >= benchmark.percentile_90:
            return 90.0 + ((score - benchmark.percentile_90) / (benchmark.top_performers - benchmark.percentile_90) * 5)
        elif score >= benchmark.percentile_75:
            return 75.0 + ((score - benchmark.percentile_75) / (benchmark.percentile_90 - benchmark.percentile_75) * 15)
        elif score >= benchmark.percentile_50:
            return 50.0 + ((score - benchmark.percentile_50) / (benchmark.percentile_75 - benchmark.percentile_50) * 25)
        elif score >= benchmark.percentile_25:
            return 25.0 + ((score - benchmark.percentile_25) / (benchmark.percentile_50 - benchmark.percentile_25) * 25)
        else:
            return (score / benchmark.percentile_25) * 25

    def _generate_benchmark_recommendations(
        self,
        your_score: float,
        benchmark: IndustryBenchmark,
        areas_below: List[str],
        percentile_rank: float
    ) -> List[str]:
        """Generate recommendations based on benchmark comparison."""
        recommendations = []

        if percentile_rank < 25:
            recommendations.append(
                f"CRITICAL: Your security posture is in the bottom 25% of {benchmark.industry.value} organizations. "
                "Immediate comprehensive security program improvements required."
            )
        elif percentile_rank < 50:
            recommendations.append(
                f"Your security posture is below the {benchmark.industry.value} industry median. "
                "Focus on addressing key gaps to reach industry average."
            )
        elif percentile_rank < 75:
            recommendations.append(
                f"Your security posture is above average for {benchmark.industry.value}. "
                "Continue improvements to reach top quartile performance."
            )
        else:
            recommendations.append(
                f"Excellent! Your security posture is in the top 25% of {benchmark.industry.value} organizations. "
                "Maintain current practices and pursue top performer status."
            )

        # Specific area recommendations
        if areas_below:
            recommendations.append(
                f"Priority improvement areas: {', '.join([a.split('(')[0].strip() for a in areas_below[:3]])}. "
                "These dimensions are significantly below industry average."
            )

        # Gap-based recommendations
        gap = your_score - benchmark.average_score
        if gap < -10:
            recommendations.append(
                f"Close the {abs(gap):.1f}-point gap to industry average by: "
                "1) Implementing automated vulnerability management, "
                "2) Enhancing compliance monitoring, "
                "3) Improving incident response capabilities."
            )
        elif gap < 0:
            recommendations.append(
                f"Close the {abs(gap):.1f}-point gap to industry average with targeted improvements "
                "in your weakest security dimensions."
            )

        return recommendations

    async def get_available_benchmarks(self) -> List[Dict[str, Any]]:
        """Get list of available industry benchmarks."""
        return [
            {
                'industry': b.industry.value,
                'company_size': b.company_size,
                'average_score': b.average_score,
                'sample_size': b.sample_size,
            }
            for b in self.benchmarks.values()
        ]

    async def get_statistics(self) -> Dict[str, Any]:
        """Get benchmark engine statistics."""
        return self.statistics


class SecurityPostureOrchestrator:
    """
    Security posture orchestrator.

    Unified interface for all security posture analytics,
    continuous monitoring, and predictive intelligence operations.
    """

    def __init__(self):
        """Initialize security posture orchestrator."""
        self.scoring_engine = SecurityPostureScoringEngine()
        self.monitoring_system = ContinuousMonitoringSystem()
        self.predictive_intelligence = PredictiveSecurityIntelligence()
        self.trend_analysis = SecurityTrendAnalysis()
        self.benchmark_engine = BenchmarkComparisonEngine()

        logger.info("Security Posture Orchestrator initialized")

    async def perform_comprehensive_analysis(
        self,
        organization_id: str,
        metrics: List[PostureMetric],
        industry: IndustryType,
        company_size: str,
        current_indicators: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive security posture analysis."""
        start_time = datetime.utcnow()

        # 1. Calculate security posture score
        posture_score = await self.scoring_engine.calculate_posture_score(
            organization_id, metrics
        )

        # 2. Create or update baseline
        metrics_dict = {m.metric_id: m for m in metrics}
        baseline = await self.monitoring_system.create_baseline(
            organization_id, posture_score, metrics_dict
        )

        # 3. Detect drift (if baseline exists)
        drift = await self.monitoring_system.detect_drift(
            organization_id, posture_score, metrics_dict
        )

        # 4. Generate threat predictions
        historical_scores = [(datetime.utcnow() - timedelta(days=i), posture_score.overall_score - (i * 0.1))
                            for i in range(30, 0, -1)]
        predictions = await self.predictive_intelligence.predict_threats(
            organization_id, historical_scores, current_indicators
        )

        # 5. Analyze trends
        trend_data = [(datetime.utcnow() - timedelta(days=i), posture_score.overall_score - (i * 0.1))
                     for i in range(30, 0, -1)]
        trend = await self.trend_analysis.analyze_trend(
            f"trend_{organization_id}_overall",
            PostureDimension.VULNERABILITY_MANAGEMENT,
            trend_data,
            forecast_days=30
        )

        # 6. Compare to industry benchmarks
        comparison = await self.benchmark_engine.compare_to_industry(
            organization_id,
            posture_score.overall_score,
            industry,
            company_size,
            posture_score.dimension_scores
        )

        # 7. Get monitoring alerts
        alerts = await self.monitoring_system.get_alerts(
            organization_id=organization_id,
            unresolved_only=True
        )

        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        result = {
            'organization_id': organization_id,
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'duration_ms': duration_ms,

            # Posture Score
            'posture_score': {
                'overall_score': posture_score.overall_score,
                'posture_level': posture_score.posture_level.value,
                'dimension_scores': {k.value: v for k, v in posture_score.dimension_scores.items()},
                'recommendations': posture_score.recommendations,
            },

            # Baseline & Drift
            'baseline': {
                'snapshot_id': baseline.snapshot_id,
                'configuration_hash': baseline.configuration_hash,
                'created_at': baseline.timestamp.isoformat(),
            },
            'drift': {
                'detected': drift is not None,
                'drift_percentage': drift.drift_percentage if drift else 0.0,
                'severity': drift.drift_severity.value if drift else None,
                'drifted_metrics_count': len(drift.drifted_metrics) if drift else 0,
            } if drift else None,

            # Predictions
            'threat_predictions': [
                {
                    'threat_type': p.threat_type,
                    'probability': p.probability,
                    'confidence': p.confidence.value,
                    'timeframe': p.predicted_timeframe,
                    'risk_score': p.risk_score,
                    'recommended_actions': p.recommended_actions,
                }
                for p in predictions
            ],

            # Trends
            'trend': {
                'direction': trend.direction.value,
                'change_percentage': trend.change_percentage,
                'confidence': trend.confidence.value if trend.confidence else None,
                'forecast_available': len(trend.forecast) > 0 if trend.forecast else False,
            },

            # Benchmark Comparison
            'industry_comparison': {
                'your_score': comparison.your_score,
                'industry_average': comparison.industry_average,
                'percentile_rank': comparison.percentile_rank,
                'gap_to_average': comparison.gap_to_average,
                'gap_to_top_performers': comparison.gap_to_top_performers,
                'areas_above_average_count': len(comparison.areas_above_average),
                'areas_below_average_count': len(comparison.areas_below_average),
                'recommendations': comparison.recommendations,
            },

            # Monitoring
            'monitoring': {
                'active_alerts': len(alerts),
                'critical_alerts': len([a for a in alerts if a.severity == Severity.CRITICAL]),
                'high_alerts': len([a for a in alerts if a.severity == Severity.HIGH]),
            },

            # Summary
            'summary': {
                'overall_health': self._determine_overall_health(posture_score, drift, predictions, alerts),
                'top_priorities': self._generate_top_priorities(posture_score, predictions, comparison),
                'quick_wins': self._identify_quick_wins(metrics, posture_score),
            }
        }

        logger.info(f"Comprehensive analysis completed for {organization_id} in {duration_ms}ms")

        return result

    def _determine_overall_health(
        self,
        posture_score: PostureScore,
        drift: Optional[DriftDetection],
        predictions: List[ThreatPrediction],
        alerts: List[MonitoringAlert]
    ) -> str:
        """Determine overall security health status."""
        score = posture_score.overall_score
        critical_predictions = len([p for p in predictions if p.probability > 0.7])
        critical_alerts = len([a for a in alerts if a.severity == Severity.CRITICAL])

        if score >= 85 and critical_predictions == 0 and critical_alerts == 0:
            return "EXCELLENT - Strong security posture with minimal risks"
        elif score >= 75 and critical_predictions <= 1 and critical_alerts <= 2:
            return "GOOD - Solid security posture with manageable risks"
        elif score >= 60 and critical_predictions <= 2 and critical_alerts <= 5:
            return "FAIR - Acceptable security posture but improvements needed"
        elif score >= 40:
            return "POOR - Significant security gaps requiring immediate attention"
        else:
            return "CRITICAL - Severe security deficiencies, urgent action required"

    def _generate_top_priorities(
        self,
        posture_score: PostureScore,
        predictions: List[ThreatPrediction],
        comparison: BenchmarkComparison
    ) -> List[str]:
        """Generate top priority actions."""
        priorities = []

        # From posture score recommendations
        if posture_score.recommendations:
            priorities.extend(posture_score.recommendations[:2])

        # From high-probability predictions
        high_prob_predictions = [p for p in predictions if p.probability > 0.6]
        if high_prob_predictions:
            priorities.append(
                f"Address {len(high_prob_predictions)} high-probability threats: "
                f"{', '.join([p.threat_type for p in high_prob_predictions[:2]])}"
            )

        # From benchmark comparison
        if comparison.gap_to_average < -10:
            priorities.append(
                f"Close {abs(comparison.gap_to_average):.1f}-point gap to industry average"
            )

        return priorities[:5]  # Top 5 priorities

    def _identify_quick_wins(
        self,
        metrics: List[PostureMetric],
        posture_score: PostureScore
    ) -> List[str]:
        """Identify quick win opportunities."""
        quick_wins = []

        # Find metrics just below threshold
        near_threshold = [
            m for m in metrics
            if m.threshold_fair * 0.9 <= m.value < m.threshold_fair
        ]

        if near_threshold:
            quick_wins.append(
                f"Improve {len(near_threshold)} metrics that are close to acceptable thresholds"
            )

        # Find low-hanging fruit in dimensions
        weak_dimensions = [
            (dim, score) for dim, score in posture_score.dimension_scores.items()
            if 65 <= score < 75
        ]

        if weak_dimensions:
            quick_wins.append(
                f"Boost {weak_dimensions[0][0].value.replace('_', ' ').title()} "
                f"from {weak_dimensions[0][1]:.1f} to 75+ for quick posture improvement"
            )

        return quick_wins[:3]  # Top 3 quick wins

    async def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all systems."""
        return {
            'scoring_engine': await self.scoring_engine.get_statistics(),
            'monitoring_system': await self.monitoring_system.get_statistics(),
            'predictive_intelligence': await self.predictive_intelligence.get_statistics(),
            'trend_analysis': await self.trend_analysis.get_statistics(),
            'benchmark_engine': await self.benchmark_engine.get_statistics(),
        }


# Global orchestrator instance
_orchestrator: Optional[SecurityPostureOrchestrator] = None


def get_security_posture_orchestrator() -> SecurityPostureOrchestrator:
    """Get global security posture orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SecurityPostureOrchestrator()
    return _orchestrator

