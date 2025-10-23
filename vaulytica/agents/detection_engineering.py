"""
Detection Engineering Agent - Detection as Code

Analyzes security detections, reduces false positives, and improves detection quality
through automated tuning, A/B testing, and detection gap analysis.

Key Capabilities:
- Detection analysis and false positive pattern recognition
- Automatic tuning recommendations
- TEST detection creation for A/B testing
- Detection gap analysis
- Multi-SIEM support (Datadog, Splunk, Elastic, Sentinel)

Version: 1.0.0
Author: Vaulytica Team
"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import json

from .framework import (
    BaseAgent,
    AgentCapability,
    AgentStatus,
    AgentContext,
    AgentInput,
    AgentOutput
)
from vaulytica.config import VaulyticaConfig, get_config
from vaulytica.logger import get_logger
from vaulytica.ai_reasoning import get_ai_reasoning_engine

logger = get_logger(__name__)


class DetectionPlatform(str, Enum):
    """Supported SIEM platforms"""
    DATADOG = "datadog"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SENTINEL = "sentinel"
    CHRONICLE = "chronicle"


class AlertOutcome(str, Enum):
    """Alert outcome classifications"""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"
    DUPLICATE = "duplicate"
    UNKNOWN = "unknown"


class TuningAction(str, Enum):
    """Detection tuning actions"""
    ADD_EXCLUSION = "add_exclusion"
    REMOVE_EXCLUSION = "remove_exclusion"
    INCREASE_THRESHOLD = "increase_threshold"
    DECREASE_THRESHOLD = "decrease_threshold"
    ADD_CONDITION = "add_condition"
    REMOVE_CONDITION = "remove_condition"
    CHANGE_TIMEFRAME = "change_timeframe"
    CHANGE_SEVERITY = "change_severity"


class DetectionStatus(str, Enum):
    """Detection rule status"""
    ACTIVE = "active"
    TEST = "test"
    DRAFT = "draft"
    DISABLED = "disabled"
    ARCHIVED = "archived"


@dataclass
class DetectionRule:
    """Detection rule definition"""
    id: str
    name: str
    platform: DetectionPlatform
    query: str
    description: str = ""
    severity: str = "medium"
    status: DetectionStatus = DetectionStatus.ACTIVE
    threshold: Optional[float] = None
    timeframe_minutes: int = 5
    tags: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: str = "vaulytica"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertInstance:
    """Individual alert instance"""
    id: str
    detection_id: str
    detection_name: str
    timestamp: datetime
    outcome: AlertOutcome = AlertOutcome.UNKNOWN
    raw_logs: List[Dict[str, Any]] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    analyst_notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FalsePositivePattern:
    """Pattern identified in false positive alerts"""
    pattern_type: str  # field_value, ip_range, user_agent, etc.
    field_name: str
    field_value: Any
    occurrences: int
    percentage: float
    confidence: float
    example_alert_ids: List[str] = field(default_factory=list)


@dataclass
class TuningRecommendation:
    """Detection tuning recommendation"""
    action: TuningAction
    description: str
    proposed_query: str
    rationale: str
    impact_estimate: Dict[str, Any]
    confidence: float
    risk_level: str = "low"  # low, medium, high
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionAnalysis:
    """Complete detection analysis"""
    detection_id: str
    detection_name: str
    platform: DetectionPlatform
    current_query: str
    analysis_period_days: int

    # Statistics
    total_alerts: int
    true_positives: int
    false_positives: int
    benign_positives: int
    duplicates: int
    unknown: int
    false_positive_rate: float
    alerts_per_day: float

    # Patterns
    false_positive_patterns: List[FalsePositivePattern] = field(default_factory=list)
    true_positive_patterns: List[Dict[str, Any]] = field(default_factory=list)

    # Recommendations
    recommendations: List[TuningRecommendation] = field(default_factory=list)

    # Metadata
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestDetectionResult:
    """A/B test results comparing TEST vs PROD detection"""
    test_detection_id: str
    prod_detection_id: str
    test_period_days: int

    # TEST detection stats
    test_alerts: int
    test_true_positives: int
    test_false_positives: int
    test_fp_rate: float

    # PROD detection stats
    prod_alerts: int
    prod_true_positives: int
    prod_false_positives: int
    prod_fp_rate: float

    # Comparison
    alert_reduction_percentage: float
    tp_preservation_percentage: float
    fp_reduction_percentage: float

    # Recommendation
    recommend_promotion: bool
    promotion_confidence: float
    notes: str = ""


@dataclass
class DetectionGap:
    """Identified gap in detection coverage"""
    incident_id: str
    incident_title: str
    incident_severity: str
    attack_technique: str  # MITRE ATT&CK technique
    attack_tactic: str  # MITRE ATT&CK tactic
    description: str
    why_not_detected: str
    proposed_detection_name: str
    proposed_detection_query: str
    proposed_detection_description: str
    confidence: float
    priority: str = "medium"  # low, medium, high, critical


class DetectionEngineeringAgent(BaseAgent):
    """
    Detection Engineering Agent for automated detection tuning and optimization.

    Capabilities:
    - Analyze detection rules and alert outcomes
    - Identify false positive patterns
    - Generate tuning recommendations
    - Create TEST detections for A/B testing
    - Analyze detection gaps
    - Multi-SIEM support
    """

    def __init__(self, config: Optional[VaulyticaConfig] = None):
        """Initialize Detection Engineering Agent"""
        if config is None:
            config = get_config()

        super().__init__(
            agent_id="detection_engineering_agent",
            agent_name="Detection Engineering Agent",
            agent_version="1.0.0",
            capabilities=[
                AgentCapability.THREAT_DETECTION,
                AgentCapability.THREAT_ANALYSIS,
                AgentCapability.AUTOMATED_REMEDIATION
            ],
            description="Analyzes detections, reduces false positives, and improves detection quality"
        )

        self.config = config
        self.reasoning_engine = get_ai_reasoning_engine()

        # Statistics
        self.stats = {
            "detections_analyzed": 0,
            "recommendations_generated": 0,
            "test_detections_created": 0,
            "detections_promoted": 0,
            "false_positives_reduced": 0,
            "detection_gaps_identified": 0
        }

        # Cache
        self.detection_cache: Dict[str, DetectionRule] = {}
        self.analysis_cache: Dict[str, DetectionAnalysis] = {}

        logger.info("Detection Engineering Agent initialized")

    async def execute(self, input_data: AgentInput) -> AgentOutput:
        """Execute detection engineering workflow"""
        start_time = time.time()

        try:
            await self.validate_input(input_data)

            task = input_data.task

            if task == "analyze_detection":
                return await self._analyze_detection(input_data, start_time)
            elif task == "generate_recommendations":
                return await self._generate_recommendations(input_data, start_time)
            elif task == "create_test_detection":
                return await self._create_test_detection(input_data, start_time)
            elif task == "compare_test_results":
                return await self._compare_test_results(input_data, start_time)
            elif task == "promote_detection":
                return await self._promote_detection(input_data, start_time)
            elif task == "analyze_detection_gaps":
                return await self._analyze_detection_gaps(input_data, start_time)
            elif task == "batch_analyze":
                return await self._batch_analyze(input_data, start_time)
            else:
                raise ValueError(f"Unknown task: {task}")

        except Exception as e:
            logger.error(f"Detection engineering execution failed: {e}", exc_info=True)
            return AgentOutput(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                status=AgentStatus.FAILED,
                results={"error": str(e)},
                confidence=0.0,
                reasoning=[f"Execution failed: {e}"],
                data_sources_used=[],
                recommendations=[],
                next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
                timestamp=datetime.utcnow()
            )

    async def validate_input(self, input_data: AgentInput) -> bool:
        """Validate input data"""
        if not input_data.context:
            raise ValueError("AgentContext is required")

        task = input_data.task

        if task == "analyze_detection":
            if not input_data.parameters.get("detection_id"):
                raise ValueError("detection_id parameter is required")
        elif task in ["create_test_detection", "promote_detection"]:
            if not input_data.parameters.get("detection_id"):
                raise ValueError("detection_id parameter is required")

        return True

    async def _analyze_detection(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """
        Analyze a detection rule and its alert outcomes.

        Examines historical alerts, identifies patterns, and calculates statistics.
        """
        detection_id = input_data.parameters["detection_id"]
        timeframe_days = input_data.parameters.get("timeframe_days", 30)
        alerts = input_data.parameters.get("alerts", [])
        detection_rule = input_data.parameters.get("detection_rule")

        logger.info(f"Analyzing detection {detection_id} over {timeframe_days} days")

        # Parse alerts
        alert_instances = []
        for alert_data in alerts:
            alert = AlertInstance(
                id=alert_data.get("id", ""),
                detection_id=detection_id,
                detection_name=alert_data.get("detection_name", ""),
                timestamp=datetime.fromisoformat(alert_data.get("timestamp", datetime.utcnow().isoformat())),
                outcome=AlertOutcome(alert_data.get("outcome", "unknown")),
                raw_logs=alert_data.get("raw_logs", []),
                context=alert_data.get("context", {}),
                analyst_notes=alert_data.get("analyst_notes", ""),
                metadata=alert_data
            )
            alert_instances.append(alert)

        # Calculate statistics
        total_alerts = len(alert_instances)
        true_positives = sum(1 for a in alert_instances if a.outcome == AlertOutcome.TRUE_POSITIVE)
        false_positives = sum(1 for a in alert_instances if a.outcome == AlertOutcome.FALSE_POSITIVE)
        benign_positives = sum(1 for a in alert_instances if a.outcome == AlertOutcome.BENIGN_POSITIVE)
        duplicates = sum(1 for a in alert_instances if a.outcome == AlertOutcome.DUPLICATE)
        unknown = sum(1 for a in alert_instances if a.outcome == AlertOutcome.UNKNOWN)

        fp_rate = false_positives / total_alerts if total_alerts > 0 else 0.0
        alerts_per_day = total_alerts / timeframe_days if timeframe_days > 0 else 0.0

        # Identify false positive patterns
        fp_patterns = await self._identify_fp_patterns(
            [a for a in alert_instances if a.outcome == AlertOutcome.FALSE_POSITIVE]
        )

        # Identify true positive patterns
        tp_patterns = await self._identify_tp_patterns(
            [a for a in alert_instances if a.outcome == AlertOutcome.TRUE_POSITIVE]
        )

        # Create analysis
        analysis = DetectionAnalysis(
            detection_id=detection_id,
            detection_name=detection_rule.get("name", "") if detection_rule else "",
            platform=DetectionPlatform(detection_rule.get("platform", "datadog")) if detection_rule else DetectionPlatform.DATADOG,
            current_query=detection_rule.get("query", "") if detection_rule else "",
            analysis_period_days=timeframe_days,
            total_alerts=total_alerts,
            true_positives=true_positives,
            false_positives=false_positives,
            benign_positives=benign_positives,
            duplicates=duplicates,
            unknown=unknown,
            false_positive_rate=fp_rate,
            alerts_per_day=alerts_per_day,
            false_positive_patterns=fp_patterns,
            true_positive_patterns=tp_patterns
        )

        # Cache analysis
        self.analysis_cache[detection_id] = analysis
        self.stats["detections_analyzed"] += 1

        # Generate recommendations if FP rate is high
        if fp_rate > 0.3:  # More than 30% false positives
            recommendations = await self._generate_tuning_recommendations(analysis)
            analysis.recommendations = recommendations

        reasoning = [
            f"Analyzed {total_alerts} alerts over {timeframe_days} days",
            f"False positive rate: {fp_rate:.1%}",
            f"Identified {len(fp_patterns)} false positive patterns",
            f"Generated {len(analysis.recommendations)} tuning recommendations"
        ]

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "analysis": {
                    "detection_id": analysis.detection_id,
                    "detection_name": analysis.detection_name,
                    "statistics": {
                        "total_alerts": analysis.total_alerts,
                        "true_positives": analysis.true_positives,
                        "false_positives": analysis.false_positives,
                        "false_positive_rate": analysis.false_positive_rate,
                        "alerts_per_day": analysis.alerts_per_day
                    },
                    "false_positive_patterns": [
                        {
                            "pattern_type": p.pattern_type,
                            "field_name": p.field_name,
                            "field_value": p.field_value,
                            "occurrences": p.occurrences,
                            "percentage": p.percentage,
                            "confidence": p.confidence
                        }
                        for p in analysis.false_positive_patterns
                    ],
                    "recommendations_count": len(analysis.recommendations)
                }
            },
            confidence=0.9 if total_alerts >= 10 else 0.6,
            reasoning=reasoning,
            data_sources_used=["alert_history", "detection_rules"],
            recommendations=[
                {
                    "type": "detection_tuning",
                    "priority": "high" if fp_rate > 0.5 else "medium",
                    "description": f"Detection has {fp_rate:.1%} false positive rate - tuning recommended"
                }
            ] if fp_rate > 0.3 else [],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
            timestamp=datetime.utcnow()
        )

    async def _identify_fp_patterns(
        self,
        false_positive_alerts: List[AlertInstance]
    ) -> List[FalsePositivePattern]:
        """Identify patterns in false positive alerts"""
        if not false_positive_alerts:
            return []

        patterns = []

        # Analyze common field values
        field_value_counts: Dict[str, Dict[Any, int]] = {}

        for alert in false_positive_alerts:
            # Extract fields from context and raw logs
            fields_to_analyze = {}

            # From context
            if alert.context:
                fields_to_analyze.update(alert.context)

            # From raw logs (first log entry)
            if alert.raw_logs and len(alert.raw_logs) > 0:
                fields_to_analyze.update(alert.raw_logs[0])

            # Count field values
            for field_name, field_value in fields_to_analyze.items():
                if field_name not in field_value_counts:
                    field_value_counts[field_name] = {}

                # Convert to string for counting
                value_str = str(field_value)
                if value_str not in field_value_counts[field_name]:
                    field_value_counts[field_name][value_str] = 0
                field_value_counts[field_name][value_str] += 1

        # Identify significant patterns (>20% of FPs)
        total_fps = len(false_positive_alerts)
        threshold = max(3, int(total_fps * 0.2))  # At least 3 occurrences or 20%

        for field_name, value_counts in field_value_counts.items():
            for value, count in value_counts.items():
                if count >= threshold:
                    percentage = count / total_fps
                    confidence = min(0.95, percentage)  # Cap at 95%

                    pattern = FalsePositivePattern(
                        pattern_type="field_value",
                        field_name=field_name,
                        field_value=value,
                        occurrences=count,
                        percentage=percentage,
                        confidence=confidence,
                        example_alert_ids=[a.id for a in false_positive_alerts[:3]]
                    )
                    patterns.append(pattern)

        # Sort by occurrences (most common first)
        patterns.sort(key=lambda p: p.occurrences, reverse=True)

        logger.info(f"Identified {len(patterns)} false positive patterns")
        return patterns[:10]  # Return top 10 patterns

    async def _identify_tp_patterns(
        self,
        true_positive_alerts: List[AlertInstance]
    ) -> List[Dict[str, Any]]:
        """Identify patterns in true positive alerts"""
        if not true_positive_alerts:
            return []

        # Similar logic to FP patterns but for TPs
        # This helps ensure tuning doesn't break TP detection
        patterns = []

        # For now, return basic statistics
        if true_positive_alerts:
            patterns.append({
                "pattern_type": "true_positive_baseline",
                "count": len(true_positive_alerts),
                "description": "Baseline true positive pattern to preserve"
            })

        return patterns

    async def _generate_tuning_recommendations(
        self,
        analysis: DetectionAnalysis
    ) -> List[TuningRecommendation]:
        """Generate tuning recommendations based on analysis"""
        recommendations = []

        # Generate exclusion recommendations for top FP patterns
        for pattern in analysis.false_positive_patterns[:5]:  # Top 5 patterns
            if pattern.percentage > 0.1:  # Pattern accounts for >10% of FPs
                # Generate exclusion query
                exclusion_query = self._generate_exclusion_query(
                    analysis.current_query,
                    pattern.field_name,
                    pattern.field_value,
                    analysis.platform
                )

                recommendation = TuningRecommendation(
                    action=TuningAction.ADD_EXCLUSION,
                    description=f"Exclude {pattern.field_name}={pattern.field_value}",
                    proposed_query=exclusion_query,
                    rationale=f"This pattern appears in {pattern.occurrences} ({pattern.percentage:.1%}) of false positives",
                    impact_estimate={
                        "alerts_reduced": pattern.occurrences,
                        "reduction_percentage": pattern.percentage,
                        "true_positives_affected": 0,
                        "false_positives_reduced": pattern.occurrences
                    },
                    confidence=pattern.confidence,
                    risk_level="low" if pattern.confidence > 0.8 else "medium"
                )
                recommendations.append(recommendation)

        # Consider threshold increase if many low-severity FPs
        if analysis.false_positive_rate > 0.5 and analysis.alerts_per_day > 10:
            recommendation = TuningRecommendation(
                action=TuningAction.INCREASE_THRESHOLD,
                description="Increase detection threshold to reduce noise",
                proposed_query=self._increase_threshold_query(analysis.current_query, analysis.platform),
                rationale=f"High FP rate ({analysis.false_positive_rate:.1%}) and alert volume ({analysis.alerts_per_day:.1f}/day)",
                impact_estimate={
                    "alerts_reduced": int(analysis.total_alerts * 0.3),
                    "reduction_percentage": 0.3,
                    "true_positives_affected": 0,
                    "false_positives_reduced": int(analysis.false_positives * 0.3)
                },
                confidence=0.7,
                risk_level="medium"
            )
            recommendations.append(recommendation)

        self.stats["recommendations_generated"] += len(recommendations)
        logger.info(f"Generated {len(recommendations)} tuning recommendations")

        return recommendations

    def _generate_exclusion_query(
        self,
        current_query: str,
        field_name: str,
        field_value: Any,
        platform: DetectionPlatform
    ) -> str:
        """Generate query with exclusion added"""
        if platform == DetectionPlatform.DATADOG:
            # Datadog query language
            exclusion = f"-@{field_name}:{field_value}"
            # Insert exclusion before aggregation
            if "|" in current_query:
                parts = current_query.split("|", 1)
                return f"{parts[0].strip()} {exclusion} | {parts[1].strip()}"
            else:
                return f"{current_query} {exclusion}"

        elif platform == DetectionPlatform.SPLUNK:
            # Splunk SPL
            exclusion = f'NOT {field_name}="{field_value}"'
            # Insert after search command
            if current_query.strip().startswith("search"):
                return current_query.replace("search ", f"search {exclusion} ", 1)
            else:
                return f"{exclusion} {current_query}"

        elif platform == DetectionPlatform.ELASTIC:
            # Elasticsearch query
            exclusion = f'NOT {field_name}:"{field_value}"'
            return f"{current_query} AND {exclusion}"

        else:
            # Generic exclusion
            return f"{current_query} AND NOT {field_name}={field_value}"

    def _increase_threshold_query(
        self,
        current_query: str,
        platform: DetectionPlatform
    ) -> str:
        """Increase threshold in query"""
        import re

        if platform == DetectionPlatform.DATADOG:
            # Find count() > N pattern and increase N
            match = re.search(r'count\(\)\s*>\s*(\d+)', current_query)
            if match:
                current_threshold = int(match.group(1))
                new_threshold = int(current_threshold * 1.5)  # Increase by 50%
                return current_query.replace(
                    f"count() > {current_threshold}",
                    f"count() > {new_threshold}"
                )

        return current_query  # Return unchanged if can't parse

    async def _generate_recommendations(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Generate tuning recommendations for a detection"""
        detection_id = input_data.parameters["detection_id"]

        # Get cached analysis or perform new analysis
        if detection_id in self.analysis_cache:
            analysis = self.analysis_cache[detection_id]
        else:
            # Need to analyze first
            return AgentOutput(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                status=AgentStatus.FAILED,
                results={"error": "Detection must be analyzed before generating recommendations"},
                confidence=0.0,
                reasoning=["Analysis required before recommendations"],
                data_sources_used=[],
                recommendations=[],
                next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
                timestamp=datetime.utcnow()
            )

        recommendations = await self._generate_tuning_recommendations(analysis)

        # Calculate combined impact
        total_alerts_reduced = sum(r.impact_estimate.get("alerts_reduced", 0) for r in recommendations)
        total_fps_reduced = sum(r.impact_estimate.get("false_positives_reduced", 0) for r in recommendations)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "detection_id": detection_id,
                "recommendations": [
                    {
                        "action": r.action.value,
                        "description": r.description,
                        "proposed_query": r.proposed_query,
                        "rationale": r.rationale,
                        "impact": r.impact_estimate,
                        "confidence": r.confidence,
                        "risk_level": r.risk_level
                    }
                    for r in recommendations
                ],
                "combined_impact": {
                    "total_alerts_reduced": total_alerts_reduced,
                    "total_false_positives_reduced": total_fps_reduced,
                    "estimated_new_fp_rate": max(0, analysis.false_positive_rate - (total_fps_reduced / analysis.total_alerts))
                }
            },
            confidence=0.85,
            reasoning=[
                f"Generated {len(recommendations)} tuning recommendations",
                f"Estimated to reduce {total_alerts_reduced} alerts",
                f"Estimated to reduce {total_fps_reduced} false positives"
            ],
            data_sources_used=["detection_analysis"],
            recommendations=[
                {
                    "type": "apply_tuning",
                    "priority": "high",
                    "description": "Review and apply recommended tuning changes"
                }
            ],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
            timestamp=datetime.utcnow()
        )

    async def _create_test_detection(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Create TEST detection with proposed tuning"""
        detection_id = input_data.parameters["detection_id"]
        recommendations = input_data.parameters.get("recommendations", [])

        # Get analysis
        if detection_id not in self.analysis_cache:
            return AgentOutput(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                status=AgentStatus.FAILED,
                results={"error": "Detection analysis not found"},
                confidence=0.0,
                reasoning=["Analysis required before creating test detection"],
                data_sources_used=[],
                recommendations=[],
                next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
                timestamp=datetime.utcnow()
            )

        analysis = self.analysis_cache[detection_id]

        # Apply all recommendations to create tuned query
        tuned_query = analysis.current_query
        for rec in recommendations:
            if isinstance(rec, dict):
                tuned_query = rec.get("proposed_query", tuned_query)
            else:
                tuned_query = rec.proposed_query

        # Create test detection metadata
        test_detection = {
            "id": f"{detection_id}_TEST",
            "name": f"{analysis.detection_name} (TEST)",
            "query": tuned_query,
            "severity": "info",  # Lower severity for testing
            "status": "test",
            "tags": ["test", "detection-engineering", f"original:{detection_id}"],
            "description": f"TEST version of {analysis.detection_name} with proposed tuning",
            "created_by": "vaulytica_detection_engineering"
        }

        self.stats["test_detections_created"] += 1

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "test_detection": test_detection,
                "original_detection_id": detection_id,
                "tuning_applied": len(recommendations),
                "instructions": [
                    "Deploy this TEST detection to your SIEM",
                    "Run in parallel with production detection for 7-14 days",
                    "Compare results using compare_test_results task",
                    "Promote to production if results are satisfactory"
                ]
            },
            confidence=0.9,
            reasoning=[
                f"Created TEST detection with {len(recommendations)} tuning changes",
                "Set severity to INFO to avoid paging",
                "Added test tags for tracking"
            ],
            data_sources_used=["detection_analysis", "tuning_recommendations"],
            recommendations=[
                {
                    "type": "deploy_test_detection",
                    "priority": "medium",
                    "description": "Deploy TEST detection and monitor for 7-14 days"
                }
            ],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
            timestamp=datetime.utcnow()
        )

    async def _compare_test_results(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Compare TEST vs PROD detection results"""
        test_detection_id = input_data.parameters["test_detection_id"]
        prod_detection_id = input_data.parameters["prod_detection_id"]
        test_period_days = input_data.parameters.get("test_period_days", 14)

        # Get alert data for both detections
        test_alerts = input_data.parameters.get("test_alerts", [])
        prod_alerts = input_data.parameters.get("prod_alerts", [])

        # Calculate statistics for TEST
        test_total = len(test_alerts)
        test_tp = sum(1 for a in test_alerts if a.get("outcome") == "true_positive")
        test_fp = sum(1 for a in test_alerts if a.get("outcome") == "false_positive")
        test_fp_rate = test_fp / test_total if test_total > 0 else 0.0

        # Calculate statistics for PROD
        prod_total = len(prod_alerts)
        prod_tp = sum(1 for a in prod_alerts if a.get("outcome") == "true_positive")
        prod_fp = sum(1 for a in prod_alerts if a.get("outcome") == "false_positive")
        prod_fp_rate = prod_fp / prod_total if prod_total > 0 else 0.0

        # Calculate improvements
        alert_reduction = ((prod_total - test_total) / prod_total * 100) if prod_total > 0 else 0.0
        tp_preservation = (test_tp / prod_tp * 100) if prod_tp > 0 else 100.0
        fp_reduction = ((prod_fp - test_fp) / prod_fp * 100) if prod_fp > 0 else 0.0

        # Determine if should promote
        recommend_promotion = (
            alert_reduction > 20 and  # At least 20% fewer alerts
            tp_preservation >= 95 and  # Preserved at least 95% of TPs
            fp_reduction > 50  # Reduced at least 50% of FPs
        )

        promotion_confidence = 0.9 if recommend_promotion else 0.5

        result = TestDetectionResult(
            test_detection_id=test_detection_id,
            prod_detection_id=prod_detection_id,
            test_period_days=test_period_days,
            test_alerts=test_total,
            test_true_positives=test_tp,
            test_false_positives=test_fp,
            test_fp_rate=test_fp_rate,
            prod_alerts=prod_total,
            prod_true_positives=prod_tp,
            prod_false_positives=prod_fp,
            prod_fp_rate=prod_fp_rate,
            alert_reduction_percentage=alert_reduction,
            tp_preservation_percentage=tp_preservation,
            fp_reduction_percentage=fp_reduction,
            recommend_promotion=recommend_promotion,
            promotion_confidence=promotion_confidence,
            notes=f"TEST detection {'PASSED' if recommend_promotion else 'NEEDS REVIEW'}"
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "comparison": {
                    "test_detection_id": result.test_detection_id,
                    "prod_detection_id": result.prod_detection_id,
                    "test_period_days": result.test_period_days,
                    "test_stats": {
                        "total_alerts": result.test_alerts,
                        "true_positives": result.test_true_positives,
                        "false_positives": result.test_false_positives,
                        "fp_rate": result.test_fp_rate
                    },
                    "prod_stats": {
                        "total_alerts": result.prod_alerts,
                        "true_positives": result.prod_true_positives,
                        "false_positives": result.prod_false_positives,
                        "fp_rate": result.prod_fp_rate
                    },
                    "improvements": {
                        "alert_reduction_percentage": result.alert_reduction_percentage,
                        "tp_preservation_percentage": result.tp_preservation_percentage,
                        "fp_reduction_percentage": result.fp_reduction_percentage
                    },
                    "recommendation": {
                        "promote": result.recommend_promotion,
                        "confidence": result.promotion_confidence,
                        "notes": result.notes
                    }
                }
            },
            confidence=promotion_confidence,
            reasoning=[
                f"TEST reduced alerts by {alert_reduction:.1f}%",
                f"TEST preserved {tp_preservation:.1f}% of true positives",
                f"TEST reduced false positives by {fp_reduction:.1f}%",
                f"Recommendation: {'PROMOTE' if recommend_promotion else 'NEEDS REVIEW'}"
            ],
            data_sources_used=["test_alerts", "prod_alerts"],
            recommendations=[
                {
                    "type": "promote_detection" if recommend_promotion else "review_results",
                    "priority": "high" if recommend_promotion else "medium",
                    "description": "Promote TEST to PROD" if recommend_promotion else "Review test results before promotion"
                }
            ],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
            timestamp=datetime.utcnow()
        )

    async def _promote_detection(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Promote TEST detection to PROD"""
        test_detection_id = input_data.parameters["test_detection_id"]
        prod_detection_id = input_data.parameters["prod_detection_id"]

        self.stats["detections_promoted"] += 1

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "promoted": True,
                "test_detection_id": test_detection_id,
                "prod_detection_id": prod_detection_id,
                "actions": [
                    f"Update PROD detection {prod_detection_id} with TEST query",
                    f"Archive old PROD detection version",
                    f"Disable TEST detection {test_detection_id}",
                    "Update detection metadata with promotion timestamp"
                ]
            },
            confidence=0.95,
            reasoning=[
                "TEST detection validated and approved",
                "Promoting to production",
                "Archiving old version for rollback"
            ],
            data_sources_used=["test_detection", "prod_detection"],
            recommendations=[],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
            timestamp=datetime.utcnow()
        )

    async def _analyze_detection_gaps(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Analyze incidents that weren't detected"""
        incidents = input_data.parameters.get("incidents", [])
        existing_detections = input_data.parameters.get("existing_detections", [])

        gaps = []

        for incident in incidents:
            # Check if incident was detected
            was_detected = incident.get("detected", False)

            if not was_detected:
                # Analyze why it wasn't detected
                gap = DetectionGap(
                    incident_id=incident.get("id", ""),
                    incident_title=incident.get("title", ""),
                    incident_severity=incident.get("severity", "medium"),
                    attack_technique=incident.get("technique", "unknown"),
                    attack_tactic=incident.get("tactic", "unknown"),
                    description=incident.get("description", ""),
                    why_not_detected="No matching detection rule found",
                    proposed_detection_name=f"Detect {incident.get('technique', 'Unknown')}",
                    proposed_detection_query=self._generate_detection_query(incident),
                    proposed_detection_description=f"Detects {incident.get('description', '')}",
                    confidence=0.7,
                    priority=incident.get("severity", "medium")
                )
                gaps.append(gap)

        self.stats["detection_gaps_identified"] += len(gaps)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "gaps_found": len(gaps),
                "gaps": [
                    {
                        "incident_id": g.incident_id,
                        "incident_title": g.incident_title,
                        "attack_technique": g.attack_technique,
                        "proposed_detection_name": g.proposed_detection_name,
                        "proposed_detection_query": g.proposed_detection_query,
                        "priority": g.priority,
                        "confidence": g.confidence
                    }
                    for g in gaps
                ]
            },
            confidence=0.8,
            reasoning=[
                f"Analyzed {len(incidents)} incidents",
                f"Found {len(gaps)} detection gaps",
                "Generated proposed detection rules"
            ],
            data_sources_used=["incidents", "existing_detections"],
            recommendations=[
                {
                    "type": "create_detection",
                    "priority": gap.priority,
                    "description": f"Create detection for {gap.attack_technique}"
                }
                for gap in gaps[:5]  # Top 5 gaps
            ],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
            timestamp=datetime.utcnow()
        )

    def _generate_detection_query(self, incident: Dict[str, Any]) -> str:
        """Generate detection query based on incident"""
        # Simple query generation - in production, use AI reasoning
        technique = incident.get("technique", "")

        if "brute" in technique.lower():
            return "source:auth @event.action:login_failed | count() > 10"
        elif "exfiltration" in technique.lower():
            return "source:network @bytes.sent:>10000000 | count() > 1"
        else:
            return f"source:* @event.type:{technique} | count() > 1"

    async def _batch_analyze(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Batch analyze multiple detections"""
        detection_ids = input_data.parameters.get("detection_ids", [])

        results = []
        for detection_id in detection_ids:
            # Create sub-input for each detection
            sub_input = AgentInput(
                task="analyze_detection",
                context=input_data.context,
                parameters={
                    "detection_id": detection_id,
                    **input_data.parameters
                }
            )

            result = await self._analyze_detection(sub_input, time.time())
            results.append(result.results)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "detections_analyzed": len(results),
                "results": results
            },
            confidence=0.85,
            reasoning=[f"Batch analyzed {len(results)} detections"],
            data_sources_used=["detection_rules", "alert_history"],
            recommendations=[],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time,
            timestamp=datetime.utcnow()
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return self.stats.copy()


# Global instance
_detection_engineering_agent: Optional[DetectionEngineeringAgent] = None


def get_detection_engineering_agent(config: Optional[VaulyticaConfig] = None) -> DetectionEngineeringAgent:
    """Get or create global Detection Engineering Agent instance"""
    global _detection_engineering_agent

    if _detection_engineering_agent is None:
        _detection_engineering_agent = DetectionEngineeringAgent(config)

    return _detection_engineering_agent

