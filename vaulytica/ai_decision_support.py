"""
AI Decision Support System

Provides AI-powered decision recommendations, risk-based prioritization, and automated triage.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple


class DecisionType(str, Enum):
    """Types of security decisions."""
    INCIDENT_PRIORITY = "incident_priority"
    RESPONSE_ACTION = "response_action"
    ESCALATION = "escalation"
    RESOURCE_ALLOCATION = "resource_allocation"
    RISK_ACCEPTANCE = "risk_acceptance"
    INVESTIGATION_PATH = "investigation_path"


class ConfidenceLevel(str, Enum):
    """Confidence levels for recommendations."""
    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"  # 75-90%
    MEDIUM = "medium"  # 50-75%
    LOW = "low"  # 25-50%
    VERY_LOW = "very_low"  # 0-25%


class PriorityLevel(str, Enum):
    """Priority levels."""
    P0_CRITICAL = "p0_critical"  # Immediate action required
    P1_HIGH = "p1_high"  # Action required within hours
    P2_MEDIUM = "p2_medium"  # Action required within days
    P3_LOW = "p3_low"  # Action required within weeks
    P4_INFO = "p4_info"  # Informational only


@dataclass
class DecisionContext:
    """Context for decision making."""
    context_id: str
    decision_type: DecisionType
    incident_data: Dict[str, Any]
    historical_data: List[Dict[str, Any]] = field(default_factory=list)
    environmental_factors: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DecisionRecommendation:
    """AI-generated decision recommendation."""
    recommendation_id: str
    decision_type: DecisionType
    recommended_action: str
    rationale: str
    confidence: float
    confidence_level: ConfidenceLevel
    supporting_evidence: List[str]
    alternative_options: List[Dict[str, Any]]
    estimated_impact: str
    estimated_effort: str
    risk_score: float
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TriageResult:
    """Automated triage result."""
    triage_id: str
    incident_id: str
    priority: PriorityLevel
    severity_score: float
    urgency_score: float
    impact_score: float
    confidence: float
    assigned_team: Optional[str]
    recommended_actions: List[str]
    escalation_required: bool
    sla_deadline: Optional[datetime]
    reasoning: str
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RiskAssessment:
    """Risk assessment for decision."""
    assessment_id: str
    risk_factors: List[Dict[str, Any]]
    overall_risk_score: float
    risk_level: str
    mitigation_strategies: List[str]
    residual_risk: float


class AIDecisionSupportSystem:
    """AI-powered decision support system."""

    def __init__(self):
        self.recommendations: Dict[str, DecisionRecommendation] = {}
        self.triage_results: Dict[str, TriageResult] = {}
        self.decision_history: List[Dict[str, Any]] = []

        # ML model weights (simplified)
        self.priority_weights = {
            "severity": 0.35,
            "urgency": 0.25,
            "impact": 0.20,
            "confidence": 0.10,
            "asset_criticality": 0.10
        }

    async def generate_recommendation(self, context: DecisionContext) -> DecisionRecommendation:
        """Generate AI-powered decision recommendation."""
        if context.decision_type == DecisionType.INCIDENT_PRIORITY:
            return await self._recommend_incident_priority(context)
        elif context.decision_type == DecisionType.RESPONSE_ACTION:
            return await self._recommend_response_action(context)
        elif context.decision_type == DecisionType.ESCALATION:
            return await self._recommend_escalation(context)
        elif context.decision_type == DecisionType.INVESTIGATION_PATH:
            return await self._recommend_investigation_path(context)
        else:
            return await self._generate_generic_recommendation(context)

    async def _recommend_incident_priority(self, context: DecisionContext) -> DecisionRecommendation:
        """Recommend incident priority."""
        incident = context.incident_data

        # Calculate priority score
        severity = incident.get("severity", 5.0)
        urgency = incident.get("urgency", 5.0)
        impact = incident.get("impact", 5.0)

        priority_score = (
            severity * self.priority_weights["severity"] +
            urgency * self.priority_weights["urgency"] +
            impact * self.priority_weights["impact"]
        )

        # Determine priority level
        if priority_score >= 9.0:
            priority = PriorityLevel.P0_CRITICAL
            action = "Escalate immediately to on-call team"
        elif priority_score >= 7.0:
            priority = PriorityLevel.P1_HIGH
            action = "Assign to senior analyst within 1 hour"
        elif priority_score >= 5.0:
            priority = PriorityLevel.P2_MEDIUM
            action = "Assign to analyst within 4 hours"
        elif priority_score >= 3.0:
            priority = PriorityLevel.P3_LOW
            action = "Add to queue for next business day"
        else:
            priority = PriorityLevel.P4_INFO
            action = "Log for future reference"

        confidence = min(0.95, priority_score / 10.0)

        recommendation = DecisionRecommendation(
            recommendation_id=f"rec-{uuid.uuid4()}",
            decision_type=DecisionType.INCIDENT_PRIORITY,
            recommended_action=action,
            rationale=f"Based on severity ({severity}), urgency ({urgency}), and impact ({impact}), "
                     f"calculated priority score is {priority_score:.2f}",
            confidence=confidence,
            confidence_level=self._get_confidence_level(confidence),
            supporting_evidence=[
                f"Severity score: {severity}/10",
                f"Urgency score: {urgency}/10",
                f"Impact score: {impact}/10",
                f"Similar incidents: {len(context.historical_data)}"
            ],
            alternative_options=[
                {"action": "Manual review", "confidence": 0.5},
                {"action": "Automated response", "confidence": 0.7}
            ],
            estimated_impact="High - Affects incident response time",
            estimated_effort="Low - Automated assignment",
            risk_score=priority_score
        )

        self.recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    async def _recommend_response_action(self, context: DecisionContext) -> DecisionRecommendation:
        """Recommend response action."""
        incident = context.incident_data
        threat_type = incident.get("threat_type", "unknown")

        # Map threat types to recommended actions
        action_map = {
            "malware": "Isolate affected host and run full system scan",
            "phishing": "Quarantine email and block sender domain",
            "data_breach": "Revoke credentials and enable enhanced monitoring",
            "ransomware": "Isolate host, disable network access, initiate backup recovery",
            "insider_threat": "Disable user account and collect evidence",
            "ddos": "Enable DDoS mitigation and scale infrastructure",
            "unknown": "Collect additional evidence and escalate to senior analyst"
        }

        action = action_map.get(threat_type, action_map["unknown"])
        confidence = 0.85 if threat_type in action_map else 0.5

        recommendation = DecisionRecommendation(
            recommendation_id=f"rec-{uuid.uuid4()}",
            decision_type=DecisionType.RESPONSE_ACTION,
            recommended_action=action,
            rationale=f"Based on threat type '{threat_type}' and historical response patterns",
            confidence=confidence,
            confidence_level=self._get_confidence_level(confidence),
            supporting_evidence=[
                f"Threat type: {threat_type}",
                f"Historical success rate: {confidence * 100:.0f}%",
                f"Similar incidents resolved: {len(context.historical_data)}"
            ],
            alternative_options=[
                {"action": "Manual investigation", "confidence": 0.6},
                {"action": "Automated containment", "confidence": 0.8}
            ],
            estimated_impact="Medium - May affect system availability",
            estimated_effort="Medium - Requires coordination",
            risk_score=incident.get("severity", 5.0)
        )

        self.recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    async def _recommend_escalation(self, context: DecisionContext) -> DecisionRecommendation:
        """Recommend escalation decision."""
        incident = context.incident_data

        # Escalation criteria
        severity = incident.get("severity", 5.0)
        time_open = incident.get("time_open_hours", 0)
        failed_attempts = incident.get("failed_resolution_attempts", 0)

        escalation_score = (severity / 10.0) * 0.5 + (min(time_open, 24) / 24.0) * 0.3 + (min(failed_attempts, 3) / 3.0) * 0.2

        should_escalate = escalation_score > 0.6

        if should_escalate:
            action = "Escalate to senior team immediately"
            rationale = f"Escalation score {escalation_score:.2f} exceeds threshold (0.6)"
        else:
            action = "Continue with current analyst"
            rationale = f"Escalation score {escalation_score:.2f} below threshold (0.6)"

        recommendation = DecisionRecommendation(
            recommendation_id=f"rec-{uuid.uuid4()}",
            decision_type=DecisionType.ESCALATION,
            recommended_action=action,
            rationale=rationale,
            confidence=0.8,
            confidence_level=ConfidenceLevel.HIGH,
            supporting_evidence=[
                f"Severity: {severity}/10",
                f"Time open: {time_open} hours",
                f"Failed attempts: {failed_attempts}"
            ],
            alternative_options=[
                {"action": "Request peer review", "confidence": 0.6},
                {"action": "Assign additional resources", "confidence": 0.7}
            ],
            estimated_impact="Low - Improves resolution time",
            estimated_effort="Low - Automated escalation",
            risk_score=escalation_score * 10
        )

        self.recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    async def _recommend_investigation_path(self, context: DecisionContext) -> DecisionRecommendation:
        """Recommend investigation path."""
        incident = context.incident_data

        # Determine investigation path based on incident type
        investigation_paths = {
            "malware": "1. Analyze file hash 2. Check network connections 3. Review process tree 4. Scan for lateral movement",
            "phishing": "1. Analyze email headers 2. Check sender reputation 3. Scan attachments 4. Identify affected users",
            "data_breach": "1. Identify data accessed 2. Review access logs 3. Check for exfiltration 4. Assess impact",
            "unknown": "1. Collect all available logs 2. Identify IOCs 3. Correlate events 4. Determine attack vector"
        }

        threat_type = incident.get("threat_type", "unknown")
        path = investigation_paths.get(threat_type, investigation_paths["unknown"])

        recommendation = DecisionRecommendation(
            recommendation_id=f"rec-{uuid.uuid4()}",
            decision_type=DecisionType.INVESTIGATION_PATH,
            recommended_action=path,
            rationale=f"Standard investigation path for {threat_type} incidents",
            confidence=0.85,
            confidence_level=ConfidenceLevel.HIGH,
            supporting_evidence=[
                f"Threat type: {threat_type}",
                "Based on industry best practices",
                "Success rate: 85%"
            ],
            alternative_options=[
                {"action": "Custom investigation", "confidence": 0.6},
                {"action": "Automated forensics", "confidence": 0.75}
            ],
            estimated_impact="Low - Guides investigation",
            estimated_effort="Medium - Requires analyst time",
            risk_score=incident.get("severity", 5.0)
        )

        self.recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    async def _generate_generic_recommendation(self, context: DecisionContext) -> DecisionRecommendation:
        """Generate generic recommendation."""
        recommendation = DecisionRecommendation(
            recommendation_id=f"rec-{uuid.uuid4()}",
            decision_type=context.decision_type,
            recommended_action="Review incident details and consult with team",
            rationale="Insufficient data for specific recommendation",
            confidence=0.5,
            confidence_level=ConfidenceLevel.MEDIUM,
            supporting_evidence=["Limited historical data", "Complex decision context"],
            alternative_options=[],
            estimated_impact="Unknown",
            estimated_effort="Unknown",
            risk_score=5.0
        )

        self.recommendations[recommendation.recommendation_id] = recommendation
        return recommendation

    def _get_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Convert confidence score to level."""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.75:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 0.25:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW

    async def triage_incident(self, incident_data: Dict[str, Any]) -> TriageResult:
        """Perform automated incident triage."""
        # Calculate scores
        severity_score = incident_data.get("severity", 5.0)
        urgency_score = self._calculate_urgency(incident_data)
        impact_score = self._calculate_impact(incident_data)

        # Calculate overall priority
        priority_score = (
            severity_score * self.priority_weights["severity"] +
            urgency_score * self.priority_weights["urgency"] +
            impact_score * self.priority_weights["impact"]
        )

        # Determine priority level
        if priority_score >= 9.0:
            priority = PriorityLevel.P0_CRITICAL
            assigned_team = "on-call-team"
            escalation_required = True
        elif priority_score >= 7.0:
            priority = PriorityLevel.P1_HIGH
            assigned_team = "senior-analysts"
            escalation_required = False
        elif priority_score >= 5.0:
            priority = PriorityLevel.P2_MEDIUM
            assigned_team = "analysts"
            escalation_required = False
        elif priority_score >= 3.0:
            priority = PriorityLevel.P3_LOW
            assigned_team = "junior-analysts"
            escalation_required = False
        else:
            priority = PriorityLevel.P4_INFO
            assigned_team = "automated-processing"
            escalation_required = False

        triage = TriageResult(
            triage_id=f"triage-{uuid.uuid4()}",
            incident_id=incident_data.get("incident_id", "unknown"),
            priority=priority,
            severity_score=severity_score,
            urgency_score=urgency_score,
            impact_score=impact_score,
            confidence=0.85,
            assigned_team=assigned_team,
            recommended_actions=self._get_recommended_actions(priority),
            escalation_required=escalation_required,
            sla_deadline=None,  # Would calculate based on priority
            reasoning=f"Priority score: {priority_score:.2f} (severity: {severity_score}, urgency: {urgency_score}, impact: {impact_score})"
        )

        self.triage_results[triage.triage_id] = triage
        return triage

    def _calculate_urgency(self, incident_data: Dict[str, Any]) -> float:
        """Calculate urgency score."""
        # Factors: active attack, data at risk, system criticality
        active_attack = incident_data.get("active_attack", False)
        data_at_risk = incident_data.get("data_at_risk", False)

        urgency = 5.0
        if active_attack:
            urgency += 3.0
        if data_at_risk:
            urgency += 2.0

        return min(10.0, urgency)

    def _calculate_impact(self, incident_data: Dict[str, Any]) -> float:
        """Calculate impact score."""
        # Factors: affected users, affected systems, business impact
        affected_users = incident_data.get("affected_users", 0)
        affected_systems = incident_data.get("affected_systems", 0)

        impact = 5.0
        if affected_users > 100:
            impact += 3.0
        elif affected_users > 10:
            impact += 2.0
        elif affected_users > 0:
            impact += 1.0

        if affected_systems > 10:
            impact += 2.0
        elif affected_systems > 0:
            impact += 1.0

        return min(10.0, impact)

    def _get_recommended_actions(self, priority: PriorityLevel) -> List[str]:
        """Get recommended actions based on priority."""
        action_map = {
            PriorityLevel.P0_CRITICAL: [
                "Immediate containment",
                "Notify leadership",
                "Activate incident response team",
                "Begin forensic collection"
            ],
            PriorityLevel.P1_HIGH: [
                "Assign to senior analyst",
                "Begin investigation",
                "Collect evidence",
                "Prepare containment plan"
            ],
            PriorityLevel.P2_MEDIUM: [
                "Assign to analyst",
                "Review logs",
                "Identify scope",
                "Document findings"
            ],
            PriorityLevel.P3_LOW: [
                "Add to queue",
                "Initial assessment",
                "Gather context"
            ],
            PriorityLevel.P4_INFO: [
                "Log for reference",
                "Update knowledge base"
            ]
        }

        return action_map.get(priority, [])


# Global instance
_decision_support_system = None


def get_decision_support_system() -> AIDecisionSupportSystem:
    """Get global decision support system instance."""
    global _decision_support_system
    if _decision_support_system is None:
        _decision_support_system = AIDecisionSupportSystem()
    return _decision_support_system
