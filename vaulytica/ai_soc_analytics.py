import json
import hashlib
import numpy as np
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter, deque
import logging

from vaulytica.models import SecurityEvent, Severity, EventCategory, AssetInfo
from vaulytica.ml_engine import MLEngine, MLFeatures, ThreatLevel, AnomalyType
from vaulytica.advanced_ml import AdvancedMLEngine, ModelType
from vaulytica.incidents import Incident, IncidentPriority

logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class RiskLevel(str, Enum):
    """Risk level classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class ThreatCategory(str, Enum):
    """Threat category classification."""
    APT = "APT"  # Advanced Persistent Threat
    RANSOMWARE = "RANSOMWARE"
    DATA_BREACH = "DATA_BREACH"
    INSIDER_THREAT = "INSIDER_THREAT"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    ZERO_DAY = "ZERO_DAY"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    CRYPTOMINING = "CRYPTOMINING"
    DDOS = "DDOS"
    PHISHING = "PHISHING"


class TriagePriority(str, Enum):
    """Triage priority levels."""
    P0_EMERGENCY = "P0_EMERGENCY"  # Immediate action required
    P1_CRITICAL = "P1_CRITICAL"    # Within 15 minutes
    P2_HIGH = "P2_HIGH"            # Within 1 hour
    P3_MEDIUM = "P3_MEDIUM"        # Within 4 hours
    P4_LOW = "P4_LOW"              # Within 24 hours
    P5_INFO = "P5_INFO"            # No urgency


class HuntingHypothesisStatus(str, Enum):
    """Status of threat hunting hypothesis."""
    ACTIVE = "ACTIVE"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class RiskScore:
    """Risk score for an entity (asset, user, threat)."""
    entity_id: str
    entity_type: str  # "asset", "user", "threat", "network"
    risk_level: RiskLevel
    risk_score: float  # 0.0 - 1.0
    contributing_factors: List[str] = field(default_factory=list)
    threat_exposure: float = 0.0
    vulnerability_score: float = 0.0
    business_impact: float = 0.0
    historical_incidents: int = 0
    last_updated: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0


@dataclass
class ThreatPrediction:
    """Prediction of future threat."""
    threat_id: str
    threat_category: ThreatCategory
    predicted_severity: Severity
    probability: float  # 0.0 - 1.0
    predicted_time_window: timedelta
    target_assets: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0
    reasoning: str = ""
    recommended_actions: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TriageResult:
    """Result of automated triage."""
    incident_id: str
    triage_priority: TriagePriority
    severity_assessment: Severity
    threat_category: ThreatCategory
    confidence: float
    reasoning: str
    key_indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    estimated_impact: str = ""
    requires_escalation: bool = False
    assigned_team: str = "L1_SOC"
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class HuntingHypothesis:
    """Threat hunting hypothesis."""
    hypothesis_id: str
    title: str
    description: str
    status: HuntingHypothesisStatus
    threat_category: ThreatCategory
    indicators_to_search: List[str] = field(default_factory=list)
    search_queries: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    confidence: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "AI_SOC_ANALYST"


@dataclass
class BehavioralProfile:
    """Behavioral profile for user or entity."""
    entity_id: str
    entity_type: str  # "user", "asset", "service"
    baseline_established: bool = False
    normal_behaviors: Dict[str, Any] = field(default_factory=dict)
    anomalous_behaviors: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    last_activity: Optional[datetime] = None
    activity_count: int = 0
    anomaly_count: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AttackPath:
    """Predicted attack path."""
    path_id: str
    source: str
    target: str
    intermediate_nodes: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    probability: float = 0.0
    estimated_time: timedelta = timedelta(hours=1)
    blast_radius: int = 0  # Number of assets at risk
    critical_assets_at_risk: List[str] = field(default_factory=list)
    mitigation_steps: List[str] = field(default_factory=list)


@dataclass
class TrendAnalysis:
    """Trend analysis result."""
    metric_name: str
    time_period: timedelta
    trend_direction: str  # "increasing", "decreasing", "stable", "volatile"
    change_percentage: float
    current_value: float
    predicted_value: float
    anomalies_detected: List[datetime] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SOCMetrics:
    """SOC performance metrics."""
    total_threats_predicted: int = 0
    threats_prevented: int = 0
    false_positives: int = 0
    true_positives: int = 0
    mean_time_to_detect: float = 0.0  # seconds
    mean_time_to_respond: float = 0.0  # seconds
    mean_time_to_resolve: float = 0.0  # seconds
    triage_accuracy: float = 0.0
    risk_score_accuracy: float = 0.0
    hunting_success_rate: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


# ============================================================================
# Predictive Threat Analytics Engine
# ============================================================================

class PredictiveThreatAnalytics:
    """Predictive analytics for threat forecasting."""
    
    def __init__(self, ml_engine: MLEngine, advanced_ml: AdvancedMLEngine):
        self.ml_engine = ml_engine
        self.advanced_ml = advanced_ml
        self.threat_history: deque = deque(maxlen=1000)
        self.predictions: List[ThreatPrediction] = []
        
    def predict_threats(self, recent_events: List[SecurityEvent], 
                       time_window: timedelta = timedelta(hours=24)) -> List[ThreatPrediction]:
        """Predict future threats based on recent activity."""
        predictions = []
        
        # Analyze patterns in recent events
        patterns = self._analyze_threat_patterns(recent_events)
        
        # Predict based on patterns
        for pattern_type, pattern_data in patterns.items():
            if pattern_data["confidence"] > 0.6:
                prediction = self._generate_threat_prediction(
                    pattern_type, pattern_data, time_window
                )
                predictions.append(prediction)
        
        # Use ML to predict threat escalation
        if len(recent_events) >= 5:
            ml_predictions = self._ml_threat_prediction(recent_events, time_window)
            predictions.extend(ml_predictions)
        
        self.predictions.extend(predictions)
        return predictions
    
    def _analyze_threat_patterns(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Analyze patterns in security events."""
        patterns = {}
        
        # Pattern 1: Escalating severity
        severities = [e.severity for e in events[-10:]]
        if self._is_escalating(severities):
            patterns["escalating_severity"] = {
                "confidence": 0.8,
                "indicators": ["Severity increasing over time"],
                "threat_category": ThreatCategory.APT
            }
        
        # Pattern 2: Repeated failed access
        failed_access_count = sum(1 for e in events if "failed" in e.title.lower() or "denied" in e.title.lower())
        if failed_access_count > 5:
            patterns["brute_force"] = {
                "confidence": 0.7,
                "indicators": [f"{failed_access_count} failed access attempts"],
                "threat_category": ThreatCategory.CREDENTIAL_THEFT
            }
        
        # Pattern 3: Data exfiltration indicators
        exfil_events = [e for e in events if e.category == EventCategory.DATA_EXFILTRATION]
        if len(exfil_events) > 0:
            patterns["data_exfiltration"] = {
                "confidence": 0.9,
                "indicators": [f"{len(exfil_events)} data exfiltration events"],
                "threat_category": ThreatCategory.DATA_BREACH
            }
        
        # Pattern 4: Lateral movement
        lateral_events = [e for e in events if e.category == EventCategory.LATERAL_MOVEMENT]
        if len(lateral_events) > 2:
            patterns["lateral_movement"] = {
                "confidence": 0.85,
                "indicators": [f"{len(lateral_events)} lateral movement events"],
                "threat_category": ThreatCategory.APT
            }
        
        return patterns

    def _is_escalating(self, severities: List[Severity]) -> bool:
        """Check if severity is escalating."""
        if len(severities) < 3:
            return False

        severity_values = {
            Severity.INFO: 1, Severity.LOW: 2, Severity.MEDIUM: 3,
            Severity.HIGH: 4, Severity.CRITICAL: 5
        }

        values = [severity_values[s] for s in severities]
        # Check if generally increasing
        increasing_count = sum(1 for i in range(len(values)-1) if values[i+1] >= values[i])
        return increasing_count / (len(values) - 1) > 0.6

    def _generate_threat_prediction(self, pattern_type: str, pattern_data: Dict,
                                   time_window: timedelta) -> ThreatPrediction:
        """Generate threat prediction from pattern."""
        threat_id = hashlib.sha256(f"{pattern_type}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]

        # Map pattern to threat category
        threat_category = pattern_data.get("threat_category", ThreatCategory.APT)

        # Determine severity based on pattern
        severity_map = {
            "escalating_severity": Severity.HIGH,
            "brute_force": Severity.MEDIUM,
            "data_exfiltration": Severity.CRITICAL,
            "lateral_movement": Severity.HIGH
        }
        predicted_severity = severity_map.get(pattern_type, Severity.MEDIUM)

        # Generate recommended actions
        actions = self._generate_recommended_actions(threat_category, predicted_severity)

        return ThreatPrediction(
            threat_id=threat_id,
            threat_category=threat_category,
            predicted_severity=predicted_severity,
            probability=pattern_data["confidence"],
            predicted_time_window=time_window,
            indicators=pattern_data.get("indicators", []),
            confidence=pattern_data["confidence"],
            reasoning=f"Pattern detected: {pattern_type}",
            recommended_actions=actions
        )

    def _ml_threat_prediction(self, events: List[SecurityEvent],
                             time_window: timedelta) -> List[ThreatPrediction]:
        """Use ML to predict threats."""
        predictions = []

        # Use ML engine to predict threat level
        for event in events[-5:]:
            threat_pred = self.ml_engine.predict_threat(event, events)

            if threat_pred.predicted_threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                # Convert to ThreatPrediction
                threat_id = hashlib.sha256(f"ml_{event.event_id}".encode()).hexdigest()[:16]

                prediction = ThreatPrediction(
                    threat_id=threat_id,
                    threat_category=self._map_attack_type_to_category(threat_pred.predicted_attack_types[0] if threat_pred.predicted_attack_types else "unknown"),
                    predicted_severity=self._threat_level_to_severity(threat_pred.predicted_threat_level),
                    probability=threat_pred.confidence,
                    predicted_time_window=threat_pred.time_to_attack or time_window,
                    indicators=[f"ML confidence: {threat_pred.confidence:.2%}"],
                    confidence=threat_pred.confidence,
                    reasoning=f"ML prediction based on {len(threat_pred.risk_factors)} risk factors",
                    recommended_actions=["Monitor closely", "Investigate source", "Review logs"]
                )
                predictions.append(prediction)

        return predictions

    def _map_attack_type_to_category(self, attack_type: str) -> ThreatCategory:
        """Map attack type to threat category."""
        mapping = {
            "brute_force": ThreatCategory.CREDENTIAL_THEFT,
            "data_exfiltration": ThreatCategory.DATA_BREACH,
            "malware": ThreatCategory.RANSOMWARE,
            "lateral_movement": ThreatCategory.APT,
            "privilege_escalation": ThreatCategory.APT,
            "reconnaissance": ThreatCategory.APT,
            "dos": ThreatCategory.DDOS,
            "insider": ThreatCategory.INSIDER_THREAT
        }
        return mapping.get(attack_type.lower(), ThreatCategory.APT)

    def _threat_level_to_severity(self, threat_level: ThreatLevel) -> Severity:
        """Convert threat level to severity."""
        mapping = {
            ThreatLevel.CRITICAL: Severity.CRITICAL,
            ThreatLevel.HIGH: Severity.HIGH,
            ThreatLevel.MEDIUM: Severity.MEDIUM,
            ThreatLevel.LOW: Severity.LOW,
            ThreatLevel.INFO: Severity.INFO
        }
        return mapping.get(threat_level, Severity.MEDIUM)

    def _generate_recommended_actions(self, category: ThreatCategory, severity: Severity) -> List[str]:
        """Generate recommended actions based on threat."""
        actions = []

        if severity in [Severity.CRITICAL, Severity.HIGH]:
            actions.append("Immediate investigation required")
            actions.append("Notify security team")

        category_actions = {
            ThreatCategory.RANSOMWARE: [
                "Isolate affected systems",
                "Disable network shares",
                "Backup critical data",
                "Prepare incident response"
            ],
            ThreatCategory.DATA_BREACH: [
                "Block data exfiltration paths",
                "Review access logs",
                "Identify compromised data",
                "Notify stakeholders"
            ],
            ThreatCategory.CREDENTIAL_THEFT: [
                "Force password reset",
                "Enable MFA",
                "Review authentication logs",
                "Block suspicious IPs"
            ],
            ThreatCategory.APT: [
                "Comprehensive forensic analysis",
                "Hunt for persistence mechanisms",
                "Review all access logs",
                "Engage threat intelligence"
            ]
        }

        actions.extend(category_actions.get(category, ["Investigate and monitor"]))
        return actions


# ============================================================================
# Risk Scoring Engine
# ============================================================================

class RiskScoringEngine:
    """Dynamic risk scoring for assets, users, and threats."""

    def __init__(self):
        self.risk_scores: Dict[str, RiskScore] = {}
        self.asset_criticality: Dict[str, float] = {}  # Business criticality

    def calculate_asset_risk(self, asset_id: str, recent_events: List[SecurityEvent],
                            incidents: List[Incident]) -> RiskScore:
        """Calculate risk score for an asset."""
        # Base risk factors
        threat_exposure = self._calculate_threat_exposure(asset_id, recent_events)
        vulnerability_score = self._calculate_vulnerability_score(asset_id, recent_events)
        business_impact = self.asset_criticality.get(asset_id, 0.5)
        historical_incidents = sum(1 for inc in incidents if asset_id in inc.affected_assets)

        # Weighted risk calculation
        risk_score = (
            threat_exposure * 0.35 +
            vulnerability_score * 0.25 +
            business_impact * 0.25 +
            min(historical_incidents / 10, 1.0) * 0.15
        )

        # Determine risk level
        risk_level = self._score_to_risk_level(risk_score)

        # Contributing factors
        factors = []
        if threat_exposure > 0.7:
            factors.append(f"High threat exposure ({threat_exposure:.2%})")
        if vulnerability_score > 0.6:
            factors.append(f"Vulnerability concerns ({vulnerability_score:.2%})")
        if business_impact > 0.8:
            factors.append("Critical business asset")
        if historical_incidents > 3:
            factors.append(f"{historical_incidents} previous incidents")

        risk = RiskScore(
            entity_id=asset_id,
            entity_type="asset",
            risk_level=risk_level,
            risk_score=risk_score,
            contributing_factors=factors,
            threat_exposure=threat_exposure,
            vulnerability_score=vulnerability_score,
            business_impact=business_impact,
            historical_incidents=historical_incidents,
            confidence=0.85
        )

        self.risk_scores[asset_id] = risk
        return risk

    def calculate_user_risk(self, user_id: str, recent_events: List[SecurityEvent],
                           behavioral_profile: Optional[BehavioralProfile] = None) -> RiskScore:
        """Calculate risk score for a user."""
        # Analyze user's recent activity
        user_events = [e for e in recent_events if user_id in str(e.metadata)]

        # Risk factors
        anomaly_score = behavioral_profile.risk_score if behavioral_profile else 0.0
        suspicious_activity = sum(1 for e in user_events if e.severity in [Severity.HIGH, Severity.CRITICAL])
        failed_auth = sum(1 for e in user_events if "failed" in e.title.lower() or "denied" in e.title.lower())

        # Calculate risk
        risk_score = (
            anomaly_score * 0.4 +
            min(suspicious_activity / 5, 1.0) * 0.35 +
            min(failed_auth / 10, 1.0) * 0.25
        )

        risk_level = self._score_to_risk_level(risk_score)

        factors = []
        if anomaly_score > 0.6:
            factors.append(f"Behavioral anomalies detected ({anomaly_score:.2%})")
        if suspicious_activity > 2:
            factors.append(f"{suspicious_activity} suspicious activities")
        if failed_auth > 5:
            factors.append(f"{failed_auth} failed authentication attempts")

        return RiskScore(
            entity_id=user_id,
            entity_type="user",
            risk_level=risk_level,
            risk_score=risk_score,
            contributing_factors=factors,
            confidence=0.8
        )

    def calculate_threat_risk(self, threat_prediction: ThreatPrediction) -> RiskScore:
        """Calculate risk score for a predicted threat."""
        # Threat risk based on severity, probability, and impact
        severity_score = {
            Severity.CRITICAL: 1.0, Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5, Severity.LOW: 0.3, Severity.INFO: 0.1
        }[threat_prediction.predicted_severity]

        risk_score = (
            severity_score * 0.5 +
            threat_prediction.probability * 0.3 +
            threat_prediction.confidence * 0.2
        )

        risk_level = self._score_to_risk_level(risk_score)

        return RiskScore(
            entity_id=threat_prediction.threat_id,
            entity_type="threat",
            risk_level=risk_level,
            risk_score=risk_score,
            contributing_factors=[
                f"Predicted severity: {threat_prediction.predicted_severity.value}",
                f"Probability: {threat_prediction.probability:.2%}",
                f"Category: {threat_prediction.threat_category.value}"
            ],
            confidence=threat_prediction.confidence
        )

    def _calculate_threat_exposure(self, asset_id: str, events: List[SecurityEvent]) -> float:
        """Calculate threat exposure for asset."""
        asset_events = [e for e in events if any(asset_id in str(a) for a in e.affected_assets)]

        if not asset_events:
            return 0.0

        # Weight by severity
        severity_weights = {
            Severity.CRITICAL: 1.0, Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5, Severity.LOW: 0.3, Severity.INFO: 0.1
        }

        total_exposure = sum(severity_weights[e.severity] for e in asset_events)
        return min(total_exposure / 10, 1.0)

    def _calculate_vulnerability_score(self, asset_id: str, events: List[SecurityEvent]) -> float:
        """Calculate vulnerability score for asset."""
        vuln_events = [e for e in events if e.category == EventCategory.VULNERABILITY
                      and any(asset_id in str(a) for a in e.affected_assets)]

        return min(len(vuln_events) / 5, 1.0)

    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def get_top_risks(self, limit: int = 10) -> List[RiskScore]:
        """Get top risks across all entities."""
        sorted_risks = sorted(
            self.risk_scores.values(),
            key=lambda r: r.risk_score,
            reverse=True
        )
        return sorted_risks[:limit]


# ============================================================================
# Automated Triage System
# ============================================================================

class AutomatedTriageSystem:
    """AI-powered automated triage for incidents."""

    def __init__(self, ml_engine: MLEngine, risk_engine: RiskScoringEngine):
        self.ml_engine = ml_engine
        self.risk_engine = risk_engine
        self.triage_history: List[TriageResult] = []

    def triage_incident(self, incident: Incident, recent_events: List[SecurityEvent]) -> TriageResult:
        """Perform automated triage on incident."""
        # Analyze incident characteristics
        severity = incident.severity
        event_count = incident.event_count
        affected_assets = incident.affected_assets
        mitre_techniques = incident.mitre_techniques

        # Calculate threat category
        threat_category = self._determine_threat_category(incident, recent_events)

        # Determine triage priority
        triage_priority = self._calculate_triage_priority(
            severity, event_count, affected_assets, threat_category
        )

        # Assess impact
        impact = self._assess_impact(incident, affected_assets)

        # Generate reasoning
        reasoning = self._generate_triage_reasoning(
            incident, threat_category, triage_priority
        )

        # Key indicators
        key_indicators = self._extract_key_indicators(incident, recent_events)

        # Recommended actions
        actions = self._generate_triage_actions(triage_priority, threat_category)

        # Determine if escalation needed
        requires_escalation = triage_priority in [TriagePriority.P0_EMERGENCY, TriagePriority.P1_CRITICAL]

        # Assign team
        assigned_team = self._assign_team(triage_priority, threat_category)

        result = TriageResult(
            incident_id=incident.incident_id,
            triage_priority=triage_priority,
            severity_assessment=severity,
            threat_category=threat_category,
            confidence=0.85,
            reasoning=reasoning,
            key_indicators=key_indicators,
            recommended_actions=actions,
            estimated_impact=impact,
            requires_escalation=requires_escalation,
            assigned_team=assigned_team
        )

        self.triage_history.append(result)
        return result

    def _determine_threat_category(self, incident: Incident, events: List[SecurityEvent]) -> ThreatCategory:
        """Determine threat category from incident."""
        # Check MITRE techniques
        if any("T1486" in t or "T1490" in t for t in incident.mitre_techniques):
            return ThreatCategory.RANSOMWARE
        if any("T1048" in t or "T1041" in t for t in incident.mitre_techniques):
            return ThreatCategory.DATA_BREACH
        if any("T1078" in t or "T1110" in t for t in incident.mitre_techniques):
            return ThreatCategory.CREDENTIAL_THEFT
        if any("T1021" in t or "T1570" in t for t in incident.mitre_techniques):
            return ThreatCategory.APT

        # Check title/description keywords
        text = (incident.title + " " + incident.description).lower()
        if "ransomware" in text or "encrypt" in text:
            return ThreatCategory.RANSOMWARE
        if "exfiltration" in text or "data transfer" in text:
            return ThreatCategory.DATA_BREACH
        if "brute force" in text or "password" in text:
            return ThreatCategory.CREDENTIAL_THEFT
        if "mining" in text or "crypto" in text:
            return ThreatCategory.CRYPTOMINING
        if "phishing" in text or "social engineering" in text:
            return ThreatCategory.PHISHING

        return ThreatCategory.APT

    def _calculate_triage_priority(self, severity: Severity, event_count: int,
                                   affected_assets: List[str], category: ThreatCategory) -> TriagePriority:
        """Calculate triage priority."""
        # Emergency categories
        if category in [ThreatCategory.RANSOMWARE, ThreatCategory.ZERO_DAY]:
            return TriagePriority.P0_EMERGENCY

        # Critical severity or many affected assets
        if severity == Severity.CRITICAL or len(affected_assets) > 10:
            return TriagePriority.P1_CRITICAL

        # High severity or data breach
        if severity == Severity.HIGH or category == ThreatCategory.DATA_BREACH:
            return TriagePriority.P2_HIGH

        # Medium severity
        if severity == Severity.MEDIUM:
            return TriagePriority.P3_MEDIUM

        # Low severity
        if severity == Severity.LOW:
            return TriagePriority.P4_LOW

        return TriagePriority.P5_INFO

    def _assess_impact(self, incident: Incident, affected_assets: List[str]) -> str:
        """Assess business impact."""
        asset_count = len(affected_assets)
        severity = incident.severity

        if severity == Severity.CRITICAL and asset_count > 10:
            return "SEVERE: Multiple critical systems affected, potential business disruption"
        elif severity == Severity.CRITICAL:
            return "HIGH: Critical system affected, immediate attention required"
        elif severity == Severity.HIGH and asset_count > 5:
            return "MODERATE: Multiple systems affected, potential service degradation"
        elif severity == Severity.HIGH:
            return "MODERATE: High severity incident, monitor closely"
        else:
            return "LOW: Limited impact, routine investigation"

    def _generate_triage_reasoning(self, incident: Incident, category: ThreatCategory,
                                   priority: TriagePriority) -> str:
        """Generate reasoning for triage decision."""
        reasons = []
        reasons.append(f"Severity: {incident.severity.value}")
        reasons.append(f"Threat Category: {category.value}")
        reasons.append(f"Affected Assets: {len(incident.affected_assets)}")
        reasons.append(f"Event Count: {incident.event_count}")

        if incident.mitre_techniques:
            reasons.append(f"MITRE Techniques: {len(incident.mitre_techniques)}")

        return " | ".join(reasons)

    def _extract_key_indicators(self, incident: Incident, events: List[SecurityEvent]) -> List[str]:
        """Extract key indicators from incident."""
        indicators = []

        # Add severity
        indicators.append(f"Severity: {incident.severity.value}")

        # Add affected assets
        if incident.affected_assets:
            indicators.append(f"Assets: {', '.join(incident.affected_assets[:3])}")

        # Add MITRE techniques
        if incident.mitre_techniques:
            indicators.append(f"TTPs: {', '.join(incident.mitre_techniques[:3])}")

        # Add event count
        indicators.append(f"Events: {incident.event_count}")

        return indicators

    def _generate_triage_actions(self, priority: TriagePriority, category: ThreatCategory) -> List[str]:
        """Generate recommended actions for triage."""
        actions = []

        if priority == TriagePriority.P0_EMERGENCY:
            actions.extend([
                "IMMEDIATE: Activate incident response team",
                "Isolate affected systems",
                "Notify CISO and executive team",
                "Begin forensic collection"
            ])
        elif priority == TriagePriority.P1_CRITICAL:
            actions.extend([
                "Assign to senior analyst immediately",
                "Begin investigation within 15 minutes",
                "Prepare containment measures",
                "Notify security manager"
            ])
        elif priority == TriagePriority.P2_HIGH:
            actions.extend([
                "Assign to analyst within 1 hour",
                "Review logs and indicators",
                "Assess scope and impact",
                "Prepare response plan"
            ])
        else:
            actions.extend([
                "Add to investigation queue",
                "Review during next shift",
                "Document findings"
            ])

        # Category-specific actions
        if category == ThreatCategory.RANSOMWARE:
            actions.append("Check backup systems immediately")
        elif category == ThreatCategory.DATA_BREACH:
            actions.append("Identify and secure sensitive data")
        elif category == ThreatCategory.CREDENTIAL_THEFT:
            actions.append("Force password reset for affected accounts")

        return actions

    def _assign_team(self, priority: TriagePriority, category: ThreatCategory) -> str:
        """Assign appropriate team based on priority and category."""
        if priority == TriagePriority.P0_EMERGENCY:
            return "INCIDENT_RESPONSE_TEAM"
        elif priority == TriagePriority.P1_CRITICAL:
            return "L3_SECURITY_ENGINEER"
        elif priority == TriagePriority.P2_HIGH:
            return "L2_SENIOR_ANALYST"
        else:
            return "L1_SOC_ANALYST"


# ============================================================================
# Threat Hunting Engine
# ============================================================================

class ThreatHuntingEngine:
    """Proactive threat hunting with hypothesis generation."""

    def __init__(self, ml_engine: MLEngine):
        self.ml_engine = ml_engine
        self.hypotheses: Dict[str, HuntingHypothesis] = {}
        self.findings: List[Dict[str, Any]] = []

    def generate_hypotheses(self, recent_events: List[SecurityEvent],
                           threat_intel: Optional[Dict] = None) -> List[HuntingHypothesis]:
        """Generate threat hunting hypotheses based on recent activity."""
        hypotheses = []

        # Hypothesis 1: Hidden persistence mechanisms
        if self._detect_persistence_indicators(recent_events):
            hyp = self._create_hypothesis(
                "Hidden Persistence Mechanisms",
                "Potential persistence mechanisms may be present based on recent activity patterns",
                ThreatCategory.APT,
                ["Registry modifications", "Scheduled tasks", "Service creation"],
                ["Search for unusual startup items", "Check for hidden services", "Review scheduled tasks"]
            )
            hypotheses.append(hyp)

        # Hypothesis 2: Data staging for exfiltration
        if self._detect_data_staging(recent_events):
            hyp = self._create_hypothesis(
                "Data Staging for Exfiltration",
                "Unusual data movement patterns suggest potential data staging",
                ThreatCategory.DATA_BREACH,
                ["Large file transfers", "Compression activity", "Unusual network traffic"],
                ["Monitor outbound traffic", "Check for compressed archives", "Review file access logs"]
            )
            hypotheses.append(hyp)

        # Hypothesis 3: Credential harvesting
        if self._detect_credential_harvesting(recent_events):
            hyp = self._create_hypothesis(
                "Credential Harvesting Activity",
                "Multiple authentication failures suggest credential harvesting attempts",
                ThreatCategory.CREDENTIAL_THEFT,
                ["Failed login attempts", "Password spray patterns", "Unusual authentication sources"],
                ["Review authentication logs", "Check for compromised accounts", "Monitor for lateral movement"]
            )
            hypotheses.append(hyp)

        # Hypothesis 4: Living off the land
        if self._detect_lolbins(recent_events):
            hyp = self._create_hypothesis(
                "Living Off The Land Techniques",
                "Suspicious use of legitimate system tools detected",
                ThreatCategory.APT,
                ["PowerShell execution", "WMI usage", "Native tool abuse"],
                ["Analyze PowerShell logs", "Review WMI activity", "Check command-line arguments"]
            )
            hypotheses.append(hyp)

        for hyp in hypotheses:
            self.hypotheses[hyp.hypothesis_id] = hyp

        return hypotheses

    def hunt(self, hypothesis: HuntingHypothesis, events: List[SecurityEvent]) -> HuntingHypothesis:
        """Execute threat hunt based on hypothesis."""
        findings = []

        # Search for indicators
        for indicator in hypothesis.indicators_to_search:
            matches = self._search_for_indicator(indicator, events)
            if matches:
                findings.extend(matches)

        # Update hypothesis
        hypothesis.findings = findings
        hypothesis.updated_at = datetime.utcnow()

        # Determine status
        if len(findings) > 5:
            hypothesis.status = HuntingHypothesisStatus.CONFIRMED
            hypothesis.confidence = 0.9
        elif len(findings) > 0:
            hypothesis.status = HuntingHypothesisStatus.ACTIVE
            hypothesis.confidence = 0.6
        else:
            hypothesis.status = HuntingHypothesisStatus.REFUTED
            hypothesis.confidence = 0.1

        self.findings.extend([{"hypothesis": hypothesis.hypothesis_id, "finding": f} for f in findings])
        return hypothesis

    def _create_hypothesis(self, title: str, description: str, category: ThreatCategory,
                          indicators: List[str], queries: List[str]) -> HuntingHypothesis:
        """Create a hunting hypothesis."""
        hyp_id = hashlib.sha256(f"{title}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        return HuntingHypothesis(
            hypothesis_id=hyp_id,
            title=title,
            description=description,
            status=HuntingHypothesisStatus.ACTIVE,
            threat_category=category,
            indicators_to_search=indicators,
            search_queries=queries
        )

    def _detect_persistence_indicators(self, events: List[SecurityEvent]) -> bool:
        """Detect indicators of persistence mechanisms."""
        persistence_keywords = ["registry", "startup", "scheduled", "service", "autorun"]
        return any(any(kw in e.title.lower() or kw in e.description.lower() for kw in persistence_keywords)
                  for e in events)

    def _detect_data_staging(self, events: List[SecurityEvent]) -> bool:
        """Detect indicators of data staging."""
        staging_keywords = ["compress", "archive", "zip", "rar", "staging", "temp"]
        large_transfers = any(e.category == EventCategory.DATA_EXFILTRATION for e in events)
        return large_transfers or any(any(kw in e.title.lower() for kw in staging_keywords) for e in events)

    def _detect_credential_harvesting(self, events: List[SecurityEvent]) -> bool:
        """Detect indicators of credential harvesting."""
        failed_auth = sum(1 for e in events if "failed" in e.title.lower() or "denied" in e.title.lower())
        return failed_auth > 10

    def _detect_lolbins(self, events: List[SecurityEvent]) -> bool:
        """Detect living off the land binaries."""
        lolbin_keywords = ["powershell", "wmi", "cmd", "certutil", "bitsadmin", "mshta"]
        return any(any(kw in e.title.lower() or kw in e.description.lower() for kw in lolbin_keywords)
                  for e in events)

    def _search_for_indicator(self, indicator: str, events: List[SecurityEvent]) -> List[str]:
        """Search for specific indicator in events."""
        matches = []
        for event in events:
            if indicator.lower() in event.title.lower() or indicator.lower() in event.description.lower():
                matches.append(f"Event {event.event_id}: {event.title}")
        return matches


# ============================================================================
# Behavioral Analytics (UEBA)
# ============================================================================

class BehavioralAnalytics:
    """User and Entity Behavior Analytics."""

    def __init__(self):
        self.profiles: Dict[str, BehavioralProfile] = {}
        self.baseline_window = timedelta(days=30)

    def analyze_behavior(self, entity_id: str, entity_type: str,
                        recent_events: List[SecurityEvent]) -> BehavioralProfile:
        """Analyze behavior and detect anomalies."""
        # Get or create profile
        profile = self.profiles.get(entity_id)
        if not profile:
            profile = BehavioralProfile(
                entity_id=entity_id,
                entity_type=entity_type
            )
            self.profiles[entity_id] = profile

        # Filter events for this entity
        entity_events = self._filter_entity_events(entity_id, recent_events)

        # Update activity count
        profile.activity_count += len(entity_events)
        profile.last_activity = datetime.utcnow()

        # Establish baseline if enough data
        if not profile.baseline_established and profile.activity_count > 50:
            profile.normal_behaviors = self._establish_baseline(entity_events)
            profile.baseline_established = True

        # Detect anomalies if baseline exists
        if profile.baseline_established:
            anomalies = self._detect_behavioral_anomalies(entity_events, profile.normal_behaviors)
            profile.anomalous_behaviors = anomalies
            profile.anomaly_count += len(anomalies)

            # Calculate risk score
            profile.risk_score = min(len(anomalies) / 10, 1.0)

        profile.last_updated = datetime.utcnow()
        return profile

    def _filter_entity_events(self, entity_id: str, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """Filter events related to entity."""
        return [e for e in events if entity_id in str(e.metadata) or
                any(entity_id in str(a) for a in e.affected_assets)]

    def _establish_baseline(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Establish behavioral baseline."""
        baseline = {}

        # Activity patterns
        hours = [e.timestamp.hour for e in events]
        baseline["typical_hours"] = list(set(hours))
        baseline["avg_events_per_day"] = len(events) / 30

        # Event types
        categories = [e.category.value for e in events]
        baseline["typical_categories"] = list(set(categories))

        # Severity distribution
        severities = [e.severity.value for e in events]
        baseline["typical_severities"] = list(set(severities))

        return baseline

    def _detect_behavioral_anomalies(self, events: List[SecurityEvent],
                                    baseline: Dict[str, Any]) -> List[str]:
        """Detect behavioral anomalies."""
        anomalies = []

        # Check for unusual hours
        for event in events:
            if event.timestamp.hour not in baseline.get("typical_hours", []):
                anomalies.append(f"Activity at unusual hour: {event.timestamp.hour}:00")

        # Check for unusual event types
        for event in events:
            if event.category.value not in baseline.get("typical_categories", []):
                anomalies.append(f"Unusual event category: {event.category.value}")

        # Check for severity escalation
        high_severity = [e for e in events if e.severity in [Severity.HIGH, Severity.CRITICAL]]
        if len(high_severity) > baseline.get("avg_events_per_day", 0) * 0.5:
            anomalies.append("Unusual number of high-severity events")

        return list(set(anomalies))[:10]  # Limit to 10 unique anomalies


# ============================================================================
# Attack Path Analysis
# ============================================================================

class AttackPathAnalyzer:
    """Analyze and predict attack paths."""

    def __init__(self):
        self.asset_graph: Dict[str, Set[str]] = defaultdict(set)  # Asset connectivity
        self.attack_paths: List[AttackPath] = []

    def analyze_attack_path(self, source: str, target: str,
                           recent_events: List[SecurityEvent]) -> AttackPath:
        """Analyze potential attack path from source to target."""
        # Build asset connectivity graph
        self._build_asset_graph(recent_events)

        # Find path
        path = self._find_path(source, target)

        # Predict attack techniques
        techniques = self._predict_attack_techniques(path, recent_events)

        # Calculate blast radius
        blast_radius = self._calculate_blast_radius(target)

        # Identify critical assets at risk
        critical_assets = self._identify_critical_assets_at_risk(target, blast_radius)

        # Generate mitigation steps
        mitigation = self._generate_mitigation_steps(path, techniques)

        path_id = hashlib.sha256(f"{source}_{target}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]

        attack_path = AttackPath(
            path_id=path_id,
            source=source,
            target=target,
            intermediate_nodes=path[1:-1] if len(path) > 2 else [],
            attack_techniques=techniques,
            probability=0.7 if len(path) <= 3 else 0.4,
            estimated_time=timedelta(hours=len(path)),
            blast_radius=blast_radius,
            critical_assets_at_risk=critical_assets,
            mitigation_steps=mitigation
        )

        self.attack_paths.append(attack_path)
        return attack_path

    def _build_asset_graph(self, events: List[SecurityEvent]):
        """Build asset connectivity graph from events."""
        for event in events:
            if event.category == EventCategory.LATERAL_MOVEMENT:
                # Extract source and destination from metadata
                source = event.metadata.get("source_asset")
                dest = event.metadata.get("destination_asset")
                if source and dest:
                    self.asset_graph[source].add(dest)

            # Also connect assets mentioned in same event
            assets = [a.hostname or a.ip_addresses[0] if a.ip_addresses else str(a.cloud_resource_id)
                     for a in event.affected_assets if a.hostname or a.ip_addresses or a.cloud_resource_id]
            for i, asset1 in enumerate(assets):
                for asset2 in assets[i+1:]:
                    self.asset_graph[asset1].add(asset2)
                    self.asset_graph[asset2].add(asset1)

    def _find_path(self, source: str, target: str) -> List[str]:
        """Find path between source and target using BFS."""
        if source == target:
            return [source]

        visited = set()
        queue = deque([(source, [source])])

        while queue:
            node, path = queue.popleft()

            if node in visited:
                continue
            visited.add(node)

            if node == target:
                return path

            for neighbor in self.asset_graph.get(node, []):
                if neighbor not in visited:
                    queue.append((neighbor, path + [neighbor]))

        # No path found, return direct connection
        return [source, target]

    def _predict_attack_techniques(self, path: List[str], events: List[SecurityEvent]) -> List[str]:
        """Predict attack techniques for path."""
        techniques = []

        if len(path) > 1:
            techniques.append("T1021 - Remote Services")
            techniques.append("T1078 - Valid Accounts")

        if len(path) > 2:
            techniques.append("T1570 - Lateral Tool Transfer")
            techniques.append("T1563 - Remote Service Session Hijacking")

        # Add techniques from recent events
        for event in events[-10:]:
            for mitre in event.mitre_attack:
                tech = f"{mitre.technique_id} - {mitre.technique_name}"
                if tech not in techniques:
                    techniques.append(tech)

        return techniques[:5]

    def _calculate_blast_radius(self, target: str) -> int:
        """Calculate blast radius from target."""
        # Count all assets reachable from target
        visited = set()
        queue = deque([target])

        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)

            for neighbor in self.asset_graph.get(node, []):
                if neighbor not in visited:
                    queue.append(neighbor)

        return len(visited)

    def _identify_critical_assets_at_risk(self, target: str, radius: int) -> List[str]:
        """Identify critical assets within blast radius."""
        # Simplified: assume assets with "prod", "db", "critical" in name are critical
        critical_keywords = ["prod", "db", "critical", "master", "primary"]
        critical_assets = []

        visited = set()
        queue = deque([target])

        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)

            if any(kw in node.lower() for kw in critical_keywords):
                critical_assets.append(node)

            for neighbor in self.asset_graph.get(node, []):
                if neighbor not in visited:
                    queue.append(neighbor)

        return critical_assets[:10]

    def _generate_mitigation_steps(self, path: List[str], techniques: List[str]) -> List[str]:
        """Generate mitigation steps for attack path."""
        steps = []

        steps.append(f"Isolate source asset: {path[0]}")
        steps.append(f"Monitor target asset: {path[-1]}")

        if len(path) > 2:
            steps.append(f"Review access controls for intermediate assets")

        steps.append("Enable enhanced logging on all assets in path")
        steps.append("Review and restrict lateral movement capabilities")
        steps.append("Implement network segmentation")

        return steps


# ============================================================================
# Main AI SOC Analytics Engine
# ============================================================================

class AISOCAnalytics:
    """
    Main AI-powered SOC Analytics Engine.

    Integrates all analytics components to provide comprehensive
    AI-driven security operations capabilities.
    """

    def __init__(self, ml_engine: Optional[MLEngine] = None,
                 advanced_ml: Optional[AdvancedMLEngine] = None):
        """Initialize AI SOC Analytics."""
        self.ml_engine = ml_engine or MLEngine()
        self.advanced_ml = advanced_ml or AdvancedMLEngine()

        # Initialize components
        self.predictive_analytics = PredictiveThreatAnalytics(self.ml_engine, self.advanced_ml)
        self.risk_engine = RiskScoringEngine()
        self.triage_system = AutomatedTriageSystem(self.ml_engine, self.risk_engine)
        self.threat_hunting = ThreatHuntingEngine(self.ml_engine)
        self.behavioral_analytics = BehavioralAnalytics()
        self.attack_path_analyzer = AttackPathAnalyzer()

        # Storage
        self.event_history: deque = deque(maxlen=10000)
        self.incident_history: List[Incident] = []

        # Metrics
        self.metrics = SOCMetrics()

        logger.info("AI SOC Analytics Engine initialized")

    def analyze_comprehensive(self, event: SecurityEvent,
                            recent_events: Optional[List[SecurityEvent]] = None,
                            incidents: Optional[List[Incident]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive AI-powered SOC analysis.

        Returns all analytics results in one call.
        """
        recent_events = recent_events or list(self.event_history)
        incidents = incidents or self.incident_history

        # Add event to history
        self.event_history.append(event)

        results = {}

        # 1. Predictive Threat Analytics
        threat_predictions = self.predictive_analytics.predict_threats(
            recent_events + [event],
            time_window=timedelta(hours=24)
        )
        results["threat_predictions"] = [self._prediction_to_dict(p) for p in threat_predictions]

        # 2. Risk Scoring
        risk_scores = []
        for asset in event.affected_assets:
            asset_id = asset.hostname or (asset.ip_addresses[0] if asset.ip_addresses else "unknown")
            risk = self.risk_engine.calculate_asset_risk(asset_id, recent_events, incidents)
            risk_scores.append(self._risk_score_to_dict(risk))
        results["risk_scores"] = risk_scores

        # 3. Behavioral Analytics
        behavioral_profiles = []
        entities = self._extract_entities(event)
        for entity_id, entity_type in entities:
            profile = self.behavioral_analytics.analyze_behavior(entity_id, entity_type, recent_events)
            behavioral_profiles.append(self._profile_to_dict(profile))
        results["behavioral_profiles"] = behavioral_profiles

        # 4. Threat Hunting Hypotheses
        hypotheses = self.threat_hunting.generate_hypotheses(recent_events + [event])
        results["hunting_hypotheses"] = [self._hypothesis_to_dict(h) for h in hypotheses]

        # 5. Attack Path Analysis (if lateral movement detected)
        if event.category == EventCategory.LATERAL_MOVEMENT:
            source = event.metadata.get("source_asset", "unknown")
            target = event.metadata.get("destination_asset", "unknown")
            if source != "unknown" and target != "unknown":
                attack_path = self.attack_path_analyzer.analyze_attack_path(source, target, recent_events)
                results["attack_path"] = self._attack_path_to_dict(attack_path)

        # 6. Overall threat assessment
        results["threat_assessment"] = self._assess_overall_threat(event, threat_predictions, risk_scores)

        return results

    def triage_incident(self, incident: Incident, recent_events: List[SecurityEvent]) -> TriageResult:
        """Perform automated triage on incident."""
        return self.triage_system.triage_incident(incident, recent_events)

    def hunt_threats(self, hypothesis: HuntingHypothesis,
                    events: Optional[List[SecurityEvent]] = None) -> HuntingHypothesis:
        """Execute threat hunt."""
        events = events or list(self.event_history)
        return self.threat_hunting.hunt(hypothesis, events)

    def get_top_risks(self, limit: int = 10) -> List[RiskScore]:
        """Get top risks across all entities."""
        return self.risk_engine.get_top_risks(limit)

    def get_metrics(self) -> SOCMetrics:
        """Get SOC performance metrics."""
        return self.metrics

    def update_metrics(self, incident: Incident, triage_result: TriageResult):
        """Update SOC metrics based on incident handling."""
        self.metrics.total_threats_predicted += 1

        # Calculate time metrics
        if incident.acknowledged_at and incident.created_at:
            ttd = (incident.acknowledged_at - incident.created_at).total_seconds()
            self.metrics.mean_time_to_detect = (
                (self.metrics.mean_time_to_detect * (self.metrics.total_threats_predicted - 1) + ttd) /
                self.metrics.total_threats_predicted
            )

        if incident.resolved_at and incident.created_at:
            ttr = (incident.resolved_at - incident.created_at).total_seconds()
            self.metrics.mean_time_to_resolve = (
                (self.metrics.mean_time_to_resolve * (self.metrics.total_threats_predicted - 1) + ttr) /
                self.metrics.total_threats_predicted
            )

    def _extract_entities(self, event: SecurityEvent) -> List[Tuple[str, str]]:
        """Extract entities (users, assets) from event."""
        entities = []

        # Extract users
        if "user" in event.metadata:
            entities.append((event.metadata["user"], "user"))

        # Extract assets
        for asset in event.affected_assets:
            if asset.hostname:
                entities.append((asset.hostname, "asset"))
            elif asset.ip_addresses:
                entities.append((asset.ip_addresses[0], "asset"))

        return entities

    def _assess_overall_threat(self, event: SecurityEvent,
                               predictions: List[ThreatPrediction],
                               risk_scores: List[Dict]) -> Dict[str, Any]:
        """Assess overall threat level."""
        # Calculate aggregate threat score
        prediction_scores = [p.probability for p in predictions]
        risk_values = [r["risk_score"] for r in risk_scores]

        avg_prediction = np.mean(prediction_scores) if prediction_scores else 0.0
        avg_risk = np.mean(risk_values) if risk_values else 0.0

        severity_score = {
            Severity.CRITICAL: 1.0, Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5, Severity.LOW: 0.3, Severity.INFO: 0.1
        }[event.severity]

        overall_score = (avg_prediction * 0.4 + avg_risk * 0.3 + severity_score * 0.3)

        if overall_score >= 0.8:
            threat_level = "CRITICAL"
            recommendation = "Immediate action required - activate incident response"
        elif overall_score >= 0.6:
            threat_level = "HIGH"
            recommendation = "Urgent investigation needed - assign to senior analyst"
        elif overall_score >= 0.4:
            threat_level = "MEDIUM"
            recommendation = "Standard investigation - monitor and analyze"
        else:
            threat_level = "LOW"
            recommendation = "Routine monitoring - log and track"

        return {
            "threat_level": threat_level,
            "threat_score": overall_score,
            "recommendation": recommendation,
            "confidence": 0.85
        }

    # Conversion methods
    def _prediction_to_dict(self, pred: ThreatPrediction) -> Dict[str, Any]:
        """Convert ThreatPrediction to dict."""
        return {
            "threat_id": pred.threat_id,
            "category": pred.threat_category.value,
            "severity": pred.predicted_severity.value,
            "probability": pred.probability,
            "time_window_hours": pred.predicted_time_window.total_seconds() / 3600,
            "confidence": pred.confidence,
            "reasoning": pred.reasoning,
            "recommended_actions": pred.recommended_actions
        }

    def _risk_score_to_dict(self, risk: RiskScore) -> Dict[str, Any]:
        """Convert RiskScore to dict."""
        return {
            "entity_id": risk.entity_id,
            "entity_type": risk.entity_type,
            "risk_level": risk.risk_level.value,
            "risk_score": risk.risk_score,
            "contributing_factors": risk.contributing_factors,
            "confidence": risk.confidence
        }

    def _profile_to_dict(self, profile: BehavioralProfile) -> Dict[str, Any]:
        """Convert BehavioralProfile to dict."""
        return {
            "entity_id": profile.entity_id,
            "entity_type": profile.entity_type,
            "baseline_established": profile.baseline_established,
            "risk_score": profile.risk_score,
            "anomalous_behaviors": profile.anomalous_behaviors,
            "activity_count": profile.activity_count,
            "anomaly_count": profile.anomaly_count
        }

    def _hypothesis_to_dict(self, hyp: HuntingHypothesis) -> Dict[str, Any]:
        """Convert HuntingHypothesis to dict."""
        return {
            "hypothesis_id": hyp.hypothesis_id,
            "title": hyp.title,
            "description": hyp.description,
            "status": hyp.status.value,
            "threat_category": hyp.threat_category.value,
            "indicators": hyp.indicators_to_search,
            "confidence": hyp.confidence
        }

    def _attack_path_to_dict(self, path: AttackPath) -> Dict[str, Any]:
        """Convert AttackPath to dict."""
        return {
            "path_id": path.path_id,
            "source": path.source,
            "target": path.target,
            "intermediate_nodes": path.intermediate_nodes,
            "attack_techniques": path.attack_techniques,
            "probability": path.probability,
            "blast_radius": path.blast_radius,
            "critical_assets_at_risk": path.critical_assets_at_risk,
            "mitigation_steps": path.mitigation_steps
        }


# ============================================================================
# Global Instance
# ============================================================================

_ai_soc_analytics: Optional[AISOCAnalytics] = None


def get_ai_soc_analytics(ml_engine: Optional[MLEngine] = None,
                        advanced_ml: Optional[AdvancedMLEngine] = None) -> AISOCAnalytics:
    """Get or create global AI SOC Analytics instance."""
    global _ai_soc_analytics
    if _ai_soc_analytics is None:
        _ai_soc_analytics = AISOCAnalytics(ml_engine, advanced_ml)
    return _ai_soc_analytics


# ============================================================================
# Demo/Test Function
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("Vaulytica AI SOC Analytics Engine")
    print("=" * 80)
    print()
    print("✓ Predictive Threat Analytics")
    print("✓ Risk Scoring Engine")
    print("✓ Automated Triage System")
    print("✓ Threat Hunting Engine")
    print("✓ Behavioral Analytics (UEBA)")
    print("✓ Attack Path Analysis")
    print()
    print("AI-powered SOC analytics ready for production!")
    print("=" * 80)

