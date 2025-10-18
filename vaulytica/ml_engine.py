import json
import pickle
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from collections import defaultdict, Counter

from vaulytica.models import SecurityEvent, Severity
from vaulytica.threat_intel import ThreatLevel
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class MLModelType(str, Enum):
    """Machine learning model types."""
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    THREAT_PREDICTION = "THREAT_PREDICTION"
    ATTACK_CLUSTERING = "ATTACK_CLUSTERING"
    TIME_SERIES_FORECAST = "TIME_SERIES_FORECAST"
    BEHAVIORAL_BASELINE = "BEHAVIORAL_BASELINE"


class AnomalyType(str, Enum):
    """Types of anomalies detected."""
    VOLUME_SPIKE = "VOLUME_SPIKE"
    UNUSUAL_SOURCE = "UNUSUAL_SOURCE"
    UNUSUAL_TARGET = "UNUSUAL_TARGET"
    UNUSUAL_TIME = "UNUSUAL_TIME"
    UNUSUAL_PATTERN = "UNUSUAL_PATTERN"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"
    STATISTICAL_OUTLIER = "STATISTICAL_OUTLIER"


@dataclass
class MLFeatures:
    """Feature vector extracted from security events."""
    # Temporal features
    hour_of_day: int
    day_of_week: int
    is_weekend: bool
    is_business_hours: bool
    
    # Event characteristics
    severity_score: float  # 0-1
    threat_level_score: float  # 0-1
    event_type_hash: int
    source_entropy: float
    target_entropy: float
    
    # Behavioral features
    events_per_hour: float
    unique_sources: int
    unique_targets: int
    failed_attempts_ratio: float
    
    # Network features
    source_ip_reputation: float  # 0-1
    target_ip_reputation: float  # 0-1
    port_risk_score: float  # 0-1
    protocol_risk_score: float  # 0-1
    
    # Historical features
    source_history_score: float  # 0-1
    target_history_score: float  # 0-1
    pattern_frequency: float
    
    # IOC features
    ioc_count: int
    malicious_ioc_ratio: float
    ioc_confidence_avg: float
    
    # Metadata
    feature_timestamp: datetime = field(default_factory=datetime.utcnow)
    event_id: Optional[str] = None
    
    def to_vector(self) -> np.ndarray:
        """Convert features to numpy vector for ML models."""
        return np.array([
            self.hour_of_day / 24.0,
            self.day_of_week / 7.0,
            float(self.is_weekend),
            float(self.is_business_hours),
            self.severity_score,
            self.threat_level_score,
            self.event_type_hash / 1000000.0,  # Normalize hash
            self.source_entropy,
            self.target_entropy,
            self.events_per_hour / 100.0,  # Normalize
            self.unique_sources / 100.0,
            self.unique_targets / 100.0,
            self.failed_attempts_ratio,
            self.source_ip_reputation,
            self.target_ip_reputation,
            self.port_risk_score,
            self.protocol_risk_score,
            self.source_history_score,
            self.target_history_score,
            self.pattern_frequency,
            self.ioc_count / 10.0,  # Normalize
            self.malicious_ioc_ratio,
            self.ioc_confidence_avg
        ])


@dataclass
class AnomalyDetection:
    """Anomaly detection result."""
    is_anomaly: bool
    anomaly_score: float  # 0-1, higher = more anomalous
    anomaly_types: List[AnomalyType]
    confidence: float  # 0-1
    explanation: str
    features: MLFeatures
    detection_timestamp: datetime = field(default_factory=datetime.utcnow)
    model_version: str = "1.0"


@dataclass
class ThreatPrediction:
    """Threat prediction result."""
    predicted_threat_level: ThreatLevel
    probability: float  # 0-1
    confidence: float  # 0-1
    predicted_attack_types: List[str]
    time_to_attack: Optional[timedelta]  # Predicted time until attack
    risk_factors: List[str]
    mitigation_recommendations: List[str]
    prediction_timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AttackCluster:
    """Attack pattern cluster."""
    cluster_id: int
    cluster_name: str
    event_count: int
    common_features: Dict[str, Any]
    attack_types: List[str]
    severity_distribution: Dict[str, int]
    time_range: Tuple[datetime, datetime]
    representative_events: List[str]  # Event IDs


@dataclass
class ThreatForecast:
    """Time series threat forecast."""
    forecast_period: timedelta
    predicted_event_count: int
    confidence_interval: Tuple[int, int]  # (lower, upper)
    predicted_severity_distribution: Dict[str, float]
    trend: str  # INCREASING, DECREASING, STABLE
    seasonality_detected: bool
    forecast_timestamp: datetime = field(default_factory=datetime.utcnow)


class FeatureExtractor:
    """Extract ML features from security events."""
    
    def __init__(self):
        self.event_history: List[SecurityEvent] = []
        self.source_history: Dict[str, List[datetime]] = defaultdict(list)
        self.target_history: Dict[str, List[datetime]] = defaultdict(list)
        self.pattern_frequency: Dict[str, int] = Counter()
        
    def extract_features(self, event: SecurityEvent, context_events: Optional[List[SecurityEvent]] = None) -> MLFeatures:
        """Extract feature vector from security event."""
        timestamp = event.timestamp

        # Extract IPs from metadata
        source_ip = event.metadata.get("source_ip")
        target_ip = event.metadata.get("target_ip")

        # Temporal features
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday()
        is_weekend = day_of_week >= 5
        is_business_hours = 9 <= hour_of_day <= 17 and not is_weekend

        # Event characteristics
        severity_score = self._severity_to_score(event.severity)
        # Use category as a proxy for threat level
        threat_level_score = self._category_to_score(event.category)
        event_type_hash = abs(hash(event.title)) % 1000000

        # Calculate entropy
        source_entropy = self._calculate_entropy(source_ip or "unknown")
        target_entropy = self._calculate_entropy(target_ip or "unknown")
        
        # Behavioral features from context
        if context_events:
            events_per_hour = len([e for e in context_events
                                  if (timestamp - e.timestamp).total_seconds() < 3600])
            unique_sources = len(set(e.metadata.get("source_ip") for e in context_events
                                    if e.metadata.get("source_ip")))
            unique_targets = len(set(e.metadata.get("target_ip") for e in context_events
                                    if e.metadata.get("target_ip")))

            failed_events = len([e for e in context_events if "failed" in e.title.lower()])
            failed_attempts_ratio = failed_events / len(context_events) if context_events else 0.0
        else:
            events_per_hour = 1.0
            unique_sources = 1
            unique_targets = 1
            failed_attempts_ratio = 0.0

        # Network features (simplified scoring)
        source_ip_reputation = self._calculate_ip_reputation(source_ip)
        target_ip_reputation = self._calculate_ip_reputation(target_ip)
        port_risk_score = self._calculate_port_risk(event.metadata.get("port"))
        protocol_risk_score = self._calculate_protocol_risk(event.metadata.get("protocol"))

        # Historical features
        source_history_score = self._calculate_history_score(
            source_ip, self.source_history
        )
        target_history_score = self._calculate_history_score(
            target_ip, self.target_history
        )

        # Pattern frequency
        pattern_key = f"{event.title}:{source_ip}:{target_ip}"
        pattern_frequency = self.pattern_frequency.get(pattern_key, 0) / 100.0
        
        # IOC features
        ioc_count = len(event.technical_indicators) if event.technical_indicators else 0
        if ioc_count > 0:
            # TechnicalIndicator doesn't have reputation_score or confidence
            # Use heuristics based on indicator type and value
            malicious_count = sum(1 for ioc in event.technical_indicators
                                 if self._is_suspicious_indicator(ioc))
            malicious_ioc_ratio = malicious_count / ioc_count
            ioc_confidence_avg = 0.5  # Default confidence
        else:
            malicious_ioc_ratio = 0.0
            ioc_confidence_avg = 0.0

        # Update history
        if source_ip:
            self.source_history[source_ip].append(timestamp)
        if target_ip:
            self.target_history[target_ip].append(timestamp)
        self.pattern_frequency[pattern_key] += 1
        
        return MLFeatures(
            hour_of_day=hour_of_day,
            day_of_week=day_of_week,
            is_weekend=is_weekend,
            is_business_hours=is_business_hours,
            severity_score=severity_score,
            threat_level_score=threat_level_score,
            event_type_hash=event_type_hash,
            source_entropy=source_entropy,
            target_entropy=target_entropy,
            events_per_hour=events_per_hour,
            unique_sources=unique_sources,
            unique_targets=unique_targets,
            failed_attempts_ratio=failed_attempts_ratio,
            source_ip_reputation=source_ip_reputation,
            target_ip_reputation=target_ip_reputation,
            port_risk_score=port_risk_score,
            protocol_risk_score=protocol_risk_score,
            source_history_score=source_history_score,
            target_history_score=target_history_score,
            pattern_frequency=pattern_frequency,
            ioc_count=ioc_count,
            malicious_ioc_ratio=malicious_ioc_ratio,
            ioc_confidence_avg=ioc_confidence_avg,
            event_id=event.event_id
        )
    
    def _severity_to_score(self, severity: Severity) -> float:
        """Convert severity to 0-1 score."""
        mapping = {
            Severity.INFO: 0.0,
            Severity.LOW: 0.25,
            Severity.MEDIUM: 0.5,
            Severity.HIGH: 0.75,
            Severity.CRITICAL: 1.0
        }
        return mapping.get(severity, 0.5)

    def _category_to_score(self, category) -> float:
        """Convert event category to 0-1 threat score."""
        from vaulytica.models import EventCategory
        mapping = {
            EventCategory.UNKNOWN: 0.1,
            EventCategory.POLICY_VIOLATION: 0.2,
            EventCategory.VULNERABILITY: 0.3,
            EventCategory.RECONNAISSANCE: 0.4,
            EventCategory.UNAUTHORIZED_ACCESS: 0.6,
            EventCategory.DEFENSE_EVASION: 0.7,
            EventCategory.LATERAL_MOVEMENT: 0.8,
            EventCategory.DATA_EXFILTRATION: 0.9,
            EventCategory.MALWARE: 0.95,
            EventCategory.PERSISTENCE: 0.7,
            EventCategory.PRIVILEGE_ESCALATION: 0.8
        }
        return mapping.get(category, 0.5)
    
    def _threat_level_to_score(self, threat_level: ThreatLevel) -> float:
        """Convert threat level to 0-1 score."""
        mapping = {
            ThreatLevel.BENIGN: 0.0,
            ThreatLevel.UNKNOWN: 0.1,
            ThreatLevel.LOW: 0.2,
            ThreatLevel.MEDIUM: 0.4,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.CRITICAL: 1.0
        }
        return mapping.get(threat_level, 0.5)
    
    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string (0-1)."""
        if not value:
            return 0.0
        
        counts = Counter(value)
        length = len(value)
        entropy = -sum((count / length) * np.log2(count / length) 
                      for count in counts.values())
        
        # Normalize to 0-1 (max entropy for ASCII is ~6.6)
        return min(entropy / 6.6, 1.0)
    
    def _calculate_ip_reputation(self, ip: Optional[str]) -> float:
        """Calculate IP reputation score (0-1, higher = more suspicious)."""
        if not ip:
            return 0.5
        
        # Simple heuristics (in production, use threat intel)
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            return 0.1  # Private IP, low risk
        
        # Check for suspicious patterns
        if "198.51.100" in ip:  # Test range
            return 0.7
        
        return 0.3  # Default for public IPs
    
    def _calculate_port_risk(self, port: Optional[Any]) -> float:
        """Calculate port risk score (0-1)."""
        if not port:
            return 0.0
        
        try:
            port_num = int(port)
            # High-risk ports
            if port_num in [22, 23, 3389, 445, 135, 139]:
                return 0.8
            # Medium-risk ports
            elif port_num in [80, 443, 8080, 8443]:
                return 0.4
            # Low-risk ports
            else:
                return 0.2
        except (ValueError, TypeError):
            return 0.0
    
    def _calculate_protocol_risk(self, protocol: Optional[str]) -> float:
        """Calculate protocol risk score (0-1)."""
        if not protocol:
            return 0.0
        
        protocol = protocol.lower()
        risk_map = {
            "smb": 0.8,
            "rdp": 0.8,
            "ssh": 0.6,
            "telnet": 0.9,
            "ftp": 0.7,
            "http": 0.3,
            "https": 0.2,
            "dns": 0.2
        }
        return risk_map.get(protocol, 0.3)
    
    def _calculate_history_score(self, identifier: Optional[str],
                                 history: Dict[str, List[datetime]]) -> float:
        """Calculate historical activity score (0-1, higher = more active)."""
        if not identifier or identifier not in history:
            return 0.0

        events = history[identifier]
        if not events:
            return 0.0

        # Score based on frequency in last 24 hours
        recent_events = [e for e in events
                        if (datetime.utcnow() - e).total_seconds() < 86400]

        # Normalize to 0-1 (cap at 100 events)
        return min(len(recent_events) / 100.0, 1.0)

    def _is_suspicious_indicator(self, indicator) -> bool:
        """Check if indicator appears suspicious based on heuristics."""
        value = indicator.value.lower()
        ioc_type = indicator.indicator_type.lower()

        # Suspicious IP patterns
        if ioc_type == "ip":
            if "198.51.100" in value or "203.0.113" in value:
                return True

        # Suspicious domain patterns
        elif ioc_type == "domain":
            suspicious_keywords = ["evil", "malware", "phishing", "hack", "exploit"]
            if any(keyword in value for keyword in suspicious_keywords):
                return True

        # Suspicious hash patterns (simplified)
        elif ioc_type == "hash":
            if value.startswith("deadbeef"):
                return True

        return False


class MLEngine:
    """Machine Learning Engine for threat detection and prediction."""
    
    def __init__(self, enable_training: bool = True):
        self.feature_extractor = FeatureExtractor()
        self.enable_training = enable_training
        
        # Training data storage
        self.training_features: List[MLFeatures] = []
        self.training_labels: List[int] = []  # 0 = benign, 1 = malicious
        
        # Model storage (simplified - in production use scikit-learn)
        self.anomaly_threshold = 0.7
        self.threat_threshold = 0.6
        
        # Statistics
        self.total_predictions = 0
        self.anomalies_detected = 0
        self.threats_predicted = 0
        
        logger.info("ML Engine initialized")
    
    def detect_anomaly(self, event: SecurityEvent, 
                      context_events: Optional[List[SecurityEvent]] = None) -> AnomalyDetection:
        """Detect anomalies in security event using ML."""
        # Extract features
        features = self.feature_extractor.extract_features(event, context_events)
        feature_vector = features.to_vector()
        
        # Calculate anomaly score (simplified Isolation Forest logic)
        anomaly_score = self._calculate_anomaly_score(feature_vector)
        is_anomaly = anomaly_score > self.anomaly_threshold
        
        # Detect specific anomaly types
        anomaly_types = self._detect_anomaly_types(features, context_events or [])
        
        # Calculate confidence
        confidence = abs(anomaly_score - 0.5) * 2  # Distance from decision boundary
        
        # Generate explanation
        explanation = self._generate_anomaly_explanation(features, anomaly_types, anomaly_score)
        
        if is_anomaly:
            self.anomalies_detected += 1
        
        self.total_predictions += 1
        
        return AnomalyDetection(
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            anomaly_types=anomaly_types,
            confidence=confidence,
            explanation=explanation,
            features=features
        )

    def predict_threat(self, event: SecurityEvent,
                      context_events: Optional[List[SecurityEvent]] = None) -> ThreatPrediction:
        """Predict threat level and attack types using ML."""
        # Extract features
        features = self.feature_extractor.extract_features(event, context_events)
        feature_vector = features.to_vector()

        # Predict threat level (simplified Random Forest logic)
        threat_score = self._calculate_threat_score(feature_vector)
        predicted_threat_level = self._score_to_threat_level(threat_score)

        # Predict attack types
        predicted_attack_types = self._predict_attack_types(features)

        # Estimate time to attack
        time_to_attack = self._estimate_time_to_attack(features, threat_score)

        # Identify risk factors
        risk_factors = self._identify_risk_factors(features)

        # Generate mitigation recommendations
        mitigation_recommendations = self._generate_mitigations(
            predicted_threat_level, predicted_attack_types
        )

        # Calculate confidence
        confidence = min(threat_score, 1.0)

        if threat_score > self.threat_threshold:
            self.threats_predicted += 1

        return ThreatPrediction(
            predicted_threat_level=predicted_threat_level,
            probability=threat_score,
            confidence=confidence,
            predicted_attack_types=predicted_attack_types,
            time_to_attack=time_to_attack,
            risk_factors=risk_factors,
            mitigation_recommendations=mitigation_recommendations
        )

    def cluster_attacks(self, events: List[SecurityEvent],
                       num_clusters: int = 5) -> List[AttackCluster]:
        """Cluster attack patterns using K-Means."""
        if len(events) < num_clusters:
            num_clusters = max(1, len(events) // 2)

        # Extract features for all events
        feature_vectors = []
        feature_objects = []

        for event in events:
            features = self.feature_extractor.extract_features(event)
            feature_vectors.append(features.to_vector())
            feature_objects.append((features, event))

        if not feature_vectors:
            return []

        # Perform clustering (simplified K-Means)
        clusters = self._kmeans_clustering(feature_vectors, num_clusters)

        # Build cluster objects
        attack_clusters = []
        for cluster_id in range(num_clusters):
            cluster_indices = [i for i, c in enumerate(clusters) if c == cluster_id]

            if not cluster_indices:
                continue

            cluster_events = [events[i] for i in cluster_indices]
            cluster_features = [feature_objects[i][0] for i in cluster_indices]

            # Analyze cluster
            common_features = self._extract_common_features(cluster_features)
            attack_types = list(set(e.title for e in cluster_events))

            severity_dist = Counter(e.severity.value for e in cluster_events)

            timestamps = [e.timestamp for e in cluster_events]
            time_range = (min(timestamps), max(timestamps))

            # Select representative events (up to 5)
            representative_events = [e.event_id for e in cluster_events[:5]]

            # Generate cluster name
            cluster_name = self._generate_cluster_name(attack_types, common_features)

            attack_clusters.append(AttackCluster(
                cluster_id=cluster_id,
                cluster_name=cluster_name,
                event_count=len(cluster_events),
                common_features=common_features,
                attack_types=attack_types,
                severity_distribution=dict(severity_dist),
                time_range=time_range,
                representative_events=representative_events
            ))

        return attack_clusters

    def forecast_threats(self, historical_events: List[SecurityEvent],
                        forecast_hours: int = 24) -> ThreatForecast:
        """Forecast future threats using time series analysis."""
        if not historical_events:
            return ThreatForecast(
                forecast_period=timedelta(hours=forecast_hours),
                predicted_event_count=0,
                confidence_interval=(0, 0),
                predicted_severity_distribution={},
                trend="STABLE",
                seasonality_detected=False
            )

        # Group events by hour
        hourly_counts = defaultdict(int)
        severity_counts = defaultdict(lambda: defaultdict(int))

        for event in historical_events:
            hour_key = event.timestamp.replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour_key] += 1
            severity_counts[hour_key][event.severity.value] += 1

        # Calculate trend
        sorted_hours = sorted(hourly_counts.keys())
        if len(sorted_hours) >= 2:
            recent_avg = np.mean([hourly_counts[h] for h in sorted_hours[-6:]])
            older_avg = np.mean([hourly_counts[h] for h in sorted_hours[:6]])

            if recent_avg > older_avg * 1.2:
                trend = "INCREASING"
            elif recent_avg < older_avg * 0.8:
                trend = "DECREASING"
            else:
                trend = "STABLE"
        else:
            trend = "STABLE"

        # Detect seasonality (simplified)
        seasonality_detected = self._detect_seasonality(hourly_counts)

        # Forecast event count (simple moving average)
        recent_counts = [hourly_counts[h] for h in sorted_hours[-24:]]
        if recent_counts:
            predicted_hourly = np.mean(recent_counts)
            predicted_event_count = int(predicted_hourly * forecast_hours)

            # Confidence interval (±20%)
            lower_bound = int(predicted_event_count * 0.8)
            upper_bound = int(predicted_event_count * 1.2)
        else:
            predicted_event_count = 0
            lower_bound = 0
            upper_bound = 0

        # Predict severity distribution
        total_events = sum(hourly_counts.values())
        severity_totals = defaultdict(int)
        for hour_severities in severity_counts.values():
            for severity, count in hour_severities.items():
                severity_totals[severity] += count

        predicted_severity_distribution = {
            severity: count / total_events if total_events > 0 else 0.0
            for severity, count in severity_totals.items()
        }

        return ThreatForecast(
            forecast_period=timedelta(hours=forecast_hours),
            predicted_event_count=predicted_event_count,
            confidence_interval=(lower_bound, upper_bound),
            predicted_severity_distribution=predicted_severity_distribution,
            trend=trend,
            seasonality_detected=seasonality_detected
        )

    def train_model(self, events: List[SecurityEvent], labels: List[int]):
        """Train ML models on labeled data."""
        if not self.enable_training:
            logger.warning("Training is disabled")
            return

        if len(events) != len(labels):
            raise ValueError("Events and labels must have same length")

        # Extract features
        for event, label in zip(events, labels):
            features = self.feature_extractor.extract_features(event)
            self.training_features.append(features)
            self.training_labels.append(label)

        logger.info(f"Trained on {len(events)} events")

    def get_statistics(self) -> Dict[str, Any]:
        """Get ML engine statistics."""
        return {
            "total_predictions": self.total_predictions,
            "anomalies_detected": self.anomalies_detected,
            "threats_predicted": self.threats_predicted,
            "anomaly_rate": self.anomalies_detected / self.total_predictions if self.total_predictions > 0 else 0.0,
            "threat_rate": self.threats_predicted / self.total_predictions if self.total_predictions > 0 else 0.0,
            "training_samples": len(self.training_features),
            "anomaly_threshold": self.anomaly_threshold,
            "threat_threshold": self.threat_threshold
        }

    # Private helper methods

    def _calculate_anomaly_score(self, feature_vector: np.ndarray) -> float:
        """Calculate anomaly score using Isolation Forest logic."""
        # Simplified scoring based on feature deviations
        # In production, use sklearn.ensemble.IsolationForest

        # Check for extreme values
        extreme_count = np.sum(feature_vector > 0.8) + np.sum(feature_vector < 0.2)
        extreme_ratio = extreme_count / len(feature_vector)

        # Check for unusual patterns
        variance = np.var(feature_vector)

        # Combine scores
        anomaly_score = (extreme_ratio * 0.6) + (min(variance, 1.0) * 0.4)

        return min(anomaly_score, 1.0)

    def _detect_anomaly_types(self, features: MLFeatures,
                             context_events: List[SecurityEvent]) -> List[AnomalyType]:
        """Detect specific types of anomalies."""
        anomaly_types = []

        # Volume spike
        if features.events_per_hour > 50:
            anomaly_types.append(AnomalyType.VOLUME_SPIKE)

        # Unusual source
        if features.source_ip_reputation > 0.7:
            anomaly_types.append(AnomalyType.UNUSUAL_SOURCE)

        # Unusual target
        if features.target_ip_reputation > 0.7:
            anomaly_types.append(AnomalyType.UNUSUAL_TARGET)

        # Unusual time
        if not features.is_business_hours and features.severity_score > 0.7:
            anomaly_types.append(AnomalyType.UNUSUAL_TIME)

        # Behavioral deviation
        if features.source_history_score > 0.8 or features.target_history_score > 0.8:
            anomaly_types.append(AnomalyType.BEHAVIORAL_DEVIATION)

        # Statistical outlier
        if features.malicious_ioc_ratio > 0.5:
            anomaly_types.append(AnomalyType.STATISTICAL_OUTLIER)

        return anomaly_types

    def _generate_anomaly_explanation(self, features: MLFeatures,
                                     anomaly_types: List[AnomalyType],
                                     anomaly_score: float) -> str:
        """Generate human-readable explanation of anomaly."""
        if not anomaly_types:
            return f"Normal behavior detected (score: {anomaly_score:.2f})"

        explanations = []

        for atype in anomaly_types:
            if atype == AnomalyType.VOLUME_SPIKE:
                explanations.append(f"Unusual volume spike: {features.events_per_hour:.0f} events/hour")
            elif atype == AnomalyType.UNUSUAL_SOURCE:
                explanations.append(f"Suspicious source IP (reputation: {features.source_ip_reputation:.2f})")
            elif atype == AnomalyType.UNUSUAL_TARGET:
                explanations.append(f"Suspicious target IP (reputation: {features.target_ip_reputation:.2f})")
            elif atype == AnomalyType.UNUSUAL_TIME:
                explanations.append(f"Activity outside business hours (hour: {features.hour_of_day})")
            elif atype == AnomalyType.BEHAVIORAL_DEVIATION:
                explanations.append("Deviation from normal behavioral patterns")
            elif atype == AnomalyType.STATISTICAL_OUTLIER:
                explanations.append(f"Statistical outlier detected (malicious IOC ratio: {features.malicious_ioc_ratio:.2f})")

        return f"Anomaly detected (score: {anomaly_score:.2f}): " + "; ".join(explanations)

    def _calculate_threat_score(self, feature_vector: np.ndarray) -> float:
        """Calculate threat score using Random Forest logic."""
        # Simplified scoring (in production, use sklearn.ensemble.RandomForestClassifier)

        # Weight important features
        weights = np.array([
            0.02,  # hour_of_day
            0.02,  # day_of_week
            0.03,  # is_weekend
            0.03,  # is_business_hours
            0.10,  # severity_score (important)
            0.12,  # threat_level_score (important)
            0.02,  # event_type_hash
            0.04,  # source_entropy
            0.04,  # target_entropy
            0.05,  # events_per_hour
            0.04,  # unique_sources
            0.04,  # unique_targets
            0.06,  # failed_attempts_ratio
            0.08,  # source_ip_reputation (important)
            0.08,  # target_ip_reputation (important)
            0.06,  # port_risk_score
            0.05,  # protocol_risk_score
            0.04,  # source_history_score
            0.04,  # target_history_score
            0.03,  # pattern_frequency
            0.05,  # ioc_count
            0.10,  # malicious_ioc_ratio (important)
            0.08   # ioc_confidence_avg (important)
        ])

        # Weighted sum
        threat_score = np.dot(feature_vector, weights)

        return min(threat_score, 1.0)

    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """Convert threat score to threat level."""
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        elif score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.BENIGN

    def _predict_attack_types(self, features: MLFeatures) -> List[str]:
        """Predict likely attack types based on features."""
        attack_types = []

        # Brute force indicators
        if features.failed_attempts_ratio > 0.5 and features.events_per_hour > 20:
            attack_types.append("Brute Force Attack")

        # Port scanning
        if features.unique_targets > 10 and features.port_risk_score > 0.5:
            attack_types.append("Port Scanning")

        # Data exfiltration
        if features.is_business_hours == False and features.target_ip_reputation > 0.6:
            attack_types.append("Data Exfiltration")

        # Malware activity
        if features.malicious_ioc_ratio > 0.5:
            attack_types.append("Malware Activity")

        # Lateral movement
        if features.source_history_score > 0.7 and features.unique_targets > 5:
            attack_types.append("Lateral Movement")

        # DDoS
        if features.events_per_hour > 100 and features.unique_sources > 20:
            attack_types.append("DDoS Attack")

        # Credential theft
        if features.port_risk_score > 0.7 and features.failed_attempts_ratio > 0.3:
            attack_types.append("Credential Theft")

        if not attack_types:
            attack_types.append("Unknown Attack Pattern")

        return attack_types

    def _estimate_time_to_attack(self, features: MLFeatures,
                                threat_score: float) -> Optional[timedelta]:
        """Estimate time until attack based on threat indicators."""
        if threat_score < 0.5:
            return None  # Low threat, no imminent attack

        # Higher threat = shorter time to attack
        if threat_score >= 0.9:
            return timedelta(minutes=15)  # Imminent
        elif threat_score >= 0.7:
            return timedelta(hours=1)
        elif threat_score >= 0.5:
            return timedelta(hours=6)
        else:
            return timedelta(days=1)

    def _identify_risk_factors(self, features: MLFeatures) -> List[str]:
        """Identify key risk factors from features."""
        risk_factors = []

        if features.severity_score > 0.7:
            risk_factors.append(f"High severity event (score: {features.severity_score:.2f})")

        if features.malicious_ioc_ratio > 0.5:
            risk_factors.append(f"Multiple malicious IOCs ({features.malicious_ioc_ratio:.0%})")

        if features.source_ip_reputation > 0.6:
            risk_factors.append("Suspicious source IP")

        if features.failed_attempts_ratio > 0.5:
            risk_factors.append(f"High failure rate ({features.failed_attempts_ratio:.0%})")

        if not features.is_business_hours and features.severity_score > 0.5:
            risk_factors.append("Activity outside business hours")

        if features.events_per_hour > 50:
            risk_factors.append(f"High event volume ({features.events_per_hour:.0f}/hour)")

        if features.port_risk_score > 0.7:
            risk_factors.append("High-risk port access")

        return risk_factors

    def _generate_mitigations(self, threat_level: ThreatLevel,
                            attack_types: List[str]) -> List[str]:
        """Generate mitigation recommendations."""
        mitigations = []

        # General mitigations based on threat level
        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            mitigations.append("Immediate investigation required")
            mitigations.append("Consider isolating affected systems")
            mitigations.append("Enable enhanced monitoring")

        # Specific mitigations based on attack types
        for attack_type in attack_types:
            if "Brute Force" in attack_type:
                mitigations.append("Implement rate limiting")
                mitigations.append("Enable account lockout policies")
            elif "Port Scanning" in attack_type:
                mitigations.append("Block suspicious source IPs")
                mitigations.append("Review firewall rules")
            elif "Data Exfiltration" in attack_type:
                mitigations.append("Review data access logs")
                mitigations.append("Implement DLP controls")
            elif "Malware" in attack_type:
                mitigations.append("Run antivirus scan")
                mitigations.append("Quarantine affected files")
            elif "Lateral Movement" in attack_type:
                mitigations.append("Segment network")
                mitigations.append("Review privileged access")
            elif "DDoS" in attack_type:
                mitigations.append("Enable DDoS protection")
                mitigations.append("Scale infrastructure")
            elif "Credential Theft" in attack_type:
                mitigations.append("Force password reset")
                mitigations.append("Enable MFA")

        return list(set(mitigations))  # Remove duplicates

    def _kmeans_clustering(self, feature_vectors: List[np.ndarray],
                          num_clusters: int) -> List[int]:
        """Simplified K-Means clustering."""
        # In production, use sklearn.cluster.KMeans

        if not feature_vectors:
            return []

        vectors = np.array(feature_vectors)
        n_samples = len(vectors)

        # Initialize centroids randomly
        np.random.seed(42)
        centroid_indices = np.random.choice(n_samples, num_clusters, replace=False)
        centroids = vectors[centroid_indices]

        # Iterate (simplified, max 10 iterations)
        for _ in range(10):
            # Assign to nearest centroid
            distances = np.array([[np.linalg.norm(v - c) for c in centroids]
                                 for v in vectors])
            clusters = np.argmin(distances, axis=1)

            # Update centroids
            new_centroids = np.array([vectors[clusters == i].mean(axis=0)
                                     if np.any(clusters == i) else centroids[i]
                                     for i in range(num_clusters)])

            # Check convergence
            if np.allclose(centroids, new_centroids):
                break

            centroids = new_centroids

        return clusters.tolist()

    def _extract_common_features(self, features_list: List[MLFeatures]) -> Dict[str, Any]:
        """Extract common features from a cluster."""
        if not features_list:
            return {}

        # Calculate averages
        avg_severity = np.mean([f.severity_score for f in features_list])
        avg_threat = np.mean([f.threat_level_score for f in features_list])
        avg_events_per_hour = np.mean([f.events_per_hour for f in features_list])

        # Most common time patterns
        hours = [f.hour_of_day for f in features_list]
        most_common_hour = Counter(hours).most_common(1)[0][0] if hours else 0

        return {
            "avg_severity_score": round(avg_severity, 2),
            "avg_threat_score": round(avg_threat, 2),
            "avg_events_per_hour": round(avg_events_per_hour, 1),
            "most_common_hour": most_common_hour,
            "weekend_activity": sum(f.is_weekend for f in features_list) / len(features_list)
        }

    def _generate_cluster_name(self, attack_types: List[str],
                              common_features: Dict[str, Any]) -> str:
        """Generate descriptive name for attack cluster."""
        if not attack_types:
            return "Unknown Attack Pattern"

        # Use most common attack type
        primary_type = attack_types[0] if len(attack_types) == 1 else "Mixed Attack"

        # Add severity indicator
        avg_severity = common_features.get("avg_severity_score", 0.5)
        if avg_severity > 0.7:
            severity_label = "High-Severity"
        elif avg_severity > 0.4:
            severity_label = "Medium-Severity"
        else:
            severity_label = "Low-Severity"

        return f"{severity_label} {primary_type}"

    def _detect_seasonality(self, hourly_counts: Dict[datetime, int]) -> bool:
        """Detect seasonality in time series (simplified)."""
        if len(hourly_counts) < 48:  # Need at least 2 days
            return False

        # Check for daily patterns
        sorted_hours = sorted(hourly_counts.keys())
        daily_patterns = defaultdict(list)

        for hour in sorted_hours:
            hour_of_day = hour.hour
            daily_patterns[hour_of_day].append(hourly_counts[hour])

        # Calculate variance within each hour vs overall variance
        overall_variance = np.var(list(hourly_counts.values()))
        within_hour_variances = [np.var(counts) for counts in daily_patterns.values()
                                if len(counts) > 1]

        if not within_hour_variances:
            return False

        avg_within_variance = np.mean(within_hour_variances)

        # If within-hour variance is much lower than overall, there's seasonality
        return avg_within_variance < overall_variance * 0.5


