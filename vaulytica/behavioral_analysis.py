"""Behavioral analysis engine for detecting anomalies and attack patterns."""

import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from vaulytica.models import SecurityEvent, TechnicalIndicator
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class AnomalyType(str, Enum):
    """Types of behavioral anomalies."""
    TEMPORAL = "TEMPORAL"  # Time-based anomalies
    VOLUMETRIC = "VOLUMETRIC"  # Volume/frequency anomalies
    GEOGRAPHIC = "GEOGRAPHIC"  # Location-based anomalies
    BEHAVIORAL = "BEHAVIORAL"  # Behavior pattern anomalies
    SEQUENTIAL = "SEQUENTIAL"  # Sequence/order anomalies


@dataclass
class BehavioralAnomaly:
    """Detected behavioral anomaly."""
    anomaly_type: AnomalyType
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float
    evidence: List[str]
    baseline_deviation: float  # How much it deviates from baseline (0.0-1.0)


@dataclass
class AttackPattern:
    """Detected attack pattern."""
    pattern_name: str
    pattern_type: str
    confidence: float
    indicators: List[str]
    mitre_ttps: List[str]
    description: str


class BehavioralAnalysisEngine:
    """Engine for behavioral analysis and anomaly detection."""

    def __init__(self):
        self.attack_signatures = self._load_attack_signatures()
        self.behavioral_baselines = self._load_behavioral_baselines()

    def _load_attack_signatures(self) -> Dict:
        """Load attack pattern signatures."""
        return {
            "brute_force": {
                "indicators": ["multiple failed", "authentication failure", "invalid password", "login attempt"],
                "threshold": 5,
                "time_window": 300,  # 5 minutes
                "mitre": ["T1110", "T1110.001", "T1110.003"],
                "severity": "HIGH"
            },
            "privilege_escalation": {
                "indicators": ["sudo", "runas", "privilege", "administrator", "root", "elevation"],
                "threshold": 3,
                "time_window": 600,
                "mitre": ["T1068", "T1078", "T1548"],
                "severity": "HIGH"
            },
            "data_exfiltration": {
                "indicators": ["large transfer", "upload", "exfil", "download", "copy", "ftp", "sftp"],
                "threshold": 2,
                "time_window": 1800,
                "mitre": ["T1048", "T1041", "T1567"],
                "severity": "CRITICAL"
            },
            "lateral_movement": {
                "indicators": ["psexec", "wmi", "rdp", "smb", "remote", "lateral"],
                "threshold": 3,
                "time_window": 900,
                "mitre": ["T1021", "T1021.001", "T1021.002"],
                "severity": "HIGH"
            },
            "reconnaissance": {
                "indicators": ["scan", "enumerate", "discovery", "whoami", "ipconfig", "netstat"],
                "threshold": 4,
                "time_window": 600,
                "mitre": ["T1046", "T1018", "T1082", "T1083"],
                "severity": "MEDIUM"
            },
            "persistence": {
                "indicators": ["registry", "scheduled task", "service", "startup", "autorun"],
                "threshold": 2,
                "time_window": 1200,
                "mitre": ["T1547", "T1053", "T1543"],
                "severity": "HIGH"
            },
            "defense_evasion": {
                "indicators": ["disable", "delete log", "clear", "obfuscate", "encode", "bypass"],
                "threshold": 2,
                "time_window": 600,
                "mitre": ["T1070", "T1027", "T1562"],
                "severity": "HIGH"
            },
            "command_and_control": {
                "indicators": ["beacon", "c2", "callback", "heartbeat", "tunnel", "proxy"],
                "threshold": 2,
                "time_window": 1800,
                "mitre": ["T1071", "T1573", "T1090"],
                "severity": "CRITICAL"
            }
        }

    def _load_behavioral_baselines(self) -> Dict:
        """Load behavioral baselines for anomaly detection."""
        return {
            "normal_login_hours": {
                "start": 6,  # 6 AM
                "end": 22,   # 10 PM
                "timezone": "UTC"
            },
            "normal_data_transfer": {
                "max_bytes": 100 * 1024 * 1024,  # 100 MB
                "max_files": 1000
            },
            "normal_api_calls": {
                "max_per_minute": 100,
                "max_per_hour": 5000
            },
            "normal_failed_logins": {
                "max_per_hour": 3,
                "max_per_day": 10
            }
        }

    def analyze_event(self, event: SecurityEvent) -> Tuple[List[BehavioralAnomaly], List[AttackPattern]]:
        """
        Analyze a security event for behavioral anomalies and attack patterns.

        Args:
            event: Security event to analyze

        Returns:
            Tuple of (anomalies, attack_patterns)
        """
        anomalies = []
        patterns = []

        # Detect temporal anomalies
        temporal_anomalies = self._detect_temporal_anomalies(event)
        anomalies.extend(temporal_anomalies)

        # Detect volumetric anomalies
        volumetric_anomalies = self._detect_volumetric_anomalies(event)
        anomalies.extend(volumetric_anomalies)

        # Detect geographic anomalies
        geographic_anomalies = self._detect_geographic_anomalies(event)
        anomalies.extend(geographic_anomalies)

        # Detect attack patterns
        detected_patterns = self._detect_attack_patterns(event)
        patterns.extend(detected_patterns)

        # Detect sequential anomalies
        sequential_anomalies = self._detect_sequential_anomalies(event)
        anomalies.extend(sequential_anomalies)

        logger.info(f"Behavioral analysis complete: {len(anomalies)} anomalies, {len(patterns)} patterns")
        return anomalies, patterns

    def _detect_temporal_anomalies(self, event: SecurityEvent) -> List[BehavioralAnomaly]:
        """Detect time-based anomalies."""
        anomalies = []

        # Check if event occurred during unusual hours
        event_hour = event.timestamp.hour
        baseline = self.behavioral_baselines["normal_login_hours"]

        if event_hour < baseline["start"] or event_hour >= baseline["end"]:
            anomalies.append(BehavioralAnomaly(
                anomaly_type=AnomalyType.TEMPORAL,
                description=f"Activity detected outside normal hours ({event_hour}:00 UTC)",
                severity="MEDIUM",
                confidence=0.7,
                evidence=[f"Event timestamp: {event.timestamp.isoformat()}"],
                baseline_deviation=0.6
            ))

        # Check for weekend activity (if applicable)
        if event.timestamp.weekday() >= 5:  # Saturday or Sunday
            anomalies.append(BehavioralAnomaly(
                anomaly_type=AnomalyType.TEMPORAL,
                description="Activity detected during weekend",
                severity="LOW",
                confidence=0.5,
                evidence=[f"Day of week: {event.timestamp.strftime('%A')}"],
                baseline_deviation=0.4
            ))

        return anomalies

    def _detect_volumetric_anomalies(self, event: SecurityEvent) -> List[BehavioralAnomaly]:
        """Detect volume/frequency anomalies."""
        anomalies = []

        # Check for high data transfer volumes
        description_lower = event.description.lower()

        # Look for data transfer indicators
        data_patterns = [
            (r'(\d+)\s*(gb|gigabyte)', 1024 * 1024 * 1024),
            (r'(\d+)\s*(mb|megabyte)', 1024 * 1024),
            (r'(\d+)\s*(kb|kilobyte)', 1024),
        ]

        for pattern, multiplier in data_patterns:
            match = re.search(pattern, description_lower)
            if match:
                size = int(match.group(1)) * multiplier
                baseline_max = self.behavioral_baselines["normal_data_transfer"]["max_bytes"]

                if size > baseline_max:
                    deviation = min((size - baseline_max) / baseline_max, 1.0)
                    anomalies.append(BehavioralAnomaly(
                        anomaly_type=AnomalyType.VOLUMETRIC,
                        description=f"Unusually large data transfer detected ({size / (1024*1024):.2f} MB)",
                        severity="HIGH" if deviation > 0.5 else "MEDIUM",
                        confidence=0.8,
                        evidence=[f"Transfer size: {size} bytes", f"Baseline: {baseline_max} bytes"],
                        baseline_deviation=deviation
                    ))

        # Check for high frequency indicators
        frequency_keywords = ["multiple", "repeated", "numerous", "many", "several"]
        if any(keyword in description_lower for keyword in frequency_keywords):
            anomalies.append(BehavioralAnomaly(
                anomaly_type=AnomalyType.VOLUMETRIC,
                description="High frequency activity detected",
                severity="MEDIUM",
                confidence=0.6,
                evidence=["Description contains frequency indicators"],
                baseline_deviation=0.5
            ))

        return anomalies

    def _detect_geographic_anomalies(self, event: SecurityEvent) -> List[BehavioralAnomaly]:
        """Detect location-based anomalies."""
        anomalies = []

        # Check for unusual geographic locations
        description_lower = event.description.lower()
        metadata_str = str(event.metadata).lower()

        # High-risk countries (example list)
        high_risk_countries = ["russia", "china", "north korea", "iran"]

        for country in high_risk_countries:
            if country in description_lower or country in metadata_str:
                anomalies.append(BehavioralAnomaly(
                    anomaly_type=AnomalyType.GEOGRAPHIC,
                    description=f"Activity from high-risk geographic location: {country.title()}",
                    severity="HIGH",
                    confidence=0.75,
                    evidence=[f"Location indicator: {country}"],
                    baseline_deviation=0.7
                ))

        # Check for impossible travel (rapid geographic changes)
        # This would require historical context in production

        return anomalies

    def _detect_attack_patterns(self, event: SecurityEvent) -> List[AttackPattern]:
        """Detect known attack patterns."""
        patterns = []

        event_text = f"{event.title} {event.description}".lower()

        for pattern_name, signature in self.attack_signatures.items():
            matched_indicators = []

            for indicator in signature["indicators"]:
                if indicator.lower() in event_text:
                    matched_indicators.append(indicator)

            # Calculate confidence based on matched indicators
            if matched_indicators:
                confidence = len(matched_indicators) / len(signature["indicators"])

                if confidence >= 0.3:  # Threshold for pattern detection
                    patterns.append(AttackPattern(
                        pattern_name=pattern_name,
                        pattern_type="signature_match",
                        confidence=min(confidence, 0.95),
                        indicators=matched_indicators,
                        mitre_ttps=signature["mitre"],
                        description=f"Detected {pattern_name.replace('_', ' ')} pattern based on {len(matched_indicators)} indicators"
                    ))

        return patterns

    def _detect_sequential_anomalies(self, event: SecurityEvent) -> List[BehavioralAnomaly]:
        """Detect sequence/order anomalies."""
        anomalies = []

        # Check for suspicious command sequences
        description_lower = event.description.lower()

        # Suspicious sequences
        suspicious_sequences = [
            (["whoami", "ipconfig", "net user"], "reconnaissance_sequence"),
            (["mimikatz", "lsass", "dump"], "credential_dumping_sequence"),
            (["powershell", "download", "execute"], "malware_delivery_sequence"),
            (["disable", "antivirus", "firewall"], "defense_evasion_sequence"),
        ]

        for sequence, sequence_name in suspicious_sequences:
            matched = sum(1 for cmd in sequence if cmd in description_lower)
            if matched >= 2:
                confidence = matched / len(sequence)
                anomalies.append(BehavioralAnomaly(
                    anomaly_type=AnomalyType.SEQUENTIAL,
                    description=f"Suspicious command sequence detected: {sequence_name.replace('_', ' ')}",
                    severity="HIGH",
                    confidence=confidence,
                    evidence=[f"Matched {matched}/{len(sequence)} commands in sequence"],
                    baseline_deviation=0.7
                ))

        return anomalies

    def calculate_anomaly_score(self, anomalies: List[BehavioralAnomaly]) -> float:
        """
        Calculate overall anomaly score from detected anomalies.

        Returns:
            Score from 0.0 (normal) to 10.0 (highly anomalous)
        """
        if not anomalies:
            return 0.0

        severity_weights = {
            "LOW": 1.0,
            "MEDIUM": 2.5,
            "HIGH": 5.0,
            "CRITICAL": 8.0
        }

        total_score = 0.0
        for anomaly in anomalies:
            weight = severity_weights.get(anomaly.severity, 1.0)
            total_score += weight * anomaly.confidence * anomaly.baseline_deviation

        # Normalize to 0-10 scale
        normalized_score = min(total_score / 2.0, 10.0)
        return round(normalized_score, 2)

    def generate_behavioral_summary(
        self,
        anomalies: List[BehavioralAnomaly],
        patterns: List[AttackPattern]
    ) -> Dict:
        """Generate a comprehensive behavioral analysis summary."""
        return {
            "anomaly_count": len(anomalies),
            "pattern_count": len(patterns),
            "anomaly_score": self.calculate_anomaly_score(anomalies),
            "anomalies_by_type": {
                anomaly_type.value: len([a for a in anomalies if a.anomaly_type == anomaly_type])
                for anomaly_type in AnomalyType
            },
            "anomalies_by_severity": {
                severity: len([a for a in anomalies if a.severity == severity])
                for severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            },
            "detected_patterns": [
                {
                    "name": p.pattern_name,
                    "confidence": p.confidence,
                    "mitre_ttps": p.mitre_ttps
                }
                for p in patterns
            ],
            "high_confidence_anomalies": [
                {
                    "type": a.anomaly_type.value,
                    "description": a.description,
                    "severity": a.severity,
                    "confidence": a.confidence
                }
                for a in anomalies if a.confidence >= 0.7
            ]
        }
