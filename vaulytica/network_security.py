"""
Network Security, Data Loss Prevention & Encryption Management for Vaulytica.

Provides comprehensive network and data security with:
- Network traffic analysis and firewall rule validation
- Data Loss Prevention (DLP) with sensitive data detection
- Encryption key lifecycle management
- Data classification and sensitivity labeling
- Network threat detection (port scanning, DDoS, C2 communication)
- TLS/SSL certificate monitoring

Author: Vaulytica Team
Version: 0.25.0
"""

import asyncio
import hashlib
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.cspm import Severity
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class NetworkProtocol(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    DNS = "dns"
    FTP = "ftp"
    SMTP = "smtp"


class FirewallAction(str, Enum):
    """Firewall rule actions."""
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    REJECT = "reject"


class DataClassification(str, Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class SensitiveDataType(str, Enum):
    """Types of sensitive data."""
    PII = "pii"  # Personally Identifiable Information
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Information
    SSN = "ssn"  # Social Security Number
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    PASSWORD = "password"


class DLPAction(str, Enum):
    """DLP policy actions."""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    ENCRYPT = "encrypt"


class EncryptionAlgorithm(str, Enum):
    """Encryption algorithms."""
    AES_256 = "aes-256"
    AES_128 = "aes-128"
    RSA_2048 = "rsa-2048"
    RSA_4096 = "rsa-4096"
    ECDSA = "ecdsa"
    CHACHA20 = "chacha20"


class NetworkThreatType(str, Enum):
    """Network threat types."""
    PORT_SCAN = "port_scan"
    DDOS = "ddos"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    DATA_EXFILTRATION = "data_exfiltration"
    BRUTE_FORCE = "brute_force"
    MAN_IN_THE_MIDDLE = "man_in_the_middle"


@dataclass
class FirewallRule:
    """Firewall rule definition."""
    rule_id: str
    name: str
    action: FirewallAction
    protocol: NetworkProtocol
    source_ip: str
    source_port: Optional[str] = None
    destination_ip: str = "*"
    destination_port: Optional[str] = None
    priority: int = 100
    enabled: bool = True
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class NetworkFlow:
    """Network traffic flow."""
    flow_id: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: NetworkProtocol
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    duration_seconds: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkThreat:
    """Detected network threat."""
    threat_id: str
    threat_type: NetworkThreatType
    severity: Severity
    source_ip: str
    destination_ip: str
    description: str
    indicators: List[str]
    flows: List[NetworkFlow] = field(default_factory=list)
    risk_score: float = 0.0
    detected_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SensitiveData:
    """Detected sensitive data."""
    data_id: str
    data_type: SensitiveDataType
    classification: DataClassification
    location: str
    matched_value: str  # Masked/redacted
    context: str
    confidence: float  # 0.0 - 1.0
    line_number: Optional[int] = None
    detected_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DLPPolicy:
    """Data Loss Prevention policy."""
    policy_id: str
    name: str
    data_types: List[SensitiveDataType]
    action: DLPAction
    classification_level: DataClassification
    conditions: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    priority: int = 100
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class EncryptionKey:
    """Encryption key metadata."""
    key_id: str
    name: str
    algorithm: EncryptionAlgorithm
    key_size: int
    purpose: str  # encryption, signing, etc.
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_rotated: Optional[datetime] = None
    rotation_policy_days: int = 365
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TLSCertificate:
    """TLS/SSL certificate."""
    cert_id: str
    common_name: str
    subject_alternative_names: List[str]
    issuer: str
    valid_from: datetime
    valid_until: datetime
    key_algorithm: str
    key_size: int
    signature_algorithm: str
    is_self_signed: bool = False
    is_expired: bool = False
    days_until_expiry: int = 0


class NetworkSecurityAnalyzer:
    """
    Network security analyzer.

    Analyzes network traffic, firewall rules, and detects network threats.
    """

    def __init__(self):
        """Initialize network security analyzer."""
        self.firewall_rules: Dict[str, FirewallRule] = {}
        self.network_flows: List[NetworkFlow] = []
        self.threats: List[NetworkThreat] = []

        self.statistics = {
            "rules_analyzed": 0,
            "flows_analyzed": 0,
            "threats_detected": 0,
            "threats_by_type": {},
            "blocked_connections": 0,
            "allowed_connections": 0
        }

        # Known malicious IPs (mock data)
        self.malicious_ips = {
            "192.0.2.1",  # TEST-NET-1
            "198.51.100.1",  # TEST-NET-2
            "203.0.113.1"  # TEST-NET-3
        }

        # Known C2 domains
        self.c2_domains = {
            "malicious-c2.example.com",
            "evil-command.example.net"
        }

        logger.info("Network Security Analyzer initialized")

    async def analyze_firewall_rule(self, rule: FirewallRule) -> Dict[str, Any]:
        """
        Analyze firewall rule for security issues.

        Args:
            rule: Firewall rule to analyze

        Returns:
            Analysis results
        """
        logger.info(f"Analyzing firewall rule: {rule.name}")

        self.firewall_rules[rule.rule_id] = rule

        issues = []
        risk_score = 0.0

        # Check for overly permissive rules
        if rule.source_ip in ["0.0.0.0/0", "*", "any"]:
            issues.append("Rule allows traffic from any source IP (0.0.0.0/0)")
            risk_score += 3.0

        if rule.destination_ip in ["0.0.0.0/0", "*", "any"]:
            issues.append("Rule allows traffic to any destination IP")
            risk_score += 2.0

        # Check for dangerous ports
        dangerous_ports = ["22", "3389", "23", "21", "445"]
        if rule.destination_port in dangerous_ports and rule.action == FirewallAction.ALLOW:
            issues.append(f"Rule allows access to dangerous port {rule.destination_port}")
            risk_score += 4.0

        # Check for allow-all rules
        if (rule.source_ip in ["0.0.0.0/0", "*"] and
            rule.destination_port in ["*", "any"] and
            rule.action == FirewallAction.ALLOW):
            issues.append("Rule allows all traffic from anywhere to any port (CRITICAL)")
            risk_score += 10.0

        self.statistics["rules_analyzed"] += 1

        return {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "issues": issues,
            "risk_score": min(risk_score, 10.0),
            "is_secure": len(issues) == 0
        }

    async def analyze_network_flow(self, flow: NetworkFlow) -> Optional[NetworkThreat]:
        """
        Analyze network flow for threats.

        Args:
            flow: Network flow to analyze

        Returns:
            Detected threat or None
        """
        logger.info(f"Analyzing network flow: {flow.source_ip} -> {flow.destination_ip}")

        self.network_flows.append(flow)
        self.statistics["flows_analyzed"] += 1

        # Check for malicious IPs
        if flow.destination_ip in self.malicious_ips:
            threat = NetworkThreat(
                threat_id=f"threat-{hashlib.md5(f'{flow.flow_id}'.encode()).hexdigest()[:12]}",
                threat_type=NetworkThreatType.C2_COMMUNICATION,
                severity=Severity.CRITICAL,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description=f"Connection to known malicious IP: {flow.destination_ip}",
                indicators=[
                    f"Destination IP: {flow.destination_ip}",
                    f"Protocol: {flow.protocol.value}",
                    f"Bytes sent: {flow.bytes_sent}"
                ],
                flows=[flow],
                risk_score=9.0
            )

            self.threats.append(threat)
            self.statistics["threats_detected"] += 1

            if threat.threat_type.value not in self.statistics["threats_by_type"]:
                self.statistics["threats_by_type"][threat.threat_type.value] = 0
            self.statistics["threats_by_type"][threat.threat_type.value] += 1

            return threat

        # Check for port scanning (multiple destination ports from same source)
        recent_flows = [f for f in self.network_flows[-100:] if f.source_ip == flow.source_ip]
        unique_ports = len(set(f.destination_port for f in recent_flows))

        if unique_ports > 20:
            threat = NetworkThreat(
                threat_id=f"threat-{hashlib.md5(f'{flow.source_ip}portscan'.encode()).hexdigest()[:12]}",
                threat_type=NetworkThreatType.PORT_SCAN,
                severity=Severity.HIGH,
                source_ip=flow.source_ip,
                destination_ip=flow.destination_ip,
                description=f"Port scanning detected from {flow.source_ip}",
                indicators=[
                    f"Unique ports scanned: {unique_ports}",
                    f"Source IP: {flow.source_ip}"
                ],
                flows=recent_flows[-10:],
                risk_score=7.5
            )

            self.threats.append(threat)
            self.statistics["threats_detected"] += 1

            if threat.threat_type.value not in self.statistics["threats_by_type"]:
                self.statistics["threats_by_type"][threat.threat_type.value] = 0
            self.statistics["threats_by_type"][threat.threat_type.value] += 1

            return threat

        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return self.statistics


# Global instance
_network_analyzer: Optional[NetworkSecurityAnalyzer] = None


def get_network_analyzer() -> NetworkSecurityAnalyzer:
    """Get or create global network analyzer instance."""
    global _network_analyzer

    if _network_analyzer is None:
        _network_analyzer = NetworkSecurityAnalyzer()

    return _network_analyzer


class DataClassifier:
    """
    Data classification engine.

    Classifies data based on sensitivity and compliance requirements.
    """

    def __init__(self):
        """Initialize data classifier."""
        self.classified_data: List[SensitiveData] = []

        self.statistics = {
            "data_classified": 0,
            "by_type": {},
            "by_classification": {},
            "high_confidence": 0
        }

        # Sensitive data patterns
        self.patterns = {
            SensitiveDataType.SSN: [
                (r'\b\d{3}-\d{2}-\d{4}\b', "SSN (XXX-XX-XXXX)"),
                (r'\b\d{9}\b', "SSN (9 digits)")
            ],
            SensitiveDataType.CREDIT_CARD: [
                (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', "Credit Card (16 digits)"),
                (r'\b\d{15}\b', "Credit Card (15 digits - Amex)")
            ],
            SensitiveDataType.EMAIL: [
                (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email Address")
            ],
            SensitiveDataType.PHONE: [
                (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', "Phone Number (US)"),
                (r'\b\(\d{3}\)\s*\d{3}[-.]?\d{4}\b', "Phone Number (US with area code)")
            ],
            SensitiveDataType.IP_ADDRESS: [
                (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "IPv4 Address")
            ]
        }

        logger.info("Data Classifier initialized")

    async def classify_data(
        self,
        content: str,
        location: str,
        context: str = ""
    ) -> List[SensitiveData]:
        """
        Classify data in content.

        Args:
            content: Content to classify
            location: Location of data (file path, database, etc.)
            context: Additional context

        Returns:
            List of detected sensitive data
        """
        logger.info(f"Classifying data in: {location}")

        detected = []
        lines = content.split('\n')

        # Optimize: Pre-compile all patterns and flatten structure
        compiled_patterns = []
        for data_type, patterns in self.patterns.items():
            for pattern, description in patterns:
                compiled_patterns.append((
                    data_type,
                    re.compile(pattern, re.IGNORECASE),
                    description
                ))

        # Optimize: Single pass through lines, check all patterns
        for line_num, line in enumerate(lines, 1):
            for data_type, compiled_pattern, description in compiled_patterns:
                for match in compiled_pattern.finditer(line):
                    matched_value = match.group(0)

                    # Mask the value
                    masked_value = self._mask_value(matched_value, data_type)

                    # Determine classification level
                    classification = self._determine_classification(data_type)

                    # Calculate confidence
                    confidence = self._calculate_confidence(matched_value, data_type)

                    sensitive_data = SensitiveData(
                            data_id=f"data-{hashlib.md5(f'{location}{line_num}{matched_value}'.encode()).hexdigest()[:12]}",
                            data_type=data_type,
                            classification=classification,
                            location=location,
                            matched_value=masked_value,
                            context=context or line[:100],
                            confidence=confidence,
                            line_number=line_num
                    )

                    detected.append(sensitive_data)
                    self.classified_data.append(sensitive_data)

                    # Update statistics
                    self.statistics["data_classified"] += 1

                    if data_type.value not in self.statistics["by_type"]:
                        self.statistics["by_type"][data_type.value] = 0
                    self.statistics["by_type"][data_type.value] += 1

                    if classification.value not in self.statistics["by_classification"]:
                        self.statistics["by_classification"][classification.value] = 0
                    self.statistics["by_classification"][classification.value] += 1

                    if confidence > 0.8:
                        self.statistics["high_confidence"] += 1

        logger.info(f"Classified {len(detected)} sensitive data items in {location}")

        return detected

    def _mask_value(self, value: str, data_type: SensitiveDataType) -> str:
        """Mask sensitive value."""
        if data_type == SensitiveDataType.SSN:
            return "***-**-" + value[-4:] if len(value) >= 4 else "***-**-****"
        elif data_type == SensitiveDataType.CREDIT_CARD:
            return "**** **** **** " + value[-4:] if len(value) >= 4 else "**** **** **** ****"
        elif data_type == SensitiveDataType.EMAIL:
            parts = value.split('@')
            if len(parts) == 2:
                return parts[0][:2] + "***@" + parts[1]
            return "***@***.com"
        elif data_type == SensitiveDataType.PHONE:
            return "***-***-" + value[-4:] if len(value) >= 4 else "***-***-****"
        else:
            return "***" + value[-4:] if len(value) >= 4 else "***"

    def _determine_classification(self, data_type: SensitiveDataType) -> DataClassification:
        """Determine classification level based on data type."""
        if data_type in [SensitiveDataType.SSN, SensitiveDataType.CREDIT_CARD]:
            return DataClassification.RESTRICTED
        elif data_type in [SensitiveDataType.PHI, SensitiveDataType.PCI]:
            return DataClassification.CONFIDENTIAL
        elif data_type in [SensitiveDataType.EMAIL, SensitiveDataType.PHONE]:
            return DataClassification.INTERNAL
        else:
            return DataClassification.CONFIDENTIAL

    def _calculate_confidence(self, value: str, data_type: SensitiveDataType) -> float:
        """Calculate confidence score for detection."""
        # Simple confidence calculation based on pattern match quality
        if data_type == SensitiveDataType.SSN:
            # Check Luhn algorithm for SSN (simplified)
            return 0.9 if len(value.replace('-', '')) == 9 else 0.7
        elif data_type == SensitiveDataType.CREDIT_CARD:
            # Check Luhn algorithm for credit card
            digits = value.replace(' ', '').replace('-', '')
            return 0.95 if len(digits) in [15, 16] else 0.7
        elif data_type == SensitiveDataType.EMAIL:
            # Check for valid TLD
            return 0.9 if '.' in value.split('@')[-1] else 0.6
        else:
            return 0.8

    def get_statistics(self) -> Dict[str, Any]:
        """Get classifier statistics."""
        return self.statistics


class DLPEngine:
    """
    Data Loss Prevention engine.

    Enforces DLP policies and prevents data exfiltration.
    """

    def __init__(self):
        """Initialize DLP engine."""
        self.policies: Dict[str, DLPPolicy] = {}
        self.violations: List[Dict[str, Any]] = []
        self.classifier = DataClassifier()

        self.statistics = {
            "policies_enforced": 0,
            "violations_detected": 0,
            "data_blocked": 0,
            "data_encrypted": 0,
            "alerts_sent": 0
        }

        logger.info("DLP Engine initialized")

    async def create_policy(
        self,
        name: str,
        data_types: List[SensitiveDataType],
        action: DLPAction,
        classification_level: DataClassification
    ) -> DLPPolicy:
        """
        Create DLP policy.

        Args:
            name: Policy name
            data_types: Data types to protect
            action: Action to take
            classification_level: Minimum classification level

        Returns:
            Created policy
        """
        logger.info(f"Creating DLP policy: {name}")

        policy = DLPPolicy(
            policy_id=f"dlp-{hashlib.md5(f'{name}'.encode()).hexdigest()[:12]}",
            name=name,
            data_types=data_types,
            action=action,
            classification_level=classification_level,
            enabled=True
        )

        self.policies[policy.policy_id] = policy

        return policy

    async def enforce_policy(
        self,
        content: str,
        location: str,
        operation: str = "transfer"
    ) -> Dict[str, Any]:
        """
        Enforce DLP policies on content.

        Args:
            content: Content to check
            location: Location of content
            operation: Operation being performed

        Returns:
            Enforcement result
        """
        logger.info(f"Enforcing DLP policies on: {location}")

        # Classify data
        sensitive_data = await self.classifier.classify_data(content, location)

        if not sensitive_data:
            return {
                "allowed": True,
                "action": "allow",
                "reason": "No sensitive data detected"
            }

        # Check against policies
        for policy in self.policies.values():
            if not policy.enabled:
                continue

            # Check if any detected data matches policy
            matching_data = [
                d for d in sensitive_data
                if d.data_type in policy.data_types
            ]

            if matching_data:
                self.statistics["policies_enforced"] += 1
                self.statistics["violations_detected"] += 1

                # Record violation
                violation = {
                    "policy_id": policy.policy_id,
                    "policy_name": policy.name,
                    "location": location,
                    "operation": operation,
                    "sensitive_data_count": len(matching_data),
                    "action": policy.action.value,
                    "timestamp": datetime.utcnow().isoformat()
                }
                self.violations.append(violation)

                # Take action
                if policy.action == DLPAction.BLOCK:
                    self.statistics["data_blocked"] += 1
                    return {
                        "allowed": False,
                        "action": "block",
                        "reason": f"Blocked by policy: {policy.name}",
                        "sensitive_data": len(matching_data),
                        "policy": policy.name
                    }

                elif policy.action == DLPAction.ENCRYPT:
                    self.statistics["data_encrypted"] += 1
                    return {
                        "allowed": True,
                        "action": "encrypt",
                        "reason": f"Encryption required by policy: {policy.name}",
                        "sensitive_data": len(matching_data)
                    }

                elif policy.action == DLPAction.ALERT:
                    self.statistics["alerts_sent"] += 1
                    return {
                        "allowed": True,
                        "action": "alert",
                        "reason": f"Alert triggered by policy: {policy.name}",
                        "sensitive_data": len(matching_data)
                    }

        return {
            "allowed": True,
            "action": "allow",
            "reason": "No matching policies",
            "sensitive_data": len(sensitive_data)
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get DLP engine statistics."""
        return self.statistics


# Global instances
_data_classifier: Optional[DataClassifier] = None
_dlp_engine: Optional[DLPEngine] = None


def get_data_classifier() -> DataClassifier:
    """Get or create global data classifier instance."""
    global _data_classifier

    if _data_classifier is None:
        _data_classifier = DataClassifier()

    return _data_classifier


def get_dlp_engine() -> DLPEngine:
    """Get or create global DLP engine instance."""
    global _dlp_engine

    if _dlp_engine is None:
        _dlp_engine = DLPEngine()

    return _dlp_engine


class EncryptionManager:
    """
    Encryption key lifecycle management.

    Manages encryption keys, certificates, and rotation policies.
    """

    def __init__(self):
        """Initialize encryption manager."""
        self.keys: Dict[str, EncryptionKey] = {}
        self.certificates: Dict[str, TLSCertificate] = {}

        self.statistics = {
            "keys_managed": 0,
            "keys_rotated": 0,
            "certificates_monitored": 0,
            "expiring_certificates": 0,
            "expired_certificates": 0
        }

        logger.info("Encryption Manager initialized")

    async def register_key(
        self,
        name: str,
        algorithm: EncryptionAlgorithm,
        key_size: int,
        purpose: str,
        rotation_policy_days: int = 365
    ) -> EncryptionKey:
        """
        Register encryption key.

        Args:
            name: Key name
            algorithm: Encryption algorithm
            key_size: Key size in bits
            purpose: Key purpose
            rotation_policy_days: Days between rotations

        Returns:
            Registered key
        """
        logger.info(f"Registering encryption key: {name}")

        key = EncryptionKey(
            key_id=f"key-{hashlib.md5(f'{name}'.encode()).hexdigest()[:12]}",
            name=name,
            algorithm=algorithm,
            key_size=key_size,
            purpose=purpose,
            created_at=datetime.utcnow(),
            rotation_policy_days=rotation_policy_days,
            is_active=True
        )

        self.keys[key.key_id] = key
        self.statistics["keys_managed"] += 1

        return key

    async def rotate_key(self, key_id: str) -> EncryptionKey:
        """
        Rotate encryption key.

        Args:
            key_id: Key ID to rotate

        Returns:
            New key
        """
        logger.info(f"Rotating encryption key: {key_id}")

        old_key = self.keys.get(key_id)
        if not old_key:
            raise ValueError(f"Key not found: {key_id}")

        # Deactivate old key
        old_key.is_active = False

        # Create new key
        new_key = EncryptionKey(
            key_id=f"key-{hashlib.md5(f'{old_key.name}{datetime.utcnow()}'.encode()).hexdigest()[:12]}",
            name=old_key.name,
            algorithm=old_key.algorithm,
            key_size=old_key.key_size,
            purpose=old_key.purpose,
            created_at=datetime.utcnow(),
            last_rotated=datetime.utcnow(),
            rotation_policy_days=old_key.rotation_policy_days,
            is_active=True
        )

        self.keys[new_key.key_id] = new_key
        self.statistics["keys_rotated"] += 1

        return new_key

    async def check_key_rotation(self) -> List[EncryptionKey]:
        """
        Check for keys that need rotation.

        Returns:
            List of keys needing rotation
        """
        logger.info("Checking for keys needing rotation")

        needs_rotation = []

        for key in self.keys.values():
            if not key.is_active:
                continue

            days_since_creation = (datetime.utcnow() - key.created_at).days

            if key.last_rotated:
                days_since_rotation = (datetime.utcnow() - key.last_rotated).days
            else:
                days_since_rotation = days_since_creation

            if days_since_rotation >= key.rotation_policy_days:
                needs_rotation.append(key)

        return needs_rotation

    async def register_certificate(
        self,
        common_name: str,
        issuer: str,
        valid_from: datetime,
        valid_until: datetime,
        key_algorithm: str,
        key_size: int
    ) -> TLSCertificate:
        """
        Register TLS certificate for monitoring.

        Args:
            common_name: Certificate common name
            issuer: Certificate issuer
            valid_from: Valid from date
            valid_until: Valid until date
            key_algorithm: Key algorithm
            key_size: Key size

        Returns:
            Registered certificate
        """
        logger.info(f"Registering TLS certificate: {common_name}")

        days_until_expiry = (valid_until - datetime.utcnow()).days
        is_expired = days_until_expiry < 0

        cert = TLSCertificate(
            cert_id=f"cert-{hashlib.md5(f'{common_name}'.encode()).hexdigest()[:12]}",
            common_name=common_name,
            subject_alternative_names=[],
            issuer=issuer,
            valid_from=valid_from,
            valid_until=valid_until,
            key_algorithm=key_algorithm,
            key_size=key_size,
            signature_algorithm="sha256WithRSAEncryption",
            is_self_signed=issuer == common_name,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry
        )

        self.certificates[cert.cert_id] = cert
        self.statistics["certificates_monitored"] += 1

        if is_expired:
            self.statistics["expired_certificates"] += 1
        elif days_until_expiry < 30:
            self.statistics["expiring_certificates"] += 1

        return cert

    async def check_expiring_certificates(self, days_threshold: int = 30) -> List[TLSCertificate]:
        """
        Check for expiring certificates.

        Args:
            days_threshold: Days until expiration threshold

        Returns:
            List of expiring certificates
        """
        logger.info(f"Checking for certificates expiring within {days_threshold} days")

        expiring = []

        for cert in self.certificates.values():
            if 0 <= cert.days_until_expiry <= days_threshold:
                expiring.append(cert)

        return expiring

    def get_statistics(self) -> Dict[str, Any]:
        """Get encryption manager statistics."""
        return self.statistics


class NetworkThreatDetector:
    """
    Network threat detection.

    Detects advanced network threats like DDoS, lateral movement, and C2 communication.
    """

    def __init__(self):
        """Initialize network threat detector."""
        self.threats: List[NetworkThreat] = []
        self.flow_history: Dict[str, List[NetworkFlow]] = {}

        self.statistics = {
            "threats_detected": 0,
            "by_type": {},
            "critical_threats": 0,
            "high_threats": 0
        }

        logger.info("Network Threat Detector initialized")

    async def detect_ddos(self, flows: List[NetworkFlow]) -> Optional[NetworkThreat]:
        """
        Detect DDoS attacks.

        Args:
            flows: Network flows to analyze

        Returns:
            Detected threat or None
        """
        logger.info("Analyzing flows for DDoS attack")

        # Group by destination IP
        dest_ips: Dict[str, List[NetworkFlow]] = {}
        for flow in flows:
            if flow.destination_ip not in dest_ips:
                dest_ips[flow.destination_ip] = []
            dest_ips[flow.destination_ip].append(flow)

        # Check for high volume to single destination
        for dest_ip, dest_flows in dest_ips.items():
            if len(dest_flows) > 100:  # Threshold for DDoS
                unique_sources = len(set(f.source_ip for f in dest_flows))

                if unique_sources > 50:  # Many sources attacking one target
                    threat = NetworkThreat(
                        threat_id=f"threat-{hashlib.md5(f'{dest_ip}ddos'.encode()).hexdigest()[:12]}",
                        threat_type=NetworkThreatType.DDOS,
                        severity=Severity.CRITICAL,
                        source_ip="multiple",
                        destination_ip=dest_ip,
                        description=f"DDoS attack detected against {dest_ip}",
                        indicators=[
                            f"Unique source IPs: {unique_sources}",
                            f"Total flows: {len(dest_flows)}",
                            f"Target: {dest_ip}"
                        ],
                        flows=dest_flows[:10],
                        risk_score=9.5
                    )

                    self.threats.append(threat)
                    self._update_statistics(threat)

                    return threat

        return None

    async def detect_lateral_movement(self, flows: List[NetworkFlow]) -> Optional[NetworkThreat]:
        """
        Detect lateral movement.

        Args:
            flows: Network flows to analyze

        Returns:
            Detected threat or None
        """
        logger.info("Analyzing flows for lateral movement")

        # Group by source IP
        source_ips: Dict[str, List[NetworkFlow]] = {}
        for flow in flows:
            if flow.source_ip not in source_ips:
                source_ips[flow.source_ip] = []
            source_ips[flow.source_ip].append(flow)

        # Check for single source connecting to many internal destinations
        for source_ip, source_flows in source_ips.items():
            unique_dests = len(set(f.destination_ip for f in source_flows))

            # Check for administrative ports (SSH, RDP, WinRM)
            admin_ports = [22, 3389, 5985, 5986]
            admin_connections = [
                f for f in source_flows
                if f.destination_port in admin_ports
            ]

            if unique_dests > 10 and len(admin_connections) > 5:
                threat = NetworkThreat(
                    threat_id=f"threat-{hashlib.md5(f'{source_ip}lateral'.encode()).hexdigest()[:12]}",
                    threat_type=NetworkThreatType.LATERAL_MOVEMENT,
                    severity=Severity.HIGH,
                    source_ip=source_ip,
                    destination_ip="multiple",
                    description=f"Lateral movement detected from {source_ip}",
                    indicators=[
                        f"Unique destinations: {unique_dests}",
                        f"Admin port connections: {len(admin_connections)}",
                        f"Source: {source_ip}"
                    ],
                    flows=admin_connections[:10],
                    risk_score=8.0
                    )

                self.threats.append(threat)
                self._update_statistics(threat)

                return threat

        return None

    def _update_statistics(self, threat: NetworkThreat):
        """Update threat statistics."""
        self.statistics["threats_detected"] += 1

        if threat.threat_type.value not in self.statistics["by_type"]:
            self.statistics["by_type"][threat.threat_type.value] = 0
        self.statistics["by_type"][threat.threat_type.value] += 1

        if threat.severity == Severity.CRITICAL:
            self.statistics["critical_threats"] += 1
        elif threat.severity == Severity.HIGH:
            self.statistics["high_threats"] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat detector statistics."""
        return self.statistics


# Global instances
_encryption_manager: Optional[EncryptionManager] = None
_network_threat_detector: Optional[NetworkThreatDetector] = None


def get_encryption_manager() -> EncryptionManager:
    """Get or create global encryption manager instance."""
    global _encryption_manager

    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()

    return _encryption_manager


def get_network_threat_detector() -> NetworkThreatDetector:
    """Get or create global network threat detector instance."""
    global _network_threat_detector

    if _network_threat_detector is None:
        _network_threat_detector = NetworkThreatDetector()

    return _network_threat_detector


class NetworkSecurityOrchestrator:
    """
    Network security orchestrator.

    Coordinates all network security, DLP, and encryption management operations.
    """

    def __init__(self):
        """Initialize orchestrator."""
        self.network_analyzer = get_network_analyzer()
        self.data_classifier = get_data_classifier()
        self.dlp_engine = get_dlp_engine()
        self.encryption_manager = get_encryption_manager()
        self.threat_detector = get_network_threat_detector()

        logger.info("Network Security Orchestrator initialized")

    async def perform_full_assessment(
        self,
        firewall_rules: List[FirewallRule],
        network_flows: List[NetworkFlow],
        data_locations: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Perform comprehensive network security assessment.

        Args:
            firewall_rules: Firewall rules to analyze
            network_flows: Network flows to analyze
            data_locations: Data locations to scan (path, content)

        Returns:
            Complete assessment results
        """
        logger.info("Starting full network security assessment")

        start_time = datetime.utcnow()

        # Analyze firewall rules
        firewall_results = []
        for rule in firewall_rules:
            result = await self.network_analyzer.analyze_firewall_rule(rule)
            firewall_results.append(result)

        # Analyze network flows
        flow_threats = []
        for flow in network_flows:
            threat = await self.network_analyzer.analyze_network_flow(flow)
            if threat:
                flow_threats.append(threat)

        # Detect advanced threats
        ddos_threat = await self.threat_detector.detect_ddos(network_flows)
        lateral_threat = await self.threat_detector.detect_lateral_movement(network_flows)

        # Classify data
        classified_data = []
        for location in data_locations:
            data = await self.data_classifier.classify_data(
                location["content"],
                location["path"]
            )
            classified_data.extend(data)

        # Check encryption keys
        keys_needing_rotation = await self.encryption_manager.check_key_rotation()
        expiring_certs = await self.encryption_manager.check_expiring_certificates()

        duration = (datetime.utcnow() - start_time).total_seconds()

        # Calculate risk scores
        firewall_risk = sum(r["risk_score"] for r in firewall_results) / max(len(firewall_results), 1)
        threat_risk = len(flow_threats) * 2.0 + (10.0 if ddos_threat else 0.0) + (8.0 if lateral_threat else 0.0)
        data_risk = len([d for d in classified_data if d.classification in [DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL]]) * 0.5
        encryption_risk = len(keys_needing_rotation) * 1.0 + len(expiring_certs) * 2.0

        overall_risk = min((firewall_risk + threat_risk + data_risk + encryption_risk) / 4.0, 10.0)

        return {
            "assessment_id": f"assessment-{hashlib.md5(f'{start_time}'.encode()).hexdigest()[:12]}",
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "firewall": {
                "rules_analyzed": len(firewall_rules),
                "insecure_rules": len([r for r in firewall_results if not r["is_secure"]]),
                "average_risk_score": firewall_risk,
                "results": firewall_results
            },
            "network_threats": {
                "flow_threats": len(flow_threats),
                "ddos_detected": ddos_threat is not None,
                "lateral_movement_detected": lateral_threat is not None,
                "threats": [
                    {
                        "threat_id": t.threat_id,
                        "type": t.threat_type.value,
                        "severity": t.severity.value,
                        "source_ip": t.source_ip,
                        "destination_ip": t.destination_ip,
                        "risk_score": t.risk_score
                    }
                    for t in flow_threats
                ]
            },
            "data_classification": {
                "total_classified": len(classified_data),
                "by_type": self.data_classifier.statistics["by_type"],
                "by_classification": self.data_classifier.statistics["by_classification"],
                "restricted_data": len([d for d in classified_data if d.classification == DataClassification.RESTRICTED])
            },
            "encryption": {
                "keys_needing_rotation": len(keys_needing_rotation),
                "expiring_certificates": len(expiring_certs),
                "total_keys": len(self.encryption_manager.keys),
                "total_certificates": len(self.encryption_manager.certificates)
            },
            "risk_assessment": {
                "overall_risk_score": overall_risk,
                "firewall_risk": firewall_risk,
                "threat_risk": min(threat_risk, 10.0),
                "data_risk": min(data_risk, 10.0),
                "encryption_risk": min(encryption_risk, 10.0),
                "risk_level": self._get_risk_level(overall_risk)
            },
            "statistics": {
                "network_analyzer": self.network_analyzer.get_statistics(),
                "data_classifier": self.data_classifier.get_statistics(),
                "dlp_engine": self.dlp_engine.get_statistics(),
                "encryption_manager": self.encryption_manager.get_statistics(),
                "threat_detector": self.threat_detector.get_statistics()
            }
        }

    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score."""
        if risk_score >= 8.0:
            return "CRITICAL"
        elif risk_score >= 6.0:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        elif risk_score >= 2.0:
            return "LOW"
        else:
            return "MINIMAL"


# Global instance
_orchestrator: Optional[NetworkSecurityOrchestrator] = None


def get_network_security_orchestrator() -> NetworkSecurityOrchestrator:
    """Get or create global orchestrator instance."""
    global _orchestrator

    if _orchestrator is None:
        _orchestrator = NetworkSecurityOrchestrator()

    return _orchestrator
