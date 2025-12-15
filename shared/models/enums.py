"""Shared enumerations for Vaulytica models.

These enums provide consistent values across CLI and web backends.
"""

from enum import Enum


class ScanStatus(str, Enum):
    """Status of a scan run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Status of a finding."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class ScanType(str, Enum):
    """Types of scans available."""

    FILES = "files"
    USERS = "users"
    OAUTH = "oauth"
    POSTURE = "posture"
    PII = "pii"
    DEVICES = "devices"
    ALL = "all"


class ResourceType(str, Enum):
    """Types of resources that can be scanned."""

    FILE = "file"
    USER = "user"
    DEVICE = "device"
    APP = "app"
    SETTING = "setting"
    DOMAIN = "domain"


class RiskLevel(str, Enum):
    """Risk levels for categorizing findings."""

    CRITICAL = "critical"  # Score 90-100
    HIGH = "high"  # Score 70-89
    MEDIUM = "medium"  # Score 40-69
    LOW = "low"  # Score 1-39
    NONE = "none"  # Score 0

    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        """Convert a numeric risk score to a risk level."""
        if score >= 90:
            return cls.CRITICAL
        elif score >= 70:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 1:
            return cls.LOW
        return cls.NONE


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    PCI_DSS = "pci-dss"
    FERPA = "ferpa"
    FEDRAMP = "fedramp"
    NIST = "nist"
    ISO27001 = "iso27001"
