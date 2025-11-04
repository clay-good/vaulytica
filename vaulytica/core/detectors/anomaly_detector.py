"""Anomaly detector for identifying unusual activity patterns."""

from dataclasses import dataclass, field
from typing import List, Dict, Set
from datetime import datetime, time, timezone
from collections import defaultdict
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Anomaly:
    """Represents a detected anomaly."""

    anomaly_type: str
    severity: str  # low, medium, high, critical
    user_email: str
    description: str
    timestamp: datetime
    details: Dict = field(default_factory=dict)


@dataclass
class AnomalyDetectionResult:
    """Results from anomaly detection."""

    total_anomalies: int = 0
    critical_anomalies: int = 0
    high_anomalies: int = 0
    medium_anomalies: int = 0
    low_anomalies: int = 0
    anomalies: List[Anomaly] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)


class AnomalyDetector:
    """Detector for unusual activity patterns."""

    def __init__(self, domain: str):
        """Initialize the anomaly detector.

        Args:
            domain: Primary domain
        """
        self.domain = domain
        self.logger = logger.bind(detector="anomaly", domain=domain)

        # Define normal business hours (9 AM - 6 PM)
        self.business_hours_start = time(9, 0)
        self.business_hours_end = time(18, 0)

    def detect_anomalies(self, events: List) -> AnomalyDetectionResult:
        """Detect anomalies in a list of audit events.

        Args:
            events: List of AuditEvent objects

        Returns:
            AnomalyDetectionResult with detected anomalies
        """
        self.logger.info("detecting_anomalies", total_events=len(events))

        result = AnomalyDetectionResult()

        # Detect different types of anomalies
        result.anomalies.extend(self._detect_unusual_login_location(events))
        result.anomalies.extend(self._detect_unusual_access_time(events))
        result.anomalies.extend(self._detect_mass_file_download(events))
        result.anomalies.extend(self._detect_privilege_escalation(events))
        result.anomalies.extend(self._detect_suspicious_api_usage(events))

        # Calculate statistics
        result.total_anomalies = len(result.anomalies)

        for anomaly in result.anomalies:
            if anomaly.severity == "critical":
                result.critical_anomalies += 1
            elif anomaly.severity == "high":
                result.high_anomalies += 1
            elif anomaly.severity == "medium":
                result.medium_anomalies += 1
            elif anomaly.severity == "low":
                result.low_anomalies += 1

        result.statistics = {
            "total_anomalies": result.total_anomalies,
            "critical": result.critical_anomalies,
            "high": result.high_anomalies,
            "medium": result.medium_anomalies,
            "low": result.low_anomalies,
        }

        self.logger.info(
            "anomaly_detection_complete",
            total_anomalies=result.total_anomalies,
            critical=result.critical_anomalies,
        )

        return result

    def _detect_unusual_login_location(self, events: List) -> List[Anomaly]:
        """Detect logins from unusual locations.

        Looks for:
        - Multiple countries in short time period
        - Logins from high-risk countries
        """
        anomalies = []

        # Track login locations per user
        user_locations: Dict[str, List[Dict]] = defaultdict(list)

        for event in events:
            if event.event_type == "login" and event.event_name == "login_success":
                user_locations[event.actor_email].append(
                    {
                        "ip": event.ip_address,
                        "timestamp": event.timestamp,
                        "country": event.parameters.get("login_country", ""),
                    }
                )

        # Analyze each user's login patterns
        for user_email, locations in user_locations.items():
            # Check for multiple countries
            countries = set(loc["country"] for loc in locations if loc["country"])

            if len(countries) > 2:
                anomalies.append(
                    Anomaly(
                        anomaly_type="unusual_login_location",
                        severity="high",
                        user_email=user_email,
                        description=f"User logged in from {len(countries)} different countries",
                        timestamp=locations[-1]["timestamp"],
                        details={"countries": list(countries)},
                    )
                )

        return anomalies

    def _detect_unusual_access_time(self, events: List) -> List[Anomaly]:
        """Detect access during unusual hours.

        Looks for:
        - Activity outside business hours
        - Weekend activity
        """
        anomalies = []

        # Track after-hours activity per user
        user_after_hours: Dict[str, int] = defaultdict(int)

        for event in events:
            event_time = event.timestamp.time()
            is_weekend = event.timestamp.weekday() >= 5  # Saturday = 5, Sunday = 6

            # Check if outside business hours
            is_after_hours = (
                event_time < self.business_hours_start
                or event_time > self.business_hours_end
                or is_weekend
            )

            if is_after_hours:
                user_after_hours[event.actor_email] += 1

        # Flag users with significant after-hours activity
        for user_email, count in user_after_hours.items():
            if count > 20:  # More than 20 after-hours events
                anomalies.append(
                    Anomaly(
                        anomaly_type="unusual_access_time",
                        severity="medium",
                        user_email=user_email,
                        description=f"User had {count} events outside business hours",
                        timestamp=datetime.now(timezone.utc),
                        details={"after_hours_count": count},
                    )
                )
            elif count > 5:  # 6-20 after-hours events
                anomalies.append(
                    Anomaly(
                        anomaly_type="unusual_access_time",
                        severity="low",
                        user_email=user_email,
                        description=f"User had {count} events outside business hours",
                        timestamp=datetime.now(timezone.utc),
                        details={"after_hours_count": count},
                    )
                )

        return anomalies

    def _detect_mass_file_download(self, events: List) -> List[Anomaly]:
        """Detect mass file downloads.

        Looks for:
        - High volume of downloads in short time
        - Downloads of sensitive files
        """
        anomalies = []

        # Track downloads per user
        user_downloads: Dict[str, int] = defaultdict(int)

        for event in events:
            if event.event_type == "drive" and event.event_name == "download":
                user_downloads[event.actor_email] += 1

        # Flag users with excessive downloads
        for user_email, count in user_downloads.items():
            if count > 50:  # More than 50 downloads
                severity = "critical" if count > 100 else "high"

                anomalies.append(
                    Anomaly(
                        anomaly_type="mass_file_download",
                        severity=severity,
                        user_email=user_email,
                        description=f"User downloaded {count} files",
                        timestamp=datetime.now(timezone.utc),
                        details={"download_count": count},
                    )
                )

        return anomalies

    def _detect_privilege_escalation(self, events: List) -> List[Anomaly]:
        """Detect privilege escalation attempts.

        Looks for:
        - Admin privilege grants
        - Role changes
        - Permission changes
        """
        anomalies = []

        for event in events:
            if event.event_type == "admin":
                if event.event_name == "GRANT_ADMIN_PRIVILEGE":
                    target_user = event.parameters.get("USER_EMAIL", "")

                    anomalies.append(
                        Anomaly(
                            anomaly_type="privilege_escalation",
                            severity="critical",
                            user_email=event.actor_email,
                            description=f"Admin privilege granted to {target_user}",
                            timestamp=event.timestamp,
                            details={
                                "target_user": target_user,
                                "privilege": event.parameters.get("PRIVILEGE_NAME", ""),
                            },
                        )
                    )

                elif event.event_name == "ASSIGN_ROLE":
                    target_user = event.parameters.get("USER_EMAIL", "")
                    role_name = event.parameters.get("ROLE_NAME", "")

                    anomalies.append(
                        Anomaly(
                            anomaly_type="privilege_escalation",
                            severity="high",
                            user_email=event.actor_email,
                            description=f"Role '{role_name}' assigned to {target_user}",
                            timestamp=event.timestamp,
                            details={"target_user": target_user, "role": role_name},
                        )
                    )

        return anomalies

    def _detect_suspicious_api_usage(self, events: List) -> List[Anomaly]:
        """Detect suspicious API usage patterns.

        Looks for:
        - High volume of API calls
        - Unusual API scopes
        - Token authorization events
        """
        anomalies = []

        # Track API usage per user
        user_api_calls: Dict[str, int] = defaultdict(int)

        for event in events:
            if event.event_type == "token":
                user_api_calls[event.actor_email] += 1

                # Check for suspicious token events
                if event.event_name == "authorize":
                    app_name = event.parameters.get("app_name", "")
                    scopes = event.parameters.get("scope", "")

                    # Check for sensitive scopes
                    sensitive_scopes = [
                        "https://www.googleapis.com/auth/admin.directory.user",
                        "https://www.googleapis.com/auth/admin.directory.group",
                        "https://www.googleapis.com/auth/drive",
                    ]

                    if any(scope in scopes for scope in sensitive_scopes):
                        anomalies.append(
                            Anomaly(
                                anomaly_type="suspicious_api_usage",
                                severity="high",
                                user_email=event.actor_email,
                                description=f"User authorized app '{app_name}' with sensitive scopes",
                                timestamp=event.timestamp,
                                details={"app_name": app_name, "scopes": scopes},
                            )
                        )

        # Flag users with excessive API usage
        for user_email, count in user_api_calls.items():
            if count > 100:  # More than 100 API calls
                anomalies.append(
                    Anomaly(
                        anomaly_type="suspicious_api_usage",
                        severity="medium",
                        user_email=user_email,
                        description=f"User made {count} API calls",
                        timestamp=datetime.now(timezone.utc),
                        details={"api_call_count": count},
                    )
                )

        return anomalies

