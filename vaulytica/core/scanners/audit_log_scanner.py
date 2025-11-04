"""Audit log scanner for monitoring admin and user activity."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta, timezone
import time
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class AuditEvent:
    """Represents an audit log event."""

    event_id: str
    event_type: str  # admin, login, drive, token, mobile
    event_name: str
    actor_email: str
    timestamp: datetime
    ip_address: str = ""
    parameters: Dict = field(default_factory=dict)
    severity: str = "info"  # info, warning, critical
    # Enhanced security fields
    is_admin_action: bool = False
    is_privilege_escalation: bool = False
    is_bulk_action: bool = False
    is_after_hours: bool = False
    target_user: str = ""
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class AuditLogScanResult:
    """Results from an audit log scan."""

    total_events: int = 0
    admin_events: int = 0
    login_events: int = 0
    drive_events: int = 0
    token_events: int = 0
    mobile_events: int = 0
    events: List[AuditEvent] = field(default_factory=list)
    suspicious_events: List[AuditEvent] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    # Enhanced security metrics
    privilege_escalation_events: int = 0
    bulk_action_events: int = 0
    after_hours_admin_events: int = 0
    high_risk_events: int = 0
    recommendations: List[Dict] = field(default_factory=list)


class AuditLogScanner:
    """Scanner for Google Workspace audit logs."""

    def __init__(self, client, domain: str):
        """Initialize the audit log scanner.

        Args:
            client: Authenticated Google Workspace client
            domain: Primary domain to scan
        """
        self.client = client
        self.domain = domain
        self.logger = logger.bind(scanner="audit_log", domain=domain)

    def scan_admin_activity(
        self,
        days_back: int = 7,
        max_results: int = 1000,
        event_filter: Optional[str] = None
    ) -> AuditLogScanResult:
        """Scan admin activity logs with enhanced filtering and performance.

        Args:
            days_back: Number of days to look back
            max_results: Maximum number of events to retrieve
            event_filter: Optional event name filter (e.g., "GRANT_ADMIN_PRIVILEGE")

        Returns:
            AuditLogScanResult with admin activity

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if days_back < 1 or days_back > 180:
            raise ValueError("days_back must be between 1 and 180")
        if max_results < 1 or max_results > 10000:
            raise ValueError("max_results must be between 1 and 10000")

        self.logger.info(
            "scanning_admin_activity",
            days_back=days_back,
            max_results=max_results,
            event_filter=event_filter
        )
        scan_start_time = time.time()

        result = AuditLogScanResult()
        start_time = datetime.now(timezone.utc) - timedelta(days=days_back)

        try:
            events = self._fetch_audit_logs(
                application_name="admin",
                start_time=start_time,
                max_results=max_results,
            )

            result.admin_events = len(events)
            result.total_events += len(events)

            # Apply event filter if specified
            if event_filter:
                events = [e for e in events if event_filter.lower() in e.event_name.lower()]
                self.logger.info("applied_event_filter", filter=event_filter, filtered_count=len(events))

            result.events.extend(events)

            # Detect suspicious admin activity
            result.suspicious_events = self._detect_suspicious_admin_activity(events)

            # Calculate enhanced metrics
            result.privilege_escalation_events = len([e for e in events if e.is_privilege_escalation])
            result.bulk_action_events = len([e for e in events if e.is_bulk_action])
            result.after_hours_admin_events = len([e for e in events if e.is_after_hours])
            result.high_risk_events = len([e for e in events if e.risk_score >= 70])

            # Generate issues and recommendations
            result.issues = self._generate_admin_issues(result)
            result.recommendations = self._generate_admin_recommendations(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            self.logger.info(
                "admin_activity_scan_complete",
                total_events=len(events),
                suspicious=len(result.suspicious_events),
                privilege_escalation=result.privilege_escalation_events,
                bulk_actions=result.bulk_action_events,
                after_hours=result.after_hours_admin_events,
                high_risk=result.high_risk_events,
                scan_duration_seconds=round(scan_duration, 2),
            )

        except Exception as e:
            self.logger.error("admin_activity_scan_failed", error=str(e))
            raise

        return result

    def scan_login_activity(
        self, days_back: int = 7, max_results: int = 1000
    ) -> AuditLogScanResult:
        """Scan login activity logs.

        Args:
            days_back: Number of days to look back
            max_results: Maximum number of events to retrieve

        Returns:
            AuditLogScanResult with login activity
        """
        self.logger.info("scanning_login_activity", days_back=days_back)

        result = AuditLogScanResult()
        start_time = datetime.now(timezone.utc) - timedelta(days=days_back)

        try:
            events = self._fetch_audit_logs(
                application_name="login",
                start_time=start_time,
                max_results=max_results,
            )

            result.login_events = len(events)
            result.total_events += len(events)
            result.events.extend(events)

            # Detect suspicious login activity
            result.suspicious_events = self._detect_suspicious_login_activity(events)

            self.logger.info(
                "login_activity_scan_complete",
                total_events=len(events),
                suspicious=len(result.suspicious_events),
            )

        except Exception as e:
            self.logger.error("login_activity_scan_failed", error=str(e))
            raise

        return result

    def scan_drive_activity(
        self, days_back: int = 7, max_results: int = 1000
    ) -> AuditLogScanResult:
        """Scan Drive activity logs.

        Args:
            days_back: Number of days to look back
            max_results: Maximum number of events to retrieve

        Returns:
            AuditLogScanResult with Drive activity
        """
        self.logger.info("scanning_drive_activity", days_back=days_back)

        result = AuditLogScanResult()
        start_time = datetime.now(timezone.utc) - timedelta(days=days_back)

        try:
            events = self._fetch_audit_logs(
                application_name="drive",
                start_time=start_time,
                max_results=max_results,
            )

            result.drive_events = len(events)
            result.total_events += len(events)
            result.events.extend(events)

            # Detect suspicious drive activity
            result.suspicious_events = self._detect_suspicious_drive_activity(events)

            self.logger.info(
                "drive_activity_scan_complete",
                total_events=len(events),
                suspicious=len(result.suspicious_events),
            )

        except Exception as e:
            self.logger.error("drive_activity_scan_failed", error=str(e))
            raise

        return result

    def scan_token_activity(
        self, days_back: int = 7, max_results: int = 1000
    ) -> AuditLogScanResult:
        """Scan OAuth token activity logs.

        Args:
            days_back: Number of days to look back
            max_results: Maximum number of events to retrieve

        Returns:
            AuditLogScanResult with token activity
        """
        self.logger.info("scanning_token_activity", days_back=days_back)

        result = AuditLogScanResult()
        start_time = datetime.now(timezone.utc) - timedelta(days=days_back)

        try:
            events = self._fetch_audit_logs(
                application_name="token",
                start_time=start_time,
                max_results=max_results,
            )

            result.token_events = len(events)
            result.total_events += len(events)
            result.events.extend(events)

            self.logger.info(
                "token_activity_scan_complete",
                total_events=len(events),
            )

        except Exception as e:
            self.logger.error("token_activity_scan_failed", error=str(e))
            raise

        return result

    def _fetch_audit_logs(
        self,
        application_name: str,
        start_time: datetime,
        max_results: int = 1000,
    ) -> List[AuditEvent]:
        """Fetch audit logs from the Reports API.

        Args:
            application_name: Application to fetch logs for (admin, login, drive, token, mobile)
            start_time: Start time for log retrieval
            max_results: Maximum number of events to retrieve

        Returns:
            List of AuditEvent objects
        """
        events = []
        page_token = None
        count = 0

        try:
            while count < max_results:
                response = (
                    self.client.reports.activities()
                    .list(
                        userKey="all",
                        applicationName=application_name,
                        startTime=start_time.isoformat() + "Z",
                        pageToken=page_token,
                        maxResults=min(1000, max_results - count),
                    )
                    .execute()
                )

                for item in response.get("items", []):
                    event = self._parse_audit_event(item, application_name)
                    events.append(event)
                    count += 1

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            self.logger.error(
                "failed_to_fetch_audit_logs",
                application=application_name,
                error=str(e),
            )
            raise

        return events

    def _parse_audit_event(self, item: Dict, event_type: str) -> AuditEvent:
        """Parse an audit log item into an AuditEvent."""
        event_id = item.get("id", {}).get("uniqueQualifier", "")
        timestamp_str = item.get("id", {}).get("time", "")

        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            timestamp = datetime.now(timezone.utc)

        # Extract event details
        events_list = item.get("events", [])
        event_name = events_list[0].get("name", "") if events_list else ""

        # Extract parameters
        parameters = {}
        if events_list:
            for param in events_list[0].get("parameters", []):
                param_name = param.get("name", "")
                param_value = param.get("value", "")
                parameters[param_name] = param_value

        return AuditEvent(
            event_id=event_id,
            event_type=event_type,
            event_name=event_name,
            actor_email=item.get("actor", {}).get("email", ""),
            timestamp=timestamp,
            ip_address=item.get("ipAddress", ""),
            parameters=parameters,
        )

    def _detect_suspicious_admin_activity(
        self, events: List[AuditEvent]
    ) -> List[AuditEvent]:
        """Detect suspicious admin activity with enhanced security analysis."""
        suspicious = []

        # Define privilege escalation events (CRITICAL)
        privilege_escalation_events = [
            "GRANT_ADMIN_PRIVILEGE",
            "ASSIGN_ROLE",
            "CREATE_ROLE",
            "UPDATE_ROLE",
            "GRANT_DELEGATED_ADMIN_PRIVILEGES",
        ]

        # Define bulk/destructive actions (HIGH)
        bulk_action_events = [
            "DELETE_USER",
            "SUSPEND_USER",
            "DELETE_GROUP",
            "REMOVE_FROM_GROUP",
            "CREATE_DATA_TRANSFER_REQUEST",
            "CHANGE_PASSWORD",
        ]

        # Define sensitive configuration changes (MEDIUM)
        sensitive_config_events = [
            "CHANGE_APPLICATION_SETTING",
            "TOGGLE_SERVICE_ENABLED",
            "CHANGE_CALENDAR_SETTING",
            "CHANGE_GMAIL_SETTING",
            "CHANGE_DRIVE_SETTING",
            "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT",
            "CHANGE_TWO_STEP_VERIFICATION_START_DATE",
        ]

        # Track bulk actions by actor and time window
        actor_actions = {}  # {actor_email: [(timestamp, event_name), ...]}

        for event in events:
            event.is_admin_action = True

            # Extract target user if available
            event.target_user = event.parameters.get("USER_EMAIL", "")

            # Check if after hours (outside 8am-6pm local time)
            hour = event.timestamp.hour
            event.is_after_hours = hour < 8 or hour >= 18

            # CRITICAL: Privilege escalation detection
            if event.event_name in privilege_escalation_events:
                event.is_privilege_escalation = True
                event.severity = "critical"
                event.risk_score = 90
                event.risk_factors.append("Privilege escalation: granting admin rights")
                suspicious.append(event)
                continue

            # HIGH: Bulk action detection (multiple similar actions in short time)
            if event.event_name in bulk_action_events:
                actor = event.actor_email
                if actor not in actor_actions:
                    actor_actions[actor] = []
                actor_actions[actor].append((event.timestamp, event.event_name))

                # Check for bulk actions (5+ similar actions within 10 minutes)
                recent_actions = [
                    (ts, name) for ts, name in actor_actions[actor]
                    if (event.timestamp - ts).total_seconds() <= 600  # 10 minutes
                    and name == event.event_name
                ]

                if len(recent_actions) >= 5:
                    event.is_bulk_action = True
                    event.severity = "critical"
                    event.risk_score = 85
                    event.risk_factors.append(f"Bulk action: {len(recent_actions)} {event.event_name} in 10 minutes")
                    suspicious.append(event)
                    continue

                # Single destructive action
                event.severity = "high"
                event.risk_score = 70
                event.risk_factors.append(f"Destructive action: {event.event_name}")
                suspicious.append(event)
                continue

            # MEDIUM: Sensitive configuration changes
            if event.event_name in sensitive_config_events:
                event.severity = "warning"
                event.risk_score = 50
                event.risk_factors.append(f"Configuration change: {event.event_name}")

                # Increase severity if after hours
                if event.is_after_hours:
                    event.severity = "high"
                    event.risk_score = 65
                    event.risk_factors.append("After-hours admin activity")

                suspicious.append(event)

        return suspicious

    def _detect_suspicious_login_activity(
        self, events: List[AuditEvent]
    ) -> List[AuditEvent]:
        """Detect suspicious login activity."""
        suspicious = []

        # Define suspicious login events
        suspicious_event_names = [
            "login_failure",
            "login_challenge",
            "suspicious_login",
            "account_disabled_password_leak",
        ]

        for event in events:
            if event.event_name in suspicious_event_names:
                event.severity = "warning"
                suspicious.append(event)

        return suspicious

    def _detect_suspicious_drive_activity(
        self, events: List[AuditEvent]
    ) -> List[AuditEvent]:
        """Detect suspicious Drive activity."""
        suspicious = []

        # Define suspicious drive events
        suspicious_event_names = [
            "download",
            "change_user_access",
            "change_document_access_scope",
            "shared_drive_membership_change",
        ]

        for event in events:
            if event.event_name in suspicious_event_names:
                # Check for external sharing
                visibility = event.parameters.get("visibility", "")
                if visibility in ["public", "public_on_the_web"]:
                    event.severity = "critical"
                    suspicious.append(event)
                elif event.event_name == "download":
                    event.severity = "info"
                    suspicious.append(event)

        return suspicious

    def _generate_admin_issues(self, result: AuditLogScanResult) -> List[Dict]:
        """Generate security issues from admin activity scan."""
        issues = []

        # CRITICAL: Privilege escalation events
        priv_esc_events = [e for e in result.events if e.is_privilege_escalation]
        if priv_esc_events:
            for event in priv_esc_events:
                issues.append({
                    "severity": "critical",
                    "type": "privilege_escalation",
                    "actor": event.actor_email,
                    "target_user": event.target_user,
                    "event_name": event.event_name,
                    "timestamp": event.timestamp.isoformat(),
                    "ip_address": event.ip_address,
                    "description": f"Admin privilege granted by {event.actor_email}",
                    "recommendation": "Review this privilege escalation immediately. Verify it was authorized.",
                    "risk_score": event.risk_score,
                    "risk_factors": event.risk_factors,
                })

        # CRITICAL: Bulk destructive actions
        bulk_events = [e for e in result.events if e.is_bulk_action]
        if bulk_events:
            # Group by actor
            by_actor = {}
            for event in bulk_events:
                if event.actor_email not in by_actor:
                    by_actor[event.actor_email] = []
                by_actor[event.actor_email].append(event)

            for actor, events in by_actor.items():
                issues.append({
                    "severity": "critical",
                    "type": "bulk_destructive_action",
                    "actor": actor,
                    "event_count": len(events),
                    "event_name": events[0].event_name,
                    "time_range": f"{events[0].timestamp.isoformat()} to {events[-1].timestamp.isoformat()}",
                    "description": f"Bulk action detected: {len(events)} {events[0].event_name} by {actor}",
                    "recommendation": "Investigate bulk action. May indicate account compromise or insider threat.",
                    "risk_score": 85,
                })

        # HIGH: After-hours admin activity
        after_hours_events = [e for e in result.events if e.is_after_hours and e.severity in ["high", "critical"]]
        if len(after_hours_events) > 10:
            issues.append({
                "severity": "high",
                "type": "after_hours_admin_activity",
                "event_count": len(after_hours_events),
                "description": f"{len(after_hours_events)} high-risk admin actions performed after hours",
                "recommendation": "Review after-hours admin activity. Consider implementing time-based access controls.",
                "risk_score": 70,
            })

        # MEDIUM: High volume of admin changes
        if result.admin_events > 100:
            issues.append({
                "severity": "medium",
                "type": "high_admin_activity",
                "event_count": result.admin_events,
                "description": f"High volume of admin activity: {result.admin_events} events",
                "recommendation": "Review admin activity for unusual patterns.",
                "risk_score": 50,
            })

        return issues

    def _generate_admin_recommendations(self, result: AuditLogScanResult) -> List[Dict]:
        """Generate security recommendations from admin activity scan."""
        recommendations = []

        # Recommendation: Enable admin activity alerts
        if result.high_risk_events > 0:
            recommendations.append({
                "priority": "high",
                "title": "Enable Real-Time Admin Activity Alerts",
                "description": f"{result.high_risk_events} high-risk admin events detected",
                "action": "Configure alerts in Admin Console > Reporting > Audit and investigation",
                "benefit": "Get notified immediately of suspicious admin activity",
            })

        # Recommendation: Review privilege escalations
        if result.privilege_escalation_events > 0:
            recommendations.append({
                "priority": "critical",
                "title": f"Review {result.privilege_escalation_events} Privilege Escalation Events",
                "description": "Admin privileges were granted to users",
                "action": "Review each privilege escalation and revoke if unauthorized",
                "benefit": "Prevent unauthorized admin access",
            })

        # Recommendation: Implement time-based access controls
        if result.after_hours_admin_events > 5:
            recommendations.append({
                "priority": "high",
                "title": "Implement Time-Based Access Controls",
                "description": f"{result.after_hours_admin_events} admin actions performed after hours",
                "action": "Consider restricting admin access to business hours",
                "benefit": "Reduce risk of after-hours attacks",
            })

        # Recommendation: Enable 2FA for admins
        recommendations.append({
            "priority": "high",
            "title": "Enforce 2-Step Verification for All Admins",
            "description": "Protect admin accounts with 2FA",
            "action": "Go to Admin Console > Security > 2-Step Verification",
            "benefit": "Prevent account takeover of admin accounts",
        })

        # Recommendation: Regular admin access reviews
        if result.admin_events > 50:
            recommendations.append({
                "priority": "medium",
                "title": "Schedule Regular Admin Access Reviews",
                "description": f"High admin activity: {result.admin_events} events",
                "action": "Review admin roles quarterly and remove unnecessary privileges",
                "benefit": "Maintain principle of least privilege",
            })

        return recommendations

