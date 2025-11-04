"""Calendar scanner for detecting security issues in Google Calendar."""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta, timezone
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class CalendarInfo:
    """Represents a Google Calendar."""

    calendar_id: str
    summary: str
    description: str = ""
    is_public: bool = False
    is_primary: bool = False
    owner_email: str = ""
    acl_rules: List[Dict] = field(default_factory=list)
    external_shares: List[str] = field(default_factory=list)
    risk_score: int = 0


@dataclass
class CalendarEvent:
    """Represents a calendar event."""

    event_id: str
    calendar_id: str
    summary: str
    description: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    attendees: List[str] = field(default_factory=list)
    external_attendees: List[str] = field(default_factory=list)
    has_pii: bool = False
    pii_types: List[str] = field(default_factory=list)


@dataclass
class CalendarScanResult:
    """Results from a calendar security scan."""

    total_calendars: int = 0
    public_calendars: int = 0
    calendars_with_external_shares: int = 0
    total_events_scanned: int = 0
    events_with_pii: int = 0
    calendars: List[CalendarInfo] = field(default_factory=list)
    events_with_pii_list: List[CalendarEvent] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)


class CalendarScanner:
    """Scanner for Google Calendar security issues."""

    def __init__(self, client, domain: str, pii_detector=None):
        """Initialize the calendar scanner.

        Args:
            client: Authenticated Google Workspace client
            domain: Primary domain to scan
            pii_detector: Optional PII detector instance
        """
        self.client = client
        self.domain = domain
        self.pii_detector = pii_detector
        self.logger = logger.bind(scanner="calendar", domain=domain)

    def scan_all_calendars(
        self,
        check_pii: bool = False,
        days_ahead: int = 30,
        max_calendars: Optional[int] = None,
    ) -> CalendarScanResult:
        """Scan all calendars in the domain with enhanced performance.

        Args:
            check_pii: Whether to scan events for PII
            days_ahead: Number of days ahead to scan events
            max_calendars: Maximum number of calendars to scan (for performance testing)

        Returns:
            CalendarScanResult with all findings

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_calendars is not None and (not isinstance(max_calendars, int) or max_calendars < 1):
            raise ValueError("max_calendars must be a positive integer")
        if days_ahead < 1:
            raise ValueError("days_ahead must be at least 1")

        self.logger.info(
            "starting_calendar_scan",
            check_pii=check_pii,
            days_ahead=days_ahead,
            max_calendars=max_calendars,
        )
        scan_start_time = time.time()

        result = CalendarScanResult()
        failed_calendars = []
        calendar_count = 0

        try:
            # Get all users in the domain
            self.logger.info("fetching_users")
            users = self._list_all_users()
            self.logger.info("users_fetched", count=len(users))

            # Scan each user's calendars
            for user in users:
                user_email = user.get("primaryEmail", "")

                try:
                    calendars = self._scan_user_calendars(user_email)

                    for calendar in calendars:
                        try:
                            result.calendars.append(calendar)
                            result.total_calendars += 1
                            calendar_count += 1

                            if calendar.is_public:
                                result.public_calendars += 1

                            if calendar.external_shares:
                                result.calendars_with_external_shares += 1

                            # Scan events for PII if requested
                            if check_pii and self.pii_detector:
                                events = self._scan_calendar_events(
                                    calendar.calendar_id,
                                    user_email,
                                    days_ahead,
                                )
                                result.total_events_scanned += len(events)

                                for event in events:
                                    if event.has_pii:
                                        result.events_with_pii += 1
                                        result.events_with_pii_list.append(event)

                            # Log progress every 20 calendars
                            if calendar_count % 20 == 0:
                                self.logger.info(
                                    "calendar_scan_progress",
                                    scanned=calendar_count,
                                    public=result.public_calendars,
                                    with_external_shares=result.calendars_with_external_shares,
                                )

                            # Check max_calendars limit
                            if max_calendars and calendar_count >= max_calendars:
                                self.logger.info("max_calendars_limit_reached", max_calendars=max_calendars)
                                break

                        except Exception as e:
                            self.logger.warning(
                                "failed_to_process_calendar",
                                calendar_id=calendar.calendar_id,
                                user_email=user_email,
                                error=str(e)
                            )
                            failed_calendars.append({
                                "calendar_id": calendar.calendar_id,
                                "user_email": user_email,
                                "error": str(e)
                            })
                            continue

                    # Break outer loop if limit reached
                    if max_calendars and calendar_count >= max_calendars:
                        break

                except Exception as e:
                    self.logger.debug("failed_to_scan_user_calendars", user_email=user_email, error=str(e))
                    continue

            # Generate issues
            result.issues = self._generate_issues(result)

            # Calculate statistics
            result.statistics = self._calculate_statistics(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            self.logger.info(
                "calendar_scan_complete",
                total_calendars=result.total_calendars,
                public_calendars=result.public_calendars,
                events_with_pii=result.events_with_pii,
                failed_calendars=len(failed_calendars),
                scan_duration_seconds=round(scan_duration, 2),
            )

            # Log warning if many calendars failed
            if failed_calendars and len(failed_calendars) > 5:
                self.logger.warning(
                    "many_calendars_failed_processing",
                    failed_count=len(failed_calendars),
                    sample_errors=failed_calendars[:3]
                )

        except HttpError as e:
            if e.resp.status == 403:
                self.logger.error("insufficient_permissions_to_scan_calendars", error=str(e))
                raise
            else:
                self.logger.error("calendar_scan_failed", error=str(e))
                raise
        except Exception as e:
            self.logger.error("calendar_scan_failed", error=str(e))
            raise

        return result

    def _list_all_users(self) -> List[Dict]:
        """List all users in the domain."""
        users = []
        page_token = None

        try:
            while True:
                response = (
                    self.client.admin.users()
                    .list(domain=self.domain, pageToken=page_token, maxResults=500)
                    .execute()
                )

                users.extend(response.get("users", []))

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            self.logger.error("failed_to_list_users", error=str(e))
            raise

        return users

    def _scan_user_calendars(self, user_email: str) -> List[CalendarInfo]:
        """Scan calendars for a specific user."""
        calendars = []

        try:
            # Get calendar list
            calendar_list = (
                self.client.calendar.calendarList()
                .list(userId=user_email)
                .execute()
            )

            for cal_item in calendar_list.get("items", []):
                calendar_id = cal_item.get("id", "")

                # Get calendar details and ACL
                calendar_info = self._get_calendar_details(calendar_id, user_email)
                calendars.append(calendar_info)

        except HttpError as e:
            self.logger.debug("failed_to_scan_calendars", user=user_email, error=str(e))

        return calendars

    def _get_calendar_details(self, calendar_id: str, user_email: str) -> CalendarInfo:
        """Get detailed information about a calendar."""
        calendar_info = CalendarInfo(
            calendar_id=calendar_id,
            summary="",
            owner_email=user_email,
        )

        try:
            # Get calendar metadata
            calendar = (
                self.client.calendar.calendars()
                .get(calendarId=calendar_id)
                .execute()
            )

            calendar_info.summary = calendar.get("summary", "")
            calendar_info.description = calendar.get("description", "")

            # Get ACL rules
            acl = (
                self.client.calendar.acl()
                .list(calendarId=calendar_id)
                .execute()
            )

            calendar_info.acl_rules = acl.get("items", [])

            # Check for public access and external shares
            for rule in calendar_info.acl_rules:
                scope = rule.get("scope", {})
                scope_type = scope.get("type", "")

                if scope_type == "default":
                    calendar_info.is_public = True

                if scope_type == "user":
                    scope_value = scope.get("value", "")
                    if scope_value and not scope_value.endswith(f"@{self.domain}"):
                        calendar_info.external_shares.append(scope_value)

            # Calculate risk score
            calendar_info.risk_score = self._calculate_calendar_risk_score(calendar_info)

        except HttpError as e:
            self.logger.debug("failed_to_get_calendar_details", calendar_id=calendar_id, error=str(e))

        return calendar_info

    def _scan_calendar_events(
        self,
        calendar_id: str,
        user_email: str,
        days_ahead: int,
    ) -> List[CalendarEvent]:
        """Scan calendar events for PII."""
        events = []

        try:
            # Get events for the next N days
            now = datetime.now(timezone.utc)
            time_min = now.isoformat().replace('+00:00', 'Z')
            time_max = (now + timedelta(days=days_ahead)).isoformat().replace('+00:00', 'Z')

            events_result = (
                self.client.calendar.events()
                .list(
                    calendarId=calendar_id,
                    timeMin=time_min,
                    timeMax=time_max,
                    maxResults=100,
                    singleEvents=True,
                    orderBy="startTime",
                )
                .execute()
            )

            for event_data in events_result.get("items", []):
                event = self._parse_event(event_data, calendar_id)

                # Check for PII if detector is available
                if self.pii_detector:
                    text_to_scan = f"{event.summary} {event.description}"
                    pii_findings = self.pii_detector.detect_pii(text_to_scan)

                    if pii_findings:
                        event.has_pii = True
                        event.pii_types = list(set(f.pii_type for f in pii_findings))

                events.append(event)

        except HttpError as e:
            self.logger.debug("failed_to_scan_events", calendar_id=calendar_id, error=str(e))

        return events

    def _parse_event(self, event_data: Dict, calendar_id: str) -> CalendarEvent:
        """Parse an event from API response."""
        event = CalendarEvent(
            event_id=event_data.get("id", ""),
            calendar_id=calendar_id,
            summary=event_data.get("summary", ""),
            description=event_data.get("description", ""),
        )

        # Parse attendees
        attendees = event_data.get("attendees", [])
        for attendee in attendees:
            email = attendee.get("email", "")
            event.attendees.append(email)

            if email and not email.endswith(f"@{self.domain}"):
                event.external_attendees.append(email)

        return event

    def _calculate_calendar_risk_score(self, calendar: CalendarInfo) -> int:
        """Calculate risk score for a calendar (0-100)."""
        score = 0

        # Public calendars are high risk
        if calendar.is_public:
            score += 50

        # External shares add risk
        if calendar.external_shares:
            score += min(30, len(calendar.external_shares) * 10)

        return min(100, score)

    def _generate_issues(self, result: CalendarScanResult) -> List[Dict]:
        """Generate list of security issues found."""
        issues = []

        # Public calendar issues
        for calendar in result.calendars:
            if calendar.is_public:
                issues.append(
                    {
                        "type": "public_calendar",
                        "severity": "high",
                        "calendar": calendar.summary,
                        "owner": calendar.owner_email,
                        "description": "Calendar is publicly accessible",
                        "risk_score": calendar.risk_score,
                    }
                )

            if calendar.external_shares:
                issues.append(
                    {
                        "type": "external_calendar_share",
                        "severity": "medium",
                        "calendar": calendar.summary,
                        "owner": calendar.owner_email,
                        "description": f"Calendar shared with {len(calendar.external_shares)} external users",
                        "external_users": calendar.external_shares,
                        "risk_score": calendar.risk_score,
                    }
                )

        # PII in events issues
        for event in result.events_with_pii_list:
            issues.append(
                {
                    "type": "pii_in_calendar_event",
                    "severity": "high",
                    "event": event.summary,
                    "calendar": event.calendar_id,
                    "description": f"Event contains PII: {', '.join(event.pii_types)}",
                    "pii_types": event.pii_types,
                }
            )

        return issues

    def _calculate_statistics(self, result: CalendarScanResult) -> Dict:
        """Calculate summary statistics."""
        return {
            "total_calendars": result.total_calendars,
            "public_calendars": result.public_calendars,
            "calendars_with_external_shares": result.calendars_with_external_shares,
            "total_events_scanned": result.total_events_scanned,
            "events_with_pii": result.events_with_pii,
            "total_issues": len(result.issues),
        }

