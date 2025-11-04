"""Tests for calendar scanner."""

import pytest
from datetime import datetime
from unittest.mock import Mock, MagicMock
from vaulytica.core.scanners.calendar_scanner import (
    CalendarScanner,
    CalendarInfo,
    CalendarEvent,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.admin = Mock()
    client.calendar = Mock()
    return client


@pytest.fixture
def calendar_scanner(mock_client):
    """Create a CalendarScanner instance."""
    return CalendarScanner(mock_client, "example.com")


class TestCalendarScanner:
    """Tests for CalendarScanner class."""

    def test_init(self, calendar_scanner):
        """Test scanner initialization."""
        assert calendar_scanner.domain == "example.com"
        assert calendar_scanner.pii_detector is None

    def test_list_all_users(self, calendar_scanner, mock_client):
        """Test listing all users."""
        # Mock users list response
        mock_client.admin.users().list().execute.return_value = {
            "users": [
                {"primaryEmail": "user1@example.com"},
                {"primaryEmail": "user2@example.com"},
            ]
        }

        users = calendar_scanner._list_all_users()

        assert len(users) == 2
        assert users[0]["primaryEmail"] == "user1@example.com"

    def test_calculate_calendar_risk_score_public(self, calendar_scanner):
        """Test risk score calculation for public calendar."""
        calendar = CalendarInfo(
            calendar_id="cal1",
            summary="Public Calendar",
            is_public=True,
        )

        score = calendar_scanner._calculate_calendar_risk_score(calendar)

        assert score == 50  # Public calendar = 50 points

    def test_calculate_calendar_risk_score_external_shares(self, calendar_scanner):
        """Test risk score calculation for external shares."""
        calendar = CalendarInfo(
            calendar_id="cal1",
            summary="Shared Calendar",
            external_shares=["external1@other.com", "external2@other.com"],
        )

        score = calendar_scanner._calculate_calendar_risk_score(calendar)

        assert score == 20  # 2 external shares = 20 points

    def test_calculate_calendar_risk_score_combined(self, calendar_scanner):
        """Test risk score calculation with multiple factors."""
        calendar = CalendarInfo(
            calendar_id="cal1",
            summary="Risky Calendar",
            is_public=True,
            external_shares=["external1@other.com", "external2@other.com"],
        )

        score = calendar_scanner._calculate_calendar_risk_score(calendar)

        assert score == 70  # Public (50) + 2 external shares (20)

    def test_parse_event(self, calendar_scanner):
        """Test parsing event from API response."""
        event_data = {
            "id": "event1",
            "summary": "Team Meeting",
            "description": "Discuss project",
            "attendees": [
                {"email": "user1@example.com"},
                {"email": "external@other.com"},
            ],
        }

        event = calendar_scanner._parse_event(event_data, "cal1")

        assert event.event_id == "event1"
        assert event.summary == "Team Meeting"
        assert len(event.attendees) == 2
        assert len(event.external_attendees) == 1
        assert "external@other.com" in event.external_attendees

    def test_generate_issues_public_calendar(self, calendar_scanner):
        """Test issue generation for public calendar."""
        from vaulytica.core.scanners.calendar_scanner import CalendarScanResult

        result = CalendarScanResult()
        result.calendars = [
            CalendarInfo(
                calendar_id="cal1",
                summary="Public Calendar",
                owner_email="user@example.com",
                is_public=True,
                risk_score=50,
            )
        ]

        issues = calendar_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "public_calendar"
        assert issues[0]["severity"] == "high"

    def test_generate_issues_external_shares(self, calendar_scanner):
        """Test issue generation for external shares."""
        from vaulytica.core.scanners.calendar_scanner import CalendarScanResult

        result = CalendarScanResult()
        result.calendars = [
            CalendarInfo(
                calendar_id="cal1",
                summary="Shared Calendar",
                owner_email="user@example.com",
                external_shares=["external@other.com"],
                risk_score=10,
            )
        ]

        issues = calendar_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "external_calendar_share"
        assert issues[0]["severity"] == "medium"

    def test_generate_issues_pii_in_events(self, calendar_scanner):
        """Test issue generation for PII in events."""
        from vaulytica.core.scanners.calendar_scanner import CalendarScanResult

        result = CalendarScanResult()
        result.events_with_pii_list = [
            CalendarEvent(
                event_id="event1",
                calendar_id="cal1",
                summary="Meeting with SSN",
                pii_types=["ssn"],
                has_pii=True,
            )
        ]

        issues = calendar_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "pii_in_calendar_event"
        assert issues[0]["severity"] == "high"
        assert "ssn" in issues[0]["pii_types"]

    def test_generate_issues_multiple(self, calendar_scanner):
        """Test issue generation with multiple issues."""
        from vaulytica.core.scanners.calendar_scanner import CalendarScanResult

        result = CalendarScanResult()
        result.calendars = [
            CalendarInfo(
                calendar_id="cal1",
                summary="Public Calendar",
                owner_email="user@example.com",
                is_public=True,
                risk_score=50,
            ),
            CalendarInfo(
                calendar_id="cal2",
                summary="Shared Calendar",
                owner_email="user@example.com",
                external_shares=["external@other.com"],
                risk_score=10,
            ),
        ]

        issues = calendar_scanner._generate_issues(result)

        assert len(issues) == 2

    def test_calculate_statistics(self, calendar_scanner):
        """Test statistics calculation."""
        from vaulytica.core.scanners.calendar_scanner import CalendarScanResult

        result = CalendarScanResult(
            total_calendars=10,
            public_calendars=2,
            calendars_with_external_shares=3,
            total_events_scanned=100,
            events_with_pii=5,
        )
        result.issues = [{"type": "test"}] * 5

        stats = calendar_scanner._calculate_statistics(result)

        assert stats["total_calendars"] == 10
        assert stats["public_calendars"] == 2
        assert stats["calendars_with_external_shares"] == 3
        assert stats["total_events_scanned"] == 100
        assert stats["events_with_pii"] == 5
        assert stats["total_issues"] == 5

    def test_get_calendar_details(self, calendar_scanner, mock_client):
        """Test getting calendar details."""
        # Mock calendar API responses
        mock_client.calendar.calendars().get().execute.return_value = {
            "id": "cal1",
            "summary": "Test Calendar",
            "description": "Test description",
        }

        mock_client.calendar.acl().list().execute.return_value = {
            "items": [
                {
                    "scope": {"type": "user", "value": "user@example.com"},
                    "role": "owner",
                },
                {
                    "scope": {"type": "user", "value": "external@other.com"},
                    "role": "reader",
                },
                {
                    "scope": {"type": "default"},
                    "role": "reader",
                },
            ]
        }

        calendar = calendar_scanner._get_calendar_details("cal1", "user@example.com")

        assert calendar.calendar_id == "cal1"
        assert calendar.summary == "Test Calendar"
        assert calendar.is_public is True  # Has default scope
        assert len(calendar.external_shares) == 1
        assert "external@other.com" in calendar.external_shares

    def test_scan_calendar_events_with_pii(self, calendar_scanner, mock_client):
        """Test scanning calendar events with PII detection."""
        from vaulytica.core.detectors.pii_detector import PIIMatch, PIIType

        # Create scanner with PII detector
        pii_detector = Mock()
        calendar_scanner.pii_detector = pii_detector

        # Mock events API response
        mock_client.calendar.events().list().execute.return_value = {
            "items": [
                {
                    "id": "event1",
                    "summary": "Meeting with SSN 123-45-6789",
                    "description": "Discuss sensitive data",
                }
            ]
        }

        # Mock PII detection
        pii_detector.detect_pii.return_value = [
            PIIMatch(
                pii_type=PIIType.SSN,
                value="123-45-6789",
                start_pos=17,
                end_pos=28,
                confidence=0.95,
            )
        ]

        events = calendar_scanner._scan_calendar_events("cal1", "user@example.com", 30)

        assert len(events) == 1
        assert events[0].has_pii is True
        assert PIIType.SSN in events[0].pii_types

