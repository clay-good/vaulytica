"""Tests for scheduled scans API endpoints."""

import pytest
from datetime import datetime, timedelta
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import User, Domain, ScheduledScan, UserDomain
from backend.auth.security import create_access_token
from backend.api.schedules import calculate_next_run


class TestCalculateNextRun:
    """Test next run calculation utility."""

    def test_hourly_schedule(self):
        """Hourly should be ~1 hour from now."""
        next_run = calculate_next_run("hourly")
        expected = datetime.utcnow() + timedelta(hours=1)
        assert abs((next_run - expected).total_seconds()) < 5

    def test_daily_schedule(self):
        """Daily should be at specified hour next day."""
        next_run = calculate_next_run("daily", {"hour": 3})
        assert next_run.hour == 3
        assert next_run.minute == 0

    def test_weekly_schedule(self):
        """Weekly should be on specified day of week."""
        next_run = calculate_next_run("weekly", {"day_of_week": 0, "hour": 2})
        assert next_run.weekday() == 0  # Monday
        assert next_run.hour == 2

    def test_monthly_schedule(self):
        """Monthly should be on specified day of month."""
        next_run = calculate_next_run("monthly", {"day": 15, "hour": 4})
        assert next_run.day == 15
        assert next_run.hour == 4


class TestListScheduledScans:
    """Test scheduled scans listing endpoint."""

    def test_list_schedules_empty(self, authenticated_client: TestClient):
        """Should return empty list when no schedules exist."""
        response = authenticated_client.get("/api/v1/schedules")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data == []

    def test_list_schedules_with_data(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should return list of scheduled scans."""
        schedule = ScheduledScan(
            name="Daily Posture Scan",
            domain_id=test_domain.id,
            scan_type="posture",
            schedule_type="daily",
            schedule_config={"hour": 2},
            is_active=True,
            next_run=datetime.utcnow() + timedelta(days=1),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()

        response = authenticated_client.get("/api/v1/schedules")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]["name"] == "Daily Posture Scan"

    def test_list_schedules_filter_by_domain(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should filter schedules by domain."""
        schedule = ScheduledScan(
            name="Domain Scan",
            domain_id=test_domain.id,
            scan_type="files",
            schedule_type="weekly",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()

        response = authenticated_client.get(
            "/api/v1/schedules",
            params={"domain": test_domain.name},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1

    def test_list_schedules_filter_by_active(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should filter schedules by active status."""
        # Create active and inactive schedules
        for is_active in [True, False]:
            schedule = ScheduledScan(
                name=f"{'Active' if is_active else 'Inactive'} Scan",
                domain_id=test_domain.id,
                scan_type="users",
                schedule_type="monthly",
                is_active=is_active,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(schedule)
        db.commit()

        # Get only active
        response = authenticated_client.get(
            "/api/v1/schedules",
            params={"is_active": True},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]["is_active"] is True


class TestCreateScheduledScan:
    """Test scheduled scan creation endpoint."""

    def test_create_schedule(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should create a new scheduled scan."""
        schedule_data = {
            "name": "New Weekly Scan",
            "domain_name": test_domain.name,
            "scan_type": "all",
            "schedule_type": "weekly",
            "schedule_config": {"day_of_week": 1, "hour": 3},
            "is_active": True,
        }

        response = authenticated_client.post("/api/v1/schedules", json=schedule_data)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == "New Weekly Scan"
        assert data["scan_type"] == "all"
        assert data["schedule_type"] == "weekly"
        assert data["next_run"] is not None

    def test_create_schedule_invalid_scan_type(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should reject invalid scan types."""
        schedule_data = {
            "name": "Invalid Scan",
            "domain_name": test_domain.name,
            "scan_type": "invalid_type",
            "schedule_type": "daily",
        }

        response = authenticated_client.post("/api/v1/schedules", json=schedule_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_create_schedule_invalid_schedule_type(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should reject invalid schedule types."""
        schedule_data = {
            "name": "Invalid Schedule",
            "domain_name": test_domain.name,
            "scan_type": "posture",
            "schedule_type": "every_minute",  # Invalid
        }

        response = authenticated_client.post("/api/v1/schedules", json=schedule_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_create_schedule_unauthorized_domain(
        self, client: TestClient, db: Session, test_user: User
    ):
        """Should reject schedule creation for unauthorized domains."""
        # Create domain without user access
        other_domain = Domain(
            name="noaccess.com",
            display_name="No Access",
            is_active=True,
        )
        db.add(other_domain)
        db.commit()

        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        schedule_data = {
            "name": "Unauthorized Scan",
            "domain_name": "noaccess.com",
            "scan_type": "posture",
            "schedule_type": "daily",
        }

        response = client.post("/api/v1/schedules", headers=headers, json=schedule_data)
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestGetScheduledScan:
    """Test get single scheduled scan endpoint."""

    def test_get_schedule(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should return schedule details."""
        schedule = ScheduledScan(
            name="Test Schedule",
            domain_id=test_domain.id,
            scan_type="oauth",
            schedule_type="hourly",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()

        response = authenticated_client.get(f"/api/v1/schedules/{schedule.id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "Test Schedule"
        assert data["scan_type"] == "oauth"

    def test_get_schedule_not_found(self, authenticated_client: TestClient):
        """Should return 404 for non-existent schedule."""
        response = authenticated_client.get("/api/v1/schedules/99999")
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestUpdateScheduledScan:
    """Test scheduled scan update endpoint."""

    def test_update_schedule(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should update scheduled scan."""
        schedule = ScheduledScan(
            name="Original Name",
            domain_id=test_domain.id,
            scan_type="files",
            schedule_type="daily",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()

        update_data = {
            "name": "Updated Name",
            "is_active": False,
        }

        response = authenticated_client.patch(
            f"/api/v1/schedules/{schedule.id}",
            json=update_data,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "Updated Name"
        assert data["is_active"] is False

    def test_update_schedule_type_recalculates_next_run(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Changing schedule type should recalculate next_run."""
        schedule = ScheduledScan(
            name="Schedule",
            domain_id=test_domain.id,
            scan_type="posture",
            schedule_type="daily",
            next_run=datetime.utcnow() + timedelta(days=1),
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()
        old_next_run = schedule.next_run

        update_data = {
            "schedule_type": "hourly",
        }

        response = authenticated_client.patch(
            f"/api/v1/schedules/{schedule.id}",
            json=update_data,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Next run should be different (sooner for hourly)
        new_next_run = datetime.fromisoformat(data["next_run"].replace("Z", "+00:00"))
        assert new_next_run != old_next_run


class TestDeleteScheduledScan:
    """Test scheduled scan deletion endpoint."""

    def test_delete_schedule(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should delete scheduled scan."""
        schedule = ScheduledScan(
            name="To Delete",
            domain_id=test_domain.id,
            scan_type="users",
            schedule_type="weekly",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()
        schedule_id = schedule.id

        response = authenticated_client.delete(f"/api/v1/schedules/{schedule_id}")
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify deletion
        response = authenticated_client.get(f"/api/v1/schedules/{schedule_id}")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_schedule_not_found(self, authenticated_client: TestClient):
        """Should return 404 for non-existent schedule."""
        response = authenticated_client.delete("/api/v1/schedules/99999")
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestToggleScheduledScan:
    """Test schedule toggle endpoint."""

    def test_toggle_schedule_off(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should toggle schedule from active to inactive."""
        schedule = ScheduledScan(
            name="Toggle Test",
            domain_id=test_domain.id,
            scan_type="posture",
            schedule_type="daily",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()

        response = authenticated_client.post(f"/api/v1/schedules/{schedule.id}/toggle")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_active"] is False

    def test_toggle_schedule_on(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should toggle schedule from inactive to active."""
        schedule = ScheduledScan(
            name="Toggle Test",
            domain_id=test_domain.id,
            scan_type="files",
            schedule_type="monthly",
            is_active=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()

        response = authenticated_client.post(f"/api/v1/schedules/{schedule.id}/toggle")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_active"] is True
        # Should also set next_run when activating
        assert data["next_run"] is not None


class TestRunScheduledScanNow:
    """Test run schedule now endpoint."""

    def test_run_now_triggers_scan(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should trigger immediate scan execution."""
        schedule = ScheduledScan(
            name="Run Now Test",
            domain_id=test_domain.id,
            scan_type="posture",
            schedule_type="weekly",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule)
        db.commit()

        response = authenticated_client.post(f"/api/v1/schedules/{schedule.id}/run")
        # Should either start scan or return accepted
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_202_ACCEPTED,
        ]


class TestScheduledScanAuthorization:
    """Test schedule access control."""

    def test_user_only_sees_own_domain_schedules(
        self, client: TestClient, db: Session, test_user: User, test_domain: Domain
    ):
        """Users should only see schedules for their domains."""
        # Give user access to test_domain
        user_domain = UserDomain(
            user_id=test_user.id,
            domain=test_domain.name,
            role="admin",
        )
        db.add(user_domain)

        # Create schedule for test_domain
        schedule1 = ScheduledScan(
            name="Visible Schedule",
            domain_id=test_domain.id,
            scan_type="posture",
            schedule_type="daily",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule1)

        # Create another domain and schedule
        other_domain = Domain(name="other.com", display_name="Other", is_active=True)
        db.add(other_domain)
        db.commit()

        schedule2 = ScheduledScan(
            name="Hidden Schedule",
            domain_id=other_domain.id,
            scan_type="files",
            schedule_type="weekly",
            is_active=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(schedule2)
        db.commit()

        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/schedules", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        # Should only see schedule for test_domain
        schedule_names = [s["name"] for s in data]
        assert "Visible Schedule" in schedule_names
        assert "Hidden Schedule" not in schedule_names
