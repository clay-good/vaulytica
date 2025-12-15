"""Tests for audit log API endpoints."""

import pytest
from datetime import datetime, timedelta
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import AuditLog, User
from backend.auth.security import create_access_token


class TestAuditLogAPI:
    """Test audit log retrieval endpoints."""

    def test_list_audit_logs_empty(self, authenticated_client: TestClient):
        """Should return empty list when no logs exist."""
        response = authenticated_client.get("/api/v1/audit")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_list_audit_logs(self, authenticated_client: TestClient, db: Session, test_user: User):
        """Should return paginated audit logs."""
        # Create some audit logs
        for i in range(5):
            log = AuditLog(
                user_id=test_user.id,
                action=f"test_action_{i}",
                resource_type="test",
                resource_id=str(i),
                details={"key": f"value_{i}"},
                created_at=datetime.utcnow() - timedelta(hours=i),
            )
            db.add(log)
        db.commit()

        response = authenticated_client.get("/api/v1/audit")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 5
        assert len(data["items"]) == 5
        # Should be ordered by created_at descending (newest first)
        assert data["items"][0]["action"] == "test_action_0"

    def test_filter_by_action(self, authenticated_client: TestClient, db: Session, test_user: User):
        """Should filter logs by action type."""
        # Create logs with different actions
        for action in ["login", "logout", "scan_triggered", "login"]:
            log = AuditLog(
                user_id=test_user.id,
                action=action,
                resource_type="auth",
                created_at=datetime.utcnow(),
            )
            db.add(log)
        db.commit()

        response = authenticated_client.get("/api/v1/audit", params={"action": "login"})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 2
        for item in data["items"]:
            assert item["action"] == "login"

    def test_filter_by_resource_type(
        self, authenticated_client: TestClient, db: Session, test_user: User
    ):
        """Should filter logs by resource type."""
        for resource_type in ["scan", "finding", "user", "scan"]:
            log = AuditLog(
                user_id=test_user.id,
                action="update",
                resource_type=resource_type,
                created_at=datetime.utcnow(),
            )
            db.add(log)
        db.commit()

        response = authenticated_client.get("/api/v1/audit", params={"resource_type": "scan"})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 2

    def test_filter_by_date_range(
        self, authenticated_client: TestClient, db: Session, test_user: User
    ):
        """Should filter logs by date range."""
        # Create logs across different dates
        now = datetime.utcnow()
        for days_ago in [1, 3, 5, 7, 10]:
            log = AuditLog(
                user_id=test_user.id,
                action="test",
                resource_type="test",
                created_at=now - timedelta(days=days_ago),
            )
            db.add(log)
        db.commit()

        # Filter last 5 days
        start_date = (now - timedelta(days=5)).isoformat()
        response = authenticated_client.get("/api/v1/audit", params={"start_date": start_date})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 3  # 1, 3, 5 days ago

    def test_pagination(self, authenticated_client: TestClient, db: Session, test_user: User):
        """Should paginate results correctly."""
        # Create 25 logs
        for i in range(25):
            log = AuditLog(
                user_id=test_user.id,
                action=f"action_{i}",
                resource_type="test",
                created_at=datetime.utcnow() - timedelta(minutes=i),
            )
            db.add(log)
        db.commit()

        # First page
        response = authenticated_client.get("/api/v1/audit", params={"page": 1, "page_size": 10})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 25
        assert len(data["items"]) == 10
        assert data["page"] == 1
        assert data["total_pages"] == 3

        # Second page
        response = authenticated_client.get("/api/v1/audit", params={"page": 2, "page_size": 10})
        data = response.json()
        assert len(data["items"]) == 10
        assert data["page"] == 2

        # Third page
        response = authenticated_client.get("/api/v1/audit", params={"page": 3, "page_size": 10})
        data = response.json()
        assert len(data["items"]) == 5


class TestAuditLogSummary:
    """Test audit log summary endpoint."""

    def test_audit_summary(self, authenticated_client: TestClient, db: Session, test_user: User):
        """Should return activity summary."""
        # Create diverse audit logs
        actions = ["login", "login", "logout", "scan_triggered", "finding_updated", "login"]
        for action in actions:
            log = AuditLog(
                user_id=test_user.id,
                action=action,
                resource_type="auth" if action in ["login", "logout"] else "scan",
                created_at=datetime.utcnow(),
            )
            db.add(log)
        db.commit()

        response = authenticated_client.get("/api/v1/audit/summary")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total_events"] == 6
        assert "actions" in data
        assert data["actions"].get("login") == 3


class TestAuditLogAccess:
    """Test audit log access control."""

    def test_regular_user_sees_own_logs(
        self, client: TestClient, db: Session, test_user: User, test_superuser: User
    ):
        """Regular users should only see their own audit logs."""
        # Create logs for test_user
        for _ in range(3):
            db.add(AuditLog(
                user_id=test_user.id,
                action="user_action",
                resource_type="test",
                created_at=datetime.utcnow(),
            ))

        # Create logs for superuser
        for _ in range(2):
            db.add(AuditLog(
                user_id=test_superuser.id,
                action="admin_action",
                resource_type="test",
                created_at=datetime.utcnow(),
            ))
        db.commit()

        # Regular user token
        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/audit", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # Regular user sees only their logs
        assert data["total"] == 3
        for item in data["items"]:
            assert item["action"] == "user_action"

    def test_superuser_sees_all_logs(
        self, client: TestClient, db: Session, test_user: User, test_superuser: User
    ):
        """Superusers should see all audit logs."""
        # Create logs for different users
        db.add(AuditLog(
            user_id=test_user.id,
            action="user_action",
            resource_type="test",
            created_at=datetime.utcnow(),
        ))
        db.add(AuditLog(
            user_id=test_superuser.id,
            action="admin_action",
            resource_type="test",
            created_at=datetime.utcnow(),
        ))
        db.commit()

        # Superuser token
        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/audit", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 2

    def test_filter_by_user_id_superuser_only(
        self, client: TestClient, db: Session, test_user: User, test_superuser: User
    ):
        """Only superusers should filter by user_id."""
        db.add(AuditLog(
            user_id=test_user.id,
            action="test",
            resource_type="test",
            created_at=datetime.utcnow(),
        ))
        db.commit()

        # Superuser can filter by user_id
        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get(
            "/api/v1/audit",
            headers=headers,
            params={"user_id": test_user.id},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 1


class TestAuditLogDetails:
    """Test audit log details field."""

    def test_details_stored_correctly(
        self, authenticated_client: TestClient, db: Session, test_user: User
    ):
        """Should store and retrieve details JSON correctly."""
        details = {
            "old_value": "inactive",
            "new_value": "active",
            "changed_fields": ["status", "last_login"],
            "metadata": {"ip": "192.168.1.1", "browser": "Chrome"},
        }

        log = AuditLog(
            user_id=test_user.id,
            action="user_updated",
            resource_type="user",
            resource_id="123",
            details=details,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0 Chrome/120",
            created_at=datetime.utcnow(),
        )
        db.add(log)
        db.commit()

        response = authenticated_client.get("/api/v1/audit")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 1
        item = data["items"][0]
        assert item["details"]["old_value"] == "inactive"
        assert item["details"]["new_value"] == "active"
        assert "changed_fields" in item["details"]
        assert item["ip_address"] == "192.168.1.1"
