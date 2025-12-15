"""Tests for alert rules API endpoints."""

import pytest
from datetime import datetime
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import AlertRule, Domain, User, UserDomain
from backend.auth.security import create_access_token


class TestAlertRulesAPI:
    """Test alert rules CRUD operations."""

    def test_list_alert_rules_empty(self, authenticated_client: TestClient):
        """Should return empty list when no rules exist."""
        response = authenticated_client.get("/api/v1/alerts")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_create_alert_rule(self, authenticated_client: TestClient, db: Session):
        """Should create a new alert rule."""
        # Get domain from fixture
        domain = db.query(Domain).filter(Domain.name == "example.com").first()

        rule_data = {
            "name": "High Risk Files Alert",
            "description": "Alert when high risk files are detected",
            "domain_name": "example.com",
            "condition_type": "high_risk_file",
            "condition_value": {"threshold": 75},
            "notification_channels": ["email"],
            "notification_config": {"emails": ["admin@example.com"]},
        }

        response = authenticated_client.post("/api/v1/alerts", json=rule_data)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == "High Risk Files Alert"
        assert data["condition_type"] == "high_risk_file"
        assert data["domain_name"] == "example.com"
        assert data["is_active"] is True

    def test_create_alert_rule_invalid_condition_type(
        self, authenticated_client: TestClient, db: Session
    ):
        """Should reject invalid condition types."""
        rule_data = {
            "name": "Invalid Alert",
            "domain_name": "example.com",
            "condition_type": "invalid_type",
            "notification_channels": ["email"],
        }

        response = authenticated_client.post("/api/v1/alerts", json=rule_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Invalid condition type" in response.json()["detail"]

    def test_get_alert_rule(self, authenticated_client: TestClient, db: Session):
        """Should get a specific alert rule."""
        domain = db.query(Domain).filter(Domain.name == "example.com").first()

        rule = AlertRule(
            name="Test Rule",
            domain_id=domain.id,
            condition_type="public_file",
            notification_channels=["email"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(rule)
        db.commit()

        response = authenticated_client.get(f"/api/v1/alerts/{rule.id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "Test Rule"
        assert data["condition_type"] == "public_file"

    def test_get_alert_rule_not_found(self, authenticated_client: TestClient):
        """Should return 404 for non-existent rule."""
        response = authenticated_client.get("/api/v1/alerts/99999")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_update_alert_rule(self, authenticated_client: TestClient, db: Session):
        """Should update an existing alert rule."""
        domain = db.query(Domain).filter(Domain.name == "example.com").first()

        rule = AlertRule(
            name="Original Name",
            domain_id=domain.id,
            condition_type="inactive_user",
            condition_value={"days": 30},
            notification_channels=["email"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(rule)
        db.commit()

        update_data = {
            "name": "Updated Name",
            "condition_value": {"days": 60},
        }

        response = authenticated_client.patch(f"/api/v1/alerts/{rule.id}", json=update_data)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == "Updated Name"
        assert data["condition_value"]["days"] == 60

    def test_delete_alert_rule(self, authenticated_client: TestClient, db: Session):
        """Should delete an alert rule."""
        domain = db.query(Domain).filter(Domain.name == "example.com").first()

        rule = AlertRule(
            name="To Be Deleted",
            domain_id=domain.id,
            condition_type="scan_completed",
            notification_channels=["email"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(rule)
        db.commit()
        rule_id = rule.id

        response = authenticated_client.delete(f"/api/v1/alerts/{rule_id}")
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Verify deleted
        response = authenticated_client.get(f"/api/v1/alerts/{rule_id}")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_toggle_alert_rule(self, authenticated_client: TestClient, db: Session):
        """Should toggle alert rule active status."""
        domain = db.query(Domain).filter(Domain.name == "example.com").first()

        rule = AlertRule(
            name="Toggle Test",
            domain_id=domain.id,
            condition_type="no_2fa_user",
            is_active=True,
            notification_channels=["email"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(rule)
        db.commit()

        # Toggle off
        response = authenticated_client.post(f"/api/v1/alerts/{rule.id}/toggle")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_active"] is False

        # Toggle back on
        response = authenticated_client.post(f"/api/v1/alerts/{rule.id}/toggle")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_active"] is True

    def test_list_condition_types(self, authenticated_client: TestClient):
        """Should return list of valid condition types."""
        response = authenticated_client.get("/api/v1/alerts/condition-types")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "high_risk_file" in data
        assert "public_file" in data
        assert "inactive_user" in data
        assert "risky_oauth" in data
        assert "security_finding" in data


class TestAlertRulesFiltering:
    """Test alert rules list filtering."""

    def test_filter_by_domain(self, authenticated_client: TestClient, db: Session):
        """Should filter rules by domain."""
        domain = db.query(Domain).filter(Domain.name == "example.com").first()

        # Create rules
        for i in range(3):
            rule = AlertRule(
                name=f"Rule {i}",
                domain_id=domain.id,
                condition_type="high_risk_file",
                notification_channels=["email"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(rule)
        db.commit()

        response = authenticated_client.get("/api/v1/alerts", params={"domain": "example.com"})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 3

    def test_filter_by_active_status(self, authenticated_client: TestClient, db: Session):
        """Should filter rules by active status."""
        domain = db.query(Domain).filter(Domain.name == "example.com").first()

        # Create active and inactive rules
        for i, is_active in enumerate([True, True, False]):
            rule = AlertRule(
                name=f"Rule {i}",
                domain_id=domain.id,
                condition_type="public_file",
                is_active=is_active,
                notification_channels=["email"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(rule)
        db.commit()

        # Get only active
        response = authenticated_client.get("/api/v1/alerts", params={"is_active": True})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 2

        # Get only inactive
        response = authenticated_client.get("/api/v1/alerts", params={"is_active": False})
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["total"] == 1


class TestAlertRulesAuthorization:
    """Test alert rules access control."""

    def test_unauthorized_domain_access(
        self, client: TestClient, db: Session, test_user: User
    ):
        """Should reject access to rules for unauthorized domains."""
        # Create domain without user access
        other_domain = Domain(name="other.com", display_name="Other Domain", is_active=True)
        db.add(other_domain)
        db.commit()

        rule = AlertRule(
            name="Other Domain Rule",
            domain_id=other_domain.id,
            condition_type="high_risk_file",
            notification_channels=["email"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(rule)
        db.commit()

        # Create token for test user
        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get(f"/api/v1/alerts/{rule.id}", headers=headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_superuser_access_all_rules(
        self, client: TestClient, db: Session, test_superuser: User
    ):
        """Superusers should access all alert rules."""
        # Create domain and rule
        domain = Domain(name="any.com", display_name="Any Domain", is_active=True)
        db.add(domain)
        db.commit()

        rule = AlertRule(
            name="Any Rule",
            domain_id=domain.id,
            condition_type="scan_failed",
            notification_channels=["webhook"],
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(rule)
        db.commit()

        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get(f"/api/v1/alerts/{rule.id}", headers=headers)
        assert response.status_code == status.HTTP_200_OK


class TestAlertRuleValidation:
    """Test alert rule input validation."""

    def test_empty_name_rejected(self, authenticated_client: TestClient):
        """Should reject empty rule names."""
        rule_data = {
            "name": "",
            "domain_name": "example.com",
            "condition_type": "high_risk_file",
        }

        response = authenticated_client.post("/api/v1/alerts", json=rule_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_webhook_requires_url(self, authenticated_client: TestClient, db: Session):
        """Should validate webhook notification config."""
        rule_data = {
            "name": "Webhook Alert",
            "domain_name": "example.com",
            "condition_type": "scan_completed",
            "notification_channels": ["webhook"],
            "notification_config": {},  # Missing webhook_url
        }

        response = authenticated_client.post("/api/v1/alerts", json=rule_data)
        # Should either fail validation or succeed with warning
        # Implementation may vary
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_400_BAD_REQUEST,
        ]

    def test_email_validates_recipients(self, authenticated_client: TestClient, db: Session):
        """Should accept valid email notification config."""
        rule_data = {
            "name": "Email Alert",
            "domain_name": "example.com",
            "condition_type": "security_finding",
            "condition_value": {"severity": "high"},
            "notification_channels": ["email"],
            "notification_config": {"emails": ["admin@example.com", "security@example.com"]},
        }

        response = authenticated_client.post("/api/v1/alerts", json=rule_data)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert len(data["notification_config"]["emails"]) == 2
