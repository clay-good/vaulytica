"""Tests for domain management API endpoints."""

import pytest
from datetime import datetime
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.models import User, Domain, UserDomain
from backend.auth.security import create_access_token


class TestListDomains:
    """Test domain listing endpoint."""

    def test_list_domains_empty(self, authenticated_client: TestClient):
        """Should return list with only user's accessible domains."""
        response = authenticated_client.get("/api/v1/domains/")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # authenticated_client fixture creates example.com domain
        assert len(data) >= 1

    def test_list_domains_user_sees_own_domains(
        self, client: TestClient, db: Session, test_user: User, test_domain: Domain
    ):
        """User should only see domains they have access to."""
        # Give user access to test domain
        user_domain = UserDomain(
            user_id=test_user.id,
            domain=test_domain.name,
            role="viewer",
        )
        db.add(user_domain)
        db.commit()

        # Create another domain without access
        other_domain = Domain(
            name="other.com",
            display_name="Other Domain",
            is_active=True,
        )
        db.add(other_domain)
        db.commit()

        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/domains/", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()

        domain_names = [d["name"] for d in data]
        assert test_domain.name in domain_names
        assert "other.com" not in domain_names

    def test_list_domains_superuser_sees_all(
        self, client: TestClient, db: Session, test_superuser: User
    ):
        """Superuser should see all active domains."""
        # Create multiple domains
        for name in ["domain1.com", "domain2.com", "domain3.com"]:
            domain = Domain(name=name, display_name=name, is_active=True)
            db.add(domain)
        db.commit()

        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/domains/", headers=headers)
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) >= 3


class TestCreateDomain:
    """Test domain creation endpoint."""

    def test_create_domain_superuser(
        self, client: TestClient, db: Session, test_superuser: User
    ):
        """Superuser should be able to create domains."""
        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        domain_data = {
            "name": "newdomain.com",
            "display_name": "New Domain",
            "admin_email": "admin@newdomain.com",
        }

        response = client.post("/api/v1/domains/", headers=headers, json=domain_data)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["name"] == "newdomain.com"
        assert data["display_name"] == "New Domain"
        assert data["is_active"] is True

    def test_create_domain_regular_user_forbidden(
        self, client: TestClient, db: Session, test_user: User
    ):
        """Regular users should not be able to create domains."""
        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        domain_data = {
            "name": "forbidden.com",
            "display_name": "Forbidden Domain",
        }

        response = client.post("/api/v1/domains/", headers=headers, json=domain_data)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_create_duplicate_domain_rejected(
        self, client: TestClient, db: Session, test_superuser: User, test_domain: Domain
    ):
        """Should reject duplicate domain names."""
        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        domain_data = {
            "name": test_domain.name,  # Already exists
            "display_name": "Duplicate",
        }

        response = client.post("/api/v1/domains/", headers=headers, json=domain_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in response.json()["detail"]


class TestGetDomain:
    """Test get single domain endpoint."""

    def test_get_domain_with_access(
        self, authenticated_client: TestClient, db: Session, test_domain: Domain
    ):
        """Should return domain details for authorized user."""
        response = authenticated_client.get(f"/api/v1/domains/{test_domain.name}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["name"] == test_domain.name

    def test_get_domain_not_found(self, authenticated_client: TestClient):
        """Should return 404 for non-existent domain."""
        response = authenticated_client.get("/api/v1/domains/nonexistent.com")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_domain_forbidden(
        self, client: TestClient, db: Session, test_user: User
    ):
        """Should reject access to unauthorized domains."""
        # Create domain without user access
        other_domain = Domain(
            name="private.com",
            display_name="Private Domain",
            is_active=True,
        )
        db.add(other_domain)
        db.commit()

        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        response = client.get("/api/v1/domains/private.com", headers=headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestUpdateDomain:
    """Test domain update endpoint."""

    def test_update_domain_superuser(
        self, client: TestClient, db: Session, test_superuser: User, test_domain: Domain
    ):
        """Superuser should be able to update domains."""
        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        update_data = {
            "name": test_domain.name,
            "display_name": "Updated Display Name",
            "admin_email": "new-admin@example.com",
        }

        response = client.put(
            f"/api/v1/domains/{test_domain.name}",
            headers=headers,
            json=update_data,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["display_name"] == "Updated Display Name"

    def test_update_domain_regular_user_forbidden(
        self, client: TestClient, db: Session, test_user: User, test_domain: Domain
    ):
        """Regular users should not be able to update domains."""
        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        update_data = {
            "name": test_domain.name,
            "display_name": "Hacked",
        }

        response = client.put(
            f"/api/v1/domains/{test_domain.name}",
            headers=headers,
            json=update_data,
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_update_nonexistent_domain(
        self, client: TestClient, db: Session, test_superuser: User
    ):
        """Should return 404 for non-existent domain."""
        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        update_data = {
            "name": "ghost.com",
            "display_name": "Ghost",
        }

        response = client.put(
            "/api/v1/domains/ghost.com",
            headers=headers,
            json=update_data,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestDeleteDomain:
    """Test domain deletion endpoint."""

    def test_delete_domain_superuser(
        self, client: TestClient, db: Session, test_superuser: User
    ):
        """Superuser should be able to delete (deactivate) domains."""
        # Create a domain to delete
        domain = Domain(
            name="todelete.com",
            display_name="To Delete",
            is_active=True,
        )
        db.add(domain)
        db.commit()

        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        response = client.delete("/api/v1/domains/todelete.com", headers=headers)
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_204_NO_CONTENT]

        # Verify domain is deactivated
        db.refresh(domain)
        assert domain.is_active is False

    def test_delete_domain_regular_user_forbidden(
        self, client: TestClient, db: Session, test_user: User, test_domain: Domain
    ):
        """Regular users should not be able to delete domains."""
        token = create_access_token(data={"sub": test_user.email, "user_id": test_user.id})
        headers = {"Authorization": f"Bearer {token}"}

        response = client.delete(f"/api/v1/domains/{test_domain.name}", headers=headers)
        assert response.status_code == status.HTTP_403_FORBIDDEN


class TestDomainCredentials:
    """Test domain credentials management."""

    def test_update_credentials_path(
        self, client: TestClient, db: Session, test_superuser: User, test_domain: Domain
    ):
        """Should be able to update credentials path."""
        token = create_access_token(
            data={"sub": test_superuser.email, "user_id": test_superuser.id}
        )
        headers = {"Authorization": f"Bearer {token}"}

        update_data = {
            "name": test_domain.name,
            "display_name": test_domain.display_name,
            "credentials_path": "/new/path/to/credentials.json",
        }

        response = client.put(
            f"/api/v1/domains/{test_domain.name}",
            headers=headers,
            json=update_data,
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify update
        db.refresh(test_domain)
        assert test_domain.credentials_path == "/new/path/to/credentials.json"
