"""Tests for user management API endpoints."""

import pytest
from fastapi.testclient import TestClient

from backend.db.models import User, UserDomain
from backend.auth.security import get_password_hash


class TestUserList:
    """Tests for user listing endpoint."""

    def test_list_users_as_superuser(self, client: TestClient, db_session, superuser_token):
        """Superusers can list all users."""
        # Create some test users
        for i in range(3):
            user = User(
                email=f"testuser{i}@example.com",
                hashed_password=get_password_hash("password123"),
                full_name=f"Test User {i}",
                is_active=True,
            )
            db_session.add(user)
        db_session.commit()

        response = client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert data["total"] >= 3  # At least our 3 test users + superuser

    def test_list_users_with_pagination(self, client: TestClient, db_session, superuser_token):
        """Test pagination of user list."""
        # Create 10 test users
        for i in range(10):
            user = User(
                email=f"pageuser{i}@example.com",
                hashed_password=get_password_hash("password123"),
                full_name=f"Page User {i}",
                is_active=True,
            )
            db_session.add(user)
        db_session.commit()

        response = client.get(
            "/api/users?page=1&page_size=5",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) <= 5
        assert data["page"] == 1
        assert data["page_size"] == 5

    def test_list_users_with_search(self, client: TestClient, db_session, superuser_token):
        """Test searching users by email or name."""
        user = User(
            email="searchable@unique.com",
            hashed_password=get_password_hash("password123"),
            full_name="Unique Searchable Name",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()

        response = client.get(
            "/api/users?search=searchable",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        emails = [u["email"] for u in data["items"]]
        assert "searchable@unique.com" in emails

    def test_list_users_filter_by_active(self, client: TestClient, db_session, superuser_token):
        """Test filtering users by active status."""
        inactive_user = User(
            email="inactive@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Inactive User",
            is_active=False,
        )
        db_session.add(inactive_user)
        db_session.commit()

        response = client.get(
            "/api/users?is_active=false",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        for user in data["items"]:
            assert user["is_active"] is False

    def test_list_users_unauthorized(self, client: TestClient, regular_user_token):
        """Regular users cannot list all users."""
        response = client.get(
            "/api/users",
            headers={"Authorization": f"Bearer {regular_user_token}"},
        )
        assert response.status_code == 403


class TestGetUser:
    """Tests for getting a specific user."""

    def test_get_user_by_id(self, client: TestClient, db_session, superuser_token):
        """Superusers can get a user by ID."""
        user = User(
            email="getme@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Get Me User",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.get(
            f"/api/users/{user.id}",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "getme@example.com"
        assert data["full_name"] == "Get Me User"

    def test_get_nonexistent_user(self, client: TestClient, superuser_token):
        """Getting a nonexistent user returns 404."""
        response = client.get(
            "/api/users/99999",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 404


class TestUpdateUser:
    """Tests for updating users."""

    def test_update_user_email(self, client: TestClient, db_session, superuser_token):
        """Superusers can update a user's email."""
        user = User(
            email="oldemail@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Update Me",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.patch(
            f"/api/users/{user.id}",
            json={"email": "newemail@example.com"},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "newemail@example.com"

    def test_update_user_full_name(self, client: TestClient, db_session, superuser_token):
        """Superusers can update a user's full name."""
        user = User(
            email="updatename@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Old Name",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.patch(
            f"/api/users/{user.id}",
            json={"full_name": "New Name"},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["full_name"] == "New Name"

    def test_update_user_is_active(self, client: TestClient, db_session, superuser_token):
        """Superusers can deactivate a user."""
        user = User(
            email="deactivate@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Deactivate Me",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.patch(
            f"/api/users/{user.id}",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False

    def test_update_user_is_superuser(self, client: TestClient, db_session, superuser_token):
        """Superusers can promote a user to superuser."""
        user = User(
            email="promote@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Promote Me",
            is_active=True,
            is_superuser=False,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.patch(
            f"/api/users/{user.id}",
            json={"is_superuser": True},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_superuser"] is True

    def test_cannot_self_demote(self, client: TestClient, db_session, superuser_token, superuser):
        """Superusers cannot remove their own superuser status."""
        response = client.patch(
            f"/api/users/{superuser.id}",
            json={"is_superuser": False},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 400
        assert "own superuser status" in response.json()["detail"]

    def test_cannot_self_deactivate(self, client: TestClient, db_session, superuser_token, superuser):
        """Superusers cannot deactivate their own account."""
        response = client.patch(
            f"/api/users/{superuser.id}",
            json={"is_active": False},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 400
        assert "own account" in response.json()["detail"]

    def test_update_email_already_taken(self, client: TestClient, db_session, superuser_token):
        """Cannot update email to one that's already taken."""
        user1 = User(
            email="user1@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        user2 = User(
            email="user2@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add_all([user1, user2])
        db_session.commit()
        db_session.refresh(user1)

        response = client.patch(
            f"/api/users/{user1.id}",
            json={"email": "user2@example.com"},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 400
        assert "already in use" in response.json()["detail"]

    def test_update_nonexistent_user(self, client: TestClient, superuser_token):
        """Updating a nonexistent user returns 404."""
        response = client.patch(
            "/api/users/99999",
            json={"full_name": "New Name"},
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 404


class TestDeleteUser:
    """Tests for deleting users."""

    def test_delete_user(self, client: TestClient, db_session, superuser_token):
        """Superusers can delete a user."""
        user = User(
            email="deleteme@example.com",
            hashed_password=get_password_hash("password123"),
            full_name="Delete Me",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        user_id = user.id

        response = client.delete(
            f"/api/users/{user_id}",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 204

        # Verify user is deleted
        deleted_user = db_session.query(User).filter(User.id == user_id).first()
        assert deleted_user is None

    def test_delete_user_with_domains(self, client: TestClient, db_session, superuser_token):
        """Deleting a user also removes their domain associations."""
        user = User(
            email="userdomains@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Add domain access
        user_domain = UserDomain(user_id=user.id, domain="example.com", role="viewer")
        db_session.add(user_domain)
        db_session.commit()

        user_id = user.id
        response = client.delete(
            f"/api/users/{user_id}",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 204

        # Verify domain association is deleted
        domain_assoc = db_session.query(UserDomain).filter(UserDomain.user_id == user_id).first()
        assert domain_assoc is None

    def test_cannot_self_delete(self, client: TestClient, superuser_token, superuser):
        """Superusers cannot delete their own account."""
        response = client.delete(
            f"/api/users/{superuser.id}",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 400
        assert "own account" in response.json()["detail"]

    def test_delete_nonexistent_user(self, client: TestClient, superuser_token):
        """Deleting a nonexistent user returns 404."""
        response = client.delete(
            "/api/users/99999",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 404


class TestActivateDeactivate:
    """Tests for activate/deactivate endpoints."""

    def test_deactivate_user(self, client: TestClient, db_session, superuser_token):
        """Superusers can deactivate a user."""
        user = User(
            email="tobedeactivated@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.post(
            f"/api/users/{user.id}/deactivate",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is False

    def test_activate_user(self, client: TestClient, db_session, superuser_token):
        """Superusers can activate a deactivated user."""
        user = User(
            email="tobeactivated@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=False,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.post(
            f"/api/users/{user.id}/activate",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_active"] is True

    def test_activate_already_active(self, client: TestClient, db_session, superuser_token):
        """Activating an already active user returns 400."""
        user = User(
            email="alreadyactive@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.post(
            f"/api/users/{user.id}/activate",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 400
        assert "already active" in response.json()["detail"]

    def test_deactivate_already_inactive(self, client: TestClient, db_session, superuser_token):
        """Deactivating an already inactive user returns 400."""
        user = User(
            email="alreadyinactive@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=False,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.post(
            f"/api/users/{user.id}/deactivate",
            headers={"Authorization": f"Bearer {superuser_token}"},
        )
        assert response.status_code == 400
        assert "already deactivated" in response.json()["detail"]
