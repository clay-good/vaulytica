"""Tests for authentication API."""

import pytest
from fastapi.testclient import TestClient


class TestAuthRoutes:
    """Test authentication routes."""

    def test_login_success(self, client: TestClient, test_user):
        """Test successful login."""
        response = client.post(
            "/api/auth/login",
            data={"username": "test@example.com", "password": "testpassword"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "test@example.com"

    def test_login_wrong_password(self, client: TestClient, test_user):
        """Test login with wrong password."""
        response = client.post(
            "/api/auth/login",
            data={"username": "test@example.com", "password": "wrongpassword"},
        )
        assert response.status_code == 401

    def test_login_nonexistent_user(self, client: TestClient):
        """Test login with nonexistent user."""
        response = client.post(
            "/api/auth/login",
            data={"username": "nonexistent@example.com", "password": "password"},
        )
        assert response.status_code == 401

    def test_register_success(self, client: TestClient):
        """Test successful registration."""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "new@example.com",
                "password": "newpassword123",
                "full_name": "New User",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "new@example.com"
        assert data["full_name"] == "New User"
        assert data["is_active"] is True
        assert data["is_superuser"] is False

    def test_register_duplicate_email(self, client: TestClient, test_user):
        """Test registration with duplicate email."""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "test@example.com",
                "password": "newpassword123",
                "full_name": "Duplicate User",
            },
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]

    def test_register_short_password(self, client: TestClient):
        """Test registration with short password."""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "new@example.com",
                "password": "short",
                "full_name": "New User",
            },
        )
        assert response.status_code == 422  # Validation error

    def test_get_current_user(self, client: TestClient, auth_headers):
        """Test getting current user info."""
        response = client.get("/api/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"

    def test_get_current_user_unauthorized(self, client: TestClient):
        """Test getting current user without auth."""
        response = client.get("/api/auth/me")
        assert response.status_code == 401

    def test_update_current_user(self, client: TestClient, auth_headers):
        """Test updating current user."""
        response = client.put(
            "/api/auth/me",
            headers=auth_headers,
            json={"full_name": "Updated Name"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["full_name"] == "Updated Name"

    def test_change_password(self, client: TestClient, auth_headers):
        """Test changing password."""
        response = client.post(
            "/api/auth/me/change-password",
            headers=auth_headers,
            json={
                "current_password": "testpassword",
                "new_password": "newpassword123",
            },
        )
        assert response.status_code == 200

    def test_change_password_wrong_current(self, client: TestClient, auth_headers):
        """Test changing password with wrong current password."""
        response = client.post(
            "/api/auth/me/change-password",
            headers=auth_headers,
            json={
                "current_password": "wrongpassword",
                "new_password": "newpassword123",
            },
        )
        assert response.status_code == 400


class TestUserManagement:
    """Test user management routes (superuser only)."""

    def test_list_users_as_superuser(self, client: TestClient, superuser_headers, test_user):
        """Test listing users as superuser."""
        response = client.get("/api/auth/users", headers=superuser_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1

    def test_list_users_as_regular_user(self, client: TestClient, auth_headers):
        """Test listing users as regular user (should fail)."""
        response = client.get("/api/auth/users", headers=auth_headers)
        assert response.status_code == 403

    def test_add_user_domain(
        self, client: TestClient, superuser_headers, test_user, test_domain
    ):
        """Test adding domain access to user."""
        response = client.post(
            f"/api/auth/users/{test_user.id}/domains",
            params={"domain": test_domain.name, "role": "admin"},
            headers=superuser_headers,
        )
        assert response.status_code == 200

    def test_remove_user_domain(
        self, client: TestClient, superuser_headers, user_with_domain, test_domain
    ):
        """Test removing domain access from user."""
        response = client.delete(
            f"/api/auth/users/{user_with_domain.id}/domains/{test_domain.name}",
            headers=superuser_headers,
        )
        assert response.status_code == 200
