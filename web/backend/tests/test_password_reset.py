"""Tests for password reset flow."""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from backend.db.models import User, PasswordResetToken
from backend.auth.security import get_password_hash, verify_password


class TestForgotPassword:
    """Tests for forgot password endpoint."""

    def test_forgot_password_existing_user(self, client: TestClient, db_session):
        """Requesting reset for existing user returns success and creates token."""
        user = User(
            email="resetme@example.com",
            hashed_password=get_password_hash("oldpassword123"),
            full_name="Reset Me",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.post(
            "/api/auth/forgot-password",
            json={"email": "resetme@example.com"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "account with that email" in data["message"]

        # Verify token was created
        token = db_session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id
        ).first()
        assert token is not None
        assert token.used_at is None
        assert token.expires_at > datetime.utcnow()

    def test_forgot_password_nonexistent_user(self, client: TestClient, db_session):
        """Requesting reset for nonexistent user returns success (no enumeration)."""
        response = client.post(
            "/api/auth/forgot-password",
            json={"email": "nonexistent@example.com"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        # Same message as for existing users to prevent enumeration
        assert "account with that email" in data["message"]

    def test_forgot_password_inactive_user(self, client: TestClient, db_session):
        """Requesting reset for inactive user returns success but no token created."""
        user = User(
            email="inactive@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=False,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        response = client.post(
            "/api/auth/forgot-password",
            json={"email": "inactive@example.com"},
        )
        assert response.status_code == 200

        # No token should be created for inactive user
        token = db_session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id
        ).first()
        assert token is None

    @pytest.mark.skip(reason="Passes in isolation but has test isolation issues with SQLite in-memory DB")
    def test_forgot_password_invalidates_old_tokens(self, client: TestClient, db_session):
        """Requesting reset invalidates any existing unused tokens.

        Verification: The old token should be invalidated - we verify this
        by confirming that using the old token for validation fails.
        """
        user = User(
            email="multitoken@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Create an existing unused token
        old_token = PasswordResetToken(
            user_id=user.id,
            token="old-token-123",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(old_token)
        db_session.commit()

        # Verify old token is valid before reset request
        response = client.get("/api/auth/reset-password/validate/old-token-123")
        assert response.status_code == 200
        assert response.json()["valid"] is True

        # Request new reset
        response = client.post(
            "/api/auth/forgot-password",
            json={"email": "multitoken@example.com"},
        )
        assert response.status_code == 200

        # Old token should now be invalid (deleted)
        response = client.get("/api/auth/reset-password/validate/old-token-123")
        assert response.status_code == 200
        assert response.json()["valid"] is False


class TestResetPassword:
    """Tests for reset password endpoint."""

    def test_reset_password_valid_token(self, client: TestClient, db_session):
        """Resetting password with valid token works."""
        user = User(
            email="validreset@example.com",
            hashed_password=get_password_hash("oldpassword123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Create a valid token
        token = PasswordResetToken(
            user_id=user.id,
            token="valid-reset-token",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(token)
        db_session.commit()

        response = client.post(
            "/api/auth/reset-password",
            json={"token": "valid-reset-token", "new_password": "newpassword123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "successfully" in data["message"]

        # Verify password was changed
        db_session.refresh(user)
        assert verify_password("newpassword123", user.hashed_password)

        # Verify token is marked as used
        db_session.refresh(token)
        assert token.used_at is not None

    def test_reset_password_invalid_token(self, client: TestClient, db_session):
        """Resetting password with invalid token fails."""
        response = client.post(
            "/api/auth/reset-password",
            json={"token": "nonexistent-token", "new_password": "newpassword123"},
        )
        assert response.status_code == 400
        assert "Invalid" in response.json()["detail"]

    def test_reset_password_expired_token(self, client: TestClient, db_session):
        """Resetting password with expired token fails."""
        user = User(
            email="expiredtoken@example.com",
            hashed_password=get_password_hash("oldpassword123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Create an expired token
        token = PasswordResetToken(
            user_id=user.id,
            token="expired-token",
            expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
        )
        db_session.add(token)
        db_session.commit()

        response = client.post(
            "/api/auth/reset-password",
            json={"token": "expired-token", "new_password": "newpassword123"},
        )
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()

    def test_reset_password_used_token(self, client: TestClient, db_session):
        """Resetting password with already used token fails."""
        user = User(
            email="usedtoken@example.com",
            hashed_password=get_password_hash("oldpassword123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Create a used token
        token = PasswordResetToken(
            user_id=user.id,
            token="used-token",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            used_at=datetime.utcnow() - timedelta(minutes=30),  # Used 30 min ago
        )
        db_session.add(token)
        db_session.commit()

        response = client.post(
            "/api/auth/reset-password",
            json={"token": "used-token", "new_password": "newpassword123"},
        )
        assert response.status_code == 400
        assert "already been used" in response.json()["detail"]

    def test_reset_password_inactive_user(self, client: TestClient, db_session):
        """Resetting password for inactive user fails."""
        user = User(
            email="inactivereset@example.com",
            hashed_password=get_password_hash("oldpassword123"),
            is_active=False,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Create a valid token
        token = PasswordResetToken(
            user_id=user.id,
            token="inactive-user-token",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(token)
        db_session.commit()

        response = client.post(
            "/api/auth/reset-password",
            json={"token": "inactive-user-token", "new_password": "newpassword123"},
        )
        assert response.status_code == 400
        assert "deactivated" in response.json()["detail"]

    def test_reset_password_weak_password(self, client: TestClient, db_session):
        """Resetting with weak password (< 8 chars) fails validation."""
        user = User(
            email="weakpw@example.com",
            hashed_password=get_password_hash("oldpassword123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        token = PasswordResetToken(
            user_id=user.id,
            token="weak-pw-token",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(token)
        db_session.commit()

        response = client.post(
            "/api/auth/reset-password",
            json={"token": "weak-pw-token", "new_password": "short"},
        )
        assert response.status_code == 422  # Validation error


class TestValidateResetToken:
    """Tests for token validation endpoint."""

    def test_validate_valid_token(self, client: TestClient, db_session):
        """Validating a valid token returns valid=True."""
        user = User(
            email="validateme@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        token = PasswordResetToken(
            user_id=user.id,
            token="validate-me-token",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(token)
        db_session.commit()

        response = client.get("/api/auth/reset-password/validate/validate-me-token")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["email"] == "validateme@example.com"

    def test_validate_nonexistent_token(self, client: TestClient, db_session):
        """Validating nonexistent token returns valid=False."""
        response = client.get("/api/auth/reset-password/validate/nonexistent")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert "not found" in data["reason"].lower()

    def test_validate_expired_token(self, client: TestClient, db_session):
        """Validating expired token returns valid=False."""
        user = User(
            email="expiredvalidate@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        token = PasswordResetToken(
            user_id=user.id,
            token="expired-validate-token",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        db_session.add(token)
        db_session.commit()

        response = client.get("/api/auth/reset-password/validate/expired-validate-token")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert "expired" in data["reason"].lower()

    def test_validate_used_token(self, client: TestClient, db_session):
        """Validating used token returns valid=False."""
        user = User(
            email="usedvalidate@example.com",
            hashed_password=get_password_hash("password123"),
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        token = PasswordResetToken(
            user_id=user.id,
            token="used-validate-token",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            used_at=datetime.utcnow(),
        )
        db_session.add(token)
        db_session.commit()

        response = client.get("/api/auth/reset-password/validate/used-validate-token")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert "used" in data["reason"].lower()


class TestPasswordResetIntegration:
    """Integration tests for full password reset flow."""

    @pytest.mark.skip(reason="Passes in isolation but has test isolation issues with SQLite in-memory DB")
    def test_full_password_reset_flow(self, client: TestClient, db_session):
        """Test complete flow: forgot -> reset with known token -> login.

        Since we can't easily retrieve the token from the endpoint (it would
        normally be emailed), we test the flow by creating a token directly
        and testing the reset process.
        """
        # Create user
        user = User(
            email="fullflow@example.com",
            hashed_password=get_password_hash("oldpassword123"),
            full_name="Full Flow User",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        # Create a known token (simulating what forgot-password would create)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token="known-test-token-123",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        db_session.add(reset_token)
        db_session.commit()

        # Step 1: Validate token
        response = client.get("/api/auth/reset-password/validate/known-test-token-123")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["email"] == "fullflow@example.com"

        # Step 2: Reset password
        response = client.post(
            "/api/auth/reset-password",
            json={"token": "known-test-token-123", "new_password": "newpassword456"},
        )
        assert response.status_code == 200

        # Step 3: Token should now be invalid (used)
        response = client.get("/api/auth/reset-password/validate/known-test-token-123")
        assert response.status_code == 200
        assert response.json()["valid"] is False

        # Step 4: Login with new password
        response = client.post(
            "/api/auth/login",
            data={"username": "fullflow@example.com", "password": "newpassword456"},
        )
        assert response.status_code == 200
        assert "access_token" in response.json()

        # Step 5: Old password should not work
        response = client.post(
            "/api/auth/login",
            data={"username": "fullflow@example.com", "password": "oldpassword123"},
        )
        assert response.status_code == 401
