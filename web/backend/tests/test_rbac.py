"""Tests for role-based access control (RBAC)."""

import pytest
from fastapi.testclient import TestClient

from backend.auth.security import (
    Role,
    ROLE_HIERARCHY,
    get_user_role_for_domain,
    check_domain_access,
    check_domain_role,
)
from backend.db.models import User, UserDomain, Domain


class TestRoleEnum:
    """Test Role enum."""

    def test_role_values(self):
        """Test role values are correct."""
        assert Role.VIEWER.value == "viewer"
        assert Role.EDITOR.value == "editor"
        assert Role.ADMIN.value == "admin"


class TestRoleHierarchy:
    """Test role hierarchy."""

    def test_viewer_has_only_viewer_permission(self):
        """Test viewer role only has viewer permissions."""
        assert ROLE_HIERARCHY[Role.VIEWER] == [Role.VIEWER]

    def test_editor_has_viewer_and_editor_permissions(self):
        """Test editor role has viewer and editor permissions."""
        assert Role.VIEWER in ROLE_HIERARCHY[Role.EDITOR]
        assert Role.EDITOR in ROLE_HIERARCHY[Role.EDITOR]
        assert Role.ADMIN not in ROLE_HIERARCHY[Role.EDITOR]

    def test_admin_has_all_permissions(self):
        """Test admin role has all permissions."""
        assert Role.VIEWER in ROLE_HIERARCHY[Role.ADMIN]
        assert Role.EDITOR in ROLE_HIERARCHY[Role.ADMIN]
        assert Role.ADMIN in ROLE_HIERARCHY[Role.ADMIN]


class TestGetUserRoleForDomain:
    """Test get_user_role_for_domain function."""

    def test_superuser_has_admin_role_for_any_domain(self, db):
        """Test superuser has admin role for any domain."""
        user = User(
            email="admin@example.com",
            hashed_password="hash",
            is_superuser=True,
        )
        db.add(user)
        db.commit()

        role = get_user_role_for_domain(user, "any-domain.com")
        assert role == Role.ADMIN

    def test_regular_user_no_access_without_domain(self, db):
        """Test regular user has no role for domain they don't have access to."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        role = get_user_role_for_domain(user, "some-domain.com")
        assert role is None

    def test_user_gets_assigned_role_for_domain(self, db):
        """Test user gets their assigned role for a domain."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        user_domain = UserDomain(
            user_id=user.id,
            domain="example.com",
            role="editor",
        )
        db.add(user_domain)
        db.commit()
        db.refresh(user)

        role = get_user_role_for_domain(user, "example.com")
        assert role == Role.EDITOR

    def test_unknown_role_defaults_to_viewer(self, db):
        """Test unknown role value defaults to viewer."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        user_domain = UserDomain(
            user_id=user.id,
            domain="example.com",
            role="unknown_role",
        )
        db.add(user_domain)
        db.commit()
        db.refresh(user)

        role = get_user_role_for_domain(user, "example.com")
        assert role == Role.VIEWER


class TestCheckDomainAccess:
    """Test check_domain_access function."""

    def test_superuser_has_access_to_any_domain(self, db):
        """Test superuser has access to any domain."""
        user = User(
            email="admin@example.com",
            hashed_password="hash",
            is_superuser=True,
        )
        db.add(user)
        db.commit()

        assert check_domain_access(user, "any-domain.com") is True

    def test_regular_user_no_access_without_assignment(self, db):
        """Test regular user has no access without domain assignment."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        assert check_domain_access(user, "some-domain.com") is False

    def test_user_has_access_with_assignment(self, db):
        """Test user has access with domain assignment."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        user_domain = UserDomain(
            user_id=user.id,
            domain="example.com",
            role="viewer",
        )
        db.add(user_domain)
        db.commit()
        db.refresh(user)

        assert check_domain_access(user, "example.com") is True
        assert check_domain_access(user, "other-domain.com") is False


class TestCheckDomainRole:
    """Test check_domain_role function."""

    def test_viewer_can_view(self, db):
        """Test viewer can perform viewer actions."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        user_domain = UserDomain(
            user_id=user.id,
            domain="example.com",
            role="viewer",
        )
        db.add(user_domain)
        db.commit()
        db.refresh(user)

        assert check_domain_role(user, "example.com", Role.VIEWER) is True
        assert check_domain_role(user, "example.com", Role.EDITOR) is False
        assert check_domain_role(user, "example.com", Role.ADMIN) is False

    def test_editor_can_view_and_edit(self, db):
        """Test editor can perform viewer and editor actions."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        user_domain = UserDomain(
            user_id=user.id,
            domain="example.com",
            role="editor",
        )
        db.add(user_domain)
        db.commit()
        db.refresh(user)

        assert check_domain_role(user, "example.com", Role.VIEWER) is True
        assert check_domain_role(user, "example.com", Role.EDITOR) is True
        assert check_domain_role(user, "example.com", Role.ADMIN) is False

    def test_admin_can_do_everything(self, db):
        """Test admin can perform all actions."""
        user = User(
            email="user@example.com",
            hashed_password="hash",
            is_superuser=False,
        )
        db.add(user)
        db.commit()

        user_domain = UserDomain(
            user_id=user.id,
            domain="example.com",
            role="admin",
        )
        db.add(user_domain)
        db.commit()
        db.refresh(user)

        assert check_domain_role(user, "example.com", Role.VIEWER) is True
        assert check_domain_role(user, "example.com", Role.EDITOR) is True
        assert check_domain_role(user, "example.com", Role.ADMIN) is True

    def test_superuser_has_admin_role_everywhere(self, db):
        """Test superuser has admin role for any domain."""
        user = User(
            email="admin@example.com",
            hashed_password="hash",
            is_superuser=True,
        )
        db.add(user)
        db.commit()

        assert check_domain_role(user, "any-domain.com", Role.VIEWER) is True
        assert check_domain_role(user, "any-domain.com", Role.EDITOR) is True
        assert check_domain_role(user, "any-domain.com", Role.ADMIN) is True


class TestPermissionsEndpoint:
    """Test the /me/permissions endpoint."""

    def test_superuser_permissions(self, client: TestClient, test_superuser, superuser_headers, db):
        """Test superuser gets correct permissions."""
        # Create a domain for testing
        domain = Domain(name="test.com", is_active=True)
        db.add(domain)
        db.commit()

        response = client.get("/api/auth/me/permissions", headers=superuser_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["is_superuser"] is True
        assert "test.com" in data["accessible_domains"]
        assert "test.com" in data["editable_domains"]
        assert "test.com" in data["admin_domains"]

    def test_viewer_permissions(self, client: TestClient, test_user, auth_headers, db):
        """Test viewer gets correct permissions."""
        # Create a domain and assign viewer role
        domain = Domain(name="viewer-test.com", is_active=True)
        db.add(domain)
        db.commit()

        user_domain = UserDomain(
            user_id=test_user.id,
            domain="viewer-test.com",
            role="viewer",
        )
        db.add(user_domain)
        db.commit()

        response = client.get("/api/auth/me/permissions", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["is_superuser"] is False
        assert "viewer-test.com" in data["accessible_domains"]
        assert "viewer-test.com" not in data["editable_domains"]
        assert "viewer-test.com" not in data["admin_domains"]

    def test_editor_permissions(self, client: TestClient, test_user, auth_headers, db):
        """Test editor gets correct permissions."""
        # Create a domain and assign editor role
        domain = Domain(name="editor-test.com", is_active=True)
        db.add(domain)
        db.commit()

        user_domain = UserDomain(
            user_id=test_user.id,
            domain="editor-test.com",
            role="editor",
        )
        db.add(user_domain)
        db.commit()

        response = client.get("/api/auth/me/permissions", headers=auth_headers)
        assert response.status_code == 200

        data = response.json()
        assert data["is_superuser"] is False
        assert "editor-test.com" in data["accessible_domains"]
        assert "editor-test.com" in data["editable_domains"]
        assert "editor-test.com" not in data["admin_domains"]


class TestScanTriggerWithRBAC:
    """Test scan trigger endpoint with RBAC."""

    def test_viewer_cannot_trigger_scan(self, client: TestClient, test_user, auth_headers, db):
        """Test viewer cannot trigger a scan."""
        # Create a domain and assign viewer role
        domain = Domain(name="rbac-test.com", is_active=True)
        db.add(domain)
        db.commit()

        user_domain = UserDomain(
            user_id=test_user.id,
            domain="rbac-test.com",
            role="viewer",
        )
        db.add(user_domain)
        db.commit()

        response = client.post(
            "/api/scans/trigger",
            json={"domain_name": "rbac-test.com", "scan_type": "files"},
            headers=auth_headers,
        )
        assert response.status_code == 403
        assert "editor" in response.json()["detail"].lower()

    def test_editor_can_trigger_scan(self, client: TestClient, test_user, auth_headers, db):
        """Test editor can trigger a scan."""
        # Create a domain and assign editor role
        domain = Domain(name="editor-scan.com", is_active=True)
        db.add(domain)
        db.commit()

        user_domain = UserDomain(
            user_id=test_user.id,
            domain="editor-scan.com",
            role="editor",
        )
        db.add(user_domain)
        db.commit()

        response = client.post(
            "/api/scans/trigger",
            json={"domain_name": "editor-scan.com", "scan_type": "files"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "running"

    def test_admin_can_trigger_scan(self, client: TestClient, test_user, auth_headers, db):
        """Test admin can trigger a scan."""
        # Create a domain and assign admin role
        domain = Domain(name="admin-scan.com", is_active=True)
        db.add(domain)
        db.commit()

        user_domain = UserDomain(
            user_id=test_user.id,
            domain="admin-scan.com",
            role="admin",
        )
        db.add(user_domain)
        db.commit()

        response = client.post(
            "/api/scans/trigger",
            json={"domain_name": "admin-scan.com", "scan_type": "files"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "running"
