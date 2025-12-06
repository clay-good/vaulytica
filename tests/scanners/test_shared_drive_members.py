"""Tests for Phase 2.3: Shared Drive Membership Audit features."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock

from vaulytica.core.scanners.shared_drive_scanner import (
    SharedDriveScanner,
    SharedDriveInfo,
    SharedDriveMember,
    SharedDriveScannerError,
)


class TestSharedDriveMemberDataclass:
    """Tests for SharedDriveMember dataclass."""

    def test_shared_drive_member_creation(self):
        """Test creating a SharedDriveMember with all fields."""
        member = SharedDriveMember(
            drive_id="drive123",
            drive_name="Project Drive",
            member_email="user@company.com",
            member_type="user",
            role="writer",
            is_external=False,
            access_source="direct",
            display_name="Test User",
            permission_id="perm123",
        )

        assert member.drive_id == "drive123"
        assert member.drive_name == "Project Drive"
        assert member.member_email == "user@company.com"
        assert member.member_type == "user"
        assert member.role == "writer"
        assert member.is_external is False
        assert member.access_source == "direct"
        assert member.display_name == "Test User"
        assert member.permission_id == "perm123"

    def test_shared_drive_member_defaults(self):
        """Test SharedDriveMember with default values."""
        member = SharedDriveMember(
            drive_id="drive123",
            drive_name="Project Drive",
            member_email="user@company.com",
            member_type="user",
            role="reader",
        )

        assert member.is_external is False
        assert member.access_source == "direct"
        assert member.display_name is None
        assert member.permission_id == ""

    def test_external_member(self):
        """Test creating an external member."""
        member = SharedDriveMember(
            drive_id="drive123",
            drive_name="Project Drive",
            member_email="external@other.com",
            member_type="user",
            role="reader",
            is_external=True,
        )

        assert member.is_external is True

    def test_group_member(self):
        """Test creating a group member."""
        member = SharedDriveMember(
            drive_id="drive123",
            drive_name="Project Drive",
            member_email="team@company.com",
            member_type="group",
            role="writer",
        )

        assert member.member_type == "group"


class TestSharedDriveInfoMembers:
    """Tests for members field in SharedDriveInfo."""

    def test_shared_drive_info_has_members_field(self):
        """Test that SharedDriveInfo has members field."""
        drive_info = SharedDriveInfo(
            id="drive123",
            name="Project Drive",
            created_time=datetime.now(timezone.utc),
        )

        assert hasattr(drive_info, "members")
        assert drive_info.members == []

    def test_shared_drive_info_with_members(self):
        """Test SharedDriveInfo with populated members list."""
        members = [
            SharedDriveMember(
                drive_id="drive123",
                drive_name="Project Drive",
                member_email="user1@company.com",
                member_type="user",
                role="organizer",
            ),
            SharedDriveMember(
                drive_id="drive123",
                drive_name="Project Drive",
                member_email="user2@company.com",
                member_type="user",
                role="writer",
            ),
        ]

        drive_info = SharedDriveInfo(
            id="drive123",
            name="Project Drive",
            created_time=datetime.now(timezone.utc),
            members=members,
        )

        assert len(drive_info.members) == 2


class TestSharedDriveScannerProcessPermission:
    """Tests for _process_permission_to_member method."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock GoogleWorkspaceClient."""
        client = Mock()
        client.drive = Mock()
        return client

    @pytest.fixture
    def scanner(self, mock_client):
        """Create a SharedDriveScanner instance."""
        return SharedDriveScanner(
            client=mock_client,
            domain="company.com",
        )

    def test_process_user_permission_internal(self, scanner):
        """Test processing internal user permission."""
        perm_data = {
            "id": "perm123",
            "type": "user",
            "role": "writer",
            "emailAddress": "user@company.com",
            "displayName": "Internal User",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is not None
        assert member.member_email == "user@company.com"
        assert member.member_type == "user"
        assert member.role == "writer"
        assert member.is_external is False
        assert member.display_name == "Internal User"

    def test_process_user_permission_external(self, scanner):
        """Test processing external user permission."""
        perm_data = {
            "id": "perm123",
            "type": "user",
            "role": "reader",
            "emailAddress": "external@other.com",
            "displayName": "External User",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is not None
        assert member.member_email == "external@other.com"
        assert member.is_external is True

    def test_process_group_permission(self, scanner):
        """Test processing group permission."""
        perm_data = {
            "id": "perm123",
            "type": "group",
            "role": "writer",
            "emailAddress": "team@company.com",
            "displayName": "Team Group",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is not None
        assert member.member_type == "group"
        assert member.member_email == "team@company.com"
        assert member.is_external is False

    def test_process_external_group_permission(self, scanner):
        """Test processing external group permission."""
        perm_data = {
            "id": "perm123",
            "type": "group",
            "role": "reader",
            "emailAddress": "external-team@partner.com",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is not None
        assert member.member_type == "group"
        assert member.is_external is True

    def test_process_domain_permission_internal(self, scanner):
        """Test processing internal domain permission."""
        perm_data = {
            "id": "perm123",
            "type": "domain",
            "role": "reader",
            "domain": "company.com",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is not None
        assert member.member_type == "domain"
        assert member.member_email == "*@company.com"
        assert member.is_external is False

    def test_process_domain_permission_external(self, scanner):
        """Test processing external domain permission."""
        perm_data = {
            "id": "perm123",
            "type": "domain",
            "role": "commenter",
            "domain": "partner.com",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is not None
        assert member.member_type == "domain"
        assert member.member_email == "*@partner.com"
        assert member.is_external is True

    def test_process_anyone_permission(self, scanner):
        """Test processing public (anyone) permission."""
        perm_data = {
            "id": "perm123",
            "type": "anyone",
            "role": "reader",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is not None
        assert member.member_type == "anyone"
        assert member.member_email == "anyone (public)"
        assert member.is_external is True

    def test_process_invalid_permission_type(self, scanner):
        """Test that invalid permission types return None."""
        perm_data = {
            "id": "perm123",
            "type": "unknown",
            "role": "reader",
        }

        member = scanner._process_permission_to_member(perm_data, "drive123", "Test Drive")

        assert member is None


class TestSharedDriveScannerScanMembers:
    """Tests for scan_drive_members method."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock GoogleWorkspaceClient."""
        client = Mock()
        client.drive = Mock()
        return client

    @pytest.fixture
    def scanner(self, mock_client):
        """Create a SharedDriveScanner instance."""
        return SharedDriveScanner(
            client=mock_client,
            domain="company.com",
        )

    def test_scan_drive_members_returns_all_members(self, scanner, mock_client):
        """Test that scan_drive_members returns all members across drives."""
        # Mock drives list
        mock_client.drive.drives().list().execute.return_value = {
            "drives": [
                {
                    "id": "drive1",
                    "name": "Project A",
                    "createdTime": "2024-01-01T00:00:00Z",
                },
                {
                    "id": "drive2",
                    "name": "Project B",
                    "createdTime": "2024-02-01T00:00:00Z",
                },
            ],
        }

        # Mock permissions for each drive
        def mock_permissions(*args, **kwargs):
            mock_result = Mock()
            file_id = kwargs.get("fileId", "")
            if file_id == "drive1":
                mock_result.execute.return_value = {
                    "permissions": [
                        {"id": "p1", "type": "user", "role": "organizer", "emailAddress": "admin@company.com"},
                        {"id": "p2", "type": "user", "role": "writer", "emailAddress": "user1@company.com"},
                    ]
                }
            else:
                mock_result.execute.return_value = {
                    "permissions": [
                        {"id": "p3", "type": "user", "role": "organizer", "emailAddress": "admin@company.com"},
                        {"id": "p4", "type": "user", "role": "reader", "emailAddress": "external@other.com"},
                    ]
                }
            return mock_result

        mock_client.drive.permissions().list = mock_permissions

        members = list(scanner.scan_drive_members())

        # Should have 4 total members (2 per drive)
        assert len(members) == 4

    def test_scan_drive_members_identifies_external(self, scanner, mock_client):
        """Test that external members are correctly identified."""
        mock_client.drive.drives().list().execute.return_value = {
            "drives": [
                {"id": "drive1", "name": "Project", "createdTime": "2024-01-01T00:00:00Z"},
            ],
        }

        mock_client.drive.permissions().list().execute.return_value = {
            "permissions": [
                {"id": "p1", "type": "user", "role": "writer", "emailAddress": "internal@company.com"},
                {"id": "p2", "type": "user", "role": "reader", "emailAddress": "external@other.com"},
                {"id": "p3", "type": "anyone", "role": "reader"},
            ]
        }

        members = list(scanner.scan_drive_members())

        external_members = [m for m in members if m.is_external]
        internal_members = [m for m in members if not m.is_external]

        assert len(external_members) == 2  # external user + anyone
        assert len(internal_members) == 1

    def test_scan_drive_members_skips_deleted_permissions(self, scanner, mock_client):
        """Test that deleted permissions are skipped."""
        mock_client.drive.drives().list().execute.return_value = {
            "drives": [
                {"id": "drive1", "name": "Project", "createdTime": "2024-01-01T00:00:00Z"},
            ],
        }

        mock_client.drive.permissions().list().execute.return_value = {
            "permissions": [
                {"id": "p1", "type": "user", "role": "writer", "emailAddress": "active@company.com"},
                {"id": "p2", "type": "user", "role": "reader", "emailAddress": "deleted@company.com", "deleted": True},
            ]
        }

        members = list(scanner.scan_drive_members())

        assert len(members) == 1
        assert members[0].member_email == "active@company.com"

    def test_scan_drive_members_includes_all_roles(self, scanner, mock_client):
        """Test that all permission roles are captured."""
        mock_client.drive.drives().list().execute.return_value = {
            "drives": [
                {"id": "drive1", "name": "Project", "createdTime": "2024-01-01T00:00:00Z"},
            ],
        }

        mock_client.drive.permissions().list().execute.return_value = {
            "permissions": [
                {"id": "p1", "type": "user", "role": "organizer", "emailAddress": "org@company.com"},
                {"id": "p2", "type": "user", "role": "fileOrganizer", "emailAddress": "fileorg@company.com"},
                {"id": "p3", "type": "user", "role": "writer", "emailAddress": "writer@company.com"},
                {"id": "p4", "type": "user", "role": "commenter", "emailAddress": "commenter@company.com"},
                {"id": "p5", "type": "user", "role": "reader", "emailAddress": "reader@company.com"},
            ]
        }

        members = list(scanner.scan_drive_members())

        roles = {m.role for m in members}
        assert "organizer" in roles
        assert "fileOrganizer" in roles
        assert "writer" in roles
        assert "commenter" in roles
        assert "reader" in roles
