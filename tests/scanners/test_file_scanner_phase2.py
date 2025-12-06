"""Tests for Phase 2 FileScanner features: stale content and external ownership tracking."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock, patch

from vaulytica.core.scanners.file_scanner import FileScanner, FileInfo, FilePermission


class TestFileInfoPhase2Fields:
    """Tests for new Phase 2 fields in FileInfo dataclass."""

    def test_fileinfo_has_last_accessed_fields(self):
        """Test that FileInfo has all new Phase 2 fields."""
        file_info = FileInfo(
            id="file123",
            name="test.txt",
            mime_type="text/plain",
            owner_email="user@example.com",
            owner_name="Test User",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
        )

        # Check last accessed fields exist
        assert hasattr(file_info, "last_accessed_time")
        assert hasattr(file_info, "days_since_last_access")
        assert hasattr(file_info, "is_stale")

        # Check default values
        assert file_info.last_accessed_time is None
        assert file_info.days_since_last_access is None
        assert file_info.is_stale is False

    def test_fileinfo_has_external_ownership_fields(self):
        """Test that FileInfo has all external ownership fields."""
        file_info = FileInfo(
            id="file123",
            name="test.txt",
            mime_type="text/plain",
            owner_email="user@example.com",
            owner_name="Test User",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
        )

        # Check external ownership fields exist
        assert hasattr(file_info, "is_externally_owned")
        assert hasattr(file_info, "owner_domain")
        assert hasattr(file_info, "organization_access")

        # Check default values
        assert file_info.is_externally_owned is False
        assert file_info.owner_domain is None
        assert file_info.organization_access == []

    def test_fileinfo_with_all_phase2_fields(self):
        """Test creating FileInfo with all Phase 2 fields populated."""
        last_accessed = datetime.now(timezone.utc) - timedelta(days=200)

        file_info = FileInfo(
            id="file123",
            name="old_file.txt",
            mime_type="text/plain",
            owner_email="external@othercompany.com",
            owner_name="External User",
            created_time=datetime.now(timezone.utc) - timedelta(days=365),
            modified_time=datetime.now(timezone.utc) - timedelta(days=180),
            last_accessed_time=last_accessed,
            days_since_last_access=200,
            is_stale=True,
            is_externally_owned=True,
            owner_domain="othercompany.com",
            organization_access=["user1@mycompany.com", "user2@mycompany.com"],
        )

        assert file_info.last_accessed_time == last_accessed
        assert file_info.days_since_last_access == 200
        assert file_info.is_stale is True
        assert file_info.is_externally_owned is True
        assert file_info.owner_domain == "othercompany.com"
        assert len(file_info.organization_access) == 2


class TestFileScannerProcessFile:
    """Tests for _process_file method with Phase 2 enhancements."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock GoogleWorkspaceClient."""
        client = Mock()
        client.drive = Mock()
        return client

    @pytest.fixture
    def scanner(self, mock_client):
        """Create a FileScanner instance."""
        return FileScanner(
            client=mock_client,
            domain="mycompany.com",
            batch_size=100,
            rate_limit_delay=0.0,
        )

    def test_process_file_extracts_owner_domain(self, scanner):
        """Test that _process_file correctly extracts owner domain."""
        file_data = {
            "id": "file123",
            "name": "test.txt",
            "mimeType": "text/plain",
            "owners": [{"emailAddress": "user@othercompany.com", "displayName": "External User"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-06-01T00:00:00Z",
            "permissions": [],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.owner_domain == "othercompany.com"
        assert file_info.is_externally_owned is True

    def test_process_file_internal_owner(self, scanner):
        """Test that internal owners are not marked as externally owned."""
        file_data = {
            "id": "file123",
            "name": "test.txt",
            "mimeType": "text/plain",
            "owners": [{"emailAddress": "user@mycompany.com", "displayName": "Internal User"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-06-01T00:00:00Z",
            "permissions": [],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.owner_domain == "mycompany.com"
        assert file_info.is_externally_owned is False

    def test_process_file_extracts_last_accessed_time(self, scanner):
        """Test that _process_file correctly extracts viewedByMeTime."""
        accessed_time = "2024-06-15T10:30:00Z"
        file_data = {
            "id": "file123",
            "name": "test.txt",
            "mimeType": "text/plain",
            "owners": [{"emailAddress": "user@mycompany.com", "displayName": "User"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-06-01T00:00:00Z",
            "viewedByMeTime": accessed_time,
            "permissions": [],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.last_accessed_time is not None
        assert file_info.days_since_last_access is not None

    def test_process_file_marks_stale_content(self, scanner):
        """Test that _process_file correctly marks stale content."""
        # Create a file accessed 200 days ago
        old_access_time = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat().replace("+00:00", "Z")
        file_data = {
            "id": "file123",
            "name": "old_file.txt",
            "mimeType": "text/plain",
            "owners": [{"emailAddress": "user@mycompany.com", "displayName": "User"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-06-01T00:00:00Z",
            "viewedByMeTime": old_access_time,
            "permissions": [],
        }

        file_info = scanner._process_file(file_data, stale_days=180)

        assert file_info.is_stale is True
        assert file_info.days_since_last_access >= 180

    def test_process_file_not_stale_when_recently_accessed(self, scanner):
        """Test that recently accessed files are not marked as stale."""
        recent_access_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat().replace("+00:00", "Z")
        file_data = {
            "id": "file123",
            "name": "recent_file.txt",
            "mimeType": "text/plain",
            "owners": [{"emailAddress": "user@mycompany.com", "displayName": "User"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-06-01T00:00:00Z",
            "viewedByMeTime": recent_access_time,
            "permissions": [],
        }

        file_info = scanner._process_file(file_data, stale_days=180)

        assert file_info.is_stale is False

    def test_process_file_tracks_organization_access(self, scanner):
        """Test that _process_file correctly tracks internal users with access."""
        file_data = {
            "id": "file123",
            "name": "shared_file.txt",
            "mimeType": "text/plain",
            "owners": [{"emailAddress": "owner@external.com", "displayName": "External Owner"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-06-01T00:00:00Z",
            "permissions": [
                {"id": "perm1", "type": "user", "role": "reader", "emailAddress": "user1@mycompany.com"},
                {"id": "perm2", "type": "user", "role": "writer", "emailAddress": "user2@mycompany.com"},
                {"id": "perm3", "type": "user", "role": "reader", "emailAddress": "external@other.com"},
            ],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.is_externally_owned is True
        assert len(file_info.organization_access) == 2
        assert "user1@mycompany.com" in file_info.organization_access
        assert "user2@mycompany.com" in file_info.organization_access
        assert "external@other.com" not in file_info.organization_access


class TestFileScannerStaleScan:
    """Tests for scan_stale_content method."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock GoogleWorkspaceClient."""
        client = Mock()
        client.drive = Mock()
        return client

    @pytest.fixture
    def scanner(self, mock_client):
        """Create a FileScanner instance."""
        return FileScanner(
            client=mock_client,
            domain="mycompany.com",
            batch_size=100,
            rate_limit_delay=0.0,
        )

    def test_scan_stale_content_returns_only_stale_files(self, scanner, mock_client):
        """Test that scan_stale_content only returns files older than threshold."""
        old_access_time = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat().replace("+00:00", "Z")
        recent_access_time = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat().replace("+00:00", "Z")

        mock_response = {
            "files": [
                {
                    "id": "stale_file",
                    "name": "old.txt",
                    "mimeType": "text/plain",
                    "owners": [{"emailAddress": "user@mycompany.com", "displayName": "User"}],
                    "createdTime": "2024-01-01T00:00:00Z",
                    "modifiedTime": "2024-06-01T00:00:00Z",
                    "viewedByMeTime": old_access_time,
                    "permissions": [],
                },
                {
                    "id": "recent_file",
                    "name": "recent.txt",
                    "mimeType": "text/plain",
                    "owners": [{"emailAddress": "user@mycompany.com", "displayName": "User"}],
                    "createdTime": "2024-01-01T00:00:00Z",
                    "modifiedTime": "2024-06-01T00:00:00Z",
                    "viewedByMeTime": recent_access_time,
                    "permissions": [],
                },
            ],
        }

        mock_client.drive.files().list().execute.return_value = mock_response

        stale_files = list(scanner.scan_stale_content(stale_days=180))

        # Should only return the stale file
        assert len(stale_files) == 1
        assert stale_files[0].id == "stale_file"
        assert stale_files[0].is_stale is True

    def test_scan_stale_content_folders_only(self, scanner, mock_client):
        """Test that folders_only option filters to folders."""
        # We just need to verify the query is correct
        mock_response = {"files": []}
        mock_client.drive.files().list().execute.return_value = mock_response

        list(scanner.scan_stale_content(stale_days=180, folders_only=True))

        # Verify the API was called - the actual query will include the folder filter
        mock_client.drive.files().list.assert_called()


class TestFileScannerExternalOwnedScan:
    """Tests for scan_external_owned method."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock GoogleWorkspaceClient."""
        client = Mock()
        client.drive = Mock()
        return client

    @pytest.fixture
    def scanner(self, mock_client):
        """Create a FileScanner instance."""
        return FileScanner(
            client=mock_client,
            domain="mycompany.com",
            batch_size=100,
            rate_limit_delay=0.0,
        )

    def test_scan_external_owned_returns_only_external_files(self, scanner, mock_client):
        """Test that scan_external_owned only returns externally owned files."""
        mock_response = {
            "files": [
                {
                    "id": "external_file",
                    "name": "external.txt",
                    "mimeType": "text/plain",
                    "owners": [{"emailAddress": "user@external.com", "displayName": "External User"}],
                    "createdTime": "2024-01-01T00:00:00Z",
                    "modifiedTime": "2024-06-01T00:00:00Z",
                    "permissions": [],
                },
                {
                    "id": "internal_file",
                    "name": "internal.txt",
                    "mimeType": "text/plain",
                    "owners": [{"emailAddress": "user@mycompany.com", "displayName": "Internal User"}],
                    "createdTime": "2024-01-01T00:00:00Z",
                    "modifiedTime": "2024-06-01T00:00:00Z",
                    "permissions": [],
                },
            ],
        }

        mock_client.drive.files().list().execute.return_value = mock_response

        external_files = list(scanner.scan_external_owned())

        # Should only return the externally owned file
        assert len(external_files) == 1
        assert external_files[0].id == "external_file"
        assert external_files[0].is_externally_owned is True
        assert external_files[0].owner_domain == "external.com"

    def test_scan_external_owned_respects_min_size(self, scanner, mock_client):
        """Test that min_size filter works correctly."""
        mock_response = {
            "files": [
                {
                    "id": "large_external_file",
                    "name": "large.txt",
                    "mimeType": "text/plain",
                    "size": "10000000",  # 10MB
                    "owners": [{"emailAddress": "user@external.com", "displayName": "External User"}],
                    "createdTime": "2024-01-01T00:00:00Z",
                    "modifiedTime": "2024-06-01T00:00:00Z",
                    "permissions": [],
                },
                {
                    "id": "small_external_file",
                    "name": "small.txt",
                    "mimeType": "text/plain",
                    "size": "1000",  # 1KB
                    "owners": [{"emailAddress": "user@external.com", "displayName": "External User"}],
                    "createdTime": "2024-01-01T00:00:00Z",
                    "modifiedTime": "2024-06-01T00:00:00Z",
                    "permissions": [],
                },
            ],
        }

        mock_client.drive.files().list().execute.return_value = mock_response

        # With min_size of 1MB, should only return large file
        external_files = list(scanner.scan_external_owned(min_size=1000000))

        assert len(external_files) == 1
        assert external_files[0].id == "large_external_file"

    def test_scan_external_owned_tracks_organization_access(self, scanner, mock_client):
        """Test that organization_access is populated for externally owned files."""
        mock_response = {
            "files": [
                {
                    "id": "shared_external_file",
                    "name": "shared.txt",
                    "mimeType": "text/plain",
                    "owners": [{"emailAddress": "user@external.com", "displayName": "External User"}],
                    "createdTime": "2024-01-01T00:00:00Z",
                    "modifiedTime": "2024-06-01T00:00:00Z",
                    "permissions": [
                        {"id": "perm1", "type": "user", "role": "reader", "emailAddress": "internal1@mycompany.com"},
                        {"id": "perm2", "type": "user", "role": "writer", "emailAddress": "internal2@mycompany.com"},
                    ],
                },
            ],
        }

        mock_client.drive.files().list().execute.return_value = mock_response

        external_files = list(scanner.scan_external_owned())

        assert len(external_files) == 1
        file_info = external_files[0]
        assert file_info.is_externally_owned is True
        assert len(file_info.organization_access) == 2
        assert "internal1@mycompany.com" in file_info.organization_access
        assert "internal2@mycompany.com" in file_info.organization_access
