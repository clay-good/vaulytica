"""Tests for file scanner."""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock

from vaulytica.core.scanners.file_scanner import (
    FileScanner,
    FileInfo,
    FilePermission,
    FileScannerError,
)


class TestFileScanner:
    """Tests for FileScanner."""

    def test_init(self):
        """Test FileScanner initialization."""
        client = Mock()
        scanner = FileScanner(client, domain="example.com")

        assert scanner.client == client
        assert scanner.domain == "example.com"
        assert scanner.batch_size == 100
        assert scanner.rate_limit_delay == 0.1

    def test_init_with_custom_params(self):
        """Test FileScanner with custom parameters."""
        client = Mock()
        scanner = FileScanner(
            client,
            domain="example.com",
            batch_size=50,
            rate_limit_delay=0.5,
        )

        assert scanner.batch_size == 50
        assert scanner.rate_limit_delay == 0.5

    def test_process_file_basic(self):
        """Test processing basic file data."""
        client = Mock()
        scanner = FileScanner(client, domain="example.com")

        file_data = {
            "id": "file123",
            "name": "test.pdf",
            "mimeType": "application/pdf",
            "owners": [{"emailAddress": "owner@example.com", "displayName": "Owner"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-01-02T00:00:00Z",
            "size": "1024",
            "webViewLink": "https://drive.google.com/file/d/file123",
            "permissions": [],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.id == "file123"
        assert file_info.name == "test.pdf"
        assert file_info.mime_type == "application/pdf"
        assert file_info.owner_email == "owner@example.com"
        assert file_info.owner_name == "Owner"
        assert file_info.size == 1024
        assert file_info.is_shared_externally is False
        assert file_info.is_public is False

    def test_process_file_with_public_sharing(self):
        """Test processing file with public sharing."""
        client = Mock()
        scanner = FileScanner(client, domain="example.com")

        file_data = {
            "id": "file123",
            "name": "public.pdf",
            "mimeType": "application/pdf",
            "owners": [{"emailAddress": "owner@example.com", "displayName": "Owner"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-01-02T00:00:00Z",
            "permissions": [
                {
                    "id": "perm1",
                    "type": "anyone",
                    "role": "reader",
                }
            ],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.is_public is True
        assert file_info.risk_score == 100  # Public files have max risk

    def test_process_file_with_external_sharing(self):
        """Test processing file with external sharing."""
        client = Mock()
        scanner = FileScanner(client, domain="example.com")

        file_data = {
            "id": "file123",
            "name": "shared.pdf",
            "mimeType": "application/pdf",
            "owners": [{"emailAddress": "owner@example.com", "displayName": "Owner"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-01-02T00:00:00Z",
            "permissions": [
                {
                    "id": "perm1",
                    "type": "user",
                    "role": "reader",
                    "emailAddress": "external@other.com",
                    "displayName": "External User",
                }
            ],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.is_shared_externally is True
        assert "external@other.com" in file_info.external_emails
        assert "other.com" in file_info.external_domains
        assert file_info.risk_score >= 50  # External sharing has high risk

    def test_process_file_with_internal_sharing(self):
        """Test processing file with internal sharing only."""
        client = Mock()
        scanner = FileScanner(client, domain="example.com")

        file_data = {
            "id": "file123",
            "name": "internal.pdf",
            "mimeType": "application/pdf",
            "owners": [{"emailAddress": "owner@example.com", "displayName": "Owner"}],
            "createdTime": "2024-01-01T00:00:00Z",
            "modifiedTime": "2024-01-02T00:00:00Z",
            "permissions": [
                {
                    "id": "perm1",
                    "type": "user",
                    "role": "reader",
                    "emailAddress": "colleague@example.com",
                    "displayName": "Colleague",
                }
            ],
        }

        file_info = scanner._process_file(file_data)

        assert file_info.is_shared_externally is False
        assert len(file_info.external_emails) == 0
        assert len(file_info.external_domains) == 0

    def test_calculate_risk_score_public(self):
        """Test risk score calculation for public files."""
        client = Mock()
        scanner = FileScanner(client, domain="example.com")

        file_info = FileInfo(
            id="file123",
            name="test.pdf",
            mime_type="application/pdf",
            owner_email="owner@example.com",
            owner_name="Owner",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            is_public=True,
        )

        score = scanner._calculate_risk_score(file_info)
        assert score == 100

    def test_calculate_risk_score_external(self):
        """Test risk score calculation for externally shared files."""
        client = Mock()
        scanner = FileScanner(client, domain="example.com")

        file_info = FileInfo(
            id="file123",
            name="test.pdf",
            mime_type="application/pdf",
            owner_email="owner@example.com",
            owner_name="Owner",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
            is_shared_externally=True,
            external_domains=["other.com"],
        )

        score = scanner._calculate_risk_score(file_info)
        assert score >= 50

    def test_scan_all_files_mock(self):
        """Test scanning all files with mocked API."""
        client = Mock()

        # Mock Drive API response
        mock_files_list = Mock()
        mock_execute = Mock(
            return_value={
                "files": [
                    {
                        "id": "file1",
                        "name": "test1.pdf",
                        "mimeType": "application/pdf",
                        "owners": [{"emailAddress": "owner@example.com", "displayName": "Owner"}],
                        "createdTime": "2024-01-01T00:00:00Z",
                        "modifiedTime": "2024-01-02T00:00:00Z",
                        "permissions": [],
                    }
                ],
                "nextPageToken": None,
            }
        )
        mock_files_list.execute = mock_execute
        client.drive.files().list.return_value = mock_files_list

        scanner = FileScanner(client, domain="example.com")
        files = list(scanner.scan_all_files())

        assert len(files) == 1
        assert files[0].id == "file1"
        assert files[0].name == "test1.pdf"


class TestFilePermission:
    """Tests for FilePermission dataclass."""

    def test_file_permission_creation(self):
        """Test creating FilePermission."""
        perm = FilePermission(
            id="perm123",
            type="user",
            role="reader",
            email_address="user@example.com",
            display_name="User",
        )

        assert perm.id == "perm123"
        assert perm.type == "user"
        assert perm.role == "reader"
        assert perm.email_address == "user@example.com"
        assert perm.deleted is False


class TestFileInfo:
    """Tests for FileInfo dataclass."""

    def test_file_info_creation(self):
        """Test creating FileInfo."""
        file_info = FileInfo(
            id="file123",
            name="test.pdf",
            mime_type="application/pdf",
            owner_email="owner@example.com",
            owner_name="Owner",
            created_time=datetime.now(timezone.utc),
            modified_time=datetime.now(timezone.utc),
        )

        assert file_info.id == "file123"
        assert file_info.name == "test.pdf"
        assert file_info.is_shared_externally is False
        assert file_info.is_public is False
        assert len(file_info.permissions) == 0

