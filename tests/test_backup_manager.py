"""Tests for Backup Manager."""

import json
import pytest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch, mock_open

from vaulytica.core.backup.backup_manager import (
    BackupManager,
    BackupMetadata,
    BackupError,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.admin = Mock()
    client.admin.users = Mock(return_value=Mock())
    client.admin.groups = Mock(return_value=Mock())
    client.admin.orgunits = Mock(return_value=Mock())
    return client


@pytest.fixture
def temp_backup_dir(tmp_path):
    """Create a temporary backup directory."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    return backup_dir


@pytest.fixture
def backup_manager(mock_client, temp_backup_dir):
    """Create a backup manager instance."""
    return BackupManager(
        client=mock_client,
        backup_dir=temp_backup_dir,
        domain="example.com",
    )


class TestBackupManager:
    """Tests for BackupManager class."""
    
    def test_init(self, mock_client, temp_backup_dir):
        """Test backup manager initialization."""
        manager = BackupManager(
            client=mock_client,
            backup_dir=temp_backup_dir,
            domain="example.com",
        )
        assert manager.client == mock_client
        assert manager.backup_dir == temp_backup_dir
        assert manager.domain == "example.com"
        assert temp_backup_dir.exists()
    
    def test_init_creates_directory(self, mock_client, tmp_path):
        """Test backup manager creates directory if it doesn't exist."""
        backup_dir = tmp_path / "new_backups"
        assert not backup_dir.exists()
        
        manager = BackupManager(
            client=mock_client,
            backup_dir=backup_dir,
            domain="example.com",
        )
        
        assert backup_dir.exists()
    
    def test_backup_users_json_success(self, backup_manager, mock_client, temp_backup_dir):
        """Test backing up users to JSON successfully."""
        # Mock API response
        mock_users = [
            {
                "primaryEmail": "user1@example.com",
                "name": {"fullName": "User One"},
                "suspended": False,
                "isAdmin": True,
                "creationTime": "2024-01-01T00:00:00Z",
                "lastLoginTime": "2024-10-31T00:00:00Z",
            },
            {
                "primaryEmail": "user2@example.com",
                "name": {"fullName": "User Two"},
                "suspended": False,
                "isAdmin": False,
                "creationTime": "2024-01-02T00:00:00Z",
            },
        ]
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = {
            "users": mock_users,
        }
        mock_client.admin.users.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_users(output_format="json")
        
        # Verify metadata
        assert metadata.backup_type == "users"
        assert metadata.item_count == 2
        assert metadata.status == "completed"
        assert metadata.backup_path.exists()
        assert metadata.backup_path.suffix == ".json"
        assert metadata.size_bytes > 0
        
        # Verify file content
        with open(metadata.backup_path) as f:
            saved_users = json.load(f)
        assert len(saved_users) == 2
        assert saved_users[0]["primaryEmail"] == "user1@example.com"
        
        # Verify API call
        mock_list.list.assert_called_once_with(
            domain="example.com",
            maxResults=500,
            pageToken=None,
            projection="full",
        )
        
        # Verify metadata file was created
        metadata_dir = temp_backup_dir / ".metadata"
        assert metadata_dir.exists()
        metadata_files = list(metadata_dir.glob("*.json"))
        assert len(metadata_files) == 1
    
    def test_backup_users_csv_success(self, backup_manager, mock_client, temp_backup_dir):
        """Test backing up users to CSV successfully."""
        mock_users = [
            {
                "primaryEmail": "user1@example.com",
                "name": {"fullName": "User One"},
                "suspended": False,
                "isAdmin": True,
                "creationTime": "2024-01-01T00:00:00Z",
                "lastLoginTime": "2024-10-31T00:00:00Z",
            },
        ]
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = {
            "users": mock_users,
        }
        mock_client.admin.users.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_users(output_format="csv")
        
        # Verify
        assert metadata.backup_path.suffix == ".csv"
        assert metadata.backup_path.exists()
        
        # Verify CSV content
        with open(metadata.backup_path) as f:
            content = f.read()
        assert "primaryEmail" in content
        assert "user1@example.com" in content
        assert "User One" in content
    
    def test_backup_users_pagination(self, backup_manager, mock_client):
        """Test backing up users with pagination."""
        # Mock paginated responses
        mock_response_1 = {
            "users": [{"primaryEmail": "user1@example.com", "name": {"fullName": "User 1"}}],
            "nextPageToken": "token123",
        }
        mock_response_2 = {
            "users": [{"primaryEmail": "user2@example.com", "name": {"fullName": "User 2"}}],
        }
        
        mock_list = Mock()
        mock_list.list.return_value.execute.side_effect = [mock_response_1, mock_response_2]
        mock_client.admin.users.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_users(output_format="json")
        
        # Verify
        assert metadata.item_count == 2
        assert mock_list.list.call_count == 2
        
        # Verify second call includes page token
        second_call_args = mock_list.list.call_args_list[1]
        assert second_call_args[1]["pageToken"] == "token123"
    
    def test_backup_users_empty(self, backup_manager, mock_client):
        """Test backing up when no users exist."""
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = {"users": []}
        mock_client.admin.users.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_users(output_format="json")
        
        # Verify
        assert metadata.item_count == 0
        assert metadata.status == "completed"
    
    def test_backup_users_error(self, backup_manager, mock_client):
        """Test backing up users with error."""
        mock_list = Mock()
        mock_list.list.return_value.execute.side_effect = Exception("API error")
        mock_client.admin.users.return_value = mock_list
        
        # Test
        with pytest.raises(BackupError, match="Failed to backup users"):
            backup_manager.backup_users(output_format="json")
    
    def test_backup_groups_json_success(self, backup_manager, mock_client, temp_backup_dir):
        """Test backing up groups to JSON successfully."""
        mock_groups = [
            {
                "email": "group1@example.com",
                "name": "Group One",
                "description": "First group",
                "directMembersCount": 5,
            },
            {
                "email": "group2@example.com",
                "name": "Group Two",
                "directMembersCount": 3,
            },
        ]
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = {
            "groups": mock_groups,
        }
        mock_client.admin.groups.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_groups(output_format="json")
        
        # Verify
        assert metadata.backup_type == "groups"
        assert metadata.item_count == 2
        assert metadata.status == "completed"
        assert metadata.backup_path.exists()
        
        # Verify file content
        with open(metadata.backup_path) as f:
            saved_groups = json.load(f)
        assert len(saved_groups) == 2
        assert saved_groups[0]["email"] == "group1@example.com"
        
        # Verify API call
        mock_list.list.assert_called_once_with(
            domain="example.com",
            maxResults=200,
            pageToken=None,
        )
    
    def test_backup_groups_csv_success(self, backup_manager, mock_client):
        """Test backing up groups to CSV successfully."""
        mock_groups = [
            {
                "email": "group1@example.com",
                "name": "Group One",
                "description": "First group",
                "directMembersCount": 5,
            },
        ]
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = {
            "groups": mock_groups,
        }
        mock_client.admin.groups.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_groups(output_format="csv")
        
        # Verify
        assert metadata.backup_path.suffix == ".csv"
        
        # Verify CSV content
        with open(metadata.backup_path) as f:
            content = f.read()
        assert "email" in content
        assert "group1@example.com" in content
    
    def test_backup_groups_error(self, backup_manager, mock_client):
        """Test backing up groups with error."""
        mock_list = Mock()
        mock_list.list.return_value.execute.side_effect = Exception("API error")
        mock_client.admin.groups.return_value = mock_list
        
        # Test
        with pytest.raises(BackupError, match="Failed to backup groups"):
            backup_manager.backup_groups(output_format="json")
    
    def test_backup_org_units_json_success(self, backup_manager, mock_client, temp_backup_dir):
        """Test backing up organizational units to JSON successfully."""
        mock_ous = [
            {
                "name": "Engineering",
                "orgUnitPath": "/Engineering",
                "parentOrgUnitPath": "/",
                "description": "Engineering team",
            },
            {
                "name": "Sales",
                "orgUnitPath": "/Sales",
                "parentOrgUnitPath": "/",
            },
        ]
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = {
            "organizationUnits": mock_ous,
        }
        mock_client.admin.orgunits.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_org_units(output_format="json")
        
        # Verify
        assert metadata.backup_type == "org_units"
        assert metadata.item_count == 2
        assert metadata.status == "completed"
        assert metadata.backup_path.exists()
        
        # Verify file content
        with open(metadata.backup_path) as f:
            saved_ous = json.load(f)
        assert len(saved_ous) == 2
        assert saved_ous[0]["name"] == "Engineering"
        
        # Verify API call
        mock_list.list.assert_called_once_with(
            customerId="my_customer",
            type="all",
        )
    
    def test_backup_org_units_csv_success(self, backup_manager, mock_client):
        """Test backing up organizational units to CSV successfully."""
        mock_ous = [
            {
                "name": "Engineering",
                "orgUnitPath": "/Engineering",
                "parentOrgUnitPath": "/",
                "description": "Engineering team",
            },
        ]
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = {
            "organizationUnits": mock_ous,
        }
        mock_client.admin.orgunits.return_value = mock_list
        
        # Test
        metadata = backup_manager.backup_org_units(output_format="csv")
        
        # Verify
        assert metadata.backup_path.suffix == ".csv"
        
        # Verify CSV content
        with open(metadata.backup_path) as f:
            content = f.read()
        assert "name" in content
        assert "Engineering" in content
    
    def test_backup_org_units_error(self, backup_manager, mock_client):
        """Test backing up organizational units with error."""
        mock_list = Mock()
        mock_list.list.return_value.execute.side_effect = Exception("API error")
        mock_client.admin.orgunits.return_value = mock_list
        
        # Test
        with pytest.raises(BackupError, match="Failed to backup organizational units"):
            backup_manager.backup_org_units(output_format="json")
    
    def test_backup_full_success(self, backup_manager, mock_client):
        """Test performing a full backup successfully."""
        # Mock all API responses
        mock_client.admin.users.return_value.list.return_value.execute.return_value = {
            "users": [{"primaryEmail": "user@example.com", "name": {"fullName": "User"}}],
        }
        mock_client.admin.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": "group@example.com", "name": "Group"}],
        }
        mock_client.admin.orgunits.return_value.list.return_value.execute.return_value = {
            "organizationUnits": [{"name": "Engineering", "orgUnitPath": "/Engineering", "parentOrgUnitPath": "/"}],
        }
        
        # Test
        backups = backup_manager.backup_full(output_format="json")
        
        # Verify
        assert len(backups) == 3
        assert backups[0].backup_type == "users"
        assert backups[1].backup_type == "groups"
        assert backups[2].backup_type == "org_units"
        
        # Verify all backups completed
        for backup in backups:
            assert backup.status == "completed"
            assert backup.backup_path.exists()
    
    def test_backup_full_error(self, backup_manager, mock_client):
        """Test full backup with error."""
        # First backup succeeds, second fails
        mock_client.admin.users.return_value.list.return_value.execute.return_value = {
            "users": [{"primaryEmail": "user@example.com", "name": {"fullName": "User"}}],
        }
        mock_client.admin.groups.return_value.list.return_value.execute.side_effect = Exception("API error")
        
        # Test
        with pytest.raises(BackupError, match="Failed to perform full backup"):
            backup_manager.backup_full(output_format="json")
    
    def test_list_backups_success(self, backup_manager, temp_backup_dir):
        """Test listing backups successfully."""
        # Create metadata directory and files
        metadata_dir = temp_backup_dir / ".metadata"
        metadata_dir.mkdir()
        
        # Create mock metadata files
        metadata1 = {
            "backup_id": "users_20241031_120000",
            "backup_type": "users",
            "created_at": "2024-10-31T12:00:00+00:00",
            "backup_path": str(temp_backup_dir / "users_20241031_120000.json"),
            "item_count": 10,
            "size_bytes": 1024,
            "status": "completed",
        }
        metadata2 = {
            "backup_id": "groups_20241031_130000",
            "backup_type": "groups",
            "created_at": "2024-10-31T13:00:00+00:00",
            "backup_path": str(temp_backup_dir / "groups_20241031_130000.json"),
            "item_count": 5,
            "size_bytes": 512,
            "status": "completed",
        }
        
        with open(metadata_dir / "users_20241031_120000.json", "w") as f:
            json.dump(metadata1, f)
        with open(metadata_dir / "groups_20241031_130000.json", "w") as f:
            json.dump(metadata2, f)
        
        # Test
        backups = backup_manager.list_backups()
        
        # Verify
        assert len(backups) == 2
        # Should be sorted by creation time (newest first)
        assert backups[0].backup_type == "groups"
        assert backups[1].backup_type == "users"
        assert backups[0].item_count == 5
        assert backups[1].item_count == 10
    
    def test_list_backups_empty(self, backup_manager):
        """Test listing backups when none exist."""
        # Test
        backups = backup_manager.list_backups()
        
        # Verify
        assert len(backups) == 0
    
    def test_list_backups_corrupted_metadata(self, backup_manager, temp_backup_dir):
        """Test listing backups with corrupted metadata file."""
        # Create metadata directory with corrupted file
        metadata_dir = temp_backup_dir / ".metadata"
        metadata_dir.mkdir()
        
        with open(metadata_dir / "corrupted.json", "w") as f:
            f.write("invalid json{")
        
        # Test - should not raise error, just skip corrupted file
        backups = backup_manager.list_backups()
        
        # Verify
        assert len(backups) == 0

