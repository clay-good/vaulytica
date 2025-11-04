"""Tests for OU Manager."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from googleapiclient.errors import HttpError

from vaulytica.core.lifecycle.ou_manager import (
    OUManager,
    OrganizationalUnit,
    OUManagementError,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.admin = Mock()
    client.admin.orgunits = Mock(return_value=Mock())
    client.admin.users = Mock(return_value=Mock())
    return client


@pytest.fixture
def ou_manager(mock_client):
    """Create an OU manager instance."""
    return OUManager(mock_client, customer_id="test_customer")


class TestOUManager:
    """Tests for OUManager class."""
    
    def test_init(self, mock_client):
        """Test OU manager initialization."""
        manager = OUManager(mock_client, customer_id="test_customer")
        assert manager.client == mock_client
        assert manager.customer_id == "test_customer"
    
    def test_list_ous_success(self, ou_manager, mock_client):
        """Test listing OUs successfully."""
        # Mock API response
        mock_response = {
            "organizationUnits": [
                {
                    "name": "Engineering",
                    "orgUnitPath": "/Engineering",
                    "parentOrgUnitPath": "/",
                    "description": "Engineering team",
                    "blockInheritance": False,
                    "etag": "etag123",
                },
                {
                    "name": "Sales",
                    "orgUnitPath": "/Sales",
                    "parentOrgUnitPath": "/",
                    "description": "Sales team",
                    "blockInheritance": True,
                    "etag": "etag456",
                },
            ]
        }
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_list
        
        # Test
        ous = ou_manager.list_ous()
        
        # Verify
        assert len(ous) == 2
        assert ous[0].name == "Engineering"
        assert ous[0].org_unit_path == "/Engineering"
        assert ous[0].parent_org_unit_path == "/"
        assert ous[0].description == "Engineering team"
        assert ous[0].block_inheritance is False
        assert ous[1].name == "Sales"
        assert ous[1].block_inheritance is True
        
        # Verify API call
        mock_list.list.assert_called_once_with(
            customerId="test_customer",
            type="all",
        )
    
    def test_list_ous_with_parent_filter(self, ou_manager, mock_client):
        """Test listing OUs with parent filter."""
        mock_response = {"organizationUnits": []}
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_list
        
        # Test
        ou_manager.list_ous(org_unit_path="/Engineering")
        
        # Verify API call includes parent filter
        mock_list.list.assert_called_once_with(
            customerId="test_customer",
            type="all",
            orgUnitPath="/Engineering",
        )
    
    def test_list_ous_empty(self, ou_manager, mock_client):
        """Test listing OUs when none exist."""
        mock_response = {"organizationUnits": []}
        
        mock_list = Mock()
        mock_list.list.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_list
        
        # Test
        ous = ou_manager.list_ous()
        
        # Verify
        assert len(ous) == 0
    
    def test_list_ous_http_error(self, ou_manager, mock_client):
        """Test listing OUs with HTTP error."""
        mock_list = Mock()
        mock_list.list.return_value.execute.side_effect = HttpError(
            resp=Mock(status=403), content=b"Access denied"
        )
        mock_client.admin.orgunits.return_value = mock_list
        
        # Test
        with pytest.raises(OUManagementError, match="Failed to list OUs"):
            ou_manager.list_ous()
    
    def test_get_ou_success(self, ou_manager, mock_client):
        """Test getting a specific OU successfully."""
        mock_response = {
            "name": "Engineering",
            "orgUnitPath": "/Engineering",
            "parentOrgUnitPath": "/",
            "description": "Engineering team",
            "blockInheritance": False,
            "etag": "etag123",
        }
        
        mock_get = Mock()
        mock_get.get.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_get
        
        # Test
        ou = ou_manager.get_ou("/Engineering")
        
        # Verify
        assert ou.name == "Engineering"
        assert ou.org_unit_path == "/Engineering"
        assert ou.parent_org_unit_path == "/"
        assert ou.description == "Engineering team"
        assert ou.block_inheritance is False
        
        # Verify API call with URL encoding
        mock_get.get.assert_called_once()
        call_args = mock_get.get.call_args
        assert call_args[1]["customerId"] == "test_customer"
        assert "%2FEngineering" in call_args[1]["orgUnitPath"]  # URL encoded
    
    def test_get_ou_http_error(self, ou_manager, mock_client):
        """Test getting OU with HTTP error."""
        mock_get = Mock()
        mock_get.get.return_value.execute.side_effect = HttpError(
            resp=Mock(status=404), content=b"Not found"
        )
        mock_client.admin.orgunits.return_value = mock_get
        
        # Test
        with pytest.raises(OUManagementError, match="Failed to get OU"):
            ou_manager.get_ou("/NonExistent")
    
    def test_create_ou_success(self, ou_manager, mock_client):
        """Test creating an OU successfully."""
        mock_response = {
            "name": "Engineering",
            "orgUnitPath": "/Engineering",
            "parentOrgUnitPath": "/",
            "description": "Engineering team",
            "blockInheritance": False,
            "etag": "etag123",
        }
        
        mock_insert = Mock()
        mock_insert.insert.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_insert
        
        # Test
        ou = ou_manager.create_ou(
            name="Engineering",
            parent_org_unit_path="/",
            description="Engineering team",
            block_inheritance=False,
        )
        
        # Verify
        assert ou.name == "Engineering"
        assert ou.org_unit_path == "/Engineering"
        assert ou.description == "Engineering team"
        
        # Verify API call
        mock_insert.insert.assert_called_once()
        call_args = mock_insert.insert.call_args
        assert call_args[1]["customerId"] == "test_customer"
        assert call_args[1]["body"]["name"] == "Engineering"
        assert call_args[1]["body"]["parentOrgUnitPath"] == "/"
        assert call_args[1]["body"]["description"] == "Engineering team"
        assert call_args[1]["body"]["blockInheritance"] is False
    
    def test_create_ou_minimal(self, ou_manager, mock_client):
        """Test creating an OU with minimal parameters."""
        mock_response = {
            "name": "Sales",
            "orgUnitPath": "/Sales",
            "parentOrgUnitPath": "/",
            "blockInheritance": False,
        }
        
        mock_insert = Mock()
        mock_insert.insert.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_insert
        
        # Test
        ou = ou_manager.create_ou(name="Sales")
        
        # Verify
        assert ou.name == "Sales"
        assert ou.org_unit_path == "/Sales"
        
        # Verify API call doesn't include description
        call_args = mock_insert.insert.call_args
        assert "description" not in call_args[1]["body"]
    
    def test_create_ou_http_error(self, ou_manager, mock_client):
        """Test creating OU with HTTP error."""
        mock_insert = Mock()
        mock_insert.insert.return_value.execute.side_effect = HttpError(
            resp=Mock(status=409), content=b"Already exists"
        )
        mock_client.admin.orgunits.return_value = mock_insert
        
        # Test
        with pytest.raises(OUManagementError, match="Failed to create OU"):
            ou_manager.create_ou(name="Engineering")
    
    def test_update_ou_success(self, ou_manager, mock_client):
        """Test updating an OU successfully."""
        mock_response = {
            "name": "Engineering Team",
            "orgUnitPath": "/Engineering",
            "parentOrgUnitPath": "/",
            "description": "Updated description",
            "blockInheritance": True,
            "etag": "etag456",
        }
        
        mock_update = Mock()
        mock_update.update.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_update
        
        # Test
        ou = ou_manager.update_ou(
            org_unit_path="/Engineering",
            name="Engineering Team",
            description="Updated description",
            block_inheritance=True,
        )
        
        # Verify
        assert ou.name == "Engineering Team"
        assert ou.description == "Updated description"
        assert ou.block_inheritance is True
        
        # Verify API call
        mock_update.update.assert_called_once()
        call_args = mock_update.update.call_args
        assert call_args[1]["customerId"] == "test_customer"
        assert call_args[1]["body"]["name"] == "Engineering Team"
        assert call_args[1]["body"]["description"] == "Updated description"
        assert call_args[1]["body"]["blockInheritance"] is True
    
    def test_update_ou_partial(self, ou_manager, mock_client):
        """Test updating OU with partial parameters."""
        mock_response = {
            "name": "Engineering Team",
            "orgUnitPath": "/Engineering",
            "parentOrgUnitPath": "/",
        }
        
        mock_update = Mock()
        mock_update.update.return_value.execute.return_value = mock_response
        mock_client.admin.orgunits.return_value = mock_update
        
        # Test - only update name
        ou_manager.update_ou(org_unit_path="/Engineering", name="Engineering Team")
        
        # Verify API call only includes name
        call_args = mock_update.update.call_args
        assert "name" in call_args[1]["body"]
        assert "description" not in call_args[1]["body"]
        assert "blockInheritance" not in call_args[1]["body"]
    
    def test_update_ou_http_error(self, ou_manager, mock_client):
        """Test updating OU with HTTP error."""
        mock_update = Mock()
        mock_update.update.return_value.execute.side_effect = HttpError(
            resp=Mock(status=404), content=b"Not found"
        )
        mock_client.admin.orgunits.return_value = mock_update
        
        # Test
        with pytest.raises(OUManagementError, match="Failed to update OU"):
            ou_manager.update_ou(org_unit_path="/NonExistent", name="New Name")
    
    def test_delete_ou_success(self, ou_manager, mock_client):
        """Test deleting an OU successfully."""
        mock_delete = Mock()
        mock_delete.delete.return_value.execute.return_value = {}
        mock_client.admin.orgunits.return_value = mock_delete
        
        # Test
        ou_manager.delete_ou("/Engineering")
        
        # Verify API call
        mock_delete.delete.assert_called_once()
        call_args = mock_delete.delete.call_args
        assert call_args[1]["customerId"] == "test_customer"
        assert "%2FEngineering" in call_args[1]["orgUnitPath"]  # URL encoded
    
    def test_delete_ou_http_error(self, ou_manager, mock_client):
        """Test deleting OU with HTTP error."""
        mock_delete = Mock()
        mock_delete.delete.return_value.execute.side_effect = HttpError(
            resp=Mock(status=404), content=b"Not found"
        )
        mock_client.admin.orgunits.return_value = mock_delete
        
        # Test
        with pytest.raises(OUManagementError, match="Failed to delete OU"):
            ou_manager.delete_ou("/NonExistent")
    
    def test_move_users_to_ou_success(self, ou_manager, mock_client):
        """Test moving users to OU successfully."""
        mock_update = Mock()
        mock_update.update.return_value.execute.return_value = {}
        mock_client.admin.users.return_value = mock_update
        
        # Test
        results = ou_manager.move_users_to_ou(
            user_emails=["user1@example.com", "user2@example.com"],
            org_unit_path="/Engineering",
        )
        
        # Verify
        assert results["success"] == 2
        assert results["failed"] == 0
        assert len(results["errors"]) == 0
        
        # Verify API calls
        assert mock_update.update.call_count == 2
    
    def test_move_users_to_ou_partial_failure(self, ou_manager, mock_client):
        """Test moving users with some failures."""
        mock_update = Mock()
        
        # First call succeeds, second fails
        mock_update.update.return_value.execute.side_effect = [
            {},  # Success
            HttpError(resp=Mock(status=404), content=b"User not found"),  # Failure
        ]
        mock_client.admin.users.return_value = mock_update
        
        # Test
        results = ou_manager.move_users_to_ou(
            user_emails=["user1@example.com", "user2@example.com"],
            org_unit_path="/Engineering",
        )
        
        # Verify
        assert results["success"] == 1
        assert results["failed"] == 1
        assert len(results["errors"]) == 1
        assert results["errors"][0]["email"] == "user2@example.com"
    
    def test_move_users_to_ou_empty_list(self, ou_manager, mock_client):
        """Test moving empty list of users."""
        # Test
        results = ou_manager.move_users_to_ou(
            user_emails=[],
            org_unit_path="/Engineering",
        )
        
        # Verify
        assert results["success"] == 0
        assert results["failed"] == 0
        assert len(results["errors"]) == 0

