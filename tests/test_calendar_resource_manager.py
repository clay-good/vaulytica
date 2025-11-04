"""Tests for Calendar Resource Manager."""

import pytest
from unittest.mock import Mock, MagicMock
from googleapiclient.errors import HttpError

from vaulytica.core.resources.calendar_resource_manager import (
    CalendarResourceManager,
    CalendarResource,
    Building,
    ResourceManagementError,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.admin = Mock()
    client.admin.resources = Mock(return_value=Mock())
    return client


@pytest.fixture
def resource_manager(mock_client):
    """Create a calendar resource manager instance."""
    return CalendarResourceManager(mock_client, customer_id="test_customer")


class TestCalendarResourceManager:
    """Tests for CalendarResourceManager class."""
    
    def test_init(self, mock_client):
        """Test resource manager initialization."""
        manager = CalendarResourceManager(mock_client, customer_id="test_customer")
        assert manager.client == mock_client
        assert manager.customer_id == "test_customer"
    
    def test_list_resources_success(self, resource_manager, mock_client):
        """Test listing resources successfully."""
        # Mock API response
        mock_response = {
            "items": [
                {
                    "resourceId": "room1",
                    "resourceName": "Conference Room A",
                    "resourceEmail": "room-a@example.com",
                    "resourceType": "CONFERENCE_ROOM",
                    "capacity": 10,
                    "buildingId": "building-1",
                    "floorName": "2nd Floor",
                    "featureInstances": [
                        {"feature": {"name": "Video Conference"}},
                        {"feature": {"name": "Whiteboard"}},
                    ],
                },
                {
                    "resourceId": "room2",
                    "resourceName": "Conference Room B",
                    "resourceEmail": "room-b@example.com",
                    "resourceType": "CONFERENCE_ROOM",
                    "capacity": 6,
                },
            ]
        }
        
        mock_calendars = Mock()
        mock_calendars.list.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resources = resource_manager.list_resources()
        
        # Verify
        assert len(resources) == 2
        assert resources[0].resource_id == "room1"
        assert resources[0].resource_name == "Conference Room A"
        assert resources[0].resource_email == "room-a@example.com"
        assert resources[0].resource_type == "CONFERENCE_ROOM"
        assert resources[0].capacity == 10
        assert resources[0].building_id == "building-1"
        assert resources[0].floor_name == "2nd Floor"
        assert len(resources[0].feature_instances) == 2
        assert "Video Conference" in resources[0].feature_instances
        
        # Verify API call
        mock_calendars.list.assert_called_once_with(
            customer="test_customer",
            maxResults=500,
        )
    
    def test_list_resources_pagination(self, resource_manager, mock_client):
        """Test listing resources with pagination."""
        # Mock API responses with pagination
        mock_response_1 = {
            "items": [{"resourceId": "room1", "resourceName": "Room 1", "resourceEmail": "room1@example.com", "resourceType": "CONFERENCE_ROOM"}],
            "nextPageToken": "token123",
        }
        mock_response_2 = {
            "items": [{"resourceId": "room2", "resourceName": "Room 2", "resourceEmail": "room2@example.com", "resourceType": "CONFERENCE_ROOM"}],
        }
        
        mock_calendars = Mock()
        mock_calendars.list.return_value.execute.side_effect = [mock_response_1, mock_response_2]
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resources = resource_manager.list_resources()
        
        # Verify
        assert len(resources) == 2
        assert mock_calendars.list.call_count == 2
        
        # Verify second call includes page token
        second_call_args = mock_calendars.list.call_args_list[1]
        assert second_call_args[1]["pageToken"] == "token123"
    
    def test_list_resources_empty(self, resource_manager, mock_client):
        """Test listing resources when none exist."""
        mock_response = {"items": []}
        
        mock_calendars = Mock()
        mock_calendars.list.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resources = resource_manager.list_resources()
        
        # Verify
        assert len(resources) == 0
    
    def test_list_resources_http_error(self, resource_manager, mock_client):
        """Test listing resources with HTTP error."""
        mock_calendars = Mock()
        mock_calendars.list.return_value.execute.side_effect = HttpError(
            resp=Mock(status=403), content=b"Access denied"
        )
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        with pytest.raises(ResourceManagementError, match="Failed to list calendar resources"):
            resource_manager.list_resources()
    
    def test_get_resource_success(self, resource_manager, mock_client):
        """Test getting a specific resource successfully."""
        mock_response = {
            "resourceId": "room1",
            "resourceName": "Conference Room A",
            "resourceEmail": "room-a@example.com",
            "resourceType": "CONFERENCE_ROOM",
            "capacity": 10,
            "buildingId": "building-1",
            "floorName": "2nd Floor",
            "resourceDescription": "Main conference room",
            "featureInstances": [],
        }
        
        mock_calendars = Mock()
        mock_calendars.get.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resource = resource_manager.get_resource("room1")
        
        # Verify
        assert resource.resource_id == "room1"
        assert resource.resource_name == "Conference Room A"
        assert resource.capacity == 10
        assert resource.resource_description == "Main conference room"
        
        # Verify API call
        mock_calendars.get.assert_called_once_with(
            customer="test_customer",
            calendarResourceId="room1",
        )
    
    def test_get_resource_http_error(self, resource_manager, mock_client):
        """Test getting resource with HTTP error."""
        mock_calendars = Mock()
        mock_calendars.get.return_value.execute.side_effect = HttpError(
            resp=Mock(status=404), content=b"Not found"
        )
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        with pytest.raises(ResourceManagementError, match="Failed to get resource"):
            resource_manager.get_resource("nonexistent")
    
    def test_create_resource_success(self, resource_manager, mock_client):
        """Test creating a resource successfully."""
        mock_response = {
            "resourceId": "room1",
            "resourceName": "Conference Room A",
            "resourceEmail": "room-a@example.com",
            "resourceType": "CONFERENCE_ROOM",
            "capacity": 10,
            "buildingId": "building-1",
            "floorName": "2nd Floor",
            "resourceDescription": "Main conference room",
            "featureInstances": [{"feature": {"name": "Video Conference"}}],
        }
        
        mock_calendars = Mock()
        mock_calendars.insert.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resource = resource_manager.create_resource(
            resource_name="Conference Room A",
            resource_type="CONFERENCE_ROOM",
            capacity=10,
            building_id="building-1",
            floor_name="2nd Floor",
            description="Main conference room",
            features=["Video Conference"],
        )
        
        # Verify
        assert resource.resource_id == "room1"
        assert resource.resource_name == "Conference Room A"
        assert resource.capacity == 10
        
        # Verify API call
        mock_calendars.insert.assert_called_once()
        call_args = mock_calendars.insert.call_args
        assert call_args[1]["customer"] == "test_customer"
        body = call_args[1]["body"]
        assert body["resourceName"] == "Conference Room A"
        assert body["resourceType"] == "CONFERENCE_ROOM"
        assert body["capacity"] == 10
        assert body["buildingId"] == "building-1"
        assert body["floorName"] == "2nd Floor"
        assert body["resourceDescription"] == "Main conference room"
        assert len(body["featureInstances"]) == 1
    
    def test_create_resource_minimal(self, resource_manager, mock_client):
        """Test creating a resource with minimal parameters."""
        mock_response = {
            "resourceId": "room1",
            "resourceName": "Room 1",
            "resourceEmail": "room1@example.com",
            "resourceType": "CONFERENCE_ROOM",
        }
        
        mock_calendars = Mock()
        mock_calendars.insert.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resource = resource_manager.create_resource(resource_name="Room 1")
        
        # Verify
        assert resource.resource_name == "Room 1"
        
        # Verify API call doesn't include optional fields
        call_args = mock_calendars.insert.call_args
        body = call_args[1]["body"]
        assert "capacity" not in body
        assert "buildingId" not in body
        assert "resourceDescription" not in body
    
    def test_create_resource_http_error(self, resource_manager, mock_client):
        """Test creating resource with HTTP error."""
        mock_calendars = Mock()
        mock_calendars.insert.return_value.execute.side_effect = HttpError(
            resp=Mock(status=409), content=b"Already exists"
        )
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        with pytest.raises(ResourceManagementError, match="Failed to create resource"):
            resource_manager.create_resource(resource_name="Room 1")
    
    def test_update_resource_success(self, resource_manager, mock_client):
        """Test updating a resource successfully."""
        mock_response = {
            "resourceId": "room1",
            "resourceName": "Updated Room",
            "resourceEmail": "room1@example.com",
            "resourceType": "CONFERENCE_ROOM",
            "capacity": 12,
            "resourceDescription": "Updated description",
        }
        
        mock_calendars = Mock()
        mock_calendars.update.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resource = resource_manager.update_resource(
            resource_id="room1",
            resource_name="Updated Room",
            capacity=12,
            description="Updated description",
        )
        
        # Verify
        assert resource.resource_name == "Updated Room"
        assert resource.capacity == 12
        assert resource.resource_description == "Updated description"
        
        # Verify API call
        mock_calendars.update.assert_called_once()
        call_args = mock_calendars.update.call_args
        assert call_args[1]["customer"] == "test_customer"
        assert call_args[1]["calendarResourceId"] == "room1"
        body = call_args[1]["body"]
        assert body["resourceName"] == "Updated Room"
        assert body["capacity"] == 12
        assert body["resourceDescription"] == "Updated description"
    
    def test_update_resource_partial(self, resource_manager, mock_client):
        """Test updating resource with partial parameters."""
        mock_response = {
            "resourceId": "room1",
            "resourceName": "Updated Room",
            "resourceEmail": "room1@example.com",
            "resourceType": "CONFERENCE_ROOM",
        }
        
        mock_calendars = Mock()
        mock_calendars.update.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test - only update name
        resource_manager.update_resource(resource_id="room1", resource_name="Updated Room")
        
        # Verify API call only includes name
        call_args = mock_calendars.update.call_args
        body = call_args[1]["body"]
        assert "resourceName" in body
        assert "capacity" not in body
        assert "buildingId" not in body
    
    def test_update_resource_http_error(self, resource_manager, mock_client):
        """Test updating resource with HTTP error."""
        mock_calendars = Mock()
        mock_calendars.update.return_value.execute.side_effect = HttpError(
            resp=Mock(status=404), content=b"Not found"
        )
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        with pytest.raises(ResourceManagementError, match="Failed to update resource"):
            resource_manager.update_resource(resource_id="nonexistent", resource_name="New Name")
    
    def test_delete_resource_success(self, resource_manager, mock_client):
        """Test deleting a resource successfully."""
        mock_calendars = Mock()
        mock_calendars.delete.return_value.execute.return_value = {}
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        resource_manager.delete_resource("room1")
        
        # Verify API call
        mock_calendars.delete.assert_called_once_with(
            customer="test_customer",
            calendarResourceId="room1",
        )
    
    def test_delete_resource_http_error(self, resource_manager, mock_client):
        """Test deleting resource with HTTP error."""
        mock_calendars = Mock()
        mock_calendars.delete.return_value.execute.side_effect = HttpError(
            resp=Mock(status=404), content=b"Not found"
        )
        mock_resources = Mock()
        mock_resources.calendars.return_value = mock_calendars
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        with pytest.raises(ResourceManagementError, match="Failed to delete resource"):
            resource_manager.delete_resource("nonexistent")
    
    def test_list_buildings_success(self, resource_manager, mock_client):
        """Test listing buildings successfully."""
        mock_response = {
            "buildings": [
                {
                    "buildingId": "building-1",
                    "buildingName": "Main Building",
                    "description": "Main office building",
                    "address": {
                        "addressLines": ["123 Main St", "Suite 100"],
                    },
                    "coordinates": {"latitude": 37.7749, "longitude": -122.4194},
                },
                {
                    "buildingId": "building-2",
                    "buildingName": "Annex",
                    "address": {"addressLines": []},
                },
            ]
        }
        
        mock_buildings = Mock()
        mock_buildings.list.return_value.execute.return_value = mock_response
        mock_resources = Mock()
        mock_resources.buildings.return_value = mock_buildings
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        buildings = resource_manager.list_buildings()
        
        # Verify
        assert len(buildings) == 2
        assert buildings[0].building_id == "building-1"
        assert buildings[0].building_name == "Main Building"
        assert buildings[0].description == "Main office building"
        assert len(buildings[0].address_lines) == 2
        assert buildings[0].coordinates == {"latitude": 37.7749, "longitude": -122.4194}
        
        # Verify API call
        mock_buildings.list.assert_called_once_with(
            customer="test_customer",
            maxResults=500,
        )
    
    def test_list_buildings_pagination(self, resource_manager, mock_client):
        """Test listing buildings with pagination."""
        mock_response_1 = {
            "buildings": [{"buildingId": "b1", "buildingName": "Building 1"}],
            "nextPageToken": "token123",
        }
        mock_response_2 = {
            "buildings": [{"buildingId": "b2", "buildingName": "Building 2"}],
        }
        
        mock_buildings = Mock()
        mock_buildings.list.return_value.execute.side_effect = [mock_response_1, mock_response_2]
        mock_resources = Mock()
        mock_resources.buildings.return_value = mock_buildings
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        buildings = resource_manager.list_buildings()
        
        # Verify
        assert len(buildings) == 2
        assert mock_buildings.list.call_count == 2
    
    def test_list_buildings_http_error(self, resource_manager, mock_client):
        """Test listing buildings with HTTP error."""
        mock_buildings = Mock()
        mock_buildings.list.return_value.execute.side_effect = HttpError(
            resp=Mock(status=403), content=b"Access denied"
        )
        mock_resources = Mock()
        mock_resources.buildings.return_value = mock_buildings
        mock_client.admin.resources.return_value = mock_resources
        
        # Test
        with pytest.raises(ResourceManagementError, match="Failed to list buildings"):
            resource_manager.list_buildings()

