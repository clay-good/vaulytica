"""Calendar resource management (conference rooms, equipment)."""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


class ResourceManagementError(Exception):
    """Exception raised for resource management errors."""
    pass


@dataclass
class CalendarResource:
    """Represents a calendar resource (conference room, equipment)."""
    
    resource_id: str
    resource_name: str
    resource_email: str
    resource_type: str  # "CONFERENCE_ROOM", "OTHER"
    resource_category: Optional[str] = None
    resource_description: Optional[str] = None
    capacity: Optional[int] = None
    building_id: Optional[str] = None
    floor_name: Optional[str] = None
    floor_section: Optional[str] = None
    user_visible_description: Optional[str] = None
    feature_instances: List[str] = None
    
    def __post_init__(self):
        if self.feature_instances is None:
            self.feature_instances = []


@dataclass
class Building:
    """Represents a building."""
    
    building_id: str
    building_name: str
    description: Optional[str] = None
    address_lines: List[str] = None
    coordinates: Optional[Dict[str, float]] = None
    
    def __post_init__(self):
        if self.address_lines is None:
            self.address_lines = []


class CalendarResourceManager:
    """Manager for calendar resource operations."""
    
    def __init__(self, client: GoogleWorkspaceClient, customer_id: str = "my_customer"):
        """Initialize calendar resource manager.
        
        Args:
            client: Google Workspace client
            customer_id: Customer ID (default: "my_customer")
        """
        self.client = client
        self.customer_id = customer_id
        self.logger = logger.bind(component="calendar_resource_manager")
    
    def list_resources(self) -> List[CalendarResource]:
        """List all calendar resources.
        
        Returns:
            List of CalendarResource objects
            
        Raises:
            ResourceManagementError: If listing fails
        """
        self.logger.info("listing_calendar_resources")
        
        try:
            resources = []
            page_token = None
            
            while True:
                params = {
                    "customer": self.customer_id,
                    "maxResults": 500,
                }
                
                if page_token:
                    params["pageToken"] = page_token
                
                response = self.client.admin.resources().calendars().list(**params).execute()
                
                for resource_data in response.get("items", []):
                    resource = CalendarResource(
                        resource_id=resource_data.get("resourceId", ""),
                        resource_name=resource_data.get("resourceName", ""),
                        resource_email=resource_data.get("resourceEmail", ""),
                        resource_type=resource_data.get("resourceType", "OTHER"),
                        resource_category=resource_data.get("resourceCategory"),
                        resource_description=resource_data.get("resourceDescription"),
                        capacity=resource_data.get("capacity"),
                        building_id=resource_data.get("buildingId"),
                        floor_name=resource_data.get("floorName"),
                        floor_section=resource_data.get("floorSection"),
                        user_visible_description=resource_data.get("userVisibleDescription"),
                        feature_instances=[f.get("feature", {}).get("name", "") for f in resource_data.get("featureInstances", [])],
                    )
                    resources.append(resource)
                
                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            
            self.logger.info("resources_listed", count=len(resources))
            return resources
            
        except HttpError as e:
            self.logger.error("list_resources_failed", error=str(e))
            raise ResourceManagementError(f"Failed to list calendar resources: {e}")
    
    def get_resource(self, resource_id: str) -> CalendarResource:
        """Get a specific calendar resource.
        
        Args:
            resource_id: Resource ID
            
        Returns:
            CalendarResource object
            
        Raises:
            ResourceManagementError: If retrieval fails
        """
        self.logger.info("getting_resource", resource_id=resource_id)
        
        try:
            response = self.client.admin.resources().calendars().get(
                customer=self.customer_id,
                calendarResourceId=resource_id,
            ).execute()
            
            resource = CalendarResource(
                resource_id=response.get("resourceId", ""),
                resource_name=response.get("resourceName", ""),
                resource_email=response.get("resourceEmail", ""),
                resource_type=response.get("resourceType", "OTHER"),
                resource_category=response.get("resourceCategory"),
                resource_description=response.get("resourceDescription"),
                capacity=response.get("capacity"),
                building_id=response.get("buildingId"),
                floor_name=response.get("floorName"),
                floor_section=response.get("floorSection"),
                user_visible_description=response.get("userVisibleDescription"),
                feature_instances=[f.get("feature", {}).get("name", "") for f in response.get("featureInstances", [])],
            )
            
            self.logger.info("resource_retrieved", resource_id=resource_id)
            return resource
            
        except HttpError as e:
            self.logger.error("get_resource_failed", resource_id=resource_id, error=str(e))
            raise ResourceManagementError(f"Failed to get resource {resource_id}: {e}")
    
    def create_resource(
        self,
        resource_name: str,
        resource_type: str = "CONFERENCE_ROOM",
        capacity: Optional[int] = None,
        building_id: Optional[str] = None,
        floor_name: Optional[str] = None,
        floor_section: Optional[str] = None,
        description: Optional[str] = None,
        features: Optional[List[str]] = None,
    ) -> CalendarResource:
        """Create a new calendar resource.
        
        Args:
            resource_name: Name of the resource
            resource_type: Type of resource (default: "CONFERENCE_ROOM")
            capacity: Capacity (number of people)
            building_id: Building ID
            floor_name: Floor name
            floor_section: Floor section
            description: Description
            features: List of feature names
            
        Returns:
            Created CalendarResource object
            
        Raises:
            ResourceManagementError: If creation fails
        """
        self.logger.info("creating_resource", resource_name=resource_name)
        
        try:
            resource_body = {
                "resourceName": resource_name,
                "resourceType": resource_type,
            }
            
            if capacity is not None:
                resource_body["capacity"] = capacity
            if building_id:
                resource_body["buildingId"] = building_id
            if floor_name:
                resource_body["floorName"] = floor_name
            if floor_section:
                resource_body["floorSection"] = floor_section
            if description:
                resource_body["resourceDescription"] = description
                resource_body["userVisibleDescription"] = description
            if features:
                resource_body["featureInstances"] = [{"feature": {"name": f}} for f in features]
            
            response = self.client.admin.resources().calendars().insert(
                customer=self.customer_id,
                body=resource_body,
            ).execute()
            
            resource = CalendarResource(
                resource_id=response.get("resourceId", ""),
                resource_name=response.get("resourceName", ""),
                resource_email=response.get("resourceEmail", ""),
                resource_type=response.get("resourceType", "OTHER"),
                resource_category=response.get("resourceCategory"),
                resource_description=response.get("resourceDescription"),
                capacity=response.get("capacity"),
                building_id=response.get("buildingId"),
                floor_name=response.get("floorName"),
                floor_section=response.get("floorSection"),
                user_visible_description=response.get("userVisibleDescription"),
                feature_instances=[f.get("feature", {}).get("name", "") for f in response.get("featureInstances", [])],
            )
            
            self.logger.info("resource_created", resource_id=resource.resource_id)
            return resource
            
        except HttpError as e:
            self.logger.error("create_resource_failed", resource_name=resource_name, error=str(e))
            raise ResourceManagementError(f"Failed to create resource {resource_name}: {e}")
    
    def update_resource(
        self,
        resource_id: str,
        resource_name: Optional[str] = None,
        capacity: Optional[int] = None,
        building_id: Optional[str] = None,
        floor_name: Optional[str] = None,
        floor_section: Optional[str] = None,
        description: Optional[str] = None,
        features: Optional[List[str]] = None,
    ) -> CalendarResource:
        """Update a calendar resource.
        
        Args:
            resource_id: Resource ID to update
            resource_name: New name (optional)
            capacity: New capacity (optional)
            building_id: New building ID (optional)
            floor_name: New floor name (optional)
            floor_section: New floor section (optional)
            description: New description (optional)
            features: New list of feature names (optional)
            
        Returns:
            Updated CalendarResource object
            
        Raises:
            ResourceManagementError: If update fails
        """
        self.logger.info("updating_resource", resource_id=resource_id)
        
        try:
            resource_body = {}
            
            if resource_name is not None:
                resource_body["resourceName"] = resource_name
            if capacity is not None:
                resource_body["capacity"] = capacity
            if building_id is not None:
                resource_body["buildingId"] = building_id
            if floor_name is not None:
                resource_body["floorName"] = floor_name
            if floor_section is not None:
                resource_body["floorSection"] = floor_section
            if description is not None:
                resource_body["resourceDescription"] = description
                resource_body["userVisibleDescription"] = description
            if features is not None:
                resource_body["featureInstances"] = [{"feature": {"name": f}} for f in features]
            
            response = self.client.admin.resources().calendars().update(
                customer=self.customer_id,
                calendarResourceId=resource_id,
                body=resource_body,
            ).execute()
            
            resource = CalendarResource(
                resource_id=response.get("resourceId", ""),
                resource_name=response.get("resourceName", ""),
                resource_email=response.get("resourceEmail", ""),
                resource_type=response.get("resourceType", "OTHER"),
                resource_category=response.get("resourceCategory"),
                resource_description=response.get("resourceDescription"),
                capacity=response.get("capacity"),
                building_id=response.get("buildingId"),
                floor_name=response.get("floorName"),
                floor_section=response.get("floorSection"),
                user_visible_description=response.get("userVisibleDescription"),
                feature_instances=[f.get("feature", {}).get("name", "") for f in response.get("featureInstances", [])],
            )
            
            self.logger.info("resource_updated", resource_id=resource_id)
            return resource
            
        except HttpError as e:
            self.logger.error("update_resource_failed", resource_id=resource_id, error=str(e))
            raise ResourceManagementError(f"Failed to update resource {resource_id}: {e}")
    
    def delete_resource(self, resource_id: str) -> None:
        """Delete a calendar resource.
        
        Args:
            resource_id: Resource ID to delete
            
        Raises:
            ResourceManagementError: If deletion fails
        """
        self.logger.info("deleting_resource", resource_id=resource_id)
        
        try:
            self.client.admin.resources().calendars().delete(
                customer=self.customer_id,
                calendarResourceId=resource_id,
            ).execute()
            
            self.logger.info("resource_deleted", resource_id=resource_id)
            
        except HttpError as e:
            self.logger.error("delete_resource_failed", resource_id=resource_id, error=str(e))
            raise ResourceManagementError(f"Failed to delete resource {resource_id}: {e}")
    
    def list_buildings(self) -> List[Building]:
        """List all buildings.
        
        Returns:
            List of Building objects
            
        Raises:
            ResourceManagementError: If listing fails
        """
        self.logger.info("listing_buildings")
        
        try:
            buildings = []
            page_token = None
            
            while True:
                params = {
                    "customer": self.customer_id,
                    "maxResults": 500,
                }
                
                if page_token:
                    params["pageToken"] = page_token
                
                response = self.client.admin.resources().buildings().list(**params).execute()
                
                for building_data in response.get("buildings", []):
                    building = Building(
                        building_id=building_data.get("buildingId", ""),
                        building_name=building_data.get("buildingName", ""),
                        description=building_data.get("description"),
                        address_lines=building_data.get("address", {}).get("addressLines", []),
                        coordinates=building_data.get("coordinates"),
                    )
                    buildings.append(building)
                
                page_token = response.get("nextPageToken")
                if not page_token:
                    break
            
            self.logger.info("buildings_listed", count=len(buildings))
            return buildings
            
        except HttpError as e:
            self.logger.error("list_buildings_failed", error=str(e))
            raise ResourceManagementError(f"Failed to list buildings: {e}")

