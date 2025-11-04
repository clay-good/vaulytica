"""Organizational Unit (OU) management."""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


class OUManagementError(Exception):
    """Exception raised for OU management errors."""
    pass


@dataclass
class OrganizationalUnit:
    """Represents an organizational unit."""
    
    name: str
    org_unit_path: str
    parent_org_unit_path: str
    description: Optional[str] = None
    block_inheritance: bool = False
    etag: Optional[str] = None


class OUManager:
    """Manager for organizational unit operations."""
    
    def __init__(self, client: GoogleWorkspaceClient, customer_id: str = "my_customer"):
        """Initialize OU manager.
        
        Args:
            client: Google Workspace client
            customer_id: Customer ID (default: "my_customer")
        """
        self.client = client
        self.customer_id = customer_id
        self.logger = logger.bind(component="ou_manager")
    
    def list_ous(self, org_unit_path: Optional[str] = None) -> List[OrganizationalUnit]:
        """List all organizational units.
        
        Args:
            org_unit_path: Optional parent OU path to filter by
            
        Returns:
            List of OrganizationalUnit objects
            
        Raises:
            OUManagementError: If listing fails
        """
        self.logger.info("listing_ous", org_unit_path=org_unit_path)
        
        try:
            params = {
                "customerId": self.customer_id,
                "type": "all",
            }
            
            if org_unit_path:
                params["orgUnitPath"] = org_unit_path
            
            response = self.client.admin.orgunits().list(**params).execute()
            
            ous = []
            for ou_data in response.get("organizationUnits", []):
                ou = OrganizationalUnit(
                    name=ou_data.get("name", ""),
                    org_unit_path=ou_data.get("orgUnitPath", ""),
                    parent_org_unit_path=ou_data.get("parentOrgUnitPath", ""),
                    description=ou_data.get("description"),
                    block_inheritance=ou_data.get("blockInheritance", False),
                    etag=ou_data.get("etag"),
                )
                ous.append(ou)
            
            self.logger.info("ous_listed", count=len(ous))
            return ous
            
        except HttpError as e:
            self.logger.error("list_ous_failed", error=str(e))
            raise OUManagementError(f"Failed to list OUs: {e}")
    
    def get_ou(self, org_unit_path: str) -> OrganizationalUnit:
        """Get a specific organizational unit.
        
        Args:
            org_unit_path: Path to the OU (e.g., "/Engineering")
            
        Returns:
            OrganizationalUnit object
            
        Raises:
            OUManagementError: If retrieval fails
        """
        self.logger.info("getting_ou", org_unit_path=org_unit_path)
        
        try:
            # Encode the path for URL
            from urllib.parse import quote
            encoded_path = quote(org_unit_path, safe='')
            
            response = self.client.admin.orgunits().get(
                customerId=self.customer_id,
                orgUnitPath=encoded_path,
            ).execute()
            
            ou = OrganizationalUnit(
                name=response.get("name", ""),
                org_unit_path=response.get("orgUnitPath", ""),
                parent_org_unit_path=response.get("parentOrgUnitPath", ""),
                description=response.get("description"),
                block_inheritance=response.get("blockInheritance", False),
                etag=response.get("etag"),
            )
            
            self.logger.info("ou_retrieved", org_unit_path=org_unit_path)
            return ou
            
        except HttpError as e:
            self.logger.error("get_ou_failed", org_unit_path=org_unit_path, error=str(e))
            raise OUManagementError(f"Failed to get OU {org_unit_path}: {e}")
    
    def create_ou(
        self,
        name: str,
        parent_org_unit_path: str = "/",
        description: Optional[str] = None,
        block_inheritance: bool = False,
    ) -> OrganizationalUnit:
        """Create a new organizational unit.
        
        Args:
            name: Name of the OU
            parent_org_unit_path: Parent OU path (default: "/")
            description: Optional description
            block_inheritance: Whether to block policy inheritance
            
        Returns:
            Created OrganizationalUnit object
            
        Raises:
            OUManagementError: If creation fails
        """
        self.logger.info(
            "creating_ou",
            name=name,
            parent_org_unit_path=parent_org_unit_path,
        )
        
        try:
            ou_body = {
                "name": name,
                "parentOrgUnitPath": parent_org_unit_path,
                "blockInheritance": block_inheritance,
            }
            
            if description:
                ou_body["description"] = description
            
            response = self.client.admin.orgunits().insert(
                customerId=self.customer_id,
                body=ou_body,
            ).execute()
            
            ou = OrganizationalUnit(
                name=response.get("name", ""),
                org_unit_path=response.get("orgUnitPath", ""),
                parent_org_unit_path=response.get("parentOrgUnitPath", ""),
                description=response.get("description"),
                block_inheritance=response.get("blockInheritance", False),
                etag=response.get("etag"),
            )
            
            self.logger.info("ou_created", org_unit_path=ou.org_unit_path)
            return ou
            
        except HttpError as e:
            self.logger.error("create_ou_failed", name=name, error=str(e))
            raise OUManagementError(f"Failed to create OU {name}: {e}")
    
    def update_ou(
        self,
        org_unit_path: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        parent_org_unit_path: Optional[str] = None,
        block_inheritance: Optional[bool] = None,
    ) -> OrganizationalUnit:
        """Update an organizational unit.
        
        Args:
            org_unit_path: Path to the OU to update
            name: New name (optional)
            description: New description (optional)
            parent_org_unit_path: New parent path (optional, moves the OU)
            block_inheritance: New block inheritance setting (optional)
            
        Returns:
            Updated OrganizationalUnit object
            
        Raises:
            OUManagementError: If update fails
        """
        self.logger.info("updating_ou", org_unit_path=org_unit_path)
        
        try:
            from urllib.parse import quote
            encoded_path = quote(org_unit_path, safe='')
            
            ou_body = {}
            
            if name is not None:
                ou_body["name"] = name
            if description is not None:
                ou_body["description"] = description
            if parent_org_unit_path is not None:
                ou_body["parentOrgUnitPath"] = parent_org_unit_path
            if block_inheritance is not None:
                ou_body["blockInheritance"] = block_inheritance
            
            response = self.client.admin.orgunits().update(
                customerId=self.customer_id,
                orgUnitPath=encoded_path,
                body=ou_body,
            ).execute()
            
            ou = OrganizationalUnit(
                name=response.get("name", ""),
                org_unit_path=response.get("orgUnitPath", ""),
                parent_org_unit_path=response.get("parentOrgUnitPath", ""),
                description=response.get("description"),
                block_inheritance=response.get("blockInheritance", False),
                etag=response.get("etag"),
            )
            
            self.logger.info("ou_updated", org_unit_path=org_unit_path)
            return ou
            
        except HttpError as e:
            self.logger.error("update_ou_failed", org_unit_path=org_unit_path, error=str(e))
            raise OUManagementError(f"Failed to update OU {org_unit_path}: {e}")
    
    def delete_ou(self, org_unit_path: str) -> None:
        """Delete an organizational unit.
        
        Args:
            org_unit_path: Path to the OU to delete
            
        Raises:
            OUManagementError: If deletion fails
        """
        self.logger.info("deleting_ou", org_unit_path=org_unit_path)
        
        try:
            from urllib.parse import quote
            encoded_path = quote(org_unit_path, safe='')
            
            self.client.admin.orgunits().delete(
                customerId=self.customer_id,
                orgUnitPath=encoded_path,
            ).execute()
            
            self.logger.info("ou_deleted", org_unit_path=org_unit_path)
            
        except HttpError as e:
            self.logger.error("delete_ou_failed", org_unit_path=org_unit_path, error=str(e))
            raise OUManagementError(f"Failed to delete OU {org_unit_path}: {e}")
    
    def move_users_to_ou(self, user_emails: List[str], org_unit_path: str) -> Dict[str, Any]:
        """Move multiple users to an organizational unit.
        
        Args:
            user_emails: List of user email addresses
            org_unit_path: Target OU path
            
        Returns:
            Dictionary with success/failure counts
            
        Raises:
            OUManagementError: If operation fails
        """
        self.logger.info(
            "moving_users_to_ou",
            user_count=len(user_emails),
            org_unit_path=org_unit_path,
        )
        
        results = {
            "success": 0,
            "failed": 0,
            "errors": [],
        }
        
        for email in user_emails:
            try:
                self.client.admin.users().update(
                    userKey=email,
                    body={"orgUnitPath": org_unit_path},
                ).execute()
                results["success"] += 1
                self.logger.debug("user_moved", email=email, org_unit_path=org_unit_path)
            except HttpError as e:
                results["failed"] += 1
                results["errors"].append({"email": email, "error": str(e)})
                self.logger.error("move_user_failed", email=email, error=str(e))
        
        self.logger.info(
            "users_moved",
            success=results["success"],
            failed=results["failed"],
        )
        
        return results

