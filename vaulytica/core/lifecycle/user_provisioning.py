"""User provisioning and lifecycle management."""

from typing import Dict, Any
import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


class UserProvisioningError(Exception):
    """Raised when user provisioning fails."""
    pass


class UserProvisioner:
    """Manages user provisioning and lifecycle operations."""

    def __init__(self, client: GoogleWorkspaceClient):
        """Initialize user provisioner.

        Args:
            client: Authenticated Google Workspace client
        """
        self.client = client
        logger.info("user_provisioner_initialized")

    def create_user(
        self,
        email: str,
        first_name: str,
        last_name: str,
        password: str,
        org_unit_path: str = "/",
        change_password_at_next_login: bool = True,
        **kwargs,
    ) -> Dict[str, Any]:
        """Create a new user account.

        Args:
            email: User's email address
            first_name: User's first name
            last_name: User's last name
            password: Initial password
            org_unit_path: Organizational unit path (default: "/")
            change_password_at_next_login: Require password change on first login
            **kwargs: Additional user properties (title, department, etc.)

        Returns:
            Created user object

        Raises:
            UserProvisioningError: If user creation fails
        """
        logger.info("creating_user", email=email, org_unit=org_unit_path)

        user_body = {
            "primaryEmail": email,
            "name": {
                "givenName": first_name,
                "familyName": last_name,
            },
            "password": password,
            "changePasswordAtNextLogin": change_password_at_next_login,
            "orgUnitPath": org_unit_path,
        }

        # Add optional fields
        if "title" in kwargs:
            user_body["organizations"] = [{"title": kwargs["title"], "primary": True}]

        if "department" in kwargs:
            if "organizations" not in user_body:
                user_body["organizations"] = [{}]
            user_body["organizations"][0]["department"] = kwargs["department"]

        if "phone" in kwargs:
            user_body["phones"] = [{"value": kwargs["phone"], "type": "work"}]

        if "recovery_email" in kwargs:
            user_body["recoveryEmail"] = kwargs["recovery_email"]

        if "recovery_phone" in kwargs:
            user_body["recoveryPhone"] = kwargs["recovery_phone"]

        try:
            user = self.client.admin.users().insert(body=user_body).execute()
            logger.info("user_created", email=email, user_id=user.get("id"))
            return user
        except HttpError as e:
            logger.error("user_creation_failed", email=email, error=str(e))
            raise UserProvisioningError(f"Failed to create user {email}: {e}")

    def suspend_user(self, email: str) -> Dict[str, Any]:
        """Suspend a user account.

        Args:
            email: User's email address

        Returns:
            Updated user object

        Raises:
            UserProvisioningError: If suspension fails
        """
        logger.info("suspending_user", email=email)

        try:
            user = self.client.admin.users().update(
                userKey=email,
                body={"suspended": True}
            ).execute()
            logger.info("user_suspended", email=email)
            return user
        except HttpError as e:
            logger.error("user_suspension_failed", email=email, error=str(e))
            raise UserProvisioningError(f"Failed to suspend user {email}: {e}")

    def restore_user(self, email: str) -> Dict[str, Any]:
        """Restore a suspended user account.

        Args:
            email: User's email address

        Returns:
            Updated user object

        Raises:
            UserProvisioningError: If restoration fails
        """
        logger.info("restoring_user", email=email)

        try:
            user = self.client.admin.users().update(
                userKey=email,
                body={"suspended": False}
            ).execute()
            logger.info("user_restored", email=email)
            return user
        except HttpError as e:
            logger.error("user_restoration_failed", email=email, error=str(e))
            raise UserProvisioningError(f"Failed to restore user {email}: {e}")

    def delete_user(self, email: str) -> None:
        """Delete a user account (permanent).

        Args:
            email: User's email address

        Raises:
            UserProvisioningError: If deletion fails
        """
        logger.warning("deleting_user", email=email)

        try:
            self.client.admin.users().delete(userKey=email).execute()
            logger.info("user_deleted", email=email)
        except HttpError as e:
            logger.error("user_deletion_failed", email=email, error=str(e))
            raise UserProvisioningError(f"Failed to delete user {email}: {e}")

    def update_user(self, email: str, **kwargs) -> Dict[str, Any]:
        """Update user account details.

        Args:
            email: User's email address
            **kwargs: Fields to update (first_name, last_name, org_unit_path, title, etc.)

        Returns:
            Updated user object

        Raises:
            UserProvisioningError: If update fails
        """
        logger.info("updating_user", email=email, fields=list(kwargs.keys()))

        user_body = {}

        # Handle name updates
        if "first_name" in kwargs or "last_name" in kwargs:
            user_body["name"] = {}
            if "first_name" in kwargs:
                user_body["name"]["givenName"] = kwargs["first_name"]
            if "last_name" in kwargs:
                user_body["name"]["familyName"] = kwargs["last_name"]

        # Handle org unit
        if "org_unit_path" in kwargs:
            user_body["orgUnitPath"] = kwargs["org_unit_path"]

        # Handle organization info
        if "title" in kwargs or "department" in kwargs:
            user_body["organizations"] = [{"primary": True}]
            if "title" in kwargs:
                user_body["organizations"][0]["title"] = kwargs["title"]
            if "department" in kwargs:
                user_body["organizations"][0]["department"] = kwargs["department"]

        # Handle manager
        if "manager_email" in kwargs:
            user_body["relations"] = [
                {"value": kwargs["manager_email"], "type": "manager"}
            ]

        # Handle password
        if "password" in kwargs:
            user_body["password"] = kwargs["password"]
            if "change_password_at_next_login" in kwargs:
                user_body["changePasswordAtNextLogin"] = kwargs["change_password_at_next_login"]

        try:
            user = self.client.admin.users().update(
                userKey=email,
                body=user_body
            ).execute()
            logger.info("user_updated", email=email)
            return user
        except HttpError as e:
            logger.error("user_update_failed", email=email, error=str(e))
            raise UserProvisioningError(f"Failed to update user {email}: {e}")

    def reset_password(
        self,
        email: str,
        new_password: str,
        change_password_at_next_login: bool = True
    ) -> Dict[str, Any]:
        """Reset user password.

        Args:
            email: User's email address
            new_password: New password
            change_password_at_next_login: Require password change on next login

        Returns:
            Updated user object

        Raises:
            UserProvisioningError: If password reset fails
        """
        logger.info("resetting_password", email=email)

        try:
            user = self.client.admin.users().update(
                userKey=email,
                body={
                    "password": new_password,
                    "changePasswordAtNextLogin": change_password_at_next_login,
                }
            ).execute()
            logger.info("password_reset", email=email)
            return user
        except HttpError as e:
            logger.error("password_reset_failed", email=email, error=str(e))
            raise UserProvisioningError(f"Failed to reset password for {email}: {e}")

    def add_user_to_group(self, user_email: str, group_email: str) -> Dict[str, Any]:
        """Add user to a group.

        Args:
            user_email: User's email address
            group_email: Group's email address

        Returns:
            Group member object

        Raises:
            UserProvisioningError: If adding to group fails
        """
        logger.info("adding_user_to_group", user=user_email, group=group_email)

        try:
            member = self.client.admin.members().insert(
                groupKey=group_email,
                body={"email": user_email, "role": "MEMBER"}
            ).execute()
            logger.info("user_added_to_group", user=user_email, group=group_email)
            return member
        except HttpError as e:
            logger.error("add_to_group_failed", user=user_email, group=group_email, error=str(e))
            raise UserProvisioningError(f"Failed to add {user_email} to group {group_email}: {e}")

    def remove_user_from_group(self, user_email: str, group_email: str) -> None:
        """Remove user from a group.

        Args:
            user_email: User's email address
            group_email: Group's email address

        Raises:
            UserProvisioningError: If removal from group fails
        """
        logger.info("removing_user_from_group", user=user_email, group=group_email)

        try:
            self.client.admin.members().delete(
                groupKey=group_email,
                memberKey=user_email
            ).execute()
            logger.info("user_removed_from_group", user=user_email, group=group_email)
        except HttpError as e:
            logger.error("remove_from_group_failed", user=user_email, group=group_email, error=str(e))
            raise UserProvisioningError(f"Failed to remove {user_email} from group {group_email}: {e}")

    def get_user(self, email: str) -> Dict[str, Any]:
        """Get user details.

        Args:
            email: User's email address

        Returns:
            User object

        Raises:
            UserProvisioningError: If user not found
        """
        try:
            user = self.client.admin.users().get(userKey=email).execute()
            return user
        except HttpError as e:
            logger.error("get_user_failed", email=email, error=str(e))
            raise UserProvisioningError(f"Failed to get user {email}: {e}")

