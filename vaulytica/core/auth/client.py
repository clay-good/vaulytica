"""Google Workspace API client wrapper."""

from typing import Optional, Any
from googleapiclient.discovery import build, Resource
from googleapiclient.errors import HttpError
import structlog

from .credentials import CredentialManager, AuthenticationError

logger = structlog.get_logger(__name__)


class APIError(Exception):
    """Raised when API calls fail."""

    pass


class GoogleWorkspaceClient:
    """Wrapper for Google Workspace API clients."""

    def __init__(
        self,
        credential_manager: CredentialManager,
        impersonate_user: Optional[str] = None,
    ):
        """Initialize Google Workspace client.

        Args:
            credential_manager: CredentialManager instance
            impersonate_user: Email of user to impersonate (for service accounts)
        """
        self.credential_manager = credential_manager
        self.impersonate_user = impersonate_user
        self._drive_service: Optional[Resource] = None
        self._admin_service: Optional[Resource] = None
        self._reports_service: Optional[Resource] = None
        self._gmail_service: Optional[Resource] = None

        logger.info(
            "google_workspace_client_initialized",
            impersonate_user=impersonate_user,
        )

    @property
    def drive(self) -> Resource:
        """Get Google Drive API service.

        Returns:
            Drive API service resource

        Raises:
            AuthenticationError: If authentication fails
        """
        if not self._drive_service:
            try:
                credentials = self.credential_manager.get_credentials(self.impersonate_user)
                self._drive_service = build("drive", "v3", credentials=credentials)
                logger.info("drive_service_initialized")
            except Exception as e:
                logger.error("drive_service_initialization_failed", error=str(e))
                raise AuthenticationError(f"Failed to initialize Drive service: {e}")

        return self._drive_service

    @property
    def admin(self) -> Resource:
        """Get Admin SDK Directory API service.

        Returns:
            Admin SDK service resource

        Raises:
            AuthenticationError: If authentication fails
        """
        if not self._admin_service:
            try:
                credentials = self.credential_manager.get_credentials(self.impersonate_user)
                self._admin_service = build("admin", "directory_v1", credentials=credentials)
                logger.info("admin_service_initialized")
            except Exception as e:
                logger.error("admin_service_initialization_failed", error=str(e))
                raise AuthenticationError(f"Failed to initialize Admin service: {e}")

        return self._admin_service

    @property
    def reports(self) -> Resource:
        """Get Admin SDK Reports API service.

        Returns:
            Reports API service resource

        Raises:
            AuthenticationError: If authentication fails
        """
        if not self._reports_service:
            try:
                credentials = self.credential_manager.get_credentials(self.impersonate_user)
                self._reports_service = build("admin", "reports_v1", credentials=credentials)
                logger.info("reports_service_initialized")
            except Exception as e:
                logger.error("reports_service_initialization_failed", error=str(e))
                raise AuthenticationError(f"Failed to initialize Reports service: {e}")

        return self._reports_service

    @property
    def gmail(self) -> Resource:
        """Get Gmail API service.

        Returns:
            Gmail API service resource

        Raises:
            AuthenticationError: If authentication fails
        """
        if not self._gmail_service:
            try:
                credentials = self.credential_manager.get_credentials(self.impersonate_user)
                self._gmail_service = build("gmail", "v1", credentials=credentials)
                logger.info("gmail_service_initialized")
            except Exception as e:
                logger.error("gmail_service_initialization_failed", error=str(e))
                raise AuthenticationError(f"Failed to initialize Gmail service: {e}")

        return self._gmail_service

    @property
    def calendar(self) -> Resource:
        """Get Google Calendar API service.

        Returns:
            Calendar API service resource

        Raises:
            AuthenticationError: If authentication fails
        """
        if not hasattr(self, "_calendar_service") or not self._calendar_service:
            try:
                credentials = self.credential_manager.get_credentials(self.impersonate_user)
                self._calendar_service = build("calendar", "v3", credentials=credentials)
                logger.info("calendar_service_initialized")
            except Exception as e:
                logger.error("calendar_service_initialization_failed", error=str(e))
                raise AuthenticationError(f"Failed to initialize Calendar service: {e}")

        return self._calendar_service

    @property
    def vault(self) -> Resource:
        """Get Google Vault API service.

        Returns:
            Vault API service resource

        Raises:
            AuthenticationError: If authentication fails
        """
        if not hasattr(self, "_vault_service") or not self._vault_service:
            try:
                credentials = self.credential_manager.get_credentials(self.impersonate_user)
                self._vault_service = build("vault", "v1", credentials=credentials)
                logger.info("vault_service_initialized")
            except Exception as e:
                logger.error("vault_service_initialization_failed", error=str(e))
                raise AuthenticationError(f"Failed to initialize Vault service: {e}")

        return self._vault_service

    def test_connection(self) -> bool:
        """Test API connection by making a simple request.

        Returns:
            True if connection is successful

        Raises:
            APIError: If connection test fails
        """
        try:
            # Try to get user info from Admin API
            result = self.admin.users().list(domain="", maxResults=1).execute()
            logger.info("connection_test_successful")
            return True
        except HttpError as e:
            logger.error("connection_test_failed", error=str(e))
            raise APIError(f"Connection test failed: {e}")
        except Exception as e:
            logger.error("connection_test_error", error=str(e))
            raise APIError(f"Unexpected error during connection test: {e}")


def create_client_from_config(config: dict) -> GoogleWorkspaceClient:
    """Create Google Workspace client from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        Configured GoogleWorkspaceClient instance
    """
    from .credentials import create_credential_manager_from_config

    credential_manager = create_credential_manager_from_config(config)
    impersonate_user = config.get("google_workspace", {}).get("impersonate_user")

    return GoogleWorkspaceClient(
        credential_manager=credential_manager,
        impersonate_user=impersonate_user,
    )

