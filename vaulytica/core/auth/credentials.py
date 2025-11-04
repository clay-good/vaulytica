"""Google Workspace authentication and credential management."""

import json
import os
from pathlib import Path
from typing import Optional, List

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import structlog

logger = structlog.get_logger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class CredentialManager:
    """Manages Google Workspace API credentials."""

    # Required API scopes
    SCOPES = [
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
    ]

    def __init__(
        self,
        credentials_file: Optional[str] = None,
        oauth_credentials_file: Optional[str] = None,
        token_file: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ):
        """Initialize credential manager.

        Args:
            credentials_file: Path to service account JSON file
            oauth_credentials_file: Path to OAuth 2.0 credentials JSON file
            token_file: Path to store OAuth tokens
            scopes: List of API scopes (defaults to SCOPES)
        """
        self.credentials_file = credentials_file
        self.oauth_credentials_file = oauth_credentials_file
        self.token_file = token_file or "token.json"
        self.scopes = scopes or self.SCOPES
        self._credentials: Optional[Credentials] = None

        logger.info(
            "credential_manager_initialized",
            has_service_account=bool(credentials_file),
            has_oauth=bool(oauth_credentials_file),
        )

    def get_credentials(self, impersonate_user: Optional[str] = None) -> Credentials:
        """Get authenticated credentials.

        Args:
            impersonate_user: Email of user to impersonate (for service accounts)

        Returns:
            Authenticated credentials object

        Raises:
            AuthenticationError: If authentication fails
        """
        if self._credentials and self._credentials.valid:
            return self._credentials

        # Try service account first
        if self.credentials_file:
            logger.info("authenticating_with_service_account")
            self._credentials = self._get_service_account_credentials(impersonate_user)
            return self._credentials

        # Fall back to OAuth
        if self.oauth_credentials_file:
            logger.info("authenticating_with_oauth")
            self._credentials = self._get_oauth_credentials()
            return self._credentials

        raise AuthenticationError(
            "No credentials provided. Set credentials_file or oauth_credentials_file."
        )

    def _get_service_account_credentials(
        self, impersonate_user: Optional[str] = None
    ) -> service_account.Credentials:
        """Get service account credentials with domain-wide delegation.

        Args:
            impersonate_user: Email of user to impersonate

        Returns:
            Service account credentials

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            if not self.credentials_file or not os.path.exists(self.credentials_file):
                raise AuthenticationError(
                    f"Service account file not found: {self.credentials_file}"
                )

            credentials = service_account.Credentials.from_service_account_file(
                self.credentials_file, scopes=self.scopes
            )

            # Impersonate user for domain-wide delegation
            if impersonate_user:
                credentials = credentials.with_subject(impersonate_user)
                logger.info("impersonating_user", user=impersonate_user)

            logger.info("service_account_authentication_successful")
            return credentials

        except Exception as e:
            logger.error("service_account_authentication_failed", error=str(e))
            raise AuthenticationError(f"Service account authentication failed: {e}")

    def _get_oauth_credentials(self) -> Credentials:
        """Get OAuth 2.0 credentials with automatic refresh.

        Returns:
            OAuth credentials

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            creds = None

            # Load existing token if available
            if os.path.exists(self.token_file):
                logger.info("loading_existing_token", token_file=self.token_file)
                creds = Credentials.from_authorized_user_file(self.token_file, self.scopes)

            # Refresh or get new credentials
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    logger.info("refreshing_expired_token")
                    creds.refresh(Request())
                else:
                    logger.info("starting_oauth_flow")
                    if not self.oauth_credentials_file or not os.path.exists(
                        self.oauth_credentials_file
                    ):
                        raise AuthenticationError(
                            f"OAuth credentials file not found: {self.oauth_credentials_file}"
                        )

                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.oauth_credentials_file, self.scopes
                    )
                    creds = flow.run_local_server(port=0)

                # Save credentials for next run
                logger.info("saving_token", token_file=self.token_file)
                with open(self.token_file, "w") as token:
                    token.write(creds.to_json())

            logger.info("oauth_authentication_successful")
            return creds

        except Exception as e:
            logger.error("oauth_authentication_failed", error=str(e))
            raise AuthenticationError(f"OAuth authentication failed: {e}")

    def validate_credentials(self) -> bool:
        """Validate that credentials are working.

        Returns:
            True if credentials are valid and working
        """
        try:
            creds = self.get_credentials()
            return creds is not None and creds.valid
        except Exception as e:
            logger.error("credential_validation_failed", error=str(e))
            return False

    def revoke_credentials(self) -> None:
        """Revoke OAuth credentials and delete token file."""
        if os.path.exists(self.token_file):
            os.remove(self.token_file)
            logger.info("token_file_deleted", token_file=self.token_file)

        self._credentials = None
        logger.info("credentials_revoked")


def create_credential_manager_from_config(config: dict) -> CredentialManager:
    """Create credential manager from configuration dictionary.

    Args:
        config: Configuration dictionary with google_workspace section

    Returns:
        Configured CredentialManager instance

    Raises:
        ValueError: If configuration is invalid
    """
    gws_config = config.get("google_workspace", {})

    credentials_file = gws_config.get("credentials_file")
    oauth_credentials_file = gws_config.get("oauth_credentials")
    token_file = gws_config.get("token_file", "token.json")

    if not credentials_file and not oauth_credentials_file:
        raise ValueError(
            "Configuration must include either credentials_file or oauth_credentials"
        )

    return CredentialManager(
        credentials_file=credentials_file,
        oauth_credentials_file=oauth_credentials_file,
        token_file=token_file,
    )

